//! Off-task FMP + FSP decrypt + delivery worker.
//!
//! Incremental data-plane shard restructure: each worker owns its hot receive
//! state directly in local `HashMap`s, with no `Arc<RwLock<HashMap>>` cache on
//! the Node side and no `Arc<Mutex<ReplayWindow>>` shared with the rx_loop.
//! FMP state is keyed by the link receiver session; local established FSP
//! state is keyed by the end-to-end source peer so path drift does not split
//! replay ownership.
//!
//! Dispatch is **deterministic by session key**: rx_loop computes
//! `worker_idx = hash(session_key) % N` and routes both
//! `RegisterSession` control messages and per-packet `Job` messages
//! through the same hash, so a session always lands on the same shard.
//!
//! Worker messages travel through two bounded per-worker lanes:
//!
//! - **`RegisterSession`** — sent when an FMP session is promoted or
//!   rekeyed. Hands the worker an owned snapshot of the recv cipher,
//!   replay window, and authenticated source peer for the FMP layer.
//!   It uses the priority lane.
//! - **`Job`** — per-packet FMP decrypt. Large packets use the bulk lane;
//!   small control-shaped packets use the priority lane so
//!   heartbeats/MMP/rekey-sized traffic is not trapped behind a full bulk
//!   queue. Local established FSP session datagrams are handed to the FSP
//!   owner shard; other link messages fall back to the rx loop.
//! - **`UnregisterSession`** — sent on rekey / peer drop so the worker
//!   releases the owned cipher + replay state. It uses the priority
//!   lane.
//!
//! Direct-hop FSP data no longer carries payload bytes back through rx_loop:
//! the worker authenticates, admits replay, queues a compact receive commit to
//! rx_loop, then delivers the already-decoded payload to the configured TUN or
//! external packet sink once that commit is accepted. Transit-delivered data
//! still returns to rx_loop so reverse-route learning happens before local
//! delivery.

// **Unix only at the call sites.** On Windows nothing constructs an
// `OwnedSessionState` or spawns the pool (see `lifecycle.rs`), so
// every field + function in here becomes dead. Silence the warnings
// rather than gate them individually.
#![cfg_attr(not(unix), allow(dead_code))]

use crate::FipsAddress;
use crate::NodeAddr;
use crate::PeerIdentity;
use crate::node::handlers::session::AuthenticatedSessionMessage;
use crate::node::handlers::session::mark_ipv6_ecn_ce;
use crate::node::session::{EpochSlot, FspReceiveSync, FspRecvSessionSnapshot};
use crate::node::session_wire::{
    FSP_FLAG_K, FSP_HEADER_SIZE, FSP_PHASE_ESTABLISHED, FSP_PORT_HEADER_SIZE, FSP_PORT_IPV6_SHIM,
    FspCommonPrefix, FspEncryptedHeader, fsp_strip_inner_header,
};
use crate::node::{
    EndpointDataDelivery, EndpointEventSender, NodeDeliveredPacket, NodeEndpointEvent,
};
use crate::protocol::{LinkMessageType, SessionDatagramRef, SessionMessageType};
use crate::transport::{TransportAddr, TransportId};
use crate::upper::tun::TunTx;
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use ring::aead::{Aad, LessSafeKey, Nonce};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::mpsc::{
    Receiver as TokioReceiver, Sender as TokioSender, error::TrySendError as TokioTrySendError,
};
use tracing::{debug, trace, warn};

// `endpoint_event_tx` used to ride on every `DecryptJob`, bloating the hot
// packet shape with an extra Arc clone and accidentally gating TUN-only worker
// use. Keep it pool-owned instead: workers may deliver direct-hop endpoint data
// after the direct-session commit is accepted by the rx-loop bookkeeping lane.

use crate::noise::ReplayWindow;

const DEFAULT_DECRYPT_WORKER_BULK_CHANNEL_CAP: usize = 32768;
const DEFAULT_DECRYPT_WORKER_PRIORITY_CHANNEL_CAP: usize = 1024;
const DEFAULT_DECRYPT_FALLBACK_BULK_CHANNEL_CAP: usize = 32768;
const DEFAULT_DECRYPT_FALLBACK_PRIORITY_CHANNEL_CAP: usize = 1024;
/// Fallback completions are pressure-drained by rx_loop before a full raw
/// receive turn's worth of already-decrypted bulk packets can accumulate. Emit
/// the backlog-high event at that same point so long-run soak evidence reports
/// the pressure signal when the adaptive path first matters.
pub(crate) const DECRYPT_FALLBACK_BACKLOG_HIGH_WATER: usize = 256;
const DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN: usize = 512;
const DECRYPT_WORKER_BULK_BURST_BUDGET: usize = 128;
const DECRYPT_WORKER_BULK_BATCH_MAX: usize = 32;
const DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX: usize = DECRYPT_WORKER_BULK_BURST_BUDGET;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecryptWorkerLane {
    Priority,
    Bulk,
}

/// Stable owner key for decrypt-worker shard state.
///
/// The rx loop still looks up peers by the raw `(transport_id,
/// receiver_idx)` tuple, but once a packet crosses into the worker pool this
/// named key is the contract: registration, packet jobs, and unregister all
/// hash the same value so one FMP recv session has one shard owner.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct DecryptSessionKey {
    transport_id: TransportId,
    receiver_idx: u32,
}

impl DecryptSessionKey {
    pub(crate) fn new(transport_id: TransportId, receiver_idx: u32) -> Self {
        Self {
            transport_id,
            receiver_idx,
        }
    }
}

impl From<(TransportId, u32)> for DecryptSessionKey {
    fn from((transport_id, receiver_idx): (TransportId, u32)) -> Self {
        Self::new(transport_id, receiver_idx)
    }
}

#[inline]
fn decrypt_session_fast_hash(session_key: DecryptSessionKey) -> u64 {
    let packed =
        (u64::from(session_key.transport_id.as_u32()) << 32) | u64::from(session_key.receiver_idx);
    mix_decrypt_session_hash(packed ^ 0x9e37_79b9_7f4a_7c15)
}

#[inline]
fn decrypt_fsp_session_fast_hash(source_addr: &NodeAddr) -> u64 {
    let bytes = source_addr.as_bytes();
    let mut lo = [0u8; 8];
    let mut hi = [0u8; 8];
    lo.copy_from_slice(&bytes[..8]);
    hi.copy_from_slice(&bytes[8..]);
    mix_decrypt_session_hash(
        u64::from_le_bytes(lo) ^ u64::from_le_bytes(hi).rotate_left(17) ^ 0xa24b_aed4_963e_e407,
    )
}

#[inline]
fn mix_decrypt_session_hash(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn parse_channel_cap(primary: Option<&str>, fallback: Option<&str>, default: usize) -> usize {
    primary
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .or_else(|| fallback.and_then(|raw| raw.trim().parse::<usize>().ok()))
        .unwrap_or(default)
        .clamp(1, default)
}

fn bulk_channel_cap() -> usize {
    let decrypt_cap = std::env::var("FIPS_DECRYPT_WORKER_CHANNEL_CAP").ok();
    let shared_cap = std::env::var("FIPS_WORKER_CHANNEL_CAP").ok();
    parse_channel_cap(
        decrypt_cap.as_deref(),
        shared_cap.as_deref(),
        DEFAULT_DECRYPT_WORKER_BULK_CHANNEL_CAP,
    )
}

fn priority_channel_cap() -> usize {
    let priority_cap = std::env::var("FIPS_DECRYPT_WORKER_PRIORITY_CHANNEL_CAP").ok();
    parse_channel_cap(
        priority_cap.as_deref(),
        None,
        DEFAULT_DECRYPT_WORKER_PRIORITY_CHANNEL_CAP,
    )
}

fn fallback_bulk_channel_cap() -> usize {
    let bulk_cap = std::env::var("FIPS_DECRYPT_FALLBACK_CHANNEL_CAP").ok();
    fallback_bulk_channel_cap_from_raw(bulk_cap.as_deref())
}

fn fallback_bulk_channel_cap_from_raw(bulk_cap: Option<&str>) -> usize {
    // Keep the worker input pressure knob from shrinking the worker->rx-loop
    // return lane. Tests can still force this lane small with the explicit
    // fallback cap.
    parse_channel_cap(bulk_cap, None, DEFAULT_DECRYPT_FALLBACK_BULK_CHANNEL_CAP)
}

fn fallback_priority_channel_cap() -> usize {
    let priority_cap = std::env::var("FIPS_DECRYPT_FALLBACK_PRIORITY_CHANNEL_CAP").ok();
    parse_channel_cap(
        priority_cap.as_deref(),
        None,
        DEFAULT_DECRYPT_FALLBACK_PRIORITY_CHANNEL_CAP,
    )
}

fn decrypt_worker_packet_lane(len: usize) -> DecryptWorkerLane {
    if len <= DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN {
        DecryptWorkerLane::Priority
    } else {
        DecryptWorkerLane::Bulk
    }
}

fn decrypt_job_lane(job: &DecryptJob) -> DecryptWorkerLane {
    job.lane()
}

/// Owning recv-side state for one established FMP session. Lives
/// **inside the worker thread that owns this session** — never
/// shared, never behind a mutex.
///
/// **FMP only** — the worker exclusively handles the FMP layer
/// (decrypt + replay accept), then bounces the FMP plaintext back to
/// rx_loop for FSP-layer dispatch. This split is what makes
/// register-at-FMP-establishment correct: the worker doesn't need
/// the FSP cipher / replay window, and can therefore be the
/// authoritative recv path for a peer the moment FMP is up — well
/// before the FSP handshake completes.
///
/// Built at FMP-session establishment time (`promote_connection`)
/// and shipped to the assigned worker via `WorkerMsg::RegisterSession`.
pub(crate) struct OwnedSessionState {
    pub fmp_cipher: LessSafeKey,
    pub fmp_replay: ReplayWindow,
    pub source_peer: PeerIdentity,
}

struct OwnedFspEpochState {
    cipher: LessSafeKey,
    replay: ReplayWindow,
}

pub(crate) struct OwnedFspSessionState {
    source_peer: PeerIdentity,
    current_k_bit: bool,
    current: OwnedFspEpochState,
    pending: Option<OwnedFspEpochState>,
    previous: Option<OwnedFspEpochState>,
}

struct FspOpenSuccess {
    plaintext: Vec<u8>,
    slot: EpochSlot,
}

struct FspOpenInPlaceSuccess {
    plaintext_len: usize,
    slot: EpochSlot,
}

enum FspOpenError {
    Replay,
    Aead,
}

impl From<FspRecvSessionSnapshot> for OwnedFspSessionState {
    fn from(snapshot: FspRecvSessionSnapshot) -> Self {
        Self {
            source_peer: snapshot.source_peer,
            current_k_bit: snapshot.current_k_bit,
            current: OwnedFspEpochState {
                cipher: snapshot.current.cipher,
                replay: snapshot.current.replay,
            },
            pending: snapshot.pending.map(|epoch| OwnedFspEpochState {
                cipher: epoch.cipher,
                replay: epoch.replay,
            }),
            previous: snapshot.previous.map(|epoch| OwnedFspEpochState {
                cipher: epoch.cipher,
                replay: epoch.replay,
            }),
        }
    }
}

impl OwnedFspEpochState {
    fn open(
        &mut self,
        ciphertext: &[u8],
        counter: u64,
        aad: &[u8],
    ) -> Result<Vec<u8>, FspOpenError> {
        if !self.replay.check(counter) {
            return Err(FspOpenError::Replay);
        }
        let mut plaintext = ciphertext.to_vec();
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let plaintext_len = self
            .cipher
            .open_in_place(nonce, Aad::from(aad), &mut plaintext)
            .map_err(|_| FspOpenError::Aead)?
            .len();
        plaintext.truncate(plaintext_len);
        self.replay.accept(counter);
        Ok(plaintext)
    }

    fn open_in_place(
        &mut self,
        ciphertext: &mut [u8],
        counter: u64,
        aad: &[u8],
    ) -> Result<usize, FspOpenError> {
        if !self.replay.check(counter) {
            return Err(FspOpenError::Replay);
        }
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let plaintext_len = self
            .cipher
            .open_in_place(nonce, Aad::from(aad), ciphertext)
            .map_err(|_| FspOpenError::Aead)?
            .len();
        self.replay.accept(counter);
        Ok(plaintext_len)
    }
}

impl OwnedFspSessionState {
    fn has_single_current_epoch(&self) -> bool {
        self.pending.is_none() && self.previous.is_none()
    }

    fn open_established_frame(
        &mut self,
        header: &FspEncryptedHeader,
        ciphertext: &[u8],
    ) -> Result<FspOpenSuccess, FspOpenError> {
        let received_k_bit = header.flags & FSP_FLAG_K != 0;
        let pending_first = received_k_bit != self.current_k_bit && self.pending.is_some();
        let order = if pending_first {
            [EpochSlot::Pending, EpochSlot::Current, EpochSlot::Previous]
        } else {
            [EpochSlot::Current, EpochSlot::Pending, EpochSlot::Previous]
        };

        let mut saw_replay = false;
        for slot in order {
            let epoch = match slot {
                EpochSlot::Current => Some(&mut self.current),
                EpochSlot::Pending => self.pending.as_mut(),
                EpochSlot::Previous => self.previous.as_mut(),
            };
            let Some(epoch) = epoch else {
                continue;
            };
            match epoch.open(ciphertext, header.counter, &header.header_bytes) {
                Ok(plaintext) => {
                    if slot == EpochSlot::Pending {
                        let old = std::mem::replace(
                            &mut self.current,
                            self.pending
                                .take()
                                .expect("pending epoch exists for pending slot"),
                        );
                        self.previous = Some(old);
                        self.current_k_bit = !self.current_k_bit;
                    }
                    return Ok(FspOpenSuccess { plaintext, slot });
                }
                Err(FspOpenError::Replay) => saw_replay = true,
                Err(FspOpenError::Aead) => {}
            }
        }

        if saw_replay {
            Err(FspOpenError::Replay)
        } else {
            Err(FspOpenError::Aead)
        }
    }

    fn open_current_established_frame_in_place(
        &mut self,
        header: &FspEncryptedHeader,
        ciphertext: &mut [u8],
    ) -> Result<FspOpenInPlaceSuccess, FspOpenError> {
        debug_assert!(self.has_single_current_epoch());
        let plaintext_len =
            self.current
                .open_in_place(ciphertext, header.counter, &header.header_bytes)?;
        Ok(FspOpenInPlaceSuccess {
            plaintext_len,
            slot: EpochSlot::Current,
        })
    }
}

#[derive(Debug)]
struct FmpOpenOutcome {
    plaintext_len: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum FmpOpenError {
    Replay,
    Aead { fmp_replay_highest: u64 },
}

impl OwnedSessionState {
    fn open_fmp_in_place(
        &mut self,
        packet_data: &mut [u8],
        fmp_ciphertext_offset: usize,
        fmp_counter: u64,
        fmp_header: &[u8; 16],
    ) -> Result<FmpOpenOutcome, FmpOpenError> {
        let fmp_replay_highest = self.fmp_replay.highest();
        if !self.fmp_replay.check(fmp_counter) {
            return Err(FmpOpenError::Replay);
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&fmp_counter.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let buf = &mut packet_data[fmp_ciphertext_offset..];
        let plaintext_len = self
            .fmp_cipher
            .open_in_place(nonce, Aad::from(fmp_header), buf)
            .map_err(|_| FmpOpenError::Aead { fmp_replay_highest })?
            .len();

        self.fmp_replay.accept(fmp_counter);
        Ok(FmpOpenOutcome { plaintext_len })
    }
}

/// Pre-cooked decrypt + dispatch job. Built on rx_loop after parsing
/// the FMP header; the worker pulls its session state from its own
/// local HashMap (keyed by `session_key`) instead of receiving a
/// `WorkerSessionState` clone per packet.
pub(crate) struct DecryptJob {
    /// The raw packet bytes (incl. the 16-byte FMP outer header).
    /// Mutated in place during AEAD open — must reach the worker
    /// with the full ciphertext + tag intact.
    pub packet_data: Vec<u8>,
    /// Lane selected when rx_loop builds the worker message. Dispatch consumes
    /// this queued value instead of recalculating lane policy later.
    lane: DecryptWorkerLane,
    /// Lookup key into the worker's owned session HashMap. Mirrors the
    /// active peer registry session-index key on the Node side:
    /// `(transport_id, receiver_idx)`.
    pub session_key: DecryptSessionKey,
    /// Source kernel transport. Forwarded into the bounced
    /// `DecryptFallback` so rx_loop can update per-peer last-seen +
    /// link stats (otherwise the MMP link-dead timer fires at 30s
    /// because the worker handles packets without ever calling
    /// `peer.touch()` / `record_recv()`).
    pub _transport_id: TransportId,
    pub _remote_addr: TransportAddr,
    pub local_node_addr: NodeAddr,
    pub timestamp_ms: u64,
    /// Counter from the FMP outer header. Used both as nonce input
    /// and to update the replay window.
    pub fmp_counter: u64,
    /// Flag byte from the FMP outer header. Carried through the
    /// fallback so the rx_loop bounce arm can extract `CE` and `SP`
    /// for ECN propagation, MMP stats, and spin-bit RTT
    /// observation — these used to be dropped on the worker path
    /// because the bounce hardcoded `fmp_flags: 0`.
    pub fmp_flags: u8,
    /// 16-byte FMP outer header used as AAD during AEAD open.
    pub fmp_header: [u8; 16],
    /// Offset within `packet_data` where the FMP ciphertext+tag begins.
    pub fmp_ciphertext_offset: usize,

    /// Worker completions return through this channel. Control-shaped link
    /// plaintext still falls back to rx_loop dispatch; local established FSP
    /// data can return as a worker-decoded direct-data completion whose final
    /// commit still runs on rx_loop.
    pub fallback_tx: DecryptWorkerFallbackSender,
    /// Monotonic timestamp captured immediately before rx_loop queues this job
    /// to the decrypt worker. Used only when pipeline tracing is on.
    trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

impl DecryptJob {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        packet_data: Vec<u8>,
        session_key: DecryptSessionKey,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        local_node_addr: NodeAddr,
        timestamp_ms: u64,
        fmp_counter: u64,
        fmp_flags: u8,
        fmp_header: [u8; 16],
        fmp_ciphertext_offset: usize,
        fallback_tx: DecryptWorkerFallbackSender,
    ) -> Self {
        let lane = decrypt_worker_packet_lane(packet_data.len());
        Self {
            packet_data,
            lane,
            session_key,
            _transport_id: transport_id,
            _remote_addr: remote_addr,
            local_node_addr,
            timestamp_ms,
            fmp_counter,
            fmp_flags,
            fmp_header,
            fmp_ciphertext_offset,
            fallback_tx,
            trace_enqueued_at: None,
        }
    }

    fn lane(&self) -> DecryptWorkerLane {
        self.lane
    }

    fn is_bulk_lane(&self) -> bool {
        matches!(self.lane(), DecryptWorkerLane::Bulk)
    }

    fn set_trace_enqueued_at(&mut self, queued_at: Option<crate::perf_profile::TraceStamp>) {
        self.trace_enqueued_at = queued_at;
    }

    fn record_queue_wait(&self) {
        let queued_at = self.trace_enqueued_at;
        if queued_at.is_none() {
            return;
        }
        let priority_count = u64::from(matches!(self.lane(), DecryptWorkerLane::Priority));
        let bulk_count = u64::from(matches!(self.lane(), DecryptWorkerLane::Bulk));
        crate::perf_profile::record_since_split_count(
            crate::perf_profile::Stage::DecryptWorkerQueueWait,
            crate::perf_profile::Stage::DecryptWorkerPriorityQueueWait,
            crate::perf_profile::Stage::DecryptWorkerBulkQueueWait,
            queued_at,
            1,
            priority_count,
            bulk_count,
        );
    }
}

/// Result of a successful FMP decrypt + replay accept that still needs legacy
/// link-message dispatch on rx_loop. Local established FSP data takes the
/// narrower authenticated/direct-data event when the worker can safely decode
/// it first.
#[allow(dead_code)] // fmp_counter / fmp_flags retained for future debug paths
pub(crate) struct DecryptFallback {
    pub source_peer: PeerIdentity,
    /// Transport this packet arrived on — used by rx_loop's bounce
    /// arm to call `peer.set_current_addr()` so address rotation +
    /// MMP link-dead tracking continue to see updates for packets
    /// handled by the worker.
    pub transport_id: TransportId,
    /// Remote transport address — companion to `transport_id`.
    pub remote_addr: TransportAddr,
    pub timestamp_ms: u64,
    /// Length of the wire packet that produced this bounce. Used
    /// by rx_loop to call `peer.link_stats_mut().record_recv()` so
    /// per-peer stats + MMP last-seen + link-dead detection see
    /// progress for worker-handled packets. Without this update,
    /// MMP's 30-second link-dead timer fires even though packets
    /// are arriving fine.
    pub packet_len: usize,
    /// Fallback queue lane selected when the worker creates this completion
    /// event. The fallback sender consumes this queued value instead of
    /// deriving queue policy later from mutable metadata.
    lane: DecryptWorkerLane,
    pub fmp_counter: u64,
    pub fmp_flags: u8,
    /// Original received wire buffer, mutated in place by the FMP
    /// AEAD open. Bytes `[fmp_plaintext_offset ..
    /// fmp_plaintext_offset+fmp_plaintext_len]` are the decrypted
    /// FMP plaintext: a 4-byte session timestamp followed by the
    /// link-layer message (FSP frame when
    /// `phase == FSP_PHASE_ESTABLISHED`). rx_loop slices into this
    /// Vec for FSP decrypt + dispatch and only allocates on the
    /// actual delivery hop.
    ///
    /// **Why packet_data + offset, not `Vec<u8>` of the plaintext:**
    /// the pre-fix bounce did `packet_data[a..b].to_vec()` per
    /// packet, which is one fresh ~1500-byte allocation on every
    /// inbound bulk frame. At 150k pps that's ~225 MB/sec of
    /// memory bandwidth on the worker + rx_loop hot path, and a
    /// per-packet allocator round-trip. Passing the original Vec
    /// through unmodified lets the consumer borrow a slice; zero
    /// alloc, zero memcpy.
    pub packet_data: Vec<u8>,
    pub fmp_plaintext_offset: usize,
    pub fmp_plaintext_len: usize,
    /// Monotonic timestamp captured immediately before the worker queues this
    /// completion back to the rx loop. Used only when pipeline tracing is on.
    pub(crate) trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

impl DecryptFallback {
    #[allow(clippy::too_many_arguments)]
    fn new(
        source_peer: PeerIdentity,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        timestamp_ms: u64,
        packet_len: usize,
        fmp_counter: u64,
        fmp_flags: u8,
        packet_data: Vec<u8>,
        fmp_plaintext_offset: usize,
        fmp_plaintext_len: usize,
    ) -> Self {
        let lane = decrypt_worker_packet_lane(packet_len);
        Self {
            source_peer,
            transport_id,
            remote_addr,
            timestamp_ms,
            packet_len,
            lane,
            fmp_counter,
            fmp_flags,
            packet_data,
            fmp_plaintext_offset,
            fmp_plaintext_len,
            trace_enqueued_at: None,
        }
    }

    fn lane(&self) -> DecryptWorkerLane {
        self.lane
    }
}

/// Report from the decrypt worker when a registered FMP session fails
/// AEAD authentication. Routed back to rx_loop so peer/session recovery
/// decisions stay in one place instead of being silently dropped inside
/// the worker thread.
pub(crate) struct DecryptFailureReport {
    pub source_peer: PeerIdentity,
    pub fmp_counter: u64,
    pub fmp_replay_highest: u64,
    /// Monotonic timestamp captured immediately before the worker queues this
    /// failure report back to the rx loop.
    pub(crate) trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

pub(crate) struct DecryptFmpBookkeeping {
    pub source_peer: PeerIdentity,
    pub transport_id: TransportId,
    pub remote_addr: TransportAddr,
    pub packet_timestamp_ms: u64,
    pub packet_len: usize,
    pub fmp_counter: u64,
    pub inner_timestamp_ms: u32,
    pub fmp_flags: u8,
}

pub(crate) struct DecryptAuthenticatedSession {
    pub fmp: DecryptFmpBookkeeping,
    pub source_addr: NodeAddr,
    pub previous_hop_peer: PeerIdentity,
    pub ce_flag: bool,
    pub message: AuthenticatedSessionMessage,
    pub receive_sync: FspReceiveSync,
    lane: DecryptWorkerLane,
    pub(crate) trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

pub(crate) enum DecryptDirectSessionDelivery {
    Ipv6Packet(Vec<u8>),
    EndpointData(EndpointDataDelivery),
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DecryptDirectSessionDeliverySink {
    tun_tx: Option<TunTx>,
    external_packet_tx: Option<TokioSender<NodeDeliveredPacket>>,
    endpoint_event_tx: Option<EndpointEventSender>,
}

impl DecryptDirectSessionDeliverySink {
    pub(crate) fn new(
        tun_tx: Option<TunTx>,
        external_packet_tx: Option<TokioSender<NodeDeliveredPacket>>,
        endpoint_event_tx: Option<EndpointEventSender>,
    ) -> Self {
        Self {
            tun_tx,
            external_packet_tx,
            endpoint_event_tx,
        }
    }

    fn can_deliver(&self, delivery: &DecryptDirectSessionDelivery) -> bool {
        match delivery {
            DecryptDirectSessionDelivery::EndpointData(_) => self.endpoint_event_tx.is_some(),
            DecryptDirectSessionDelivery::Ipv6Packet(_) => {
                self.external_packet_tx.is_some() || self.tun_tx.is_some()
            }
        }
    }

    fn same_endpoint_event_channel(&self, other: &Self) -> bool {
        match (&self.endpoint_event_tx, &other.endpoint_event_tx) {
            (Some(lhs), Some(rhs)) => lhs.same_channels(rhs),
            (None, None) => true,
            _ => false,
        }
    }

    fn endpoint_event_sender(&self) -> Option<&EndpointEventSender> {
        self.endpoint_event_tx.as_ref()
    }

    fn deliver(
        &self,
        source_addr: NodeAddr,
        source_peer: PeerIdentity,
        ce_flag: bool,
        delivery: DecryptDirectSessionDelivery,
    ) {
        match delivery {
            DecryptDirectSessionDelivery::EndpointData(delivery) => {
                let Some(endpoint_event_tx) = &self.endpoint_event_tx else {
                    return;
                };
                let _t_deliver =
                    crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointDeliver);
                let event = NodeEndpointEvent::Data {
                    source_peer: delivery.source_peer,
                    payload: delivery.payload,
                    queued_at: crate::perf_profile::stamp(),
                };
                if let Err(error) = endpoint_event_tx.send(event) {
                    debug!(error = %error, "Failed to deliver worker-decoded endpoint data");
                }
            }
            DecryptDirectSessionDelivery::Ipv6Packet(mut packet) => {
                if ce_flag {
                    mark_ipv6_ecn_ce(&mut packet);
                }
                if let Some(external_packet_tx) = &self.external_packet_tx {
                    if packet.len() < 40 {
                        return;
                    }
                    let Ok(destination) = FipsAddress::from_slice(&packet[24..40]) else {
                        return;
                    };
                    let delivered = NodeDeliveredPacket {
                        source_node_addr: source_addr,
                        source_npub: Some(source_peer.npub()),
                        destination,
                        packet,
                    };
                    if let Err(error) = external_packet_tx.try_send(delivered) {
                        debug!(error = %error, "Failed to deliver worker-decoded packet to external app sink");
                    }
                    return;
                }
                if let Some(tun_tx) = &self.tun_tx {
                    let _t =
                        crate::perf_profile::Timer::start(crate::perf_profile::Stage::TunWrite);
                    if let Err(error) = tun_tx.send(packet) {
                        debug!(error = %error, "Failed to deliver worker-decoded IPv6 packet to TUN");
                    }
                }
            }
        }
    }
}

struct PendingDirectSessionDelivery {
    sink: DecryptDirectSessionDeliverySink,
    source_addr: NodeAddr,
    source_peer: PeerIdentity,
    ce_flag: bool,
    delivery: DecryptDirectSessionDelivery,
}

impl PendingDirectSessionDelivery {
    fn deliver(self) {
        self.sink.deliver(
            self.source_addr,
            self.source_peer,
            self.ce_flag,
            self.delivery,
        );
    }

    fn is_endpoint_data(&self) -> bool {
        match &self.delivery {
            DecryptDirectSessionDelivery::EndpointData(_) => {
                self.sink.endpoint_event_sender().is_some()
            }
            DecryptDirectSessionDelivery::Ipv6Packet(_) => false,
        }
    }

    fn into_endpoint_data(
        self,
    ) -> Result<(DecryptDirectSessionDeliverySink, EndpointDataDelivery), Self> {
        match self.delivery {
            DecryptDirectSessionDelivery::EndpointData(delivery) => Ok((self.sink, delivery)),
            delivery => Err(Self {
                sink: self.sink,
                source_addr: self.source_addr,
                source_peer: self.source_peer,
                ce_flag: self.ce_flag,
                delivery,
            }),
        }
    }
}

pub(crate) struct DecryptDirectSessionData {
    pub fmp: DecryptFmpBookkeeping,
    pub source_addr: NodeAddr,
    pub previous_hop_peer: PeerIdentity,
    pub ce_flag: bool,
    pub receive_sync: FspReceiveSync,
    pub body_len: usize,
    pub delivery: DecryptDirectSessionDelivery,
    lane: DecryptWorkerLane,
    pub(crate) trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

impl DecryptDirectSessionData {
    #[cfg(test)]
    pub(in crate::node) fn for_test(
        fmp: DecryptFmpBookkeeping,
        source_addr: NodeAddr,
        previous_hop_peer: PeerIdentity,
        ce_flag: bool,
        receive_sync: FspReceiveSync,
        body_len: usize,
        delivery: DecryptDirectSessionDelivery,
    ) -> Self {
        Self {
            fmp,
            source_addr,
            previous_hop_peer,
            ce_flag,
            receive_sync,
            body_len,
            delivery,
            lane: DecryptWorkerLane::Bulk,
            trace_enqueued_at: None,
        }
    }
}

pub(crate) struct DecryptDirectSessionCommit {
    pub fmp: DecryptFmpBookkeeping,
    pub source_addr: NodeAddr,
    pub previous_hop_peer: PeerIdentity,
    pub ce_flag: bool,
    pub receive_sync: FspReceiveSync,
    pub body_len: usize,
    pub delivered_ipv6: bool,
    lane: DecryptWorkerLane,
    pub(crate) trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

impl DecryptDirectSessionCommit {
    #[cfg(test)]
    pub(in crate::node) fn for_test(
        fmp: DecryptFmpBookkeeping,
        source_addr: NodeAddr,
        previous_hop_peer: PeerIdentity,
        ce_flag: bool,
        receive_sync: FspReceiveSync,
        body_len: usize,
        delivered_ipv6: bool,
    ) -> Self {
        Self {
            fmp,
            source_addr,
            previous_hop_peer,
            ce_flag,
            receive_sync,
            body_len,
            delivered_ipv6,
            lane: DecryptWorkerLane::Bulk,
            trace_enqueued_at: None,
        }
    }
}

pub(crate) struct DecryptFspFailureReport {
    pub fmp: DecryptFmpBookkeeping,
    pub source_addr: NodeAddr,
    pub counter: u64,
    pub received_k_bit: bool,
    lane: DecryptWorkerLane,
    pub(crate) trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

/// Event emitted by the decrypt worker to the rx_loop.
pub(crate) enum DecryptWorkerEvent {
    Plaintext(DecryptFallback),
    PlaintextBatch(Vec<DecryptFallback>),
    AuthenticatedSession(DecryptAuthenticatedSession),
    DirectSessionCommit(DecryptDirectSessionCommit),
    DirectSessionCommitBatch(Vec<DecryptDirectSessionCommit>),
    DirectSessionData(DecryptDirectSessionData),
    FspDecryptFailure(DecryptFspFailureReport),
    DecryptFailure(DecryptFailureReport),
}

impl DecryptWorkerEvent {
    fn lane(&self) -> DecryptWorkerLane {
        decrypt_worker_event_lane(self)
    }

    pub(crate) fn packet_count(&self) -> usize {
        match self {
            Self::Plaintext(_) | Self::DecryptFailure(_) => 1,
            Self::AuthenticatedSession(_) => 1,
            Self::DirectSessionCommit(_) => 1,
            Self::DirectSessionCommitBatch(commits) => commits.len(),
            Self::DirectSessionData(_) => 1,
            Self::FspDecryptFailure(_) => 1,
            Self::PlaintextBatch(fallbacks) => fallbacks.len(),
        }
    }

    fn set_trace_enqueued_at(&mut self, queued_at: Option<crate::perf_profile::TraceStamp>) {
        match self {
            Self::Plaintext(fallback) => fallback.trace_enqueued_at = queued_at,
            Self::PlaintextBatch(fallbacks) => {
                for fallback in fallbacks {
                    fallback.trace_enqueued_at = queued_at;
                }
            }
            Self::AuthenticatedSession(session) => session.trace_enqueued_at = queued_at,
            Self::DirectSessionCommit(commit) => commit.trace_enqueued_at = queued_at,
            Self::DirectSessionCommitBatch(commits) => {
                for commit in commits {
                    commit.trace_enqueued_at = queued_at;
                }
            }
            Self::DirectSessionData(direct) => direct.trace_enqueued_at = queued_at,
            Self::FspDecryptFailure(report) => report.trace_enqueued_at = queued_at,
            Self::DecryptFailure(report) => report.trace_enqueued_at = queued_at,
        }
    }

    fn trace_enqueued_at(&self) -> Option<crate::perf_profile::TraceStamp> {
        match self {
            Self::Plaintext(fallback) => fallback.trace_enqueued_at,
            Self::PlaintextBatch(fallbacks) => fallbacks
                .first()
                .and_then(|fallback| fallback.trace_enqueued_at),
            Self::AuthenticatedSession(session) => session.trace_enqueued_at,
            Self::DirectSessionCommit(commit) => commit.trace_enqueued_at,
            Self::DirectSessionCommitBatch(commits) => {
                commits.first().and_then(|commit| commit.trace_enqueued_at)
            }
            Self::DirectSessionData(direct) => direct.trace_enqueued_at,
            Self::FspDecryptFailure(report) => report.trace_enqueued_at,
            Self::DecryptFailure(report) => report.trace_enqueued_at,
        }
    }

    fn queue_wait_stages(
        &self,
    ) -> (
        crate::perf_profile::Stage,
        crate::perf_profile::Stage,
        crate::perf_profile::Stage,
    ) {
        match self {
            Self::AuthenticatedSession(_)
            | Self::DirectSessionCommit(_)
            | Self::DirectSessionCommitBatch(_)
            | Self::DirectSessionData(_) => (
                crate::perf_profile::Stage::DecryptAuthenticatedSessionWait,
                crate::perf_profile::Stage::DecryptAuthenticatedSessionPriorityWait,
                crate::perf_profile::Stage::DecryptAuthenticatedSessionBulkWait,
            ),
            Self::Plaintext(_)
            | Self::PlaintextBatch(_)
            | Self::FspDecryptFailure(_)
            | Self::DecryptFailure(_) => (
                crate::perf_profile::Stage::DecryptFallbackWait,
                crate::perf_profile::Stage::DecryptFallbackPriorityWait,
                crate::perf_profile::Stage::DecryptFallbackBulkWait,
            ),
        }
    }

    pub(crate) fn record_queue_wait(&self) {
        let queued_at = self.trace_enqueued_at();
        if queued_at.is_none() {
            return;
        }
        let count = self.packet_count() as u64;
        let (priority_count, bulk_count) = match self.lane() {
            DecryptWorkerLane::Priority => (count, 0),
            DecryptWorkerLane::Bulk => (0, count),
        };
        let (total_stage, priority_stage, bulk_stage) = self.queue_wait_stages();
        crate::perf_profile::record_since_split_count(
            total_stage,
            priority_stage,
            bulk_stage,
            queued_at,
            count,
            priority_count,
            bulk_count,
        );
    }
}

#[derive(Clone)]
pub(crate) struct DecryptWorkerFallbackSender {
    priority: TokioSender<DecryptWorkerEvent>,
    bulk: TokioSender<DecryptWorkerEvent>,
    bulk_queued_packets: Arc<AtomicUsize>,
    bulk_packet_cap: usize,
}

pub(crate) struct DecryptWorkerFallbackReceivers {
    pub(crate) priority: TokioReceiver<DecryptWorkerEvent>,
    pub(crate) bulk: TokioReceiver<DecryptWorkerEvent>,
    bulk_queued_packets: Arc<AtomicUsize>,
}

pub(crate) fn decrypt_worker_fallback_channels()
-> (DecryptWorkerFallbackSender, DecryptWorkerFallbackReceivers) {
    decrypt_worker_fallback_channels_with_caps(
        fallback_priority_channel_cap(),
        fallback_bulk_channel_cap(),
    )
}

fn decrypt_worker_fallback_channels_with_caps(
    priority_cap: usize,
    bulk_cap: usize,
) -> (DecryptWorkerFallbackSender, DecryptWorkerFallbackReceivers) {
    let (priority_tx, priority_rx) = tokio::sync::mpsc::channel(priority_cap.max(1));
    let (bulk_tx, bulk_rx) = tokio::sync::mpsc::channel(bulk_cap.max(1));
    let bulk_queued_packets = Arc::new(AtomicUsize::new(0));
    (
        DecryptWorkerFallbackSender {
            priority: priority_tx,
            bulk: bulk_tx,
            bulk_queued_packets: Arc::clone(&bulk_queued_packets),
            bulk_packet_cap: bulk_cap.max(1),
        },
        DecryptWorkerFallbackReceivers {
            priority: priority_rx,
            bulk: bulk_rx,
            bulk_queued_packets,
        },
    )
}

impl DecryptWorkerFallbackSender {
    fn same_channels(&self, other: &Self) -> bool {
        self.priority.same_channel(&other.priority)
            && self.bulk.same_channel(&other.bulk)
            && Arc::ptr_eq(&self.bulk_queued_packets, &other.bulk_queued_packets)
            && self.bulk_packet_cap == other.bulk_packet_cap
    }

    fn send(&self, mut event: DecryptWorkerEvent) -> bool {
        let lane = decrypt_worker_event_lane(&event);
        let packet_count = event.packet_count();
        let drop_event = decrypt_worker_event_drop_event(&event, lane);
        event.set_trace_enqueued_at(crate::perf_profile::stamp());
        if matches!(lane, DecryptWorkerLane::Bulk) {
            let Some(previous) = try_reserve_bulk_packets_with_previous(
                &self.bulk_queued_packets,
                self.bulk_packet_cap,
                packet_count,
            ) else {
                record_decrypt_worker_return_drop_count(drop_event, lane, packet_count);
                return false;
            };
            let queued = previous.saturating_add(packet_count);
            if previous < DECRYPT_FALLBACK_BACKLOG_HIGH_WATER
                && queued >= DECRYPT_FALLBACK_BACKLOG_HIGH_WATER
            {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptFallbackBacklogHigh,
                );
            }
        }
        let result = match lane {
            DecryptWorkerLane::Priority => self.priority.try_send(event),
            DecryptWorkerLane::Bulk => self.bulk.try_send(event),
        };
        match result {
            Ok(()) => true,
            Err(TokioTrySendError::Full(_)) => {
                if matches!(lane, DecryptWorkerLane::Bulk) {
                    release_bulk_packets(&self.bulk_queued_packets, packet_count);
                }
                record_decrypt_worker_return_drop_count(drop_event, lane, packet_count);
                false
            }
            Err(TokioTrySendError::Closed(_)) => {
                if matches!(lane, DecryptWorkerLane::Bulk) {
                    release_bulk_packets(&self.bulk_queued_packets, packet_count);
                }
                debug!(
                    ?lane,
                    "decrypt fallback receiver gone; dropping worker event"
                );
                false
            }
        }
    }
}

impl DecryptWorkerFallbackReceivers {
    pub(crate) fn release_dequeued_event(&self, event: &DecryptWorkerEvent) {
        if matches!(event.lane(), DecryptWorkerLane::Bulk) {
            release_bulk_packets(&self.bulk_queued_packets, event.packet_count());
        }
    }

    pub(crate) fn bulk_queued_packets(&self) -> usize {
        self.bulk_queued_packets.load(Ordering::Relaxed)
    }
}

fn decrypt_worker_event_lane(event: &DecryptWorkerEvent) -> DecryptWorkerLane {
    match event {
        DecryptWorkerEvent::Plaintext(fallback) => fallback.lane(),
        DecryptWorkerEvent::PlaintextBatch(_) => DecryptWorkerLane::Bulk,
        DecryptWorkerEvent::AuthenticatedSession(session) => session.lane,
        DecryptWorkerEvent::DirectSessionCommit(commit) => commit.lane,
        DecryptWorkerEvent::DirectSessionCommitBatch(_) => DecryptWorkerLane::Bulk,
        DecryptWorkerEvent::DirectSessionData(direct) => direct.lane,
        DecryptWorkerEvent::FspDecryptFailure(report) => report.lane,
        DecryptWorkerEvent::DecryptFailure(_) => DecryptWorkerLane::Priority,
    }
}

fn decrypt_worker_event_drop_event(
    event: &DecryptWorkerEvent,
    lane: DecryptWorkerLane,
) -> crate::perf_profile::Event {
    match event {
        DecryptWorkerEvent::AuthenticatedSession(_)
        | DecryptWorkerEvent::DirectSessionCommit(_)
        | DecryptWorkerEvent::DirectSessionCommitBatch(_)
        | DecryptWorkerEvent::DirectSessionData(_) => match lane {
            DecryptWorkerLane::Priority => {
                crate::perf_profile::Event::DecryptAuthenticatedSessionPriorityDropped
            }
            DecryptWorkerLane::Bulk => {
                crate::perf_profile::Event::DecryptAuthenticatedSessionBulkDropped
            }
        },
        DecryptWorkerEvent::Plaintext(_)
        | DecryptWorkerEvent::PlaintextBatch(_)
        | DecryptWorkerEvent::FspDecryptFailure(_)
        | DecryptWorkerEvent::DecryptFailure(_) => match lane {
            DecryptWorkerLane::Priority => {
                crate::perf_profile::Event::DecryptFallbackPriorityDropped
            }
            DecryptWorkerLane::Bulk => crate::perf_profile::Event::DecryptFallbackBulkDropped,
        },
    }
}

/// Messages travelling through the per-worker crossbeam channel.
/// `Job` is the per-packet hot path; `RegisterSession` /
/// `UnregisterSession` are control plane events sent at session
/// establishment / teardown.
///
/// The `Job` variant is intentionally much larger than the control
/// variants (it carries the whole packet buffer + cipher clone). The
/// alternative — boxing `Job` — adds a per-packet alloc on the hot
/// path, which is the exact thing this module is designed to avoid.
#[allow(clippy::large_enum_variant)]
enum WorkerMsg {
    Job(DecryptJob),
    FspJob(FspDecryptJob),
    RegisterSession {
        session_key: DecryptSessionKey,
        state: OwnedSessionState,
    },
    RegisterFspSession {
        source_addr: NodeAddr,
        state: OwnedFspSessionState,
    },
    UnregisterSession {
        session_key: DecryptSessionKey,
    },
    UnregisterFspSession {
        source_addr: NodeAddr,
    },
}

#[allow(clippy::large_enum_variant)]
enum DecryptWorkerBulkItem {
    Job(DecryptJob),
    FspJob(FspDecryptJob),
    Batch(Vec<DecryptJob>),
}

impl DecryptWorkerBulkItem {
    fn packet_count(&self) -> usize {
        match self {
            Self::Job(_) | Self::FspJob(_) => 1,
            Self::Batch(jobs) => jobs.len(),
        }
    }
}

struct FspDecryptJob {
    fallback_tx: DecryptWorkerFallbackSender,
    fallback: DecryptFallback,
    local_node_addr: NodeAddr,
    source_addr: NodeAddr,
    previous_hop_peer: PeerIdentity,
    path_mtu: u16,
    ce_flag: bool,
    inner_timestamp_ms: u32,
    fsp_payload_offset: usize,
    fsp_payload_len: usize,
    trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

impl FspDecryptJob {
    fn lane(&self) -> DecryptWorkerLane {
        self.fallback.lane()
    }

    fn set_trace_enqueued_at(&mut self, queued_at: Option<crate::perf_profile::TraceStamp>) {
        self.trace_enqueued_at = queued_at;
    }

    fn record_queue_wait(&self) {
        let queued_at = self.trace_enqueued_at;
        if queued_at.is_none() {
            return;
        }
        let (priority_count, bulk_count) = match self.lane() {
            DecryptWorkerLane::Priority => (1, 0),
            DecryptWorkerLane::Bulk => (0, 1),
        };
        crate::perf_profile::record_since_split_count(
            crate::perf_profile::Stage::DecryptFspWorkerQueueWait,
            crate::perf_profile::Stage::DecryptFspWorkerPriorityQueueWait,
            crate::perf_profile::Stage::DecryptFspWorkerBulkQueueWait,
            queued_at,
            1,
            priority_count,
            bulk_count,
        );
    }
}

struct FspDecryptJobMeta {
    source_addr: NodeAddr,
    path_mtu: u16,
    fsp_payload_offset: usize,
    fsp_payload_len: usize,
}

pub(crate) struct DecryptJobBatcher {
    worker_idx: Option<usize>,
    jobs: Vec<DecryptJob>,
}

impl DecryptJobBatcher {
    pub(crate) fn new() -> Self {
        Self {
            worker_idx: None,
            jobs: Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
        }
    }

    #[cfg(test)]
    fn pending_buffer_ptr(&self) -> *const DecryptJob {
        self.jobs.as_ptr()
    }

    pub(crate) fn push(&mut self, workers: &DecryptWorkerPool, job: DecryptJob) {
        if !job.is_bulk_lane() {
            self.flush(workers);
            workers.dispatch_job(job);
            return;
        }

        let worker_idx = workers.worker_idx_for(job.session_key);
        let batch_max = workers.bulk_batch_packet_max_for(worker_idx);
        if self.worker_idx != Some(worker_idx) || self.jobs.len() >= batch_max {
            self.flush(workers);
        }
        self.worker_idx = Some(worker_idx);
        self.jobs.push(job);

        if self.jobs.len() >= batch_max {
            self.flush(workers);
        }
    }

    pub(crate) fn flush(&mut self, workers: &DecryptWorkerPool) {
        let Some(worker_idx) = self.worker_idx.take() else {
            return;
        };
        if self.jobs.is_empty() {
            return;
        }

        if self.jobs.len() == 1 {
            let job = self.jobs.pop().expect("checked single pending job");
            workers.dispatch_bulk_job(worker_idx, job);
            return;
        }

        let jobs = std::mem::replace(
            &mut self.jobs,
            Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
        );
        workers.dispatch_bulk_job_batch(worker_idx, jobs);
    }
}

/// Handle to the decrypt worker pool. Shard-style: each worker is one
/// OS thread that owns its sessions outright. Dispatch is
/// deterministic on `session_key` so a session always reaches the same
/// shard.
#[derive(Clone)]
pub(crate) struct DecryptWorkerPool {
    senders: Arc<[DecryptWorkerSender]>,
    direct_delivery_sink: DecryptDirectSessionDeliverySink,
}

#[derive(Clone)]
struct DecryptWorkerSender {
    priority: Sender<WorkerMsg>,
    bulk: Sender<DecryptWorkerBulkItem>,
    bulk_queued_packets: Arc<AtomicUsize>,
    bulk_packet_cap: usize,
}

impl DecryptWorkerPool {
    #[cfg(test)]
    pub(crate) fn spawn(n: usize) -> Self {
        Self::spawn_with_direct_delivery_sink(n, DecryptDirectSessionDeliverySink::default())
    }

    pub(crate) fn spawn_with_direct_delivery_sink(
        n: usize,
        direct_delivery_sink: DecryptDirectSessionDeliverySink,
    ) -> Self {
        let n = n.max(1);
        let bulk_channel_cap = bulk_channel_cap();
        let priority_channel_cap = priority_channel_cap();
        let mut senders = Vec::with_capacity(n);
        let mut receivers = Vec::with_capacity(n);
        for _ in 0..n {
            let (priority_tx, priority_rx) = bounded::<WorkerMsg>(priority_channel_cap);
            let (bulk_tx, bulk_rx) = bounded::<DecryptWorkerBulkItem>(bulk_channel_cap);
            let bulk_queued_packets = Arc::new(AtomicUsize::new(0));
            receivers.push((priority_rx, bulk_rx, Arc::clone(&bulk_queued_packets)));
            senders.push(DecryptWorkerSender {
                priority: priority_tx,
                bulk: bulk_tx,
                bulk_queued_packets,
                bulk_packet_cap: bulk_channel_cap,
            });
        }
        let pool = Self {
            senders: senders.into(),
            direct_delivery_sink,
        };
        for (i, (priority_rx, bulk_rx, worker_bulk_queued_packets)) in
            receivers.into_iter().enumerate()
        {
            let worker_pool = pool.clone();
            std::thread::Builder::new()
                .name(format!("fips-decrypt-{i}"))
                .spawn(move || {
                    run_worker(
                        i,
                        worker_pool,
                        priority_rx,
                        bulk_rx,
                        worker_bulk_queued_packets,
                    )
                })
                .expect("failed to spawn fips-decrypt OS thread");
        }
        pool
    }

    /// Stable hash from session key → worker index. Same hash is used
    /// for session registration and per-packet dispatch so packets and
    /// registration arrive at the same shard.
    fn worker_idx_for(&self, session_key: DecryptSessionKey) -> usize {
        (decrypt_session_fast_hash(session_key) as usize) % self.senders.len()
    }

    fn worker_idx_for_fsp(&self, source_addr: &NodeAddr) -> usize {
        (decrypt_fsp_session_fast_hash(source_addr) as usize) % self.senders.len()
    }

    fn bulk_batch_packet_max_for(&self, idx: usize) -> usize {
        self.senders[idx]
            .bulk_packet_cap
            .min(DECRYPT_WORKER_BULK_BATCH_MAX)
            .max(1)
    }

    /// Dispatch a per-packet decrypt job. Drops if the per-worker
    /// channel is full (sustained rate overrun); the rx_loop's drain
    /// caps inbound at the same scale upstream so the cliff is
    /// bounded.
    pub fn dispatch_job(&self, mut job: DecryptJob) {
        if self.senders.is_empty() {
            return;
        }
        job.set_trace_enqueued_at(crate::perf_profile::stamp());
        let idx = self.worker_idx_for(job.session_key);
        match decrypt_job_lane(&job) {
            DecryptWorkerLane::Priority => self.dispatch_priority_job(idx, job),
            DecryptWorkerLane::Bulk => self.dispatch_bulk_job(idx, job),
        }
    }

    fn dispatch_priority_job(&self, idx: usize, job: DecryptJob) {
        match self.senders[idx].priority.try_send(WorkerMsg::Job(job)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                record_decrypt_worker_priority_drop(idx, "packet");
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; dropping priority job"
                );
            }
        }
    }

    fn dispatch_bulk_job(&self, idx: usize, job: DecryptJob) {
        self.dispatch_bulk_item(idx, DecryptWorkerBulkItem::Job(job));
    }

    fn dispatch_fsp_job_or_return(&self, job: FspDecryptJob) -> Result<(), FspDecryptJob> {
        if self.senders.is_empty() {
            return Err(job);
        }
        let idx = self.worker_idx_for_fsp(&job.source_addr);
        match job.lane() {
            DecryptWorkerLane::Priority => self.dispatch_priority_fsp_job_or_return(idx, job),
            DecryptWorkerLane::Bulk => self.dispatch_bulk_fsp_job_or_return(idx, job),
        }
    }

    fn dispatch_priority_fsp_job_or_return(
        &self,
        idx: usize,
        mut job: FspDecryptJob,
    ) -> Result<(), FspDecryptJob> {
        job.set_trace_enqueued_at(crate::perf_profile::stamp());
        match self.senders[idx].priority.try_send(WorkerMsg::FspJob(job)) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(job)) => {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptWorkerQueueFull,
                );
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptFspPriorityQueueFullFallback,
                );
                Err(match job {
                    WorkerMsg::FspJob(job) => job,
                    _ => unreachable!("priority FSP dispatch only sends FSP jobs"),
                })
            }
            Err(TrySendError::Disconnected(job)) => {
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; falling FSP priority job back to rx_loop"
                );
                Err(match job {
                    WorkerMsg::FspJob(job) => job,
                    _ => unreachable!("priority FSP dispatch only sends FSP jobs"),
                })
            }
        }
    }

    fn dispatch_bulk_fsp_job_or_return(
        &self,
        idx: usize,
        mut job: FspDecryptJob,
    ) -> Result<(), FspDecryptJob> {
        job.set_trace_enqueued_at(crate::perf_profile::stamp());
        let sender = &self.senders[idx];
        if !try_reserve_bulk_packets(&sender.bulk_queued_packets, sender.bulk_packet_cap, 1) {
            crate::perf_profile::record_event(crate::perf_profile::Event::DecryptWorkerQueueFull);
            crate::perf_profile::record_event(
                crate::perf_profile::Event::DecryptFspBulkQueueFullFallback,
            );
            return Err(job);
        }

        match sender.bulk.try_send(DecryptWorkerBulkItem::FspJob(job)) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(DecryptWorkerBulkItem::FspJob(job))) => {
                release_bulk_packets(&sender.bulk_queued_packets, 1);
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptWorkerQueueFull,
                );
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptFspBulkQueueFullFallback,
                );
                Err(job)
            }
            Err(TrySendError::Disconnected(DecryptWorkerBulkItem::FspJob(job))) => {
                release_bulk_packets(&sender.bulk_queued_packets, 1);
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; falling FSP bulk job back to rx_loop"
                );
                Err(job)
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                unreachable!("bulk FSP dispatch only sends FSP jobs")
            }
        }
    }

    fn dispatch_bulk_job_batch(&self, idx: usize, mut jobs: Vec<DecryptJob>) {
        debug_assert!(!jobs.is_empty());
        debug_assert!(jobs.len() <= DECRYPT_WORKER_BULK_BATCH_MAX);
        debug_assert!(jobs.iter().all(DecryptJob::is_bulk_lane));

        let queued_at = crate::perf_profile::stamp();
        for job in &mut jobs {
            job.set_trace_enqueued_at(queued_at);
        }

        if jobs.len() == 1 {
            let job = jobs.pop().expect("checked non-empty batch");
            self.dispatch_bulk_job(idx, job);
            return;
        }

        self.dispatch_bulk_item(idx, DecryptWorkerBulkItem::Batch(jobs));
    }

    fn dispatch_bulk_item(&self, idx: usize, item: DecryptWorkerBulkItem) {
        let _ = self.dispatch_bulk_item_or_return(idx, item);
    }

    fn dispatch_bulk_item_or_return(
        &self,
        idx: usize,
        item: DecryptWorkerBulkItem,
    ) -> Result<(), DecryptWorkerBulkItem> {
        let packet_count = item.packet_count();
        let sender = &self.senders[idx];
        if !try_reserve_bulk_packets(
            &sender.bulk_queued_packets,
            sender.bulk_packet_cap,
            packet_count,
        ) {
            record_decrypt_worker_bulk_drop_count(idx, packet_count);
            return Err(item);
        }

        match sender.bulk.try_send(item) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(item)) => {
                release_bulk_packets(&sender.bulk_queued_packets, packet_count);
                record_decrypt_worker_bulk_drop_count(idx, packet_count);
                Err(item)
            }
            Err(TrySendError::Disconnected(item)) => {
                release_bulk_packets(&sender.bulk_queued_packets, packet_count);
                debug!(worker = idx, "DecryptWorker thread gone; dropping bulk job");
                Err(item)
            }
        }
    }

    /// Hand ownership of a session's recv-side FMP state to its assigned
    /// worker. Called when a session is promoted or rekeyed; the worker
    /// thereafter is the sole authority over the FMP replay window and
    /// recv cipher clone for this session.
    ///
    /// Returns `true` iff the registration message was actually
    /// queued. Callers MUST gate any "this session is now worker-
    /// owned" state on the returned bool — the previous version
    /// fire-and-forget'd the `try_send` and the caller unconditionally
    /// marked the session as registered on its side, so under
    /// sustained queue pressure rx_loop believed the worker owned a
    /// session that had never received the cipher + replay state.
    /// Subsequent `dispatch_job` packets then arrived at a worker
    /// shard without that session in its local `HashMap` and were
    /// silently dropped (the "session unregistered mid-flight"
    /// fallback path in `handle_job`). The caller's normal retry —
    /// "re-register on a later event" — is documented at the only
    /// call site (`register_decrypt_worker_session`).
    #[must_use = "registration may have failed under queue pressure; caller must gate its own session-registered flag on the returned bool"]
    pub fn register_session(
        &self,
        session_key: DecryptSessionKey,
        state: OwnedSessionState,
    ) -> bool {
        if self.senders.is_empty() {
            return false;
        }
        let idx = self.worker_idx_for(session_key);
        match self.senders[idx]
            .priority
            .try_send(WorkerMsg::RegisterSession { session_key, state })
        {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptWorkerQueueFull,
                );
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptWorkerRegisterFull,
                );
                warn!(
                    worker = idx,
                    "DecryptWorker channel full at session registration; will retry on next packet"
                );
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; ignoring registration"
                );
                false
            }
        }
    }

    #[must_use = "registration may have failed under queue pressure"]
    pub fn register_fsp_session(
        &self,
        source_addr: NodeAddr,
        state: FspRecvSessionSnapshot,
    ) -> bool {
        if self.senders.is_empty() {
            return false;
        }
        let idx = self.worker_idx_for_fsp(&source_addr);
        let state = OwnedFspSessionState::from(state);
        match self.senders[idx]
            .priority
            .try_send(WorkerMsg::RegisterFspSession { source_addr, state })
        {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptWorkerQueueFull,
                );
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::DecryptWorkerRegisterFull,
                );
                warn!(
                    worker = idx,
                    "DecryptWorker channel full at FSP session registration; rx-loop fallback remains available"
                );
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; ignoring FSP registration"
                );
                false
            }
        }
    }

    pub fn unregister_fsp_session(&self, source_addr: NodeAddr) -> bool {
        if self.senders.is_empty() {
            return false;
        }
        let idx = self.worker_idx_for_fsp(&source_addr);
        match self.senders[idx]
            .priority
            .try_send(WorkerMsg::UnregisterFspSession { source_addr })
        {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                record_decrypt_worker_priority_drop(idx, "unregister-fsp");
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; ignoring FSP unregister"
                );
                false
            }
        }
    }

    /// Drop a session from its worker (rekey, peer removed).
    ///
    /// Returns `true` iff the unregister control message reached the worker's
    /// bounded priority lane. A full priority lane is still non-blocking, but
    /// it records visible pressure instead of silently hiding stale
    /// worker-owned session state.
    pub fn unregister_session(&self, session_key: DecryptSessionKey) -> bool {
        if self.senders.is_empty() {
            return false;
        }
        let idx = self.worker_idx_for(session_key);
        match self.senders[idx]
            .priority
            .try_send(WorkerMsg::UnregisterSession { session_key })
        {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                record_decrypt_worker_priority_drop(idx, "unregister");
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; ignoring unregister"
                );
                false
            }
        }
    }
}

fn record_decrypt_worker_bulk_drop_count(worker: usize, count: usize) {
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DecryptWorkerQueueFull,
        count as u64,
    );
    crate::perf_profile::record_event_count(
        crate::perf_profile::Event::DecryptWorkerBulkDropped,
        count as u64,
    );
    static FULL_COUNT: AtomicU64 = AtomicU64::new(0);
    let n = FULL_COUNT.fetch_add(count as u64, Ordering::Relaxed);
    if n < 8 || n.is_multiple_of(10000) {
        warn!(
            worker,
            drops = n + count as u64,
            dropped = count,
            "DecryptWorker bulk channel full; dropping inbound packets"
        );
    }
}

fn try_reserve_bulk_packets_with_previous(
    counter: &AtomicUsize,
    capacity: usize,
    count: usize,
) -> Option<usize> {
    if count == 0 {
        return Some(counter.load(Ordering::Relaxed));
    }

    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(count).filter(|next| *next <= capacity)
        })
        .ok()
}

fn try_reserve_bulk_packets(counter: &AtomicUsize, capacity: usize, count: usize) -> bool {
    try_reserve_bulk_packets_with_previous(counter, capacity, count).is_some()
}

fn release_bulk_packets(counter: &AtomicUsize, count: usize) {
    if count == 0 {
        return;
    }

    let previous = counter.fetch_sub(count, Ordering::Relaxed);
    debug_assert!(
        previous >= count,
        "decrypt worker bulk job accounting underflow: previous={previous}, release={count}"
    );
}

fn record_decrypt_worker_priority_drop(worker: usize, kind: &'static str) {
    crate::perf_profile::record_event(crate::perf_profile::Event::DecryptWorkerQueueFull);
    crate::perf_profile::record_event(crate::perf_profile::Event::DecryptWorkerPriorityDropped);
    static FULL_COUNT: AtomicU64 = AtomicU64::new(0);
    let n = FULL_COUNT.fetch_add(1, Ordering::Relaxed);
    if n < 8 || n.is_multiple_of(10000) {
        warn!(
            worker,
            kind,
            drops = n + 1,
            "DecryptWorker priority channel full; dropping inbound item"
        );
    }
}

fn record_decrypt_worker_return_drop_count(
    event: crate::perf_profile::Event,
    lane: DecryptWorkerLane,
    count: usize,
) {
    crate::perf_profile::record_event_count(event, count as u64);
    static FULL_COUNT: AtomicU64 = AtomicU64::new(0);
    let n = FULL_COUNT.fetch_add(count as u64, Ordering::Relaxed);
    if n < 8 || n.is_multiple_of(10000) {
        warn!(
            ?lane,
            drops = n + count as u64,
            dropped = count,
            "DecryptWorker return channel full; dropping worker event"
        );
    }
}

fn run_worker(
    idx: usize,
    pool: DecryptWorkerPool,
    priority_rx: Receiver<WorkerMsg>,
    bulk_rx: Receiver<DecryptWorkerBulkItem>,
    bulk_queued_packets: Arc<AtomicUsize>,
) {
    trace!(worker = idx, "FMP+FSP decrypt worker thread starting");

    let mut shard = DecryptWorkerShard::new(pool);

    loop {
        drain_worker_queues(
            idx,
            &mut shard,
            &priority_rx,
            &bulk_rx,
            &bulk_queued_packets,
        );
        crossbeam_channel::select! {
            recv(priority_rx) -> msg => {
                match msg {
                    Ok(msg) => shard.handle_msg(idx, msg),
                    Err(_) => {
                        drain_worker_queues(idx, &mut shard, &priority_rx, &bulk_rx, &bulk_queued_packets);
                        break;
                    }
                }
            }
            recv(bulk_rx) -> item => {
                match item {
                    Ok(item) => {
                        release_bulk_packets(&bulk_queued_packets, item.packet_count());
                        let mut plaintext_batch = DecryptPlaintextFallbackBatch::new();
                        handle_bulk_item(idx, &mut shard, &priority_rx, item, &mut plaintext_batch);
                        plaintext_batch.flush();
                    }
                    Err(_) => {
                        drain_worker_queues(idx, &mut shard, &priority_rx, &bulk_rx, &bulk_queued_packets);
                        break;
                    }
                }
            }
        }
    }
    trace!(worker = idx, "FMP+FSP decrypt worker thread exiting");
}

fn drain_worker_queues(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    priority_rx: &Receiver<WorkerMsg>,
    bulk_rx: &Receiver<DecryptWorkerBulkItem>,
    bulk_queued_packets: &AtomicUsize,
) {
    while let Ok(msg) = priority_rx.try_recv() {
        shard.handle_msg(idx, msg);
    }
    let mut drained_bulk_jobs = 0;
    let mut plaintext_batch = DecryptPlaintextFallbackBatch::new();
    while drained_bulk_jobs < DECRYPT_WORKER_BULK_BURST_BUDGET {
        if let Ok(msg) = priority_rx.try_recv() {
            plaintext_batch.flush();
            shard.handle_msg(idx, msg);
            continue;
        }
        match bulk_rx.try_recv() {
            Ok(item) => {
                release_bulk_packets(bulk_queued_packets, item.packet_count());
                drained_bulk_jobs +=
                    handle_bulk_item(idx, shard, priority_rx, item, &mut plaintext_batch);
            }
            Err(_) => break,
        }
    }
    plaintext_batch.flush();
}

fn handle_bulk_item(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    priority_rx: &Receiver<WorkerMsg>,
    item: DecryptWorkerBulkItem,
    plaintext_batch: &mut DecryptPlaintextFallbackBatch,
) -> usize {
    match item {
        DecryptWorkerBulkItem::Job(job) => {
            shard.handle_bulk_job_msg(idx, job, plaintext_batch);
            1
        }
        DecryptWorkerBulkItem::FspJob(job) => {
            shard.handle_bulk_fsp_job_msg(idx, job, plaintext_batch);
            1
        }
        DecryptWorkerBulkItem::Batch(jobs) => {
            let count = jobs.len();
            for job in jobs {
                while let Ok(msg) = priority_rx.try_recv() {
                    plaintext_batch.flush();
                    shard.handle_msg(idx, msg);
                }
                shard.handle_bulk_job_msg(idx, job, plaintext_batch);
            }
            count
        }
    }
}

struct DecryptWorkerOutput {
    fallback_tx: DecryptWorkerFallbackSender,
    event: DecryptWorkerEvent,
    direct_delivery: Option<PendingDirectSessionDelivery>,
}

impl DecryptWorkerOutput {
    fn send(mut self) -> bool {
        let direct_delivery = self.direct_delivery.take();
        if !self.fallback_tx.send(self.event) {
            return false;
        }
        if let Some(delivery) = direct_delivery {
            delivery.deliver();
        }
        true
    }

    fn is_batchable_bulk_plaintext(&self) -> bool {
        matches!(
            &self.event,
            DecryptWorkerEvent::Plaintext(fallback)
                if matches!(fallback.lane(), DecryptWorkerLane::Bulk)
        )
    }

    fn is_batchable_direct_endpoint(&self) -> bool {
        matches!(
            (&self.event, &self.direct_delivery),
            (
                DecryptWorkerEvent::DirectSessionCommit(commit),
                Some(delivery),
            ) if matches!(commit.lane, DecryptWorkerLane::Bulk) && delivery.is_endpoint_data()
        )
    }
}

struct DecryptPlaintextFallbackBatch {
    fallback_tx: Option<DecryptWorkerFallbackSender>,
    fallbacks: Vec<DecryptFallback>,
    endpoint_fallback_tx: Option<DecryptWorkerFallbackSender>,
    endpoint_sink: Option<DecryptDirectSessionDeliverySink>,
    endpoint_commits: Vec<DecryptDirectSessionCommit>,
    endpoint_deliveries: Vec<EndpointDataDelivery>,
}

impl DecryptPlaintextFallbackBatch {
    fn new() -> Self {
        Self {
            fallback_tx: None,
            fallbacks: Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
            endpoint_fallback_tx: None,
            endpoint_sink: None,
            endpoint_commits: Vec::with_capacity(DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX),
            endpoint_deliveries: Vec::with_capacity(DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX),
        }
    }

    fn batch_max_for(fallback_tx: &DecryptWorkerFallbackSender) -> usize {
        fallback_tx
            .bulk_packet_cap
            .min(DECRYPT_WORKER_BULK_BATCH_MAX)
            .max(1)
    }

    fn endpoint_batch_max_for(fallback_tx: &DecryptWorkerFallbackSender) -> usize {
        fallback_tx
            .bulk_packet_cap
            .min(DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX)
            .max(1)
    }

    fn push_output(&mut self, output: DecryptWorkerOutput) {
        if output.is_batchable_bulk_plaintext() {
            self.flush_endpoint();
            let DecryptWorkerOutput {
                fallback_tx,
                event,
                direct_delivery,
            } = output;
            debug_assert!(direct_delivery.is_none());
            let DecryptWorkerEvent::Plaintext(fallback) = event else {
                unreachable!("checked batchable plaintext output")
            };
            if self
                .fallback_tx
                .as_ref()
                .is_some_and(|current| !current.same_channels(&fallback_tx))
            {
                self.flush();
            }
            if self.fallback_tx.is_none() {
                self.fallback_tx = Some(fallback_tx);
            }
            let batch_max = Self::batch_max_for(
                self.fallback_tx
                    .as_ref()
                    .expect("fallback sender set before batching plaintext"),
            );
            self.fallbacks.push(fallback);
            if self.fallbacks.len() >= batch_max {
                self.flush();
            }
            return;
        }
        if output.is_batchable_direct_endpoint() {
            self.flush_plaintext();
            let DecryptWorkerOutput {
                fallback_tx,
                event,
                direct_delivery,
            } = output;
            let DecryptWorkerEvent::DirectSessionCommit(commit) = event else {
                unreachable!("checked batchable direct endpoint commit output")
            };
            let Some(direct_delivery) = direct_delivery else {
                unreachable!("checked batchable direct endpoint delivery")
            };
            let Ok((sink, delivery)) = direct_delivery.into_endpoint_data() else {
                unreachable!("checked batchable endpoint delivery")
            };

            let same_fallback = self
                .endpoint_fallback_tx
                .as_ref()
                .map_or(true, |current| current.same_channels(&fallback_tx));
            let same_endpoint = self
                .endpoint_sink
                .as_ref()
                .map_or(true, |current| current.same_endpoint_event_channel(&sink));
            if !same_fallback || !same_endpoint {
                self.flush_endpoint();
            }
            if self.endpoint_fallback_tx.is_none() {
                self.endpoint_fallback_tx = Some(fallback_tx);
            }
            if self.endpoint_sink.is_none() {
                self.endpoint_sink = Some(sink);
            }
            let batch_max = Self::endpoint_batch_max_for(
                self.endpoint_fallback_tx
                    .as_ref()
                    .expect("fallback sender set before batching direct endpoint completions"),
            );
            self.endpoint_commits.push(commit);
            self.endpoint_deliveries.push(delivery);
            if self.endpoint_commits.len() >= batch_max {
                self.flush_endpoint();
            }
            return;
        }
        self.flush();
        let _ = output.send();
    }

    fn flush(&mut self) {
        self.flush_plaintext();
        self.flush_endpoint();
    }

    fn flush_plaintext(&mut self) {
        if self.fallbacks.is_empty() {
            return;
        }
        let Some(fallback_tx) = self.fallback_tx.take() else {
            return;
        };
        let event = if self.fallbacks.len() == 1 {
            DecryptWorkerEvent::Plaintext(self.fallbacks.pop().expect("checked single fallback"))
        } else {
            let fallbacks = std::mem::replace(
                &mut self.fallbacks,
                Vec::with_capacity(DECRYPT_WORKER_BULK_BATCH_MAX),
            );
            DecryptWorkerEvent::PlaintextBatch(fallbacks)
        };
        let _ = fallback_tx.send(event);
    }

    fn flush_endpoint(&mut self) {
        if self.endpoint_commits.is_empty() {
            return;
        }
        let Some(fallback_tx) = self.endpoint_fallback_tx.take() else {
            return;
        };
        let Some(sink) = self.endpoint_sink.take() else {
            self.endpoint_commits.clear();
            self.endpoint_deliveries.clear();
            return;
        };
        let Some(endpoint_event_tx) = sink.endpoint_event_sender().cloned() else {
            self.endpoint_commits.clear();
            self.endpoint_deliveries.clear();
            return;
        };

        let event = if self.endpoint_commits.len() == 1 {
            DecryptWorkerEvent::DirectSessionCommit(
                self.endpoint_commits
                    .pop()
                    .expect("checked single direct endpoint commit"),
            )
        } else {
            let commits = std::mem::replace(
                &mut self.endpoint_commits,
                Vec::with_capacity(DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX),
            );
            DecryptWorkerEvent::DirectSessionCommitBatch(commits)
        };

        if !fallback_tx.send(event) {
            self.endpoint_deliveries.clear();
            return;
        }

        let count = self.endpoint_deliveries.len();
        if count == 0 {
            return;
        }
        let queued_at = crate::perf_profile::stamp();
        let endpoint_event = if count == 1 {
            let delivery = self
                .endpoint_deliveries
                .pop()
                .expect("checked single endpoint delivery");
            NodeEndpointEvent::Data {
                source_peer: delivery.source_peer,
                payload: delivery.payload,
                queued_at,
            }
        } else {
            let messages = std::mem::replace(
                &mut self.endpoint_deliveries,
                Vec::with_capacity(DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX),
            );
            NodeEndpointEvent::DataBatch {
                messages,
                queued_at,
            }
        };
        let _t_deliver =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointDeliver);
        if let Err(error) = endpoint_event_tx.send(endpoint_event) {
            debug!(
                error = %error,
                messages = count,
                "Failed to deliver worker-decoded endpoint data batch"
            );
        }
    }
}

struct DecryptWorkerShard {
    pool: DecryptWorkerPool,
    // Lives entirely on this OS thread — never observed by any other thread.
    sessions: HashMap<DecryptSessionKey, OwnedSessionState>,
    fsp_sessions: HashMap<NodeAddr, OwnedFspSessionState>,
}

impl DecryptWorkerShard {
    fn new(pool: DecryptWorkerPool) -> Self {
        Self {
            pool,
            sessions: HashMap::new(),
            fsp_sessions: HashMap::new(),
        }
    }

    fn handle_msg(&mut self, idx: usize, msg: WorkerMsg) {
        match msg {
            WorkerMsg::Job(job) => {
                self.handle_job_msg(idx, job);
            }
            WorkerMsg::FspJob(job) => {
                self.handle_fsp_job_msg(idx, job);
            }
            WorkerMsg::RegisterSession { session_key, state } => {
                self.register_session(idx, session_key, state);
            }
            WorkerMsg::RegisterFspSession { source_addr, state } => {
                self.register_fsp_session(idx, source_addr, state);
            }
            WorkerMsg::UnregisterSession { session_key } => {
                self.unregister_session(idx, session_key);
            }
            WorkerMsg::UnregisterFspSession { source_addr } => {
                self.unregister_fsp_session(idx, source_addr);
            }
        }
    }

    fn handle_job_msg(&mut self, idx: usize, job: DecryptJob) {
        match self.handle_job_output(idx, job) {
            Ok(Some(output)) => {
                let _ = output.send();
            }
            Ok(None) => {}
            Err(err) => {
                debug!(worker = idx, error = %err, "decrypt worker job failed");
            }
        }
    }

    fn handle_bulk_job_msg(
        &mut self,
        idx: usize,
        job: DecryptJob,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        match self.handle_job_output(idx, job) {
            Ok(Some(output)) => plaintext_batch.push_output(output),
            Ok(None) => {}
            Err(err) => {
                debug!(worker = idx, error = %err, "decrypt worker job failed");
            }
        }
    }

    fn handle_fsp_job_msg(&mut self, idx: usize, job: FspDecryptJob) {
        job.record_queue_wait();
        match self.handle_fsp_job_output(job) {
            Some(output) => {
                let _ = output.send();
            }
            None => {}
        }
        trace!(worker = idx, "processed FSP decrypt worker job");
    }

    fn handle_bulk_fsp_job_msg(
        &mut self,
        idx: usize,
        job: FspDecryptJob,
        plaintext_batch: &mut DecryptPlaintextFallbackBatch,
    ) {
        job.record_queue_wait();
        match self.handle_fsp_job_output(job) {
            Some(output) => plaintext_batch.push_output(output),
            None => {}
        }
        trace!(worker = idx, "processed bulk FSP decrypt worker job");
    }

    fn register_session(
        &mut self,
        idx: usize,
        session_key: DecryptSessionKey,
        state: OwnedSessionState,
    ) {
        trace!(
            worker = idx,
            ?session_key,
            "DecryptWorker: register session"
        );
        self.sessions.insert(session_key, state);
    }

    fn unregister_session(&mut self, idx: usize, session_key: DecryptSessionKey) {
        trace!(
            worker = idx,
            ?session_key,
            "DecryptWorker: unregister session"
        );
        self.sessions.remove(&session_key);
    }

    fn register_fsp_session(
        &mut self,
        idx: usize,
        source_addr: NodeAddr,
        state: OwnedFspSessionState,
    ) {
        trace!(
            worker = idx,
            %source_addr,
            "DecryptWorker: register FSP session"
        );
        self.fsp_sessions.insert(source_addr, state);
    }

    fn unregister_fsp_session(&mut self, idx: usize, source_addr: NodeAddr) {
        trace!(
            worker = idx,
            %source_addr,
            "DecryptWorker: unregister FSP session"
        );
        self.fsp_sessions.remove(&source_addr);
    }

    #[cfg(test)]
    fn handle_job(
        &mut self,
        job: DecryptJob,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(output) = self.handle_job_output(0, job)? {
            let _ = output.send();
        }
        Ok(())
    }

    fn local_established_fsp_meta(
        packet_data: &[u8],
        local_node_addr: NodeAddr,
        link_msg_start: usize,
        link_msg_end: usize,
    ) -> Option<FspDecryptJobMeta> {
        let link_msg = packet_data.get(link_msg_start..link_msg_end)?;
        let (&msg_type, datagram_payload) = link_msg.split_first()?;
        if msg_type != LinkMessageType::SessionDatagram.to_byte() {
            return None;
        }
        let datagram = SessionDatagramRef::decode(datagram_payload).ok()?;
        if datagram.ttl == 0 || datagram.dest_addr != local_node_addr {
            return None;
        }
        let prefix = FspCommonPrefix::parse(datagram.payload)?;
        if prefix.phase != FSP_PHASE_ESTABLISHED || prefix.is_unencrypted() || prefix.has_coords() {
            return None;
        }
        let fsp_payload_offset = link_msg_start + 1 + SessionDatagramRef::HEADER_LEN;
        Some(FspDecryptJobMeta {
            source_addr: datagram.src_addr,
            path_mtu: datagram.path_mtu,
            fsp_payload_offset,
            fsp_payload_len: datagram.payload.len(),
        })
    }

    fn direct_session_delivery_from_message(
        source_addr: NodeAddr,
        local_node_addr: NodeAddr,
        message: AuthenticatedSessionMessage,
    ) -> Result<DecryptDirectSessionDelivery, AuthenticatedSessionMessage> {
        match SessionMessageType::from_byte(message.msg_type()) {
            Some(SessionMessageType::EndpointData) => Ok(
                DecryptDirectSessionDelivery::EndpointData(message.into_endpoint_data_delivery()),
            ),
            Some(SessionMessageType::DataPacket) => {
                let body = message.body();
                if body.len() < FSP_PORT_HEADER_SIZE {
                    return Err(message);
                }
                let dst_port = u16::from_le_bytes([body[2], body[3]]);
                if dst_port != FSP_PORT_IPV6_SHIM {
                    return Err(message);
                }

                let src_ipv6 = FipsAddress::from_node_addr(&source_addr).to_ipv6().octets();
                let dst_ipv6 = FipsAddress::from_node_addr(&local_node_addr)
                    .to_ipv6()
                    .octets();
                let Some(packet) = crate::upper::ipv6_shim::decompress_ipv6(
                    &body[FSP_PORT_HEADER_SIZE..],
                    src_ipv6,
                    dst_ipv6,
                ) else {
                    return Err(message);
                };
                Ok(DecryptDirectSessionDelivery::Ipv6Packet(packet))
            }
            _ => Err(message),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn direct_session_event(
        sink: &DecryptDirectSessionDeliverySink,
        fmp: DecryptFmpBookkeeping,
        source_addr: NodeAddr,
        previous_hop_peer: PeerIdentity,
        ce_flag: bool,
        body_len: usize,
        delivery: DecryptDirectSessionDelivery,
        receive_sync: FspReceiveSync,
        lane: DecryptWorkerLane,
    ) -> (DecryptWorkerEvent, Option<PendingDirectSessionDelivery>) {
        let source_peer = match &delivery {
            DecryptDirectSessionDelivery::EndpointData(delivery) => delivery.source_peer,
            DecryptDirectSessionDelivery::Ipv6Packet(_) => fmp.source_peer,
        };
        let direct_hop = previous_hop_peer.node_addr() == &source_addr;
        let delivered_ipv6 = matches!(delivery, DecryptDirectSessionDelivery::Ipv6Packet(_));
        if direct_hop && sink.can_deliver(&delivery) {
            return (
                DecryptWorkerEvent::DirectSessionCommit(DecryptDirectSessionCommit {
                    fmp,
                    source_addr,
                    previous_hop_peer,
                    ce_flag,
                    receive_sync,
                    body_len,
                    delivered_ipv6,
                    lane,
                    trace_enqueued_at: None,
                }),
                Some(PendingDirectSessionDelivery {
                    sink: sink.clone(),
                    source_addr,
                    source_peer,
                    ce_flag,
                    delivery,
                }),
            );
        }

        (
            DecryptWorkerEvent::DirectSessionData(DecryptDirectSessionData {
                fmp,
                source_addr,
                previous_hop_peer,
                ce_flag,
                receive_sync,
                body_len,
                delivery,
                lane,
                trace_enqueued_at: None,
            }),
            None,
        )
    }

    fn dispatch_or_handle_fsp_job(
        &mut self,
        idx: usize,
        job: FspDecryptJob,
    ) -> Option<DecryptWorkerOutput> {
        if self.pool.worker_idx_for_fsp(&job.source_addr) == idx {
            return self.handle_fsp_job_output(job);
        }
        match self.pool.dispatch_fsp_job_or_return(job) {
            Ok(()) => None,
            Err(job) => Some(DecryptWorkerOutput {
                fallback_tx: job.fallback_tx,
                event: DecryptWorkerEvent::Plaintext(job.fallback),
                direct_delivery: None,
            }),
        }
    }

    fn handle_fsp_job_output(&mut self, job: FspDecryptJob) -> Option<DecryptWorkerOutput> {
        let FspDecryptJob {
            fallback_tx,
            mut fallback,
            local_node_addr,
            source_addr,
            previous_hop_peer,
            path_mtu,
            ce_flag,
            inner_timestamp_ms,
            fsp_payload_offset,
            fsp_payload_len,
            trace_enqueued_at: _,
        } = job;

        let Some(state) = self.fsp_sessions.get_mut(&source_addr) else {
            return Some(DecryptWorkerOutput {
                fallback_tx,
                event: DecryptWorkerEvent::Plaintext(fallback),
                direct_delivery: None,
            });
        };
        let payload_end = fsp_payload_offset.saturating_add(fsp_payload_len);
        let header = {
            let Some(payload) = fallback.packet_data.get(fsp_payload_offset..payload_end) else {
                return Some(DecryptWorkerOutput {
                    fallback_tx,
                    event: DecryptWorkerEvent::Plaintext(fallback),
                    direct_delivery: None,
                });
            };
            let Some(header) = FspEncryptedHeader::parse(payload) else {
                return Some(DecryptWorkerOutput {
                    fallback_tx,
                    event: DecryptWorkerEvent::Plaintext(fallback),
                    direct_delivery: None,
                });
            };
            header
        };
        let lane = fallback.lane();
        let fmp = DecryptFmpBookkeeping {
            source_peer: fallback.source_peer,
            transport_id: fallback.transport_id,
            remote_addr: fallback.remote_addr.clone(),
            packet_timestamp_ms: fallback.timestamp_ms,
            packet_len: fallback.packet_len,
            fmp_counter: fallback.fmp_counter,
            inner_timestamp_ms,
            fmp_flags: fallback.fmp_flags,
        };

        if state.has_single_current_epoch() {
            let ciphertext_offset = fsp_payload_offset + FSP_HEADER_SIZE;
            let Some(ciphertext) = fallback.packet_data.get_mut(ciphertext_offset..payload_end)
            else {
                return Some(DecryptWorkerOutput {
                    fallback_tx,
                    event: DecryptWorkerEvent::Plaintext(fallback),
                    direct_delivery: None,
                });
            };
            let received_k_bit = header.flags & FSP_FLAG_K != 0;
            let FspOpenInPlaceSuccess {
                plaintext_len,
                slot,
            } = match state.open_current_established_frame_in_place(&header, ciphertext) {
                Ok(success) => success,
                Err(FspOpenError::Replay) => {
                    crate::perf_profile::record_event(
                        crate::perf_profile::Event::DecryptFspWorkerReplayDropped,
                    );
                    return None;
                }
                Err(FspOpenError::Aead) => {
                    return Some(DecryptWorkerOutput {
                        fallback_tx,
                        event: DecryptWorkerEvent::FspDecryptFailure(DecryptFspFailureReport {
                            fmp,
                            source_addr,
                            counter: header.counter,
                            received_k_bit,
                            lane,
                            trace_enqueued_at: None,
                        }),
                        direct_delivery: None,
                    });
                }
            };
            let Some(plaintext) = fallback
                .packet_data
                .get(ciphertext_offset..ciphertext_offset + plaintext_len)
            else {
                return None;
            };
            let Some((timestamp, msg_type, inner_flags_byte, _body)) =
                fsp_strip_inner_header(plaintext)
            else {
                return None;
            };
            let spin_bit = inner_flags_byte & 0x01 != 0;
            let sync = FspReceiveSync {
                counter: header.counter,
                slot,
                received_k_bit,
                timestamp,
                plaintext_len,
                ce_flag,
                path_mtu,
                spin_bit,
            };
            let message = AuthenticatedSessionMessage::from_buffer(
                state.source_peer,
                fallback.packet_data,
                ciphertext_offset,
                plaintext_len,
                msg_type,
                inner_flags_byte,
                timestamp,
            );
            let body_len = message.body_len();

            let event = match Self::direct_session_delivery_from_message(
                source_addr,
                local_node_addr,
                message,
            ) {
                Ok(delivery) => {
                    let (event, direct_delivery) = Self::direct_session_event(
                        &self.pool.direct_delivery_sink,
                        fmp,
                        source_addr,
                        previous_hop_peer,
                        ce_flag,
                        body_len,
                        delivery,
                        sync,
                        lane,
                    );
                    return Some(DecryptWorkerOutput {
                        fallback_tx,
                        event,
                        direct_delivery,
                    });
                }
                Err(message) => {
                    DecryptWorkerEvent::AuthenticatedSession(DecryptAuthenticatedSession {
                        fmp,
                        source_addr,
                        previous_hop_peer,
                        ce_flag,
                        message,
                        receive_sync: sync,
                        lane,
                        trace_enqueued_at: None,
                    })
                }
            };

            return Some(DecryptWorkerOutput {
                fallback_tx,
                event,
                direct_delivery: None,
            });
        }

        let Some(payload) = fallback.packet_data.get(fsp_payload_offset..payload_end) else {
            return Some(DecryptWorkerOutput {
                fallback_tx,
                event: DecryptWorkerEvent::Plaintext(fallback),
                direct_delivery: None,
            });
        };
        let ciphertext = &payload[FSP_HEADER_SIZE..];
        let received_k_bit = header.flags & FSP_FLAG_K != 0;
        let FspOpenSuccess { plaintext, slot } =
            match state.open_established_frame(&header, ciphertext) {
                Ok(success) => success,
                Err(FspOpenError::Replay) => {
                    crate::perf_profile::record_event(
                        crate::perf_profile::Event::DecryptFspWorkerReplayDropped,
                    );
                    return None;
                }
                Err(FspOpenError::Aead) => {
                    return Some(DecryptWorkerOutput {
                        fallback_tx,
                        event: DecryptWorkerEvent::Plaintext(fallback),
                        direct_delivery: None,
                    });
                }
            };
        let Some((timestamp, msg_type, inner_flags_byte, _body)) =
            fsp_strip_inner_header(&plaintext)
        else {
            return None;
        };
        let spin_bit = inner_flags_byte & 0x01 != 0;
        let plaintext_len = plaintext.len();
        let lane = fallback.lane();
        let sync = FspReceiveSync {
            counter: header.counter,
            slot,
            received_k_bit,
            timestamp,
            plaintext_len,
            ce_flag,
            path_mtu,
            spin_bit,
        };
        let message = AuthenticatedSessionMessage::new(
            state.source_peer,
            plaintext,
            msg_type,
            inner_flags_byte,
            timestamp,
        );
        let body_len = message.body_len();

        let event =
            match Self::direct_session_delivery_from_message(source_addr, local_node_addr, message)
            {
                Ok(delivery) => {
                    let (event, direct_delivery) = Self::direct_session_event(
                        &self.pool.direct_delivery_sink,
                        fmp,
                        source_addr,
                        previous_hop_peer,
                        ce_flag,
                        body_len,
                        delivery,
                        sync,
                        lane,
                    );
                    return Some(DecryptWorkerOutput {
                        fallback_tx,
                        event,
                        direct_delivery,
                    });
                }
                Err(message) => {
                    DecryptWorkerEvent::AuthenticatedSession(DecryptAuthenticatedSession {
                        fmp,
                        source_addr,
                        previous_hop_peer,
                        ce_flag,
                        message,
                        receive_sync: sync,
                        lane,
                        trace_enqueued_at: None,
                    })
                }
            };

        Some(DecryptWorkerOutput {
            fallback_tx,
            event,
            direct_delivery: None,
        })
    }

    fn handle_job_output(
        &mut self,
        idx: usize,
        job: DecryptJob,
    ) -> Result<Option<DecryptWorkerOutput>, Box<dyn std::error::Error + Send + Sync>> {
        job.record_queue_wait();
        let DecryptJob {
            mut packet_data,
            lane: _,
            session_key,
            _transport_id: transport_id,
            _remote_addr: remote_addr,
            local_node_addr,
            timestamp_ms,
            fmp_counter,
            fmp_flags,
            fmp_header,
            fmp_ciphertext_offset,
            fallback_tx,
            trace_enqueued_at: _,
        } = job;
        // Capture the wire packet length BEFORE decrypt mutates the
        // buffer — it'll be the same number either way (in-place AEAD
        // open doesn't change Vec::len), but documenting the intent.
        let packet_len = packet_data.len();

        // Look up the shard-owned session state. If absent (session not
        // yet registered, or unregistered mid-flight), drop. The caller only
        // marks a session worker-owned after registration is accepted, so an
        // absent session here is stale in-flight work, not a fallback path.
        let state = match self.sessions.get_mut(&session_key) {
            Some(s) => s,
            None => {
                let _ = fallback_tx; // explicitly ignore — drop path
                let _ = packet_data;
                return Ok(None);
            }
        };
        let source_peer = state.source_peer;

        // === Phase 1: FMP decrypt ===
        let _t_fmp = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpDecrypt);

        // **Direct &mut access** to shard-owned cipher + replay state — no
        // Arc<Mutex> lock acquire and no split-brain replay owner. Replays are
        // dropped before AEAD work; successful AEAD is the only path that
        // accepts the counter into the replay window.
        let plaintext_len = match state.open_fmp_in_place(
            &mut packet_data,
            fmp_ciphertext_offset,
            fmp_counter,
            &fmp_header,
        ) {
            Ok(outcome) => outcome.plaintext_len,
            Err(FmpOpenError::Replay) => return Ok(None),
            Err(FmpOpenError::Aead { fmp_replay_highest }) => {
                return Ok(Some(DecryptWorkerOutput {
                    fallback_tx,
                    event: DecryptWorkerEvent::DecryptFailure(DecryptFailureReport {
                        source_peer,
                        fmp_counter,
                        fmp_replay_highest,
                        trace_enqueued_at: None,
                    }),
                    direct_delivery: None,
                }));
            }
        };
        drop(_t_fmp);

        // The FMP plaintext lives in packet_data[fmp_ciphertext_offset..
        // fmp_ciphertext_offset + plaintext_len]. It carries a 4-byte
        // session-relative timestamp prefix, then the link-layer message.
        let fmp_plaintext_start = fmp_ciphertext_offset;
        let fmp_plaintext_end = fmp_ciphertext_offset + plaintext_len;
        const INNER_TIMESTAMP_LEN: usize = 4;
        if plaintext_len < INNER_TIMESTAMP_LEN + 1 {
            return Ok(None);
        }
        let link_msg_start = fmp_plaintext_start + INNER_TIMESTAMP_LEN;
        let link_msg_end = fmp_plaintext_end;

        let inner_timestamp_ms = u32::from_le_bytes([
            packet_data[fmp_plaintext_start],
            packet_data[fmp_plaintext_start + 1],
            packet_data[fmp_plaintext_start + 2],
            packet_data[fmp_plaintext_start + 3],
        ]);
        let fsp_meta = Self::local_established_fsp_meta(
            &packet_data,
            local_node_addr,
            link_msg_start,
            link_msg_end,
        );

        // Pass the buffer through by ownership + offset/length. No FMP-layer
        // allocation; rx_loop or the FSP worker slices into `packet_data`.
        let fallback = DecryptFallback::new(
            source_peer,
            transport_id,
            remote_addr,
            timestamp_ms,
            packet_len,
            fmp_counter,
            fmp_flags,
            packet_data,
            fmp_plaintext_start,
            plaintext_len,
        );

        if let Some(meta) = fsp_meta {
            let fsp_job = FspDecryptJob {
                fallback_tx: fallback_tx.clone(),
                fallback,
                local_node_addr,
                source_addr: meta.source_addr,
                previous_hop_peer: source_peer,
                path_mtu: meta.path_mtu,
                ce_flag: fmp_flags & crate::node::wire::FLAG_CE != 0,
                inner_timestamp_ms,
                fsp_payload_offset: meta.fsp_payload_offset,
                fsp_payload_len: meta.fsp_payload_len,
                trace_enqueued_at: None,
            };
            return Ok(self.dispatch_or_handle_fsp_job(idx, fsp_job));
        }

        let event = DecryptWorkerEvent::Plaintext(fallback);
        Ok(Some(DecryptWorkerOutput {
            fallback_tx,
            event,
            direct_delivery: None,
        }))
    }

    #[cfg(test)]
    fn contains_session(&self, session_key: DecryptSessionKey) -> bool {
        self.sessions.contains_key(&session_key)
    }

    #[cfg(test)]
    fn fmp_replay_highest(&self, session_key: DecryptSessionKey) -> Option<u64> {
        self.sessions
            .get(&session_key)
            .map(|state| state.fmp_replay.highest())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::ReplayWindow;
    use crossbeam_channel::bounded;
    use ring::aead::{LessSafeKey, UnboundKey};
    use std::time::Duration;

    #[test]
    fn decrypt_worker_channel_cap_prefers_specific_then_shared_value() {
        assert_eq!(parse_channel_cap(Some("4"), Some("8"), 1024), 4);
        assert_eq!(parse_channel_cap(None, Some("8"), 1024), 8);
        assert_eq!(parse_channel_cap(Some("bad"), Some("9"), 1024), 9);
        assert_eq!(parse_channel_cap(Some("0"), None, 1024), 1);
        assert_eq!(parse_channel_cap(Some("999999"), None, 1024), 1024);
    }

    #[test]
    fn decrypt_fallback_bulk_cap_ignores_shared_worker_cap() {
        assert_eq!(
            parse_channel_cap(None, Some("4"), DEFAULT_DECRYPT_WORKER_BULK_CHANNEL_CAP),
            4
        );
        assert_eq!(
            fallback_bulk_channel_cap_from_raw(None),
            DEFAULT_DECRYPT_FALLBACK_BULK_CHANNEL_CAP
        );
        assert_eq!(fallback_bulk_channel_cap_from_raw(Some("4")), 4);
    }

    #[test]
    fn decrypt_worker_priority_packet_classifier_keeps_small_packets_reserved() {
        assert_eq!(
            decrypt_worker_packet_lane(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN),
            DecryptWorkerLane::Priority
        );
        assert_eq!(
            decrypt_worker_packet_lane(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1),
            DecryptWorkerLane::Bulk
        );
    }

    fn one_slot_worker_pool() -> (
        DecryptWorkerPool,
        Receiver<WorkerMsg>,
        Receiver<DecryptWorkerBulkItem>,
    ) {
        let (priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (bulk_tx, bulk_rx) = bounded::<DecryptWorkerBulkItem>(1);
        let bulk_queued_packets = Arc::new(AtomicUsize::new(0));
        (
            DecryptWorkerPool {
                senders: std::sync::Arc::from(
                    vec![DecryptWorkerSender {
                        priority: priority_tx,
                        bulk: bulk_tx,
                        bulk_queued_packets,
                        bulk_packet_cap: 1,
                    }]
                    .into_boxed_slice(),
                ),
                direct_delivery_sink: DecryptDirectSessionDeliverySink::default(),
            },
            priority_rx,
            bulk_rx,
        )
    }

    fn test_worker_pool(
        worker_count: usize,
        cap: usize,
    ) -> (
        DecryptWorkerPool,
        Vec<Receiver<WorkerMsg>>,
        Vec<Receiver<DecryptWorkerBulkItem>>,
    ) {
        let mut senders = Vec::with_capacity(worker_count);
        let mut priority_receivers = Vec::with_capacity(worker_count);
        let mut bulk_receivers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let (priority_tx, priority_rx) = bounded::<WorkerMsg>(cap);
            let (bulk_tx, bulk_rx) = bounded::<DecryptWorkerBulkItem>(cap);
            let bulk_queued_packets = Arc::new(AtomicUsize::new(0));
            senders.push(DecryptWorkerSender {
                priority: priority_tx,
                bulk: bulk_tx,
                bulk_queued_packets,
                bulk_packet_cap: cap,
            });
            priority_receivers.push(priority_rx);
            bulk_receivers.push(bulk_rx);
        }
        (
            DecryptWorkerPool {
                senders: std::sync::Arc::from(senders.into_boxed_slice()),
                direct_delivery_sink: DecryptDirectSessionDeliverySink::default(),
            },
            priority_receivers,
            bulk_receivers,
        )
    }

    fn test_bulk_lane(
        cap: usize,
    ) -> (
        Sender<DecryptWorkerBulkItem>,
        Receiver<DecryptWorkerBulkItem>,
        Arc<AtomicUsize>,
    ) {
        let (bulk_tx, bulk_rx) = bounded::<DecryptWorkerBulkItem>(cap);
        let bulk_queued_packets = Arc::new(AtomicUsize::new(0));
        (bulk_tx, bulk_rx, bulk_queued_packets)
    }

    fn queue_bulk_item_for_test(
        tx: &Sender<DecryptWorkerBulkItem>,
        queued_packets: &AtomicUsize,
        item: DecryptWorkerBulkItem,
    ) {
        queued_packets.fetch_add(item.packet_count(), Ordering::Relaxed);
        tx.try_send(item).expect("test bulk queue should have room");
    }

    fn test_shard() -> DecryptWorkerShard {
        let (pool, _priority, _bulk) = test_worker_pool(1, 8);
        DecryptWorkerShard::new(pool)
    }

    fn test_source_peer() -> PeerIdentity {
        PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full())
    }

    fn test_owned_session_state() -> OwnedSessionState {
        let key_bytes = [7u8; 32];
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        OwnedSessionState {
            fmp_cipher: LessSafeKey::new(unbound),
            fmp_replay: ReplayWindow::new(),
            source_peer: test_source_peer(),
        }
    }

    #[test]
    fn owned_session_state_carries_authenticated_source_peer() {
        let source_peer = test_source_peer();
        let key_bytes = [8u8; 32];
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        let state = OwnedSessionState {
            fmp_cipher: LessSafeKey::new(unbound),
            fmp_replay: ReplayWindow::new(),
            source_peer,
        };

        assert_eq!(state.source_peer, source_peer);
    }

    fn test_session_key(transport_id: u32, receiver_idx: u32) -> DecryptSessionKey {
        DecryptSessionKey::new(TransportId::new(transport_id), receiver_idx)
    }

    fn dummy_decrypt_job_with_len(session_key: DecryptSessionKey, packet_len: usize) -> DecryptJob {
        let packet_len = packet_len.max(crate::node::wire::ESTABLISHED_HEADER_SIZE + 16);
        let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        DecryptJob::new(
            vec![0; packet_len],
            session_key,
            session_key.transport_id,
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *test_source_peer().node_addr(),
            1_000,
            1,
            0,
            [0u8; crate::node::wire::ESTABLISHED_HEADER_SIZE],
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
            fallback_tx,
        )
    }

    fn dummy_bulk_decrypt_job(session_key: DecryptSessionKey) -> DecryptJob {
        dummy_decrypt_job_with_len(session_key, DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1)
    }

    fn dummy_priority_decrypt_job(session_key: DecryptSessionKey) -> DecryptJob {
        dummy_decrypt_job_with_len(session_key, DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN)
    }

    fn dummy_plaintext_event(packet_len: usize) -> DecryptWorkerEvent {
        DecryptWorkerEvent::Plaintext(DecryptFallback::new(
            test_source_peer(),
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            1_000,
            packet_len,
            1,
            0,
            vec![0; packet_len.max(1)],
            0,
            1,
        ))
    }

    fn dummy_plaintext_batch_event(count: usize, packet_len: usize) -> DecryptWorkerEvent {
        DecryptWorkerEvent::PlaintextBatch(
            (0..count)
                .map(|idx| {
                    DecryptFallback::new(
                        test_source_peer(),
                        TransportId::new(1),
                        crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                        1_000,
                        packet_len,
                        idx as u64,
                        0,
                        vec![0; packet_len.max(1)],
                        0,
                        1,
                    )
                })
                .collect(),
        )
    }

    fn dummy_failure_event() -> DecryptWorkerEvent {
        DecryptWorkerEvent::DecryptFailure(DecryptFailureReport {
            source_peer: test_source_peer(),
            fmp_counter: 2,
            fmp_replay_highest: 1,
            trace_enqueued_at: None,
        })
    }

    fn dummy_direct_endpoint_output(
        fallback_tx: DecryptWorkerFallbackSender,
        sink: DecryptDirectSessionDeliverySink,
        source_peer: PeerIdentity,
        fmp_counter: u64,
        payload: &[u8],
    ) -> DecryptWorkerOutput {
        let source_addr = *source_peer.node_addr();
        let payload_len = payload.len();
        let commit = DecryptDirectSessionCommit::for_test(
            DecryptFmpBookkeeping {
                source_peer,
                transport_id: TransportId::new(1),
                remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                packet_timestamp_ms: 1_000,
                packet_len: payload_len,
                fmp_counter,
                inner_timestamp_ms: fmp_counter as u32,
                fmp_flags: 0,
            },
            source_addr,
            source_peer,
            false,
            FspReceiveSync {
                counter: fmp_counter,
                slot: EpochSlot::Current,
                received_k_bit: false,
                timestamp: fmp_counter as u32,
                plaintext_len: payload_len,
                ce_flag: false,
                path_mtu: 1_280,
                spin_bit: false,
            },
            payload_len,
            false,
        );

        DecryptWorkerOutput {
            fallback_tx,
            event: DecryptWorkerEvent::DirectSessionCommit(commit),
            direct_delivery: Some(PendingDirectSessionDelivery {
                sink,
                source_addr,
                source_peer,
                ce_flag: false,
                delivery: DecryptDirectSessionDelivery::EndpointData(EndpointDataDelivery::new(
                    source_peer,
                    payload.to_vec(),
                )),
            }),
        }
    }

    #[test]
    fn decrypt_worker_return_drop_metric_splits_fallback_and_authenticated_outputs() {
        let bulk_len = DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1;
        let plaintext = dummy_plaintext_event(bulk_len);
        assert_eq!(
            decrypt_worker_event_drop_event(&plaintext, plaintext.lane()),
            crate::perf_profile::Event::DecryptFallbackBulkDropped
        );

        let failure = dummy_failure_event();
        assert_eq!(
            decrypt_worker_event_drop_event(&failure, failure.lane()),
            crate::perf_profile::Event::DecryptFallbackPriorityDropped
        );

        let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        let (endpoint_tx, _endpoint_rx) = EndpointEventSender::channel(1);
        let sink = DecryptDirectSessionDeliverySink::new(None, None, Some(endpoint_tx));
        let source_peer = test_source_peer();
        let bulk_payload = vec![0x55; bulk_len];
        let output = dummy_direct_endpoint_output(fallback_tx, sink, source_peer, 7, &bulk_payload);
        assert_eq!(
            decrypt_worker_event_drop_event(&output.event, output.event.lane()),
            crate::perf_profile::Event::DecryptAuthenticatedSessionBulkDropped
        );

        let DecryptWorkerEvent::DirectSessionCommit(mut commit) = output.event else {
            panic!("expected direct session commit");
        };
        commit.lane = DecryptWorkerLane::Priority;
        let priority_commit = DecryptWorkerEvent::DirectSessionCommit(commit);
        assert_eq!(
            decrypt_worker_event_drop_event(&priority_commit, priority_commit.lane()),
            crate::perf_profile::Event::DecryptAuthenticatedSessionPriorityDropped
        );
    }

    fn dummy_fsp_job(packet_len: usize) -> FspDecryptJob {
        let source_peer = test_source_peer();
        let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        FspDecryptJob {
            fallback_tx,
            fallback: DecryptFallback::new(
                test_source_peer(),
                TransportId::new(1),
                crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                1_000,
                packet_len,
                1,
                0,
                vec![0; packet_len.max(1)],
                0,
                1,
            ),
            local_node_addr: *test_source_peer().node_addr(),
            source_addr: *source_peer.node_addr(),
            previous_hop_peer: test_source_peer(),
            path_mtu: 1_280,
            ce_flag: false,
            inner_timestamp_ms: 2,
            fsp_payload_offset: 0,
            fsp_payload_len: 0,
            trace_enqueued_at: None,
        }
    }

    fn dummy_authenticated_session_event(lane: DecryptWorkerLane) -> DecryptWorkerEvent {
        let source_peer = test_source_peer();
        let previous_hop_peer = test_source_peer();
        DecryptWorkerEvent::AuthenticatedSession(DecryptAuthenticatedSession {
            fmp: DecryptFmpBookkeeping {
                source_peer: previous_hop_peer,
                transport_id: TransportId::new(1),
                remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                packet_timestamp_ms: 1_000,
                packet_len: 128,
                fmp_counter: 2,
                inner_timestamp_ms: 3,
                fmp_flags: 0,
            },
            source_addr: *source_peer.node_addr(),
            previous_hop_peer,
            ce_flag: false,
            message: AuthenticatedSessionMessage::new(source_peer, vec![0; 8], 0x01, 0, 4),
            receive_sync: FspReceiveSync {
                counter: 5,
                slot: EpochSlot::Current,
                received_k_bit: false,
                timestamp: 4,
                plaintext_len: 8,
                ce_flag: false,
                path_mtu: 1_280,
                spin_bit: false,
            },
            lane,
            trace_enqueued_at: None,
        })
    }

    fn test_chacha_key(key_bytes: [u8; 32]) -> LessSafeKey {
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        LessSafeKey::new(unbound)
    }

    fn test_xk_session_pair(
        sender: &crate::Identity,
        receiver: &crate::Identity,
    ) -> (crate::noise::NoiseSession, crate::noise::NoiseSession) {
        let mut initiator = crate::noise::HandshakeState::new_xk_initiator(
            sender.keypair(),
            receiver.pubkey_full(),
        );
        let mut responder = crate::noise::HandshakeState::new_xk_responder(receiver.keypair());
        initiator.set_local_epoch([1u8; 8]);
        responder.set_local_epoch([2u8; 8]);
        let msg1 = initiator.write_xk_message_1().unwrap();
        responder.read_xk_message_1(&msg1).unwrap();
        let msg2 = responder.write_xk_message_2().unwrap();
        initiator.read_xk_message_2(&msg2).unwrap();
        let msg3 = initiator.write_xk_message_3().unwrap();
        responder.read_xk_message_3(&msg3).unwrap();
        (
            initiator.into_session().unwrap(),
            responder.into_session().unwrap(),
        )
    }

    fn sealed_fmp_test_packet(
        cipher: &LessSafeKey,
        counter: u64,
        flags: u8,
    ) -> (Vec<u8>, [u8; crate::node::wire::ESTABLISHED_HEADER_SIZE]) {
        sealed_fmp_test_packet_with_link_body(cipher, counter, flags, 1)
    }

    fn sealed_fmp_test_packet_with_link_body(
        cipher: &LessSafeKey,
        counter: u64,
        flags: u8,
        link_body_len: usize,
    ) -> (Vec<u8>, [u8; crate::node::wire::ESTABLISHED_HEADER_SIZE]) {
        const HDR: usize = crate::node::wire::ESTABLISHED_HEADER_SIZE;
        let mut header = [0u8; HDR];
        header[1] = flags;
        let link_body_len = link_body_len.max(1);
        let mut wire = Vec::with_capacity(HDR + 4 + link_body_len + 16);
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&[0u8; 4]);
        wire.push(0xAB);
        wire.resize(HDR + 4 + link_body_len, 0xCD);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = ring::aead::Nonce::assume_unique_for_key(nonce_bytes);
        let (hdr_slice, payload_slice) = wire.split_at_mut(HDR);
        let tag = cipher
            .seal_in_place_separate_tag(nonce, ring::aead::Aad::from(&*hdr_slice), payload_slice)
            .unwrap();
        wire.extend_from_slice(tag.as_ref());
        (wire, header)
    }

    fn sealed_fmp_test_packet_with_plaintext(
        cipher: &LessSafeKey,
        counter: u64,
        flags: u8,
        plaintext: &[u8],
    ) -> (Vec<u8>, [u8; crate::node::wire::ESTABLISHED_HEADER_SIZE]) {
        const HDR: usize = crate::node::wire::ESTABLISHED_HEADER_SIZE;
        let mut header = [0u8; HDR];
        header[1] = flags;
        let mut wire = Vec::with_capacity(HDR + plaintext.len() + 16);
        wire.extend_from_slice(&header);
        wire.extend_from_slice(plaintext);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = ring::aead::Nonce::assume_unique_for_key(nonce_bytes);
        let (hdr_slice, payload_slice) = wire.split_at_mut(HDR);
        let tag = cipher
            .seal_in_place_separate_tag(nonce, ring::aead::Aad::from(&*hdr_slice), payload_slice)
            .unwrap();
        wire.extend_from_slice(tag.as_ref());
        (wire, header)
    }

    fn invalid_fmp_test_packet(
        flags: u8,
    ) -> (Vec<u8>, [u8; crate::node::wire::ESTABLISHED_HEADER_SIZE]) {
        const HDR: usize = crate::node::wire::ESTABLISHED_HEADER_SIZE;
        let mut header = [0u8; HDR];
        header[1] = flags;
        let mut wire = Vec::with_capacity(HDR + 4 + 1 + 16);
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&[0u8; 4]);
        wire.push(0xAB);
        wire.extend_from_slice(&[0u8; 16]);
        (wire, header)
    }

    fn decrypt_job_for_test_packet(
        packet_data: Vec<u8>,
        header: [u8; crate::node::wire::ESTABLISHED_HEADER_SIZE],
        session_key: DecryptSessionKey,
        fmp_counter: u64,
        fmp_flags: u8,
        fallback_tx: DecryptWorkerFallbackSender,
    ) -> DecryptJob {
        DecryptJob::new(
            packet_data,
            session_key,
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *test_source_peer().node_addr(),
            1_000,
            fmp_counter,
            fmp_flags,
            header,
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
            fallback_tx,
        )
    }

    #[test]
    fn decrypt_session_fast_hash_distinguishes_transport_and_receiver() {
        let baseline = test_session_key(7, 42);
        assert_ne!(
            decrypt_session_fast_hash(baseline),
            decrypt_session_fast_hash(test_session_key(8, 42)),
            "transport id must participate in worker routing"
        );
        assert_ne!(
            decrypt_session_fast_hash(baseline),
            decrypt_session_fast_hash(test_session_key(7, 43)),
            "receiver index must participate in worker routing"
        );

        let mut buckets = [0usize; 8];
        for transport_id in 1..=8 {
            for receiver_idx in 1..=64 {
                let worker =
                    (decrypt_session_fast_hash(test_session_key(transport_id, receiver_idx))
                        as usize)
                        % buckets.len();
                buckets[worker] += 1;
            }
        }
        assert!(
            buckets.iter().all(|count| *count > 0),
            "common session keys should spread across all workers: {buckets:?}"
        );
    }

    #[test]
    fn worker_decodes_local_ipv6_shim_data_without_plaintext_bounce() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let source_addr = *source.node_addr();
        let local_addr = *local.node_addr();
        let src_ipv6 = FipsAddress::from_node_addr(&source_addr).to_ipv6().octets();
        let dst_ipv6 = FipsAddress::from_node_addr(&local_addr).to_ipv6().octets();
        let payload = b"worker-decompressed-ipv6";

        let mut ipv6 = Vec::with_capacity(40 + payload.len());
        ipv6.extend_from_slice(&[0x60, 0, 0, 0]);
        ipv6.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        ipv6.push(59);
        ipv6.push(64);
        ipv6.extend_from_slice(&src_ipv6);
        ipv6.extend_from_slice(&dst_ipv6);
        ipv6.extend_from_slice(payload);

        let compressed = crate::upper::ipv6_shim::compress_ipv6(&ipv6)
            .expect("test IPv6 packet should compress");
        let mut data_packet_body = Vec::with_capacity(FSP_PORT_HEADER_SIZE + compressed.len());
        data_packet_body.extend_from_slice(&0u16.to_le_bytes());
        data_packet_body.extend_from_slice(&FSP_PORT_IPV6_SHIM.to_le_bytes());
        data_packet_body.extend_from_slice(&compressed);
        let plaintext = crate::node::session_wire::fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::DataPacket.to_byte(),
            0,
            &data_packet_body,
        );
        let message = AuthenticatedSessionMessage::new(
            source_peer,
            plaintext,
            SessionMessageType::DataPacket.to_byte(),
            0,
            0x0102_0304,
        );

        match DecryptWorkerShard::direct_session_delivery_from_message(
            source_addr,
            local_addr,
            message,
        )
        .expect("IPv6 shim data packet should decode in worker")
        {
            DecryptDirectSessionDelivery::Ipv6Packet(packet) => assert_eq!(packet, ipv6),
            DecryptDirectSessionDelivery::EndpointData(_) => {
                panic!("IPv6 shim data must not become endpoint data")
            }
        }
    }

    #[test]
    fn worker_directs_local_established_session_datagram_to_fsp_owner() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let previous_hop = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let previous_hop_peer = PeerIdentity::from_pubkey_full(previous_hop.pubkey_full());
        let (mut fsp_sender, fsp_receiver) = test_xk_session_pair(&source, &local);
        let inner_plaintext = crate::node::session_wire::fsp_prepend_inner_header(
            0x0102_0304,
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0x01,
            b"direct endpoint",
        );
        let fsp_counter = fsp_sender.current_send_counter();
        let fsp_header = crate::node::session_wire::build_fsp_header(
            fsp_counter,
            0,
            inner_plaintext.len() as u16,
        );
        let fsp_ciphertext = fsp_sender
            .encrypt_with_aad(&inner_plaintext, &fsp_header)
            .unwrap();
        let mut fsp_payload = Vec::with_capacity(fsp_header.len() + fsp_ciphertext.len());
        fsp_payload.extend_from_slice(&fsp_header);
        fsp_payload.extend_from_slice(&fsp_ciphertext);
        let datagram = crate::protocol::SessionDatagram::new(
            *source.node_addr(),
            *local.node_addr(),
            fsp_payload,
        );
        let inner_timestamp_ms = 0x0a0b_0c0d_u32;
        let mut fmp_plaintext = Vec::new();
        fmp_plaintext.extend_from_slice(&inner_timestamp_ms.to_le_bytes());
        fmp_plaintext.extend_from_slice(&datagram.encode());

        let fmp_key_bytes = [0x33; 32];
        let fmp_seal = test_chacha_key(fmp_key_bytes);
        let fmp_open = test_chacha_key(fmp_key_bytes);
        let fmp_counter = 77;
        let (wire, fmp_header) =
            sealed_fmp_test_packet_with_plaintext(&fmp_seal, fmp_counter, 0, &fmp_plaintext);
        let session_key = test_session_key(1, 9);
        let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let job = DecryptJob::new(
            wire,
            session_key,
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *local.node_addr(),
            1_000,
            fmp_counter,
            0,
            fmp_header,
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
            fallback_tx,
        );

        let (pool, _priority, _bulk) = test_worker_pool(1, 8);
        let mut shard = DecryptWorkerShard::new(pool);
        shard.register_session(
            0,
            session_key,
            OwnedSessionState {
                fmp_cipher: fmp_open,
                fmp_replay: ReplayWindow::new(),
                source_peer: previous_hop_peer,
            },
        );
        let fsp_snapshot = crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: fsp_receiver.recv_cipher_clone().unwrap(),
                replay: fsp_receiver.recv_replay_snapshot_owned(),
            },
            pending: None,
            previous: None,
        };
        shard.register_fsp_session(
            0,
            *source.node_addr(),
            OwnedFspSessionState::from(fsp_snapshot),
        );

        let output = shard
            .handle_job_output(0, job)
            .expect("worker job should not fail")
            .expect("direct FSP path should emit an event");
        match output.event {
            DecryptWorkerEvent::DirectSessionData(direct) => {
                assert_eq!(direct.source_addr, *source.node_addr());
                assert_eq!(direct.previous_hop_peer, previous_hop_peer);
                assert_eq!(direct.fmp.source_peer, previous_hop_peer);
                assert_eq!(direct.fmp.fmp_counter, fmp_counter);
                assert_eq!(direct.fmp.inner_timestamp_ms, inner_timestamp_ms);
                assert_eq!(direct.receive_sync.counter, fsp_counter);
                assert_eq!(direct.receive_sync.slot, EpochSlot::Current);
                assert_eq!(direct.receive_sync.timestamp, 0x0102_0304);
                assert_eq!(direct.receive_sync.plaintext_len, inner_plaintext.len());
                assert_eq!(direct.body_len, b"direct endpoint".len());
                assert!(direct.receive_sync.spin_bit);
                match direct.delivery {
                    DecryptDirectSessionDelivery::EndpointData(delivery) => {
                        assert_eq!(delivery.source_peer, source_peer);
                        assert_eq!(delivery.payload, b"direct endpoint");
                    }
                    DecryptDirectSessionDelivery::Ipv6Packet(_) => {
                        panic!("endpoint data must not become an IPv6 packet")
                    }
                }
            }
            other => panic!(
                "expected direct session data event, got {:?}",
                other.packet_count()
            ),
        }
    }

    #[test]
    fn worker_direct_hop_tun_delivery_waits_for_commit_queue_acceptance() {
        let source_peer = test_source_peer();
        let source_addr = *source_peer.node_addr();
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let (tun_tx, tun_rx) = std::sync::mpsc::channel();
        let mut ipv6 = vec![0u8; 48];
        ipv6[0] = 0x60;
        ipv6[1] = 0x20;

        let commit = DecryptDirectSessionCommit::for_test(
            DecryptFmpBookkeeping {
                source_peer,
                transport_id: TransportId::new(1),
                remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                packet_timestamp_ms: 1_000,
                packet_len: ipv6.len(),
                fmp_counter: 9,
                inner_timestamp_ms: 10,
                fmp_flags: 0,
            },
            source_addr,
            source_peer,
            true,
            FspReceiveSync {
                counter: 7,
                slot: EpochSlot::Current,
                received_k_bit: false,
                timestamp: 0x0102_0304,
                plaintext_len: FSP_HEADER_SIZE + ipv6.len(),
                ce_flag: true,
                path_mtu: 1_280,
                spin_bit: false,
            },
            ipv6.len(),
            true,
        );
        let output = DecryptWorkerOutput {
            fallback_tx,
            event: DecryptWorkerEvent::DirectSessionCommit(commit),
            direct_delivery: Some(PendingDirectSessionDelivery {
                sink: DecryptDirectSessionDeliverySink::new(Some(tun_tx), None, None),
                source_addr,
                source_peer,
                ce_flag: true,
                delivery: DecryptDirectSessionDelivery::Ipv6Packet(ipv6),
            }),
        };

        assert!(
            tun_rx.try_recv().is_err(),
            "direct TUN bytes must wait until the commit is queued"
        );
        assert!(output.send(), "commit queue should accept direct commit");

        match fallback_rx.bulk.try_recv().expect("commit event") {
            DecryptWorkerEvent::DirectSessionCommit(commit) => {
                assert_eq!(commit.source_addr, source_addr);
                assert!(commit.delivered_ipv6);
            }
            other => panic!(
                "expected direct commit event, got {:?}",
                other.packet_count()
            ),
        }
        let delivered = tun_rx.try_recv().expect("TUN packet delivered");
        assert_eq!(delivered[1] & 0x30, 0x30, "CE mark should be applied");
    }

    #[test]
    fn worker_drops_replayed_fsp_without_rx_loop_fallback() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let previous_hop = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let previous_hop_peer = PeerIdentity::from_pubkey_full(previous_hop.pubkey_full());
        let (mut fsp_sender, fsp_receiver) = test_xk_session_pair(&source, &local);
        let inner_plaintext = crate::node::session_wire::fsp_prepend_inner_header(
            0x0102_0304,
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0x01,
            b"direct endpoint",
        );
        let fsp_counter = fsp_sender.current_send_counter();
        let fsp_header = crate::node::session_wire::build_fsp_header(
            fsp_counter,
            0,
            inner_plaintext.len() as u16,
        );
        let fsp_ciphertext = fsp_sender
            .encrypt_with_aad(&inner_plaintext, &fsp_header)
            .unwrap();
        let mut fsp_payload = Vec::with_capacity(fsp_header.len() + fsp_ciphertext.len());
        fsp_payload.extend_from_slice(&fsp_header);
        fsp_payload.extend_from_slice(&fsp_ciphertext);
        let datagram = crate::protocol::SessionDatagram::new(
            *source.node_addr(),
            *local.node_addr(),
            fsp_payload,
        );
        let mut fmp_plaintext = Vec::new();
        fmp_plaintext.extend_from_slice(&0x0a0b_0c0d_u32.to_le_bytes());
        fmp_plaintext.extend_from_slice(&datagram.encode());

        let fmp_key_bytes = [0x44; 32];
        let fmp_seal = test_chacha_key(fmp_key_bytes);
        let fmp_open = test_chacha_key(fmp_key_bytes);
        let (wire_a, header_a) =
            sealed_fmp_test_packet_with_plaintext(&fmp_seal, 77, 0, &fmp_plaintext);
        let (wire_b, header_b) =
            sealed_fmp_test_packet_with_plaintext(&fmp_seal, 78, 0, &fmp_plaintext);
        let session_key = test_session_key(1, 9);
        let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);

        let (pool, _priority, _bulk) = test_worker_pool(1, 8);
        let mut shard = DecryptWorkerShard::new(pool);
        shard.register_session(
            0,
            session_key,
            OwnedSessionState {
                fmp_cipher: fmp_open,
                fmp_replay: ReplayWindow::new(),
                source_peer: previous_hop_peer,
            },
        );
        let fsp_snapshot = crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: fsp_receiver.recv_cipher_clone().unwrap(),
                replay: fsp_receiver.recv_replay_snapshot_owned(),
            },
            pending: None,
            previous: None,
        };
        shard.register_fsp_session(
            0,
            *source.node_addr(),
            OwnedFspSessionState::from(fsp_snapshot),
        );

        let first = DecryptJob::new(
            wire_a,
            session_key,
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *local.node_addr(),
            1_000,
            77,
            0,
            header_a,
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
            fallback_tx.clone(),
        );
        let second = DecryptJob::new(
            wire_b,
            session_key,
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *local.node_addr(),
            1_000,
            78,
            0,
            header_b,
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
            fallback_tx,
        );

        assert!(matches!(
            shard
                .handle_job_output(0, first)
                .expect("first worker job should not fail")
                .expect("first FSP frame should authenticate")
                .event,
            DecryptWorkerEvent::DirectSessionData(_)
        ));
        assert!(
            shard
                .handle_job_output(0, second)
                .expect("second worker job should not fail")
                .is_none(),
            "FSP replay must not bounce into rx-loop decrypt failure accounting"
        );
        assert_eq!(
            shard.fmp_replay_highest(session_key),
            Some(78),
            "outer FMP replay still advances independently"
        );
    }

    #[test]
    fn worker_reports_fsp_aead_failure_without_plaintext_fallback() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let previous_hop = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let previous_hop_peer = PeerIdentity::from_pubkey_full(previous_hop.pubkey_full());
        let (mut fsp_sender, fsp_receiver) = test_xk_session_pair(&source, &local);
        let inner_plaintext = crate::node::session_wire::fsp_prepend_inner_header(
            0x0102_0304,
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0x01,
            b"bad inner tag",
        );
        let fsp_counter = fsp_sender.current_send_counter();
        let fsp_header = crate::node::session_wire::build_fsp_header(
            fsp_counter,
            0,
            inner_plaintext.len() as u16,
        );
        let mut fsp_ciphertext = fsp_sender
            .encrypt_with_aad(&inner_plaintext, &fsp_header)
            .unwrap();
        let last = fsp_ciphertext
            .last_mut()
            .expect("ciphertext includes authentication tag");
        *last ^= 0x80;
        let mut fsp_payload = Vec::with_capacity(fsp_header.len() + fsp_ciphertext.len());
        fsp_payload.extend_from_slice(&fsp_header);
        fsp_payload.extend_from_slice(&fsp_ciphertext);
        let datagram = crate::protocol::SessionDatagram::new(
            *source.node_addr(),
            *local.node_addr(),
            fsp_payload,
        );
        let inner_timestamp_ms = 0x0a0b_0c0d_u32;
        let mut fmp_plaintext = Vec::new();
        fmp_plaintext.extend_from_slice(&inner_timestamp_ms.to_le_bytes());
        fmp_plaintext.extend_from_slice(&datagram.encode());

        let fmp_key_bytes = [0x55; 32];
        let fmp_seal = test_chacha_key(fmp_key_bytes);
        let fmp_open = test_chacha_key(fmp_key_bytes);
        let fmp_counter = 77;
        let (wire, fmp_header) =
            sealed_fmp_test_packet_with_plaintext(&fmp_seal, fmp_counter, 0, &fmp_plaintext);
        let session_key = test_session_key(1, 9);
        let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let job = DecryptJob::new(
            wire,
            session_key,
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *local.node_addr(),
            1_000,
            fmp_counter,
            0,
            fmp_header,
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
            fallback_tx,
        );

        let (pool, _priority, _bulk) = test_worker_pool(1, 8);
        let mut shard = DecryptWorkerShard::new(pool);
        shard.register_session(
            0,
            session_key,
            OwnedSessionState {
                fmp_cipher: fmp_open,
                fmp_replay: ReplayWindow::new(),
                source_peer: previous_hop_peer,
            },
        );
        let fsp_snapshot = crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: fsp_receiver.recv_cipher_clone().unwrap(),
                replay: fsp_receiver.recv_replay_snapshot_owned(),
            },
            pending: None,
            previous: None,
        };
        shard.register_fsp_session(
            0,
            *source.node_addr(),
            OwnedFspSessionState::from(fsp_snapshot),
        );

        let output = shard
            .handle_job_output(0, job)
            .expect("worker job should not fail")
            .expect("FSP AEAD failure should report to rx_loop");
        match output.event {
            DecryptWorkerEvent::FspDecryptFailure(report) => {
                assert_eq!(report.source_addr, *source.node_addr());
                assert_eq!(report.counter, fsp_counter);
                assert_eq!(report.fmp.source_peer, previous_hop_peer);
                assert_eq!(report.fmp.fmp_counter, fmp_counter);
                assert_eq!(report.fmp.inner_timestamp_ms, inner_timestamp_ms);
            }
            DecryptWorkerEvent::Plaintext(_) | DecryptWorkerEvent::PlaintextBatch(_) => {
                panic!("FSP AEAD failure must not bounce a possibly mutated packet")
            }
            DecryptWorkerEvent::AuthenticatedSession(_)
            | DecryptWorkerEvent::DirectSessionCommit(_)
            | DecryptWorkerEvent::DirectSessionCommitBatch(_)
            | DecryptWorkerEvent::DirectSessionData(_)
            | DecryptWorkerEvent::DecryptFailure(_) => {
                panic!("expected FSP decrypt failure report")
            }
        }
    }

    #[test]
    fn decrypt_session_key_routes_registration_jobs_and_unregister_to_same_worker() {
        let (pool, priority_receivers, bulk_receivers) = test_worker_pool(4, 4);
        let session_key = test_session_key(7, 42);
        let owner = pool.worker_idx_for(session_key);

        assert!(pool.register_session(session_key, test_owned_session_state()));
        pool.dispatch_job(dummy_priority_decrypt_job(session_key));
        assert!(pool.unregister_session(session_key));

        match priority_receivers[owner]
            .try_recv()
            .expect("registration should reach owner")
        {
            WorkerMsg::RegisterSession {
                session_key: queued_key,
                ..
            } => assert_eq!(queued_key, session_key),
            WorkerMsg::Job(_)
            | WorkerMsg::FspJob(_)
            | WorkerMsg::RegisterFspSession { .. }
            | WorkerMsg::UnregisterSession { .. }
            | WorkerMsg::UnregisterFspSession { .. } => {
                panic!("expected registration first")
            }
        }
        match priority_receivers[owner]
            .try_recv()
            .expect("priority packet should reach same owner")
        {
            WorkerMsg::Job(job) => assert_eq!(job.session_key, session_key),
            WorkerMsg::RegisterSession { .. }
            | WorkerMsg::FspJob(_)
            | WorkerMsg::RegisterFspSession { .. }
            | WorkerMsg::UnregisterSession { .. }
            | WorkerMsg::UnregisterFspSession { .. } => {
                panic!("expected priority job second")
            }
        }
        match priority_receivers[owner]
            .try_recv()
            .expect("unregister should reach same owner")
        {
            WorkerMsg::UnregisterSession {
                session_key: queued_key,
            } => {
                assert_eq!(queued_key, session_key);
            }
            WorkerMsg::RegisterSession { .. }
            | WorkerMsg::RegisterFspSession { .. }
            | WorkerMsg::Job(_)
            | WorkerMsg::FspJob(_)
            | WorkerMsg::UnregisterFspSession { .. } => {
                panic!("expected unregister third")
            }
        }

        for (idx, rx) in priority_receivers.iter().enumerate() {
            if idx != owner {
                assert!(
                    rx.is_empty(),
                    "other worker {idx} must not receive this session key"
                );
            }
        }
        assert!(
            bulk_receivers.iter().all(Receiver::is_empty),
            "priority session-key dispatch must not consume bulk lanes"
        );
    }

    #[test]
    fn fsp_jobs_keep_original_priority_and_bulk_lanes_to_fsp_owner() {
        let (pool, priority_receivers, bulk_receivers) = test_worker_pool(4, 4);

        let priority_job = dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN);
        let priority_owner = pool.worker_idx_for_fsp(&priority_job.source_addr);
        assert!(
            pool.dispatch_fsp_job_or_return(priority_job).is_ok(),
            "priority FSP job should queue"
        );
        match priority_receivers[priority_owner]
            .try_recv()
            .expect("priority FSP job should use priority lane")
        {
            WorkerMsg::FspJob(job) => assert_eq!(job.lane(), DecryptWorkerLane::Priority),
            WorkerMsg::Job(_)
            | WorkerMsg::RegisterSession { .. }
            | WorkerMsg::RegisterFspSession { .. }
            | WorkerMsg::UnregisterSession { .. }
            | WorkerMsg::UnregisterFspSession { .. } => {
                panic!("expected priority FSP job")
            }
        }
        assert!(
            bulk_receivers[priority_owner].is_empty(),
            "priority FSP jobs must not wait behind bulk work"
        );

        let bulk_job = dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1);
        let bulk_owner = pool.worker_idx_for_fsp(&bulk_job.source_addr);
        assert!(
            pool.dispatch_fsp_job_or_return(bulk_job).is_ok(),
            "bulk FSP job should queue"
        );
        match bulk_receivers[bulk_owner]
            .try_recv()
            .expect("bulk FSP job should use bulk lane")
        {
            DecryptWorkerBulkItem::FspJob(job) => assert_eq!(job.lane(), DecryptWorkerLane::Bulk),
            DecryptWorkerBulkItem::Job(_) | DecryptWorkerBulkItem::Batch(_) => {
                panic!("expected bulk FSP job")
            }
        }
    }

    #[test]
    fn full_fsp_owner_queues_return_to_rx_loop_fallback_without_waiting() {
        let (pool, priority_rx, bulk_rx) = one_slot_worker_pool();

        let session_key = test_session_key(1, 88);
        assert!(pool.register_session(session_key, test_owned_session_state()));
        assert_eq!(priority_rx.len(), 1, "priority lane should be full");

        let priority_job = dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN);
        assert!(
            pool.dispatch_fsp_job_or_return(priority_job).is_err(),
            "full priority FSP lane should fall back to rx_loop"
        );
        assert_eq!(
            priority_rx.len(),
            1,
            "priority FSP fallback must not overflow the priority lane"
        );

        pool.dispatch_bulk_job(0, dummy_bulk_decrypt_job(session_key));
        assert_eq!(bulk_rx.len(), 1, "bulk lane should be full");
        let bulk_job = dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1);
        assert!(
            pool.dispatch_fsp_job_or_return(bulk_job).is_err(),
            "full bulk FSP lane should fall back to rx_loop"
        );
        assert_eq!(
            bulk_rx.len(),
            1,
            "bulk FSP fallback must not overflow the bulk lane"
        );
    }

    #[test]
    fn decrypt_worker_fallback_event_classifier_uses_priority_and_bulk_lanes() {
        assert_eq!(
            decrypt_worker_event_lane(&dummy_plaintext_event(
                DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN
            )),
            DecryptWorkerLane::Priority
        );
        assert_eq!(
            decrypt_worker_event_lane(&dummy_plaintext_event(
                DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1
            )),
            DecryptWorkerLane::Bulk
        );
        assert_eq!(
            decrypt_worker_event_lane(&dummy_failure_event()),
            DecryptWorkerLane::Priority
        );
        let batch = dummy_plaintext_batch_event(3, DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1);
        assert_eq!(decrypt_worker_event_lane(&batch), DecryptWorkerLane::Bulk);
        assert_eq!(batch.packet_count(), 3);
    }

    #[test]
    fn decrypt_worker_event_wait_metrics_split_authenticated_sessions_from_fallbacks() {
        let plaintext = dummy_plaintext_event(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN);
        assert_eq!(
            plaintext.queue_wait_stages().0,
            crate::perf_profile::Stage::DecryptFallbackWait
        );

        let failure = dummy_failure_event();
        assert_eq!(
            failure.queue_wait_stages().1,
            crate::perf_profile::Stage::DecryptFallbackPriorityWait
        );

        let authenticated = dummy_authenticated_session_event(DecryptWorkerLane::Bulk);
        assert_eq!(
            decrypt_worker_event_lane(&authenticated),
            DecryptWorkerLane::Bulk
        );
        assert_eq!(
            authenticated.queue_wait_stages(),
            (
                crate::perf_profile::Stage::DecryptAuthenticatedSessionWait,
                crate::perf_profile::Stage::DecryptAuthenticatedSessionPriorityWait,
                crate::perf_profile::Stage::DecryptAuthenticatedSessionBulkWait
            )
        );
    }

    #[test]
    fn decrypt_worker_fallback_sender_stamps_queue_wait_origin() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);

        assert!(fallback_tx.send(dummy_failure_event()));
        match fallback_rx
            .priority
            .try_recv()
            .expect("priority event should enqueue")
        {
            DecryptWorkerEvent::DecryptFailure(report) => {
                assert!(
                    report.trace_enqueued_at.is_none() || crate::perf_profile::enabled(),
                    "trace stamps should only appear when pipeline tracing is enabled"
                );
            }
            DecryptWorkerEvent::Plaintext(_) => panic!("expected failure report"),
            DecryptWorkerEvent::PlaintextBatch(_) => panic!("expected failure report"),
            DecryptWorkerEvent::AuthenticatedSession(_) => panic!("expected failure report"),
            DecryptWorkerEvent::DirectSessionCommit(_) => panic!("expected failure report"),
            DecryptWorkerEvent::DirectSessionCommitBatch(_) => panic!("expected failure report"),
            DecryptWorkerEvent::DirectSessionData(_) => panic!("expected failure report"),
            DecryptWorkerEvent::FspDecryptFailure(_) => panic!("expected failure report"),
        }
    }

    #[test]
    fn decrypt_job_owns_lane_selected_at_construction() {
        let session_key = test_session_key(1, 55);
        let mut priority =
            dummy_decrypt_job_with_len(session_key, DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN);

        assert_eq!(decrypt_job_lane(&priority), DecryptWorkerLane::Priority);
        priority
            .packet_data
            .resize(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1024, 0);
        assert_eq!(
            decrypt_job_lane(&priority),
            DecryptWorkerLane::Priority,
            "queued decrypt jobs must keep the lane chosen before dispatch"
        );

        let bulk =
            dummy_decrypt_job_with_len(session_key, DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1);
        assert_eq!(decrypt_job_lane(&bulk), DecryptWorkerLane::Bulk);
    }

    #[test]
    fn decrypt_fallback_event_owns_lane_selected_at_construction() {
        let mut priority = dummy_plaintext_event(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN);

        assert_eq!(
            decrypt_worker_event_lane(&priority),
            DecryptWorkerLane::Priority
        );
        let DecryptWorkerEvent::Plaintext(fallback) = &mut priority else {
            panic!("dummy plaintext event should be plaintext");
        };
        fallback.packet_len = DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1024;
        fallback.packet_data.resize(fallback.packet_len, 0);
        assert_eq!(
            decrypt_worker_event_lane(&priority),
            DecryptWorkerLane::Priority,
            "queued fallback events must keep the lane chosen before enqueue"
        );

        let bulk = dummy_plaintext_event(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1);
        assert_eq!(decrypt_worker_event_lane(&bulk), DecryptWorkerLane::Bulk);
    }

    #[test]
    fn decrypt_worker_fallback_bulk_full_does_not_starve_priority_events() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);

        assert!(fallback_tx.send(dummy_plaintext_event(
            DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1
        )));
        assert!(
            !fallback_tx.send(dummy_plaintext_event(
                DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1
            )),
            "second bulk fallback should be dropped at the bounded bulk lane"
        );
        assert!(
            fallback_tx.send(dummy_failure_event()),
            "priority fallback should still fit its reserved lane"
        );

        assert_eq!(fallback_rx.bulk.len(), 1);
        assert_eq!(fallback_rx.priority.len(), 1);
        assert!(matches!(
            fallback_rx.priority.try_recv().expect("priority event"),
            DecryptWorkerEvent::DecryptFailure(_)
        ));
        assert!(matches!(
            fallback_rx.bulk.try_recv().expect("bulk event"),
            DecryptWorkerEvent::Plaintext(_)
        ));
    }

    #[test]
    fn decrypt_worker_fallback_bulk_capacity_counts_batch_packets() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 2);

        assert!(fallback_tx.send(dummy_plaintext_batch_event(
            2,
            DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1
        )));
        assert_eq!(
            fallback_rx.bulk_queued_packets(),
            2,
            "batch should reserve one bulk slot per packet, not per mpsc item"
        );
        assert!(
            !fallback_tx.send(dummy_plaintext_event(
                DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1
            )),
            "bulk packet cap should reject another packet while the two-packet batch is queued"
        );
        assert!(
            fallback_tx.send(dummy_failure_event()),
            "priority fallback must not consume bulk packet capacity"
        );

        let event = fallback_rx.bulk.try_recv().expect("bulk batch event");
        assert!(matches!(event, DecryptWorkerEvent::PlaintextBatch(_)));
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.bulk_queued_packets(), 0);
        assert!(fallback_tx.send(dummy_plaintext_event(
            DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1
        )));
    }

    #[test]
    fn decrypt_worker_fallback_priority_full_returns_false_without_waiting() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);

        assert!(fallback_tx.send(dummy_failure_event()));
        assert_eq!(
            fallback_rx.priority.len(),
            1,
            "test priority fallback lane should start full"
        );

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let tx_for_thread = fallback_tx.clone();
        std::thread::spawn(move || {
            done_tx
                .send(tx_for_thread.send(dummy_failure_event()))
                .unwrap();
        });

        let sent = done_rx
            .recv_timeout(Duration::from_millis(250))
            .expect("full fallback priority lane must not park decrypt worker");
        assert!(
            !sent,
            "priority fallback sender should report pressure when the lane is full"
        );
        assert_eq!(
            fallback_rx.priority.len(),
            1,
            "priority fallback lane must stay bounded"
        );

        assert!(
            fallback_tx.send(dummy_plaintext_event(
                DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1
            )),
            "full priority fallback lane must not consume bulk fallback capacity"
        );
        assert_eq!(fallback_rx.bulk.len(), 1);
        assert!(matches!(
            fallback_rx.priority.try_recv().expect("priority event"),
            DecryptWorkerEvent::DecryptFailure(_)
        ));
        assert!(matches!(
            fallback_rx.bulk.try_recv().expect("bulk event"),
            DecryptWorkerEvent::Plaintext(_)
        ));
    }

    #[test]
    fn decrypt_worker_full_queue_drops_bulk_without_waiting() {
        let (pool, _priority_rx, bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 99);
        pool.dispatch_job(dummy_bulk_decrypt_job(session_key));
        assert_eq!(bulk_rx.len(), 1, "test bulk queue should start full");

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let pool_for_thread = pool.clone();
        std::thread::spawn(move || {
            pool_for_thread.dispatch_job(dummy_bulk_decrypt_job(session_key));
            done_tx.send(()).unwrap();
        });

        done_rx
            .recv_timeout(Duration::from_millis(250))
            .expect("full decrypt-worker bulk queue must not park dispatch");
        assert_eq!(
            bulk_rx.len(),
            1,
            "bulk packet should be dropped rather than queued past the bound"
        );
    }

    #[test]
    fn decrypt_worker_priority_packet_uses_priority_lane_when_bulk_queue_is_full() {
        let (pool, priority_rx, bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 99);
        pool.dispatch_job(dummy_bulk_decrypt_job(session_key));
        assert_eq!(bulk_rx.len(), 1, "test bulk queue should start full");

        pool.dispatch_job(dummy_priority_decrypt_job(session_key));
        assert_eq!(priority_rx.len(), 1, "priority packet should enqueue");
        assert_eq!(
            bulk_rx.len(),
            1,
            "priority packet should not overflow or consume the bulk lane"
        );
    }

    #[test]
    fn decrypt_job_batcher_groups_consecutive_bulk_jobs_for_one_worker() {
        let (pool, _priority_rx, bulk_rx) = test_worker_pool(1, DECRYPT_WORKER_BULK_BATCH_MAX);
        let session_key = test_session_key(1, 101);
        let mut batcher = DecryptJobBatcher::new();

        for _ in 0..3 {
            batcher.push(&pool, dummy_bulk_decrypt_job(session_key));
        }
        batcher.flush(&pool);

        assert_eq!(
            bulk_rx[0].len(),
            1,
            "three same-worker bulk packets should consume one channel slot"
        );
        match bulk_rx[0].try_recv().expect("batched bulk item") {
            DecryptWorkerBulkItem::Batch(jobs) => {
                assert_eq!(jobs.len(), 3);
                assert!(jobs.iter().all(DecryptJob::is_bulk_lane));
            }
            DecryptWorkerBulkItem::Job(_) => panic!("expected a multi-job bulk batch"),
            DecryptWorkerBulkItem::FspJob(_) => panic!("expected a multi-job bulk batch"),
        }
    }

    #[test]
    fn decrypt_worker_bulk_batch_emits_one_plaintext_fallback_batch() {
        let session_key = test_session_key(1, 106);
        let source_peer = test_source_peer();
        let cipher = test_chacha_key([0x42; 32]);
        let mut shard = test_shard();
        shard.register_session(
            0,
            session_key,
            OwnedSessionState {
                fmp_cipher: cipher.clone(),
                fmp_replay: ReplayWindow::new(),
                source_peer,
            },
        );
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, 4);
        let (priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        drop(priority_tx);
        let bulk_body_len = DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 64;
        let (packet_one, header_one) =
            sealed_fmp_test_packet_with_link_body(&cipher, 1, 0, bulk_body_len);
        let (packet_two, header_two) =
            sealed_fmp_test_packet_with_link_body(&cipher, 2, 0, bulk_body_len);

        let mut plaintext_batch = DecryptPlaintextFallbackBatch::new();
        let processed = handle_bulk_item(
            0,
            &mut shard,
            &priority_rx,
            DecryptWorkerBulkItem::Batch(vec![
                decrypt_job_for_test_packet(
                    packet_one,
                    header_one,
                    session_key,
                    1,
                    0,
                    fallback_tx.clone(),
                ),
                decrypt_job_for_test_packet(packet_two, header_two, session_key, 2, 0, fallback_tx),
            ]),
            &mut plaintext_batch,
        );
        assert!(
            fallback_rx.bulk.try_recv().is_err(),
            "shared output batch should wait for an explicit flush"
        );
        plaintext_batch.flush();

        assert_eq!(processed, 2);
        assert_eq!(
            fallback_rx.bulk_queued_packets(),
            2,
            "one fallback batch should still reserve two bulk packet slots"
        );
        let event = fallback_rx.bulk.try_recv().expect("bulk fallback batch");
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.bulk_queued_packets(), 0);
        match event {
            DecryptWorkerEvent::PlaintextBatch(fallbacks) => {
                assert_eq!(fallbacks.len(), 2);
                assert_eq!(fallbacks[0].source_peer, source_peer);
                assert_eq!(fallbacks[1].source_peer, source_peer);
                assert_eq!(fallbacks[0].fmp_counter, 1);
                assert_eq!(fallbacks[1].fmp_counter, 2);
                assert!(fallbacks.iter().all(|fallback| {
                    fallback.packet_len > DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN
                }));
            }
            DecryptWorkerEvent::Plaintext(_)
            | DecryptWorkerEvent::AuthenticatedSession(_)
            | DecryptWorkerEvent::DirectSessionCommit(_)
            | DecryptWorkerEvent::DirectSessionCommitBatch(_)
            | DecryptWorkerEvent::DirectSessionData(_)
            | DecryptWorkerEvent::FspDecryptFailure(_)
            | DecryptWorkerEvent::DecryptFailure(_) => {
                panic!("expected plaintext fallback batch")
            }
        }
    }

    #[test]
    fn decrypt_worker_plaintext_batch_never_exceeds_fallback_packet_cap() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, 2);
        let bulk_len = DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1;
        let mut batch = DecryptPlaintextFallbackBatch::new();

        batch.push_output(DecryptWorkerOutput {
            fallback_tx: fallback_tx.clone(),
            event: dummy_plaintext_event(bulk_len),
            direct_delivery: None,
        });
        assert!(
            fallback_rx.bulk.try_recv().is_err(),
            "first packet should stay buffered until the fallback cap-width batch is full"
        );
        batch.push_output(DecryptWorkerOutput {
            fallback_tx: fallback_tx.clone(),
            event: dummy_plaintext_event(bulk_len),
            direct_delivery: None,
        });

        let event = fallback_rx.bulk.try_recv().expect("two-packet batch");
        assert_eq!(
            event.packet_count(),
            2,
            "plaintext batch should fill, but not exceed, the fallback packet cap"
        );
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.bulk_queued_packets(), 0);

        batch.push_output(DecryptWorkerOutput {
            fallback_tx,
            event: dummy_plaintext_event(bulk_len),
            direct_delivery: None,
        });
        batch.flush();

        let event = fallback_rx.bulk.try_recv().expect("single trailing packet");
        assert_eq!(event.packet_count(), 1);
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.bulk_queued_packets(), 0);
    }

    #[test]
    fn decrypt_worker_plaintext_batch_flushes_at_batch_width() {
        let cap = DECRYPT_WORKER_BULK_BATCH_MAX + 1;
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, cap);
        let bulk_len = DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1;
        let mut batch = DecryptPlaintextFallbackBatch::new();

        for _ in 0..DECRYPT_WORKER_BULK_BATCH_MAX {
            batch.push_output(DecryptWorkerOutput {
                fallback_tx: fallback_tx.clone(),
                event: dummy_plaintext_event(bulk_len),
                direct_delivery: None,
            });
        }

        let event = fallback_rx.bulk.try_recv().expect("full-width batch");
        assert_eq!(
            event.packet_count(),
            DECRYPT_WORKER_BULK_BATCH_MAX,
            "plaintext completion batches should use the configured bounded width"
        );
        fallback_rx.release_dequeued_event(&event);

        batch.push_output(DecryptWorkerOutput {
            fallback_tx,
            event: dummy_plaintext_event(bulk_len),
            direct_delivery: None,
        });
        batch.flush();

        let event = fallback_rx.bulk.try_recv().expect("single trailing packet");
        assert_eq!(event.packet_count(), 1);
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.bulk_queued_packets(), 0);
    }

    #[test]
    fn decrypt_worker_direct_endpoint_batch_waits_for_commit_queue_acceptance() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let (endpoint_tx, mut endpoint_rx) = EndpointEventSender::channel(8);
        let sink = DecryptDirectSessionDeliverySink::new(None, None, Some(endpoint_tx));
        let source_peer = test_source_peer();
        let mut batch = DecryptPlaintextFallbackBatch::new();

        batch.push_output(dummy_direct_endpoint_output(
            fallback_tx.clone(),
            sink.clone(),
            source_peer,
            1,
            b"direct-one",
        ));
        assert!(
            fallback_rx.bulk.try_recv().is_err(),
            "first endpoint completion should wait for a batch flush"
        );
        assert!(
            endpoint_rx.try_recv().is_err(),
            "endpoint bytes must not release before the commit is queued"
        );

        batch.push_output(dummy_direct_endpoint_output(
            fallback_tx,
            sink,
            source_peer,
            2,
            b"direct-two",
        ));
        assert!(
            fallback_rx.bulk.try_recv().is_err(),
            "second endpoint completion should still wait below batch cap"
        );
        assert!(
            endpoint_rx.try_recv().is_err(),
            "endpoint bytes must still wait below batch cap"
        );
        batch.flush();

        let event = fallback_rx.bulk.try_recv().expect("direct commit batch");
        assert_eq!(event.packet_count(), 2);
        match &event {
            DecryptWorkerEvent::DirectSessionCommitBatch(commits) => {
                assert_eq!(commits.len(), 2);
                assert_eq!(commits[0].source_addr, *source_peer.node_addr());
                assert_eq!(commits[1].source_addr, *source_peer.node_addr());
                assert_eq!(commits[0].fmp.fmp_counter, 1);
                assert_eq!(commits[1].fmp.fmp_counter, 2);
                assert!(commits.iter().all(|commit| !commit.delivered_ipv6));
            }
            DecryptWorkerEvent::DirectSessionCommit(_) => panic!("expected a commit batch"),
            DecryptWorkerEvent::Plaintext(_)
            | DecryptWorkerEvent::PlaintextBatch(_)
            | DecryptWorkerEvent::AuthenticatedSession(_)
            | DecryptWorkerEvent::DirectSessionData(_)
            | DecryptWorkerEvent::FspDecryptFailure(_)
            | DecryptWorkerEvent::DecryptFailure(_) => panic!("expected a direct commit batch"),
        }
        fallback_rx.release_dequeued_event(&event);

        match endpoint_rx.try_recv().expect("endpoint batch") {
            NodeEndpointEvent::DataBatch { messages, .. } => {
                assert_eq!(messages.len(), 2);
                assert_eq!(messages[0].source_peer, source_peer);
                assert_eq!(messages[1].source_peer, source_peer);
                assert_eq!(messages[0].payload, b"direct-one");
                assert_eq!(messages[1].payload, b"direct-two");
            }
            NodeEndpointEvent::Data { .. } => panic!("expected endpoint data batch"),
        }
    }

    #[test]
    fn decrypt_worker_direct_endpoint_batch_drops_delivery_when_commit_queue_is_full() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 2);
        let bulk_len = DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1;
        assert!(fallback_tx.send(dummy_plaintext_event(bulk_len)));
        assert_eq!(
            fallback_rx.bulk_queued_packets(),
            1,
            "test precondition should reserve one bulk packet slot"
        );

        let (endpoint_tx, mut endpoint_rx) = EndpointEventSender::channel(8);
        let sink = DecryptDirectSessionDeliverySink::new(None, None, Some(endpoint_tx));
        let source_peer = test_source_peer();
        let mut batch = DecryptPlaintextFallbackBatch::new();

        batch.push_output(dummy_direct_endpoint_output(
            fallback_tx.clone(),
            sink.clone(),
            source_peer,
            1,
            b"drop-one",
        ));
        batch.push_output(dummy_direct_endpoint_output(
            fallback_tx,
            sink,
            source_peer,
            2,
            b"drop-two",
        ));

        assert!(
            endpoint_rx.try_recv().is_err(),
            "endpoint bytes must not release when their commit batch cannot reserve fallback space"
        );

        let event = fallback_rx.bulk.try_recv().expect("pre-filled bulk event");
        assert!(
            matches!(event, DecryptWorkerEvent::Plaintext(_)),
            "failed endpoint commit batch must not enqueue after pressure rejection"
        );
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.bulk_queued_packets(), 0);
        assert!(
            fallback_rx.bulk.try_recv().is_err(),
            "only the pre-filled event should have reached the bulk fallback lane"
        );
    }

    #[test]
    fn decrypt_worker_direct_endpoint_delivery_accepts_bulk_payloads() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let (endpoint_tx, mut endpoint_rx) = EndpointEventSender::channel(8);
        let sink = DecryptDirectSessionDeliverySink::new(None, None, Some(endpoint_tx));
        let source_peer = test_source_peer();
        let bulk_payload = vec![0xAB; crate::node::ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1];
        let delivery = DecryptDirectSessionDelivery::EndpointData(EndpointDataDelivery::new(
            source_peer,
            bulk_payload.clone(),
        ));

        assert!(
            sink.can_deliver(&delivery),
            "direct-hop bulk endpoint payloads should not bounce through rx_loop after worker decrypt"
        );

        let mut batch = DecryptPlaintextFallbackBatch::new();
        batch.push_output(dummy_direct_endpoint_output(
            fallback_tx,
            sink,
            source_peer,
            1,
            &bulk_payload,
        ));
        batch.flush();

        let event = fallback_rx.bulk.try_recv().expect("direct commit");
        assert_eq!(event.packet_count(), 1);
        fallback_rx.release_dequeued_event(&event);

        match endpoint_rx.try_recv().expect("bulk endpoint event") {
            NodeEndpointEvent::Data { payload, .. } => assert_eq!(payload, bulk_payload),
            event => panic!("expected direct bulk endpoint data event, got {event:?}"),
        }
    }

    #[test]
    fn decrypt_worker_direct_endpoint_batch_can_span_one_worker_burst() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(
            8,
            DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX + 1,
        );
        let (endpoint_tx, mut endpoint_rx) =
            EndpointEventSender::channel(DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX + 1);
        let sink = DecryptDirectSessionDeliverySink::new(None, None, Some(endpoint_tx));
        let source_peer = test_source_peer();
        let bulk_payload = vec![0xCD; crate::node::ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1];
        let mut batch = DecryptPlaintextFallbackBatch::new();

        for idx in 0..DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX {
            batch.push_output(dummy_direct_endpoint_output(
                fallback_tx.clone(),
                sink.clone(),
                source_peer,
                idx as u64,
                &bulk_payload,
            ));
        }

        let event = fallback_rx
            .bulk
            .try_recv()
            .expect("burst-sized commit batch");
        assert_eq!(
            event.packet_count(),
            DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX
        );
        fallback_rx.release_dequeued_event(&event);

        match endpoint_rx.try_recv().expect("burst-sized endpoint batch") {
            NodeEndpointEvent::DataBatch { messages, .. } => {
                assert_eq!(messages.len(), DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX);
                assert!(
                    messages
                        .iter()
                        .all(|message| message.payload == bulk_payload)
                );
            }
            event => panic!("expected burst-sized endpoint data batch, got {event:?}"),
        }
    }

    #[test]
    fn decrypt_job_batcher_flushes_bulk_before_priority_job() {
        let (pool, priority_rx, bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 102);
        let mut batcher = DecryptJobBatcher::new();

        batcher.push(&pool, dummy_bulk_decrypt_job(session_key));
        batcher.push(&pool, dummy_priority_decrypt_job(session_key));

        assert_eq!(
            bulk_rx.len(),
            1,
            "pending bulk should be flushed before the priority job is queued"
        );
        assert_eq!(
            priority_rx.len(),
            1,
            "priority jobs must keep their reserved lane"
        );
        assert!(matches!(
            priority_rx.try_recv().expect("priority item"),
            WorkerMsg::Job(_)
        ));
        assert!(matches!(
            bulk_rx.try_recv().expect("bulk item"),
            DecryptWorkerBulkItem::Job(_)
        ));
    }

    #[test]
    fn decrypt_job_batcher_keeps_bulk_capacity_in_packet_units() {
        let (pool, _priority_rx, bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 103);
        let mut batcher = DecryptJobBatcher::new();

        batcher.push(&pool, dummy_bulk_decrypt_job(session_key));
        batcher.push(&pool, dummy_bulk_decrypt_job(session_key));
        batcher.flush(&pool);

        assert_eq!(
            bulk_rx.len(),
            1,
            "a one-packet bulk capacity should enqueue exactly one packet"
        );
        assert!(
            matches!(
                bulk_rx.try_recv().expect("single packet bulk item"),
                DecryptWorkerBulkItem::Job(_)
            ),
            "single-packet capacity must not be inflated into a wider batch"
        );
    }

    #[test]
    fn decrypt_job_batcher_reuses_pending_buffer_for_single_bulk_flush() {
        let (pool, _priority_rx, bulk_rx) = test_worker_pool(1, DECRYPT_WORKER_BULK_BATCH_MAX);
        let session_key = test_session_key(1, 104);
        let mut batcher = DecryptJobBatcher::new();
        let pending_buffer = batcher.pending_buffer_ptr();

        batcher.push(&pool, dummy_bulk_decrypt_job(session_key));
        batcher.flush(&pool);

        assert_eq!(
            batcher.pending_buffer_ptr(),
            pending_buffer,
            "single-job flushes should not allocate a replacement pending buffer"
        );
        assert!(
            matches!(
                bulk_rx[0].try_recv().expect("single bulk item"),
                DecryptWorkerBulkItem::Job(_)
            ),
            "single-job flush should still dispatch a single job, not a batch"
        );
    }

    #[test]
    fn decrypt_job_batcher_limits_batch_width_to_worker_packet_capacity() {
        const WORKER_PACKET_CAP: usize = 8;

        let (pool, _priority_rx, bulk_rx) = test_worker_pool(1, WORKER_PACKET_CAP);
        let session_key = test_session_key(1, 105);
        let mut batcher = DecryptJobBatcher::new();

        for _ in 0..=WORKER_PACKET_CAP {
            batcher.push(&pool, dummy_bulk_decrypt_job(session_key));
        }
        batcher.flush(&pool);

        assert_eq!(
            bulk_rx[0].len(),
            1,
            "worker packet capacity should be consumed by one bounded batch"
        );
        match bulk_rx[0].try_recv().expect("bounded bulk batch") {
            DecryptWorkerBulkItem::Batch(jobs) => assert_eq!(
                jobs.len(),
                WORKER_PACKET_CAP,
                "batch width should stop at the worker packet capacity"
            ),
            DecryptWorkerBulkItem::Job(_) => panic!("expected an eight-packet bulk batch"),
            DecryptWorkerBulkItem::FspJob(_) => panic!("expected an eight-packet bulk batch"),
        }
        assert!(
            bulk_rx[0].is_empty(),
            "the ninth packet should be rejected while eight packets remain queued"
        );
    }

    #[test]
    fn decrypt_worker_bulk_accounting_reserves_and_releases_exact_counts() {
        let counter = AtomicUsize::new(0);

        assert!(try_reserve_bulk_packets(&counter, 4, 3));
        assert_eq!(counter.load(Ordering::Relaxed), 3);
        assert!(
            !try_reserve_bulk_packets(&counter, 4, 2),
            "bulk packet capacity must be counted in jobs, not channel items"
        );
        release_bulk_packets(&counter, 2);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        assert!(try_reserve_bulk_packets(&counter, 4, 3));
        assert_eq!(counter.load(Ordering::Relaxed), 4);
        release_bulk_packets(&counter, 4);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn decrypt_worker_register_uses_priority_lane_when_bulk_queue_is_full() {
        let (pool, priority_rx, bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 77);
        pool.dispatch_job(dummy_bulk_decrypt_job(session_key));
        assert_eq!(bulk_rx.len(), 1, "test bulk queue should start full");

        assert!(pool.register_session(session_key, test_owned_session_state()));
        assert_eq!(priority_rx.len(), 1, "registration should enqueue");
        assert_eq!(
            bulk_rx.len(),
            1,
            "registration should not consume the full bulk lane"
        );
    }

    #[test]
    fn decrypt_worker_unregister_uses_priority_lane_when_bulk_queue_is_full() {
        let (pool, priority_rx, bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 78);
        pool.dispatch_job(dummy_bulk_decrypt_job(session_key));
        assert_eq!(bulk_rx.len(), 1, "test bulk queue should start full");

        assert!(pool.unregister_session(session_key));
        assert_eq!(priority_rx.len(), 1, "unregister should enqueue");
        assert_eq!(
            bulk_rx.len(),
            1,
            "unregister should not consume the full bulk lane"
        );
    }

    #[test]
    fn decrypt_worker_register_full_returns_false_without_waiting() {
        let (pool, priority_rx, _bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 77);
        assert!(pool.register_session(session_key, test_owned_session_state()));
        assert_eq!(
            priority_rx.len(),
            1,
            "test priority queue should start full"
        );

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let pool_for_thread = pool.clone();
        std::thread::spawn(move || {
            let registered =
                pool_for_thread.register_session(session_key, test_owned_session_state());
            done_tx.send(registered).unwrap();
        });

        let registered = done_rx
            .recv_timeout(Duration::from_millis(250))
            .expect("full decrypt-worker control queue must not park registration");
        assert!(
            !registered,
            "registration should report pressure so caller retries later"
        );
        assert_eq!(
            priority_rx.len(),
            1,
            "registration should not overflow the bounded priority queue"
        );
    }

    #[test]
    fn decrypt_worker_unregister_full_returns_false_without_waiting() {
        let (pool, priority_rx, _bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 78);
        assert!(pool.register_session(session_key, test_owned_session_state()));
        assert_eq!(
            priority_rx.len(),
            1,
            "test priority queue should start full"
        );

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let pool_for_thread = pool.clone();
        std::thread::spawn(move || {
            let unregistered = pool_for_thread.unregister_session(session_key);
            done_tx.send(unregistered).unwrap();
        });

        let unregistered = done_rx
            .recv_timeout(Duration::from_millis(250))
            .expect("full decrypt-worker control queue must not park unregister");
        assert!(
            !unregistered,
            "unregister should report pressure when the priority lane is full"
        );
        assert_eq!(
            priority_rx.len(),
            1,
            "unregister should not overflow the bounded priority queue"
        );
    }

    #[test]
    fn decrypt_worker_drain_registers_priority_before_bulk_jobs() {
        let (priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (bulk_tx, bulk_rx, bulk_queued_packets) = test_bulk_lane(1);
        let session_key = test_session_key(1, 77);
        priority_tx
            .try_send(WorkerMsg::RegisterSession {
                session_key,
                state: test_owned_session_state(),
            })
            .expect("priority registration should enqueue");

        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        let mut bulk_job = dummy_bulk_decrypt_job(session_key);
        bulk_job.fallback_tx = fallback_tx;
        queue_bulk_item_for_test(
            &bulk_tx,
            &bulk_queued_packets,
            DecryptWorkerBulkItem::Job(bulk_job),
        );

        let mut shard = test_shard();
        drain_worker_queues(0, &mut shard, &priority_rx, &bulk_rx, &bulk_queued_packets);

        assert!(
            shard.contains_session(session_key),
            "priority registration must be applied before queued bulk work"
        );
        match fallback_rx
            .priority
            .try_recv()
            .expect("bulk job should run after registration")
        {
            DecryptWorkerEvent::DecryptFailure(report) => {
                assert_eq!(report.fmp_counter, 1);
            }
            DecryptWorkerEvent::Plaintext(_) => panic!("invalid bulk job should fail AEAD"),
            DecryptWorkerEvent::PlaintextBatch(_) => panic!("invalid bulk job should fail AEAD"),
            DecryptWorkerEvent::AuthenticatedSession(_) => {
                panic!("invalid bulk job should fail AEAD")
            }
            DecryptWorkerEvent::DirectSessionCommit(_) => {
                panic!("invalid bulk job should fail AEAD")
            }
            DecryptWorkerEvent::DirectSessionCommitBatch(_) => {
                panic!("invalid bulk job should fail AEAD")
            }
            DecryptWorkerEvent::DirectSessionData(_) => {
                panic!("invalid bulk job should fail AEAD")
            }
            DecryptWorkerEvent::FspDecryptFailure(_) => {
                panic!("invalid bulk job should fail FMP AEAD")
            }
        }
        assert!(
            priority_rx.is_empty(),
            "priority queue should be fully drained before bulk"
        );
        assert!(bulk_rx.is_empty(), "bulk queue should be drained");
    }

    #[test]
    fn decrypt_worker_drain_unregisters_priority_before_bulk_jobs() {
        let (priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (bulk_tx, bulk_rx, bulk_queued_packets) = test_bulk_lane(1);
        let session_key = test_session_key(1, 78);

        priority_tx
            .try_send(WorkerMsg::UnregisterSession { session_key })
            .expect("priority unregister should enqueue");

        let (fallback_tx, fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        let mut bulk_job = dummy_bulk_decrypt_job(session_key);
        bulk_job.fallback_tx = fallback_tx;
        queue_bulk_item_for_test(
            &bulk_tx,
            &bulk_queued_packets,
            DecryptWorkerBulkItem::Job(bulk_job),
        );

        let mut shard = test_shard();
        shard.register_session(0, session_key, test_owned_session_state());
        drain_worker_queues(0, &mut shard, &priority_rx, &bulk_rx, &bulk_queued_packets);

        assert!(
            !shard.contains_session(session_key),
            "priority unregister must remove stale session state before queued bulk work"
        );
        assert!(
            fallback_rx.priority.is_empty(),
            "bulk job for unregistered session must not use stale state and emit AEAD failure"
        );
        assert!(
            fallback_rx.bulk.is_empty(),
            "bulk job for unregistered session must not produce plaintext"
        );
        assert!(
            priority_rx.is_empty(),
            "priority queue should be fully drained before bulk"
        );
        assert!(bulk_rx.is_empty(), "bulk queue should be drained");
    }

    #[test]
    fn decrypt_worker_bulk_drain_budget_matches_receive_batch_width() {
        assert_eq!(
            DECRYPT_WORKER_BULK_BURST_BUDGET, 128,
            "worker burst should track the reference packet-mover receive batch width"
        );
        assert_eq!(
            DECRYPT_WORKER_BULK_BATCH_MAX, 32,
            "bulk batches should amortize handoff churn without becoming a whole worker turn"
        );
        assert_eq!(
            DECRYPT_WORKER_BULK_BURST_BUDGET % DECRYPT_WORKER_BULK_BATCH_MAX,
            0,
            "bulk batch width should divide the worker burst budget cleanly"
        );
        assert!(
            DECRYPT_WORKER_BULK_BATCH_MAX <= DECRYPT_WORKER_BULK_BURST_BUDGET / 4,
            "one worker burst should still contain several bounded bulk batches"
        );
        assert_eq!(
            DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX, DECRYPT_WORKER_BULK_BURST_BUDGET,
            "direct endpoint delivery may coalesce one bounded worker turn after payload bytes leave the rx-loop bounce"
        );

        let (_priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (bulk_tx, bulk_rx, bulk_queued_packets) =
            test_bulk_lane(DECRYPT_WORKER_BULK_BURST_BUDGET + 1);
        let session_key = test_session_key(1, 79);
        for _ in 0..=DECRYPT_WORKER_BULK_BURST_BUDGET {
            queue_bulk_item_for_test(
                &bulk_tx,
                &bulk_queued_packets,
                DecryptWorkerBulkItem::Job(dummy_bulk_decrypt_job(session_key)),
            );
        }

        let mut shard = test_shard();
        drain_worker_queues(0, &mut shard, &priority_rx, &bulk_rx, &bulk_queued_packets);

        assert_eq!(
            bulk_rx.len(),
            1,
            "one worker drain call must respect the bounded bulk burst budget"
        );
    }

    #[test]
    fn decrypt_worker_accepts_fmp_replay_only_after_aead_success() {
        let key_bytes = [3u8; 32];
        let seal_cipher = test_chacha_key(key_bytes);
        let open_cipher = test_chacha_key(key_bytes);
        let session_key = test_session_key(1, 79);
        let mut shard = test_shard();
        shard.register_session(
            0,
            session_key,
            OwnedSessionState {
                fmp_cipher: open_cipher,
                fmp_replay: ReplayWindow::new(),
                source_peer: test_source_peer(),
            },
        );
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, 4);
        let counter = 7;
        let flags = crate::node::wire::FLAG_CE | crate::node::wire::FLAG_SP;

        let (invalid_packet, invalid_header) = invalid_fmp_test_packet(flags);
        shard
            .handle_job(decrypt_job_for_test_packet(
                invalid_packet,
                invalid_header,
                session_key,
                counter,
                flags,
                fallback_tx.clone(),
            ))
            .expect("invalid worker job should be handled");
        match fallback_rx
            .priority
            .try_recv()
            .expect("AEAD failure report")
        {
            DecryptWorkerEvent::DecryptFailure(report) => {
                assert_eq!(report.fmp_counter, counter);
                assert_eq!(
                    report.fmp_replay_highest, 0,
                    "failed AEAD must report the old replay high-water mark"
                );
            }
            DecryptWorkerEvent::Plaintext(_) => panic!("invalid packet must not produce plaintext"),
            DecryptWorkerEvent::PlaintextBatch(_) => {
                panic!("invalid packet must not produce plaintext")
            }
            DecryptWorkerEvent::AuthenticatedSession(_) => {
                panic!("invalid packet must not produce plaintext")
            }
            DecryptWorkerEvent::DirectSessionCommit(_) => {
                panic!("invalid packet must not produce plaintext")
            }
            DecryptWorkerEvent::DirectSessionCommitBatch(_) => {
                panic!("invalid packet must not produce plaintext")
            }
            DecryptWorkerEvent::DirectSessionData(_) => {
                panic!("invalid packet must not produce plaintext")
            }
            DecryptWorkerEvent::FspDecryptFailure(_) => {
                panic!("invalid packet must fail FMP AEAD")
            }
        }
        assert_eq!(
            shard.fmp_replay_highest(session_key).unwrap(),
            0,
            "failed AEAD must not consume the worker-owned replay window"
        );

        let (valid_packet, valid_header) = sealed_fmp_test_packet(&seal_cipher, counter, flags);
        shard
            .handle_job(decrypt_job_for_test_packet(
                valid_packet,
                valid_header,
                session_key,
                counter,
                flags,
                fallback_tx.clone(),
            ))
            .expect("valid worker job should be handled");
        assert!(
            matches!(
                fallback_rx.priority.try_recv().expect("plaintext fallback"),
                DecryptWorkerEvent::Plaintext(_)
            ),
            "valid packet must bounce plaintext after FMP decrypt"
        );
        assert_eq!(
            shard.fmp_replay_highest(session_key).unwrap(),
            counter,
            "successful AEAD must advance the worker-owned replay window"
        );

        let (replay_packet, replay_header) = sealed_fmp_test_packet(&seal_cipher, counter, flags);
        shard
            .handle_job(decrypt_job_for_test_packet(
                replay_packet,
                replay_header,
                session_key,
                counter,
                flags,
                fallback_tx,
            ))
            .expect("replay worker job should be handled");
        assert!(
            fallback_rx.priority.is_empty(),
            "replayed counter must be dropped before plaintext or failure events"
        );
        assert!(
            fallback_rx.bulk.is_empty(),
            "replayed counter must not reach the bulk fallback lane"
        );
    }

    #[test]
    fn owned_session_state_open_fmp_owns_replay_acceptance() {
        let key_bytes = [4u8; 32];
        let seal_cipher = test_chacha_key(key_bytes);
        let open_cipher = test_chacha_key(key_bytes);
        let counter = 9;
        let flags = crate::node::wire::FLAG_CE | crate::node::wire::FLAG_SP;
        let mut state = OwnedSessionState {
            fmp_cipher: open_cipher,
            fmp_replay: ReplayWindow::new(),
            source_peer: test_source_peer(),
        };

        let (mut invalid_packet, invalid_header) = invalid_fmp_test_packet(flags);
        let err = state
            .open_fmp_in_place(
                &mut invalid_packet,
                crate::node::wire::ESTABLISHED_HEADER_SIZE,
                counter,
                &invalid_header,
            )
            .expect_err("invalid AEAD must not open");
        assert_eq!(
            err,
            FmpOpenError::Aead {
                fmp_replay_highest: 0
            }
        );
        assert_eq!(
            state.fmp_replay.highest(),
            0,
            "failed AEAD must not advance the owned replay window"
        );

        let (mut valid_packet, valid_header) = sealed_fmp_test_packet(&seal_cipher, counter, flags);
        let outcome = state
            .open_fmp_in_place(
                &mut valid_packet,
                crate::node::wire::ESTABLISHED_HEADER_SIZE,
                counter,
                &valid_header,
            )
            .expect("valid AEAD must open");
        assert_eq!(outcome.plaintext_len, 5);
        assert_eq!(
            state.fmp_replay.highest(),
            counter,
            "successful AEAD must accept the counter in the same owner"
        );

        let (mut replay_packet, replay_header) =
            sealed_fmp_test_packet(&seal_cipher, counter, flags);
        let err = state
            .open_fmp_in_place(
                &mut replay_packet,
                crate::node::wire::ESTABLISHED_HEADER_SIZE,
                counter,
                &replay_header,
            )
            .expect_err("replayed counter must be rejected before AEAD");
        assert_eq!(err, FmpOpenError::Replay);
        assert_eq!(
            state.fmp_replay.highest(),
            counter,
            "replay rejection must leave the owned replay window unchanged"
        );
    }

    #[test]
    fn decrypt_worker_shard_owns_register_and_unregister_state() {
        let session_key = test_session_key(2, 80);
        let mut shard = test_shard();

        assert!(
            !shard.contains_session(session_key),
            "new shard starts without session state"
        );
        shard.handle_msg(
            0,
            WorkerMsg::RegisterSession {
                session_key,
                state: test_owned_session_state(),
            },
        );
        assert!(
            shard.contains_session(session_key),
            "registration must populate shard-owned state"
        );

        shard.handle_msg(0, WorkerMsg::UnregisterSession { session_key });
        assert!(
            !shard.contains_session(session_key),
            "unregister must remove shard-owned state"
        );
    }

    /// `DecryptJob.fmp_flags` must survive the worker bounce as
    /// `DecryptFallback.fmp_flags`. Pre-fix the worker hardcoded
    /// `fmp_flags: 0`, dropping CE / SP on every packet handled by
    /// the production worker path (i.e. every bulk-data packet).
    /// Loss of CE wrecks ECN propagation; loss of SP wrecks
    /// spin-bit RTT observation.
    ///
    /// Drives the worker's `handle_job` directly: build an FMP wire
    /// packet sealed with a known cipher, ship a `DecryptJob` with
    /// non-zero flags through, observe the resulting `DecryptFallback`.
    #[test]
    fn worker_preserves_fmp_flags_through_fallback() {
        let key_bytes = [0u8; 32];
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        // Both the sealing cipher (for building the test packet) and
        // the worker's owning cipher are clones of the same key.
        let seal_cipher = LessSafeKey::new(unbound);
        let unbound2 = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        let open_cipher = LessSafeKey::new(unbound2);

        let counter: u64 = 7;
        const HDR: usize = crate::node::wire::ESTABLISHED_HEADER_SIZE;
        // Build a wire packet `[16-byte header][4-byte inner ts][1 byte link msg]`
        // with capacity for the trailing AEAD tag. Header bytes
        // double as AAD and as the on-wire prefix.
        let mut wire = Vec::with_capacity(HDR + 4 + 1 + 16);
        // Header: fill the flags byte (the second byte) with both
        // FLAG_CE and FLAG_SP set; the rest is uninterpreted by the
        // worker (it just AADs the whole 16 bytes).
        let flags_byte = crate::node::wire::FLAG_CE | crate::node::wire::FLAG_SP;
        let mut header = [0u8; HDR];
        header[1] = flags_byte;
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&[0u8; 4]); // inner ts placeholder
        wire.push(0xAB); // a single byte of "link message" payload

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = ring::aead::Nonce::assume_unique_for_key(nonce_bytes);
        let (hdr_slice, payload_slice) = wire.split_at_mut(HDR);
        let tag = seal_cipher
            .seal_in_place_separate_tag(nonce, ring::aead::Aad::from(&*hdr_slice), payload_slice)
            .unwrap();
        wire.extend_from_slice(tag.as_ref());

        // Owning state held by the worker for this session.
        let session_key = test_session_key(1, 99);
        let mut shard = test_shard();
        let source_peer = test_source_peer();
        shard.register_session(
            0,
            session_key,
            OwnedSessionState {
                fmp_cipher: open_cipher,
                fmp_replay: ReplayWindow::new(),
                source_peer,
            },
        );

        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);

        let job = DecryptJob::new(
            wire,
            session_key,
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *source_peer.node_addr(),
            1_000,
            counter,
            flags_byte,
            header,
            HDR,
            fallback_tx,
        );

        shard.handle_job(job).expect("worker job handled");

        let event = fallback_rx.priority.try_recv().expect("fallback delivered");
        let fallback = match event {
            DecryptWorkerEvent::Plaintext(fallback) => fallback,
            DecryptWorkerEvent::DecryptFailure(_) => panic!("expected plaintext fallback event"),
            DecryptWorkerEvent::PlaintextBatch(_) => panic!("expected plaintext fallback event"),
            DecryptWorkerEvent::AuthenticatedSession(_) => {
                panic!("expected plaintext fallback event")
            }
            DecryptWorkerEvent::DirectSessionCommit(_) => {
                panic!("expected plaintext fallback event")
            }
            DecryptWorkerEvent::DirectSessionCommitBatch(_) => {
                panic!("expected plaintext fallback event")
            }
            DecryptWorkerEvent::DirectSessionData(_) => {
                panic!("expected plaintext fallback event")
            }
            DecryptWorkerEvent::FspDecryptFailure(_) => {
                panic!("expected plaintext fallback event")
            }
        };
        assert_eq!(
            fallback.source_peer, source_peer,
            "plaintext fallback must carry the worker-registered source peer"
        );
        assert_eq!(
            fallback.fmp_flags, flags_byte,
            "fmp_flags must round-trip from DecryptJob to DecryptFallback"
        );
        assert!(
            fallback.fmp_flags & crate::node::wire::FLAG_CE != 0,
            "FLAG_CE bit lost on worker path"
        );
        assert!(
            fallback.fmp_flags & crate::node::wire::FLAG_SP != 0,
            "FLAG_SP bit lost on worker path"
        );
    }

    #[test]
    fn worker_reports_fmp_aead_failure_to_rx_loop() {
        let key_bytes = [0u8; 32];
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        let open_cipher = LessSafeKey::new(unbound);

        let counter: u64 = 11;
        const HDR: usize = crate::node::wire::ESTABLISHED_HEADER_SIZE;
        let header = [0u8; HDR];
        let mut wire = Vec::with_capacity(HDR + 4 + 1 + 16);
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&[0u8; 4]);
        wire.push(0xAB);
        wire.extend_from_slice(&[0u8; 16]); // invalid AEAD tag

        let session_key = test_session_key(1, 77);
        let mut shard = test_shard();
        let source_peer = test_source_peer();
        shard.register_session(
            0,
            session_key,
            OwnedSessionState {
                fmp_cipher: open_cipher,
                fmp_replay: ReplayWindow::new(),
                source_peer,
            },
        );

        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        let job = DecryptJob::new(
            wire,
            session_key,
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *source_peer.node_addr(),
            1_000,
            counter,
            0,
            header,
            HDR,
            fallback_tx,
        );

        shard.handle_job(job).expect("worker job handled");

        let event = fallback_rx.priority.try_recv().expect("failure delivered");
        match event {
            DecryptWorkerEvent::DecryptFailure(report) => {
                assert_eq!(report.source_peer, source_peer);
                assert_eq!(report.fmp_counter, counter);
            }
            DecryptWorkerEvent::Plaintext(_) => panic!("expected decrypt failure report"),
            DecryptWorkerEvent::PlaintextBatch(_) => panic!("expected decrypt failure report"),
            DecryptWorkerEvent::AuthenticatedSession(_) => {
                panic!("expected decrypt failure report")
            }
            DecryptWorkerEvent::DirectSessionCommit(_) => {
                panic!("expected decrypt failure report")
            }
            DecryptWorkerEvent::DirectSessionCommitBatch(_) => {
                panic!("expected decrypt failure report")
            }
            DecryptWorkerEvent::DirectSessionData(_) => {
                panic!("expected decrypt failure report")
            }
            DecryptWorkerEvent::FspDecryptFailure(_) => panic!("expected decrypt failure report"),
        }
    }
}
