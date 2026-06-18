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
use crate::transport::{PacketBuffer, TransportAddr, TransportId};
use crate::upper::tun::TunTx;
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use ring::aead::{Aad, LessSafeKey, Nonce};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::mpsc::{
    Receiver as TokioReceiver, Sender as TokioSender, error::TrySendError as TokioTrySendError,
};
use tracing::{debug, trace, warn};

// `endpoint_event_tx` used to ride on every `DecryptJob`, bloating the hot
// packet shape with an extra Arc clone and accidentally gating TUN-only worker
// use. Keep it pool-owned instead: workers may deliver direct-hop endpoint data
// after the direct-session commit is accepted by the rx-loop bookkeeping lane.

use crate::noise::{ReplayRejection, ReplayWindow};

const DEFAULT_DECRYPT_WORKER_BULK_CHANNEL_CAP: usize = 32768;
const DEFAULT_DECRYPT_WORKER_CONTROL_CHANNEL_CAP: usize = 1024;
const DEFAULT_DECRYPT_WORKER_PRIORITY_CHANNEL_CAP: usize = 1024;
const DEFAULT_DECRYPT_FALLBACK_BULK_CHANNEL_CAP: usize = 32768;
const DEFAULT_DECRYPT_FALLBACK_PRIORITY_CHANNEL_CAP: usize = 1024;
/// Emit the backlog-high event before already-decrypted bulk completions can
/// crowd out priority/control work. The receive loop no longer expands its
/// drain budget under pressure, so this is an observability threshold, not a
/// trigger for a second packet path.
pub(crate) const DECRYPT_FALLBACK_BACKLOG_HIGH_WATER: usize = 256;
const DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN: usize = 512;
const DECRYPT_WORKER_BULK_BURST_BUDGET: usize = 128;
const DECRYPT_WORKER_BULK_BATCH_MAX: usize = 32;
const DECRYPT_WORKER_AEAD_COMPLETION_DRAIN_BUDGET: usize = DECRYPT_WORKER_BULK_BATCH_MAX;
const DECRYPT_WORKER_AEAD_COMPLETION_INTERLEAVE_BUDGET: usize = DECRYPT_WORKER_BULK_BATCH_MAX;
const DECRYPT_WORKER_FMP_RECEIVE_WINDOW_RESERVE: usize = 64;
const DECRYPT_WORKER_FSP_RECEIVE_WINDOW_RESERVE: usize = 64;
const DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX: usize = DECRYPT_WORKER_BULK_BATCH_MAX;
const DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX: usize = DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX;
const DEFAULT_DECRYPT_FSP_OPEN_WORKER_MAX_COMPLETION_BACKLOG: usize = 128;
/// Keep the common same-owner FSP bulk path on the session owner by default.
/// The opener worker remains available as an explicit experiment, but local
/// bulk traffic can otherwise bounce through an ordered completion lane and
/// build receive-side queue residence under ordinary LAN TCP transfers.
const DEFAULT_DECRYPT_FSP_LOCAL_BULK_OPEN_WORKER: bool = false;
/// Remote FSP bulk packets commonly arrive on an FMP owner that is not the FSP
/// session owner. Keep the default on the owner handoff lane so pressure cannot
/// create a second completion/backlog path; the remote open worker remains an
/// explicit throughput experiment that preserves the FIPS wire protocol.
const DEFAULT_DECRYPT_FSP_REMOTE_BULK_OPEN_WORKER: bool = false;
/// Keep FMP receive sessions on the same peer-derived owner as FSP receive
/// sessions by default. This removes the direct-peer hash lottery between
/// local and handoff FSP lanes while preserving the wire protocol.
const DEFAULT_DECRYPT_FMP_SOURCE_AFFINE_SESSION_OWNER: bool = true;
const DEFAULT_DECRYPT_FMP_AEAD_HELPER_MAX_COMPLETION_BACKLOG: usize = 64;
/// Match one owner-side completion interleave slice so a helper can return a
/// full bounded packet-mover turn without spending it across multiple messages.
const DEFAULT_DECRYPT_WORKER_FMP_AEAD_COMPLETION_BATCH_MAX: usize =
    DECRYPT_WORKER_AEAD_COMPLETION_INTERLEAVE_BUDGET;
const DEFAULT_DECRYPT_WORKER_FSP_AEAD_COMPLETION_BATCH_MAX: usize =
    DECRYPT_WORKER_AEAD_COMPLETION_INTERLEAVE_BUDGET;
/// Keep FMP opens on the session owner by default. The helper lane remains an
/// explicit experiment, but the simpler owner path avoids a second ordered
/// completion queue and has been more reliable under connected UDP pressure.
const DEFAULT_DECRYPT_FMP_AEAD_HELPERS: usize = 0;
static NEXT_FMP_RECEIVE_ORDER_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_FSP_RECEIVE_ORDER_ID: AtomicU64 = AtomicU64::new(1);

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
fn decrypt_fsp_open_worker_fast_hash(source_addr: &NodeAddr) -> u64 {
    mix_decrypt_session_hash(decrypt_fsp_session_fast_hash(source_addr) ^ 0xd1b5_4a32_d192_ed03)
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

fn control_channel_cap() -> usize {
    let control_cap = std::env::var("FIPS_DECRYPT_WORKER_CONTROL_CHANNEL_CAP").ok();
    parse_channel_cap(
        control_cap.as_deref(),
        None,
        DEFAULT_DECRYPT_WORKER_CONTROL_CHANNEL_CAP,
    )
}

fn fmp_receive_window_from_bulk_cap(bulk_cap: usize) -> usize {
    bulk_cap
        .max(1)
        .saturating_add(DECRYPT_WORKER_FMP_RECEIVE_WINDOW_RESERVE)
        .min(crate::noise::REPLAY_WINDOW_SIZE)
}

fn fmp_receive_window() -> usize {
    static VALUE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| fmp_receive_window_from_bulk_cap(bulk_channel_cap()))
}

fn fmp_aead_completion_channel_cap_from_bulk_cap(bulk_cap: usize) -> usize {
    // Keep completion headroom aligned with the ordered ticket window.
    fmp_receive_window_from_bulk_cap(bulk_cap)
}

fn fsp_receive_window_from_bulk_cap(bulk_cap: usize) -> usize {
    bulk_cap
        .max(1)
        .saturating_add(DECRYPT_WORKER_FSP_RECEIVE_WINDOW_RESERVE)
}

fn fsp_receive_window() -> usize {
    static VALUE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| fsp_receive_window_from_bulk_cap(bulk_channel_cap()))
}

fn fsp_aead_completion_channel_cap_from_bulk_cap(bulk_cap: usize) -> usize {
    // The channel stores completion batches, but pressure safety has to hold
    // when completions arrive singly. Match the ordered ticket window so a
    // helper/open worker cannot block merely because it used the advertised
    // FSP receive headroom.
    fsp_receive_window_from_bulk_cap(bulk_cap)
}

fn fsp_aead_completion_batch_max_from_raw(raw: Option<&str>) -> usize {
    raw.and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_DECRYPT_WORKER_FSP_AEAD_COMPLETION_BATCH_MAX)
        .clamp(1, 64)
}

fn fsp_aead_completion_batch_max() -> usize {
    static VALUE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| {
        fsp_aead_completion_batch_max_from_raw(
            std::env::var("FIPS_DECRYPT_FSP_AEAD_COMPLETION_BATCH_MAX")
                .ok()
                .as_deref(),
        )
    })
}

fn fmp_aead_completion_batch_max_from_raw(raw: Option<&str>) -> usize {
    raw.and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_DECRYPT_WORKER_FMP_AEAD_COMPLETION_BATCH_MAX)
        .clamp(1, 64)
}

fn fmp_aead_completion_batch_max() -> usize {
    static VALUE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| {
        fmp_aead_completion_batch_max_from_raw(
            std::env::var("FIPS_DECRYPT_FMP_AEAD_COMPLETION_BATCH_MAX")
                .ok()
                .as_deref(),
        )
    })
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

fn fsp_open_worker_max_completion_backlog_from_raw(
    raw: Option<&str>,
    completion_cap: usize,
) -> usize {
    raw.and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_DECRYPT_FSP_OPEN_WORKER_MAX_COMPLETION_BACKLOG)
        .min(completion_cap)
}

fn fsp_open_worker_max_completion_backlog() -> usize {
    static VALUE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| {
        fsp_open_worker_max_completion_backlog_from_raw(
            std::env::var("FIPS_DECRYPT_FSP_OPEN_WORKER_MAX_COMPLETION_BACKLOG")
                .ok()
                .as_deref(),
            fsp_aead_completion_channel_cap_from_bulk_cap(bulk_channel_cap()),
        )
    })
}

fn fmp_aead_helper_max_completion_backlog_from_raw(
    raw: Option<&str>,
    completion_cap: usize,
) -> usize {
    raw.and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_DECRYPT_FMP_AEAD_HELPER_MAX_COMPLETION_BACKLOG)
        .min(completion_cap)
}

fn fmp_aead_helper_max_completion_backlog() -> usize {
    static VALUE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| {
        fmp_aead_helper_max_completion_backlog_from_raw(
            std::env::var("FIPS_DECRYPT_FMP_AEAD_HELPER_MAX_COMPLETION_BACKLOG")
                .ok()
                .as_deref(),
            fmp_aead_completion_channel_cap_from_bulk_cap(bulk_channel_cap()),
        )
    })
}

fn enabled_from_raw_with_default(raw: Option<&str>, default: bool) -> bool {
    raw.map(|raw| {
        !matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off"
        )
    })
    .unwrap_or(default)
}

fn fsp_local_bulk_open_worker_enabled_from_raw(raw: Option<&str>) -> bool {
    enabled_from_raw_with_default(raw, DEFAULT_DECRYPT_FSP_LOCAL_BULK_OPEN_WORKER)
}

fn fsp_local_bulk_open_worker_enabled() -> bool {
    fsp_local_bulk_open_worker_enabled_from_raw(
        std::env::var("FIPS_DECRYPT_FSP_LOCAL_BULK_OPEN_WORKER")
            .ok()
            .as_deref(),
    )
}

fn fsp_remote_bulk_open_worker_enabled_from_raw(raw: Option<&str>) -> bool {
    enabled_from_raw_with_default(raw, DEFAULT_DECRYPT_FSP_REMOTE_BULK_OPEN_WORKER)
}

fn fsp_remote_bulk_open_worker_enabled() -> bool {
    fsp_remote_bulk_open_worker_enabled_from_raw(
        std::env::var("FIPS_DECRYPT_FSP_REMOTE_BULK_OPEN_WORKER")
            .ok()
            .as_deref(),
    )
}

fn fmp_source_affine_session_owner_enabled_from_raw(raw: Option<&str>) -> bool {
    enabled_from_raw_with_default(raw, DEFAULT_DECRYPT_FMP_SOURCE_AFFINE_SESSION_OWNER)
}

fn fmp_source_affine_session_owner_enabled() -> bool {
    fmp_source_affine_session_owner_enabled_from_raw(
        std::env::var("FIPS_DECRYPT_FMP_SOURCE_AFFINE_SESSION_OWNER")
            .ok()
            .as_deref(),
    )
}

fn fmp_aead_helper_count_from_raw(raw: Option<&str>) -> usize {
    raw.and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_DECRYPT_FMP_AEAD_HELPERS)
        .min(64)
}

fn fmp_aead_helper_count() -> usize {
    fmp_aead_helper_count_from_raw(
        std::env::var("FIPS_DECRYPT_FMP_AEAD_HELPERS")
            .ok()
            .as_deref(),
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
/// **FMP first** — the worker owns FMP decrypt + replay accept. It returns
/// compact receive bookkeeping for timestamp-only frames, decodes direct local
/// established-session data once FSP state is registered, and only falls back
/// to authenticated FMP plaintext when rx_loop still owns the link dispatch.
/// This split is what makes register-at-FMP-establishment correct: the worker
/// can become authoritative for FMP replay before the FSP handshake completes.
///
/// Built at FMP-session establishment time (`promote_connection`)
/// and shipped to the assigned worker via `WorkerMsg::RegisterSession`.
pub(crate) struct OwnedSessionState {
    fmp_cipher: Arc<LessSafeKey>,
    fmp_replay: ReplayWindow,
    source_peer: PeerIdentity,
    fmp_receive_order_id: u64,
    fmp_receive_order: FmpReceiveOrder,
}

struct OwnedFspEpochState {
    cipher: Arc<LessSafeKey>,
    replay: ReplayWindow,
}

pub(crate) struct OwnedFspSessionState {
    source_peer: PeerIdentity,
    current_k_bit: bool,
    current: OwnedFspEpochState,
    pending: Option<OwnedFspEpochState>,
    previous: Option<OwnedFspEpochState>,
    fsp_receive_order_id: u64,
    fsp_receive_order: FspReceiveOrder,
    fsp_shared_crypto: Option<Arc<FspSharedCryptoSession>>,
}

#[derive(Clone, Copy)]
struct FspReceiveProgress {
    next_ticket: u64,
    next_ready: u64,
}

struct FspOpenSuccess {
    plaintext: Vec<u8>,
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
                cipher: Arc::new(snapshot.current.cipher),
                replay: snapshot.current.replay,
            },
            pending: snapshot.pending.map(|epoch| OwnedFspEpochState {
                cipher: Arc::new(epoch.cipher),
                replay: epoch.replay,
            }),
            previous: snapshot.previous.map(|epoch| OwnedFspEpochState {
                cipher: Arc::new(epoch.cipher),
                replay: epoch.replay,
            }),
            fsp_receive_order_id: NEXT_FSP_RECEIVE_ORDER_ID.fetch_add(1, Ordering::Relaxed),
            fsp_receive_order: FspReceiveOrder::new(),
            fsp_shared_crypto: None,
        }
    }
}

struct FspSharedCryptoSession {
    owner_idx: usize,
    receive_order_id: u64,
    current_k_bit: bool,
    cipher: Arc<LessSafeKey>,
    next_ticket: AtomicU64,
    next_ready: AtomicU64,
}

impl FspSharedCryptoSession {
    #[cfg(test)]
    fn new(
        owner_idx: usize,
        receive_order_id: u64,
        current_k_bit: bool,
        cipher: Arc<LessSafeKey>,
    ) -> Self {
        Self::new_with_progress(
            owner_idx,
            receive_order_id,
            current_k_bit,
            cipher,
            FspReceiveProgress {
                next_ticket: 0,
                next_ready: 0,
            },
        )
    }

    fn new_with_progress(
        owner_idx: usize,
        receive_order_id: u64,
        current_k_bit: bool,
        cipher: Arc<LessSafeKey>,
        progress: FspReceiveProgress,
    ) -> Self {
        Self {
            owner_idx,
            receive_order_id,
            current_k_bit,
            cipher,
            next_ticket: AtomicU64::new(progress.next_ticket),
            next_ready: AtomicU64::new(progress.next_ready),
        }
    }

    #[cfg(test)]
    fn can_issue_ticket(&self) -> bool {
        self.next_ticket
            .load(Ordering::Relaxed)
            .saturating_sub(self.next_ready.load(Ordering::Relaxed))
            < fsp_receive_window() as u64
    }

    fn try_issue_ticket(&self) -> Option<FspReceiveTicket> {
        self
            .next_ticket
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                let in_flight = current.saturating_sub(self.next_ready.load(Ordering::Relaxed));
                (in_flight < fsp_receive_window() as u64).then(|| current.saturating_add(1))
            })
            .ok()
            .map(|sequence| FspReceiveTicket { sequence })
    }

    #[cfg(test)]
    fn issue_ticket(&self) -> FspReceiveTicket {
        self.try_issue_ticket()
            .expect("FSP receive-order test ticket window is full")
    }

    fn mark_next_ready(&self, next_ready: u64) {
        self.next_ready.store(next_ready, Ordering::Relaxed);
    }

    fn progress(&self) -> FspReceiveProgress {
        FspReceiveProgress {
            next_ticket: self.next_ticket.load(Ordering::Relaxed),
            next_ready: self.next_ready.load(Ordering::Relaxed),
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

    fn open_in_place_deferred_replay(
        &self,
        ciphertext: &mut [u8],
        counter: u64,
        aad: &[u8],
    ) -> Result<usize, FspOpenError> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        self.cipher
            .open_in_place(nonce, Aad::from(aad), ciphertext)
            .map(|plaintext| plaintext.len())
            .map_err(|_| FspOpenError::Aead)
    }
}

impl OwnedFspSessionState {
    fn has_single_current_epoch(&self) -> bool {
        self.pending.is_none() && self.previous.is_none()
    }

    fn receive_progress(&self) -> FspReceiveProgress {
        self.fsp_shared_crypto
            .as_ref()
            .map(|shared| shared.progress())
            .unwrap_or_else(|| FspReceiveProgress {
                next_ticket: self.fsp_receive_order.next_ticket(),
                next_ready: self.fsp_receive_order_next_ready(),
            })
    }

    fn shared_crypto_session(&self, owner_idx: usize) -> Option<FspSharedCryptoSession> {
        self.has_single_current_epoch().then(|| {
            FspSharedCryptoSession::new_with_progress(
                owner_idx,
                self.fsp_receive_order_id,
                self.current_k_bit,
                Arc::clone(&self.current.cipher),
                self.receive_progress(),
            )
        })
    }

    fn attach_shared_crypto_session(&mut self, shared: Arc<FspSharedCryptoSession>) {
        self.fsp_shared_crypto = Some(shared);
    }

    fn preserve_receive_order_from(&mut self, previous: OwnedFspSessionState) {
        let progress = previous.receive_progress();
        self.fsp_receive_order_id = previous.fsp_receive_order_id;
        self.fsp_receive_order = previous.fsp_receive_order;
        self.fsp_receive_order
            .advance_next_ticket_to(progress.next_ticket);
        self.fsp_shared_crypto = None;
    }

    fn fsp_receive_order_id(&self) -> u64 {
        self.fsp_receive_order_id
    }

    fn fsp_receive_order_next_ready(&self) -> u64 {
        self.fsp_receive_order.completions.next_ready()
    }

    fn current_epoch_matches(&self, header: &FspEncryptedHeader) -> bool {
        (header.flags & FSP_FLAG_K != 0) == self.current_k_bit
    }

    fn issue_fsp_receive_ticket(&mut self) -> Option<FspReceiveTicket> {
        if let Some(shared) = &self.fsp_shared_crypto {
            return shared.try_issue_ticket();
        }
        self.fsp_receive_order.issue()
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
        let mut replay_rejection = None;
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
                Err(FspOpenError::Replay) => {
                    saw_replay = true;
                    if replay_rejection.is_none()
                        && let Some(reason) = epoch.replay.rejection_reason(header.counter)
                    {
                        replay_rejection = Some((
                            reason,
                            epoch.replay.highest().saturating_sub(header.counter),
                        ));
                    }
                }
                Err(FspOpenError::Aead) => {}
            }
        }

        if saw_replay {
            if let Some((reason, counter_lag)) = replay_rejection {
                crate::perf_profile::record_decrypt_fsp_worker_replay_drop_reason(
                    reason,
                    counter_lag,
                );
            }
            Err(FspOpenError::Replay)
        } else {
            Err(FspOpenError::Aead)
        }
    }

    fn open_current_established_frame_in_place_deferred_replay(
        &mut self,
        header: &FspEncryptedHeader,
        ciphertext: &mut [u8],
    ) -> Result<usize, FspOpenError> {
        debug_assert!(self.has_single_current_epoch());
        self.current
            .open_in_place_deferred_replay(ciphertext, header.counter, &header.header_bytes)
    }

    fn accept_opened_current_established_frame(
        &mut self,
        header: &FspEncryptedHeader,
    ) -> Result<EpochSlot, FspOpenError> {
        debug_assert!(self.has_single_current_epoch());
        if header.flags & FSP_FLAG_K != u8::from(self.current_k_bit) * FSP_FLAG_K {
            return Err(FspOpenError::Aead);
        }
        if let Some(rejection) = self.current.replay.rejection_reason(header.counter) {
            let counter_lag = self.current.replay.highest().saturating_sub(header.counter);
            crate::perf_profile::record_fsp_aead_completion_replay_drop_reason(
                rejection,
                counter_lag,
            );
            return Err(FspOpenError::Replay);
        }
        self.current.replay.accept(header.counter);
        Ok(EpochSlot::Current)
    }

    fn complete_ordered_fsp_open(
        &mut self,
        ticket: FspReceiveTicket,
        completion: FspOrderedCompletion,
    ) -> Result<FspOrderedDrain, OrderedCompletionError> {
        let mut ready = Vec::new();
        let ready_count = self
            .fsp_receive_order
            .complete(ticket, completion, |completion| ready.push(completion))?;

        let mut drain = FspOrderedDrain {
            ready: ready_count,
            ..FspOrderedDrain::default()
        };
        for completion in ready {
            match completion {
                FspOrderedCompletion::Opened { opened, source } => {
                    match self.accept_opened_current_established_frame(&opened.header) {
                        Ok(slot) => {
                            drain.accepted += 1;
                            drain.outputs.push(FspReadyCompletion::Opened {
                                opened,
                                slot,
                                source_peer: self.source_peer,
                            });
                        }
                        Err(FspOpenError::Replay) => {
                            drain.replay_drops += 1;
                            drain.replay_drop_sources.add(source);
                            crate::perf_profile::record_event(
                                crate::perf_profile::Event::DecryptFspWorkerReplayDropped,
                            );
                        }
                        Err(FspOpenError::Aead) => {
                            drain.aead_failures += 1;
                            drain.aead_failure_sources.add(source);
                            crate::perf_profile::record_fsp_aead_completion_accept_kbit_mismatch();
                        }
                    }
                }
                FspOrderedCompletion::AeadFailed {
                    job,
                    header,
                    source,
                } => {
                    drain.aead_failures += 1;
                    drain.aead_failure_sources.add(source);
                    drain
                        .outputs
                        .push(FspReadyCompletion::AeadFailed { job, header });
                }
                FspOrderedCompletion::EpochMismatch {
                    job,
                    header,
                    source,
                } => {
                    let _ = source;
                    drain.epoch_mismatches += 1;
                    drain
                        .outputs
                        .push(FspReadyCompletion::AeadFailed { job, header });
                }
                FspOrderedCompletion::Dropped { source } => {
                    let _ = source;
                    drain.dropped += 1;
                }
            }
        }
        Ok(drain)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FspReceiveTicket {
    sequence: u64,
}

type FmpReceiveTicket = FspReceiveTicket;

#[derive(Debug)]
enum OrderedCompletionError {
    Stale,
    Duplicate,
    WindowExceeded,
}

#[derive(Debug)]
struct OrderedCompletionBuffer<T> {
    next_ready: u64,
    pending: VecDeque<Option<T>>,
    pending_limit: usize,
}

impl<T> OrderedCompletionBuffer<T> {
    fn new(pending_limit: usize) -> Self {
        Self {
            next_ready: 0,
            pending: VecDeque::new(),
            pending_limit: pending_limit.max(1),
        }
    }

    fn complete(
        &mut self,
        ticket: FspReceiveTicket,
        completion: T,
        mut on_ready: impl FnMut(T),
    ) -> Result<usize, OrderedCompletionError> {
        if ticket.sequence < self.next_ready {
            return Err(OrderedCompletionError::Stale);
        }

        let offset = (ticket.sequence - self.next_ready) as usize;
        if offset == 0 {
            on_ready(completion);
            self.next_ready = self.next_ready.saturating_add(1);
            if !self.pending.is_empty() {
                let _ = self.pending.pop_front();
            }

            let mut ready = 1;
            while matches!(self.pending.front(), Some(Some(_))) {
                let completion = self
                    .pending
                    .pop_front()
                    .and_then(|completion| completion)
                    .expect("checked ready pending completion");
                on_ready(completion);
                self.next_ready = self.next_ready.saturating_add(1);
                ready += 1;
            }
            return Ok(ready);
        }

        if offset >= self.pending_limit {
            return Err(OrderedCompletionError::WindowExceeded);
        }

        if self.pending.len() <= offset {
            self.pending.resize_with(offset + 1, || None);
        }
        if self.pending[offset].is_some() {
            return Err(OrderedCompletionError::Duplicate);
        }
        self.pending[offset] = Some(completion);
        Ok(0)
    }

    fn next_ready(&self) -> u64 {
        self.next_ready
    }

    fn pending_limit(&self) -> usize {
        self.pending_limit
    }
}

struct FmpReceiveOrder {
    next_ticket: u64,
    completions: OrderedCompletionBuffer<FmpOrderedCompletion<OpenedFmpJob>>,
}

impl FmpReceiveOrder {
    fn new() -> Self {
        Self {
            next_ticket: 0,
            completions: OrderedCompletionBuffer::new(fmp_receive_window()),
        }
    }

    fn issue(&mut self) -> FmpReceiveTicket {
        let ticket = FmpReceiveTicket {
            sequence: self.next_ticket,
        };
        self.next_ticket = self.next_ticket.saturating_add(1);
        ticket
    }

    fn can_issue(&self) -> bool {
        self.next_ticket
            .saturating_sub(self.completions.next_ready())
            < self.completions.pending_limit() as u64
    }

    fn complete(
        &mut self,
        ticket: FmpReceiveTicket,
        completion: FmpOrderedCompletion<OpenedFmpJob>,
        on_ready: impl FnMut(FmpOrderedCompletion<OpenedFmpJob>),
    ) -> Result<usize, OrderedCompletionError> {
        self.completions.complete(ticket, completion, on_ready)
    }
}

enum FmpOrderedCompletion<T> {
    Opened {
        replay: FmpReplayDecision,
        value: T,
    },
    AeadFailed(FmpAeadFailure),
}

#[derive(Default, Debug, Eq, PartialEq)]
struct FmpOrderedDrain {
    ready: usize,
    accepted: usize,
    aead_failures: usize,
    replay_drops: usize,
}

struct FmpAeadFailure {
    fallback_tx: DecryptWorkerFallbackSender,
    source_peer: PeerIdentity,
    lane: DecryptWorkerLane,
    fmp_counter: u64,
    fmp_replay_highest: Option<u64>,
}

enum FmpReadyCompletion<T> {
    Opened(T),
    AeadFailed(FmpAeadFailure),
}

struct FspReceiveOrder {
    next_ticket: u64,
    completions: OrderedCompletionBuffer<FspOrderedCompletion>,
}

impl FspReceiveOrder {
    fn new() -> Self {
        Self {
            next_ticket: 0,
            completions: OrderedCompletionBuffer::new(fsp_receive_window()),
        }
    }

    fn issue(&mut self) -> Option<FspReceiveTicket> {
        if self
            .next_ticket
            .saturating_sub(self.completions.next_ready())
            >= self.completions.pending_limit() as u64
        {
            return None;
        }
        let ticket = FspReceiveTicket {
            sequence: self.next_ticket,
        };
        self.next_ticket = self.next_ticket.saturating_add(1);
        Some(ticket)
    }

    fn next_ticket(&self) -> u64 {
        self.next_ticket
    }

    fn advance_next_ticket_to(&mut self, next_ticket: u64) {
        self.next_ticket = self.next_ticket.max(next_ticket);
    }

    fn complete(
        &mut self,
        ticket: FspReceiveTicket,
        completion: FspOrderedCompletion,
        on_ready: impl FnMut(FspOrderedCompletion),
    ) -> Result<usize, OrderedCompletionError> {
        self.completions.complete(ticket, completion, on_ready)
    }
}

struct FspOpenedJob {
    job: FspDecryptJob,
    header: FspEncryptedHeader,
    plaintext_len: usize,
}

enum FspOrderedCompletion {
    Opened {
        opened: FspOpenedJob,
        source: FspAeadCompletionSource,
    },
    AeadFailed {
        job: FspDecryptJob,
        header: FspEncryptedHeader,
        source: FspAeadCompletionSource,
    },
    EpochMismatch {
        job: FspDecryptJob,
        header: FspEncryptedHeader,
        source: FspAeadCompletionSource,
    },
    Dropped {
        source: FspAeadCompletionSource,
    },
}

enum FspReadyCompletion {
    Opened {
        opened: FspOpenedJob,
        slot: EpochSlot,
        source_peer: PeerIdentity,
    },
    AeadFailed {
        job: FspDecryptJob,
        header: FspEncryptedHeader,
    },
}

#[derive(Default)]
struct FspOrderedDrain {
    ready: usize,
    accepted: usize,
    aead_failures: usize,
    epoch_mismatches: usize,
    replay_drops: usize,
    dropped: usize,
    aead_failure_sources: FspAeadFailureSources,
    replay_drop_sources: FspReplayDropSources,
    outputs: Vec<FspReadyCompletion>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FspAeadFailureSources {
    local: usize,
    worker_open: usize,
    worker_open_returned: usize,
}

impl FspAeadFailureSources {
    fn add(&mut self, source: FspAeadCompletionSource) {
        match source {
            FspAeadCompletionSource::Local => self.local += 1,
            FspAeadCompletionSource::WorkerOpen => self.worker_open += 1,
            FspAeadCompletionSource::WorkerOpenReturned => self.worker_open_returned += 1,
        }
    }

    fn add_sources(&mut self, other: Self) {
        self.local += other.local;
        self.worker_open += other.worker_open;
        self.worker_open_returned += other.worker_open_returned;
    }

    fn record(self) {
        crate::perf_profile::record_fsp_aead_completion_source_aead_failures(
            self.local,
            0,
            0,
            self.worker_open,
            self.worker_open_returned,
        );
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FspReplayDropSources {
    worker_open: usize,
    worker_open_returned: usize,
}

impl FspReplayDropSources {
    fn add(&mut self, source: FspAeadCompletionSource) {
        match source {
            FspAeadCompletionSource::Local => {}
            FspAeadCompletionSource::WorkerOpen => self.worker_open += 1,
            FspAeadCompletionSource::WorkerOpenReturned => self.worker_open_returned += 1,
        }
    }

    fn add_sources(&mut self, other: Self) {
        self.worker_open += other.worker_open;
        self.worker_open_returned += other.worker_open_returned;
    }

    fn record(self) {
        crate::perf_profile::record_fsp_aead_completion_source_replay_drops(
            0,
            0,
            self.worker_open,
            self.worker_open_returned,
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FmpReplayPrecheck {
    counter: u64,
    replay_highest: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FmpReplayDecision {
    Prechecked(FmpReplayPrecheck),
}

impl FmpReplayDecision {
    fn prechecked_highest(self) -> Option<u64> {
        match self {
            Self::Prechecked(precheck) => Some(precheck.replay_highest),
        }
    }

    fn counter(self) -> u64 {
        match self {
            Self::Prechecked(precheck) => precheck.counter,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FmpReplayReject {
    reason: ReplayRejection,
    counter_lag: u64,
    deferred: bool,
}

struct OpenedFmpJob {
    packet_data: PacketBuffer,
    lane: DecryptWorkerLane,
    source_peer: PeerIdentity,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    local_node_addr: NodeAddr,
    timestamp_ms: u64,
    packet_len: usize,
    fmp_counter: u64,
    fmp_flags: u8,
    fmp_plaintext_offset: usize,
    fmp_plaintext_len: usize,
    fallback_tx: DecryptWorkerFallbackSender,
}

struct FmpAeadHelperJob {
    session_key: DecryptSessionKey,
    receive_order_id: u64,
    ticket: FmpReceiveTicket,
    replay: FmpReplayDecision,
    cipher: Arc<LessSafeKey>,
    fmp_header: [u8; 16],
    opened: OpenedFmpJob,
    completion_tx: Option<Sender<FmpAeadCompletionBatch>>,
    helper_queued_at: Option<crate::perf_profile::TraceStamp>,
}

struct FmpAeadCompletion {
    session_key: DecryptSessionKey,
    receive_order_id: u64,
    ticket: FmpReceiveTicket,
    completed_at: Option<crate::perf_profile::TraceStamp>,
    result: FmpAeadCompletionResult,
}

enum FmpAeadCompletionResult {
    Opened {
        replay: FmpReplayDecision,
        opened: OpenedFmpJob,
    },
    AeadFailed(FmpAeadFailure),
}

enum FmpAeadCompletionBatch {
    One(FmpAeadCompletion),
    Many(Vec<FmpAeadCompletion>),
}

impl FmpAeadCompletionBatch {
    fn one(completion: FmpAeadCompletion) -> Self {
        Self::One(completion)
    }

    fn common_session_order(&self) -> Option<(DecryptSessionKey, u64)> {
        let first = match self {
            Self::One(completion) => completion,
            Self::Many(completions) => completions.first()?,
        };
        let session_key = first.session_key;
        let receive_order_id = first.receive_order_id;
        let all_same = match self {
            Self::One(_) => true,
            Self::Many(completions) => completions.iter().all(|completion| {
                completion.session_key == session_key
                    && completion.receive_order_id == receive_order_id
            }),
        };
        all_same.then_some((session_key, receive_order_id))
    }

    fn push(&mut self, completion: FmpAeadCompletion) {
        match self {
            Self::One(_) => {
                let Self::One(existing) = std::mem::replace(
                    self,
                    Self::Many(Vec::with_capacity(fmp_aead_completion_batch_max())),
                ) else {
                    unreachable!("replaced One with Many")
                };
                let Self::Many(completions) = self else {
                    unreachable!("batch was replaced with Many")
                };
                completions.push(existing);
                completions.push(completion);
            }
            Self::Many(completions) => completions.push(completion),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(completions) => completions.len(),
        }
    }

    fn into_vec(self) -> Vec<FmpAeadCompletion> {
        match self {
            Self::One(completion) => vec![completion],
            Self::Many(completions) => completions,
        }
    }

    fn for_each(self, mut on_completion: impl FnMut(FmpAeadCompletion)) {
        match self {
            Self::One(completion) => on_completion(completion),
            Self::Many(completions) => {
                for completion in completions {
                    on_completion(completion);
                }
            }
        }
    }
}

impl FmpAeadCompletionResult {
    fn lane(&self) -> DecryptWorkerLane {
        match self {
            Self::Opened { opened, .. } => opened.lane,
            Self::AeadFailed(failure) => failure.lane,
        }
    }
}

fn local_established_fsp_datagram_meta(
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

impl FmpAeadHelperJob {
    fn into_completion(mut self) -> FmpAeadCompletion {
        let _t_fmp = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpDecrypt);
        let completed_at = self.helper_queued_at.and_then(|_| crate::perf_profile::stamp());
        match OwnedSessionState::open_fmp_aead_in_place(
            &self.cipher,
            &mut self.opened.packet_data,
            self.opened.fmp_plaintext_offset,
            self.opened.fmp_counter,
            self.opened.fmp_flags,
            &self.fmp_header,
        ) {
            Ok(outcome) => {
                self.opened.fmp_plaintext_len = outcome.plaintext_len;
                FmpAeadCompletion {
                    session_key: self.session_key,
                    receive_order_id: self.receive_order_id,
                    ticket: self.ticket,
                    completed_at,
                    result: FmpAeadCompletionResult::Opened {
                        replay: self.replay,
                        opened: self.opened,
                    },
                }
            }
            Err(()) => FmpAeadCompletion {
                session_key: self.session_key,
                receive_order_id: self.receive_order_id,
                ticket: self.ticket,
                completed_at,
                result: FmpAeadCompletionResult::AeadFailed(FmpAeadFailure {
                    fallback_tx: self.opened.fallback_tx,
                    source_peer: self.opened.source_peer,
                    lane: self.opened.lane,
                    fmp_counter: self.opened.fmp_counter,
                    fmp_replay_highest: self.replay.prechecked_highest(),
                }),
            },
        }
    }

}

struct FspAeadOpenJob {
    source_addr: NodeAddr,
    receive_order_id: u64,
    ticket: FspReceiveTicket,
    cipher: Arc<LessSafeKey>,
    job: FspDecryptJob,
    header: FspEncryptedHeader,
    completion_source: FspAeadCompletionSource,
    completion_tx: Option<Sender<FspAeadCompletionBatch>>,
    open_queued_at: Option<crate::perf_profile::TraceStamp>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FspAeadCompletionSource {
    Local,
    WorkerOpen,
    WorkerOpenReturned,
}

impl FspAeadCompletionSource {
    fn returned(self) -> Self {
        match self {
            Self::Local => Self::Local,
            Self::WorkerOpen => Self::WorkerOpenReturned,
            already_returned => already_returned,
        }
    }

    fn is_worker_open(self) -> bool {
        matches!(self, Self::WorkerOpen | Self::WorkerOpenReturned)
    }
}

struct FspAeadCompletion {
    source_addr: NodeAddr,
    receive_order_id: u64,
    ticket: FspReceiveTicket,
    source: FspAeadCompletionSource,
    result: FspOrderedCompletion,
    completed_at: Option<crate::perf_profile::TraceStamp>,
}

enum FspAeadCompletionBatch {
    One(FspAeadCompletion),
    Many(Vec<FspAeadCompletion>),
}

impl FspAeadCompletionBatch {
    fn one(completion: FspAeadCompletion) -> Self {
        Self::One(completion)
    }

    fn common_source_order(&self) -> Option<(NodeAddr, u64)> {
        let first = match self {
            Self::One(completion) => completion,
            Self::Many(completions) => completions.first()?,
        };
        let source_addr = first.source_addr;
        let receive_order_id = first.receive_order_id;
        let all_same = match self {
            Self::One(_) => true,
            Self::Many(completions) => completions.iter().all(|completion| {
                completion.source_addr == source_addr
                    && completion.receive_order_id == receive_order_id
            }),
        };
        all_same.then_some((source_addr, receive_order_id))
    }

    fn push(&mut self, completion: FspAeadCompletion) {
        match self {
            Self::One(_) => {
                let Self::One(existing) = std::mem::replace(
                    self,
                    Self::Many(Vec::with_capacity(fsp_aead_completion_batch_max())),
                ) else {
                    unreachable!("replaced One with Many")
                };
                let Self::Many(completions) = self else {
                    unreachable!("batch was replaced with Many")
                };
                completions.push(existing);
                completions.push(completion);
            }
            Self::Many(completions) => completions.push(completion),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(completions) => completions.len(),
        }
    }

    fn into_vec(self) -> Vec<FspAeadCompletion> {
        match self {
            Self::One(completion) => vec![completion],
            Self::Many(completions) => completions,
        }
    }

    fn for_each(self, mut on_completion: impl FnMut(FspAeadCompletion)) {
        match self {
            Self::One(completion) => on_completion(completion),
            Self::Many(completions) => {
                for completion in completions {
                    on_completion(completion);
                }
            }
        }
    }
}

impl FspAeadOpenJob {
    fn mark_returned_completion(&mut self) {
        match self.completion_source {
            FspAeadCompletionSource::WorkerOpen => crate::perf_profile::record_event(
                crate::perf_profile::Event::FspAeadCompletionReturnedWorkerOpen,
            ),
            FspAeadCompletionSource::Local | FspAeadCompletionSource::WorkerOpenReturned => {}
        }
        self.completion_source = self.completion_source.returned();
    }

    fn into_completion(mut self) -> FspAeadCompletion {
        let source = self.completion_source;
        if source.is_worker_open() {
            crate::perf_profile::record_since_count(
                crate::perf_profile::Stage::FspAeadWorkerOpenQueueWait,
                self.open_queued_at,
                1,
            );
        }
        let completed_at = self.open_queued_at.and_then(|_| crate::perf_profile::stamp());
        let payload_end = self
            .job
            .fsp_payload_offset
            .saturating_add(self.job.fsp_payload_len);
        let ciphertext_offset = self.job.fsp_payload_offset + FSP_HEADER_SIZE;
        let result = match self
            .job
            .fallback
            .packet_data
            .get_mut(ciphertext_offset..payload_end)
        {
            Some(ciphertext) => {
                let _t_fsp =
                    crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspDecrypt);
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[4..12].copy_from_slice(&self.header.counter.to_le_bytes());
                let nonce = Nonce::assume_unique_for_key(nonce_bytes);
                match self
                    .cipher
                    .open_in_place(nonce, Aad::from(&self.header.header_bytes), ciphertext)
                {
                    Ok(plaintext) => {
                        let plaintext_len = plaintext.len();
                        FspOrderedCompletion::Opened {
                            opened: FspOpenedJob {
                                job: self.job,
                                header: self.header,
                                plaintext_len,
                            },
                            source,
                        }
                    }
                    Err(_) => FspOrderedCompletion::AeadFailed {
                        job: self.job,
                        header: self.header,
                        source,
                    },
                }
            }
            None => FspOrderedCompletion::AeadFailed {
                job: self.job,
                header: self.header,
                source,
            },
        };
        FspAeadCompletion {
            source_addr: self.source_addr,
            receive_order_id: self.receive_order_id,
            ticket: self.ticket,
            source,
            result,
            completed_at,
        }
    }

    fn into_dropped_completion(self) -> FspAeadCompletion {
        let source = self.completion_source;
        if source.is_worker_open() {
            crate::perf_profile::record_since_count(
                crate::perf_profile::Stage::FspAeadWorkerOpenQueueWait,
                self.open_queued_at,
                1,
            );
        }
        let completed_at = self.open_queued_at.and_then(|_| crate::perf_profile::stamp());
        FspAeadCompletion {
            source_addr: self.source_addr,
            receive_order_id: self.receive_order_id,
            ticket: self.ticket,
            source,
            result: FspOrderedCompletion::Dropped { source },
            completed_at,
        }
    }
}

#[derive(Debug)]
struct FmpOpenOutcome {
    plaintext_len: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum FmpOpenError {
    Replay,
    #[cfg(test)]
    Aead { fmp_replay_highest: u64 },
}

impl OwnedSessionState {
    pub(crate) fn new(
        fmp_cipher: LessSafeKey,
        fmp_replay: ReplayWindow,
        source_peer: PeerIdentity,
    ) -> Self {
        Self {
            fmp_cipher: Arc::new(fmp_cipher),
            fmp_replay,
            source_peer,
            fmp_receive_order_id: NEXT_FMP_RECEIVE_ORDER_ID.fetch_add(1, Ordering::Relaxed),
            fmp_receive_order: FmpReceiveOrder::new(),
        }
    }

    fn precheck_fmp_replay(&self, fmp_counter: u64) -> Result<FmpReplayPrecheck, FmpOpenError> {
        let replay_highest = self.fmp_replay.highest();
        if !self.fmp_replay.check(fmp_counter) {
            return Err(FmpOpenError::Replay);
        }
        Ok(FmpReplayPrecheck {
            counter: fmp_counter,
            replay_highest,
        })
    }

    fn open_fmp_aead_in_place(
        cipher: &LessSafeKey,
        packet_data: &mut [u8],
        fmp_ciphertext_offset: usize,
        fmp_counter: u64,
        _fmp_flags: u8,
        fmp_header: &[u8; 16],
    ) -> Result<FmpOpenOutcome, ()> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&fmp_counter.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let buf = &mut packet_data[fmp_ciphertext_offset..];
        let plaintext_len = cipher
            .open_in_place(nonce, Aad::from(fmp_header), buf)
            .map_err(|_| ())?
            .len();

        Ok(FmpOpenOutcome { plaintext_len })
    }

    fn accept_prechecked_fmp_replay_on(
        fmp_replay: &mut ReplayWindow,
        precheck: FmpReplayPrecheck,
    ) -> Result<(), FmpOpenError> {
        if !fmp_replay.check(precheck.counter) {
            return Err(FmpOpenError::Replay);
        }
        fmp_replay.accept(precheck.counter);
        Ok(())
    }

    fn accept_or_classify_fmp_replay_on(
        fmp_replay: &mut ReplayWindow,
        replay: FmpReplayDecision,
    ) -> Result<(), FmpReplayReject> {
        let counter = replay.counter();
        if let Some(reason) = fmp_replay.rejection_reason(counter) {
            return Err(FmpReplayReject {
                reason,
                counter_lag: fmp_replay.highest().saturating_sub(counter),
                deferred: false,
            });
        }
        fmp_replay.accept(counter);
        Ok(())
    }

    #[cfg(test)]
    fn accept_prechecked_fmp_replay(
        &mut self,
        precheck: FmpReplayPrecheck,
    ) -> Result<(), FmpOpenError> {
        Self::accept_prechecked_fmp_replay_on(&mut self.fmp_replay, precheck)
    }

    fn issue_fmp_receive_ticket(&mut self) -> Option<FmpReceiveTicket> {
        Some(self.fmp_receive_order.issue())
    }

    fn fmp_receive_order_id(&self) -> u64 {
        self.fmp_receive_order_id
    }

    fn can_issue_fmp_receive_ticket(&self) -> bool {
        self.fmp_receive_order.can_issue()
    }

    #[cfg(test)]
    fn complete_ordered_fmp_open(
        &mut self,
        ticket: FmpReceiveTicket,
        completion: FmpOrderedCompletion<OpenedFmpJob>,
    ) -> Result<FmpOrderedDrain, FmpOpenError> {
        let fmp_replay = &mut self.fmp_replay;
        let mut drain = FmpOrderedDrain::default();
        drain.ready = self
            .fmp_receive_order
            .complete(ticket, completion, |completion| match completion {
                FmpOrderedCompletion::Opened { replay, .. } => {
                    if let Err(reject) = Self::accept_or_classify_fmp_replay_on(fmp_replay, replay)
                    {
                        crate::perf_profile::record_fmp_aead_completion_replay_drop_mode(
                            reject.deferred,
                        );
                        crate::perf_profile::record_fmp_aead_completion_replay_drop_reason(
                            reject.reason,
                            reject.counter_lag,
                        );
                        drain.replay_drops += 1;
                    } else {
                        drain.accepted += 1;
                    }
                }
                FmpOrderedCompletion::AeadFailed(_) => {
                    drain.aead_failures += 1;
                }
            })
            .map_err(|_| FmpOpenError::Replay)?;
        Ok(drain)
    }

    fn complete_ordered_fmp_open_with_value(
        &mut self,
        ticket: FmpReceiveTicket,
        completion: FmpOrderedCompletion<OpenedFmpJob>,
        mut on_ready: impl FnMut(FmpReadyCompletion<OpenedFmpJob>),
    ) -> Result<FmpOrderedDrain, FmpOpenError> {
        let fmp_replay = &mut self.fmp_replay;
        let mut drain = FmpOrderedDrain::default();
        drain.ready = self
            .fmp_receive_order
            .complete(ticket, completion, |completion| match completion {
                FmpOrderedCompletion::Opened { replay, value } => {
                    if let Err(reject) = Self::accept_or_classify_fmp_replay_on(fmp_replay, replay)
                    {
                        crate::perf_profile::record_fmp_aead_completion_replay_drop_mode(
                            reject.deferred,
                        );
                        crate::perf_profile::record_fmp_aead_completion_replay_drop_reason(
                            reject.reason,
                            reject.counter_lag,
                        );
                        drain.replay_drops += 1;
                    } else {
                        drain.accepted += 1;
                        on_ready(FmpReadyCompletion::Opened(value));
                    }
                }
                FmpOrderedCompletion::AeadFailed(mut failure) => {
                    failure
                        .fmp_replay_highest
                        .get_or_insert_with(|| fmp_replay.highest());
                    drain.aead_failures += 1;
                    on_ready(FmpReadyCompletion::AeadFailed(failure));
                }
            })
            .map_err(|_| FmpOpenError::Replay)?;
        Ok(drain)
    }

    #[cfg(test)]
    fn open_fmp_in_place(
        &mut self,
        packet_data: &mut [u8],
        fmp_ciphertext_offset: usize,
        fmp_counter: u64,
        fmp_flags: u8,
        fmp_header: &[u8; 16],
    ) -> Result<FmpOpenOutcome, FmpOpenError> {
        let precheck = self.precheck_fmp_replay(fmp_counter)?;
        let outcome = Self::open_fmp_aead_in_place(
            &self.fmp_cipher,
            packet_data,
            fmp_ciphertext_offset,
            fmp_counter,
            fmp_flags,
            fmp_header,
        )
        .map_err(|_| FmpOpenError::Aead {
            fmp_replay_highest: precheck.replay_highest,
        })?;
        Self::accept_prechecked_fmp_replay_on(&mut self.fmp_replay, precheck)?;
        Ok(outcome)
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
    pub packet_data: PacketBuffer,
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
        packet_data: impl Into<PacketBuffer>,
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
        let packet_data = packet_data.into();
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
    pub packet_data: PacketBuffer,
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
        packet_data: impl Into<PacketBuffer>,
        fmp_plaintext_offset: usize,
        fmp_plaintext_len: usize,
    ) -> Self {
        let packet_data = packet_data.into();
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

pub(crate) struct DecryptAuthenticatedFmpReceive {
    pub fmp: DecryptFmpBookkeeping,
    lane: DecryptWorkerLane,
    pub(crate) trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
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

    fn is_ipv6_packet(&self) -> bool {
        matches!(&self.delivery, DecryptDirectSessionDelivery::Ipv6Packet(_))
    }

    #[allow(clippy::result_large_err)]
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
    AuthenticatedFmpReceive(DecryptAuthenticatedFmpReceive),
    AuthenticatedSession(DecryptAuthenticatedSession),
    AuthenticatedSessionBatch(Vec<DecryptAuthenticatedSession>),
    DirectSessionCommit(DecryptDirectSessionCommit),
    DirectSessionCommitBatch(Vec<DecryptDirectSessionCommit>),
    DirectSessionData(DecryptDirectSessionData),
    DirectSessionDataBatch(Vec<DecryptDirectSessionData>),
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
            Self::AuthenticatedFmpReceive(_) => 1,
            Self::AuthenticatedSession(_) => 1,
            Self::AuthenticatedSessionBatch(sessions) => sessions.len(),
            Self::DirectSessionCommit(_) => 1,
            Self::DirectSessionCommitBatch(commits) => commits.len(),
            Self::DirectSessionData(_) => 1,
            Self::DirectSessionDataBatch(directs) => directs.len(),
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
            Self::AuthenticatedFmpReceive(receive) => receive.trace_enqueued_at = queued_at,
            Self::AuthenticatedSession(session) => session.trace_enqueued_at = queued_at,
            Self::AuthenticatedSessionBatch(sessions) => {
                for session in sessions {
                    session.trace_enqueued_at = queued_at;
                }
            }
            Self::DirectSessionCommit(commit) => commit.trace_enqueued_at = queued_at,
            Self::DirectSessionCommitBatch(commits) => {
                for commit in commits {
                    commit.trace_enqueued_at = queued_at;
                }
            }
            Self::DirectSessionData(direct) => direct.trace_enqueued_at = queued_at,
            Self::DirectSessionDataBatch(directs) => {
                for direct in directs {
                    direct.trace_enqueued_at = queued_at;
                }
            }
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
            Self::AuthenticatedFmpReceive(receive) => receive.trace_enqueued_at,
            Self::AuthenticatedSession(session) => session.trace_enqueued_at,
            Self::AuthenticatedSessionBatch(sessions) => sessions
                .first()
                .and_then(|session| session.trace_enqueued_at),
            Self::DirectSessionCommit(commit) => commit.trace_enqueued_at,
            Self::DirectSessionCommitBatch(commits) => {
                commits.first().and_then(|commit| commit.trace_enqueued_at)
            }
            Self::DirectSessionData(direct) => direct.trace_enqueued_at,
            Self::DirectSessionDataBatch(directs) => {
                directs.first().and_then(|direct| direct.trace_enqueued_at)
            }
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
            Self::AuthenticatedFmpReceive(_) => (
                crate::perf_profile::Stage::DecryptAuthenticatedFmpReceiveWait,
                crate::perf_profile::Stage::DecryptAuthenticatedSessionPriorityWait,
                crate::perf_profile::Stage::DecryptAuthenticatedSessionBulkWait,
            ),
            Self::AuthenticatedSession(_)
            | Self::AuthenticatedSessionBatch(_)
            | Self::DirectSessionCommit(_)
            | Self::DirectSessionCommitBatch(_)
            | Self::DirectSessionData(_)
            | Self::DirectSessionDataBatch(_) => (
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

    fn direct_queue_wait_stage(&self) -> Option<crate::perf_profile::Stage> {
        match self {
            Self::DirectSessionCommit(_) | Self::DirectSessionCommitBatch(_) => {
                Some(crate::perf_profile::Stage::DecryptDirectSessionCommitWait)
            }
            Self::DirectSessionData(_) | Self::DirectSessionDataBatch(_) => {
                Some(crate::perf_profile::Stage::DecryptDirectSessionDataWait)
            }
            _ => None,
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
        if let Some(direct_stage) = self.direct_queue_wait_stage() {
            crate::perf_profile::record_since_count(direct_stage, queued_at, count);
        }
    }
}
