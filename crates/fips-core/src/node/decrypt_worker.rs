//! Off-task FMP + FSP decrypt + delivery worker.
//!
//! First incremental step of the data-plane shard restructure (per the
//! architectural plan): each worker now **owns its session state
//! directly** in a local `HashMap`, with no `Arc<RwLock<HashMap>>`
//! cache on the Node side and no `Arc<Mutex<ReplayWindow>>` shared
//! with the rx_loop. The worker is the sole authority over the replay
//! window and the recv-side ciphers for every session it owns.
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
//! - **`Job`** — per-packet FMP decrypt + bounce. Large packets use
//!   the bulk lane; small control-shaped packets use the priority lane
//!   so heartbeats/MMP/rekey-sized traffic is not trapped behind a
//!   full bulk queue. The worker looks up the session in its local
//!   HashMap; if absent (registration hasn't arrived yet, or session
//!   was unregistered), the packet is dropped and retried by later
//!   traffic.
//! - **`UnregisterSession`** — sent on rekey / peer drop so the worker
//!   releases the owned cipher + replay state. It uses the priority
//!   lane.
//!
//! The worker currently owns FMP open + replay only. Every authentic
//! link-layer message, including endpoint data, is bounced back to the
//! rx_loop via a fallback channel so the existing FSP/session dispatch
//! paths remain the only FSP owners until a peer/session runtime can
//! safely own both FMP and FSP receive state.

// **Unix only at the call sites.** On Windows nothing constructs an
// `OwnedSessionState` or spawns the pool (see `lifecycle.rs`), so
// every field + function in here becomes dead. Silence the warnings
// rather than gate them individually.
#![cfg_attr(not(unix), allow(dead_code))]

use crate::PeerIdentity;
use crate::transport::{TransportAddr, TransportId};
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use ring::aead::{Aad, LessSafeKey, Nonce};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::mpsc::{
    Receiver as TokioReceiver, Sender as TokioSender, error::TrySendError as TokioTrySendError,
};
use tracing::{debug, trace, warn};

// `endpoint_event_tx` used to ride on every `DecryptJob` so the worker
// could deliver inbound EndpointData straight to the API layer,
// bypassing rx_loop. After the FMP-only refactor (correctness fix —
// see the long comment in `handle_job`'s phase-2 block) the worker
// bounces ALL link messages back to rx_loop, so the sender went
// unused. It's been removed: it bloated `DecryptJob` (an extra Arc
// clone per packet on the rx_loop hot path) and — worse — its
// presence was used as the production-path predicate in
// `handle_encrypted_frame`, which silently disabled the entire
// worker for TUN-only configurations that never call
// `endpoint_data_io()`.

use crate::noise::ReplayWindow;

const DEFAULT_DECRYPT_WORKER_BULK_CHANNEL_CAP: usize = 32768;
const DEFAULT_DECRYPT_WORKER_PRIORITY_CHANNEL_CAP: usize = 1024;
const DEFAULT_DECRYPT_FALLBACK_BULK_CHANNEL_CAP: usize = 32768;
const DEFAULT_DECRYPT_FALLBACK_PRIORITY_CHANNEL_CAP: usize = 1024;
const DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN: usize = 512;
const DECRYPT_WORKER_BULK_BURST_BUDGET: usize = 128;
const DECRYPT_WORKER_BULK_BATCH_MAX: usize = 16;

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

    /// Every authenticated link message is bounced back to the rx_loop via
    /// this channel along with its now-decrypted FMP plaintext. The rx_loop
    /// drains this in a select! arm and remains the sole FSP/session-dispatch
    /// owner until a future shard/runtime owns both layers.
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
        crate::perf_profile::record_since(
            crate::perf_profile::Stage::DecryptWorkerQueueWait,
            queued_at,
        );
        crate::perf_profile::record_since(
            match self.lane() {
                DecryptWorkerLane::Priority => {
                    crate::perf_profile::Stage::DecryptWorkerPriorityQueueWait
                }
                DecryptWorkerLane::Bulk => crate::perf_profile::Stage::DecryptWorkerBulkQueueWait,
            },
            queued_at,
        );
    }
}

/// Result of a successful FMP decrypt + replay accept. The worker currently
/// bounces every authenticated link message back to rx_loop for FSP/session
/// dispatch, but the event carries the authenticated source peer so a future
/// shard/runtime can use the same typed handoff for direct endpoint delivery.
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

/// Event emitted by the decrypt worker to the rx_loop.
pub(crate) enum DecryptWorkerEvent {
    Plaintext(DecryptFallback),
    DecryptFailure(DecryptFailureReport),
}

impl DecryptWorkerEvent {
    fn lane(&self) -> DecryptWorkerLane {
        decrypt_worker_event_lane(self)
    }

    fn set_trace_enqueued_at(&mut self, queued_at: Option<crate::perf_profile::TraceStamp>) {
        match self {
            Self::Plaintext(fallback) => fallback.trace_enqueued_at = queued_at,
            Self::DecryptFailure(report) => report.trace_enqueued_at = queued_at,
        }
    }

    fn trace_enqueued_at(&self) -> Option<crate::perf_profile::TraceStamp> {
        match self {
            Self::Plaintext(fallback) => fallback.trace_enqueued_at,
            Self::DecryptFailure(report) => report.trace_enqueued_at,
        }
    }

    pub(crate) fn record_queue_wait(&self) {
        let queued_at = self.trace_enqueued_at();
        if queued_at.is_none() {
            return;
        }
        crate::perf_profile::record_since(
            crate::perf_profile::Stage::DecryptFallbackWait,
            queued_at,
        );
        crate::perf_profile::record_since(
            match self.lane() {
                DecryptWorkerLane::Priority => {
                    crate::perf_profile::Stage::DecryptFallbackPriorityWait
                }
                DecryptWorkerLane::Bulk => crate::perf_profile::Stage::DecryptFallbackBulkWait,
            },
            queued_at,
        );
    }
}

#[derive(Clone)]
pub(crate) struct DecryptWorkerFallbackSender {
    priority: TokioSender<DecryptWorkerEvent>,
    bulk: TokioSender<DecryptWorkerEvent>,
}

pub(crate) struct DecryptWorkerFallbackReceivers {
    pub(crate) priority: TokioReceiver<DecryptWorkerEvent>,
    pub(crate) bulk: TokioReceiver<DecryptWorkerEvent>,
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
    (
        DecryptWorkerFallbackSender {
            priority: priority_tx,
            bulk: bulk_tx,
        },
        DecryptWorkerFallbackReceivers {
            priority: priority_rx,
            bulk: bulk_rx,
        },
    )
}

impl DecryptWorkerFallbackSender {
    fn send(&self, mut event: DecryptWorkerEvent) -> bool {
        let lane = decrypt_worker_event_lane(&event);
        event.set_trace_enqueued_at(crate::perf_profile::stamp());
        let result = match lane {
            DecryptWorkerLane::Priority => self.priority.try_send(event),
            DecryptWorkerLane::Bulk => self.bulk.try_send(event),
        };
        match result {
            Ok(()) => true,
            Err(TokioTrySendError::Full(_)) => {
                record_decrypt_fallback_drop(lane);
                false
            }
            Err(TokioTrySendError::Closed(_)) => {
                debug!(
                    ?lane,
                    "decrypt fallback receiver gone; dropping worker event"
                );
                false
            }
        }
    }
}

fn decrypt_worker_event_lane(event: &DecryptWorkerEvent) -> DecryptWorkerLane {
    match event {
        DecryptWorkerEvent::Plaintext(fallback) => fallback.lane(),
        DecryptWorkerEvent::DecryptFailure(_) => DecryptWorkerLane::Priority,
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
pub(crate) enum WorkerMsg {
    Job(DecryptJob),
    RegisterSession {
        session_key: DecryptSessionKey,
        state: OwnedSessionState,
    },
    UnregisterSession {
        session_key: DecryptSessionKey,
    },
}

#[allow(clippy::large_enum_variant)]
enum DecryptWorkerBulkItem {
    Job(DecryptJob),
    Batch(Vec<DecryptJob>),
}

impl DecryptWorkerBulkItem {
    fn packet_count(&self) -> usize {
        match self {
            Self::Job(_) => 1,
            Self::Batch(jobs) => jobs.len(),
        }
    }
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
}

struct DecryptWorkerSender {
    priority: Sender<WorkerMsg>,
    bulk: Sender<DecryptWorkerBulkItem>,
    bulk_queued_packets: Arc<AtomicUsize>,
    bulk_packet_cap: usize,
}

impl DecryptWorkerPool {
    pub fn spawn(n: usize) -> Self {
        let n = n.max(1);
        let bulk_channel_cap = bulk_channel_cap();
        let priority_channel_cap = priority_channel_cap();
        let mut senders = Vec::with_capacity(n);
        for i in 0..n {
            let (priority_tx, priority_rx) = bounded::<WorkerMsg>(priority_channel_cap);
            let (bulk_tx, bulk_rx) = bounded::<DecryptWorkerBulkItem>(bulk_channel_cap);
            let bulk_queued_packets = Arc::new(AtomicUsize::new(0));
            let worker_bulk_queued_packets = Arc::clone(&bulk_queued_packets);
            std::thread::Builder::new()
                .name(format!("fips-decrypt-{i}"))
                .spawn(move || run_worker(i, priority_rx, bulk_rx, worker_bulk_queued_packets))
                .expect("failed to spawn fips-decrypt OS thread");
            senders.push(DecryptWorkerSender {
                priority: priority_tx,
                bulk: bulk_tx,
                bulk_queued_packets,
                bulk_packet_cap: bulk_channel_cap,
            });
        }
        Self {
            senders: senders.into(),
        }
    }

    /// Stable hash from session key → worker index. Same hash is used
    /// for session registration and per-packet dispatch so packets and
    /// registration arrive at the same shard.
    fn worker_idx_for(&self, session_key: DecryptSessionKey) -> usize {
        (decrypt_session_fast_hash(session_key) as usize) % self.senders.len()
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
        let packet_count = item.packet_count();
        let sender = &self.senders[idx];
        if !try_reserve_bulk_packets(
            &sender.bulk_queued_packets,
            sender.bulk_packet_cap,
            packet_count,
        ) {
            record_decrypt_worker_bulk_drop_count(idx, packet_count);
            return;
        }

        match sender.bulk.try_send(item) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                release_bulk_packets(&sender.bulk_queued_packets, packet_count);
                record_decrypt_worker_bulk_drop_count(idx, packet_count);
            }
            Err(TrySendError::Disconnected(_)) => {
                release_bulk_packets(&sender.bulk_queued_packets, packet_count);
                debug!(worker = idx, "DecryptWorker thread gone; dropping bulk job");
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

fn try_reserve_bulk_packets(counter: &AtomicUsize, capacity: usize, count: usize) -> bool {
    if count == 0 {
        return true;
    }
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(count) else {
            return false;
        };
        if next > capacity {
            return false;
        }
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

fn release_bulk_packets(counter: &AtomicUsize, count: usize) {
    if count == 0 {
        return;
    }
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        debug_assert!(
            current >= count,
            "decrypt worker bulk job accounting underflow: current={current}, release={count}"
        );
        let next = current.saturating_sub(count);
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
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

fn record_decrypt_fallback_drop(lane: DecryptWorkerLane) {
    let event = match lane {
        DecryptWorkerLane::Priority => crate::perf_profile::Event::DecryptFallbackPriorityDropped,
        DecryptWorkerLane::Bulk => crate::perf_profile::Event::DecryptFallbackBulkDropped,
    };
    crate::perf_profile::record_event(event);
    static FULL_COUNT: AtomicU64 = AtomicU64::new(0);
    let n = FULL_COUNT.fetch_add(1, Ordering::Relaxed);
    if n < 8 || n.is_multiple_of(10000) {
        warn!(
            ?lane,
            drops = n + 1,
            "DecryptWorker fallback channel full; dropping worker event"
        );
    }
}

fn run_worker(
    idx: usize,
    priority_rx: Receiver<WorkerMsg>,
    bulk_rx: Receiver<DecryptWorkerBulkItem>,
    bulk_queued_packets: Arc<AtomicUsize>,
) {
    trace!(worker = idx, "FMP+FSP decrypt worker thread starting");

    let mut shard = DecryptWorkerShard::new();

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
                        handle_bulk_item(idx, &mut shard, &priority_rx, item);
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
    while drained_bulk_jobs < DECRYPT_WORKER_BULK_BURST_BUDGET {
        if let Ok(msg) = priority_rx.try_recv() {
            shard.handle_msg(idx, msg);
            continue;
        }
        match bulk_rx.try_recv() {
            Ok(item) => {
                release_bulk_packets(bulk_queued_packets, item.packet_count());
                drained_bulk_jobs += handle_bulk_item(idx, shard, priority_rx, item);
            }
            Err(_) => break,
        }
    }
}

fn handle_bulk_item(
    idx: usize,
    shard: &mut DecryptWorkerShard,
    priority_rx: &Receiver<WorkerMsg>,
    item: DecryptWorkerBulkItem,
) -> usize {
    match item {
        DecryptWorkerBulkItem::Job(job) => {
            shard.handle_job_msg(idx, job);
            1
        }
        DecryptWorkerBulkItem::Batch(jobs) => {
            let count = jobs.len();
            for job in jobs {
                while let Ok(msg) = priority_rx.try_recv() {
                    shard.handle_msg(idx, msg);
                }
                shard.handle_job_msg(idx, job);
            }
            count
        }
    }
}

struct DecryptWorkerShard {
    // Lives entirely on this OS thread — never observed by any other thread.
    sessions: HashMap<DecryptSessionKey, OwnedSessionState>,
}

impl DecryptWorkerShard {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    fn handle_msg(&mut self, idx: usize, msg: WorkerMsg) {
        match msg {
            WorkerMsg::Job(job) => {
                self.handle_job_msg(idx, job);
            }
            WorkerMsg::RegisterSession { session_key, state } => {
                self.register_session(idx, session_key, state);
            }
            WorkerMsg::UnregisterSession { session_key } => {
                self.unregister_session(idx, session_key);
            }
        }
    }

    fn handle_job_msg(&mut self, idx: usize, job: DecryptJob) {
        if let Err(err) = self.handle_job(job) {
            debug!(worker = idx, error = %err, "decrypt worker job failed");
        }
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

    fn handle_job(
        &mut self,
        job: DecryptJob,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        job.record_queue_wait();
        let DecryptJob {
            mut packet_data,
            lane: _,
            session_key,
            _transport_id: transport_id,
            _remote_addr: remote_addr,
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
                return Ok(());
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
            Err(FmpOpenError::Replay) => return Ok(()),
            Err(FmpOpenError::Aead { fmp_replay_highest }) => {
                let _ =
                    fallback_tx.send(DecryptWorkerEvent::DecryptFailure(DecryptFailureReport {
                        source_peer,
                        fmp_counter,
                        fmp_replay_highest,
                        trace_enqueued_at: None,
                    }));
                return Ok(());
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
            return Ok(());
        }
        let link_msg_start = fmp_plaintext_start + INNER_TIMESTAMP_LEN;
        let link_msg_end = fmp_plaintext_end;
        let link_msg = &packet_data[link_msg_start..link_msg_end];

        // === Phase 2: bounce ALL link messages back to rx_loop ===
        //
        // **Why no FSP fast path here:** previous design did FSP decrypt
        // + replay-accept for SessionDatagram (link msg_type 0x00), then
        // checked the inner FSP msg_type. If it was EndpointData (0x11),
        // delivered directly to the endpoint event channel. Otherwise
        // (heartbeats, MMP reports, IPv6-shim, etc.) bounced the
        // **decrypted-in-place** FMP plaintext back to rx_loop.
        //
        // Two problems with that path:
        //   1. After the shard-owned-sessions refactor (01f6c62), the FSP
        //      replay window is owned by **this worker thread**. Once we
        //      `state.fsp_replay.accept(fsp_counter)`, the rx_loop's
        //      `noise::Session::replay_window` is stale — it still has
        //      old counters. When rx_loop tries to FSP-decrypt the
        //      bounced control frame, its legacy path's replay check
        //      passes (the counter wasn't in its window) but the AEAD
        //      tag check fails because the FSP bytes in `packet_data`
        //      were already decrypted in place (now plaintext + 16
        //      garbage tag bytes).
        //   2. Even if we didn't accept the worker's replay window for
        //      non-EndpointData, the in-place mutation of `packet_data`
        //      means the legacy path can't re-decrypt — the ciphertext
        //      is gone.
        //
        // The bug manifests in benches as link death: heartbeats never
        // make it through the worker, the link-dead timer fires at 30s,
        // peer is removed and re-handshakes, repeating forever.
        //
        // **Fix:** worker handles only the FMP layer. ALL link messages
        // (SessionDatagram, heartbeats, control) bounce back to rx_loop
        // with the FMP plaintext intact. The legacy rx_loop path does
        // FSP-decrypt as usual. Net cost vs the broken fast path: we
        // give up the rx_loop bypass for EndpointData, but the worker
        // still offloads the FMP AEAD (~half the per-packet decrypt
        // CPU). Correctness over micro-optimisation.
        //
        // The DataShard end-state (per the architectural plan) re-
        // introduces the EndpointData fast path correctly by having the
        // shard worker also own the rx_loop side for its sessions — at
        // that point there's no "rx_loop legacy path" for the worker to
        // conflict with.
        // Pass the buffer through by ownership + offset/length. No
        // per-packet allocation; rx_loop slices into `packet_data`.
        let _ = link_msg; // sanity-check borrow before sending buffer onward
        let _ = fallback_tx.send(DecryptWorkerEvent::Plaintext(DecryptFallback::new(
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
        )));
        // Suppress unused-variable warnings for the (now-removed) FSP
        // fast path. The `state` lookup is still needed for the FMP
        // cipher + replay window above.
        let _ = (link_msg_start, link_msg_end, &state.source_peer);
        Ok(())
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

    fn dummy_failure_event() -> DecryptWorkerEvent {
        DecryptWorkerEvent::DecryptFailure(DecryptFailureReport {
            source_peer: test_source_peer(),
            fmp_counter: 2,
            fmp_replay_highest: 1,
            trace_enqueued_at: None,
        })
    }

    fn test_chacha_key(key_bytes: [u8; 32]) -> LessSafeKey {
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        LessSafeKey::new(unbound)
    }

    fn sealed_fmp_test_packet(
        cipher: &LessSafeKey,
        counter: u64,
        flags: u8,
    ) -> (Vec<u8>, [u8; crate::node::wire::ESTABLISHED_HEADER_SIZE]) {
        const HDR: usize = crate::node::wire::ESTABLISHED_HEADER_SIZE;
        let mut header = [0u8; HDR];
        header[1] = flags;
        let mut wire = Vec::with_capacity(HDR + 4 + 1 + 16);
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&[0u8; 4]);
        wire.push(0xAB);

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
            WorkerMsg::Job(_) | WorkerMsg::UnregisterSession { .. } => {
                panic!("expected registration first")
            }
        }
        match priority_receivers[owner]
            .try_recv()
            .expect("priority packet should reach same owner")
        {
            WorkerMsg::Job(job) => assert_eq!(job.session_key, session_key),
            WorkerMsg::RegisterSession { .. } | WorkerMsg::UnregisterSession { .. } => {
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
            WorkerMsg::RegisterSession { .. } | WorkerMsg::Job(_) => {
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

        let mut shard = DecryptWorkerShard::new();
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

        let mut shard = DecryptWorkerShard::new();
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

        let mut shard = DecryptWorkerShard::new();
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
        let mut shard = DecryptWorkerShard::new();
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
        let mut shard = DecryptWorkerShard::new();

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
        let mut shard = DecryptWorkerShard::new();
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
        let mut shard = DecryptWorkerShard::new();
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
        }
    }
}
