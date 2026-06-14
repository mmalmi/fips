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
    EndpointDataDelivery, EndpointEventSender, EndpointPayloadLane, NodeDeliveredPacket,
    NodeEndpointEvent, classify_endpoint_payload,
};
use crate::protocol::{LinkMessageType, SessionDatagramRef, SessionMessageType};
use crate::transport::{TransportAddr, TransportId};
use crate::upper::tun::TunTx;
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use ring::aead::{Aad, LessSafeKey, Nonce};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::mpsc::{
    Receiver as TokioReceiver, Sender as TokioSender, error::TrySendError as TokioTrySendError,
};
use tracing::{debug, info, trace, warn};

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
const DECRYPT_WORKER_FMP_RECEIVE_WINDOW: usize = 1024;
const DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX: usize = DECRYPT_WORKER_BULK_BURST_BUDGET;
const DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX: usize = DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX;

static NEXT_FMP_RECEIVE_ORDER_ID: AtomicU64 = AtomicU64::new(1);

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

fn default_fmp_aead_helper_count_for(linux: bool, cpu_count: usize) -> usize {
    if linux && cpu_count >= 4 { 2 } else { 0 }
}

fn default_fmp_aead_helper_count() -> usize {
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    default_fmp_aead_helper_count_for(cfg!(target_os = "linux"), cpu_count)
}

fn fmp_aead_helper_count_from_raw(raw: Option<&str>, default: usize) -> usize {
    raw.and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(default)
        .min(64)
}

fn fmp_aead_helper_count() -> usize {
    fmp_aead_helper_count_from_raw(
        std::env::var("FIPS_DECRYPT_FMP_AEAD_HELPERS").ok().as_deref(),
        default_fmp_aead_helper_count(),
    )
}

fn decrypt_worker_packet_lane(len: usize) -> DecryptWorkerLane {
    if len <= DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN {
        DecryptWorkerLane::Priority
    } else {
        DecryptWorkerLane::Bulk
    }
}

fn endpoint_payload_decrypt_worker_lane(payload: &[u8]) -> DecryptWorkerLane {
    match classify_endpoint_payload(payload).lane() {
        EndpointPayloadLane::Priority => DecryptWorkerLane::Priority,
        EndpointPayloadLane::Bulk => DecryptWorkerLane::Bulk,
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
    pub fmp_cipher: Arc<LessSafeKey>,
    pub fmp_replay: ReplayWindow,
    pub source_peer: PeerIdentity,
    fmp_receive_order_id: u64,
    fmp_receive_order: FmpReceiveOrder,
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

struct OpenedFmpJob {
    packet_data: Vec<u8>,
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
    precheck: FmpReplayPrecheck,
    cipher: Arc<LessSafeKey>,
    fmp_header: [u8; 16],
    opened: OpenedFmpJob,
    completion_tx: Option<Sender<FmpAeadCompletion>>,
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
        precheck: FmpReplayPrecheck,
        opened: OpenedFmpJob,
    },
    AeadFailed {
        fallback_tx: DecryptWorkerFallbackSender,
        source_peer: PeerIdentity,
        lane: DecryptWorkerLane,
        fmp_counter: u64,
        fmp_replay_highest: u64,
    },
}

impl FmpAeadCompletionResult {
    fn lane(&self) -> DecryptWorkerLane {
        match self {
            Self::Opened { opened, .. } => opened.lane,
            Self::AeadFailed { lane, .. } => *lane,
        }
    }
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
                        precheck: self.precheck,
                        opened: self.opened,
                    },
                }
            }
            Err(()) => FmpAeadCompletion {
                session_key: self.session_key,
                receive_order_id: self.receive_order_id,
                ticket: self.ticket,
                completed_at,
                result: FmpAeadCompletionResult::AeadFailed {
                    fallback_tx: self.opened.fallback_tx,
                    source_peer: self.opened.source_peer,
                    lane: self.opened.lane,
                    fmp_counter: self.opened.fmp_counter,
                    fmp_replay_highest: self.precheck.replay_highest,
                },
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FmpReplayPrecheck {
    counter: u64,
    replay_highest: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FmpReceiveTicket {
    sequence: u64,
}

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
        ticket: FmpReceiveTicket,
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
            completions: OrderedCompletionBuffer::new(DECRYPT_WORKER_FMP_RECEIVE_WINDOW),
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
        self.next_ticket.saturating_sub(self.completions.next_ready())
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

#[derive(Debug)]
enum FmpOrderedCompletion<T> {
    Opened {
        precheck: FmpReplayPrecheck,
        value: T,
    },
    AeadFailed,
}

#[derive(Default, Debug, Eq, PartialEq)]
struct FmpOrderedDrain {
    ready: usize,
    accepted: usize,
    aead_failures: usize,
    replay_drops: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum FmpOpenError {
    Replay,
    #[cfg(test)]
    Aead { fmp_replay_highest: u64 },
}

impl OwnedSessionState {
    pub(crate) fn new(
        fmp_cipher: Arc<LessSafeKey>,
        fmp_replay: ReplayWindow,
        source_peer: PeerIdentity,
    ) -> Self {
        Self {
            fmp_cipher,
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

    #[cfg(test)]
    fn accept_prechecked_fmp_replay(
        &mut self,
        precheck: FmpReplayPrecheck,
    ) -> Result<(), FmpOpenError> {
        Self::accept_prechecked_fmp_replay_on(&mut self.fmp_replay, precheck)
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

    fn issue_fmp_receive_ticket(&mut self) -> FmpReceiveTicket {
        self.fmp_receive_order.issue()
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
                FmpOrderedCompletion::Opened { precheck, .. } => {
                    if Self::accept_prechecked_fmp_replay_on(fmp_replay, precheck).is_ok() {
                        drain.accepted += 1;
                    } else {
                        drain.replay_drops += 1;
                    }
                }
                FmpOrderedCompletion::AeadFailed => {
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
        mut on_opened: impl FnMut(OpenedFmpJob),
    ) -> Result<FmpOrderedDrain, FmpOpenError> {
        let fmp_replay = &mut self.fmp_replay;
        let mut drain = FmpOrderedDrain::default();
        drain.ready = self
            .fmp_receive_order
            .complete(ticket, completion, |completion| match completion {
                FmpOrderedCompletion::Opened { precheck, value } => {
                    if Self::accept_prechecked_fmp_replay_on(fmp_replay, precheck).is_ok() {
                        drain.accepted += 1;
                        on_opened(value);
                    } else {
                        drain.replay_drops += 1;
                    }
                }
                FmpOrderedCompletion::AeadFailed => {
                    drain.aead_failures += 1;
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
        fmp_header: &[u8; 16],
    ) -> Result<FmpOpenOutcome, FmpOpenError> {
        let replay_precheck = self.precheck_fmp_replay(fmp_counter)?;
        let outcome = Self::open_fmp_aead_in_place(
            &self.fmp_cipher,
            packet_data,
            fmp_ciphertext_offset,
            fmp_counter,
            fmp_header,
        )
        .map_err(|_| FmpOpenError::Aead {
            fmp_replay_highest: replay_precheck.replay_highest,
        })?;
        Self::accept_prechecked_fmp_replay_on(&mut self.fmp_replay, replay_precheck)?;
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

pub(crate) struct DecryptAuthenticatedFmpReceive {
    pub fmp: DecryptFmpBookkeeping,
    lane: DecryptWorkerLane,
    pub(crate) trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

pub(crate) struct DecryptDirectFmpEndpointData {
    pub fmp: DecryptFmpBookkeeping,
    packet_data: Vec<u8>,
    payload_offset: usize,
    payload_len: usize,
    lane: DecryptWorkerLane,
    pub(crate) trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
}

impl DecryptDirectFmpEndpointData {
    #[cfg(test)]
    pub(in crate::node) fn for_test(fmp: DecryptFmpBookkeeping, payload: Vec<u8>) -> Self {
        let payload_len = payload.len();
        Self {
            fmp,
            packet_data: payload,
            payload_offset: 0,
            payload_len,
            lane: DecryptWorkerLane::Bulk,
            trace_enqueued_at: None,
        }
    }

    pub(in crate::node) fn payload(&self) -> &[u8] {
        &self.packet_data[self.payload_offset..self.payload_offset + self.payload_len]
    }

    pub(in crate::node) fn payload_len(&self) -> usize {
        self.payload_len
    }

    pub(in crate::node) fn into_delivery(self) -> EndpointDataDelivery {
        let source_peer = self.fmp.source_peer;
        EndpointDataDelivery::new(source_peer, self.payload().to_vec())
    }
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

fn direct_session_delivery_lane(delivery: &DecryptDirectSessionDelivery) -> DecryptWorkerLane {
    match delivery {
        DecryptDirectSessionDelivery::EndpointData(delivery) => {
            endpoint_payload_decrypt_worker_lane(&delivery.payload)
        }
        DecryptDirectSessionDelivery::Ipv6Packet(packet) => {
            endpoint_payload_decrypt_worker_lane(packet)
        }
    }
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
