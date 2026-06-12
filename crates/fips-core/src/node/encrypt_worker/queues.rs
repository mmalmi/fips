#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EncryptWorkerLane {
    Priority,
    Bulk,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FmpWorkerBatchStats {
    priority_packets: usize,
    bulk_packets: usize,
}

impl FmpWorkerBatchStats {
    fn record_lane(&mut self, lane: EncryptWorkerLane) {
        match lane {
            EncryptWorkerLane::Priority => {
                self.priority_packets = self.priority_packets.saturating_add(1)
            }
            EncryptWorkerLane::Bulk => self.bulk_packets = self.bulk_packets.saturating_add(1),
        }
    }

    fn packet_count(&self) -> usize {
        self.priority_packets.saturating_add(self.bulk_packets)
    }

    #[cfg(test)]
    fn from_batch(batch: &[QueuedFmpSendJob]) -> Self {
        let mut stats = Self::default();
        for job in batch {
            stats.record_lane(job.queue_lane());
        }
        stats
    }
}

fn encrypt_worker_lane_for_endpoint_data(bulk_endpoint_data: bool) -> EncryptWorkerLane {
    if bulk_endpoint_data {
        EncryptWorkerLane::Bulk
    } else {
        EncryptWorkerLane::Priority
    }
}

#[cfg(test)]
fn fmp_worker_queue_wait_stage_for_lane(lane: EncryptWorkerLane) -> crate::perf_profile::Stage {
    match lane {
        EncryptWorkerLane::Priority => crate::perf_profile::Stage::FmpWorkerPriorityQueueWait,
        EncryptWorkerLane::Bulk => crate::perf_profile::Stage::FmpWorkerBulkQueueWait,
    }
}

fn record_fmp_worker_queue_wait(
    lane: EncryptWorkerLane,
    queued_at: Option<crate::perf_profile::TraceStamp>,
) {
    let (priority_count, bulk_count) = match lane {
        EncryptWorkerLane::Priority => (1, 0),
        EncryptWorkerLane::Bulk => (0, 1),
    };
    crate::perf_profile::record_since_split_count(
        crate::perf_profile::Stage::FmpWorkerQueueWait,
        crate::perf_profile::Stage::FmpWorkerPriorityQueueWait,
        crate::perf_profile::Stage::FmpWorkerBulkQueueWait,
        queued_at,
        1,
        priority_count,
        bulk_count,
    );
}

struct QueuedFmpSendJob {
    job: FmpSendJob,
    lane: EncryptWorkerLane,
    #[cfg(unix)]
    target_key: SendTargetKey,
    #[cfg(not(target_os = "macos"))]
    scheduling_weight: usize,
    #[cfg(not(target_os = "macos"))]
    fair_reservation: Option<FairAdmissionReservation>,
    #[cfg(target_os = "macos")]
    macos_flow: Option<Arc<MacSequencedSendFlow>>,
    #[cfg(target_os = "macos")]
    macos_seq: u64,
}

impl QueuedFmpSendJob {
    #[allow(dead_code)] // used on non-macOS and by tests; macOS production uses sequenced flows.
    fn direct(job: FmpSendJob) -> Self {
        let lane = encrypt_worker_lane_for_endpoint_data(job.bulk_endpoint_data);
        #[cfg(unix)]
        let target_key = job.send_target_key();
        #[cfg(not(target_os = "macos"))]
        let scheduling_weight = clamp_send_scheduling_weight(job.scheduling_weight);
        Self {
            job,
            lane,
            #[cfg(unix)]
            target_key,
            #[cfg(not(target_os = "macos"))]
            scheduling_weight,
            #[cfg(not(target_os = "macos"))]
            fair_reservation: None,
            #[cfg(target_os = "macos")]
            macos_flow: None,
            #[cfg(target_os = "macos")]
            macos_seq: 0,
        }
    }

    #[cfg(target_os = "macos")]
    fn macos_sequenced(job: FmpSendJob, macos_flow: Arc<MacSequencedSendFlow>) -> Self {
        let macos_seq = macos_flow.reserve_seq();
        let lane = encrypt_worker_lane_for_endpoint_data(job.bulk_endpoint_data);
        let target_key = job.send_target_key();
        Self {
            job,
            lane,
            target_key,
            macos_flow: Some(macos_flow),
            macos_seq,
        }
    }

    #[cfg(unix)]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn target_key(&self) -> SendTargetKey {
        self.target_key
    }

    #[cfg(not(target_os = "macos"))]
    fn flow_key(&self) -> SendTargetKey {
        self.target_key
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn queue_lane(&self) -> EncryptWorkerLane {
        self.lane
    }

    #[cfg(not(target_os = "macos"))]
    fn mark_fair_reserved(&mut self, reservation: FairAdmissionReservation) {
        self.fair_reservation = Some(reservation);
    }

    #[cfg(not(target_os = "macos"))]
    fn take_fair_reservation(&mut self) -> Option<FairAdmissionReservation> {
        self.fair_reservation.take()
    }

    #[cfg(not(target_os = "macos"))]
    fn scheduling_weight(&self) -> usize {
        self.scheduling_weight
    }
}

/// Handle to the encrypt worker pool. Dispatches jobs **hash-by-
/// send-target** across N worker tasks via per-worker bounded queues.
/// The bounded queue keeps bulk tunnel packets from growing without
/// bound when encryption/sending falls behind. Control traffic must not
/// sit behind that bulk backlog: blocking the rx_loop on a full send
/// queue also blocks decrypt-fallback/liveness processing, which can
/// turn a busy tunnel into a false link-dead removal.
///
/// **Ordering: hash-by-send-target, not round-robin.** Round-robin
/// across N workers causes UDP packet reordering on the wire, which
/// the receiving TCP layer reacts to with dup-ACK-triggered
/// fast-retransmits — measured in bench: 2 workers on a single-flow
/// TCP run dropped throughput 1308 → 1069 Mbps and pushed Retr count
/// from 0 to 8058. Hashing on the exact kernel send target keeps all
/// packets for one flow on one worker, preserving the FIFO order TCP
/// expects. Multi-peer / multi-flow benches still get the parallelism
/// since different send targets hash to different workers.
///
/// macOS defaults to the same hash-by-send-target shape unless explicitly
/// opted into the ordered sender. Live Wi-Fi sender tests showed the
/// worker-owned path beats the per-flow ordered sender handoff when the
/// Darwin UDP syscall/pacer path, not FMP AEAD, is the limiting stage.
/// Per-flow bounded bulk queue cap. Keep this shallower than wireguard-go's
/// 1024-slot outbound queue because this worker also has a 4x total Linux
/// bulk lane and a separate control reserve. A deeper queue hides a saturated
/// sender from TCP for tens of milliseconds, inflating RTT/retransmits instead
/// of pushing back to TUN promptly. Local clean-underlay A/Bs showed 256 keeps
/// the same ~3 Gbps class while cutting hot FMP bulk queue residence in half.
const DEFAULT_WORKER_CHANNEL_CAP: usize = 256;
// Keep the control/ACK-shaped reserve independent from synthetic bulk-pressure
// tests that deliberately shrink `FIPS_WORKER_CHANNEL_CAP`.
#[cfg(not(target_os = "macos"))]
const DEFAULT_WORKER_PRIORITY_CHANNEL_CAP: usize = 1024;
#[cfg(target_os = "macos")]
const MAC_WORKER_CONTROL_RESERVE_CAP: usize = 128;
#[cfg(not(target_os = "macos"))]
const WORKER_FAIR_QUANTUM_BYTES: usize = 64 * 1024;
// Keep the Linux worker turn close to the packet-mover receive width; larger
// turns amortize sends but make tail service less predictable under pressure.
#[cfg(target_os = "linux")]
const DEFAULT_WORKER_BATCH_SIZE: usize = 32;
#[cfg(target_os = "linux")]
const LINUX_UDP_SEND_BATCH_MAX: usize = 64;
#[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
const DEFAULT_WORKER_BATCH_SIZE: usize = 32;
pub(crate) const DEFAULT_SEND_WEIGHT: u8 = 1;
pub(crate) const EXPLICIT_PEER_SEND_WEIGHT: u8 = 2;
#[cfg(not(target_os = "macos"))]
const MIN_SEND_WEIGHT: u8 = 1;
#[cfg(not(target_os = "macos"))]
const MAX_SEND_WEIGHT: u8 = 4;

#[cfg(not(target_os = "macos"))]
fn clamp_send_scheduling_weight(weight: u8) -> usize {
    weight.clamp(MIN_SEND_WEIGHT, MAX_SEND_WEIGHT) as usize
}

fn worker_channel_cap() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        let raw = std::env::var("FIPS_WORKER_CHANNEL_CAP").ok();
        parse_worker_channel_cap(raw.as_deref(), DEFAULT_WORKER_CHANNEL_CAP)
    })
}

#[cfg(not(target_os = "macos"))]
fn worker_priority_channel_cap() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        let raw = std::env::var("FIPS_ENCRYPT_WORKER_PRIORITY_CHANNEL_CAP").ok();
        parse_worker_channel_cap(raw.as_deref(), DEFAULT_WORKER_PRIORITY_CHANNEL_CAP)
    })
}

fn parse_worker_channel_cap(raw: Option<&str>, default: usize) -> usize {
    raw.and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(1, 32768)
}

#[cfg(not(target_os = "macos"))]
fn worker_batch_size() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        let raw = std::env::var("FIPS_WORKER_BATCH").ok();
        parse_worker_batch_size(raw.as_deref(), DEFAULT_WORKER_BATCH_SIZE)
    })
}

#[cfg(not(target_os = "macos"))]
fn worker_fast_lane_cap(total_cap: usize, per_flow_cap: usize) -> usize {
    worker_fast_lane_cap_for_batch(total_cap, per_flow_cap, worker_batch_size())
}

#[cfg(not(target_os = "macos"))]
fn worker_fast_lane_cap_for_batch(
    total_cap: usize,
    per_flow_cap: usize,
    batch_size: usize,
) -> usize {
    batch_size
        // Larger experimental drain batches should not also widen the hidden
        // admission bypass before fair per-flow backpressure can engage.
        .min(DEFAULT_WORKER_BATCH_SIZE)
        .min(per_flow_cap.max(1))
        .min(total_cap.max(1))
        .max(1)
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
fn parse_worker_batch_size(raw: Option<&str>, default: usize) -> usize {
    raw.and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(default)
        // Linux UDP submission in this module is capped at 64 iovecs.
        // Keep the worker drain cap aligned so a same-target group never asks
        // the GSO path to submit a prefix while accounting the whole group.
        .clamp(1, 64)
}

#[cfg(not(target_os = "macos"))]
type FairFlowMap =
    HashMap<SendTargetKey, FairFlowQueue, std::hash::BuildHasherDefault<SendTargetFastHasher>>;

#[cfg(not(target_os = "macos"))]
struct SendTargetFastHasher(u64);

#[cfg(not(target_os = "macos"))]
impl Default for SendTargetFastHasher {
    fn default() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

#[cfg(not(target_os = "macos"))]
impl std::hash::Hasher for SendTargetFastHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut word = 0u64;
            for (idx, byte) in chunk.iter().enumerate() {
                word |= u64::from(*byte) << (idx * 8);
            }
            self.write_u64(word);
        }
    }

    fn write_u8(&mut self, i: u8) {
        self.write_u64(u64::from(i));
    }

    fn write_u16(&mut self, i: u16) {
        self.write_u64(u64::from(i));
    }

    fn write_u32(&mut self, i: u32) {
        self.write_u64(u64::from(i));
    }

    fn write_u64(&mut self, i: u64) {
        self.0 ^= i.wrapping_add(0x9e37_79b9_7f4a_7c15);
        self.0 = self.0.rotate_left(27).wrapping_mul(0x94d0_49bb_1331_11eb);
    }

    fn write_u128(&mut self, i: u128) {
        self.write_u64(i as u64);
        self.write_u64((i >> 64) as u64);
    }
}

#[cfg(not(target_os = "macos"))]
fn send_target_fast_hash(target: &SendTargetKey) -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hasher = SendTargetFastHasher::default();
    target.hash(&mut hasher);
    hasher.finish()
}

#[cfg(target_os = "macos")]
struct MacWorkerSender {
    inner: Arc<MacWorkerQueueInner>,
}

#[cfg(target_os = "macos")]
struct MacWorkerReceiver {
    inner: Arc<MacWorkerQueueInner>,
}

#[cfg(target_os = "macos")]
struct MacWorkerQueueInner {
    state: Mutex<MacWorkerQueueState>,
    not_empty: Condvar,
    not_full: Condvar,
    cap: usize,
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct MacWorkerQueueState {
    control_queue: VecDeque<QueuedFmpSendJob>,
    bulk_queue: VecDeque<QueuedFmpSendJob>,
    waiting: bool,
    closed: bool,
}

#[cfg(target_os = "macos")]
impl MacWorkerQueueState {
    fn len(&self) -> usize {
        self.control_queue.len() + self.bulk_queue.len()
    }

    fn is_empty(&self) -> bool {
        self.control_queue.is_empty() && self.bulk_queue.is_empty()
    }

    fn push_job(&mut self, job: QueuedFmpSendJob) {
        match job.queue_lane() {
            EncryptWorkerLane::Priority => self.control_queue.push_back(job),
            EncryptWorkerLane::Bulk => self.bulk_queue.push_back(job),
        }
    }

    fn pop_job(&mut self) -> Option<QueuedFmpSendJob> {
        self.control_queue
            .pop_front()
            .or_else(|| self.bulk_queue.pop_front())
    }
}

#[cfg(target_os = "macos")]
enum MacWorkerTryPushError {
    Full(Box<QueuedFmpSendJob>),
    Closed,
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct MacWorkerPushError;

#[cfg(target_os = "macos")]
fn mac_worker_channel(cap: usize) -> (MacWorkerSender, MacWorkerReceiver) {
    let inner = Arc::new(MacWorkerQueueInner {
        state: Mutex::new(MacWorkerQueueState {
            control_queue: VecDeque::with_capacity(MAC_WORKER_CONTROL_RESERVE_CAP),
            bulk_queue: VecDeque::with_capacity(cap),
            waiting: false,
            closed: false,
        }),
        not_empty: Condvar::new(),
        not_full: Condvar::new(),
        cap,
    });
    (
        MacWorkerSender {
            inner: Arc::clone(&inner),
        },
        MacWorkerReceiver { inner },
    )
}

#[cfg(target_os = "macos")]
impl MacWorkerSender {
    fn try_push(&self, job: QueuedFmpSendJob) -> Result<(), MacWorkerTryPushError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("encrypt worker queue poisoned");
        if state.closed {
            drop(job);
            return Err(MacWorkerTryPushError::Closed);
        }
        let cap = match job.queue_lane() {
            EncryptWorkerLane::Priority => self.inner.cap + MAC_WORKER_CONTROL_RESERVE_CAP,
            EncryptWorkerLane::Bulk => self.inner.cap,
        };
        if state.len() >= cap {
            return Err(MacWorkerTryPushError::Full(Box::new(job)));
        }
        let was_empty = state.is_empty();
        let should_notify = was_empty && state.waiting;
        state.push_job(job);
        drop(state);
        if should_notify {
            self.inner.not_empty.notify_one();
        }
        Ok(())
    }

    fn push_blocking(&self, job: QueuedFmpSendJob) -> Result<(), MacWorkerPushError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("encrypt worker queue poisoned");
        loop {
            if state.closed {
                drop(job);
                return Err(MacWorkerPushError);
            }
            let cap = match job.queue_lane() {
                EncryptWorkerLane::Priority => self.inner.cap + MAC_WORKER_CONTROL_RESERVE_CAP,
                EncryptWorkerLane::Bulk => self.inner.cap,
            };
            if state.len() < cap {
                let was_empty = state.is_empty();
                let should_notify = was_empty && state.waiting;
                state.push_job(job);
                drop(state);
                if should_notify {
                    self.inner.not_empty.notify_one();
                }
                return Ok(());
            }
            state = self
                .inner
                .not_full
                .wait(state)
                .expect("encrypt worker queue poisoned");
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacWorkerSender {
    fn drop(&mut self) {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("encrypt worker queue poisoned");
        state.closed = true;
        drop(state);
        self.inner.not_empty.notify_all();
        self.inner.not_full.notify_all();
    }
}

#[cfg(target_os = "macos")]
impl MacWorkerReceiver {
    fn recv_batch(
        &self,
        batch: &mut Vec<QueuedFmpSendJob>,
        max: usize,
    ) -> Option<FmpWorkerBatchStats> {
        debug_assert!(batch.is_empty());
        let mut state = self
            .inner
            .state
            .lock()
            .expect("encrypt worker queue poisoned");
        let mut stats = FmpWorkerBatchStats::default();
        loop {
            while let Some(job) = state.pop_job() {
                stats.record_lane(job.queue_lane());
                batch.push(job);
                if batch.len() >= max {
                    break;
                }
            }
            if !batch.is_empty() {
                self.inner.not_full.notify_one();
                return Some(stats);
            }
            if state.closed {
                return None;
            }
            state.waiting = true;
            state = self
                .inner
                .not_empty
                .wait(state)
                .expect("encrypt worker queue poisoned");
            state.waiting = false;
        }
    }
}

#[cfg(not(target_os = "macos"))]
struct FairWorkerSender {
    priority_tx: Sender<QueuedFmpSendJob>,
    bulk_tx: Sender<QueuedFmpSendJob>,
    admission: Arc<FairAdmission>,
}

#[cfg(not(target_os = "macos"))]
struct FairWorkerReceiver {
    priority_rx: Receiver<QueuedFmpSendJob>,
    bulk_rx: Receiver<QueuedFmpSendJob>,
    admission: Arc<FairAdmission>,
    release_buffer: Vec<FairAdmissionReservation>,
}

#[cfg(not(target_os = "macos"))]
struct FairAdmission {
    state: Mutex<FairAdmissionState>,
    not_full: Condvar,
    reserved_len: std::sync::atomic::AtomicUsize,
    total_cap: usize,
    per_flow_cap: usize,
    fast_lane_cap: usize,
}

#[cfg(not(target_os = "macos"))]
#[derive(Default)]
struct FairAdmissionState {
    flows: FairFlowMap,
    total_len: usize,
    full_waiters: usize,
    closed: bool,
}

#[cfg(not(target_os = "macos"))]
struct FairFlowQueue {
    queued: usize,
    weight: usize,
}

#[cfg(not(target_os = "macos"))]
impl FairFlowQueue {
    fn new(weight: usize) -> Self {
        Self { queued: 0, weight }
    }
}

#[cfg(not(target_os = "macos"))]
struct FairAdmissionReservation {
    key: SendTargetKey,
}

#[cfg(not(target_os = "macos"))]
impl FairAdmissionReservation {
    fn new(key: SendTargetKey) -> Self {
        Self { key }
    }

    fn key(&self) -> SendTargetKey {
        self.key
    }
}

#[cfg(not(target_os = "macos"))]
enum FairReserve {
    Reserved(FairAdmissionReservation),
    Full,
    Closed,
}

#[cfg(not(target_os = "macos"))]
enum FairWorkerTryPushError {
    Full(Box<QueuedFmpSendJob>),
    Closed,
}

#[cfg(not(target_os = "macos"))]
impl std::fmt::Debug for FairWorkerTryPushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full(_) => f.write_str("Full"),
            Self::Closed => f.write_str("Closed"),
        }
    }
}

#[cfg(not(target_os = "macos"))]
struct FairWorkerPushError;

#[cfg(not(target_os = "macos"))]
fn fair_worker_channel(
    total_cap: usize,
    per_flow_cap: usize,
    quantum_bytes: usize,
) -> (FairWorkerSender, FairWorkerReceiver) {
    fair_worker_channel_with_priority_cap(
        total_cap,
        per_flow_cap,
        worker_priority_channel_cap(),
        quantum_bytes,
    )
}

#[cfg(not(target_os = "macos"))]
fn fair_worker_channel_with_priority_cap(
    total_cap: usize,
    per_flow_cap: usize,
    priority_cap: usize,
    _quantum_bytes: usize,
) -> (FairWorkerSender, FairWorkerReceiver) {
    let total_cap = total_cap.max(1);
    let per_flow_cap = per_flow_cap.max(1);
    let priority_cap = priority_cap.max(1);
    let (priority_tx, priority_rx) = bounded(priority_cap);
    let (bulk_tx, bulk_rx) = bounded(total_cap);
    let admission = Arc::new(FairAdmission {
        state: Mutex::new(FairAdmissionState::default()),
        not_full: Condvar::new(),
        reserved_len: std::sync::atomic::AtomicUsize::new(0),
        total_cap,
        per_flow_cap,
        // Let a freshly idle worker accept one syscall-sized worker batch
        // without taking the fairness mutex, but don't let that mutex bypass
        // hide a whole extra per-flow queue window.
        fast_lane_cap: worker_fast_lane_cap(total_cap, per_flow_cap),
    });
    (
        FairWorkerSender {
            priority_tx,
            bulk_tx,
            admission: Arc::clone(&admission),
        },
        FairWorkerReceiver {
            priority_rx,
            bulk_rx,
            admission,
            release_buffer: Vec::new(),
        },
    )
}

#[cfg(not(target_os = "macos"))]
impl FairWorkerSender {
    fn try_push(&self, job: QueuedFmpSendJob) -> Result<(), FairWorkerTryPushError> {
        if job.queue_lane() == EncryptWorkerLane::Priority {
            return match self.priority_tx.try_send(job) {
                Ok(()) => Ok(()),
                Err(TrySendError::Full(job)) => Err(FairWorkerTryPushError::Full(Box::new(job))),
                Err(TrySendError::Disconnected(job)) => {
                    drop(job);
                    Err(FairWorkerTryPushError::Closed)
                }
            };
        }

        let job = if self.admission.is_idle() && self.bulk_tx.len() < self.admission.fast_lane_cap {
            match self.bulk_tx.try_send(job) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(job)) => job,
                Err(TrySendError::Disconnected(job)) => {
                    drop(job);
                    return Err(FairWorkerTryPushError::Closed);
                }
            }
        } else {
            job
        };

        let key = job.flow_key();
        let weight = job.scheduling_weight();
        match self.admission.try_reserve(key, weight) {
            FairReserve::Reserved(reservation) => {
                let mut job = job;
                job.mark_fair_reserved(reservation);
                match self.bulk_tx.try_send(job) {
                    Ok(()) => Ok(()),
                    Err(TrySendError::Full(mut job)) => {
                        if let Some(reservation) = job.take_fair_reservation() {
                            self.admission.release(reservation);
                        }
                        Err(FairWorkerTryPushError::Full(Box::new(job)))
                    }
                    Err(TrySendError::Disconnected(mut job)) => {
                        if let Some(reservation) = job.take_fair_reservation() {
                            self.admission.release(reservation);
                        }
                        drop(job);
                        Err(FairWorkerTryPushError::Closed)
                    }
                }
            }
            FairReserve::Full => Err(FairWorkerTryPushError::Full(Box::new(job))),
            FairReserve::Closed => {
                drop(job);
                Err(FairWorkerTryPushError::Closed)
            }
        }
    }

    fn push_blocking(&self, job: QueuedFmpSendJob) -> Result<(), FairWorkerPushError> {
        if job.queue_lane() == EncryptWorkerLane::Priority {
            if let Err(SendError(job)) = self.priority_tx.send(job) {
                drop(job);
                return Err(FairWorkerPushError);
            }
            return Ok(());
        }
        let key = job.flow_key();
        let weight = job.scheduling_weight();
        let reservation = match self.admission.reserve_blocking(key, weight) {
            Ok(reservation) => reservation,
            Err(err) => {
                drop(job);
                return Err(err);
            }
        };
        let mut job = job;
        job.mark_fair_reserved(reservation);
        if let Err(SendError(mut job)) = self.bulk_tx.send(job) {
            if let Some(reservation) = job.take_fair_reservation() {
                self.admission.release(reservation);
            }
            drop(job);
            return Err(FairWorkerPushError);
        }
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
impl FairAdmission {
    fn try_reserve(&self, key: SendTargetKey, weight: usize) -> FairReserve {
        let mut state = self
            .state
            .lock()
            .expect("encrypt worker fair admission poisoned");
        if state.closed {
            return FairReserve::Closed;
        }
        if Self::reserve_locked(&mut state, self.total_cap, self.per_flow_cap, key, weight) {
            self.reserved_len
                .store(state.total_len, std::sync::atomic::Ordering::Relaxed);
            return FairReserve::Reserved(FairAdmissionReservation::new(key));
        }
        FairReserve::Full
    }

    fn reserve_blocking(
        &self,
        key: SendTargetKey,
        weight: usize,
    ) -> Result<FairAdmissionReservation, FairWorkerPushError> {
        let mut state = self
            .state
            .lock()
            .expect("encrypt worker fair admission poisoned");
        loop {
            if state.closed {
                return Err(FairWorkerPushError);
            }
            if Self::reserve_locked(&mut state, self.total_cap, self.per_flow_cap, key, weight) {
                self.reserved_len
                    .store(state.total_len, std::sync::atomic::Ordering::Relaxed);
                return Ok(FairAdmissionReservation::new(key));
            }
            state.full_waiters += 1;
            state = self
                .not_full
                .wait(state)
                .expect("encrypt worker fair admission poisoned");
            state.full_waiters = state.full_waiters.saturating_sub(1);
        }
    }

    fn is_idle(&self) -> bool {
        self.reserved_len.load(std::sync::atomic::Ordering::Relaxed) == 0
    }

    fn release(&self, reservation: FairAdmissionReservation) {
        self.release_many(std::slice::from_ref(&reservation));
    }

    fn release_many(&self, reservations: &[FairAdmissionReservation]) {
        if reservations.is_empty() {
            return;
        }
        let mut state = self
            .state
            .lock()
            .expect("encrypt worker fair admission poisoned");
        for reservation in reservations {
            let key = reservation.key();
            if let Some(flow) = state.flows.get_mut(&key) {
                flow.queued = flow.queued.saturating_sub(1);
                if flow.queued == 0 {
                    state.flows.remove(&key);
                }
            }
            state.total_len = state.total_len.saturating_sub(1);
        }
        self.reserved_len
            .store(state.total_len, std::sync::atomic::Ordering::Relaxed);
        let should_notify = state.full_waiters > 0;
        drop(state);
        if should_notify {
            self.not_full.notify_all();
        }
    }

    fn close(&self) {
        let mut state = self
            .state
            .lock()
            .expect("encrypt worker fair admission poisoned");
        state.closed = true;
        drop(state);
        self.not_full.notify_all();
    }

    fn reserve_locked(
        state: &mut FairAdmissionState,
        total_cap: usize,
        per_flow_cap: usize,
        key: SendTargetKey,
        weight: usize,
    ) -> bool {
        if state.total_len.saturating_add(1) > total_cap {
            return false;
        }
        let weight = weight.clamp(MIN_SEND_WEIGHT as usize, MAX_SEND_WEIGHT as usize);
        match state.flows.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let flow = entry.get_mut();
                flow.weight = flow.weight.max(weight);
                let cap = per_flow_cap
                    .saturating_mul(flow.weight)
                    .min(total_cap)
                    .max(1);
                if flow.queued.saturating_add(1) > cap {
                    return false;
                }
                flow.queued += 1;
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                let mut flow = FairFlowQueue::new(weight);
                flow.queued = 1;
                entry.insert(flow);
            }
        }
        state.total_len += 1;
        true
    }
}

#[cfg(not(target_os = "macos"))]
impl Drop for FairWorkerSender {
    fn drop(&mut self) {
        self.admission.close();
    }
}

#[cfg(not(target_os = "macos"))]
impl FairWorkerReceiver {
    fn recv_batch(
        &mut self,
        batch: &mut Vec<QueuedFmpSendJob>,
        max: usize,
    ) -> Option<FmpWorkerBatchStats> {
        debug_assert!(batch.is_empty());
        debug_assert!(self.release_buffer.is_empty());
        let Some(first) = self.recv_next_blocking() else {
            return None;
        };
        let mut stats = FmpWorkerBatchStats::default();
        self.push_received(batch, first, &mut stats);
        while batch.len() < max {
            if let Ok(job) = self.priority_rx.try_recv() {
                self.push_received(batch, job, &mut stats);
                continue;
            }
            match self.bulk_rx.try_recv() {
                Ok(job) => self.push_received(batch, job, &mut stats),
                Err(_) => break,
            }
        }
        self.release_batch_reservations();
        Some(stats)
    }

    fn recv_next_blocking(&mut self) -> Option<QueuedFmpSendJob> {
        if let Ok(job) = self.priority_rx.try_recv() {
            return Some(job);
        }
        self.recv_next_biased_blocking()
    }

    fn recv_next_biased_blocking(&mut self) -> Option<QueuedFmpSendJob> {
        crossbeam_channel::select_biased! {
            recv(self.priority_rx) -> msg => msg.ok().or_else(|| self.recv_bulk_blocking()),
            recv(self.bulk_rx) -> msg => msg.ok().or_else(|| self.priority_rx.recv().ok()),
        }
    }

    fn recv_bulk_blocking(&mut self) -> Option<QueuedFmpSendJob> {
        self.bulk_rx.recv().ok()
    }

    fn push_received(
        &mut self,
        batch: &mut Vec<QueuedFmpSendJob>,
        mut job: QueuedFmpSendJob,
        stats: &mut FmpWorkerBatchStats,
    ) {
        stats.record_lane(job.queue_lane());
        if let Some(reservation) = job.take_fair_reservation() {
            self.release_buffer.push(reservation);
        }
        batch.push(job);
    }

    fn release_batch_reservations(&mut self) {
        if self.release_buffer.is_empty() {
            return;
        }
        self.admission.release_many(&self.release_buffer);
        self.release_buffer.clear();
    }
}

#[cfg(target_os = "macos")]
type WorkerSender = MacWorkerSender;

#[cfg(not(target_os = "macos"))]
type WorkerSender = FairWorkerSender;
