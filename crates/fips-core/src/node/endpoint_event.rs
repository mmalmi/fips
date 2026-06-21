use super::*;
use crate::transport::PacketBuffer;
#[cfg(unix)]
use crossbeam_channel::{
    Receiver as CrossbeamReceiver, Sender as CrossbeamSender, TrySendError, bounded,
};

/// App-owned packet channels for embedding FIPS without a system TUN.
#[derive(Debug)]
pub struct ExternalPacketIo {
    /// Send outbound IPv6 packets into the node.
    pub outbound_tx: crate::upper::tun::TunOutboundTx,
    /// Receive inbound IPv6 packets delivered by FIPS sessions.
    pub inbound_rx: tokio::sync::mpsc::Receiver<NodeDeliveredPacket>,
}

/// App-owned endpoint data channels for embedding FIPS without a daemon.
#[derive(Debug)]
pub(crate) struct EndpointDataIo {
    /// Send latency-sensitive endpoint data and management commands into the
    /// node RX loop ahead of queued bulk endpoint data.
    pub(crate) priority_command_tx: tokio::sync::mpsc::Sender<NodeEndpointCommand>,
    /// Send endpoint data commands into the node RX loop.
    ///
    /// Bounded with a generous default so normal sender bursts do not
    /// stall on semaphore acquisition. macOS pacing happens at the UDP
    /// egress thread where the real Wi-Fi/interface bottleneck is visible;
    /// constraining this app queue instead caused the inner TCP flow to
    /// collapse under iperf. `FIPS_ENDPOINT_DATA_QUEUE_CAP` overrides the
    /// default for benches.
    pub(crate) command_tx: tokio::sync::mpsc::Sender<NodeEndpointCommand>,
    /// Receive endpoint data delivered by FIPS sessions.
    ///
    /// Priority endpoint events use an unbounded lane so small control-shaped
    /// packets keep a wait-free push from the rx loop. Bulk endpoint messages
    /// are bounded by the endpoint-data capacity; oversized batches split at
    /// the message-credit boundary before any remaining tail drops visibly via
    /// `endpoint_event_bulk_dropped`. Backpressure is still visible through
    /// `endpoint_event_wait` latency and `endpoint_event_backlog_high` when the
    /// consumer falls materially behind.
    pub(crate) event_rx: EndpointEventReceiver,
    /// Clone of the event_tx exposed for in-process loopback (e.g.
    /// `FipsEndpoint::send` to self_npub). Lets the endpoint inject an
    /// event into the same queue without going through the encrypt /
    /// decrypt path, while keeping every consumer reading from a single
    /// channel.
    pub(crate) event_tx: EndpointEventSender,
    /// Shared endpoint-side bulk send runtime.
    ///
    /// The node publishes short-lived, invalidatable leases after it proves an
    /// established UDP/worker route is usable. Endpoint bulk batches may use
    /// those leases to prepare worker jobs without waiting for the rx-loop
    /// command mailbox; priority/control packets keep using the command lane.
    #[cfg(unix)]
    pub(crate) bulk_send_runtime: EndpointBulkSendRuntime,
}

/// Shared endpoint-side bulk send lease store plus feedback lane.
#[cfg(unix)]
#[derive(Clone)]
pub(crate) struct EndpointBulkSendRuntime {
    leases: Arc<std::sync::RwLock<std::collections::HashMap<NodeAddr, EndpointBulkSendLease>>>,
    feedback_tx: tokio::sync::mpsc::Sender<EndpointBulkSendFeedback>,
    committed_dispatch: EndpointCommittedBulkDispatch,
    generation: Arc<std::sync::atomic::AtomicU64>,
}

#[cfg(unix)]
impl std::fmt::Debug for EndpointBulkSendRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointBulkSendRuntime")
            .field("leases", &self.lease_count())
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
#[derive(Clone)]
pub(crate) struct EndpointBulkSendLease {
    pub(in crate::node) source_addr: NodeAddr,
    pub(in crate::node) dest_addr: NodeAddr,
    pub(in crate::node) next_hop_addr: NodeAddr,
    pub(in crate::node) path_mtu: u16,
    pub(in crate::node) default_ttl: u8,
    pub(in crate::node) scheduling_weight: u8,
    pub(in crate::node) direct_path_blocks_direct_payload: bool,
    pub(in crate::node) fsp: EndpointBulkSendFspLease,
    pub(in crate::node) fmp: EndpointBulkSendFmpLease,
    pub(in crate::node) send_target: crate::node::encrypt_worker::SelectedSendTarget,
    pub(in crate::node) workers: crate::node::encrypt_worker::EncryptWorkerPool,
    expires_at: crate::time::Instant,
    generation: u64,
}

#[cfg(unix)]
#[derive(Clone)]
pub(crate) struct EndpointBulkSendFspLease {
    pub(in crate::node) cipher: ring::aead::LessSafeKey,
    pub(in crate::node) counter_authority: crate::noise::SendCounterAuthority,
    pub(in crate::node) session_start_ms: u64,
    pub(in crate::node) current_k_bit: bool,
    pub(in crate::node) spin_bit: bool,
}

#[cfg(unix)]
#[derive(Clone)]
pub(crate) struct EndpointBulkSendFmpLease {
    pub(in crate::node) cipher: ring::aead::LessSafeKey,
    pub(in crate::node) counter_authority: crate::noise::SendCounterAuthority,
    pub(in crate::node) their_index: crate::utils::index::SessionIndex,
    pub(in crate::node) session_start: std::time::Instant,
    pub(in crate::node) base_flags: u8,
}

#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct EndpointBulkSendFeedback {
    pub(in crate::node) records: Vec<EndpointBulkSendFeedbackRecord>,
}

#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Clone, Copy)]
pub(in crate::node) enum EndpointBulkSendSessionBookkeeping {
    Fsp {
        path_mtu: u16,
        bookkeeping: FspSendBookkeepingInput,
    },
}

#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Clone, Copy)]
pub(crate) struct EndpointBulkSendFeedbackRecord {
    pub(in crate::node) dest_addr: NodeAddr,
    pub(in crate::node) next_hop_addr: NodeAddr,
    pub(in crate::node) fmp_counter: u64,
    pub(in crate::node) fmp_timestamp_ms: u32,
    pub(in crate::node) fmp_wire_capacity: usize,
    pub(in crate::node) originated_bytes: usize,
    pub(in crate::node) session_bookkeeping: EndpointBulkSendSessionBookkeeping,
}

#[cfg(unix)]
#[derive(Clone)]
struct EndpointCommittedBulkDispatch {
    tx: CrossbeamSender<EndpointCommittedBulkBatch>,
}

#[cfg(unix)]
struct EndpointCommittedBulkBatch {
    workers: crate::node::encrypt_worker::EncryptWorkerPool,
    jobs: Vec<crate::node::encrypt_worker::FmpSendJob>,
    ready: Arc<EndpointCommittedBulkReady>,
}

#[cfg(unix)]
pub(in crate::node) struct EndpointCommittedBulkHandle {
    ready: Option<Arc<EndpointCommittedBulkReady>>,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointCommittedBulkState {
    Pending,
    Committed,
    Canceled,
}

#[cfg(unix)]
struct EndpointCommittedBulkReady {
    state: std::sync::Mutex<EndpointCommittedBulkState>,
    changed: Condvar,
}

#[cfg(unix)]
impl EndpointCommittedBulkDispatch {
    fn channel(capacity: usize) -> Self {
        let (tx, rx) = bounded(capacity.max(1));
        std::thread::Builder::new()
            .name("fips-endpoint-bulk-commit".to_string())
            .spawn(move || run_endpoint_committed_bulk_dispatch(rx))
            .expect("failed to spawn FIPS endpoint committed bulk dispatcher");
        Self { tx }
    }

    fn try_stage(
        &self,
        workers: crate::node::encrypt_worker::EncryptWorkerPool,
        jobs: Vec<crate::node::encrypt_worker::FmpSendJob>,
    ) -> Option<EndpointCommittedBulkHandle> {
        if jobs.is_empty() {
            return Some(EndpointCommittedBulkHandle { ready: None });
        }

        let ready = Arc::new(EndpointCommittedBulkReady::new());
        let batch = EndpointCommittedBulkBatch {
            workers,
            jobs,
            ready: Arc::clone(&ready),
        };
        match self.tx.try_send(batch) {
            Ok(()) => Some(EndpointCommittedBulkHandle { ready: Some(ready) }),
            Err(TrySendError::Full(batch)) | Err(TrySendError::Disconnected(batch)) => {
                batch.ready.cancel();
                None
            }
        }
    }
}

#[cfg(unix)]
impl EndpointCommittedBulkBatch {
    fn packet_count(&self) -> usize {
        self.jobs.len()
    }
}

#[cfg(unix)]
impl EndpointCommittedBulkHandle {
    pub(in crate::node) fn commit(mut self) {
        if let Some(ready) = self.ready.take() {
            ready.commit();
        }
    }

    pub(in crate::node) fn cancel(mut self) {
        if let Some(ready) = self.ready.take() {
            ready.cancel();
        }
    }
}

#[cfg(unix)]
impl Drop for EndpointCommittedBulkHandle {
    fn drop(&mut self) {
        if let Some(ready) = self.ready.take() {
            ready.cancel();
        }
    }
}

#[cfg(unix)]
impl EndpointCommittedBulkReady {
    fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(EndpointCommittedBulkState::Pending),
            changed: Condvar::new(),
        }
    }

    fn commit(&self) {
        self.complete(EndpointCommittedBulkState::Committed);
    }

    fn cancel(&self) {
        self.complete(EndpointCommittedBulkState::Canceled);
    }

    fn complete(&self, next: EndpointCommittedBulkState) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if *state == EndpointCommittedBulkState::Pending {
            *state = next;
            self.changed.notify_one();
        }
    }

    fn wait(&self) -> EndpointCommittedBulkState {
        let Ok(mut state) = self.state.lock() else {
            return EndpointCommittedBulkState::Canceled;
        };
        while *state == EndpointCommittedBulkState::Pending {
            match self.changed.wait(state) {
                Ok(next) => state = next,
                Err(_) => return EndpointCommittedBulkState::Canceled,
            }
        }
        *state
    }

    #[cfg(test)]
    fn try_state(&self) -> EndpointCommittedBulkState {
        self.state
            .lock()
            .map(|state| *state)
            .unwrap_or(EndpointCommittedBulkState::Canceled)
    }
}

#[cfg(unix)]
fn run_endpoint_committed_bulk_dispatch(rx: CrossbeamReceiver<EndpointCommittedBulkBatch>) {
    loop {
        let Ok(batch) = rx.recv() else {
            break;
        };
        if batch.ready.wait() != EndpointCommittedBulkState::Committed {
            continue;
        }

        crate::perf_profile::record_endpoint_committed_bulk_dispatch(batch.packet_count(), 0, 0);
        let EndpointCommittedBulkBatch { workers, jobs, .. } = batch;
        let _all_enqueued = workers.dispatch_bulk_batch_blocking(jobs);
    }
}

#[cfg(unix)]
impl EndpointBulkSendRuntime {
    pub(in crate::node) fn channel(
        capacity: usize,
    ) -> (Self, tokio::sync::mpsc::Receiver<EndpointBulkSendFeedback>) {
        let feedback_capacity = endpoint_data_command_capacity(capacity).max(1);
        let (feedback_tx, feedback_rx) = tokio::sync::mpsc::channel(feedback_capacity);
        let committed_dispatch = EndpointCommittedBulkDispatch::channel(capacity);
        (
            Self {
                leases: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
                feedback_tx,
                committed_dispatch,
                generation: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            },
            feedback_rx,
        )
    }

    pub(in crate::node) fn publish(&self, mut lease: EndpointBulkSendLease) {
        lease.generation = self.generation.load(Relaxed);
        if let Ok(mut leases) = self.leases.write() {
            leases.insert(lease.dest_addr, lease);
        }
    }

    pub(in crate::node) fn invalidate(&self, dest_addr: &NodeAddr) {
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut leases) = self.leases.write() {
            leases.remove(dest_addr);
        }
    }

    pub(in crate::node) fn lease(&self, dest_addr: &NodeAddr) -> Option<EndpointBulkSendLease> {
        let now = crate::time::instant_now();
        let generation = self.generation.load(Relaxed);
        let mut expired = false;
        let lease = self.leases.read().ok().and_then(|leases| {
            leases.get(dest_addr).and_then(|lease| {
                if lease.generation != generation || lease.expires_at <= now {
                    expired = true;
                    None
                } else {
                    Some(lease.clone())
                }
            })
        });
        if expired && let Ok(mut leases) = self.leases.write() {
            leases.remove(dest_addr);
        }
        lease
    }

    pub(in crate::node) fn try_feedback(
        &self,
        records: Vec<EndpointBulkSendFeedbackRecord>,
    ) -> bool {
        if records.is_empty() {
            return true;
        }
        self.feedback_tx
            .try_send(EndpointBulkSendFeedback { records })
            .is_ok()
    }

    pub(in crate::node) fn try_stage_committed_bulk_dispatch(
        &self,
        workers: crate::node::encrypt_worker::EncryptWorkerPool,
        jobs: Vec<crate::node::encrypt_worker::FmpSendJob>,
    ) -> Option<EndpointCommittedBulkHandle> {
        self.committed_dispatch.try_stage(workers, jobs)
    }

    fn lease_count(&self) -> usize {
        self.leases.read().map(|leases| leases.len()).unwrap_or(0)
    }
}

#[cfg(unix)]
impl EndpointBulkSendLease {
    pub(in crate::node) fn new(
        source_addr: NodeAddr,
        dest_addr: NodeAddr,
        next_hop_addr: NodeAddr,
        path_mtu: u16,
        default_ttl: u8,
        scheduling_weight: u8,
        direct_path_blocks_direct_payload: bool,
        fsp: EndpointBulkSendFspLease,
        fmp: EndpointBulkSendFmpLease,
        send_target: crate::node::encrypt_worker::SelectedSendTarget,
        workers: crate::node::encrypt_worker::EncryptWorkerPool,
        ttl: std::time::Duration,
    ) -> Self {
        Self {
            source_addr,
            dest_addr,
            next_hop_addr,
            path_mtu,
            default_ttl,
            scheduling_weight,
            direct_path_blocks_direct_payload,
            fsp,
            fmp,
            send_target,
            workers,
            expires_at: crate::time::instant_now() + ttl,
            generation: 0,
        }
    }
}

/// Observable owner for endpoint events delivered to embedded applications.
#[derive(Debug, Clone)]
pub(crate) struct EndpointEventSender {
    priority: tokio::sync::mpsc::UnboundedSender<NodeEndpointEvent>,
    bulk: tokio::sync::mpsc::Sender<NodeEndpointEvent>,
    queued_messages: Arc<AtomicUsize>,
    bulk_queued_messages: Arc<AtomicUsize>,
    ready: Arc<EndpointEventReady>,
    bulk_message_cap: usize,
}

#[derive(Debug)]
pub(crate) struct EndpointEventReceiver {
    priority: tokio::sync::mpsc::UnboundedReceiver<NodeEndpointEvent>,
    bulk: tokio::sync::mpsc::Receiver<NodeEndpointEvent>,
    queued_messages: Arc<AtomicUsize>,
    bulk_queued_messages: Arc<AtomicUsize>,
    ready: Arc<EndpointEventReady>,
    priority_closed: bool,
    bulk_closed: bool,
}

#[derive(Debug, Default)]
struct EndpointEventReady {
    sequence: StdMutex<u64>,
    changed: Condvar,
}

impl EndpointEventReady {
    fn notify(&self) {
        if let Ok(mut sequence) = self.sequence.lock() {
            *sequence = sequence.wrapping_add(1);
            self.changed.notify_one();
        }
    }

    fn snapshot(&self) -> u64 {
        self.sequence.lock().map(|sequence| *sequence).unwrap_or(0)
    }

    fn wait_for_change(&self, observed: &mut u64) {
        let Ok(mut sequence) = self.sequence.lock() else {
            return;
        };
        while *sequence == *observed {
            match self.changed.wait(sequence) {
                Ok(next) => sequence = next,
                Err(_) => return,
            }
        }
        *observed = *sequence;
    }
}

#[derive(Clone, Copy)]
enum EndpointEventLane {
    Priority,
    Bulk,
}

fn endpoint_event_lane_for_len(len: usize) -> EndpointEventLane {
    if len <= ENDPOINT_EVENT_PRIORITY_MAX_LEN {
        EndpointEventLane::Priority
    } else {
        EndpointEventLane::Bulk
    }
}

fn endpoint_event_bulk_capacity(requested: usize) -> usize {
    requested.max(1)
}

fn try_reserve_endpoint_event_bulk_messages(
    counter: &AtomicUsize,
    capacity: usize,
    count: usize,
) -> Option<usize> {
    if count == 0 {
        return Some(counter.load(Relaxed));
    }

    counter
        .fetch_update(Relaxed, Relaxed, |current| {
            current.checked_add(count).filter(|next| *next <= capacity)
        })
        .ok()
}

/// Delivery-side owner for endpoint data emitted by session receive handling.
///
/// The rx loop currently owns this runtime, but keeping sender, batching, and
/// backlog accounting behind one value makes the future peer/shard receive
/// runtime move explicit instead of threading endpoint-event fields through
/// `Node` packet handlers.
#[derive(Debug, Default)]
pub(in crate::node) struct EndpointEventRuntime {
    sender: Option<EndpointEventSender>,
    batch_depth: usize,
    batch: Vec<EndpointDataDelivery>,
}

impl EndpointEventSender {
    pub(in crate::node) fn channel(capacity: usize) -> (Self, EndpointEventReceiver) {
        let (priority_tx, priority_rx) = tokio::sync::mpsc::unbounded_channel();
        let bulk_message_cap = endpoint_event_bulk_capacity(capacity);
        let (bulk_tx, bulk_rx) = tokio::sync::mpsc::channel(bulk_message_cap);
        let queued_messages = Arc::new(AtomicUsize::new(0));
        let bulk_queued_messages = Arc::new(AtomicUsize::new(0));
        let ready = Arc::new(EndpointEventReady::default());
        (
            Self {
                priority: priority_tx,
                bulk: bulk_tx,
                queued_messages: Arc::clone(&queued_messages),
                bulk_queued_messages: Arc::clone(&bulk_queued_messages),
                ready: Arc::clone(&ready),
                bulk_message_cap,
            },
            EndpointEventReceiver {
                priority: priority_rx,
                bulk: bulk_rx,
                queued_messages,
                bulk_queued_messages,
                ready,
                priority_closed: false,
                bulk_closed: false,
            },
        )
    }

    pub(in crate::node) fn same_channels(&self, other: &Self) -> bool {
        self.priority.same_channel(&other.priority)
            && self.bulk.same_channel(&other.bulk)
            && Arc::ptr_eq(&self.queued_messages, &other.queued_messages)
            && Arc::ptr_eq(&self.bulk_queued_messages, &other.bulk_queued_messages)
            && Arc::ptr_eq(&self.ready, &other.ready)
            && self.bulk_message_cap == other.bulk_message_cap
    }

    #[allow(clippy::result_large_err)]
    pub(crate) fn send(
        &self,
        event: NodeEndpointEvent,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
        match event {
            NodeEndpointEvent::Data {
                source_peer,
                payload,
                queued_at,
            } => {
                let lane = endpoint_event_lane_for_len(payload.len());
                self.send_to_lane(
                    NodeEndpointEvent::Data {
                        source_peer,
                        payload,
                        queued_at,
                    },
                    lane,
                )
            }
            NodeEndpointEvent::DataBatch {
                messages,
                queued_at,
            } => self.send_data_batch(messages, queued_at),
        }
    }

    #[allow(clippy::result_large_err)]
    fn send_data_batch(
        &self,
        messages: Vec<EndpointDataDelivery>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
        if messages.is_empty() {
            return Ok(());
        }

        let message_count = messages.len();
        let priority_count = messages
            .iter()
            .filter(|message| message.is_priority_sized())
            .count();
        if priority_count == 0 || priority_count == message_count {
            let lane = if priority_count == 0 {
                EndpointEventLane::Bulk
            } else {
                EndpointEventLane::Priority
            };
            let event = NodeEndpointEvent::from_delivery_messages(messages, queued_at)
                .expect("non-empty endpoint event batch should produce event");
            return self.send_to_lane(event, lane);
        }

        let mut priority_messages = Vec::with_capacity(priority_count);
        let mut bulk_messages = Vec::with_capacity(message_count - priority_count);
        for message in messages {
            if message.is_priority_sized() {
                priority_messages.push(message);
            } else {
                bulk_messages.push(message);
            }
        }

        if let Some(event) = NodeEndpointEvent::from_delivery_messages(priority_messages, queued_at)
        {
            self.send_to_lane(event, EndpointEventLane::Priority)?;
        }
        if let Some(event) = NodeEndpointEvent::from_delivery_messages(bulk_messages, queued_at) {
            self.send_to_lane(event, EndpointEventLane::Bulk)?;
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn send_to_lane(
        &self,
        event: NodeEndpointEvent,
        lane: EndpointEventLane,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
        if matches!(lane, EndpointEventLane::Bulk) {
            return self.send_bulk_to_lane(event, true);
        }

        let count = event.message_count();
        let previous = self.queued_messages.fetch_add(count, Relaxed);
        let queued = previous.saturating_add(count);
        match self.priority.send(event) {
            Ok(()) => {
                self.note_send_success(previous, queued);
                Ok(())
            }
            Err(error) => {
                self.note_send_rejected(count);
                Err(error)
            }
        }
    }

    #[allow(clippy::result_large_err)]
    fn send_bulk_to_lane(
        &self,
        event: NodeEndpointEvent,
        split_on_pressure: bool,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
        let count = event.message_count();
        let Some(previous_bulk) = try_reserve_endpoint_event_bulk_messages(
            &self.bulk_queued_messages,
            self.bulk_message_cap,
            count,
        ) else {
            if split_on_pressure && count > 1 {
                return self.split_and_send_bulk_event(event);
            }
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::EndpointEventBulkDropped,
                count as u64,
            );
            return Ok(());
        };

        let queued_bulk = previous_bulk.saturating_add(count);
        if previous_bulk < ENDPOINT_EVENT_BACKLOG_HIGH_WATER
            && queued_bulk >= ENDPOINT_EVENT_BACKLOG_HIGH_WATER
        {
            crate::perf_profile::record_event(
                crate::perf_profile::Event::EndpointEventBulkBacklogHigh,
            );
        }

        let previous = self.queued_messages.fetch_add(count, Relaxed);
        let queued = previous.saturating_add(count);
        match self.bulk.try_send(event) {
            Ok(()) => {
                self.note_send_success(previous, queued);
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_event)) => {
                self.note_bulk_send_rejected(count);
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::EndpointEventBulkDropped,
                    count as u64,
                );
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(event)) => {
                self.note_bulk_send_rejected(count);
                Err(tokio::sync::mpsc::error::SendError(event))
            }
        }
    }

    #[allow(clippy::result_large_err)]
    fn split_and_send_bulk_event(
        &self,
        event: NodeEndpointEvent,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
        let (mut messages, queued_at) = match event {
            NodeEndpointEvent::DataBatch {
                messages,
                queued_at,
            } => (messages, queued_at),
            event => {
                let count = event.message_count();
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::EndpointEventBulkDropped,
                    count as u64,
                );
                return Ok(());
            }
        };
        if messages.len() <= 1 {
            let event = NodeEndpointEvent::from_delivery_messages(messages, queued_at)
                .expect("non-empty split endpoint batch should produce an event");
            return self.send_bulk_to_lane(event, false);
        }

        let right = messages.split_off(messages.len() / 2);
        if let Some(left) = NodeEndpointEvent::from_delivery_messages(messages, queued_at) {
            self.send_bulk_to_lane(left, true)?;
        }
        if let Some(right) = NodeEndpointEvent::from_delivery_messages(right, queued_at) {
            self.send_bulk_to_lane(right, true)?;
        }
        Ok(())
    }

    fn note_send_success(&self, previous: usize, queued: usize) {
        if previous < ENDPOINT_EVENT_BACKLOG_HIGH_WATER
            && queued >= ENDPOINT_EVENT_BACKLOG_HIGH_WATER
        {
            crate::perf_profile::record_event(crate::perf_profile::Event::EndpointEventBacklogHigh);
        }
        self.ready.notify();
    }

    fn note_send_rejected(&self, count: usize) {
        release_endpoint_event_messages(&self.queued_messages, count);
        self.ready.notify();
    }

    fn note_bulk_send_rejected(&self, count: usize) {
        release_endpoint_event_messages(&self.queued_messages, count);
        release_endpoint_event_messages(&self.bulk_queued_messages, count);
        self.ready.notify();
    }

    #[cfg(test)]
    pub(crate) fn queued_messages(&self) -> usize {
        self.queued_messages.load(Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn bulk_queued_messages(&self) -> usize {
        self.bulk_queued_messages.load(Relaxed)
    }
}

impl Drop for EndpointEventSender {
    fn drop(&mut self) {
        if self.priority.strong_count() == 1 && self.bulk.strong_count() == 1 {
            self.ready.notify();
        }
    }
}

impl EndpointEventRuntime {
    pub(in crate::node) fn attach(&mut self, sender: EndpointEventSender) {
        self.sender = Some(sender);
        self.batch_depth = 0;
        self.batch.clear();
    }

    pub(in crate::node) fn is_attached(&self) -> bool {
        self.sender.is_some()
    }

    pub(in crate::node) fn sender(&self) -> Option<EndpointEventSender> {
        self.sender.clone()
    }

    pub(in crate::node) fn begin_batch(&mut self) {
        if self.is_attached() {
            self.batch_depth = self.batch_depth.saturating_add(1);
        }
    }

    pub(in crate::node) fn finish_batch(&mut self) {
        if self.batch_depth == 0 {
            return;
        }
        self.batch_depth -= 1;
        if self.batch_depth == 0 {
            self.flush_batch();
        }
    }

    #[allow(clippy::result_large_err)]
    pub(in crate::node) fn deliver_endpoint_data(
        &mut self,
        message: EndpointDataDelivery,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
        if self.batch_depth > 0 {
            self.batch.push(message);
            return Ok(());
        }

        self.send(NodeEndpointEvent::Data {
            source_peer: message.source_peer,
            payload: message.payload,
            queued_at: crate::perf_profile::stamp(),
        })
    }

    fn flush_batch(&mut self) {
        let count = self.batch.len();
        if count == 0 {
            return;
        }

        let queued_at = crate::perf_profile::stamp();
        let event = if count == 1 {
            let message = self.batch.pop().expect("batch should contain message");
            NodeEndpointEvent::Data {
                source_peer: message.source_peer,
                payload: message.payload,
                queued_at,
            }
        } else {
            NodeEndpointEvent::DataBatch {
                messages: std::mem::take(&mut self.batch),
                queued_at,
            }
        };

        if let Err(error) = self.send(event) {
            debug!(
                error = %error,
                messages = count,
                "Failed to deliver endpoint data event batch"
            );
        }
    }

    #[allow(clippy::result_large_err)]
    fn send(
        &self,
        event: NodeEndpointEvent,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
        let Some(sender) = &self.sender else {
            return Ok(());
        };
        let _t_deliver =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointDeliver);
        sender.send(event)
    }
}

impl EndpointEventReceiver {
    #[cfg(test)]
    pub(crate) fn ready_sequence(&self) -> u64 {
        self.ready.snapshot()
    }

    pub(crate) async fn recv(&mut self) -> Option<NodeEndpointEvent> {
        loop {
            match self.try_recv() {
                Ok(event) => return Some(event),
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return None,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
            }

            tokio::select! {
                biased;
                event = self.priority.recv(), if !self.priority_closed => {
                    match event {
                        Some(event) => {
                            self.note_dequeued(&event);
                            return Some(event);
                        }
                        None => self.priority_closed = true,
                    }
                }
                event = self.bulk.recv(), if !self.bulk_closed => {
                    match event {
                        Some(event) => {
                            self.note_dequeued(&event);
                            return Some(event);
                        }
                        None => self.bulk_closed = true,
                    }
                }
            }
        }
    }

    pub(crate) fn blocking_recv(&mut self) -> Option<NodeEndpointEvent> {
        let mut observed = self.ready.snapshot();
        loop {
            match self.try_recv() {
                Ok(event) => return Some(event),
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return None,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    self.ready.wait_for_change(&mut observed);
                }
            }
        }
    }

    pub(crate) fn try_recv(
        &mut self,
    ) -> Result<NodeEndpointEvent, tokio::sync::mpsc::error::TryRecvError> {
        match self.try_recv_priority() {
            Ok(event) => return Ok(event),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {}
        }

        match self.bulk.try_recv() {
            Ok(event) => {
                self.note_dequeued(&event);
                Ok(event)
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                if self.priority_closed && self.bulk_closed {
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
                } else {
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                }
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                self.bulk_closed = true;
                if self.priority_closed {
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
                } else {
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                }
            }
        }
    }

    pub(crate) fn try_recv_priority(
        &mut self,
    ) -> Result<NodeEndpointEvent, tokio::sync::mpsc::error::TryRecvError> {
        let event = match self.priority.try_recv() {
            Ok(event) => event,
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                return Err(tokio::sync::mpsc::error::TryRecvError::Empty);
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                self.priority_closed = true;
                return Err(tokio::sync::mpsc::error::TryRecvError::Disconnected);
            }
        };
        self.note_dequeued(&event);
        Ok(event)
    }

    fn note_dequeued(&self, event: &NodeEndpointEvent) {
        event.record_dequeue_wait();
        let counts = event.dequeue_counts();
        crate::perf_profile::record_endpoint_event_dequeue(
            counts.total,
            counts.priority,
            counts.bulk,
        );
        release_endpoint_event_messages(&self.queued_messages, counts.total);
        release_endpoint_event_messages(&self.bulk_queued_messages, counts.bulk);
    }
}

pub(in crate::node) fn release_endpoint_event_messages(counter: &AtomicUsize, count: usize) {
    if count == 0 {
        return;
    }

    let previous = counter.fetch_sub(count, Relaxed);
    debug_assert!(
        previous >= count,
        "endpoint event queued message accounting underflow"
    );
}

pub(crate) fn endpoint_data_command_capacity(requested: usize) -> usize {
    if let Ok(raw) = std::env::var("FIPS_ENDPOINT_DATA_QUEUE_CAP")
        && let Ok(value) = raw.trim().parse::<usize>()
        && value > 0
    {
        return value;
    }

    requested.max(1).max(32_768)
}

// Endpoint send batches have already paid the per-packet mpsc wakeup and peer
// identity costs at the embedded API boundary. Charge rx_loop drain budget in
// small packet groups so full batches keep moving without letting one hot
// endpoint queue monopolize the coordinator.
const ENDPOINT_SEND_BATCH_DRAIN_QUANTUM: usize = 8;

fn endpoint_send_batch_drain_cost(packet_count: usize) -> usize {
    packet_count
        .max(1)
        .saturating_add(ENDPOINT_SEND_BATCH_DRAIN_QUANTUM - 1)
        / ENDPOINT_SEND_BATCH_DRAIN_QUANTUM
}

/// Commands accepted by the node endpoint data service.
#[derive(Debug)]
pub(crate) enum NodeEndpointCommand {
    /// Send with an explicit response channel — used by callers that
    /// care whether the local-stack handoff succeeded (e.g.
    /// `blocking_send` waits for the runtime to accept the send).
    Send {
        command: EndpointSendCommand,
        response_tx: tokio::sync::oneshot::Sender<Result<(), NodeError>>,
    },
    /// **Fire-and-forget** variant of `Send` — no oneshot allocation,
    /// no per-packet result channel. Used by the data-plane fast path
    /// (`FipsEndpoint::send`) where the caller already discards the
    /// result. Saves one oneshot::channel() allocation per outbound
    /// packet on the application's send hot path.
    SendOneway { command: EndpointSendCommand },
    /// Fire-and-forget batch of endpoint payloads that already share the same
    /// peer and command lane. This keeps bursty embedded dataplanes from
    /// paying one mpsc send/wake per packet while preserving the priority/bulk
    /// split without repeating the resolved peer identity in every payload.
    SendBatchOneway {
        command: EndpointSendBatchCommand,
        lane: EndpointCommandLane,
    },
    PeerSnapshot {
        response_tx: tokio::sync::oneshot::Sender<Vec<NodeEndpointPeer>>,
    },
    RelaySnapshot {
        response_tx: tokio::sync::oneshot::Sender<Vec<NodeEndpointRelayStatus>>,
    },
    UpdateRelays {
        advert_relays: Vec<String>,
        dm_relays: Vec<String>,
        response_tx: tokio::sync::oneshot::Sender<Result<(), NodeError>>,
    },
    /// Replace the runtime peer list. Newly added auto-connect peers get
    /// `initiate_peer_connection` immediately; removed peers are dropped
    /// from the retry queue (the regular liveness timeout reaps any active
    /// session). Existing entries are kept and their `addresses` field is
    /// refreshed so the next retry sees the latest hints.
    UpdatePeers {
        peers: Vec<crate::config::PeerConfig>,
        response_tx: tokio::sync::oneshot::Sender<Result<UpdatePeersOutcome, NodeError>>,
    },
    /// Force immediate direct-path refresh attempts for configured peers.
    ///
    /// This is intentionally separate from `UpdatePeers`: callers may need to
    /// reprobe a stale active path even when the configured address set is
    /// unchanged, and `update_peers` avoids churning an active peer that is
    /// already on a known candidate.
    RefreshPeerPaths {
        npubs: Vec<String>,
        response_tx: tokio::sync::oneshot::Sender<Result<usize, NodeError>>,
    },
}

/// Message payload for outbound endpoint data handed from an embedded
/// application into the node rx loop.
#[derive(Debug)]
pub(crate) struct EndpointSendCommand {
    send: EndpointDataSend,
    queued_at: Option<crate::perf_profile::TraceStamp>,
}

impl EndpointSendCommand {
    pub(crate) fn new(
        remote: PeerIdentity,
        payload: Vec<u8>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Self {
        Self {
            send: EndpointDataSend::new(remote, EndpointDataPayload::new(payload)),
            queued_at,
        }
    }

    pub(crate) fn lane(&self) -> EndpointCommandLane {
        self.send.payload().lane()
    }

    pub(crate) fn drop_on_backpressure(&self) -> bool {
        self.send.payload().drop_on_backpressure()
    }

    pub(crate) fn into_parts(self) -> (EndpointDataSend, Option<crate::perf_profile::TraceStamp>) {
        (self.send, self.queued_at)
    }
}

/// Batch of endpoint payloads to one resolved peer.
#[derive(Debug)]
pub(crate) struct EndpointSendBatchCommand {
    remote: PeerIdentity,
    payloads: Vec<EndpointDataPayload>,
    queued_at: Option<crate::perf_profile::TraceStamp>,
}

impl EndpointSendBatchCommand {
    pub(crate) fn new(
        remote: PeerIdentity,
        payloads: Vec<EndpointDataPayload>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Option<Self> {
        if payloads.is_empty() {
            return None;
        }
        Some(Self {
            remote,
            payloads,
            queued_at,
        })
    }

    pub(crate) fn lane(&self) -> EndpointCommandLane {
        self.payloads[0].lane()
    }

    pub(crate) fn len(&self) -> usize {
        self.payloads.len()
    }

    pub(crate) fn can_coalesce_with(&self, other: &Self, max_payloads: usize) -> bool {
        self.remote == other.remote
            && self.lane() == other.lane()
            && self.len().saturating_add(other.len()) <= max_payloads
    }

    pub(crate) fn remote(&self) -> PeerIdentity {
        self.remote
    }

    pub(crate) fn drop_on_backpressure(&self) -> bool {
        self.payloads
            .iter()
            .all(EndpointDataPayload::drop_on_backpressure)
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        PeerIdentity,
        Vec<EndpointDataPayload>,
        Option<crate::perf_profile::TraceStamp>,
    ) {
        (self.remote, self.payloads, self.queued_at)
    }
}

impl NodeEndpointCommand {
    pub(crate) fn send(
        remote: PeerIdentity,
        payload: Vec<u8>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
        response_tx: tokio::sync::oneshot::Sender<Result<(), NodeError>>,
    ) -> Self {
        Self::Send {
            command: EndpointSendCommand::new(remote, payload, queued_at),
            response_tx,
        }
    }

    pub(crate) fn send_oneway(
        remote: PeerIdentity,
        payload: Vec<u8>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Self {
        Self::SendOneway {
            command: EndpointSendCommand::new(remote, payload, queued_at),
        }
    }

    pub(crate) fn send_batch_oneway(
        remote: PeerIdentity,
        payloads: Vec<EndpointDataPayload>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
        lane: EndpointCommandLane,
    ) -> Option<Self> {
        debug_assert!(payloads.iter().all(|payload| payload.lane() == lane));
        let command = EndpointSendBatchCommand::new(remote, payloads, queued_at)?;
        debug_assert_eq!(command.lane(), lane);
        Some(Self::SendBatchOneway { command, lane })
    }

    pub(crate) fn lane(&self) -> EndpointCommandLane {
        match self {
            Self::Send { command, .. } | Self::SendOneway { command } => command.lane(),
            Self::SendBatchOneway { lane, .. } => *lane,
            Self::PeerSnapshot { .. }
            | Self::RelaySnapshot { .. }
            | Self::UpdateRelays { .. }
            | Self::UpdatePeers { .. }
            | Self::RefreshPeerPaths { .. } => EndpointCommandLane::Priority,
        }
    }

    pub(crate) fn drop_on_backpressure(&self) -> bool {
        match self {
            Self::SendOneway { command } => {
                command.lane() == EndpointCommandLane::Bulk && command.drop_on_backpressure()
            }
            Self::SendBatchOneway { command, lane } => {
                *lane == EndpointCommandLane::Bulk && command.drop_on_backpressure()
            }
            Self::Send { .. }
            | Self::PeerSnapshot { .. }
            | Self::RelaySnapshot { .. }
            | Self::UpdateRelays { .. }
            | Self::UpdatePeers { .. }
            | Self::RefreshPeerPaths { .. } => false,
        }
    }

    pub(crate) fn drain_cost(&self) -> usize {
        match self {
            Self::SendBatchOneway { command, .. } => endpoint_send_batch_drain_cost(command.len()),
            Self::Send { .. }
            | Self::SendOneway { .. }
            | Self::PeerSnapshot { .. }
            | Self::RelaySnapshot { .. }
            | Self::UpdateRelays { .. }
            | Self::UpdatePeers { .. }
            | Self::RefreshPeerPaths { .. } => 1,
        }
    }

    pub(crate) fn packet_count(&self) -> usize {
        match self {
            Self::SendBatchOneway { command, .. } => command.len(),
            Self::Send { .. }
            | Self::SendOneway { .. }
            | Self::PeerSnapshot { .. }
            | Self::RelaySnapshot { .. }
            | Self::UpdateRelays { .. }
            | Self::UpdatePeers { .. }
            | Self::RefreshPeerPaths { .. } => 1,
        }
    }

    pub(crate) fn into_send_batch_oneway(
        self,
    ) -> Result<(EndpointSendBatchCommand, EndpointCommandLane), Self> {
        match self {
            Self::SendBatchOneway { command, lane } => Ok((command, lane)),
            other => Err(other),
        }
    }
}

/// Reports what changed in response to `UpdatePeers`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UpdatePeersOutcome {
    pub(crate) added: usize,
    pub(crate) removed: usize,
    pub(crate) updated: usize,
    pub(crate) unchanged: usize,
}

/// Authenticated endpoint data emitted by the session receive path.
///
/// Keeping source identity and payload together makes the delivery-side
/// ownership boundary explicit for the current rx loop and for a future
/// peer/session runtime that can move endpoint-data delivery off the bounce path.
#[derive(Debug)]
pub(crate) struct EndpointDataDelivery {
    pub(crate) source_peer: PeerIdentity,
    pub(crate) payload: PacketBuffer,
}

impl EndpointDataDelivery {
    pub(crate) fn new(source_peer: PeerIdentity, payload: impl Into<PacketBuffer>) -> Self {
        Self {
            source_peer,
            payload: payload.into(),
        }
    }

    fn is_priority_sized(&self) -> bool {
        matches!(
            endpoint_event_lane_for_len(self.payload.len()),
            EndpointEventLane::Priority
        )
    }
}

/// Endpoint data events emitted by the node session receive path.
#[derive(Debug)]
pub(crate) enum NodeEndpointEvent {
    Data {
        source_peer: PeerIdentity,
        payload: PacketBuffer,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    },
    DataBatch {
        messages: Vec<EndpointDataDelivery>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct EndpointEventDequeueCounts {
    pub(in crate::node) total: usize,
    pub(in crate::node) priority: usize,
    pub(in crate::node) bulk: usize,
}

impl NodeEndpointEvent {
    fn message_count(&self) -> usize {
        match self {
            NodeEndpointEvent::Data { .. } => 1,
            NodeEndpointEvent::DataBatch { messages, .. } => messages.len(),
        }
    }

    pub(in crate::node) fn dequeue_counts(&self) -> EndpointEventDequeueCounts {
        match self {
            NodeEndpointEvent::Data { payload, .. } => {
                let priority = usize::from(payload.len() <= ENDPOINT_EVENT_PRIORITY_MAX_LEN);
                EndpointEventDequeueCounts {
                    total: 1,
                    priority,
                    bulk: 1 - priority,
                }
            }
            NodeEndpointEvent::DataBatch { messages, .. } => {
                let priority = messages
                    .iter()
                    .filter(|message| message.is_priority_sized())
                    .count();
                EndpointEventDequeueCounts {
                    total: messages.len(),
                    priority,
                    bulk: messages.len().saturating_sub(priority),
                }
            }
        }
    }

    fn queued_at(&self) -> Option<crate::perf_profile::TraceStamp> {
        match self {
            NodeEndpointEvent::Data { queued_at, .. }
            | NodeEndpointEvent::DataBatch { queued_at, .. } => *queued_at,
        }
    }

    fn record_dequeue_wait(&self) {
        let queued_at = self.queued_at();
        if queued_at.is_none() {
            return;
        }
        let counts = self.dequeue_counts();
        crate::perf_profile::record_since_split_count(
            crate::perf_profile::Stage::EndpointEventWait,
            crate::perf_profile::Stage::EndpointPriorityEventWait,
            crate::perf_profile::Stage::EndpointBulkEventWait,
            queued_at,
            counts.total as u64,
            counts.priority as u64,
            counts.bulk as u64,
        );
    }

    fn from_delivery_messages(
        mut messages: Vec<EndpointDataDelivery>,
        queued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Option<Self> {
        match messages.len() {
            0 => None,
            1 => {
                let message = messages.pop().expect("one endpoint message should exist");
                Some(NodeEndpointEvent::Data {
                    source_peer: message.source_peer,
                    payload: message.payload,
                    queued_at,
                })
            }
            _ => Some(NodeEndpointEvent::DataBatch {
                messages,
                queued_at,
            }),
        }
    }
}

/// Authenticated peer state exposed to embedded endpoint callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeEndpointPeer {
    pub(crate) npub: String,
    pub(crate) node_addr: NodeAddr,
    pub(crate) connected: bool,
    pub(crate) transport_addr: Option<String>,
    pub(crate) transport_type: Option<String>,
    pub(crate) link_id: u64,
    pub(crate) srtt_ms: Option<u64>,
    pub(crate) srtt_age_ms: Option<u64>,
    pub(crate) packets_sent: u64,
    pub(crate) packets_recv: u64,
    pub(crate) bytes_sent: u64,
    pub(crate) bytes_recv: u64,
    pub(crate) rekey_in_progress: bool,
    pub(crate) rekey_draining: bool,
    pub(crate) current_k_bit: Option<bool>,
    pub(crate) last_outbound_route: Option<String>,
    pub(crate) direct_probe_pending: bool,
    pub(crate) direct_probe_after_ms: Option<u64>,
    pub(crate) direct_probe_retry_count: u32,
    pub(crate) direct_probe_auto_reconnect: bool,
    pub(crate) direct_probe_expires_at_ms: Option<u64>,
    pub(crate) nostr_traversal_consecutive_failures: u32,
    pub(crate) nostr_traversal_in_cooldown: bool,
    pub(crate) nostr_traversal_cooldown_until_ms: Option<u64>,
    pub(crate) nostr_traversal_last_observed_skew_ms: Option<i64>,
}

/// Live Nostr relay state exposed to embedded endpoint callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeEndpointRelayStatus {
    pub(crate) url: String,
    pub(crate) status: String,
}

#[cfg(all(test, unix))]
mod endpoint_committed_bulk_tests {
    use super::*;

    #[test]
    fn committed_bulk_ready_waits_for_commit_or_cancel() {
        let ready = Arc::new(EndpointCommittedBulkReady::new());
        assert_eq!(ready.try_state(), EndpointCommittedBulkState::Pending);
        let thread_ready = Arc::clone(&ready);
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_done = Arc::clone(&done);
        let handle = std::thread::spawn(move || {
            assert_eq!(thread_ready.wait(), EndpointCommittedBulkState::Committed);
            thread_done.store(true, Relaxed);
        });

        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(
            !done.load(Relaxed),
            "staged bulk container must stay locked until feedback commits"
        );
        ready.commit();
        handle.join().expect("commit waiter should finish");
        assert!(done.load(Relaxed));

        let ready = EndpointCommittedBulkReady::new();
        ready.cancel();
        assert_eq!(ready.try_state(), EndpointCommittedBulkState::Canceled);
        assert_eq!(ready.wait(), EndpointCommittedBulkState::Canceled);
    }
}
