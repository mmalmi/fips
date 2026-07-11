use super::*;
use crate::transport::PacketBuffer;
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Maximum endpoint packets in one authenticated direct packet run.
pub const FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS: usize = 128;

/// Maximum endpoint packets pending in an installed direct packet sink.
pub const FIPS_ENDPOINT_DIRECT_PACKET_QUEUE_MAX_PACKETS: usize = 4096;

/// Authenticated source/session facts for a direct endpoint packet run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FipsEndpointDirectPacketRunMeta {
    source_peer: PeerIdentity,
    previous_hop_addr: NodeAddr,
    received_k_bit: bool,
    direct_path: bool,
    enqueued_at_ms: u64,
}

impl FipsEndpointDirectPacketRunMeta {
    pub(crate) fn new(
        source_peer: PeerIdentity,
        previous_hop_addr: NodeAddr,
        received_k_bit: bool,
        direct_path: bool,
        enqueued_at_ms: u64,
    ) -> Self {
        Self {
            source_peer,
            previous_hop_addr,
            received_k_bit,
            direct_path,
            enqueued_at_ms,
        }
    }
}

/// Consecutive direct endpoint packets from one authenticated FIPS source.
///
/// FIPS owns authentication and ordering. The embedder can still apply live
/// routing policy before borrowing packet bytes for TUN writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsEndpointDirectPacketRun {
    meta: FipsEndpointDirectPacketRunMeta,
    packets: Vec<PacketBuffer>,
    packet_bytes: usize,
}

/// Borrowed packet slices from a direct endpoint packet run.
pub struct FipsEndpointDirectPacketSlices<'a> {
    packets: std::slice::Iter<'a, PacketBuffer>,
}

impl FipsEndpointDirectPacketRun {
    pub(crate) fn from_packet(meta: FipsEndpointDirectPacketRunMeta, packet: PacketBuffer) -> Self {
        let packet_bytes = packet.len();
        let mut packets = Vec::with_capacity(FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS);
        packets.push(packet);
        Self {
            meta,
            packets,
            packet_bytes,
        }
    }

    /// Authenticated FIPS peer that originated every packet in this run.
    pub fn source_peer(&self) -> &PeerIdentity {
        &self.meta.source_peer
    }

    /// Unix-millisecond time when FIPS handed this run to the direct sink.
    pub fn enqueued_at_ms(&self) -> u64 {
        self.meta.enqueued_at_ms
    }

    /// Number of endpoint packets in the run.
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Whether the run contains no packets.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Sum of endpoint packet bytes, excluding bulk length metadata.
    pub fn packet_bytes(&self) -> usize {
        self.packet_bytes
    }

    /// Borrow one packet by index.
    pub fn packet_slice(&self, index: usize) -> Option<&[u8]> {
        self.packets.get(index).map(PacketBuffer::as_slice)
    }

    pub(crate) fn push_packet(&mut self, packet: PacketBuffer) {
        self.packet_bytes = self.packet_bytes.saturating_add(packet.len());
        self.packets.push(packet);
    }

    pub(crate) fn try_append(&mut self, other: &mut Self) -> bool {
        if self.len().saturating_add(other.len()) > FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS
            || self.meta.source_peer != other.meta.source_peer
            || self.meta.previous_hop_addr != other.meta.previous_hop_addr
            || self.meta.received_k_bit != other.meta.received_k_bit
            || self.meta.direct_path != other.meta.direct_path
        {
            return false;
        }
        self.packet_bytes = self.packet_bytes.saturating_add(other.packet_bytes);
        other.packet_bytes = 0;
        self.packets.append(&mut other.packets);
        true
    }

    /// Borrow packet bytes from the run-owned buffers.
    pub fn packet_slices(&self) -> FipsEndpointDirectPacketSlices<'_> {
        FipsEndpointDirectPacketSlices {
            packets: self.packets.iter(),
        }
    }

    /// Keep only packets accepted by the caller while preserving packet buffers.
    ///
    /// The predicate receives the original packet index and immutable bytes. This
    /// keeps routing/admission policy outside FIPS while allowing embedders to
    /// remove rejected packets before a TUN writer borrows the run.
    pub fn retain_packets<F>(&mut self, mut keep: F)
    where
        F: FnMut(usize, &[u8]) -> bool,
    {
        let mut index = 0usize;
        let mut packet_bytes = 0usize;
        self.packets.retain(|packet| {
            let retained = keep(index, packet.as_slice());
            index = index.saturating_add(1);
            if retained {
                packet_bytes = packet_bytes.saturating_add(packet.len());
            }
            retained
        });
        self.packet_bytes = packet_bytes;
    }

    /// Split this run at a packet index without copying packet bytes.
    ///
    /// The original run keeps packets before `at`; the returned run contains
    /// packets from `at` onward with the same authenticated source metadata.
    pub fn split_off_packets(&mut self, at: usize) -> Option<Self> {
        if at >= self.packets.len() {
            return None;
        }
        let packets = self.packets.split_off(at);
        let packet_bytes = packets.iter().map(PacketBuffer::len).sum();
        self.packet_bytes = self.packet_bytes.saturating_sub(packet_bytes);
        Some(Self {
            meta: self.meta.clone(),
            packets,
            packet_bytes,
        })
    }
}

impl<'a> Iterator for FipsEndpointDirectPacketSlices<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        self.packets.next().map(PacketBuffer::as_slice)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.packets.size_hint()
    }
}

impl ExactSizeIterator for FipsEndpointDirectPacketSlices<'_> {}

impl Drop for FipsEndpointDirectPacketRun {
    fn drop(&mut self) {
        PacketBuffer::recycle_batch(&mut self.packets);
    }
}

/// Established endpoint packet runs delivered without the endpoint-event queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsEndpointDirectPacketBatch {
    packet_runs: Vec<FipsEndpointDirectPacketRun>,
}

impl FipsEndpointDirectPacketBatch {
    pub(crate) fn from_packet_runs(packet_runs: Vec<FipsEndpointDirectPacketRun>) -> Self {
        debug_assert!(
            packet_runs
                .iter()
                .all(|run| run.len() <= FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS)
        );
        Self { packet_runs }
    }

    /// Take ownership of the delivered packet runs.
    pub fn into_packet_runs(self) -> Vec<FipsEndpointDirectPacketRun> {
        self.packet_runs
    }
}

/// Error returned by an installed direct endpoint sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FipsEndpointDirectDeliveryError {
    /// The sink could not accept this batch.
    #[error("direct endpoint sink unavailable")]
    Unavailable,
}

/// Application-provided direct dataplane endpoint delivery sink.
///
/// This sink is called synchronously from the dataplane output path with owned packet
/// buffers. It should return quickly and avoid blocking unrelated dataplane progress.
pub trait FipsEndpointDirectSink: Send + Sync + 'static {
    /// Deliver established endpoint data as authenticated packet runs.
    fn deliver_endpoint_packet_batch(
        &self,
        batch: FipsEndpointDirectPacketBatch,
    ) -> Result<(), FipsEndpointDirectDeliveryError>;
}

impl<F> FipsEndpointDirectSink for F
where
    F: Fn(FipsEndpointDirectPacketBatch) -> Result<(), FipsEndpointDirectDeliveryError>
        + Send
        + Sync
        + 'static,
{
    fn deliver_endpoint_packet_batch(
        &self,
        batch: FipsEndpointDirectPacketBatch,
    ) -> Result<(), FipsEndpointDirectDeliveryError> {
        self(batch)
    }
}

#[derive(Clone)]
pub(crate) struct EndpointDirectSink {
    sink: Arc<dyn FipsEndpointDirectSink>,
}

impl std::fmt::Debug for EndpointDirectSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointDirectSink").finish_non_exhaustive()
    }
}

impl EndpointDirectSink {
    pub(crate) fn new<S>(sink: S) -> Self
    where
        S: FipsEndpointDirectSink,
    {
        Self {
            sink: Arc::new(sink),
        }
    }

    pub(crate) fn deliver_direct_packet_batch(
        &self,
        batch: FipsEndpointDirectPacketBatch,
    ) -> Result<(), FipsEndpointDirectDeliveryError> {
        self.sink.deliver_endpoint_packet_batch(batch)
    }
}

struct FipsEndpointDirectReceiverSink {
    shared: Arc<FipsEndpointDirectReceiverShared>,
}

/// Blocking bounded receiver for authenticated direct endpoint packet runs.
#[derive(Debug)]
pub struct FipsEndpointDirectReceiver {
    shared: Arc<FipsEndpointDirectReceiverShared>,
}

#[derive(Debug)]
struct FipsEndpointDirectReceiverShared {
    state: Mutex<FipsEndpointDirectReceiverState>,
    ready: Condvar,
}

#[derive(Debug, Default)]
struct FipsEndpointDirectReceiverState {
    runs: VecDeque<FipsEndpointDirectPacketRun>,
    packets: usize,
    interrupted: bool,
}

impl FipsEndpointDirectReceiver {
    pub(crate) fn channel() -> (impl FipsEndpointDirectSink, Self) {
        let shared = Arc::new(FipsEndpointDirectReceiverShared {
            state: Mutex::new(FipsEndpointDirectReceiverState::default()),
            ready: Condvar::new(),
        });
        (
            FipsEndpointDirectReceiverSink {
                shared: Arc::clone(&shared),
            },
            Self { shared },
        )
    }

    /// Wait for a source-contiguous packet run batch bounded by `packet_limit`.
    pub fn recv_timeout(
        &self,
        timeout: Duration,
        packet_limit: usize,
    ) -> Result<Vec<FipsEndpointDirectPacketRun>, std::sync::mpsc::RecvTimeoutError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| std::sync::mpsc::RecvTimeoutError::Disconnected)?;
        if state.runs.is_empty() {
            let (next, wait) = self
                .shared
                .ready
                .wait_timeout_while(state, timeout, |state| {
                    state.runs.is_empty() && !state.interrupted
                })
                .map_err(|_| std::sync::mpsc::RecvTimeoutError::Disconnected)?;
            state = next;
            let interrupted = std::mem::take(&mut state.interrupted);
            if state.runs.is_empty() && (interrupted || wait.timed_out()) {
                return Err(std::sync::mpsc::RecvTimeoutError::Timeout);
            }
        }
        take_direct_source_runs(&mut state, packet_limit)
            .ok_or(std::sync::mpsc::RecvTimeoutError::Timeout)
    }

    /// Receive a ready source-contiguous packet run batch without blocking.
    pub fn try_recv(
        &self,
        packet_limit: usize,
    ) -> Result<Vec<FipsEndpointDirectPacketRun>, std::sync::mpsc::TryRecvError> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| std::sync::mpsc::TryRecvError::Disconnected)?;
        let limit = direct_receiver_packet_limit(packet_limit);
        if state.runs.front().is_some_and(|run| run.len() > limit) {
            return Err(std::sync::mpsc::TryRecvError::Empty);
        }
        take_direct_source_runs(&mut state, limit).ok_or(std::sync::mpsc::TryRecvError::Empty)
    }

    /// Wake a blocking receive, for example during application shutdown.
    pub fn interrupt(&self) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.interrupted = true;
        }
        self.shared.ready.notify_all();
    }
}

impl FipsEndpointDirectSink for FipsEndpointDirectReceiverSink {
    fn deliver_endpoint_packet_batch(
        &self,
        batch: FipsEndpointDirectPacketBatch,
    ) -> Result<(), FipsEndpointDirectDeliveryError> {
        let runs = batch.into_packet_runs();
        if runs.is_empty() {
            return Ok(());
        }
        let packets = runs
            .iter()
            .map(FipsEndpointDirectPacketRun::len)
            .sum::<usize>();
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| FipsEndpointDirectDeliveryError::Unavailable)?;
        let queued = state
            .packets
            .checked_add(packets)
            .filter(|queued| *queued <= FIPS_ENDPOINT_DIRECT_PACKET_QUEUE_MAX_PACKETS)
            .ok_or(FipsEndpointDirectDeliveryError::Unavailable)?;
        let wake = state.runs.is_empty();
        state.packets = queued;
        state.runs.extend(runs);
        drop(state);
        if wake {
            self.shared.ready.notify_one();
        }
        Ok(())
    }
}

fn direct_receiver_packet_limit(limit: usize) -> usize {
    limit
        .max(1)
        .min(FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS)
}

fn take_direct_source_runs(
    state: &mut FipsEndpointDirectReceiverState,
    packet_limit: usize,
) -> Option<Vec<FipsEndpointDirectPacketRun>> {
    let first = state.runs.pop_front()?;
    let source = *first.source_peer().node_addr();
    let mut packets = first.len();
    let mut runs = vec![first];
    let limit = direct_receiver_packet_limit(packet_limit);
    while packets < limit {
        let Some(next) = state.runs.front() else {
            break;
        };
        let next_packets = next.len();
        if next.source_peer().node_addr() != &source || packets.saturating_add(next_packets) > limit
        {
            break;
        }
        packets = packets.saturating_add(next_packets);
        runs.push(state.runs.pop_front().expect("front direct run must exist"));
    }
    state.packets = state
        .packets
        .checked_sub(packets)
        .expect("direct receiver packet backlog must cover removed runs");
    Some(runs)
}

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
    /// Send endpoint management commands into the node RX loop ahead of queued
    /// endpoint data.
    pub(crate) control_tx: tokio::sync::mpsc::Sender<NodeEndpointControlCommand>,
    /// Send endpoint data batches into the node RX loop.
    ///
    /// Bounded by the explicit endpoint packet capacity. Bulk backpressure is
    /// visible to the caller instead of hidden behind an environment-selected
    /// queue size.
    pub(crate) data_batch_tx: EndpointDataBatchTx,
    /// Receive endpoint data delivered by FIPS sessions.
    ///
    /// Endpoint data uses one bounded app-data channel. Oversized batches split
    /// at the message-credit boundary before any remaining tail drops visibly
    /// via `endpoint_event_bulk_dropped`. Backpressure is still visible through
    /// `endpoint_event_wait` latency and `endpoint_event_backlog_high` when the
    /// consumer falls materially behind.
    pub(crate) event_rx: EndpointEventReceiver,
    /// Clone of the event_tx exposed for in-process loopback. Lets the endpoint
    /// inject an event into the same queue without going through the encrypt /
    /// decrypt path, while keeping every consumer reading from a single channel.
    pub(crate) event_tx: EndpointEventSender,
    /// Receive registered FSP service datagrams.
    pub(crate) service_event_rx: EndpointServiceEventReceiver,
    /// Clone used for registered in-process loopback service sends.
    pub(crate) service_event_tx: EndpointServiceEventSender,
}

/// Observable owner for endpoint events delivered to embedded applications.
#[derive(Debug, Clone)]
pub(crate) struct EndpointEventSender {
    tx: tokio::sync::mpsc::Sender<NodeEndpointEvent>,
    direct_sink: Option<EndpointDirectSink>,
    queued_messages: Arc<AtomicUsize>,
    ready: Arc<EndpointEventReady>,
    message_cap: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum EndpointEventSendError {
    #[error("endpoint event channel closed")]
    Closed,
}

#[derive(Debug)]
pub(crate) struct EndpointEventReceiver {
    rx: tokio::sync::mpsc::Receiver<NodeEndpointEvent>,
    queued_messages: Arc<AtomicUsize>,
    ready: Arc<EndpointEventReady>,
    closed: bool,
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

fn endpoint_event_capacity(requested: usize) -> usize {
    requested.max(1)
}

fn try_reserve_endpoint_event_messages(
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
}

impl EndpointEventSender {
    pub(in crate::node) fn channel(capacity: usize) -> (Self, EndpointEventReceiver) {
        Self::channel_with_direct_sink(capacity, None)
    }

    pub(in crate::node) fn channel_with_direct_sink(
        capacity: usize,
        direct_sink: Option<EndpointDirectSink>,
    ) -> (Self, EndpointEventReceiver) {
        let message_cap = endpoint_event_capacity(capacity);
        let (tx, rx) = tokio::sync::mpsc::channel(message_cap);
        let queued_messages = Arc::new(AtomicUsize::new(0));
        let ready = Arc::new(EndpointEventReady::default());
        (
            Self {
                tx,
                direct_sink,
                queued_messages: Arc::clone(&queued_messages),
                ready: Arc::clone(&ready),
                message_cap,
            },
            EndpointEventReceiver {
                rx,
                queued_messages,
                ready,
                closed: false,
            },
        )
    }

    pub(crate) fn direct_sink(&self) -> Option<&EndpointDirectSink> {
        self.direct_sink.as_ref()
    }

    pub(crate) fn send(&self, event: NodeEndpointEvent) -> Result<(), EndpointEventSendError> {
        if event.messages.is_empty() {
            return Ok(());
        }

        self.send_event(event, true)
    }

    fn send_event(
        &self,
        event: NodeEndpointEvent,
        split_on_pressure: bool,
    ) -> Result<(), EndpointEventSendError> {
        let count = event.message_count();
        let Some(previous) =
            try_reserve_endpoint_event_messages(&self.queued_messages, self.message_cap, count)
        else {
            if split_on_pressure && count > 1 {
                return self.split_and_send_event(event);
            }
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::EndpointEventBulkDropped,
                count as u64,
            );
            return Ok(());
        };

        let queued = previous.saturating_add(count);
        match self.tx.try_send(event) {
            Ok(()) => {
                self.note_send_success(previous, queued);
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_event)) => {
                self.note_send_rejected(count);
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::EndpointEventBulkDropped,
                    count as u64,
                );
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(event)) => {
                self.note_send_rejected(count);
                drop(event);
                Err(EndpointEventSendError::Closed)
            }
        }
    }

    fn split_and_send_event(&self, event: NodeEndpointEvent) -> Result<(), EndpointEventSendError> {
        let mut messages = event.messages;
        let queued_at = event.queued_at;
        if messages.len() <= 1 {
            return self.send_event(
                NodeEndpointEvent {
                    messages,
                    queued_at,
                },
                false,
            );
        }

        let right = messages.split_off(messages.len() / 2);
        if !messages.is_empty() {
            self.send_event(
                NodeEndpointEvent {
                    messages,
                    queued_at,
                },
                true,
            )?;
        }
        if !right.is_empty() {
            self.send_event(
                NodeEndpointEvent {
                    messages: right,
                    queued_at,
                },
                true,
            )?;
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

    #[cfg(test)]
    pub(crate) fn queued_messages(&self) -> usize {
        self.queued_messages.load(Relaxed)
    }
}

impl Drop for EndpointEventSender {
    fn drop(&mut self) {
        self.ready.notify();
    }
}

impl Drop for EndpointEventReceiver {
    fn drop(&mut self) {
        self.queued_messages.store(0, Relaxed);
        self.ready.notify();
    }
}

impl EndpointEventRuntime {
    pub(in crate::node) fn attach(&mut self, sender: EndpointEventSender) {
        self.sender = Some(sender);
    }

    pub(in crate::node) fn is_attached(&self) -> bool {
        self.sender.is_some()
    }

    pub(in crate::node) fn sender(&self) -> Option<EndpointEventSender> {
        self.sender.clone()
    }

    pub(in crate::node) fn deliver_endpoint_data_batch(
        &mut self,
        messages: Vec<EndpointDataDelivery>,
    ) -> Result<(), EndpointEventSendError> {
        if messages.is_empty() {
            return Ok(());
        }

        let Some(sender) = &self.sender else {
            return Ok(());
        };
        let _t_deliver =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointDeliver);
        sender.send(NodeEndpointEvent {
            messages,
            queued_at: crate::perf_profile::stamp(),
        })
    }
}

impl EndpointEventReceiver {
    pub(crate) async fn recv(&mut self) -> Option<NodeEndpointEvent> {
        let event = self.rx.recv().await?;
        self.note_observed(&event);
        Some(event)
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
        match self.rx.try_recv() {
            Ok(event) => {
                self.note_observed(&event);
                Ok(event)
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                if self.closed {
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
                } else {
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                }
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                self.closed = true;
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
            }
        }
    }

    pub(crate) fn release_messages(&self, count: usize) {
        release_endpoint_event_messages(&self.queued_messages, count);
    }

    fn note_observed(&self, event: &NodeEndpointEvent) {
        event.record_dequeue_wait();
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
#[derive(Debug, Clone)]
pub(crate) struct EndpointDataDelivery {
    pub(crate) source_peer: PeerIdentity,
    pub(crate) payload: PacketBuffer,
    pub(crate) enqueued_at_ms: u64,
}

impl EndpointDataDelivery {
    pub(crate) fn new(source_peer: PeerIdentity, payload: PacketBuffer) -> Self {
        Self {
            source_peer,
            payload,
            enqueued_at_ms: crate::time::now_ms(),
        }
    }
}

/// Endpoint data events emitted by the node session receive path.
#[derive(Debug)]
pub(crate) struct NodeEndpointEvent {
    pub(crate) messages: Vec<EndpointDataDelivery>,
    pub(crate) queued_at: Option<crate::perf_profile::TraceStamp>,
}

impl NodeEndpointEvent {
    pub(in crate::node) fn message_count(&self) -> usize {
        self.messages.len()
    }

    fn record_dequeue_wait(&self) {
        let queued_at = self.queued_at;
        if queued_at.is_none() {
            return;
        }
        crate::perf_profile::record_since_count(
            crate::perf_profile::Stage::EndpointEventWait,
            queued_at,
            self.message_count() as u64,
        );
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
