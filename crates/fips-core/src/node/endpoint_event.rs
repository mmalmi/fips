use super::*;
use crate::transport::PacketBuffer;

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
    /// bulk endpoint data.
    pub(crate) control_command_tx: tokio::sync::mpsc::Sender<NodeEndpointCommand>,
    /// Send endpoint data commands into the node RX loop.
    ///
    /// Bounded by the explicit endpoint packet capacity. Bulk backpressure is
    /// visible to the caller instead of hidden behind an environment-selected
    /// queue size.
    pub(crate) command_tx: tokio::sync::mpsc::Sender<NodeEndpointCommand>,
    /// Receive endpoint data delivered by FIPS sessions.
    ///
    /// Endpoint data uses one bounded app-data channel. Oversized batches split
    /// at the message-credit boundary before any remaining tail drops visibly
    /// via `endpoint_event_bulk_dropped`. Backpressure is still visible through
    /// `endpoint_event_wait` latency and `endpoint_event_backlog_high` when the
    /// consumer falls materially behind.
    pub(crate) event_rx: EndpointEventReceiver,
    /// Clone of the event_tx exposed for in-process loopback (e.g.
    /// `FipsEndpoint::send` to self_npub). Lets the endpoint inject an
    /// event into the same queue without going through the encrypt /
    /// decrypt path, while keeping every consumer reading from a single
    /// channel.
    pub(crate) event_tx: EndpointEventSender,
}

/// Observable owner for endpoint events delivered to embedded applications.
#[derive(Debug, Clone)]
pub(crate) struct EndpointEventSender {
    tx: tokio::sync::mpsc::Sender<NodeEndpointEvent>,
    queued_messages: Arc<AtomicUsize>,
    ready: Arc<EndpointEventReady>,
    message_cap: usize,
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
        let message_cap = endpoint_event_capacity(capacity);
        let (tx, rx) = tokio::sync::mpsc::channel(message_cap);
        let queued_messages = Arc::new(AtomicUsize::new(0));
        let ready = Arc::new(EndpointEventReady::default());
        (
            Self {
                tx,
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

    #[allow(clippy::result_large_err)]
    pub(crate) fn send(
        &self,
        event: NodeEndpointEvent,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
        match event {
            NodeEndpointEvent::Data { .. } => self.send_event(event, true),
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

        let event = NodeEndpointEvent::from_delivery_messages(messages, queued_at)
            .expect("non-empty endpoint event batch should produce event");
        self.send_event(event, true)
    }

    #[allow(clippy::result_large_err)]
    fn send_event(
        &self,
        event: NodeEndpointEvent,
        split_on_pressure: bool,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
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
                Err(tokio::sync::mpsc::error::SendError(event))
            }
        }
    }

    #[allow(clippy::result_large_err)]
    fn split_and_send_event(
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
            return self.send_event(event, false);
        }

        let right = messages.split_off(messages.len() / 2);
        if let Some(left) = NodeEndpointEvent::from_delivery_messages(messages, queued_at) {
            self.send_event(left, true)?;
        }
        if let Some(right) = NodeEndpointEvent::from_delivery_messages(right, queued_at) {
            self.send_event(right, true)?;
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

    #[allow(clippy::result_large_err)]
    pub(in crate::node) fn deliver_endpoint_data(
        &mut self,
        message: EndpointDataDelivery,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
        self.send(NodeEndpointEvent::Data {
            source_peer: message.source_peer,
            payload: message.payload,
            enqueued_at_ms: message.enqueued_at_ms,
            queued_at: crate::perf_profile::stamp(),
        })
    }

    #[allow(clippy::result_large_err)]
    pub(in crate::node) fn deliver_endpoint_data_batch(
        &mut self,
        messages: Vec<EndpointDataDelivery>,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
        if messages.is_empty() {
            return Ok(());
        }

        self.send(NodeEndpointEvent::DataBatch {
            messages,
            queued_at: crate::perf_profile::stamp(),
        })
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
    pub(crate) async fn recv(&mut self) -> Option<NodeEndpointEvent> {
        let event = self.rx.recv().await?;
        self.note_dequeued(&event);
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
                self.note_dequeued(&event);
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

    fn note_dequeued(&self, event: &NodeEndpointEvent) {
        event.record_dequeue_wait();
        let counts = event.dequeue_counts();
        release_endpoint_event_messages(&self.queued_messages, counts.total);
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
#[derive(Debug)]
pub(crate) struct EndpointDataDelivery {
    pub(crate) source_peer: PeerIdentity,
    pub(crate) payload: PacketBuffer,
    pub(crate) enqueued_at_ms: u64,
}

impl EndpointDataDelivery {
    pub(crate) fn new(source_peer: PeerIdentity, payload: impl Into<PacketBuffer>) -> Self {
        Self {
            source_peer,
            payload: payload.into(),
            enqueued_at_ms: crate::time::now_ms(),
        }
    }
}

/// Endpoint data events emitted by the node session receive path.
#[derive(Debug)]
pub(crate) enum NodeEndpointEvent {
    Data {
        source_peer: PeerIdentity,
        payload: PacketBuffer,
        enqueued_at_ms: u64,
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
            NodeEndpointEvent::Data { .. } => EndpointEventDequeueCounts { total: 1 },
            NodeEndpointEvent::DataBatch { messages, .. } => EndpointEventDequeueCounts {
                total: messages.len(),
            },
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
        crate::perf_profile::record_since_count(
            crate::perf_profile::Stage::EndpointEventWait,
            queued_at,
            counts.total as u64,
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
                    enqueued_at_ms: message.enqueued_at_ms,
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
