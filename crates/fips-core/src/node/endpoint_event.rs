use super::*;
use crate::transport::PacketBuffer;

/// One source-attributed endpoint payload delivered through the direct PM2 sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsEndpointDirectMessage {
    /// Authenticated FIPS peer that originated the endpoint data.
    pub source_peer: PeerIdentity,
    /// Application-owned payload bytes.
    pub data: PacketBuffer,
    /// Unix-millisecond time when FIPS handed this message to the direct sink.
    pub enqueued_at_ms: u64,
}

impl FipsEndpointDirectMessage {
    /// FIPS node address that originated the endpoint data.
    pub fn source_node_addr(&self) -> &NodeAddr {
        self.source_peer.node_addr()
    }

    /// Source Nostr public key as human-facing bech32 text.
    pub fn source_npub(&self) -> String {
        self.source_peer.npub()
    }
}

/// A PM2 endpoint-output batch delivered without the endpoint-event queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsEndpointDirectBatch {
    messages: Vec<FipsEndpointDirectMessage>,
}

impl FipsEndpointDirectBatch {
    pub(crate) fn from_messages(messages: Vec<FipsEndpointDirectMessage>) -> Self {
        Self { messages }
    }

    /// Messages in this direct delivery batch.
    pub fn messages(&self) -> &[FipsEndpointDirectMessage] {
        &self.messages
    }

    /// Whether every message in this batch came from the same FIPS node.
    pub fn is_single_source(&self) -> bool {
        self.messages
            .windows(2)
            .all(|pair| pair[0].source_node_addr() == pair[1].source_node_addr())
    }

    /// Split this batch into consecutive same-source runs.
    ///
    /// FIPS may coalesce endpoint output from multiple authenticated sources.
    /// Consumers that shard or cache admission by source should use this at
    /// the ownership boundary instead of assuming the first message describes
    /// the whole batch.
    pub fn into_source_runs(self) -> Vec<Self> {
        if self.messages.is_empty() {
            return Vec::new();
        }
        if self.is_single_source() {
            return vec![self];
        }

        let mut runs = Vec::new();
        let mut current = Vec::new();
        let mut current_source = None;

        for message in self.messages {
            let source = *message.source_node_addr();
            if current_source.is_some_and(|current| current != source) {
                runs.push(Self { messages: current });
                current = Vec::new();
            }
            current_source = Some(source);
            current.push(message);
        }

        if !current.is_empty() {
            runs.push(Self { messages: current });
        }
        runs
    }

    /// Take ownership of the delivered messages.
    pub fn into_messages(self) -> Vec<FipsEndpointDirectMessage> {
        self.messages
    }

    /// Number of endpoint messages in the batch.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether the batch contains no messages.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// Error returned by an installed direct endpoint sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FipsEndpointDirectDeliveryError {
    /// The sink could not accept this batch.
    #[error("direct endpoint sink unavailable")]
    Unavailable,
}

/// Application-provided direct PM2 endpoint delivery sink.
///
/// This sink is called synchronously from the PM2 output path with owned packet
/// buffers. It should return quickly and avoid blocking unrelated PM2 progress.
pub trait FipsEndpointDirectSink: Send + Sync + 'static {
    /// Deliver one batch of decrypted endpoint data.
    fn deliver_endpoint_batch(
        &self,
        batch: FipsEndpointDirectBatch,
    ) -> Result<(), FipsEndpointDirectDeliveryError>;
}

impl<F> FipsEndpointDirectSink for F
where
    F: Fn(FipsEndpointDirectBatch) -> Result<(), FipsEndpointDirectDeliveryError>
        + Send
        + Sync
        + 'static,
{
    fn deliver_endpoint_batch(
        &self,
        batch: FipsEndpointDirectBatch,
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

    pub(crate) fn deliver_endpoint_data_batch(
        &self,
        messages: Vec<EndpointDataDelivery>,
    ) -> Result<(), FipsEndpointDirectDeliveryError> {
        let messages = messages
            .into_iter()
            .map(FipsEndpointDirectMessage::from)
            .collect();
        self.deliver_direct_batch(FipsEndpointDirectBatch::from_messages(messages))
    }

    pub(crate) fn deliver_direct_batch(
        &self,
        batch: FipsEndpointDirectBatch,
    ) -> Result<(), FipsEndpointDirectDeliveryError> {
        self.sink.deliver_endpoint_batch(batch)
    }
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
    direct_sink: Option<EndpointDirectSink>,
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

    #[allow(clippy::result_large_err)]
    pub(crate) fn send(
        &self,
        event: NodeEndpointEvent,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
        if event.messages.is_empty() {
            return Ok(());
        }

        if let Some(direct_sink) = self.direct_sink() {
            let count = event.message_count();
            if direct_sink
                .deliver_endpoint_data_batch(event.messages)
                .is_err()
            {
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::EndpointEventBulkDropped,
                    count as u64,
                );
            }
            return Ok(());
        }

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

    #[allow(clippy::result_large_err)]
    pub(in crate::node) fn deliver_endpoint_data_batch(
        &mut self,
        messages: Vec<EndpointDataDelivery>,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<NodeEndpointEvent>> {
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
    pub(crate) fn new(source_peer: PeerIdentity, payload: impl Into<PacketBuffer>) -> Self {
        Self {
            source_peer,
            payload: payload.into(),
            enqueued_at_ms: crate::time::now_ms(),
        }
    }
}

impl From<EndpointDataDelivery> for FipsEndpointDirectMessage {
    fn from(value: EndpointDataDelivery) -> Self {
        Self {
            source_peer: value.source_peer,
            data: value.payload,
            enqueued_at_ms: value.enqueued_at_ms,
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

    fn queued_at(&self) -> Option<crate::perf_profile::TraceStamp> {
        self.queued_at
    }

    fn record_dequeue_wait(&self) {
        let queued_at = self.queued_at();
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
