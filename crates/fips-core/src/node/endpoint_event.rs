use super::*;
use crate::transport::PacketBuffer;
use std::ops::Range;
use std::sync::Arc;

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
#[derive(Debug, Clone, PartialEq, Eq)]
struct FipsEndpointDirectPacketSegment {
    buffer: Arc<PacketBuffer>,
    ranges: Vec<Range<usize>>,
    packet_bytes: usize,
}

impl FipsEndpointDirectPacketSegment {
    fn empty() -> Self {
        Self::new(PacketBuffer::new(Vec::new()), Vec::new())
    }

    fn new(buffer: PacketBuffer, ranges: Vec<Range<usize>>) -> Self {
        Self::from_shared_buffer(Arc::new(buffer), ranges)
    }

    fn from_shared_buffer(buffer: Arc<PacketBuffer>, ranges: Vec<Range<usize>>) -> Self {
        let packet_bytes = ranges.iter().map(|range| range.len()).sum();
        Self::from_shared_buffer_with_packet_bytes(buffer, ranges, packet_bytes)
    }

    fn from_shared_buffer_with_packet_bytes(
        buffer: Arc<PacketBuffer>,
        ranges: Vec<Range<usize>>,
        packet_bytes: usize,
    ) -> Self {
        debug_assert!(ranges.windows(2).all(|pair| pair[0].end <= pair[1].start));
        debug_assert_eq!(
            packet_bytes,
            ranges.iter().map(|range| range.len()).sum::<usize>()
        );
        Self {
            buffer,
            ranges,
            packet_bytes,
        }
    }

    fn len(&self) -> usize {
        self.ranges.len()
    }

    fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    fn split_off(&mut self, at: usize) -> Option<Self> {
        if at >= self.ranges.len() {
            return None;
        }
        let original_packet_bytes = self.packet_bytes;
        let tail_ranges = self.ranges.split_off(at);
        self.packet_bytes = self.ranges.iter().map(|range| range.len()).sum();
        let tail_packet_bytes = original_packet_bytes.saturating_sub(self.packet_bytes);
        Some(Self::from_shared_buffer_with_packet_bytes(
            Arc::clone(&self.buffer),
            tail_ranges,
            tail_packet_bytes,
        ))
    }

    fn retain_ranges<F>(&mut self, next_index: &mut usize, keep: &mut F) -> bool
    where
        F: FnMut(usize, &[u8]) -> bool,
    {
        let bytes = self.buffer.as_slice();
        let original_len = self.ranges.len();
        let mut write = 0usize;
        let mut packet_bytes = 0usize;

        for read in 0..original_len {
            let range = self.ranges[read].clone();
            let current_index = *next_index;
            *next_index = next_index.saturating_add(1);
            if !keep(current_index, &bytes[range.clone()]) {
                continue;
            }

            packet_bytes = packet_bytes.saturating_add(range.len());
            if write != read {
                self.ranges[write] = range;
            }
            write = write.saturating_add(1);
        }

        let changed = write != original_len;
        if changed {
            self.ranges.truncate(write);
        }
        self.packet_bytes = packet_bytes;
        changed
    }
}

/// Consecutive direct endpoint packets from one authenticated FIPS source.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FipsEndpointDirectPacketStorage {
    Segmented(FipsEndpointDirectPacketSegment),
    Chained {
        segments: Vec<FipsEndpointDirectPacketSegment>,
        packet_ends: Vec<usize>,
        packet_bytes: usize,
    },
}

impl FipsEndpointDirectPacketStorage {
    fn empty_segmented() -> Self {
        Self::Segmented(FipsEndpointDirectPacketSegment::empty())
    }

    fn push_segment(&mut self, segment: FipsEndpointDirectPacketSegment) {
        if segment.is_empty() {
            return;
        }

        match self {
            Self::Segmented(current) if current.is_empty() => {
                *current = segment;
            }
            Self::Segmented(current) => {
                let first = std::mem::replace(current, FipsEndpointDirectPacketSegment::empty());
                let first_count = first.len();
                let second_count = first_count.saturating_add(segment.len());
                let packet_bytes = first.packet_bytes.saturating_add(segment.packet_bytes);
                *self = Self::Chained {
                    segments: vec![first, segment],
                    packet_ends: vec![first_count, second_count],
                    packet_bytes,
                };
            }
            Self::Chained {
                segments,
                packet_ends,
                packet_bytes,
            } => {
                let packet_count = packet_ends
                    .last()
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(segment.len());
                *packet_bytes = packet_bytes.saturating_add(segment.packet_bytes);
                packet_ends.push(packet_count);
                segments.push(segment);
            }
        }
    }

    fn append_storage(&mut self, other: Self) {
        match other {
            Self::Segmented(segment) => self.push_segment(segment),
            Self::Chained { segments, .. } => {
                for segment in segments {
                    self.push_segment(segment);
                }
            }
        }
    }

    fn packet_count(&self) -> usize {
        match self {
            Self::Segmented(segment) => segment.len(),
            Self::Chained { packet_ends, .. } => packet_ends.last().copied().unwrap_or(0),
        }
    }

    fn split_off_packets(&mut self, at: usize) -> Option<Self> {
        if at >= self.packet_count() {
            return None;
        }
        if at == 0 {
            return Some(std::mem::replace(self, Self::empty_segmented()));
        }

        match self {
            Self::Segmented(segment) => segment.split_off(at).map(Self::Segmented),
            Self::Chained {
                segments,
                packet_ends,
                packet_bytes,
            } => {
                let original_packet_bytes = *packet_bytes;
                let segment_index = packet_ends.partition_point(|end| *end <= at);
                let previous_end = segment_index
                    .checked_sub(1)
                    .and_then(|index| packet_ends.get(index).copied())
                    .unwrap_or(0);
                let split_in_segment = at - previous_end;
                let mut tail_segments;
                let mut tail_packet_ends;

                if split_in_segment == 0 {
                    tail_segments = segments.split_off(segment_index);
                    tail_packet_ends = packet_ends.split_off(segment_index);
                    for end in &mut tail_packet_ends {
                        *end = end.saturating_sub(at);
                    }
                } else {
                    let original_segment_end = packet_ends[segment_index];
                    tail_segments = segments.split_off(segment_index + 1);
                    let tail_segment = segments[segment_index]
                        .split_off(split_in_segment)
                        .expect("split point inside segment must produce a tail");
                    tail_segments.insert(0, tail_segment);

                    tail_packet_ends = packet_ends.split_off(segment_index + 1);
                    if let Some(head_end) = packet_ends.last_mut() {
                        *head_end = at;
                    }
                    for end in &mut tail_packet_ends {
                        *end = end.saturating_sub(at);
                    }
                    tail_packet_ends.insert(0, original_segment_end - at);
                }

                *packet_bytes = segments.iter().map(|segment| segment.packet_bytes).sum();
                let tail_packet_bytes = original_packet_bytes.saturating_sub(*packet_bytes);
                Some(Self::build_chained_from_parts(
                    tail_segments,
                    tail_packet_ends,
                    tail_packet_bytes,
                ))
            }
        }
    }

    fn build_chained_from_parts(
        mut segments: Vec<FipsEndpointDirectPacketSegment>,
        packet_ends: Vec<usize>,
        packet_bytes: usize,
    ) -> Self {
        match segments.len() {
            0 => Self::empty_segmented(),
            1 => Self::Segmented(segments.pop().expect("one segment must exist")),
            _ => Self::Chained {
                segments,
                packet_ends,
                packet_bytes,
            },
        }
    }
}

/// Consecutive direct endpoint packets from one authenticated FIPS source.
///
/// This can chain opened EndpointData buffers and expose packet slices by range.
/// That is the canonical direct dataplane endpoint payload contract for
/// high-throughput embedders: FIPS owns authentication and ordering, while the
/// embedder can still apply live routing policy before borrowing packet bytes
/// for TUN writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsEndpointDirectPacketRun {
    meta: FipsEndpointDirectPacketRunMeta,
    storage: FipsEndpointDirectPacketStorage,
}

/// Borrowed packet slices from a direct endpoint packet run.
pub struct FipsEndpointDirectPacketSlices<'a> {
    storage: &'a FipsEndpointDirectPacketStorage,
    index: usize,
    segment_index: usize,
    segment_packet_index: usize,
    remaining: usize,
}

impl FipsEndpointDirectPacketRun {
    pub(crate) fn from_segmented_payload(
        meta: FipsEndpointDirectPacketRunMeta,
        buffer: PacketBuffer,
        ranges: Vec<Range<usize>>,
    ) -> Self {
        Self {
            meta,
            storage: FipsEndpointDirectPacketStorage::Segmented(
                FipsEndpointDirectPacketSegment::new(buffer, ranges),
            ),
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
        self.storage.packet_count()
    }

    /// Whether the run contains no packets.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Sum of endpoint packet bytes, excluding bulk length metadata.
    pub fn packet_bytes(&self) -> usize {
        match &self.storage {
            FipsEndpointDirectPacketStorage::Segmented(segment) => segment.packet_bytes,
            FipsEndpointDirectPacketStorage::Chained { packet_bytes, .. } => *packet_bytes,
        }
    }

    /// Borrow one packet by index.
    pub fn packet_slice(&self, index: usize) -> Option<&[u8]> {
        match &self.storage {
            FipsEndpointDirectPacketStorage::Segmented(segment) => segment
                .ranges
                .get(index)
                .map(|range| &segment.buffer.as_slice()[range.clone()]),
            FipsEndpointDirectPacketStorage::Chained {
                segments,
                packet_ends,
                ..
            } => {
                let segment_index = packet_ends.partition_point(|end| *end <= index);
                let previous_end = segment_index
                    .checked_sub(1)
                    .and_then(|previous| packet_ends.get(previous).copied())
                    .unwrap_or(0);
                segments.get(segment_index).and_then(|segment| {
                    segment
                        .ranges
                        .get(index - previous_end)
                        .map(|range| &segment.buffer.as_slice()[range.clone()])
                })
            }
        }
    }

    pub(crate) fn append_run(&mut self, other: FipsEndpointDirectPacketRun) {
        debug_assert!(self.matches_append_meta(&other));
        self.storage.append_storage(other.storage);
    }

    pub(crate) fn matches_append_meta(&self, other: &Self) -> bool {
        self.meta.source_peer == other.meta.source_peer
            && self.meta.previous_hop_addr == other.meta.previous_hop_addr
            && self.meta.received_k_bit == other.meta.received_k_bit
            && self.meta.direct_path == other.meta.direct_path
    }

    /// Borrow packet bytes without materializing per-packet buffers.
    pub fn packet_slices(&self) -> FipsEndpointDirectPacketSlices<'_> {
        FipsEndpointDirectPacketSlices {
            storage: &self.storage,
            index: 0,
            segment_index: 0,
            segment_packet_index: 0,
            remaining: self.len(),
        }
    }

    /// Keep only packets accepted by the caller while preserving backing storage.
    ///
    /// The predicate receives the original packet index and immutable bytes. This
    /// keeps routing/admission policy outside FIPS while allowing embedders to
    /// remove rejected ranges before a TUN writer borrows or mutates the run.
    pub fn retain_packets<F>(&mut self, mut keep: F)
    where
        F: FnMut(usize, &[u8]) -> bool,
    {
        match &mut self.storage {
            FipsEndpointDirectPacketStorage::Segmented(segment) => {
                let mut index = 0usize;
                segment.retain_ranges(&mut index, &mut keep);
            }
            FipsEndpointDirectPacketStorage::Chained {
                segments,
                packet_ends,
                packet_bytes,
            } => {
                let mut index = 0usize;
                let mut retained_bytes = 0usize;
                let mut changed = false;
                for segment in segments.iter_mut() {
                    changed |= segment.retain_ranges(&mut index, &mut keep);
                    retained_bytes = retained_bytes.saturating_add(segment.packet_bytes);
                }
                if changed {
                    segments.retain(|segment| !segment.is_empty());
                    packet_ends.clear();
                    let mut packet_count = 0usize;
                    for segment in segments.iter() {
                        packet_count = packet_count.saturating_add(segment.len());
                        packet_ends.push(packet_count);
                    }
                    *packet_bytes = retained_bytes;
                }
            }
        }
    }

    /// Split this run at a packet index without copying packet bytes.
    ///
    /// The original run keeps packets before `at`; the returned run contains
    /// packets from `at` onward with the same authenticated source metadata.
    pub fn split_off_packets(&mut self, at: usize) -> Option<Self> {
        let storage = self.storage.split_off_packets(at)?;
        Some(Self {
            meta: self.meta.clone(),
            storage,
        })
    }
}

impl<'a> Iterator for FipsEndpointDirectPacketSlices<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let packet = match self.storage {
            FipsEndpointDirectPacketStorage::Segmented(segment) => segment
                .ranges
                .get(self.index)
                .map(|range| &segment.buffer.as_slice()[range.clone()]),
            FipsEndpointDirectPacketStorage::Chained { segments, .. } => loop {
                let Some(segment) = segments.get(self.segment_index) else {
                    break None;
                };
                if self.segment_packet_index < segment.len() {
                    let packet = segment
                        .ranges
                        .get(self.segment_packet_index)
                        .map(|range| &segment.buffer.as_slice()[range.clone()]);
                    self.segment_packet_index = self.segment_packet_index.saturating_add(1);
                    if self.segment_packet_index >= segment.len() {
                        self.segment_index = self.segment_index.saturating_add(1);
                        self.segment_packet_index = 0;
                    }
                    break packet;
                }
                self.segment_index = self.segment_index.saturating_add(1);
                self.segment_packet_index = 0;
            },
        };
        if packet.is_some() {
            self.index = self.index.saturating_add(1);
            self.remaining = self.remaining.saturating_sub(1);
        }
        packet
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for FipsEndpointDirectPacketSlices<'_> {}

/// Established endpoint packet runs delivered without the endpoint-event queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsEndpointDirectPacketBatch {
    packet_runs: Vec<FipsEndpointDirectPacketRun>,
}

impl FipsEndpointDirectPacketBatch {
    pub(crate) fn from_packet_runs(packet_runs: Vec<FipsEndpointDirectPacketRun>) -> Self {
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
