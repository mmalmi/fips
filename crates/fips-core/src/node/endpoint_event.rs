use super::*;
use crate::transport::PacketBuffer;
use std::ops::Range;
use std::sync::Arc;

/// Authenticated source/session facts for a direct endpoint packet run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsEndpointDirectPacketRunMeta {
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

    /// Authenticated FIPS peer that originated every packet in this run.
    pub fn source_peer(&self) -> &PeerIdentity {
        &self.source_peer
    }

    /// FIPS node address that originated every packet in this run.
    pub fn source_node_addr(&self) -> &NodeAddr {
        self.source_peer.node_addr()
    }

    /// Source Nostr public key as human-facing bech32 text.
    pub fn source_npub(&self) -> String {
        self.source_peer.npub()
    }

    /// Authenticated previous hop for this established FSP receive run.
    pub fn previous_hop_node_addr(&self) -> &NodeAddr {
        &self.previous_hop_addr
    }

    /// Whether FIPS received the run directly from the source node.
    pub fn is_direct_path(&self) -> bool {
        self.direct_path
    }

    /// Whether the established FSP packet carried the key-epoch bit.
    pub fn received_k_bit(&self) -> bool {
        self.received_k_bit
    }

    /// Unix-millisecond time when FIPS handed this run to the direct sink.
    pub fn enqueued_at_ms(&self) -> u64 {
        self.enqueued_at_ms
    }
}

/// Consecutive direct endpoint packets from one authenticated FIPS source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsEndpointDirectSourceRun {
    source_peer: PeerIdentity,
    packets: Vec<PacketBuffer>,
    enqueued_at_ms: u64,
}

impl FipsEndpointDirectSourceRun {
    pub(crate) fn from_source_packets(
        source_peer: PeerIdentity,
        packets: Vec<PacketBuffer>,
        enqueued_at_ms: u64,
    ) -> Self {
        Self {
            source_peer,
            packets,
            enqueued_at_ms,
        }
    }

    /// Authenticated FIPS peer that originated every packet in this run.
    pub fn source_peer(&self) -> &PeerIdentity {
        &self.source_peer
    }

    /// FIPS node address that originated every packet in this run.
    pub fn source_node_addr(&self) -> &NodeAddr {
        self.source_peer.node_addr()
    }

    /// Source Nostr public key as human-facing bech32 text.
    pub fn source_npub(&self) -> String {
        self.source_peer.npub()
    }

    /// Unix-millisecond time when FIPS handed this run to the direct sink.
    pub fn enqueued_at_ms(&self) -> u64 {
        self.enqueued_at_ms
    }

    /// Packets delivered for this source run.
    pub fn packets(&self) -> &[PacketBuffer] {
        &self.packets
    }

    /// Take ownership of the run source and packets.
    pub fn into_parts(self) -> (PeerIdentity, Vec<PacketBuffer>) {
        (self.source_peer, self.packets)
    }

    /// Take ownership of the delivered packets.
    pub fn into_packets(self) -> Vec<PacketBuffer> {
        self.packets
    }

    /// Number of endpoint packets in the run.
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Whether the run contains no packets.
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
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
    fn new(buffer: PacketBuffer, ranges: Vec<Range<usize>>) -> Self {
        Self::from_shared_buffer(Arc::new(buffer), ranges)
    }

    fn from_shared_buffer(buffer: Arc<PacketBuffer>, ranges: Vec<Range<usize>>) -> Self {
        debug_assert!(ranges.windows(2).all(|pair| pair[0].end <= pair[1].start));
        let packet_bytes = ranges.iter().map(|range| range.len()).sum();
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

    fn push_range_from_shared_buffer(
        &mut self,
        buffer: &Arc<PacketBuffer>,
        range: Range<usize>,
    ) -> bool {
        if !Arc::ptr_eq(&self.buffer, buffer) {
            return false;
        }
        if self
            .ranges
            .last()
            .is_some_and(|previous| previous.end > range.start)
        {
            return false;
        }
        self.packet_bytes = self.packet_bytes.saturating_add(range.len());
        self.ranges.push(range);
        true
    }
}

#[derive(Debug)]
struct FipsEndpointDirectPacketSplitGroup {
    lane: usize,
    segments: Vec<FipsEndpointDirectPacketSegment>,
}

impl FipsEndpointDirectPacketSplitGroup {
    fn new(lane: usize) -> Self {
        Self {
            lane,
            segments: Vec::new(),
        }
    }

    fn push(&mut self, buffer: Arc<PacketBuffer>, range: Range<usize>) {
        if let Some(last) = self.segments.last_mut()
            && last.push_range_from_shared_buffer(&buffer, range.clone())
        {
            return;
        }
        self.segments
            .push(FipsEndpointDirectPacketSegment::from_shared_buffer(
                buffer,
                vec![range],
            ));
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
        Self::Segmented(FipsEndpointDirectPacketSegment::new(
            PacketBuffer::new(Vec::new()),
            Vec::new(),
        ))
    }

    fn build_chained(mut segments: Vec<FipsEndpointDirectPacketSegment>) -> Self {
        let mut packet_ends = Vec::with_capacity(segments.len());
        let mut packet_count = 0usize;
        let mut packet_bytes = 0usize;
        segments.retain(|segment| {
            if segment.is_empty() {
                return false;
            }
            packet_count = packet_count.saturating_add(segment.len());
            packet_ends.push(packet_count);
            packet_bytes = packet_bytes.saturating_add(segment.packet_bytes);
            true
        });
        Self::Chained {
            segments,
            packet_ends,
            packet_bytes,
        }
    }

    fn packet_count(&self) -> usize {
        match self {
            Self::Segmented(segment) => segment.len(),
            Self::Chained { packet_ends, .. } => packet_ends.last().copied().unwrap_or(0),
        }
    }

    fn into_segments(self) -> Vec<FipsEndpointDirectPacketSegment> {
        match self {
            Self::Segmented(segment) => vec![segment],
            Self::Chained { segments, .. } => segments,
        }
    }
}

/// Consecutive direct endpoint packets from one authenticated FIPS source.
///
/// Unlike [`FipsEndpointDirectSourceRun`], this can preserve an opened
/// EndpointDataBulk buffer and expose packet slices by range. That is the
/// canonical direct PM2 endpoint payload contract for high-throughput embedders:
/// FIPS owns authentication and ordering, while the embedder can still apply
/// live routing policy before borrowing packet bytes for TUN writes.
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

    /// Authenticated source/session facts for this packet run.
    pub fn meta(&self) -> &FipsEndpointDirectPacketRunMeta {
        &self.meta
    }

    /// Authenticated FIPS peer that originated every packet in this run.
    pub fn source_peer(&self) -> &PeerIdentity {
        self.meta.source_peer()
    }

    /// FIPS node address that originated every packet in this run.
    pub fn source_node_addr(&self) -> &NodeAddr {
        self.meta.source_node_addr()
    }

    /// Source Nostr public key as human-facing bech32 text.
    pub fn source_npub(&self) -> String {
        self.meta.source_npub()
    }

    /// Authenticated previous hop for this established FSP receive run.
    pub fn previous_hop_node_addr(&self) -> &NodeAddr {
        self.meta.previous_hop_node_addr()
    }

    /// Whether FIPS received the run directly from the source node.
    pub fn is_direct_path(&self) -> bool {
        self.meta.is_direct_path()
    }

    /// Whether the established FSP packet carried the key-epoch bit.
    pub fn received_k_bit(&self) -> bool {
        self.meta.received_k_bit()
    }

    /// Unix-millisecond time when FIPS handed this run to the direct sink.
    pub fn enqueued_at_ms(&self) -> u64 {
        self.meta.enqueued_at_ms()
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

    /// Mutably borrow one packet by index.
    pub fn packet_slice_mut(&mut self, index: usize) -> Option<&mut [u8]> {
        match &mut self.storage {
            FipsEndpointDirectPacketStorage::Segmented(segment) => {
                let range = segment.ranges.get(index)?.clone();
                Some(&mut Arc::make_mut(&mut segment.buffer).as_mut_slice()[range])
            }
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
                let segment = segments.get_mut(segment_index)?;
                let range = segment.ranges.get(index - previous_end)?.clone();
                Some(&mut Arc::make_mut(&mut segment.buffer).as_mut_slice()[range])
            }
        }
    }

    pub(crate) fn try_append_run(
        &mut self,
        other: FipsEndpointDirectPacketRun,
    ) -> Result<(), FipsEndpointDirectPacketRun> {
        if !self.matches_append_meta(&other) {
            return Err(other);
        }

        let current = std::mem::replace(
            &mut self.storage,
            FipsEndpointDirectPacketStorage::empty_segmented(),
        );
        let mut segments = match current {
            FipsEndpointDirectPacketStorage::Segmented(segment) => vec![segment],
            FipsEndpointDirectPacketStorage::Chained { segments, .. } => segments,
        };
        match other.storage {
            FipsEndpointDirectPacketStorage::Segmented(segment) => segments.push(segment),
            FipsEndpointDirectPacketStorage::Chained {
                segments: mut other_segments,
                ..
            } => segments.append(&mut other_segments),
        }
        self.storage = FipsEndpointDirectPacketStorage::build_chained(segments);
        Ok(())
    }

    fn matches_append_meta(&self, other: &Self) -> bool {
        self.source_peer() == other.source_peer()
            && self.previous_hop_node_addr() == other.previous_hop_node_addr()
            && self.received_k_bit() == other.received_k_bit()
            && self.is_direct_path() == other.is_direct_path()
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

    /// Partition this run into packet-lane groups without copying packet bytes.
    ///
    /// The caller chooses a lane from immutable endpoint packet bytes. FIPS keeps
    /// authentication/session metadata on every child run and shares the opened
    /// endpoint payload buffer across lane runs.
    pub fn partition_by_packet_lane<F>(
        self,
        lane_count: usize,
        mut lane_for_packet: F,
    ) -> Vec<(usize, Self)>
    where
        F: FnMut(&[u8]) -> usize,
    {
        let meta = self.meta;
        let mut groups: Vec<FipsEndpointDirectPacketSplitGroup> = Vec::new();
        for segment in self.storage.into_segments() {
            let buffer = segment.buffer;
            let bytes = buffer.as_slice();
            for range in segment.ranges {
                let lane = if lane_count == 0 {
                    0
                } else {
                    lane_for_packet(&bytes[range.clone()]) % lane_count
                };
                let group_index = groups.iter().position(|group| group.lane == lane);
                let group = match group_index {
                    Some(index) => &mut groups[index],
                    None => {
                        groups.push(FipsEndpointDirectPacketSplitGroup::new(lane));
                        groups.last_mut().expect("group was just pushed")
                    }
                };
                group.push(Arc::clone(&buffer), range);
            }
        }

        groups
            .into_iter()
            .map(|group| {
                let run = Self {
                    meta: meta.clone(),
                    storage: FipsEndpointDirectPacketStorage::build_chained(group.segments),
                };
                (group.lane, run)
            })
            .collect()
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
                let bytes = segment.buffer.as_slice();
                let mut index = 0usize;
                let mut retained_bytes = 0usize;
                segment.ranges.retain(|range| {
                    let current_index = index;
                    index = index.saturating_add(1);
                    if keep(current_index, &bytes[range.clone()]) {
                        retained_bytes = retained_bytes.saturating_add(range.len());
                        true
                    } else {
                        false
                    }
                });
                segment.packet_bytes = retained_bytes;
            }
            FipsEndpointDirectPacketStorage::Chained {
                segments,
                packet_ends,
                packet_bytes,
            } => {
                let mut index = 0usize;
                let mut retained_bytes = 0usize;
                for segment in segments.iter_mut() {
                    let bytes = segment.buffer.as_slice();
                    let mut segment_retained_bytes = 0usize;
                    segment.ranges.retain(|range| {
                        let current_index = index;
                        index = index.saturating_add(1);
                        if keep(current_index, &bytes[range.clone()]) {
                            retained_bytes = retained_bytes.saturating_add(range.len());
                            segment_retained_bytes =
                                segment_retained_bytes.saturating_add(range.len());
                            true
                        } else {
                            false
                        }
                    });
                    segment.packet_bytes = segment_retained_bytes;
                }
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

    /// Visit each packet as mutable bytes while the run owner is borrowed.
    pub fn for_each_packet_mut<F>(&mut self, mut visit: F)
    where
        F: FnMut(&mut [u8]),
    {
        match &mut self.storage {
            FipsEndpointDirectPacketStorage::Segmented(segment) => {
                let bytes = Arc::make_mut(&mut segment.buffer).as_mut_slice();
                for range in &segment.ranges {
                    visit(&mut bytes[range.clone()]);
                }
            }
            FipsEndpointDirectPacketStorage::Chained { segments, .. } => {
                for segment in segments {
                    let bytes = Arc::make_mut(&mut segment.buffer).as_mut_slice();
                    for range in &segment.ranges {
                        visit(&mut bytes[range.clone()]);
                    }
                }
            }
        }
    }

    /// Materialize this run into the older owned-packet source-run contract.
    pub fn into_source_run(self) -> FipsEndpointDirectSourceRun {
        match self.storage {
            FipsEndpointDirectPacketStorage::Segmented(segment) => {
                let body = segment.buffer.as_slice();
                let packets = segment
                    .ranges
                    .into_iter()
                    .map(|range| body[range].to_vec().into())
                    .collect();
                FipsEndpointDirectSourceRun::from_source_packets(
                    self.meta.source_peer,
                    packets,
                    self.meta.enqueued_at_ms,
                )
            }
            FipsEndpointDirectPacketStorage::Chained { segments, .. } => {
                let mut packets = Vec::new();
                for segment in segments {
                    let body = segment.buffer.as_slice();
                    packets.extend(
                        segment
                            .ranges
                            .into_iter()
                            .map(|range| body[range].to_vec().into()),
                    );
                }
                FipsEndpointDirectSourceRun::from_source_packets(
                    self.meta.source_peer,
                    packets,
                    self.meta.enqueued_at_ms,
                )
            }
        }
    }

    /// Materialize this run into owned packet buffers.
    pub fn into_packets(self) -> Vec<PacketBuffer> {
        self.into_source_run().into_packets()
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

    /// Packet runs in this direct delivery batch.
    pub fn packet_runs(&self) -> &[FipsEndpointDirectPacketRun] {
        &self.packet_runs
    }

    /// Mutably borrow packet runs so the embedder can apply live policy.
    pub fn packet_runs_mut(&mut self) -> &mut [FipsEndpointDirectPacketRun] {
        &mut self.packet_runs
    }

    /// Take ownership of the delivered packet runs.
    pub fn into_packet_runs(self) -> Vec<FipsEndpointDirectPacketRun> {
        self.packet_runs
    }

    /// Whether every run in this batch came from the same FIPS node.
    pub fn is_single_source(&self) -> bool {
        self.packet_runs
            .windows(2)
            .all(|pair| pair[0].source_node_addr() == pair[1].source_node_addr())
    }

    /// Number of endpoint messages in the batch.
    pub fn len(&self) -> usize {
        self.packet_runs
            .iter()
            .map(FipsEndpointDirectPacketRun::len)
            .sum()
    }

    /// Sum of endpoint packet bytes in the batch.
    pub fn packet_bytes(&self) -> usize {
        self.packet_runs
            .iter()
            .map(FipsEndpointDirectPacketRun::packet_bytes)
            .sum()
    }

    /// Number of packet-run records in the batch.
    pub fn run_count(&self) -> usize {
        self.packet_runs.len()
    }

    /// Whether the batch contains no packet runs.
    pub fn is_empty(&self) -> bool {
        self.packet_runs.is_empty()
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
