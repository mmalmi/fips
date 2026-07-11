//! Priority-aware packet channel for transport receive paths.

use super::{TransportAddr, TransportId};
use std::mem;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering::Relaxed},
};
use tokio::sync::mpsc::{
    Sender, UnboundedReceiver, UnboundedSender,
    error::{TryRecvError, TrySendError},
};

pub(crate) trait PacketFastIngressSink: std::fmt::Debug + Send + Sync {
    fn try_ingest_batch(&self, packets: &mut Vec<ReceivedPacket>) -> usize;
}

/// A packet received from a transport.
#[derive(Clone, Debug)]
pub struct ReceivedPacket {
    /// Which transport received this packet.
    pub transport_id: TransportId,
    /// Remote peer address.
    pub remote_addr: TransportAddr,
    /// Packet data.
    pub data: PacketBuffer,
    /// Receipt timestamp (Unix milliseconds).
    pub timestamp_ms: u64,
    /// Monotonic timestamp for optional pipeline queue-wait profiling.
    #[doc(hidden)]
    pub trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
    /// Monotonic timestamp captured when `PacketRx` takes ownership of a
    /// channel item. Distinguishes mpsc/channel residence from rx-loop-owned
    /// batch-tail residence in perf traces.
    #[doc(hidden)]
    pub trace_rx_loop_owned_at: Option<crate::perf_profile::TraceStamp>,
}

impl ReceivedPacket {
    /// Create a received packet with explicit timestamp.
    pub fn with_timestamp(
        transport_id: TransportId,
        remote_addr: TransportAddr,
        data: PacketBuffer,
        timestamp_ms: u64,
    ) -> Self {
        Self::with_trace_timestamp(
            transport_id,
            remote_addr,
            data,
            timestamp_ms,
            crate::perf_profile::stamp(),
        )
    }

    /// Create a received packet with explicit wall-clock and queue timestamps.
    ///
    /// UDP receive paths can drain several datagrams per kernel batch. Those
    /// datagrams arrived close together, so sharing one wall-clock sample and
    /// one queue trace stamp across the batch avoids per-packet clock reads
    /// while preserving arrival order and queue residence visibility.
    pub(crate) fn with_trace_timestamp(
        transport_id: TransportId,
        remote_addr: TransportAddr,
        data: PacketBuffer,
        timestamp_ms: u64,
        trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Self {
        Self {
            transport_id,
            remote_addr,
            data,
            timestamp_ms,
            trace_enqueued_at,
            trace_rx_loop_owned_at: None,
        }
    }

    pub(crate) fn is_transport_priority(&self) -> bool {
        is_transport_priority_packet(self.data.as_slice())
    }
}

/// Byte storage for a received transport packet.
///
/// Receive/decrypt/drop paths carry this owner so pressure drops and endpoint
/// delivery can recycle kernel receive buffers without an extra packet copy.
#[derive(Debug, Default)]
pub struct PacketBuffer {
    data: Vec<u8>,
    start: usize,
    pool: Option<PacketBufferPool>,
}

impl PacketBuffer {
    #[cfg(any(test, target_os = "linux", target_os = "macos"))]
    fn pooled(data: Vec<u8>, pool: PacketBufferPool) -> Self {
        Self {
            data,
            start: 0,
            pool: Some(pool),
        }
    }

    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            start: 0,
            pool: None,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.start..]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[self.start..]
    }

    pub fn len(&self) -> usize {
        self.data.len().saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn into_vec(mut self) -> Vec<u8> {
        self.pool = None;
        if self.start > 0 {
            self.data.drain(..self.start);
            self.start = 0;
        }
        mem::take(&mut self.data)
    }

    pub(crate) fn trim_front(&mut self, len: usize) -> bool {
        if len > self.len() {
            return false;
        }
        self.start += len;
        true
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        if len < self.len() {
            self.data.truncate(self.start + len);
        }
    }

    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    pub(crate) fn try_prepend_slices(&mut self, parts: &[&[u8]], reserve_tail: usize) -> bool {
        let prefix_len = parts
            .iter()
            .fold(0usize, |total, part| total.saturating_add(part.len()));
        if prefix_len == 0 {
            return self.data.capacity().saturating_sub(self.data.len()) >= reserve_tail;
        }

        let len = self.data.len();
        if self.start >= prefix_len && self.data.capacity().saturating_sub(len) >= reserve_tail {
            let new_start = self.start - prefix_len;
            let mut offset = new_start;
            for part in parts {
                self.data[offset..offset + part.len()].copy_from_slice(part);
                offset += part.len();
            }
            self.start = new_start;
            return true;
        }

        if self.data.capacity().saturating_sub(len) < prefix_len.saturating_add(reserve_tail) {
            return false;
        }

        // Move the packet body right inside the existing allocation, then fill
        // the newly opened header space. This is the Vec equivalent of the
        // fixed headroom WireGuard-go keeps in its message buffers.
        unsafe {
            let ptr = self.data.as_mut_ptr();
            std::ptr::copy(
                ptr.add(self.start),
                ptr.add(self.start + prefix_len),
                self.len(),
            );
            let mut offset = self.start;
            for part in parts {
                std::ptr::copy_nonoverlapping(part.as_ptr(), ptr.add(offset), part.len());
                offset += part.len();
            }
            self.data.set_len(len + prefix_len);
        }
        true
    }

    pub(crate) fn replace_visible_prefix(&mut self, remove_len: usize, prefix: &[u8]) -> bool {
        if remove_len > self.len() {
            return false;
        }

        let prefix_len = prefix.len();
        let tail_len = self.len() - remove_len;
        if prefix_len >= remove_len {
            let grow = prefix_len - remove_len;
            if grow > 0 && self.start >= grow {
                let new_start = self.start - grow;
                self.data[new_start..new_start + prefix_len].copy_from_slice(prefix);
                self.start = new_start;
                return true;
            }

            let len = self.data.len();
            if grow > 0 {
                self.data.reserve(grow);
                unsafe {
                    let ptr = self.data.as_mut_ptr();
                    std::ptr::copy(
                        ptr.add(self.start + remove_len),
                        ptr.add(self.start + prefix_len),
                        tail_len,
                    );
                    self.data.set_len(len + grow);
                }
            }
            self.data[self.start..self.start + prefix_len].copy_from_slice(prefix);
            return true;
        }

        let shrink = remove_len - prefix_len;
        if tail_len > 0 {
            self.data.copy_within(
                self.start + remove_len..self.start + remove_len + tail_len,
                self.start + prefix_len,
            );
        }
        self.data.truncate(self.data.len() - shrink);
        self.data[self.start..self.start + prefix_len].copy_from_slice(prefix);
        true
    }

    pub(crate) fn recycle_batch(packets: &mut [Self]) {
        let Some(pool) = packets.first().and_then(|packet| packet.pool.clone()) else {
            return;
        };
        if packets.iter().all(|packet| {
            packet
                .pool
                .as_ref()
                .is_some_and(|packet_pool| pool.shares_storage(packet_pool))
        }) {
            for packet in packets.iter_mut() {
                packet.pool = None;
            }
            pool.put_batch(packets);
        }
    }
}

impl Clone for PacketBuffer {
    fn clone(&self) -> Self {
        Self {
            data: self.as_slice().to_vec(),
            start: 0,
            pool: None,
        }
    }
}

impl AsRef<[u8]> for PacketBuffer {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Drop for PacketBuffer {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.take() {
            pool.put(mem::take(&mut self.data));
        }
    }
}

impl PartialEq for PacketBuffer {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for PacketBuffer {}

/// FMP packet shape that is visible before dataplane authenticates established data.
///
/// Bulk app data is opaque phase-0 data here, so the transport channel only
/// promotes exact control-sized frames that can be identified from public wire
/// length: handshakes, link heartbeats, and fixed-size link MMP reports.
const FMP_VERSION: u8 = crate::node::wire::FMP_VERSION;
const FMP_PHASE_ESTABLISHED: u8 = crate::node::wire::PHASE_ESTABLISHED;
const FMP_PHASE_MSG1: u8 = crate::node::wire::PHASE_MSG1;
const FMP_PHASE_MSG2: u8 = crate::node::wire::PHASE_MSG2;
const FMP_COMMON_PREFIX_SIZE: usize = crate::node::wire::COMMON_PREFIX_SIZE;
const FMP_ESTABLISHED_HEADER_SIZE: usize = crate::node::wire::ESTABLISHED_HEADER_SIZE;
const FMP_MSG1_WIRE_SIZE: usize = crate::node::wire::MSG1_WIRE_SIZE;
const FMP_MSG2_WIRE_SIZE: usize = crate::node::wire::MSG2_WIRE_SIZE;
const AEAD_TAG_SIZE: usize = crate::noise::TAG_SIZE;
const FMP_HEARTBEAT_PLAINTEXT_SIZE: usize = 4 + 1;
const FMP_MMP_SENDER_REPORT_PLAINTEXT_SIZE: usize = crate::mmp::SENDER_REPORT_WIRE_SIZE;
const FMP_MMP_RECEIVER_REPORT_PLAINTEXT_SIZE: usize = crate::mmp::RECEIVER_REPORT_WIRE_SIZE;

fn is_transport_priority_packet(data: &[u8]) -> bool {
    if data.len() < FMP_COMMON_PREFIX_SIZE {
        return false;
    }

    let version = data[0] >> 4;
    let phase = data[0] & 0x0F;
    if version != FMP_VERSION {
        return false;
    }

    match phase {
        FMP_PHASE_MSG1 => data.len() == FMP_MSG1_WIRE_SIZE,
        FMP_PHASE_MSG2 => data.len() == FMP_MSG2_WIRE_SIZE,
        FMP_PHASE_ESTABLISHED => is_fmp_established_priority_packet(data),
        _ => false,
    }
}

fn is_fmp_established_priority_packet(data: &[u8]) -> bool {
    if data.len() < FMP_ESTABLISHED_HEADER_SIZE.saturating_add(AEAD_TAG_SIZE) {
        return false;
    }

    let payload_len = usize::from(u16::from_le_bytes([data[2], data[3]]));
    let expected_len = FMP_ESTABLISHED_HEADER_SIZE
        .saturating_add(payload_len)
        .saturating_add(AEAD_TAG_SIZE);
    if data.len() != expected_len {
        return false;
    }

    matches!(
        payload_len,
        FMP_HEARTBEAT_PLAINTEXT_SIZE
            | FMP_MMP_SENDER_REPORT_PLAINTEXT_SIZE
            | FMP_MMP_RECEIVER_REPORT_PLAINTEXT_SIZE
    )
}

/// Number of receive-batch Vec containers retained for reuse.
const PACKET_BATCH_POOL_LIMIT: usize = 256;
/// Avoid pinning unusually large test/control batches in the hot-path pool.
const PACKET_BATCH_MAX_RETAINED_CAPACITY: usize = 256;
/// Number of packet byte buffers retained after pressure drops.
const PACKET_BUFFER_POOL_LIMIT: usize = 4096;
/// Avoid pinning oversized receive buffers in the hot-path pool.
const PACKET_BUFFER_MAX_RETAINED_CAPACITY: usize = 16 * 1024;

/// Packet count at which the transport receive channel is visibly backlogged.
///
/// This tracks packets still owned by the priority/bulk mpsc channels. Once a
/// batched item is dequeued into `PacketRx`'s pending iterator, it no longer
/// contributes to this counter; those packets are already inside the rx-loop
/// owner's drain budget rather than waiting behind the transport channel.
const TRANSPORT_CHANNEL_BACKLOG_HIGH_WATER: usize = 16_384;

/// Channel sender for received packets.
///
/// The priority lane stays unbounded because control-shaped datagrams must keep
/// making progress even when bulk is saturated. The bulk lane is bounded by the
/// configured packet-channel capacity in packets, not receive-batch items, and
/// uses nonblocking `try_send`: overload sheds bulk explicitly instead of
/// hiding unbounded latency behind the rx loop.
#[derive(Clone, Debug)]
pub struct PacketTx {
    priority: UnboundedSender<PacketQueueItem>,
    bulk: Sender<PacketQueueItem>,
    fast_ingress: Option<Arc<dyn PacketFastIngressSink>>,
    batch_pool: PacketBatchPool,
    #[cfg(any(test, target_os = "linux", target_os = "macos"))]
    buffer_pool: PacketBufferPool,
    /// Packet-count ready hint for priority lane probes. Bulk batch tails check
    /// this instead of touching an empty priority mpsc once per data packet.
    priority_queued_packets: Arc<AtomicUsize>,
    queued_packets: Arc<AtomicUsize>,
    bulk_queued_packets: Arc<AtomicUsize>,
    bulk_packet_capacity: usize,
    track_backlog: bool,
}

/// Channel receiver for received packets.
pub struct PacketRx {
    priority: UnboundedReceiver<PacketQueueItem>,
    bulk: tokio::sync::mpsc::Receiver<PacketQueueItem>,
    priority_queued_packets: Arc<AtomicUsize>,
    queued_packets: Arc<AtomicUsize>,
    bulk_queued_packets: Arc<AtomicUsize>,
    track_backlog: bool,
    pending_priority: Option<PendingPackets>,
    pending_bulk: Option<PendingPackets>,
    priority_closed: bool,
    bulk_closed: bool,
}

#[derive(Clone, Debug)]
struct PacketBatchPool {
    inner: Arc<Mutex<Vec<Vec<ReceivedPacket>>>>,
}

#[derive(Clone, Debug)]
struct PacketBufferPool {
    inner: Arc<Mutex<Vec<Vec<u8>>>>,
    available: Arc<AtomicUsize>,
}

#[derive(Debug)]
pub(crate) struct PacketBatch {
    packets: Vec<ReceivedPacket>,
    pool: Option<PacketBatchPool>,
}

#[derive(Debug)]
enum PacketQueueItem {
    One(ReceivedPacket),
    Batch(PacketBatch),
}

#[derive(Clone, Copy)]
enum PacketLane {
    Priority,
    Bulk,
}

#[derive(Clone, Copy)]
enum PacketQueueTx {
    Priority,
    Bulk,
}

enum PacketSendFailure {
    Closed(PacketQueueItem),
    DroppedBulk(usize),
}

struct PendingPackets {
    batch: PacketBatch,
    rx_loop_owned_at: Option<crate::perf_profile::TraceStamp>,
}

#[derive(Debug, PartialEq, Eq)]
struct PacketQueueDequeueCounts {
    total: usize,
    priority: usize,
    bulk: usize,
}

impl PacketQueueTx {
    fn try_send(self, owner: &PacketTx, item: PacketQueueItem) -> Result<(), PacketSendFailure> {
        match self {
            PacketQueueTx::Priority => owner
                .priority
                .send(item)
                .map_err(|error| PacketSendFailure::Closed(error.0)),
            PacketQueueTx::Bulk => {
                let packet_count = item.packet_count();
                match owner.bulk.try_send(item) {
                    Ok(()) => Ok(()),
                    Err(TrySendError::Full(_item)) => {
                        Err(PacketSendFailure::DroppedBulk(packet_count))
                    }
                    Err(TrySendError::Closed(item)) => Err(PacketSendFailure::Closed(item)),
                }
            }
        }
    }
}

impl PacketQueueItem {
    fn packet_count(&self) -> usize {
        match self {
            PacketQueueItem::One(_) => 1,
            PacketQueueItem::Batch(packets) => packets.packets.len(),
        }
    }

    fn dequeue_counts(&self, lane: PacketLane) -> PacketQueueDequeueCounts {
        let total = self.packet_count();
        match lane {
            PacketLane::Priority => PacketQueueDequeueCounts {
                total,
                priority: total,
                bulk: 0,
            },
            PacketLane::Bulk => PacketQueueDequeueCounts {
                total,
                priority: 0,
                bulk: total,
            },
        }
    }

    fn queued_at(&self) -> Option<crate::perf_profile::TraceStamp> {
        match self {
            PacketQueueItem::One(packet) => packet.trace_enqueued_at,
            PacketQueueItem::Batch(packets) => packets
                .packets
                .first()
                .and_then(|packet| packet.trace_enqueued_at),
        }
    }

    fn record_dequeue_wait(&self, lane: PacketLane) {
        let queued_at = self.queued_at();
        if queued_at.is_none() {
            return;
        }
        let counts = self.dequeue_counts(lane);
        crate::perf_profile::record_since_split_count(
            crate::perf_profile::Stage::TransportChannelWait,
            crate::perf_profile::Stage::TransportPriorityChannelWait,
            crate::perf_profile::Stage::TransportBulkChannelWait,
            queued_at,
            counts.total as u64,
            counts.priority as u64,
            counts.bulk as u64,
        );
    }
}

impl PacketBatchPool {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn take(&self, capacity: usize) -> PacketBatch {
        let packets = {
            let mut guard = self.inner.lock().unwrap_or_else(|error| error.into_inner());
            guard.pop()
        };
        if let Some(mut packets) = packets {
            crate::perf_profile::record_event(crate::perf_profile::Event::PacketBatchPoolReuse);
            packets.clear();
            if packets.capacity() >= capacity {
                return PacketBatch::pooled(packets, self.clone());
            }
            packets.reserve(capacity.saturating_sub(packets.capacity()));
            return PacketBatch::pooled(packets, self.clone());
        }
        crate::perf_profile::record_event(crate::perf_profile::Event::PacketBatchPoolFresh);
        PacketBatch::pooled(Vec::with_capacity(capacity), self.clone())
    }

    fn put(&self, mut packets: Vec<ReceivedPacket>) {
        packets.clear();
        if packets.capacity() > PACKET_BATCH_MAX_RETAINED_CAPACITY {
            crate::perf_profile::record_event(crate::perf_profile::Event::PacketBatchPoolDiscard);
            return;
        }
        let mut guard = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        if guard.len() < PACKET_BATCH_POOL_LIMIT {
            guard.push(packets);
            crate::perf_profile::record_event(crate::perf_profile::Event::PacketBatchPoolReturn);
        } else {
            crate::perf_profile::record_event(crate::perf_profile::Event::PacketBatchPoolDiscard);
        }
    }
}

impl PacketBufferPool {
    #[cfg(any(test, target_os = "linux", target_os = "macos"))]
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
            available: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[cfg(any(test, target_os = "linux", target_os = "macos"))]
    fn take(&self, capacity: usize) -> Vec<u8> {
        if self.available.load(Relaxed) > 0 {
            let buffer = {
                let mut guard = self.inner.lock().unwrap_or_else(|error| error.into_inner());
                guard.pop()
            };
            if let Some(mut buffer) = buffer {
                self.available.fetch_sub(1, Relaxed);
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::PacketBufferPoolReuse,
                );
                prepare_recv_buffer(&mut buffer, capacity);
                return buffer;
            }
        }

        crate::perf_profile::record_event(crate::perf_profile::Event::PacketBufferPoolFresh);
        fresh_recv_buffer(capacity)
    }

    fn put(&self, mut buffer: Vec<u8>) {
        buffer.clear();
        if buffer.capacity() > PACKET_BUFFER_MAX_RETAINED_CAPACITY {
            crate::perf_profile::record_event(crate::perf_profile::Event::PacketBufferPoolDiscard);
            return;
        }

        let mut guard = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        if guard.len() < PACKET_BUFFER_POOL_LIMIT {
            guard.push(buffer);
            self.available.fetch_add(1, Relaxed);
            crate::perf_profile::record_event(crate::perf_profile::Event::PacketBufferPoolReturn);
        } else {
            crate::perf_profile::record_event(crate::perf_profile::Event::PacketBufferPoolDiscard);
        }
    }

    fn shares_storage(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    fn put_batch(&self, packets: &mut [PacketBuffer]) {
        let mut returned = 0usize;
        let mut discarded = 0usize;
        let mut guard = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let available_slots = PACKET_BUFFER_POOL_LIMIT.saturating_sub(guard.len());
        for packet in packets {
            packet.start = 0;
            let mut buffer = mem::take(&mut packet.data);
            buffer.clear();
            if buffer.capacity() <= PACKET_BUFFER_MAX_RETAINED_CAPACITY
                && returned < available_slots
            {
                guard.push(buffer);
                returned += 1;
            } else {
                discarded += 1;
            }
        }
        if returned > 0 {
            self.available.fetch_add(returned, Relaxed);
        }
        drop(guard);
        if returned > 0 {
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::PacketBufferPoolReturn,
                returned as u64,
            );
        }
        if discarded > 0 {
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::PacketBufferPoolDiscard,
                discarded as u64,
            );
        }
    }
}

#[cfg(target_os = "macos")]
fn fresh_recv_buffer(size: usize) -> Vec<u8> {
    vec![0u8; size]
}

#[cfg(all(any(test, target_os = "linux"), not(target_os = "macos")))]
fn fresh_recv_buffer(size: usize) -> Vec<u8> {
    Vec::with_capacity(size)
}

#[cfg(target_os = "macos")]
fn prepare_recv_buffer(buffer: &mut Vec<u8>, size: usize) {
    buffer.resize(size, 0);
}

#[cfg(all(any(test, target_os = "linux"), not(target_os = "macos")))]
fn prepare_recv_buffer(buffer: &mut Vec<u8>, size: usize) {
    buffer.clear();
    if buffer.capacity() < size {
        buffer.reserve(size.saturating_sub(buffer.capacity()));
    }
}

impl PacketBatch {
    fn pooled(packets: Vec<ReceivedPacket>, pool: PacketBatchPool) -> Self {
        Self {
            packets,
            pool: Some(pool),
        }
    }

    pub(crate) fn push(&mut self, packet: ReceivedPacket) {
        self.packets.push(packet);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn as_slice(&self) -> &[ReceivedPacket] {
        &self.packets
    }
}

impl Drop for PacketBatch {
    fn drop(&mut self) {
        let Some(pool) = self.pool.take() else {
            return;
        };
        pool.put(mem::take(&mut self.packets));
    }
}

impl PendingPackets {
    fn new(
        mut batch: PacketBatch,
        rx_loop_owned_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Self {
        batch.packets.reverse();
        Self {
            batch,
            rx_loop_owned_at,
        }
    }

    fn next(&mut self) -> Option<ReceivedPacket> {
        let mut packet = self.batch.packets.pop()?;
        if let Some(rx_loop_owned_at) = self.rx_loop_owned_at {
            packet.trace_rx_loop_owned_at = Some(rx_loop_owned_at);
        }
        Some(packet)
    }
}

include!("packet_channel_io.rs");
