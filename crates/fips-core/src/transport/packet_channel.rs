//! Priority-aware packet channel for transport receive paths.

use super::{TransportAddr, TransportId};
use std::mem;
use std::ops::{Deref, DerefMut, Index};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering::Relaxed},
};
use std::time::{SystemTime, UNIX_EPOCH};
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
    /// Create a new received packet with current timestamp.
    pub fn new(
        transport_id: TransportId,
        remote_addr: TransportAddr,
        data: impl Into<PacketBuffer>,
    ) -> Self {
        Self::with_trace_timestamp(
            transport_id,
            remote_addr,
            data,
            received_timestamp_ms(),
            crate::perf_profile::stamp(),
        )
    }

    /// Create a received packet with explicit timestamp.
    pub fn with_timestamp(
        transport_id: TransportId,
        remote_addr: TransportAddr,
        data: impl Into<PacketBuffer>,
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
        data: impl Into<PacketBuffer>,
        timestamp_ms: u64,
        trace_enqueued_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Self {
        Self {
            transport_id,
            remote_addr,
            data: data.into(),
            timestamp_ms,
            trace_enqueued_at,
            trace_rx_loop_owned_at: None,
        }
    }

    pub(crate) fn is_transport_priority(&self) -> bool {
        is_transport_priority_packet(&self.data)
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

    pub(crate) fn replace_prefix(&mut self, old_prefix_len: usize, new_prefix: &[u8]) -> bool {
        if old_prefix_len > self.len() {
            return false;
        }

        let new_prefix_len = new_prefix.len();
        if new_prefix_len == old_prefix_len {
            self.data[self.start..self.start + new_prefix_len].copy_from_slice(new_prefix);
            return true;
        }

        let len = self.data.len();
        let tail_len = self.len() - old_prefix_len;
        if new_prefix_len > old_prefix_len {
            let delta = new_prefix_len - old_prefix_len;
            if self.data.capacity().saturating_sub(len) < delta {
                return false;
            }
            unsafe {
                let ptr = self.data.as_mut_ptr();
                std::ptr::copy(
                    ptr.add(self.start + old_prefix_len),
                    ptr.add(self.start + new_prefix_len),
                    tail_len,
                );
                std::ptr::copy_nonoverlapping(
                    new_prefix.as_ptr(),
                    ptr.add(self.start),
                    new_prefix_len,
                );
                self.data.set_len(len + delta);
            }
            return true;
        }

        let delta = old_prefix_len - new_prefix_len;
        unsafe {
            let ptr = self.data.as_mut_ptr();
            std::ptr::copy_nonoverlapping(new_prefix.as_ptr(), ptr.add(self.start), new_prefix_len);
            std::ptr::copy(
                ptr.add(self.start + old_prefix_len),
                ptr.add(self.start + new_prefix_len),
                tail_len,
            );
            self.data.set_len(len - delta);
        }
        true
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

impl Drop for PacketBuffer {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.take() {
            pool.put(mem::take(&mut self.data));
        }
    }
}

impl From<Vec<u8>> for PacketBuffer {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<PacketBuffer> for Vec<u8> {
    fn from(buffer: PacketBuffer) -> Self {
        buffer.into_vec()
    }
}

impl Deref for PacketBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for PacketBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl AsRef<[u8]> for PacketBuffer {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for PacketBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl PartialEq for PacketBuffer {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for PacketBuffer {}

impl PartialEq<Vec<u8>> for PacketBuffer {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl PartialEq<PacketBuffer> for Vec<u8> {
    fn eq(&self, other: &PacketBuffer) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl PartialEq<&[u8]> for PacketBuffer {
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_slice() == *other
    }
}

impl<const N: usize> PartialEq<[u8; N]> for PacketBuffer {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.as_slice() == other
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for PacketBuffer {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.as_slice() == *other
    }
}

pub(crate) fn received_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// FMP packet shape that is visible before dataplane authenticates established data.
///
/// App payloads, TCP ACKs, pings, and established FSP/MMP frames are all opaque
/// phase-0 data at this boundary. Only first-contact/link rekey handshakes get
/// the unbounded reserve lane before dataplane can classify authenticated contents.
const FMP_VERSION: u8 = 0;
const FMP_PHASE_MSG1: u8 = 0x1;
const FMP_PHASE_MSG2: u8 = 0x2;
const FMP_COMMON_PREFIX_SIZE: usize = 4;
const FMP_MSG1_WIRE_SIZE: usize = 114;
const FMP_MSG2_WIRE_SIZE: usize = 69;

fn is_transport_priority_packet(data: &[u8]) -> bool {
    if data.len() < FMP_COMMON_PREFIX_SIZE {
        return false;
    }

    let version = data[0] >> 4;
    let phase = data[0] & 0x0F;
    if version != FMP_VERSION {
        return false;
    }

    matches!(
        (phase, data.len()),
        (FMP_PHASE_MSG1, FMP_MSG1_WIRE_SIZE) | (FMP_PHASE_MSG2, FMP_MSG2_WIRE_SIZE)
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
const TRANSPORT_CHANNEL_BACKLOG_HIGH_WATER: usize = 4096;

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
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
            PacketQueueItem::Batch(packets) => packets.len(),
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
            PacketQueueItem::Batch(packets) => {
                packets.first().and_then(|packet| packet.trace_enqueued_at)
            }
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

    #[cfg(test)]
    fn cached_len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len()
    }
}

impl PacketBufferPool {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
            available: Arc::new(AtomicUsize::new(0)),
        }
    }

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

    #[cfg(test)]
    fn cached_len(&self) -> usize {
        self.available.load(Relaxed)
    }
}

#[cfg(target_os = "macos")]
fn fresh_recv_buffer(size: usize) -> Vec<u8> {
    vec![0u8; size]
}

#[cfg(not(target_os = "macos"))]
fn fresh_recv_buffer(size: usize) -> Vec<u8> {
    Vec::with_capacity(size)
}

#[cfg(target_os = "macos")]
fn prepare_recv_buffer(buffer: &mut Vec<u8>, size: usize) {
    buffer.resize(size, 0);
}

#[cfg(not(target_os = "macos"))]
fn prepare_recv_buffer(buffer: &mut Vec<u8>, size: usize) {
    buffer.clear();
    if buffer.capacity() < size {
        buffer.reserve(size.saturating_sub(buffer.capacity()));
    }
}

impl PacketBatch {
    fn from_vec(packets: Vec<ReceivedPacket>) -> Self {
        Self {
            packets,
            pool: None,
        }
    }

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

    fn len(&self) -> usize {
        self.packets.len()
    }

    fn first(&self) -> Option<&ReceivedPacket> {
        self.packets.first()
    }

    fn iter(&self) -> impl Iterator<Item = &ReceivedPacket> {
        self.packets.iter()
    }

    fn drain(&mut self) -> impl Iterator<Item = ReceivedPacket> + '_ {
        self.packets.drain(..)
    }

    fn pop(&mut self) -> Option<ReceivedPacket> {
        self.packets.pop()
    }

    fn reverse(&mut self) {
        self.packets.reverse();
    }

    fn is_pooled(&self) -> bool {
        self.pool.is_some()
    }
}

impl From<Vec<ReceivedPacket>> for PacketBatch {
    fn from(packets: Vec<ReceivedPacket>) -> Self {
        Self::from_vec(packets)
    }
}

impl Index<usize> for PacketBatch {
    type Output = ReceivedPacket;

    fn index(&self, index: usize) -> &Self::Output {
        &self.packets[index]
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
        batch.reverse();
        Self {
            batch,
            rx_loop_owned_at,
        }
    }

    fn next(&mut self) -> Option<ReceivedPacket> {
        let mut packet = self.batch.pop()?;
        if let Some(rx_loop_owned_at) = self.rx_loop_owned_at {
            packet.trace_rx_loop_owned_at = Some(rx_loop_owned_at);
        }
        Some(packet)
    }

    fn len(&self) -> usize {
        self.batch.len()
    }
}

impl PacketTx {
    pub(crate) fn set_fast_ingress_sink(&mut self, sink: Arc<dyn PacketFastIngressSink>) {
        self.fast_ingress = Some(sink);
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn try_fast_ingress_packet_batch(&self, batch: &mut PacketBatch) -> usize {
        let Some(sink) = &self.fast_ingress else {
            return 0;
        };
        sink.try_ingest_batch(&mut batch.packets)
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn packet_batch(&self, capacity: usize) -> PacketBatch {
        self.batch_pool.take(capacity)
    }

    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
    pub(crate) fn recv_buffer(&self, capacity: usize) -> Vec<u8> {
        self.buffer_pool.take(capacity)
    }

    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
    pub(crate) fn packet_buffer(&self, data: Vec<u8>) -> PacketBuffer {
        PacketBuffer::pooled(data, self.buffer_pool.clone())
    }

    pub fn send(
        &self,
        packet: ReceivedPacket,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<ReceivedPacket>> {
        let tx = if packet.is_transport_priority() {
            PacketQueueTx::Priority
        } else {
            PacketQueueTx::Bulk
        };
        self.send_item(tx, PacketQueueItem::One(packet))
            .map_err(|item| match item {
                PacketQueueItem::One(packet) => tokio::sync::mpsc::error::SendError(packet),
                PacketQueueItem::Batch(_) => {
                    unreachable!("single packet send cannot fail with a batch item")
                }
            })
    }

    #[cfg(test)]
    pub(crate) fn send_batch(&self, packets: Vec<ReceivedPacket>) -> Result<(), ()> {
        self.send_packet_batch(PacketBatch::from_vec(packets))
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn send_packet_batch(&self, mut batch: PacketBatch) -> Result<(), ()> {
        if batch.is_empty() {
            return Ok(());
        }

        let packet_count = batch.len();
        let priority_count = batch
            .iter()
            .filter(|packet| packet.is_transport_priority())
            .count();
        if priority_count == 0 || priority_count == packet_count {
            let tx = if priority_count == 0 {
                PacketQueueTx::Bulk
            } else {
                PacketQueueTx::Priority
            };
            return self.send_packet_items(tx, batch);
        }

        let mut priority_packets = self.packet_batch(priority_count);
        let mut bulk_packets = self.packet_batch(packet_count - priority_count);
        for packet in batch.drain() {
            if packet.is_transport_priority() {
                priority_packets.push(packet);
            } else {
                bulk_packets.push(packet);
            }
        }

        self.send_packet_items(PacketQueueTx::Priority, priority_packets)?;
        self.send_packet_items(PacketQueueTx::Bulk, bulk_packets)?;
        Ok(())
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn send_packet_items(&self, tx: PacketQueueTx, mut packets: PacketBatch) -> Result<(), ()> {
        if matches!(tx, PacketQueueTx::Bulk) {
            return self.send_bulk_packet_items(packets);
        }

        let item = match packets.len() {
            0 => return Ok(()),
            1 if !packets.is_pooled() => {
                PacketQueueItem::One(packets.pop().expect("one packet should be present"))
            }
            _ => PacketQueueItem::Batch(packets),
        };
        self.send_item(tx, item).map_err(|_| ())
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn send_bulk_packet_items(&self, mut packets: PacketBatch) -> Result<(), ()> {
        let packet_count = packets.len();
        if packet_count == 0 {
            return Ok(());
        }

        let granted = self.try_reserve_bulk_packet_prefix(packet_count);
        if granted == 0 {
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::TransportBulkDropped,
                packet_count as u64,
            );
            return Ok(());
        }

        if granted < packet_count {
            let dropped = packet_count - granted;
            let _dropped_tail = packets.packets.split_off(granted);
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::TransportBulkDropped,
                dropped as u64,
            );
        }

        let item = match packets.len() {
            0 => return Ok(()),
            1 if !packets.is_pooled() => {
                PacketQueueItem::One(packets.pop().expect("one packet should be present"))
            }
            _ => PacketQueueItem::Batch(packets),
        };
        self.send_reserved_item(PacketQueueTx::Bulk, item, Some(granted))
            .map_err(|_| ())
    }

    fn send_item(&self, tx: PacketQueueTx, item: PacketQueueItem) -> Result<(), PacketQueueItem> {
        let packet_count = item.packet_count();
        let bulk_reserved = if matches!(tx, PacketQueueTx::Bulk) && packet_count > 0 {
            if !self.try_reserve_bulk_packets(packet_count) {
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::TransportBulkDropped,
                    packet_count as u64,
                );
                return Ok(());
            }
            Some(packet_count)
        } else {
            None
        };
        self.send_reserved_item(tx, item, bulk_reserved)
    }

    fn send_reserved_item(
        &self,
        tx: PacketQueueTx,
        item: PacketQueueItem,
        bulk_reserved: Option<usize>,
    ) -> Result<(), PacketQueueItem> {
        let packet_count = item.packet_count();
        debug_assert_eq!(
            bulk_reserved,
            matches!(tx, PacketQueueTx::Bulk)
                .then_some(packet_count)
                .filter(|count| *count > 0)
        );
        let priority_reserved = matches!(tx, PacketQueueTx::Priority)
            .then_some(packet_count)
            .filter(|count| *count > 0);
        if let Some(count) = priority_reserved {
            self.priority_queued_packets.fetch_add(count, Relaxed);
        }

        let tracked_count = if self.track_backlog {
            Some(packet_count)
        } else {
            None
        };
        let previous = tracked_count.map(|count| self.queued_packets.fetch_add(count, Relaxed));
        match tx.try_send(self, item) {
            Ok(()) => {
                if let (Some(count), Some(previous)) = (tracked_count, previous) {
                    let queued = previous.saturating_add(count);
                    if previous < TRANSPORT_CHANNEL_BACKLOG_HIGH_WATER
                        && queued >= TRANSPORT_CHANNEL_BACKLOG_HIGH_WATER
                    {
                        crate::perf_profile::record_event(
                            crate::perf_profile::Event::TransportChannelBacklogHigh,
                        );
                    }
                }
                Ok(())
            }
            Err(PacketSendFailure::Closed(item)) => {
                if let Some(count) = tracked_count {
                    self.queued_packets.fetch_sub(count, Relaxed);
                }
                if let Some(count) = priority_reserved {
                    release_priority_packets(&self.priority_queued_packets, count);
                }
                if let Some(count) = bulk_reserved {
                    self.release_bulk_packets(count);
                }
                Err(item)
            }
            Err(PacketSendFailure::DroppedBulk(dropped_count)) => {
                if let Some(count) = tracked_count {
                    self.queued_packets.fetch_sub(count, Relaxed);
                }
                if let Some(count) = priority_reserved {
                    release_priority_packets(&self.priority_queued_packets, count);
                }
                if let Some(count) = bulk_reserved {
                    self.release_bulk_packets(count);
                }
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::TransportBulkDropped,
                    dropped_count as u64,
                );
                Ok(())
            }
        }
    }

    fn try_reserve_bulk_packets(&self, count: usize) -> bool {
        self.bulk_queued_packets
            .fetch_update(Relaxed, Relaxed, |current| {
                current
                    .checked_add(count)
                    .filter(|next| *next <= self.bulk_packet_capacity)
            })
            .is_ok()
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn try_reserve_bulk_packet_prefix(&self, requested: usize) -> usize {
        if requested == 0 {
            return 0;
        }

        let mut current = self.bulk_queued_packets.load(Relaxed);
        loop {
            let available = self.bulk_packet_capacity.saturating_sub(current);
            let granted = requested.min(available);
            if granted == 0 {
                return 0;
            }
            match self.bulk_queued_packets.compare_exchange_weak(
                current,
                current + granted,
                Relaxed,
                Relaxed,
            ) {
                Ok(_) => return granted,
                Err(actual) => current = actual,
            }
        }
    }

    fn release_bulk_packets(&self, count: usize) {
        release_reserved_bulk_packets(&self.bulk_queued_packets, count);
    }

    #[cfg(test)]
    pub(crate) fn queued_packets(&self) -> usize {
        self.queued_packets.load(Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn priority_queued_packets(&self) -> usize {
        self.priority_queued_packets.load(Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn bulk_queued_packets(&self) -> usize {
        self.bulk_queued_packets.load(Relaxed)
    }
}

impl PacketRx {
    pub(crate) fn priority_queued_packets(&self) -> usize {
        self.priority_queued_packets.load(Relaxed)
    }

    pub(crate) fn priority_ready_packets(&self) -> usize {
        self.pending_priority
            .as_ref()
            .map_or(0, PendingPackets::len)
            .saturating_add(self.priority_queued_packets())
    }

    pub async fn recv(&mut self) -> Option<ReceivedPacket> {
        loop {
            match self.try_recv() {
                Ok(packet) => return Some(packet),
                Err(TryRecvError::Disconnected) => return None,
                Err(TryRecvError::Empty) => {}
            }

            tokio::select! {
                biased;
                item = self.priority.recv(), if !self.priority_closed => {
                    match item {
                        Some(item) => {
                            if let Some(packet) = self.packet_from_item(item, PacketLane::Priority) {
                                return Some(packet);
                            }
                        }
                        None => self.priority_closed = true,
                    }
                }
                item = self.bulk.recv(), if !self.bulk_closed => {
                    match item {
                        Some(item) => {
                            if let Some(packet) = self.packet_from_item(item, PacketLane::Bulk) {
                                return Some(packet);
                            }
                        }
                        None => self.bulk_closed = true,
                    }
                }
            }
        }
    }

    pub fn try_recv(&mut self) -> Result<ReceivedPacket, TryRecvError> {
        if let Some(packet) = Self::take_pending(&mut self.pending_priority) {
            return Ok(packet);
        }

        if self.should_probe_priority() {
            match self.priority.try_recv() {
                Ok(item) => {
                    if let Some(packet) = self.packet_from_item(item, PacketLane::Priority) {
                        return Ok(packet);
                    }
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.priority_closed = true;
                }
            }
        }

        if let Some(packet) = Self::take_pending(&mut self.pending_bulk) {
            return Ok(packet);
        }

        match self.bulk.try_recv() {
            Ok(item) => self
                .packet_from_item(item, PacketLane::Bulk)
                .ok_or(TryRecvError::Empty),
            Err(TryRecvError::Empty) => {
                if self.priority_closed && self.bulk_closed {
                    Err(TryRecvError::Disconnected)
                } else {
                    Err(TryRecvError::Empty)
                }
            }
            Err(TryRecvError::Disconnected) => {
                self.bulk_closed = true;
                if self.priority_closed {
                    Err(TryRecvError::Disconnected)
                } else {
                    Err(TryRecvError::Empty)
                }
            }
        }
    }

    pub(crate) fn drain_ready<F>(&mut self, limit: usize, mut consume: F) -> usize
    where
        F: FnMut(ReceivedPacket) -> bool,
    {
        let mut drained = 0usize;
        while drained < limit {
            if !self.drain_pending_priority(limit, &mut drained, &mut consume) {
                break;
            }
            if drained >= limit {
                break;
            }

            if self.should_probe_priority() {
                match self.priority.try_recv() {
                    Ok(item) => {
                        if !self.drain_item(
                            item,
                            PacketLane::Priority,
                            limit,
                            &mut drained,
                            &mut consume,
                        ) {
                            break;
                        }
                        continue;
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => {
                        self.priority_closed = true;
                    }
                }
            }
            if drained >= limit {
                break;
            }

            if !self.drain_pending_bulk(limit, &mut drained, &mut consume) {
                break;
            }
            if drained >= limit {
                break;
            }

            match self.bulk.try_recv() {
                Ok(item) => {
                    if !self.drain_item(item, PacketLane::Bulk, limit, &mut drained, &mut consume) {
                        break;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.bulk_closed = true;
                    break;
                }
            }
        }
        drained
    }

    fn packet_from_item(
        &mut self,
        item: PacketQueueItem,
        lane: PacketLane,
    ) -> Option<ReceivedPacket> {
        item.record_dequeue_wait(lane);
        let packet_count = item.packet_count();
        if self.track_backlog {
            self.queued_packets.fetch_sub(packet_count, Relaxed);
        }
        if matches!(lane, PacketLane::Priority) {
            release_priority_packets(&self.priority_queued_packets, packet_count);
        }
        if matches!(lane, PacketLane::Bulk) {
            release_reserved_bulk_packets(&self.bulk_queued_packets, packet_count);
        }
        let rx_loop_owned_at = crate::perf_profile::stamp();
        match item {
            PacketQueueItem::One(mut packet) => {
                packet.trace_rx_loop_owned_at = rx_loop_owned_at;
                Some(packet)
            }
            PacketQueueItem::Batch(packets) => {
                let mut pending = PendingPackets::new(packets, rx_loop_owned_at);
                let packet = pending.next()?;
                if pending.len() > 0 {
                    match lane {
                        PacketLane::Priority => self.pending_priority = Some(pending),
                        PacketLane::Bulk => self.pending_bulk = Some(pending),
                    }
                }
                Some(packet)
            }
        }
    }

    fn drain_item<F>(
        &mut self,
        item: PacketQueueItem,
        lane: PacketLane,
        limit: usize,
        drained: &mut usize,
        consume: &mut F,
    ) -> bool
    where
        F: FnMut(ReceivedPacket) -> bool,
    {
        if let Some(packet) = self.packet_from_item(item, lane) {
            *drained += 1;
            if !consume(packet) {
                return false;
            }
        }

        match lane {
            PacketLane::Priority => self.drain_pending_priority(limit, drained, consume),
            PacketLane::Bulk => self.drain_pending_bulk(limit, drained, consume),
        }
    }

    fn drain_pending_priority<F>(
        &mut self,
        limit: usize,
        drained: &mut usize,
        consume: &mut F,
    ) -> bool
    where
        F: FnMut(ReceivedPacket) -> bool,
    {
        while *drained < limit {
            let Some(packet) = Self::take_pending(&mut self.pending_priority) else {
                return true;
            };
            *drained += 1;
            if !consume(packet) {
                return false;
            }
        }
        true
    }

    fn drain_pending_bulk<F>(&mut self, limit: usize, drained: &mut usize, consume: &mut F) -> bool
    where
        F: FnMut(ReceivedPacket) -> bool,
    {
        while *drained < limit {
            if self.should_probe_priority() {
                return true;
            }
            let Some(packet) = Self::take_pending(&mut self.pending_bulk) else {
                return true;
            };
            *drained += 1;
            if !consume(packet) {
                return false;
            }
        }
        true
    }

    fn should_probe_priority(&self) -> bool {
        !self.priority_closed
            && (self.priority_queued_packets.load(Relaxed) > 0 || self.bulk_closed)
    }

    fn take_pending(pending: &mut Option<PendingPackets>) -> Option<ReceivedPacket> {
        let packets = pending.as_mut()?;
        let packet = packets.next();
        if packets.len() == 0 {
            *pending = None;
        }
        packet
    }
}

#[inline]
fn packet_channel_tracks_backlog() -> bool {
    cfg!(test) || crate::perf_profile::enabled()
}

fn release_reserved_bulk_packets(counter: &AtomicUsize, count: usize) {
    if count == 0 {
        return;
    }

    let previous = counter.fetch_sub(count, Relaxed);
    debug_assert!(
        previous >= count,
        "transport bulk queued packet accounting underflow"
    );
}

fn release_priority_packets(counter: &AtomicUsize, count: usize) {
    if count == 0 {
        return;
    }

    let previous = counter.fetch_sub(count, Relaxed);
    debug_assert!(
        previous >= count,
        "transport priority queued packet accounting underflow"
    );
}

/// Create a packet channel.
///
/// The capacity applies to bulk packets. Priority traffic is intentionally
/// unbounded so small control-shaped packets can still wake the rx loop while a
/// bulk receiver is saturated.
pub fn packet_channel(buffer: usize) -> (PacketTx, PacketRx) {
    let (priority_tx, priority_rx) = tokio::sync::mpsc::unbounded_channel();
    let (bulk_tx, bulk_rx) = tokio::sync::mpsc::channel(buffer.max(1));
    let priority_queued_packets = Arc::new(AtomicUsize::new(0));
    let queued_packets = Arc::new(AtomicUsize::new(0));
    let bulk_queued_packets = Arc::new(AtomicUsize::new(0));
    let track_backlog = packet_channel_tracks_backlog();
    (
        PacketTx {
            priority: priority_tx,
            bulk: bulk_tx,
            fast_ingress: None,
            batch_pool: PacketBatchPool::new(),
            buffer_pool: PacketBufferPool::new(),
            priority_queued_packets: Arc::clone(&priority_queued_packets),
            queued_packets: Arc::clone(&queued_packets),
            bulk_queued_packets: Arc::clone(&bulk_queued_packets),
            bulk_packet_capacity: buffer.max(1),
            track_backlog,
        },
        PacketRx {
            priority: priority_rx,
            bulk: bulk_rx,
            priority_queued_packets,
            queued_packets,
            bulk_queued_packets,
            track_backlog,
            pending_priority: None,
            pending_bulk: None,
            priority_closed: false,
            bulk_closed: false,
        },
    )
}

#[cfg(test)]
mod tests;
