//! Priority-aware packet channel for transport receive paths.

use super::{TransportAddr, TransportId};
use crate::packet_mover::{
    AdmissionClass, AdmissionCredit, AdmissionDecision, AdmissionDrop, AdmissionDropReason,
    AdmissionPrefixDecision, AdmittedPacket, LaneCreditGate, LaneCreditReservation, PacketFacts,
    PacketLane, UdpAdmission, UdpBatchAdmission, UdpIngress, classify_udp_admission,
};
use std::mem;
use std::ops::{Deref, DerefMut, Index};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering::Relaxed},
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::{
    Sender,
    error::{TryRecvError, TrySendError},
};

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

    pub(crate) fn is_priority_sized(&self) -> bool {
        self.admission_class().lane() == PacketLane::Priority
    }

    pub(crate) fn admission_class(&self) -> AdmissionClass {
        classify_udp_admission(self.data.len(), PRIORITY_PACKET_MAX_LEN)
    }
}

impl From<&ReceivedPacket> for PacketFacts {
    fn from(packet: &ReceivedPacket) -> Self {
        Self {
            transport_id: packet.transport_id,
            remote_addr: packet.remote_addr.clone(),
            packet_len: packet.data.len(),
            received_at_ms: packet.timestamp_ms,
        }
    }
}

/// Byte storage for a received transport packet.
///
/// The public endpoint API still receives a plain `Vec<u8>`, but internal
/// receive/decrypt/drop paths carry this owner so pressure drops can recycle
/// kernel receive buffers without adding protocol surface area.
#[derive(Debug, Default)]
pub struct PacketBuffer {
    data: Vec<u8>,
    pool: Option<PacketBufferPool>,
}

impl PacketBuffer {
    fn pooled(data: Vec<u8>, pool: PacketBufferPool) -> Self {
        Self {
            data,
            pool: Some(pool),
        }
    }

    pub(crate) fn keep_range(&mut self, offset: usize, len: usize) {
        let end = offset
            .checked_add(len)
            .expect("packet buffer retained range should not overflow");
        debug_assert!(end <= self.data.len());
        if offset == 0 {
            self.data.truncate(len);
            return;
        }
        self.data.copy_within(offset..end, 0);
        self.data.truncate(len);
    }

    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        self.pool = None;
        mem::take(&mut self.data)
    }
}

impl Clone for PacketBuffer {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
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
        Self { data, pool: None }
    }
}

impl Deref for PacketBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for PacketBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl AsRef<[u8]> for PacketBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for PacketBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl PartialEq for PacketBuffer {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl Eq for PacketBuffer {}

impl PartialEq<Vec<u8>> for PacketBuffer {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.data == *other
    }
}

impl PartialEq<PacketBuffer> for Vec<u8> {
    fn eq(&self, other: &PacketBuffer) -> bool {
        *self == other.data
    }
}

impl PartialEq<&[u8]> for PacketBuffer {
    fn eq(&self, other: &&[u8]) -> bool {
        self.data.as_slice() == *other
    }
}

impl<const N: usize> PartialEq<[u8; N]> for PacketBuffer {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.data.as_slice() == other
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for PacketBuffer {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.data.as_slice() == *other
    }
}

pub(crate) fn received_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Wire-size threshold for keeping transport receive work out of the bulk
/// FIFO. Most heartbeat, MMP, rekey, ping, and handshake-shaped datagrams are
/// comfortably below this; full-size endpoint payloads are not.
const PRIORITY_PACKET_MAX_LEN: usize = 512;
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
/// Priority and bulk lanes are bounded by packet credits, not receive-batch
/// items. Both lanes use nonblocking `try_send`: overload sheds the saturated
/// lane explicitly instead of hiding unbounded latency behind the rx loop.
#[derive(Clone, Debug)]
pub struct PacketTx {
    priority: Sender<PacketQueueItem>,
    bulk: Sender<PacketQueueItem>,
    batch_pool: PacketBatchPool,
    buffer_pool: PacketBufferPool,
    /// Packet-count ready hint for priority lane probes. Bulk batch tails check
    /// this instead of touching an empty priority mpsc once per data packet.
    priority_credits: LaneCreditGate,
    queued_packets: Arc<AtomicUsize>,
    bulk_credits: LaneCreditGate,
    track_backlog: bool,
}

/// Channel receiver for received packets.
pub struct PacketRx {
    priority: tokio::sync::mpsc::Receiver<PacketQueueItem>,
    bulk: tokio::sync::mpsc::Receiver<PacketQueueItem>,
    priority_credits: LaneCreditGate,
    queued_packets: Arc<AtomicUsize>,
    bulk_credits: LaneCreditGate,
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
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
    Batch(PacketBatch),
}

#[derive(Clone, Copy)]
enum PacketQueueTx {
    Priority,
    Bulk,
}

enum PacketSendFailure {
    Closed(PacketQueueItem),
    Dropped(PacketQueueItem),
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
    fn lane(self) -> PacketLane {
        match self {
            PacketQueueTx::Priority => PacketLane::Priority,
            PacketQueueTx::Bulk => PacketLane::Bulk,
        }
    }

    fn try_send(self, owner: &PacketTx, item: PacketQueueItem) -> Result<(), PacketSendFailure> {
        match self {
            PacketQueueTx::Priority => match owner.priority.try_send(item) {
                Ok(()) => Ok(()),
                Err(TrySendError::Full(item)) => Err(PacketSendFailure::Dropped(item)),
                Err(TrySendError::Closed(item)) => Err(PacketSendFailure::Closed(item)),
            },
            PacketQueueTx::Bulk => match owner.bulk.try_send(item) {
                Ok(()) => Ok(()),
                Err(TrySendError::Full(item)) => Err(PacketSendFailure::Dropped(item)),
                Err(TrySendError::Closed(item)) => Err(PacketSendFailure::Closed(item)),
            },
        }
    }
}

impl From<PacketLane> for PacketQueueTx {
    fn from(lane: PacketLane) -> Self {
        match lane {
            PacketLane::Priority => Self::Priority,
            PacketLane::Bulk => Self::Bulk,
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

    fn byte_count(&self) -> usize {
        match self {
            PacketQueueItem::One(packet) => packet.data.len(),
            PacketQueueItem::Batch(packets) => packets.byte_count(),
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

    fn byte_count(&self) -> usize {
        self.packets.iter().map(|packet| packet.data.len()).sum()
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
    fn lane_credit_gate(&self, lane: PacketLane) -> &LaneCreditGate {
        match lane {
            PacketLane::Priority => &self.priority_credits,
            PacketLane::Bulk => &self.bulk_credits,
        }
    }
}

impl UdpAdmission<ReceivedPacket> for PacketTx {
    fn admit_udp(
        &self,
        ingress: UdpIngress<ReceivedPacket>,
        class: AdmissionClass,
    ) -> AdmissionDecision<ReceivedPacket> {
        let lane = class.lane();
        let byte_count = ingress.facts.packet_len;
        match self.lane_credit_gate(lane).reserve(1, byte_count) {
            Ok(reservation) => AdmissionDecision::Admit(AdmittedPacket {
                packet: ingress.packet,
                facts: ingress.facts,
                class,
                lane,
                credit: AdmissionCredit::new(lane, reservation),
            }),
            Err(drop) => AdmissionDecision::Drop(drop),
        }
    }
}

impl UdpBatchAdmission for PacketTx {
    fn reserve_udp_prefix(
        &self,
        lane: PacketLane,
        packet_count: usize,
        byte_count: usize,
    ) -> AdmissionPrefixDecision {
        match self.lane_credit_gate(lane).reserve_prefix(packet_count) {
            Some(reservation) => {
                AdmissionPrefixDecision::Admit(crate::packet_mover::AdmissionPrefix::new(
                    lane,
                    packet_count,
                    byte_count,
                    reservation,
                ))
            }
            None => AdmissionPrefixDecision::Drop(
                self.lane_credit_gate(lane)
                    .pressure_drop(packet_count, byte_count),
            ),
        }
    }
}

impl PacketTx {
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
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

    #[cfg(test)]
    pub(crate) fn cached_packet_buffers(&self) -> usize {
        self.buffer_pool.cached_len()
    }

    pub fn send(
        &self,
        packet: ReceivedPacket,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<ReceivedPacket>> {
        let class = packet.admission_class();
        let facts = PacketFacts::from(&packet);
        let admitted = match self.admit_udp(UdpIngress::new(packet, facts), class) {
            AdmissionDecision::Admit(admitted) => admitted,
            AdmissionDecision::Drop(drop) => {
                record_admission_drop(&drop);
                return Ok(());
            }
        };
        let lane = admitted.lane;
        self.send_admitted_packet(admitted)
            .map_err(|item| match item {
                PacketQueueItem::One(packet) => tokio::sync::mpsc::error::SendError(packet),
                PacketQueueItem::Batch(_) => {
                    unreachable!("single packet send cannot fail with a {lane:?} batch item")
                }
            })
    }

    #[cfg(test)]
    pub(crate) fn send_batch(&self, packets: Vec<ReceivedPacket>) -> Result<(), ()> {
        self.send_packet_batch(PacketBatch::from_vec(packets))
    }

    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
    pub(crate) fn send_packet_batch(&self, mut batch: PacketBatch) -> Result<(), ()> {
        if batch.is_empty() {
            return Ok(());
        }

        let packet_count = batch.len();
        let priority_count = batch
            .iter()
            .filter(|packet| packet.is_priority_sized())
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
            if packet.is_priority_sized() {
                priority_packets.push(packet);
            } else {
                bulk_packets.push(packet);
            }
        }

        self.send_packet_items(PacketQueueTx::Priority, priority_packets)?;
        self.send_packet_items(PacketQueueTx::Bulk, bulk_packets)?;
        Ok(())
    }

    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
    fn send_packet_items(&self, tx: PacketQueueTx, packets: PacketBatch) -> Result<(), ()> {
        self.send_lane_packet_items(tx.lane(), packets)
    }

    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
    fn send_lane_packet_items(&self, lane: PacketLane, mut packets: PacketBatch) -> Result<(), ()> {
        let packet_count = packets.len();
        if packet_count == 0 {
            return Ok(());
        }

        let requested_bytes = packets.byte_count();
        let admission = match self.reserve_udp_prefix(lane, packet_count, requested_bytes) {
            AdmissionPrefixDecision::Admit(admission) => admission,
            AdmissionPrefixDecision::Drop(drop) => {
                record_admission_drop(&drop);
                return Ok(());
            }
        };
        debug_assert_eq!(admission.lane(), lane);
        debug_assert_eq!(admission.requested_packets(), packet_count);
        debug_assert_eq!(admission.requested_bytes(), requested_bytes);
        let granted = admission.packet_count();

        if granted < packet_count {
            let dropped_tail = packets.packets.split_off(granted);
            let drop = self.lane_credit_gate(lane).pressure_drop(
                dropped_tail.len(),
                dropped_tail.iter().map(|packet| packet.data.len()).sum(),
            );
            record_admission_drop(&drop);
        }

        let item = match packets.len() {
            0 => return Ok(()),
            1 if !packets.is_pooled() => {
                PacketQueueItem::One(packets.pop().expect("one packet should be present"))
            }
            _ => PacketQueueItem::Batch(packets),
        };
        let reservation = admission.into_lane_reservation();
        let tx = PacketQueueTx::from(lane);
        let (priority_reserved, bulk_reserved) = match lane {
            PacketLane::Priority => (Some(reservation), None),
            PacketLane::Bulk => (None, Some(reservation)),
        };
        self.send_reserved_item(tx, item, priority_reserved, bulk_reserved)
            .map_err(|_| ())
    }

    fn send_admitted_packet(
        &self,
        admitted: AdmittedPacket<ReceivedPacket>,
    ) -> Result<(), PacketQueueItem> {
        debug_assert_eq!(admitted.facts.packet_len, admitted.packet.data.len());
        debug_assert_eq!(admitted.class.lane(), admitted.lane);
        debug_assert_eq!(admitted.credit.lane(), admitted.lane);
        debug_assert_eq!(admitted.credit.packet_count(), 1);
        let tx = PacketQueueTx::from(admitted.lane);
        let reservation = admitted.credit.into_lane_reservation();
        let (priority_reserved, bulk_reserved) = match admitted.lane {
            PacketLane::Priority => (Some(reservation), None),
            PacketLane::Bulk => (None, Some(reservation)),
        };
        self.send_reserved_item(
            tx,
            PacketQueueItem::One(admitted.packet),
            priority_reserved,
            bulk_reserved,
        )
    }

    fn send_reserved_item(
        &self,
        tx: PacketQueueTx,
        item: PacketQueueItem,
        priority_reserved: Option<LaneCreditReservation>,
        bulk_reserved: Option<LaneCreditReservation>,
    ) -> Result<(), PacketQueueItem> {
        let packet_count = item.packet_count();
        debug_assert_eq!(
            priority_reserved.map(LaneCreditReservation::packet_count),
            matches!(tx, PacketQueueTx::Priority)
                .then_some(packet_count)
                .filter(|count| *count > 0)
        );
        debug_assert_eq!(
            bulk_reserved.map(LaneCreditReservation::packet_count),
            matches!(tx, PacketQueueTx::Bulk)
                .then_some(packet_count)
                .filter(|count| *count > 0)
        );

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
                if let Some(reservation) = priority_reserved {
                    self.priority_credits.release(reservation);
                }
                if let Some(reservation) = bulk_reserved {
                    self.bulk_credits.release(reservation);
                }
                Err(item)
            }
            Err(PacketSendFailure::Dropped(item)) => {
                if let Some(count) = tracked_count {
                    self.queued_packets.fetch_sub(count, Relaxed);
                }
                if let Some(reservation) = priority_reserved {
                    self.priority_credits.release(reservation);
                }
                if let Some(reservation) = bulk_reserved {
                    self.bulk_credits.release(reservation);
                }
                let drop =
                    AdmissionDrop::pressure(tx.lane(), item.packet_count(), item.byte_count());
                record_admission_drop(&drop);
                Ok(())
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn queued_packets(&self) -> usize {
        self.queued_packets.load(Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn priority_queued_packets(&self) -> usize {
        self.priority_credits.queued_packets()
    }

    #[cfg(test)]
    pub(crate) fn bulk_queued_packets(&self) -> usize {
        self.bulk_credits.queued_packets()
    }
}

impl PacketRx {
    pub(crate) fn priority_queued_packets(&self) -> usize {
        self.priority_credits.queued_packets()
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
            self.priority_credits.release_count(packet_count);
        }
        if matches!(lane, PacketLane::Bulk) {
            self.bulk_credits.release_count(packet_count);
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

    fn should_probe_priority(&self) -> bool {
        !self.priority_closed && (self.priority_credits.queued_packets() > 0 || self.bulk_closed)
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
    cfg!(test) || crate::perf_profile::event_counters_enabled()
}

fn record_admission_drop(drop: &AdmissionDrop) {
    let event = match drop.reason {
        AdmissionDropReason::PriorityPressure => {
            crate::perf_profile::Event::TransportPriorityDropped
        }
        AdmissionDropReason::BulkPressure => crate::perf_profile::Event::TransportBulkDropped,
        AdmissionDropReason::Malformed | AdmissionDropReason::ReceiverClosed => return,
    };
    crate::perf_profile::record_event_count(event, drop.packet_count as u64);
}

/// Create a packet channel.
///
/// The capacity applies independently to priority and bulk packets. Priority
/// stays on a separate reserved lane so small control-shaped packets can still
/// wake the rx loop while bulk is saturated, but sustained priority overload is
/// bounded and counted.
pub fn packet_channel(buffer: usize) -> (PacketTx, PacketRx) {
    let packet_capacity = buffer.max(1);
    let (priority_tx, priority_rx) = tokio::sync::mpsc::channel(packet_capacity);
    let (bulk_tx, bulk_rx) = tokio::sync::mpsc::channel(packet_capacity);
    let queued_packets = Arc::new(AtomicUsize::new(0));
    let priority_credits = LaneCreditGate::new(PacketLane::Priority, packet_capacity);
    let bulk_credits = LaneCreditGate::new(PacketLane::Bulk, packet_capacity);
    let track_backlog = packet_channel_tracks_backlog();
    (
        PacketTx {
            priority: priority_tx,
            bulk: bulk_tx,
            batch_pool: PacketBatchPool::new(),
            buffer_pool: PacketBufferPool::new(),
            priority_credits: priority_credits.clone(),
            queued_packets: Arc::clone(&queued_packets),
            bulk_credits: bulk_credits.clone(),
            track_backlog,
        },
        PacketRx {
            priority: priority_rx,
            bulk: bulk_rx,
            priority_credits,
            queued_packets,
            bulk_credits,
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
