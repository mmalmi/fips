//! Priority-aware packet channel for transport receive paths.

use super::{TransportAddr, TransportId};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering::Relaxed},
};
use std::time::{SystemTime, UNIX_EPOCH};
use std::vec::IntoIter;
use tokio::sync::mpsc::{
    Sender, UnboundedReceiver, UnboundedSender,
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
    pub data: Vec<u8>,
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
    pub fn new(transport_id: TransportId, remote_addr: TransportAddr, data: Vec<u8>) -> Self {
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
        data: Vec<u8>,
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
        data: Vec<u8>,
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

    pub(crate) fn is_priority_sized(&self) -> bool {
        self.data.len() <= PRIORITY_PACKET_MAX_LEN
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

#[derive(Debug)]
enum PacketQueueItem {
    One(ReceivedPacket),
    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
    Batch(Vec<ReceivedPacket>),
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
    packets: IntoIter<ReceivedPacket>,
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

impl PendingPackets {
    fn new(
        packets: IntoIter<ReceivedPacket>,
        rx_loop_owned_at: Option<crate::perf_profile::TraceStamp>,
    ) -> Self {
        Self {
            packets,
            rx_loop_owned_at,
        }
    }

    fn next(&mut self) -> Option<ReceivedPacket> {
        let mut packet = self.packets.next()?;
        if let Some(rx_loop_owned_at) = self.rx_loop_owned_at {
            packet.trace_rx_loop_owned_at = Some(rx_loop_owned_at);
        }
        Some(packet)
    }

    fn len(&self) -> usize {
        self.packets.len()
    }
}

impl PacketTx {
    pub fn send(
        &self,
        packet: ReceivedPacket,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<ReceivedPacket>> {
        let tx = if packet.data.len() <= PRIORITY_PACKET_MAX_LEN {
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

    #[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
    pub(crate) fn send_batch(&self, packets: Vec<ReceivedPacket>) -> Result<(), ()> {
        if packets.is_empty() {
            return Ok(());
        }

        let packet_count = packets.len();
        let priority_count = packets
            .iter()
            .filter(|packet| packet.is_priority_sized())
            .count();
        if priority_count == 0 || priority_count == packet_count {
            let tx = if priority_count == 0 {
                PacketQueueTx::Bulk
            } else {
                PacketQueueTx::Priority
            };
            return self.send_packet_items(tx, packets);
        }

        let mut priority_packets = Vec::with_capacity(priority_count);
        let mut bulk_packets = Vec::with_capacity(packet_count - priority_count);
        for packet in packets {
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
    fn send_packet_items(
        &self,
        tx: PacketQueueTx,
        mut packets: Vec<ReceivedPacket>,
    ) -> Result<(), ()> {
        let item = match packets.len() {
            0 => return Ok(()),
            1 => PacketQueueItem::One(packets.pop().expect("one packet should be present")),
            _ => PacketQueueItem::Batch(packets),
        };
        self.send_item(tx, item).map_err(|_| ())
    }

    fn send_item(&self, tx: PacketQueueTx, item: PacketQueueItem) -> Result<(), PacketQueueItem> {
        let packet_count = item.packet_count();
        let bulk_reserved = matches!(tx, PacketQueueTx::Bulk)
            .then_some(packet_count)
            .filter(|count| *count > 0);
        let priority_reserved = matches!(tx, PacketQueueTx::Priority)
            .then_some(packet_count)
            .filter(|count| *count > 0);
        if let Some(count) = priority_reserved {
            self.priority_queued_packets.fetch_add(count, Relaxed);
        }
        if let Some(count) = bulk_reserved
            && !self.try_reserve_bulk_packets(count)
        {
            crate::perf_profile::record_event_count(
                crate::perf_profile::Event::TransportBulkDropped,
                count as u64,
            );
            return Ok(());
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

    pub(crate) fn ready_packets(&self) -> usize {
        self.pending_priority
            .as_ref()
            .map_or(0, PendingPackets::len)
            .saturating_add(self.pending_bulk.as_ref().map_or(0, PendingPackets::len))
            .saturating_add(self.priority_queued_packets())
            .saturating_add(self.bulk_queued_packets.load(Relaxed))
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
                let mut packets = packets.into_iter();
                let mut packet = packets.next()?;
                if let Some(rx_loop_owned_at) = rx_loop_owned_at {
                    packet.trace_rx_loop_owned_at = Some(rx_loop_owned_at);
                }
                if packets.len() > 0 {
                    let pending = PendingPackets::new(packets, rx_loop_owned_at);
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
