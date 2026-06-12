//! Transport Layer Abstractions
//!
//! Traits and types for FIPS transport drivers. Transports provide the
//! underlying communication mechanisms (UDP, Ethernet, Tor, etc.) over
//! which FIPS links are established.

pub mod tcp;
pub mod tor;
pub mod udp;
#[cfg(feature = "webrtc-transport")]
pub mod webrtc;

#[cfg(feature = "sim-transport")]
pub mod sim;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod ethernet;

#[cfg(target_os = "linux")]
pub mod ble;

#[cfg(feature = "webrtc-transport")]
use self::webrtc::WebRtcTransport;
#[cfg(target_os = "linux")]
use ble::DefaultBleTransport;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use ethernet::EthernetTransport;
use secp256k1::XOnlyPublicKey;
#[cfg(feature = "sim-transport")]
use sim::SimTransport;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering::Relaxed},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::vec::IntoIter;
use tcp::TcpTransport;
use thiserror::Error;
use tokio::sync::mpsc::{
    Sender, UnboundedReceiver, UnboundedSender,
    error::{TryRecvError, TrySendError},
};
use tor::TorTransport;
use tor::control::TorMonitoringInfo;
use udp::UdpTransport;

// ============================================================================
// Packet Channel Types
// ============================================================================

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

// ============================================================================
// Transport Identifiers
// ============================================================================

/// Unique identifier for a transport instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransportId(u32);

impl TransportId {
    /// Create a new transport ID.
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    /// Get the raw ID value.
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for TransportId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transport:{}", self.0)
    }
}

/// Unique identifier for a link instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LinkId(u64);

impl LinkId {
    /// Create a new link ID.
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the raw ID value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "link:{}", self.0)
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Errors related to transport operations.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("transport not started")]
    NotStarted,

    #[error("transport already started")]
    AlreadyStarted,

    #[error("transport failed to start: {0}")]
    StartFailed(String),

    #[error("transport shutdown failed: {0}")]
    ShutdownFailed(String),

    #[error("link failed: {0}")]
    LinkFailed(String),

    #[error("send failed: {0}")]
    SendFailed(String),

    #[error("receive failed: {0}")]
    RecvFailed(String),

    #[error("invalid transport address: {0}")]
    InvalidAddress(String),

    #[error("mtu exceeded: packet {packet_size} > mtu {mtu}")]
    MtuExceeded { packet_size: usize, mtu: u16 },

    #[error("transport timeout")]
    Timeout,

    #[error("connection refused")]
    ConnectionRefused,

    #[error("transport not supported: {0}")]
    NotSupported(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl TransportError {
    /// True when the local OS says the outbound underlay path is temporarily
    /// unsendable, rather than the peer or protocol being bad.
    pub fn is_local_route_unavailable(&self) -> bool {
        match self {
            TransportError::Io(error) => is_local_route_error_kind(error.kind()),
            TransportError::SendFailed(message) => is_local_route_error_text(message),
            _ => false,
        }
    }
}

fn is_local_route_error_kind(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::AddrNotAvailable
    )
}

fn is_local_route_error_text(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("network is unreachable")
        || lower.contains("no route to host")
        || lower.contains("host is unreachable")
        || lower.contains("can't assign requested address")
        || lower.contains("cannot assign requested address")
        || lower.contains("os error 51")
        || lower.contains("os error 65")
        || lower.contains("os error 49")
}

// ============================================================================
// Transport Type Metadata
// ============================================================================

/// Static metadata about a transport type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportType {
    /// Human-readable name (e.g., "udp", "ethernet", "tor").
    pub name: &'static str,
    /// Whether this transport requires connection establishment.
    pub connection_oriented: bool,
    /// Whether the transport guarantees delivery.
    pub reliable: bool,
}

impl TransportType {
    /// UDP/IP transport.
    pub const UDP: TransportType = TransportType {
        name: "udp",
        connection_oriented: false,
        reliable: false,
    };

    /// TCP/IP transport.
    pub const TCP: TransportType = TransportType {
        name: "tcp",
        connection_oriented: true,
        reliable: true,
    };

    /// Raw Ethernet transport.
    pub const ETHERNET: TransportType = TransportType {
        name: "ethernet",
        connection_oriented: false,
        reliable: false,
    };

    /// WiFi (same characteristics as Ethernet).
    pub const WIFI: TransportType = TransportType {
        name: "wifi",
        connection_oriented: false,
        reliable: false,
    };

    /// Tor onion transport.
    pub const TOR: TransportType = TransportType {
        name: "tor",
        connection_oriented: true,
        reliable: true,
    };

    /// Serial/UART transport.
    pub const SERIAL: TransportType = TransportType {
        name: "serial",
        connection_oriented: false,
        reliable: true, // typically uses framing with checksums
    };

    /// BLE L2CAP CoC transport.
    pub const BLE: TransportType = TransportType {
        name: "ble",
        connection_oriented: true,
        reliable: true, // L2CAP SeqPacket guarantees delivery
    };

    /// WebRTC DataChannel transport.
    pub const WEBRTC: TransportType = TransportType {
        name: "webrtc",
        connection_oriented: true,
        reliable: false,
    };

    /// In-memory simulated packet transport.
    #[cfg(feature = "sim-transport")]
    pub const SIM: TransportType = TransportType {
        name: "sim",
        connection_oriented: false,
        reliable: false,
    };

    /// Check if the transport is connectionless.
    pub fn is_connectionless(&self) -> bool {
        !self.connection_oriented
    }
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ============================================================================
// Transport State
// ============================================================================

/// Transport lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportState {
    /// Configured but not started.
    Configured,
    /// Initialization in progress.
    Starting,
    /// Ready for links.
    Up,
    /// Was up, now unavailable.
    Down,
    /// Failed to start.
    Failed,
}

impl TransportState {
    /// Check if the transport is operational.
    pub fn is_operational(&self) -> bool {
        matches!(self, TransportState::Up)
    }

    /// Check if the transport can be started.
    pub fn can_start(&self) -> bool {
        matches!(
            self,
            TransportState::Configured | TransportState::Down | TransportState::Failed
        )
    }

    /// Check if the transport is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, TransportState::Failed)
    }
}

impl fmt::Display for TransportState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TransportState::Configured => "configured",
            TransportState::Starting => "starting",
            TransportState::Up => "up",
            TransportState::Down => "down",
            TransportState::Failed => "failed",
        };
        write!(f, "{}", s)
    }
}

// ============================================================================
// Link State
// ============================================================================

/// Link lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    /// Connection in progress (connection-oriented only).
    Connecting,
    /// Ready for traffic.
    Connected,
    /// Was connected, now gone.
    Disconnected,
    /// Connection attempt failed.
    Failed,
}

impl LinkState {
    /// Check if the link is operational.
    pub fn is_operational(&self) -> bool {
        matches!(self, LinkState::Connected)
    }

    /// Check if the link is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, LinkState::Disconnected | LinkState::Failed)
    }
}

impl fmt::Display for LinkState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LinkState::Connecting => "connecting",
            LinkState::Connected => "connected",
            LinkState::Disconnected => "disconnected",
            LinkState::Failed => "failed",
        };
        write!(f, "{}", s)
    }
}

/// Direction of link establishment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkDirection {
    /// We initiated the connection.
    Outbound,
    /// They initiated the connection.
    Inbound,
}

impl fmt::Display for LinkDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LinkDirection::Outbound => "outbound",
            LinkDirection::Inbound => "inbound",
        };
        write!(f, "{}", s)
    }
}

// ============================================================================
// Transport Address
// ============================================================================

/// Opaque transport-specific address.
///
/// Each transport type interprets this differently:
/// - UDP/TCP: "host:port" (IP address or DNS hostname)
/// - Ethernet: MAC address (6 bytes)
///
/// The bytes are immutable and shared so hot-path clones can carry path
/// evidence through receive/session bookkeeping without copying address bytes.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TransportAddr(Arc<[u8]>);

impl TransportAddr {
    /// Create a transport address from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes.into())
    }

    /// Create a transport address from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Arc::from(bytes))
    }

    /// Create a transport address from a string.
    pub fn from_string(s: &str) -> Self {
        Self(Arc::from(s.as_bytes()))
    }

    /// Create a transport address from a `SocketAddr` without going
    /// through `to_string()`.
    ///
    /// The standard path is `from_string(&addr.to_string())`, which
    /// allocates a `String` for the formatted address and then copies
    /// its bytes into a fresh `Vec<u8>` — two heap allocations per
    /// inbound packet on the UDP receive hot path. At line rate that's
    /// a few percent of one core in malloc/free. This variant writes
    /// the `SocketAddr::Display` representation directly into a
    /// `Vec<u8>` via `std::io::Write`, halving the alloc count and
    /// skipping the intermediate `String` materialisation entirely.
    pub fn from_socket_addr(addr: std::net::SocketAddr) -> Self {
        use std::io::Write;
        // Pre-size to fit `[ipv6_lit]:65535` (47 + brackets + colon +
        // port digits ≈ 56 bytes worst case) so we don't re-grow the
        // buffer mid-format on common addresses.
        let mut buf = Vec::with_capacity(56);
        // The `write!` macro on `&mut Vec<u8>` cannot fail (Vec's
        // `Write` impl is infallible for in-memory buffers), so the
        // expect is for shape only.
        write!(&mut buf, "{addr}").expect("Vec<u8>::write_fmt is infallible");
        Self(buf.into())
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Try to interpret as a UTF-8 string.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// Get the length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for TransportAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(s) => write!(f, "TransportAddr(\"{}\")", s),
            None => write!(f, "TransportAddr({:?})", self.0),
        }
    }
}

impl fmt::Display for TransportAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Best-effort display as string if valid UTF-8, else hex
        match self.as_str() {
            Some(s) => write!(f, "{}", s),
            None => {
                for byte in self.0.iter() {
                    write!(f, "{:02x}", byte)?;
                }
                Ok(())
            }
        }
    }
}

impl From<&str> for TransportAddr {
    fn from(s: &str) -> Self {
        Self::from_string(s)
    }
}

impl From<String> for TransportAddr {
    fn from(s: String) -> Self {
        Self(s.into_bytes().into())
    }
}

// ============================================================================
// Link Statistics
// ============================================================================

/// Statistics for a link.
#[derive(Clone, Debug, Default)]
pub struct LinkStats {
    /// Total packets sent.
    pub packets_sent: u64,
    /// Total packets received.
    pub packets_recv: u64,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_recv: u64,
    /// Timestamp of last received packet (Unix milliseconds).
    pub last_recv_ms: u64,
    /// Estimated round-trip time.
    rtt_estimate: Option<Duration>,
    /// Observed packet loss rate (0.0-1.0).
    pub loss_rate: f32,
    /// Estimated throughput in bytes/second.
    pub throughput_estimate: u64,
}

impl LinkStats {
    /// Create new link statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a sent packet.
    pub fn record_sent(&mut self, bytes: usize) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
    }

    /// Record a received packet.
    pub fn record_recv(&mut self, bytes: usize, timestamp_ms: u64) {
        self.packets_recv += 1;
        self.bytes_recv += bytes as u64;
        self.last_recv_ms = timestamp_ms;
    }

    /// Get the RTT estimate, if available.
    pub fn rtt_estimate(&self) -> Option<Duration> {
        self.rtt_estimate
    }

    /// Update RTT estimate from a probe response.
    ///
    /// Uses exponential moving average with alpha=0.2.
    pub fn update_rtt(&mut self, rtt: Duration) {
        match self.rtt_estimate {
            Some(old_rtt) => {
                let alpha = 0.2;
                let new_rtt_nanos = (alpha * rtt.as_nanos() as f64
                    + (1.0 - alpha) * old_rtt.as_nanos() as f64)
                    as u64;
                self.rtt_estimate = Some(Duration::from_nanos(new_rtt_nanos));
            }
            None => {
                self.rtt_estimate = Some(rtt);
            }
        }
    }

    /// Time since last receive (for keepalive/timeout).
    pub fn time_since_recv(&self, current_time_ms: u64) -> u64 {
        if self.last_recv_ms == 0 {
            return u64::MAX;
        }
        current_time_ms.saturating_sub(self.last_recv_ms)
    }

    /// Reset all statistics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// ============================================================================
// Link
// ============================================================================

/// A link to a remote endpoint over a transport.
#[derive(Clone, Debug)]
pub struct Link {
    /// Unique link identifier.
    link_id: LinkId,
    /// Which transport this link uses.
    transport_id: TransportId,
    /// Transport-specific remote address.
    remote_addr: TransportAddr,
    /// Whether we initiated or they initiated.
    direction: LinkDirection,
    /// Current link state.
    state: LinkState,
    /// Base RTT hint from transport type.
    base_rtt: Duration,
    /// Measured statistics.
    stats: LinkStats,
    /// When this link was created (Unix milliseconds).
    created_at: u64,
}

impl Link {
    /// Create a new link in Connecting state.
    pub fn new(
        link_id: LinkId,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        direction: LinkDirection,
        base_rtt: Duration,
    ) -> Self {
        Self {
            link_id,
            transport_id,
            remote_addr,
            direction,
            state: LinkState::Connecting,
            base_rtt,
            stats: LinkStats::new(),
            created_at: 0,
        }
    }

    /// Create a link with a creation timestamp.
    pub fn new_with_timestamp(
        link_id: LinkId,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        direction: LinkDirection,
        base_rtt: Duration,
        created_at: u64,
    ) -> Self {
        let mut link = Self::new(link_id, transport_id, remote_addr, direction, base_rtt);
        link.created_at = created_at;
        link
    }

    /// Create a connectionless link (immediately connected).
    ///
    /// For connectionless transports (UDP, Ethernet), links are immediately
    /// in the Connected state.
    pub fn connectionless(
        link_id: LinkId,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        direction: LinkDirection,
        base_rtt: Duration,
    ) -> Self {
        let mut link = Self::new(link_id, transport_id, remote_addr, direction, base_rtt);
        link.state = LinkState::Connected;
        link
    }

    /// Get the link ID.
    pub fn link_id(&self) -> LinkId {
        self.link_id
    }

    /// Get the transport ID.
    pub fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    /// Get the remote address.
    pub fn remote_addr(&self) -> &TransportAddr {
        &self.remote_addr
    }

    /// Get the link direction.
    pub fn direction(&self) -> LinkDirection {
        self.direction
    }

    /// Get the current state.
    pub fn state(&self) -> LinkState {
        self.state
    }

    /// Get the base RTT hint.
    pub fn base_rtt(&self) -> Duration {
        self.base_rtt
    }

    /// Get the link statistics.
    pub fn stats(&self) -> &LinkStats {
        &self.stats
    }

    /// Get mutable access to link statistics.
    pub fn stats_mut(&mut self) -> &mut LinkStats {
        &mut self.stats
    }

    /// Get the creation timestamp.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Set the creation timestamp.
    pub fn set_created_at(&mut self, timestamp: u64) {
        self.created_at = timestamp;
    }

    /// Mark the link as connected.
    pub fn set_connected(&mut self) {
        self.state = LinkState::Connected;
    }

    /// Mark the link as disconnected.
    pub fn set_disconnected(&mut self) {
        self.state = LinkState::Disconnected;
    }

    /// Mark the link as failed.
    pub fn set_failed(&mut self) {
        self.state = LinkState::Failed;
    }

    /// Check if this link is operational.
    pub fn is_operational(&self) -> bool {
        self.state.is_operational()
    }

    /// Check if this link is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Get effective RTT (measured if available, else base hint).
    pub fn effective_rtt(&self) -> Duration {
        self.stats.rtt_estimate().unwrap_or(self.base_rtt)
    }

    /// Age of the link in milliseconds.
    pub fn age(&self, current_time_ms: u64) -> u64 {
        if self.created_at == 0 {
            return 0;
        }
        current_time_ms.saturating_sub(self.created_at)
    }
}

// ============================================================================
// Discovered Peer
// ============================================================================

/// A peer discovered via transport-layer discovery.
#[derive(Clone, Debug)]
pub struct DiscoveredPeer {
    /// Transport that discovered this peer.
    pub transport_id: TransportId,
    /// Transport address where the peer was found.
    pub addr: TransportAddr,
    /// Optional hint about the peer's identity (if known from discovery).
    pub pubkey_hint: Option<XOnlyPublicKey>,
}

impl DiscoveredPeer {
    /// Create a discovered peer without identity hint.
    pub fn new(transport_id: TransportId, addr: TransportAddr) -> Self {
        Self {
            transport_id,
            addr,
            pubkey_hint: None,
        }
    }

    /// Create a discovered peer with identity hint.
    pub fn with_hint(
        transport_id: TransportId,
        addr: TransportAddr,
        pubkey: XOnlyPublicKey,
    ) -> Self {
        Self {
            transport_id,
            addr,
            pubkey_hint: Some(pubkey),
        }
    }
}

// ============================================================================
// Transport Trait
// ============================================================================

/// Transport trait defining the interface for transport drivers.
///
/// This is a simplified synchronous trait. Actual implementations would
/// be async and use channels for event delivery.
pub trait Transport {
    /// Get the transport identifier.
    fn transport_id(&self) -> TransportId;

    /// Get the transport type metadata.
    fn transport_type(&self) -> &TransportType;

    /// Get the current state.
    fn state(&self) -> TransportState;

    /// Get the MTU for this transport.
    fn mtu(&self) -> u16;

    /// Get the MTU for a specific link.
    ///
    /// Returns the MTU negotiated for the given transport address, or
    /// falls back to the transport-wide default if the address is unknown
    /// or the transport doesn't support per-link MTU negotiation.
    fn link_mtu(&self, addr: &TransportAddr) -> u16 {
        let _ = addr;
        self.mtu()
    }

    /// Start the transport.
    fn start(&mut self) -> Result<(), TransportError>;

    /// Stop the transport.
    fn stop(&mut self) -> Result<(), TransportError>;

    /// Send data to a transport address.
    fn send(&self, addr: &TransportAddr, data: &[u8]) -> Result<(), TransportError>;

    /// Discover potential peers (if supported).
    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError>;

    /// Whether to auto-connect to peers returned by discover().
    /// Default: false. Concrete transports read from their own config.
    fn auto_connect(&self) -> bool {
        false
    }

    /// Whether to accept inbound handshake initiations on this transport.
    /// Default: true (preserves UDP's current implicit behavior).
    fn accept_connections(&self) -> bool {
        true
    }

    /// Close a specific connection (connection-oriented transports only).
    ///
    /// For connectionless transports (UDP, Ethernet), this is a no-op.
    /// Connection-oriented transports (TCP, Tor) remove the connection
    /// from their pool and drop the underlying stream.
    fn close_connection(&self, _addr: &TransportAddr) {
        // Default no-op for connectionless transports
    }
}

// ============================================================================
// Connection State (for non-blocking connect)
// ============================================================================

/// State of a transport-level connection attempt.
///
/// Used by connection-oriented transports (TCP, Tor) to report the progress
/// of a background connection attempt initiated by `connect()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    /// No connection attempt in progress for this address.
    None,
    /// Connection attempt is in progress (background task running).
    Connecting,
    /// Connection is established and ready for send().
    Connected,
    /// Connection attempt failed with the given error message.
    Failed(String),
}

// ============================================================================
// Transport Congestion
// ============================================================================

/// Transport-local congestion indicators.
///
/// All fields are optional — transports report what they can.
/// Consumers compute deltas from cumulative counters.
#[derive(Clone, Debug, Default)]
pub struct TransportCongestion {
    /// Cumulative packets dropped by kernel/OS before reaching the application.
    /// Monotonically increasing since transport start.
    pub recv_drops: Option<u64>,
}

// ============================================================================
// Transport Handle
// ============================================================================

/// Wrapper enum for concrete transport implementations.
///
/// This enables polymorphic transport handling without trait objects,
/// supporting async methods that the sync Transport trait cannot express.
pub enum TransportHandle {
    /// UDP/IP transport.
    Udp(UdpTransport),
    /// In-memory simulated packet transport.
    #[cfg(feature = "sim-transport")]
    Sim(SimTransport),
    /// Raw Ethernet transport.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Ethernet(EthernetTransport),
    /// TCP/IP transport.
    Tcp(TcpTransport),
    /// Tor transport (via SOCKS5).
    Tor(TorTransport),
    /// WebRTC DataChannel transport.
    #[cfg(feature = "webrtc-transport")]
    WebRtc(Box<WebRtcTransport>),
    /// BLE L2CAP transport.
    #[cfg(target_os = "linux")]
    Ble(DefaultBleTransport),
}

impl TransportHandle {
    /// Start the transport asynchronously.
    pub async fn start(&mut self) -> Result<(), TransportError> {
        match self {
            TransportHandle::Udp(t) => t.start_async().await,
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.start_async().await,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.start_async().await,
            TransportHandle::Tcp(t) => t.start_async().await,
            TransportHandle::Tor(t) => t.start_async().await,
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.start_async().await,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.start_async().await,
        }
    }

    /// Stop the transport asynchronously.
    pub async fn stop(&mut self) -> Result<(), TransportError> {
        match self {
            TransportHandle::Udp(t) => t.stop_async().await,
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.stop_async().await,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.stop_async().await,
            TransportHandle::Tcp(t) => t.stop_async().await,
            TransportHandle::Tor(t) => t.stop_async().await,
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.stop_async().await,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.stop_async().await,
        }
    }

    /// Send data to a remote address asynchronously.
    pub async fn send(&self, addr: &TransportAddr, data: &[u8]) -> Result<usize, TransportError> {
        match self {
            TransportHandle::Udp(t) => t.send_async(addr, data).await,
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.send_async(addr, data).await,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.send_async(addr, data).await,
            TransportHandle::Tcp(t) => t.send_async(addr, data).await,
            TransportHandle::Tor(t) => t.send_async(addr, data).await,
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.send_async(addr, data).await,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.send_async(addr, data).await,
        }
    }

    /// Get the transport ID.
    pub fn transport_id(&self) -> TransportId {
        match self {
            TransportHandle::Udp(t) => t.transport_id(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.transport_id(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.transport_id(),
            TransportHandle::Tcp(t) => t.transport_id(),
            TransportHandle::Tor(t) => t.transport_id(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.transport_id(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.transport_id(),
        }
    }

    /// Get the instance name (if configured as a named instance).
    pub fn name(&self) -> Option<&str> {
        match self {
            TransportHandle::Udp(t) => t.name(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.name(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.name(),
            TransportHandle::Tcp(t) => t.name(),
            TransportHandle::Tor(t) => t.name(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.name(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.name(),
        }
    }

    /// Get the transport type metadata.
    pub fn transport_type(&self) -> &TransportType {
        match self {
            TransportHandle::Udp(t) => t.transport_type(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.transport_type(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.transport_type(),
            TransportHandle::Tcp(t) => t.transport_type(),
            TransportHandle::Tor(t) => t.transport_type(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.transport_type(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.transport_type(),
        }
    }

    /// Get current transport state.
    pub fn state(&self) -> TransportState {
        match self {
            TransportHandle::Udp(t) => t.state(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.state(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.state(),
            TransportHandle::Tcp(t) => t.state(),
            TransportHandle::Tor(t) => t.state(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.state(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.state(),
        }
    }

    /// Get the transport MTU.
    pub fn mtu(&self) -> u16 {
        match self {
            TransportHandle::Udp(t) => t.mtu(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.mtu(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.mtu(),
            TransportHandle::Tcp(t) => t.mtu(),
            TransportHandle::Tor(t) => t.mtu(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.mtu(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.mtu(),
        }
    }

    /// Get the MTU for a specific link address.
    ///
    /// Falls back to transport-wide MTU if the transport doesn't
    /// support per-link MTU or the address is unknown.
    pub fn link_mtu(&self, addr: &TransportAddr) -> u16 {
        match self {
            TransportHandle::Udp(t) => t.link_mtu(addr),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.link_mtu(addr),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.link_mtu(addr),
            TransportHandle::Tcp(t) => t.link_mtu(addr),
            TransportHandle::Tor(t) => t.link_mtu(addr),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.link_mtu(addr),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.link_mtu(addr),
        }
    }

    /// Get the local bound address (UDP/TCP only, returns None for other transports).
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            TransportHandle::Udp(t) => t.local_addr(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(_) => None,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(_) => None,
            TransportHandle::Tcp(t) => t.local_addr(),
            TransportHandle::Tor(_) => None,
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(_) => None,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(_) => None,
        }
    }

    /// Get the interface name (Ethernet only, returns None for other transports).
    pub fn interface_name(&self) -> Option<&str> {
        match self {
            TransportHandle::Udp(_) => None,
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(_) => None,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => Some(t.interface_name()),
            TransportHandle::Tcp(_) => None,
            TransportHandle::Tor(_) => None,
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(_) => None,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(_) => None,
        }
    }

    /// Get the onion service address (Tor only, returns None for other transports).
    pub fn onion_address(&self) -> Option<&str> {
        match self {
            TransportHandle::Tor(t) => t.onion_address(),
            _ => None,
        }
    }

    /// Get cached Tor daemon monitoring info (Tor only).
    pub fn tor_monitoring(&self) -> Option<TorMonitoringInfo> {
        match self {
            TransportHandle::Tor(t) => t.cached_monitoring(),
            _ => None,
        }
    }

    /// Get the Tor transport mode (Tor only).
    pub fn tor_mode(&self) -> Option<&str> {
        match self {
            TransportHandle::Tor(t) => Some(t.mode()),
            _ => None,
        }
    }

    /// Drain discovered peers from this transport.
    pub fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        match self {
            TransportHandle::Udp(t) => t.discover(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.discover(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.discover(),
            TransportHandle::Tcp(t) => t.discover(),
            TransportHandle::Tor(t) => t.discover(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.discover(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.discover(),
        }
    }

    /// Whether this transport auto-connects to discovered peers.
    pub fn auto_connect(&self) -> bool {
        match self {
            TransportHandle::Udp(t) => t.auto_connect(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.auto_connect(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.auto_connect(),
            TransportHandle::Tcp(t) => t.auto_connect(),
            TransportHandle::Tor(t) => t.auto_connect(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.auto_connect(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.auto_connect(),
        }
    }

    /// Whether this transport accepts inbound connections.
    pub fn accept_connections(&self) -> bool {
        match self {
            TransportHandle::Udp(t) => t.accept_connections(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.accept_connections(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.accept_connections(),
            TransportHandle::Tcp(t) => t.accept_connections(),
            TransportHandle::Tor(t) => t.accept_connections(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.accept_connections(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.accept_connections(),
        }
    }

    /// Initiate a non-blocking connection to a remote address.
    ///
    /// For connection-oriented transports (TCP, Tor), spawns a background
    /// task to establish the connection. For connectionless transports
    /// (UDP, Ethernet), this is a no-op that returns Ok immediately.
    ///
    /// Poll `connection_state()` to check when the connection is ready.
    pub async fn connect(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        match self {
            TransportHandle::Udp(_) => Ok(()), // connectionless
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(_) => Ok(()), // connectionless
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(_) => Ok(()), // connectionless
            TransportHandle::Tcp(t) => t.connect_async(addr).await,
            TransportHandle::Tor(t) => t.connect_async(addr).await,
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.connect_async(addr).await,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.connect_async(addr).await,
        }
    }

    /// Query the state of a connection attempt to a remote address.
    ///
    /// For connectionless transports, always returns `ConnectionState::Connected`
    /// (they are always "connected"). For connection-oriented transports, returns
    /// the current state of the background connection attempt.
    pub fn connection_state(&self, addr: &TransportAddr) -> ConnectionState {
        match self {
            TransportHandle::Udp(_) => ConnectionState::Connected,
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(_) => ConnectionState::Connected,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(_) => ConnectionState::Connected,
            TransportHandle::Tcp(t) => t.connection_state_sync(addr),
            TransportHandle::Tor(t) => t.connection_state_sync(addr),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.connection_state_sync(addr),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.connection_state_sync(addr),
        }
    }

    /// Close a specific connection on this transport.
    ///
    /// No-op for connectionless transports. For TCP/Tor, removes the
    /// connection from the pool and drops the stream.
    pub async fn close_connection(&self, addr: &TransportAddr) {
        match self {
            TransportHandle::Udp(t) => t.close_connection(addr),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.close_connection(addr),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.close_connection(addr),
            TransportHandle::Tcp(t) => t.close_connection_async(addr).await,
            TransportHandle::Tor(t) => t.close_connection_async(addr).await,
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.close_connection_async(addr).await,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.close_connection_async(addr).await,
        }
    }

    /// Check if transport is operational.
    pub fn is_operational(&self) -> bool {
        self.state().is_operational()
    }

    /// Query transport-local congestion indicators.
    ///
    /// Returns a snapshot of congestion signals that the transport can
    /// observe locally (e.g., kernel receive buffer drops). Fields are
    /// `None` when the transport doesn't support that signal.
    pub fn congestion(&self) -> TransportCongestion {
        match self {
            TransportHandle::Udp(t) => t.congestion(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(_) => TransportCongestion::default(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(_) => TransportCongestion::default(),
            TransportHandle::Tcp(_) => TransportCongestion::default(),
            TransportHandle::Tor(_) => TransportCongestion::default(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(_) => TransportCongestion::default(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(_) => TransportCongestion::default(),
        }
    }

    /// Get transport-specific stats as a JSON value.
    ///
    /// Returns a snapshot of counters for the specific transport type.
    pub fn transport_stats(&self) -> serde_json::Value {
        match self {
            TransportHandle::Udp(t) => {
                serde_json::to_value(t.stats().snapshot()).unwrap_or_default()
            }
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => serde_json::to_value(t.stats()).unwrap_or_default(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => {
                let snap = t.stats().snapshot();
                serde_json::json!({
                    "frames_sent": snap.frames_sent,
                    "frames_recv": snap.frames_recv,
                    "bytes_sent": snap.bytes_sent,
                    "bytes_recv": snap.bytes_recv,
                    "send_errors": snap.send_errors,
                    "recv_errors": snap.recv_errors,
                    "beacons_sent": snap.beacons_sent,
                    "beacons_recv": snap.beacons_recv,
                    "frames_too_short": snap.frames_too_short,
                    "frames_too_long": snap.frames_too_long,
                })
            }
            TransportHandle::Tcp(t) => {
                serde_json::to_value(t.stats().snapshot()).unwrap_or_default()
            }
            TransportHandle::Tor(t) => {
                serde_json::to_value(t.stats().snapshot()).unwrap_or_default()
            }
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => serde_json::json!({
                "mtu": t.mtu(),
                "state": t.state().to_string(),
            }),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => {
                serde_json::to_value(t.stats().snapshot()).unwrap_or_default()
            }
        }
    }
}

// ============================================================================
// DNS Resolution
// ============================================================================

/// Resolve a TransportAddr to a SocketAddr.
///
/// Fast path: if the address parses as a numeric IP:port, returns
/// immediately with no DNS lookup. Otherwise, treats the address as
/// `hostname:port` and performs async DNS resolution via the system
/// resolver.
pub(crate) async fn resolve_socket_addr(
    addr: &TransportAddr,
) -> Result<SocketAddr, TransportError> {
    resolve_socket_addrs(addr)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| {
            TransportError::InvalidAddress(format!(
                "DNS resolution returned no addresses for {}",
                addr.as_str().unwrap_or("<non-utf8>")
            ))
        })
}

/// Resolve a TransportAddr to every SocketAddr returned by the resolver.
///
/// Numeric IP addresses still bypass DNS. Hostnames keep the resolver's
/// address order, and callers that establish connections should try more than
/// one address so dual-stack hosts still work when one address family is
/// temporarily broken.
pub(crate) async fn resolve_socket_addrs(
    addr: &TransportAddr,
) -> Result<Vec<SocketAddr>, TransportError> {
    let s = addr
        .as_str()
        .ok_or_else(|| TransportError::InvalidAddress("not valid UTF-8".into()))?;

    // Fast path: numeric IP address — no DNS lookup
    if let Ok(sock_addr) = s.parse::<SocketAddr>() {
        return Ok(vec![sock_addr]);
    }

    // Slow path: DNS resolution
    let addrs = tokio::net::lookup_host(s)
        .await
        .map_err(|e| {
            TransportError::InvalidAddress(format!("DNS resolution failed for {}: {}", s, e))
        })?
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(TransportError::InvalidAddress(format!(
            "DNS resolution returned no addresses for {}",
            s
        )));
    }
    Ok(addrs)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_id() {
        let id = TransportId::new(42);
        assert_eq!(id.as_u32(), 42);
        assert_eq!(format!("{}", id), "transport:42");
    }

    #[test]
    fn test_link_id() {
        let id = LinkId::new(12345);
        assert_eq!(id.as_u64(), 12345);
        assert_eq!(format!("{}", id), "link:12345");
    }

    #[test]
    fn test_transport_state_transitions() {
        assert!(TransportState::Configured.can_start());
        assert!(TransportState::Down.can_start());
        assert!(TransportState::Failed.can_start());
        assert!(!TransportState::Starting.can_start());
        assert!(!TransportState::Up.can_start());

        assert!(TransportState::Up.is_operational());
        assert!(!TransportState::Starting.is_operational());
        assert!(!TransportState::Failed.is_operational());
    }

    #[test]
    fn test_link_state() {
        assert!(LinkState::Connected.is_operational());
        assert!(!LinkState::Connecting.is_operational());
        assert!(!LinkState::Disconnected.is_operational());
        assert!(!LinkState::Failed.is_operational());

        assert!(LinkState::Disconnected.is_terminal());
        assert!(LinkState::Failed.is_terminal());
        assert!(!LinkState::Connected.is_terminal());
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_transport_type_constants() {
        // These assertions verify the constant definitions are correct
        assert!(!TransportType::UDP.connection_oriented);
        assert!(!TransportType::UDP.reliable);
        assert!(TransportType::UDP.is_connectionless());

        assert!(TransportType::TOR.connection_oriented);
        assert!(TransportType::TOR.reliable);
        assert!(!TransportType::TOR.is_connectionless());

        assert_eq!(TransportType::UDP.name, "udp");
        assert_eq!(TransportType::ETHERNET.name, "ethernet");
    }

    #[test]
    fn test_transport_addr_string() {
        let addr = TransportAddr::from_string("192.168.1.1:2121");
        assert_eq!(format!("{}", addr), "192.168.1.1:2121");
        assert_eq!(addr.as_str(), Some("192.168.1.1:2121"));
    }

    #[test]
    fn transport_addr_clone_shares_immutable_bytes() {
        let addr = TransportAddr::from_string("192.168.1.1:2121");
        let cloned = addr.clone();

        assert_eq!(addr, cloned);
        assert!(Arc::ptr_eq(&addr.0, &cloned.0));
    }

    #[test]
    fn transport_addr_hashes_by_value_not_pointer() {
        use std::collections::HashSet;

        let original = TransportAddr::from_string("192.168.1.1:2121");
        let same_value = TransportAddr::from_bytes(b"192.168.1.1:2121");
        let mut addrs = HashSet::new();

        addrs.insert(original);

        assert!(addrs.contains(&same_value));
    }

    #[test]
    fn test_transport_addr_binary() {
        // Binary address with invalid UTF-8 bytes (0xff, 0x80 are invalid UTF-8)
        let binary = TransportAddr::new(vec![0xff, 0x80, 0x2b, 0x3c, 0x4d, 0x5e]);
        assert_eq!(format!("{}", binary), "ff802b3c4d5e");
        assert!(binary.as_str().is_none());
        assert_eq!(binary.len(), 6);
    }

    #[test]
    fn test_transport_addr_from_string() {
        let addr: TransportAddr = "test:1234".into();
        assert_eq!(addr.as_str(), Some("test:1234"));

        let addr2: TransportAddr = String::from("hello").into();
        assert_eq!(addr2.as_str(), Some("hello"));
    }

    #[test]
    fn test_link_stats_basic() {
        let mut stats = LinkStats::new();

        stats.record_sent(100);
        stats.record_recv(200, 1000);

        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.bytes_sent, 100);
        assert_eq!(stats.packets_recv, 1);
        assert_eq!(stats.bytes_recv, 200);
        assert_eq!(stats.last_recv_ms, 1000);
    }

    #[test]
    fn test_link_stats_rtt() {
        let mut stats = LinkStats::new();

        assert!(stats.rtt_estimate().is_none());

        stats.update_rtt(Duration::from_millis(100));
        assert_eq!(stats.rtt_estimate(), Some(Duration::from_millis(100)));

        // Second update uses EMA
        stats.update_rtt(Duration::from_millis(200));
        // EMA: 0.2 * 200 + 0.8 * 100 = 120ms
        let rtt = stats.rtt_estimate().unwrap();
        assert!(rtt.as_millis() >= 110 && rtt.as_millis() <= 130);
    }

    #[test]
    fn test_link_stats_time_since_recv() {
        let mut stats = LinkStats::new();

        // No receive yet
        assert_eq!(stats.time_since_recv(1000), u64::MAX);

        stats.record_recv(100, 500);
        assert_eq!(stats.time_since_recv(1000), 500);
        assert_eq!(stats.time_since_recv(500), 0);
    }

    #[test]
    fn test_link_creation() {
        let link = Link::new(
            LinkId::new(1),
            TransportId::new(1),
            TransportAddr::from_string("test"),
            LinkDirection::Outbound,
            Duration::from_millis(50),
        );

        assert_eq!(link.state(), LinkState::Connecting);
        assert!(!link.is_operational());
        assert_eq!(link.direction(), LinkDirection::Outbound);
    }

    #[test]
    fn test_link_connectionless() {
        let link = Link::connectionless(
            LinkId::new(1),
            TransportId::new(1),
            TransportAddr::from_string("test"),
            LinkDirection::Inbound,
            Duration::from_millis(5),
        );

        assert_eq!(link.state(), LinkState::Connected);
        assert!(link.is_operational());
    }

    #[test]
    fn test_link_state_changes() {
        let mut link = Link::new(
            LinkId::new(1),
            TransportId::new(1),
            TransportAddr::from_string("test"),
            LinkDirection::Outbound,
            Duration::from_millis(50),
        );

        assert!(!link.is_operational());

        link.set_connected();
        assert!(link.is_operational());
        assert!(!link.is_terminal());

        link.set_disconnected();
        assert!(!link.is_operational());
        assert!(link.is_terminal());
    }

    #[test]
    fn test_link_effective_rtt() {
        let mut link = Link::connectionless(
            LinkId::new(1),
            TransportId::new(1),
            TransportAddr::from_string("test"),
            LinkDirection::Inbound,
            Duration::from_millis(50),
        );

        // Before measurement, uses base RTT
        assert_eq!(link.effective_rtt(), Duration::from_millis(50));

        // After measurement, uses measured RTT
        link.stats_mut().update_rtt(Duration::from_millis(100));
        assert_eq!(link.effective_rtt(), Duration::from_millis(100));
    }

    #[test]
    fn test_link_age() {
        let mut link = Link::new(
            LinkId::new(1),
            TransportId::new(1),
            TransportAddr::from_string("test"),
            LinkDirection::Outbound,
            Duration::from_millis(50),
        );

        // No timestamp set
        assert_eq!(link.age(1000), 0);

        link.set_created_at(500);
        assert_eq!(link.age(1000), 500);
        assert_eq!(link.age(500), 0);
    }

    #[test]
    fn test_discovered_peer() {
        let peer = DiscoveredPeer::new(
            TransportId::new(1),
            TransportAddr::from_string("192.168.1.1:2121"),
        );

        assert_eq!(peer.transport_id, TransportId::new(1));
        assert!(peer.pubkey_hint.is_none());
    }

    #[test]
    fn test_link_direction_display() {
        assert_eq!(format!("{}", LinkDirection::Outbound), "outbound");
        assert_eq!(format!("{}", LinkDirection::Inbound), "inbound");
    }

    #[test]
    fn test_transport_state_display() {
        assert_eq!(format!("{}", TransportState::Up), "up");
        assert_eq!(format!("{}", TransportState::Failed), "failed");
    }

    #[test]
    fn test_received_packet() {
        let packet = ReceivedPacket::new(
            TransportId::new(1),
            TransportAddr::from_string("192.168.1.1:2121"),
            vec![1, 2, 3, 4],
        );

        assert_eq!(packet.transport_id, TransportId::new(1));
        assert_eq!(packet.data, vec![1, 2, 3, 4]);
        assert!(packet.timestamp_ms > 0);
    }

    #[test]
    fn test_received_packet_with_timestamp() {
        let packet = ReceivedPacket::with_timestamp(
            TransportId::new(1),
            TransportAddr::from_string("test"),
            vec![5, 6],
            12345,
        );

        assert_eq!(packet.timestamp_ms, 12345);
    }

    #[test]
    fn received_packet_can_reuse_batch_timestamps() {
        let trace_enqueued_at = crate::perf_profile::stamp();
        let packet = ReceivedPacket::with_trace_timestamp(
            TransportId::new(7),
            TransportAddr::from_string("batch"),
            vec![8, 9],
            67890,
            trace_enqueued_at,
        );

        assert_eq!(packet.transport_id, TransportId::new(7));
        assert_eq!(packet.timestamp_ms, 67890);
        assert_eq!(packet.trace_enqueued_at, trace_enqueued_at);
    }

    #[tokio::test]
    async fn test_packet_channel() {
        let (tx, mut rx) = packet_channel(10);

        let packet = ReceivedPacket::new(
            TransportId::new(1),
            TransportAddr::from_string("test"),
            vec![1, 2, 3],
        );

        tx.send(packet.clone()).unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.data, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn packet_channel_reserves_priority_progress_ahead_of_bulk_backlog() {
        let (tx, mut rx) = packet_channel(10);
        let addr = TransportAddr::from_string("test");

        tx.send(ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
        ))
        .unwrap();
        tx.send(ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0x11; 32],
        ))
        .unwrap();
        tx.send(ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0x22; 48],
        ))
        .unwrap();
        tx.send(ReceivedPacket::new(
            TransportId::new(1),
            addr,
            vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
        ))
        .unwrap();

        assert_eq!(rx.recv().await.unwrap().data[0], 0x11);
        assert_eq!(rx.recv().await.unwrap().data[0], 0x22);
        assert_eq!(rx.recv().await.unwrap().data[0], 0xaa);
        assert_eq!(rx.recv().await.unwrap().data[0], 0xbb);
    }

    #[test]
    fn packet_channel_try_recv_uses_same_priority_policy() {
        let (tx, mut rx) = packet_channel(10);
        let addr = TransportAddr::from_string("test");

        tx.send(ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
        ))
        .unwrap();
        tx.send(ReceivedPacket::new(
            TransportId::new(1),
            addr,
            vec![0x11; 32],
        ))
        .unwrap();

        assert_eq!(rx.try_recv().unwrap().data[0], 0x11);
        assert_eq!(rx.try_recv().unwrap().data[0], 0xaa);
    }

    #[tokio::test]
    async fn packet_channel_batch_send_amortizes_bulk_channel_items() {
        let (tx, mut rx) = packet_channel(10);
        let addr = TransportAddr::from_string("test");

        tx.send_batch(vec![
            ReceivedPacket::new(
                TransportId::new(1),
                addr.clone(),
                vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
            ),
            ReceivedPacket::new(
                TransportId::new(1),
                addr.clone(),
                vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
            ),
            ReceivedPacket::new(
                TransportId::new(1),
                addr,
                vec![0xcc; PRIORITY_PACKET_MAX_LEN + 3],
            ),
        ])
        .expect("bulk batch send should succeed");

        assert_eq!(
            rx.bulk.len(),
            1,
            "bulk kernel receive batch should occupy one channel item"
        );
        assert_eq!(rx.recv().await.unwrap().data[0], 0xaa);
        assert_eq!(rx.recv().await.unwrap().data[0], 0xbb);
        assert_eq!(rx.recv().await.unwrap().data[0], 0xcc);
    }

    #[test]
    fn packet_channel_keeps_single_lane_batches_grouped() {
        let (tx, mut rx) = packet_channel(10);
        let addr = TransportAddr::from_string("test");

        tx.send_batch(vec![
            ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x11; 32]),
            ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x22; 48]),
        ])
        .expect("priority batch send should succeed");
        tx.send_batch(vec![
            ReceivedPacket::new(
                TransportId::new(1),
                addr.clone(),
                vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
            ),
            ReceivedPacket::new(
                TransportId::new(1),
                addr,
                vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
            ),
        ])
        .expect("bulk batch send should succeed");

        assert_eq!(
            rx.priority.len(),
            1,
            "priority-only receive batch should occupy one channel item"
        );
        assert_eq!(
            rx.bulk.len(),
            1,
            "bulk-only receive batch should occupy one channel item"
        );
        match rx.priority.try_recv().expect("priority channel item") {
            PacketQueueItem::Batch(packets) => {
                assert_eq!(packets.len(), 2);
                assert_eq!(packets[0].data[0], 0x11);
                assert_eq!(packets[1].data[0], 0x22);
            }
            item => panic!("expected grouped priority batch, got {item:?}"),
        }
        match rx.bulk.try_recv().expect("bulk channel item") {
            PacketQueueItem::Batch(packets) => {
                assert_eq!(packets.len(), 2);
                assert_eq!(packets[0].data[0], 0xaa);
                assert_eq!(packets[1].data[0], 0xbb);
            }
            item => panic!("expected grouped bulk batch, got {item:?}"),
        }
    }

    #[test]
    fn packet_channel_dequeue_counts_preserve_item_and_lane_counts() {
        let addr = TransportAddr::from_string("test");

        let item = PacketQueueItem::One(ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0x11; 32],
        ));
        assert_eq!(
            item.dequeue_counts(PacketLane::Priority),
            PacketQueueDequeueCounts {
                total: 1,
                priority: 1,
                bulk: 0,
            }
        );

        let item = PacketQueueItem::Batch(vec![
            ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x11; 32]),
            ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x22; 48]),
        ]);
        assert_eq!(
            item.dequeue_counts(PacketLane::Priority),
            PacketQueueDequeueCounts {
                total: 2,
                priority: 2,
                bulk: 0,
            }
        );

        let item = PacketQueueItem::Batch(vec![
            ReceivedPacket::new(
                TransportId::new(1),
                addr.clone(),
                vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
            ),
            ReceivedPacket::new(
                TransportId::new(1),
                addr,
                vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
            ),
        ]);
        assert_eq!(
            item.dequeue_counts(PacketLane::Bulk),
            PacketQueueDequeueCounts {
                total: 2,
                priority: 0,
                bulk: 2,
            }
        );
    }

    #[test]
    fn pending_packets_apply_rx_loop_owned_stamp_as_packets_are_taken() {
        let addr = TransportAddr::from_string("test");
        let rx_loop_owned_at = Some(crate::perf_profile::test_stamp());
        let packets = vec![
            ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0xaa; 32]),
            ReceivedPacket::new(TransportId::new(1), addr, vec![0xbb; 48]),
        ]
        .into_iter();
        let mut pending = Some(PendingPackets::new(packets, rx_loop_owned_at));

        let first = PacketRx::take_pending(&mut pending).expect("first pending packet");
        assert_eq!(first.trace_rx_loop_owned_at, rx_loop_owned_at);
        assert!(
            pending.is_some(),
            "one packet should remain after taking the first pending packet"
        );

        let second = PacketRx::take_pending(&mut pending).expect("second pending packet");
        assert_eq!(second.trace_rx_loop_owned_at, rx_loop_owned_at);
        assert!(
            pending.is_none(),
            "pending batch should clear after the last packet is taken"
        );
    }

    #[test]
    fn release_reserved_bulk_packets_subtracts_exact_count() {
        let counter = AtomicUsize::new(5);

        release_reserved_bulk_packets(&counter, 0);
        assert_eq!(counter.load(Relaxed), 5);

        release_reserved_bulk_packets(&counter, 3);
        assert_eq!(counter.load(Relaxed), 2);
    }

    #[test]
    fn release_priority_packets_subtracts_exact_count() {
        let counter = AtomicUsize::new(5);

        release_priority_packets(&counter, 0);
        assert_eq!(counter.load(Relaxed), 5);

        release_priority_packets(&counter, 3);
        assert_eq!(counter.load(Relaxed), 2);
    }

    #[test]
    fn packet_channel_priority_hint_counts_channel_owned_packets() {
        let (tx, mut rx) = packet_channel(10);
        let addr = TransportAddr::from_string("test");

        tx.send_batch(vec![
            ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x11; 32]),
            ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x22; 48]),
        ])
        .expect("priority batch send should succeed");
        assert_eq!(tx.priority_queued_packets(), 2);
        assert_eq!(tx.bulk_queued_packets(), 0);

        assert_eq!(rx.try_recv().unwrap().data[0], 0x11);
        assert_eq!(
            tx.priority_queued_packets(),
            0,
            "once a priority batch is dequeued, its tail is rx-loop-owned"
        );
        assert_eq!(rx.try_recv().unwrap().data[0], 0x22);
        assert_eq!(tx.priority_queued_packets(), 0);

        tx.send_batch(vec![
            ReceivedPacket::new(
                TransportId::new(1),
                addr.clone(),
                vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
            ),
            ReceivedPacket::new(
                TransportId::new(1),
                addr,
                vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
            ),
        ])
        .expect("bulk batch send should succeed");
        assert_eq!(
            tx.priority_queued_packets(),
            0,
            "bulk traffic should not make PacketRx probe the priority lane"
        );
    }

    #[test]
    fn packet_rx_priority_ready_includes_pending_batch_tail() {
        let (tx, mut rx) = packet_channel(10);
        let addr = TransportAddr::from_string("test");

        tx.send_batch(vec![
            ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x11; 32]),
            ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x22; 48]),
            ReceivedPacket::new(TransportId::new(1), addr, vec![0x33; 64]),
        ])
        .expect("priority batch send should succeed");

        assert_eq!(rx.priority_ready_packets(), 3);
        assert_eq!(rx.try_recv().unwrap().data[0], 0x11);
        assert_eq!(
            tx.priority_queued_packets(),
            0,
            "sender-side channel hint should clear once PacketRx owns the batch"
        );
        assert_eq!(
            rx.priority_ready_packets(),
            2,
            "rx-loop scheduling must still see the priority batch tail"
        );
        assert_eq!(rx.try_recv().unwrap().data[0], 0x22);
        assert_eq!(rx.priority_ready_packets(), 1);
        assert_eq!(rx.try_recv().unwrap().data[0], 0x33);
        assert_eq!(rx.priority_ready_packets(), 0);
    }

    #[tokio::test]
    async fn packet_channel_priority_overtakes_pending_bulk_batch_tail() {
        let (tx, mut rx) = packet_channel(10);
        let addr = TransportAddr::from_string("test");

        tx.send_batch(vec![
            ReceivedPacket::new(
                TransportId::new(1),
                addr.clone(),
                vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
            ),
            ReceivedPacket::new(
                TransportId::new(1),
                addr.clone(),
                vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
            ),
        ])
        .expect("bulk batch send should succeed");

        assert_eq!(rx.recv().await.unwrap().data[0], 0xaa);
        tx.send(ReceivedPacket::new(
            TransportId::new(1),
            addr,
            vec![0x11; 32],
        ))
        .expect("priority packet send should succeed");

        assert_eq!(rx.recv().await.unwrap().data[0], 0x11);
        assert_eq!(rx.recv().await.unwrap().data[0], 0xbb);
    }

    #[tokio::test]
    async fn packet_channel_bounded_bulk_drops_without_blocking_priority() {
        let (tx, mut rx) = packet_channel(1);
        let addr = TransportAddr::from_string("test");

        tx.send(ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
        ))
        .expect("first bulk packet should fill bounded bulk lane");
        assert_eq!(tx.queued_packets(), 1);
        assert_eq!(tx.bulk_queued_packets(), 1);

        tx.send(ReceivedPacket::new(
            TransportId::new(1),
            addr.clone(),
            vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
        ))
        .expect("full bulk lane should drop overload without closing sender");
        assert_eq!(
            tx.queued_packets(),
            1,
            "dropped bulk must roll back channel-owned backlog accounting"
        );
        assert_eq!(tx.bulk_queued_packets(), 1);
        assert_eq!(rx.bulk.len(), 1);

        tx.send(ReceivedPacket::new(
            TransportId::new(1),
            addr,
            vec![0x11; 32],
        ))
        .expect("priority packet should still enter reserve lane");
        assert_eq!(tx.queued_packets(), 2);
        assert_eq!(
            tx.bulk_queued_packets(),
            1,
            "priority packets must not consume bulk packet capacity"
        );

        assert_eq!(rx.recv().await.unwrap().data[0], 0x11);
        assert_eq!(tx.queued_packets(), 1);
        assert_eq!(tx.bulk_queued_packets(), 1);
        assert_eq!(rx.recv().await.unwrap().data[0], 0xaa);
        assert_eq!(tx.queued_packets(), 0);
        assert_eq!(tx.bulk_queued_packets(), 0);
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[tokio::test]
    async fn packet_channel_bounded_bulk_batch_drop_counts_packets_not_items() {
        let (tx, mut rx) = packet_channel(2);
        let addr = TransportAddr::from_string("test");

        tx.send_batch(vec![
            ReceivedPacket::new(
                TransportId::new(1),
                addr.clone(),
                vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
            ),
            ReceivedPacket::new(
                TransportId::new(1),
                addr.clone(),
                vec![0xab; PRIORITY_PACKET_MAX_LEN + 2],
            ),
        ])
        .expect("first bulk batch should fill bounded bulk lane");
        assert_eq!(tx.queued_packets(), 2);
        assert_eq!(tx.bulk_queued_packets(), 2);
        assert_eq!(
            rx.bulk.len(),
            1,
            "batching should still amortize channel items"
        );

        tx.send_batch(vec![
            ReceivedPacket::new(
                TransportId::new(1),
                addr.clone(),
                vec![0xbb; PRIORITY_PACKET_MAX_LEN + 3],
            ),
            ReceivedPacket::new(
                TransportId::new(1),
                addr,
                vec![0xbc; PRIORITY_PACKET_MAX_LEN + 4],
            ),
        ])
        .expect("full bulk packet budget should drop batch overload without closing sender");
        assert_eq!(
            tx.queued_packets(),
            2,
            "dropped bulk batch must roll back every packet it accounted"
        );
        assert_eq!(
            tx.bulk_queued_packets(),
            2,
            "dropped bulk batch must not expand the packet-count backlog"
        );
        assert_eq!(rx.bulk.len(), 1);

        assert_eq!(rx.recv().await.unwrap().data[0], 0xaa);
        assert_eq!(tx.queued_packets(), 0);
        assert_eq!(tx.bulk_queued_packets(), 0);
        assert_eq!(rx.recv().await.unwrap().data[0], 0xab);
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn packet_channel_counts_channel_owned_packet_backlog() {
        let (tx, mut rx) = packet_channel(10);
        let addr = TransportAddr::from_string("test");

        assert_eq!(tx.queued_packets(), 0);
        tx.send_batch(vec![
            ReceivedPacket::new(
                TransportId::new(1),
                addr.clone(),
                vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
            ),
            ReceivedPacket::new(
                TransportId::new(1),
                addr.clone(),
                vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
            ),
            ReceivedPacket::new(
                TransportId::new(1),
                addr.clone(),
                vec![0xcc; PRIORITY_PACKET_MAX_LEN + 3],
            ),
        ])
        .expect("bulk batch send should succeed");
        assert_eq!(tx.queued_packets(), 3);
        assert_eq!(tx.bulk_queued_packets(), 3);

        assert_eq!(rx.try_recv().unwrap().data[0], 0xaa);
        assert_eq!(
            tx.queued_packets(),
            0,
            "once a batch item is dequeued, its tail is rx-loop-owned, not channel-owned"
        );
        assert_eq!(
            tx.bulk_queued_packets(),
            0,
            "bulk capacity is released when the rx loop owns the batch tail"
        );

        tx.send(ReceivedPacket::new(
            TransportId::new(1),
            addr,
            vec![0x11; 32],
        ))
        .expect("priority packet send should succeed");
        assert_eq!(tx.queued_packets(), 1);
        assert_eq!(tx.bulk_queued_packets(), 0);

        assert_eq!(rx.try_recv().unwrap().data[0], 0x11);
        assert_eq!(tx.queued_packets(), 0);
        assert_eq!(tx.bulk_queued_packets(), 0);
        assert_eq!(rx.try_recv().unwrap().data[0], 0xbb);
        assert_eq!(rx.try_recv().unwrap().data[0], 0xcc);
        assert_eq!(tx.queued_packets(), 0);
        assert_eq!(tx.bulk_queued_packets(), 0);
    }

    #[test]
    fn packet_channel_send_failure_rolls_back_backlog() {
        let (tx, rx) = packet_channel(10);
        let addr = TransportAddr::from_string("test");
        drop(rx);

        let packet = ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x11; 32]);
        assert!(tx.send(packet).is_err());
        assert_eq!(tx.queued_packets(), 0);
        assert_eq!(tx.priority_queued_packets(), 0);

        let packets = vec![
            ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x22; 48]),
            ReceivedPacket::new(TransportId::new(1), addr.clone(), vec![0x33; 64]),
        ];
        assert!(tx.send_batch(packets).is_err());
        assert_eq!(tx.queued_packets(), 0);
        assert_eq!(tx.priority_queued_packets(), 0);

        let packets = vec![
            ReceivedPacket::new(
                TransportId::new(1),
                addr.clone(),
                vec![0xaa; PRIORITY_PACKET_MAX_LEN + 1],
            ),
            ReceivedPacket::new(
                TransportId::new(1),
                addr,
                vec![0xbb; PRIORITY_PACKET_MAX_LEN + 2],
            ),
        ];
        assert!(tx.send_batch(packets).is_err());
        assert_eq!(tx.queued_packets(), 0);
        assert_eq!(tx.bulk_queued_packets(), 0);
    }

    // ========================================================================
    // link_mtu tests
    // ========================================================================

    /// Minimal mock transport for testing the default link_mtu() behavior.
    struct MockTransport {
        id: TransportId,
        mtu_value: u16,
    }

    impl MockTransport {
        fn new(mtu: u16) -> Self {
            Self {
                id: TransportId::new(99),
                mtu_value: mtu,
            }
        }
    }

    impl Transport for MockTransport {
        fn transport_id(&self) -> TransportId {
            self.id
        }
        fn transport_type(&self) -> &TransportType {
            &TransportType::UDP
        }
        fn state(&self) -> TransportState {
            TransportState::Up
        }
        fn mtu(&self) -> u16 {
            self.mtu_value
        }
        fn start(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
        fn stop(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
        fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
            Ok(())
        }
        fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
            Ok(vec![])
        }
    }

    /// Mock transport that overrides link_mtu() to return per-link values.
    struct PerLinkMtuTransport {
        id: TransportId,
        default_mtu: u16,
        /// Address-specific MTU overrides.
        overrides: Vec<(TransportAddr, u16)>,
    }

    impl PerLinkMtuTransport {
        fn new(default_mtu: u16, overrides: Vec<(TransportAddr, u16)>) -> Self {
            Self {
                id: TransportId::new(100),
                default_mtu,
                overrides,
            }
        }
    }

    impl Transport for PerLinkMtuTransport {
        fn transport_id(&self) -> TransportId {
            self.id
        }
        fn transport_type(&self) -> &TransportType {
            &TransportType::UDP
        }
        fn state(&self) -> TransportState {
            TransportState::Up
        }
        fn mtu(&self) -> u16 {
            self.default_mtu
        }
        fn link_mtu(&self, addr: &TransportAddr) -> u16 {
            for (a, mtu) in &self.overrides {
                if a == addr {
                    return *mtu;
                }
            }
            self.mtu()
        }
        fn start(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
        fn stop(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
        fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
            Ok(())
        }
        fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_link_mtu_default_falls_back_to_mtu() {
        let transport = MockTransport::new(1280);
        let addr = TransportAddr::from_string("192.168.1.1:2121");

        // Default link_mtu() should return the transport-wide mtu()
        assert_eq!(transport.link_mtu(&addr), 1280);
        assert_eq!(transport.link_mtu(&addr), transport.mtu());

        // Any address should return the same value
        let other_addr = TransportAddr::from_string("10.0.0.1:5000");
        assert_eq!(transport.link_mtu(&other_addr), 1280);
    }

    #[test]
    fn test_link_mtu_per_link_override() {
        let addr_a = TransportAddr::from_string("192.168.1.1:2121");
        let addr_b = TransportAddr::from_string("10.0.0.1:5000");
        let addr_unknown = TransportAddr::from_string("172.16.0.1:6000");

        let transport =
            PerLinkMtuTransport::new(1280, vec![(addr_a.clone(), 512), (addr_b.clone(), 247)]);

        // Known addresses return their per-link MTU
        assert_eq!(transport.link_mtu(&addr_a), 512);
        assert_eq!(transport.link_mtu(&addr_b), 247);

        // Unknown address falls back to transport-wide default
        assert_eq!(transport.link_mtu(&addr_unknown), 1280);
        assert_eq!(transport.mtu(), 1280);
    }

    #[test]
    fn test_transport_handle_link_mtu_delegation() {
        use crate::config::UdpConfig;
        use crate::transport::udp::UdpTransport;

        let config = UdpConfig::default();
        let expected_mtu = config.mtu();
        let (tx, _rx) = packet_channel(1);
        let transport = UdpTransport::new(TransportId::new(1), None, config, tx);
        let handle = TransportHandle::Udp(transport);

        let addr = TransportAddr::from_string("192.168.1.1:2121");

        // TransportHandle::link_mtu() should delegate and return the same
        // as TransportHandle::mtu() for UDP (no per-link overrides)
        assert_eq!(handle.link_mtu(&addr), expected_mtu);
        assert_eq!(handle.link_mtu(&addr), handle.mtu());
    }
}
