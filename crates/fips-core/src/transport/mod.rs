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

mod handle;
mod packet_channel;

#[cfg(test)]
mod tests;

pub use handle::TransportHandle;
pub(crate) use packet_channel::PacketFastIngressSink;
pub use packet_channel::{PacketBuffer, PacketRx, PacketTx, ReceivedPacket, packet_channel};

use secp256k1::XOnlyPublicKey;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

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
            | std::io::ErrorKind::PermissionDenied
    )
}

fn is_local_route_error_text(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("network is unreachable")
        || lower.contains("no route to host")
        || lower.contains("host is unreachable")
        || lower.contains("can't assign requested address")
        || lower.contains("cannot assign requested address")
        || lower.contains("operation not permitted")
        || lower.contains("permission denied")
        || lower.contains("os error 51")
        || lower.contains("os error 65")
        || lower.contains("os error 49")
        || lower.contains("os error 1")
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

    /// Create a transport address from a `SocketAddr` without libc
    /// address formatting. UDP receive caches this per peer, but cache
    /// misses still sit on the hot task, so keep the common IPv4 path
    /// as plain decimal byte writes.
    pub fn from_socket_addr(addr: std::net::SocketAddr) -> Self {
        match addr {
            std::net::SocketAddr::V4(addr) => {
                let octets = addr.ip().octets();
                let mut buf = Vec::with_capacity(21);
                push_decimal_u8(&mut buf, octets[0]);
                buf.push(b'.');
                push_decimal_u8(&mut buf, octets[1]);
                buf.push(b'.');
                push_decimal_u8(&mut buf, octets[2]);
                buf.push(b'.');
                push_decimal_u8(&mut buf, octets[3]);
                buf.push(b':');
                push_decimal_u16(&mut buf, addr.port());
                Self(buf.into())
            }
            std::net::SocketAddr::V6(addr) => {
                use std::io::Write;
                let mut buf = Vec::with_capacity(56);
                buf.push(b'[');
                write!(&mut buf, "{}", addr.ip()).expect("Vec<u8>::write_fmt is infallible");
                buf.push(b']');
                buf.push(b':');
                push_decimal_u16(&mut buf, addr.port());
                Self(buf.into())
            }
        }
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

fn push_decimal_u8(buf: &mut Vec<u8>, value: u8) {
    push_decimal_u16(buf, value as u16);
}

fn push_decimal_u16(buf: &mut Vec<u8>, value: u16) {
    if value >= 10_000 {
        buf.push(b'0' + (value / 10_000) as u8);
        push_fixed_4_digits(buf, value % 10_000);
    } else if value >= 1_000 {
        push_fixed_4_digits(buf, value);
    } else if value >= 100 {
        buf.push(b'0' + (value / 100) as u8);
        push_fixed_2_digits(buf, value % 100);
    } else if value >= 10 {
        push_fixed_2_digits(buf, value);
    } else {
        buf.push(b'0' + value as u8);
    }
}

fn push_fixed_4_digits(buf: &mut Vec<u8>, value: u16) {
    buf.push(b'0' + (value / 1_000) as u8);
    push_fixed_3_digits(buf, value % 1_000);
}

fn push_fixed_3_digits(buf: &mut Vec<u8>, value: u16) {
    buf.push(b'0' + (value / 100) as u8);
    push_fixed_2_digits(buf, value % 100);
}

fn push_fixed_2_digits(buf: &mut Vec<u8>, value: u16) {
    buf.push(b'0' + (value / 10) as u8);
    buf.push(b'0' + (value % 10) as u8);
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

    /// Record multiple sent packets.
    pub fn record_sent_batch(&mut self, packets: usize, bytes: usize) {
        self.packets_sent += packets as u64;
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
    /// Cumulative packets dropped by this transport socket before userspace
    /// receive, when the platform exposes a socket-local counter.
    pub socket_recv_drops: Option<u64>,
    /// Cumulative Linux namespace UDP receive-buffer errors since transport
    /// start. This is broader than one socket, so callers should report it
    /// separately from socket-local drops.
    pub namespace_recv_drops: Option<u64>,
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
