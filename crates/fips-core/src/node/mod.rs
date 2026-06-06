//! FIPS Node Entity
//!
//! Top-level structure representing a running FIPS instance. The Node
//! holds all state required for mesh routing: identity, tree state,
//! Bloom filters, coordinate caches, transports, links, and peers.

mod acl;
mod bloom;
mod decrypt_worker;
mod discovery_rate_limit;
mod encrypt_worker;
mod handlers;
mod lifecycle;
mod rate_limit;
mod retry;
mod routing;
mod routing_error_rate_limit;
pub(crate) mod session;
pub(crate) mod session_wire;
pub(crate) mod stats;
pub(crate) mod stats_history;
#[cfg(test)]
mod tests;
mod tree;
pub(crate) mod wire;

use self::discovery_rate_limit::{DiscoveryBackoff, DiscoveryForwardRateLimiter};
use self::rate_limit::HandshakeRateLimiter;
use self::routing::{LearnedRouteTable, LearnedRouteTableSnapshot};
use self::routing_error_rate_limit::RoutingErrorRateLimiter;
#[cfg(unix)]
use self::wire::ESTABLISHED_HEADER_SIZE;
use self::wire::{
    FLAG_CE, FLAG_KEY_EPOCH, FLAG_SP, build_encrypted, build_established_header,
    prepend_inner_header,
};
use crate::bloom::BloomState;
use crate::cache::CoordCache;
use crate::config::{NostrDiscoveryPolicy, PeerConfig, RoutingMode};
use crate::node::session::SessionEntry;
use crate::node::session_wire::{FSP_PHASE_ESTABLISHED, FspCommonPrefix};
use crate::peer::{ActivePeer, PeerConnection};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::transport::ethernet::EthernetTransport;
use crate::transport::tcp::TcpTransport;
use crate::transport::tor::TorTransport;
use crate::transport::udp::UdpTransport;
#[cfg(feature = "webrtc-transport")]
use crate::transport::webrtc::WebRtcTransport;
use crate::transport::{
    ConnectionState, Link, LinkId, PacketRx, PacketTx, TransportAddr, TransportError,
    TransportHandle, TransportId,
};
use crate::tree::TreeState;
use crate::upper::hosts::HostMap;
use crate::upper::icmp_rate_limit::IcmpRateLimiter;
use crate::upper::tun::{TunError, TunOutboundRx, TunState, TunTx};
use crate::utils::index::IndexAllocator;
use crate::{
    Config, ConfigError, FipsAddress, Identity, IdentityError, LinkMessageType, NodeAddr,
    PeerIdentity, encode_npub,
};
use rand::Rng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::thread::JoinHandle;
use thiserror::Error;
use tracing::{debug, warn};

const LOCAL_SEND_FAILURE_FAST_DEAD_WINDOW: std::time::Duration = std::time::Duration::from_secs(3);
const SESSION_DIRECT_DEGRADED_HOLD_MS: u64 = 20_000;
const SESSION_DIRECT_DEGRADED_MIN_SAMPLE: u64 = 16;
const SESSION_DIRECT_DEGRADED_LOSS_THRESHOLD: f64 = 0.08;
const SESSION_DIRECT_RECOVERY_LOSS_THRESHOLD: f64 = 0.02;
const ROUTING_FALLBACK_MIN_COST_ADVANTAGE: f64 = 0.25;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FmpPlaintextTrafficClass {
    bulk_endpoint_data: bool,
    drop_on_backpressure: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct EndpointPayloadTrafficClass {
    bulk_endpoint_data: bool,
    drop_on_backpressure: bool,
}

fn classify_fmp_plaintext_traffic(plaintext: &[u8]) -> FmpPlaintextTrafficClass {
    let bulk_endpoint_data = fmp_plaintext_is_bulk_session_datagram(plaintext);
    // At this layer established FSP payloads are already end-to-end encrypted,
    // so a bulk SessionDatagram may still be TCP endpoint traffic. Keep it out
    // of the control lane, but only the pre-FSP endpoint path may mark known
    // non-TCP packets as discardable under sender backpressure.
    FmpPlaintextTrafficClass {
        bulk_endpoint_data,
        drop_on_backpressure: false,
    }
}

fn fmp_plaintext_is_bulk_session_datagram(plaintext: &[u8]) -> bool {
    if plaintext
        .first()
        .is_none_or(|ty| *ty != LinkMessageType::SessionDatagram.to_byte())
    {
        return false;
    }
    let Some(fsp_payload) = plaintext.get(crate::protocol::SESSION_DATAGRAM_HEADER_SIZE..) else {
        return false;
    };
    FspCommonPrefix::parse(fsp_payload).is_some_and(|prefix| {
        prefix.phase == FSP_PHASE_ESTABLISHED && !prefix.is_unencrypted() && !prefix.has_coords()
    })
}

fn classify_endpoint_payload(payload: &[u8]) -> EndpointPayloadTrafficClass {
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_ICMPV6: u8 = 58;

    match parse_endpoint_payload_ip_proto(payload) {
        Some((IPPROTO_ICMPV6, _)) => EndpointPayloadTrafficClass::default(),
        Some((IPPROTO_TCP, offset)) => {
            let latency_sensitive = endpoint_tcp_payload_is_latency_sensitive(payload, offset);
            EndpointPayloadTrafficClass {
                bulk_endpoint_data: !latency_sensitive,
                drop_on_backpressure: false,
            }
        }
        _ => EndpointPayloadTrafficClass {
            bulk_endpoint_data: true,
            drop_on_backpressure: true,
        },
    }
}

fn endpoint_tcp_payload_is_latency_sensitive(payload: &[u8], tcp_offset: usize) -> bool {
    const TCP_MIN_HEADER_LEN: usize = 20;
    const TCP_FLAG_FIN: u8 = 0x01;
    const TCP_FLAG_SYN: u8 = 0x02;
    const TCP_FLAG_RST: u8 = 0x04;
    const INTERACTIVE_TCP_PAYLOAD_MAX: usize = 256;

    if payload.len() < tcp_offset + TCP_MIN_HEADER_LEN {
        return true;
    }

    let tcp_header_len = usize::from(payload[tcp_offset + 12] >> 4) * 4;
    if tcp_header_len < TCP_MIN_HEADER_LEN || payload.len() < tcp_offset + tcp_header_len {
        return true;
    }

    let flags = payload[tcp_offset + 13];
    if flags & (TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST) != 0 {
        return true;
    }

    let payload_len = endpoint_ip_payload_len(payload)
        .and_then(|ip_payload_len| ip_payload_len.checked_sub(tcp_header_len))
        .unwrap_or_else(|| payload.len().saturating_sub(tcp_offset + tcp_header_len));
    payload_len <= INTERACTIVE_TCP_PAYLOAD_MAX
}

fn endpoint_ip_payload_len(payload: &[u8]) -> Option<usize> {
    const IPV4_MIN_HEADER_LEN: usize = 20;
    const IPV6_HEADER_LEN: usize = 40;

    let version_ihl = payload.first().copied()?;
    match version_ihl >> 4 {
        4 => {
            if payload.len() < IPV4_MIN_HEADER_LEN {
                return None;
            }
            let header_len = usize::from(version_ihl & 0x0f) * 4;
            if header_len < IPV4_MIN_HEADER_LEN || payload.len() < header_len {
                return None;
            }
            let total_len = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
            total_len.checked_sub(header_len)
        }
        6 => {
            if payload.len() < IPV6_HEADER_LEN {
                return None;
            }
            Some(usize::from(u16::from_be_bytes([payload[4], payload[5]])))
        }
        _ => None,
    }
}

fn parse_endpoint_payload_ip_proto(payload: &[u8]) -> Option<(u8, usize)> {
    const IPV4_MIN_HEADER_LEN: usize = 20;

    let version_ihl = payload.first().copied()?;

    match version_ihl >> 4 {
        4 => {
            if payload.len() < IPV4_MIN_HEADER_LEN {
                return None;
            }
            let header_len = usize::from(version_ihl & 0x0f) * 4;
            if header_len >= IPV4_MIN_HEADER_LEN && payload.len() >= header_len {
                Some((payload[9], header_len))
            } else {
                None
            }
        }
        6 => ipv6_payload_next_header(payload),
        _ => None,
    }
}

#[cfg(test)]
fn endpoint_payload_is_tcp(payload: &[u8]) -> bool {
    const IPPROTO_TCP: u8 = 6;
    parse_endpoint_payload_ip_proto(payload).is_some_and(|(proto, _)| proto == IPPROTO_TCP)
}

fn ipv6_payload_next_header(payload: &[u8]) -> Option<(u8, usize)> {
    const IPV6_HEADER_LEN: usize = 40;
    const IPV6_FRAGMENT_HEADER_LEN: usize = 8;

    if payload.len() < IPV6_HEADER_LEN || payload[0] >> 4 != 6 {
        return None;
    }

    let mut next_header = payload[6];
    let mut offset = IPV6_HEADER_LEN;
    let mut extension_count = 0usize;
    while ipv6_extension_header_is_skippable(next_header) {
        if next_header == 44 {
            if payload.len() < offset + IPV6_FRAGMENT_HEADER_LEN {
                return None;
            }
            next_header = payload[offset];
            offset += IPV6_FRAGMENT_HEADER_LEN;
        } else if next_header == 51 {
            if payload.len() < offset + 2 {
                return None;
            }
            let header_len = (usize::from(payload[offset + 1]) + 2) * 4;
            if payload.len() < offset + header_len {
                return None;
            }
            next_header = payload[offset];
            offset += header_len;
        } else {
            if payload.len() < offset + 2 {
                return None;
            }
            let header_len = (usize::from(payload[offset + 1]) + 1) * 8;
            if payload.len() < offset + header_len {
                return None;
            }
            next_header = payload[offset];
            offset += header_len;
        }
        extension_count += 1;
        if extension_count > 8 {
            return None;
        }
    }

    Some((next_header, offset))
}

fn ipv6_extension_header_is_skippable(next_header: u8) -> bool {
    matches!(next_header, 0 | 43 | 44 | 51 | 60 | 135)
}

/// Half-range of the symmetric jitter applied to per-session rekey timers.
///
/// Each FMP/FSP session draws an offset uniformly from
/// `[-REKEY_JITTER_SECS, +REKEY_JITTER_SECS]` seconds at construction and
/// after each cutover. This preserves the configured mean interval while
/// reducing dual-initiation bursts in symmetric-start meshes.
pub(crate) const REKEY_JITTER_SECS: i64 = 15;

/// Errors related to node operations.
#[derive(Debug, Error)]
pub enum NodeError {
    #[error("node not started")]
    NotStarted,

    #[error("node already started")]
    AlreadyStarted,

    #[error("node already stopped")]
    AlreadyStopped,

    #[error("transport not found: {0}")]
    TransportNotFound(TransportId),

    #[error("no transport available for type: {0}")]
    NoTransportForType(String),

    #[error("link not found: {0}")]
    LinkNotFound(LinkId),

    #[error("connection not found: {0}")]
    ConnectionNotFound(LinkId),

    #[error("peer not found: {0:?}")]
    PeerNotFound(NodeAddr),

    #[error("peer already exists: {0:?}")]
    PeerAlreadyExists(NodeAddr),

    #[error("connection already exists for link: {0}")]
    ConnectionAlreadyExists(LinkId),

    #[error("invalid peer npub '{npub}': {reason}")]
    InvalidPeerNpub { npub: String, reason: String },

    #[error("discovery error: {0}")]
    Discovery(String),

    #[error("access denied: {0}")]
    AccessDenied(String),

    #[error("max connections exceeded: {max}")]
    MaxConnectionsExceeded { max: usize },

    #[error("max peers exceeded: {max}")]
    MaxPeersExceeded { max: usize },

    #[error("max links exceeded: {max}")]
    MaxLinksExceeded { max: usize },

    #[error("handshake incomplete for link {0}")]
    HandshakeIncomplete(LinkId),

    #[error("no session available for link {0}")]
    NoSession(LinkId),

    #[error("promotion failed for link {link_id}: {reason}")]
    PromotionFailed { link_id: LinkId, reason: String },

    #[error("send failed to {node_addr}: {reason}")]
    SendFailed { node_addr: NodeAddr, reason: String },

    #[error("mtu exceeded forwarding to {node_addr}: packet {packet_size} > mtu {mtu}")]
    MtuExceeded {
        node_addr: NodeAddr,
        packet_size: usize,
        mtu: u16,
    },

    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),

    #[error("TUN error: {0}")]
    Tun(#[from] TunError),

    #[error("index allocation failed: {0}")]
    IndexAllocationFailed(String),

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("transport error: {0}")]
    TransportError(String),

    #[error("local route unavailable: {0}")]
    LocalRouteUnavailable(String),

    #[error("bootstrap handoff failed: {0}")]
    BootstrapHandoff(String),
}

impl NodeError {
    pub(in crate::node) fn from_transport_error(error: TransportError) -> Self {
        if error.is_local_route_unavailable() {
            Self::LocalRouteUnavailable(error.to_string())
        } else {
            Self::TransportError(error.to_string())
        }
    }

    pub(in crate::node) fn is_local_route_unavailable(&self) -> bool {
        matches!(self, Self::LocalRouteUnavailable(_))
    }
}

/// Source-attributed packet delivered by a node running without a system TUN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDeliveredPacket {
    /// FIPS node address that originated the packet.
    pub source_node_addr: NodeAddr,
    /// Source Nostr public key when the node has learned it.
    pub source_npub: Option<String>,
    /// Destination FIPS address from the IPv6 packet.
    pub destination: FipsAddress,
    /// Full IPv6 packet after FIPS session decapsulation.
    pub packet: Vec<u8>,
}

#[derive(Debug, Clone)]
struct IdentityCacheEntry {
    node_addr: NodeAddr,
    pubkey: secp256k1::PublicKey,
    npub: String,
    last_seen_ms: u64,
}

impl IdentityCacheEntry {
    fn new(
        node_addr: NodeAddr,
        pubkey: secp256k1::PublicKey,
        npub: String,
        last_seen_ms: u64,
    ) -> Self {
        Self {
            node_addr,
            pubkey,
            npub,
            last_seen_ms,
        }
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
    /// Send endpoint data commands into the node RX loop.
    ///
    /// Bounded with a generous default so normal sender bursts do not
    /// stall on semaphore acquisition. macOS pacing happens at the UDP
    /// egress thread where the real Wi-Fi/interface bottleneck is visible;
    /// constraining this app queue instead caused the inner TCP flow to
    /// collapse under iperf. `FIPS_ENDPOINT_DATA_QUEUE_CAP` overrides the
    /// default for benches.
    pub(crate) command_tx: tokio::sync::mpsc::Sender<NodeEndpointCommand>,
    /// Receive endpoint data delivered by FIPS sessions.
    ///
    /// Unbounded so the rx_loop's send on inbound packet delivery is a
    /// wait-free push (no semaphore acquire), and so we can drop the
    /// per-packet cross-task relay that previously sat between the node
    /// task and the `FipsEndpoint::recv()` consumer. Backpressure is
    /// naturally bounded — the rx_loop both produces here and runs the
    /// same runtime that schedules the consumer, so a stalled consumer
    /// stalls production too.
    pub(crate) event_rx: tokio::sync::mpsc::UnboundedReceiver<NodeEndpointEvent>,
    /// Clone of the event_tx exposed for in-process loopback (e.g.
    /// `FipsEndpoint::send` to self_npub). Lets the endpoint inject an
    /// event into the same queue without going through the encrypt /
    /// decrypt path, while keeping every consumer reading from a single
    /// channel.
    pub(crate) event_tx: tokio::sync::mpsc::UnboundedSender<NodeEndpointEvent>,
}

fn endpoint_data_command_capacity(requested: usize) -> usize {
    if let Ok(raw) = std::env::var("FIPS_ENDPOINT_DATA_QUEUE_CAP")
        && let Ok(value) = raw.trim().parse::<usize>()
        && value > 0
    {
        return value;
    }

    requested.max(1).max(32_768)
}

/// Commands accepted by the node endpoint data service.
#[derive(Debug)]
pub(crate) enum NodeEndpointCommand {
    /// Send with an explicit response channel — used by callers that
    /// care whether the local-stack handoff succeeded (e.g.
    /// `blocking_send` waits for the runtime to accept the send).
    Send {
        remote: PeerIdentity,
        payload: Vec<u8>,
        queued_at: Option<std::time::Instant>,
        response_tx: tokio::sync::oneshot::Sender<Result<(), NodeError>>,
    },
    /// **Fire-and-forget** variant of `Send` — no oneshot allocation,
    /// no per-packet result channel. Used by the data-plane fast path
    /// (`FipsEndpoint::send`) where the caller already discards the
    /// result. Saves one oneshot::channel() allocation per outbound
    /// packet on the application's send hot path.
    SendOneway {
        remote: PeerIdentity,
        payload: Vec<u8>,
        queued_at: Option<std::time::Instant>,
    },
    PeerSnapshot {
        response_tx: tokio::sync::oneshot::Sender<Vec<NodeEndpointPeer>>,
    },
    RelaySnapshot {
        response_tx: tokio::sync::oneshot::Sender<Vec<NodeEndpointRelayStatus>>,
    },
    UpdateRelays {
        advert_relays: Vec<String>,
        dm_relays: Vec<String>,
        response_tx: tokio::sync::oneshot::Sender<Result<(), NodeError>>,
    },
    /// Replace the runtime peer list. Newly added auto-connect peers get
    /// `initiate_peer_connection` immediately; removed peers are dropped
    /// from the retry queue (the regular liveness timeout reaps any active
    /// session). Existing entries are kept and their `addresses` field is
    /// refreshed so the next retry sees the latest hints.
    UpdatePeers {
        peers: Vec<crate::config::PeerConfig>,
        response_tx: tokio::sync::oneshot::Sender<Result<UpdatePeersOutcome, NodeError>>,
    },
}

/// Reports what changed in response to `UpdatePeers`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UpdatePeersOutcome {
    pub(crate) added: usize,
    pub(crate) removed: usize,
    pub(crate) updated: usize,
    pub(crate) unchanged: usize,
}

/// Endpoint data events emitted by the node session receive path.
#[derive(Debug)]
pub(crate) enum NodeEndpointEvent {
    Data {
        source_node_addr: NodeAddr,
        source_npub: Option<String>,
        payload: Vec<u8>,
        queued_at: Option<std::time::Instant>,
    },
}

/// Authenticated peer state exposed to embedded endpoint callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeEndpointPeer {
    pub(crate) npub: String,
    pub(crate) connected: bool,
    pub(crate) transport_addr: Option<String>,
    pub(crate) transport_type: Option<String>,
    pub(crate) link_id: u64,
    pub(crate) srtt_ms: Option<u64>,
    pub(crate) packets_sent: u64,
    pub(crate) packets_recv: u64,
    pub(crate) bytes_sent: u64,
    pub(crate) bytes_recv: u64,
    pub(crate) direct_probe_pending: bool,
    pub(crate) direct_probe_after_ms: Option<u64>,
}

/// Live Nostr relay state exposed to embedded endpoint callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeEndpointRelayStatus {
    pub(crate) url: String,
    pub(crate) status: String,
}

/// Node operational state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeState {
    /// Created but not started.
    Created,
    /// Starting up (initializing transports).
    Starting,
    /// Fully operational.
    Running,
    /// Shutting down.
    Stopping,
    /// Stopped.
    Stopped,
}

impl NodeState {
    /// Check if node is operational.
    pub fn is_operational(&self) -> bool {
        matches!(self, NodeState::Running)
    }

    /// Check if node can be started.
    pub fn can_start(&self) -> bool {
        matches!(self, NodeState::Created | NodeState::Stopped)
    }

    /// Check if node can be stopped.
    pub fn can_stop(&self) -> bool {
        matches!(self, NodeState::Running)
    }
}

impl fmt::Display for NodeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            NodeState::Created => "created",
            NodeState::Starting => "starting",
            NodeState::Running => "running",
            NodeState::Stopping => "stopping",
            NodeState::Stopped => "stopped",
        };
        write!(f, "{}", s)
    }
}

/// Recent request tracking for dedup and reverse-path forwarding.
///
/// When a LookupRequest is forwarded through a node, the node stores the
/// request_id and which peer sent it. When the corresponding LookupResponse
/// arrives, it's forwarded back to that peer (reverse-path forwarding).
/// The `response_forwarded` flag prevents response routing loops.
#[derive(Clone, Debug)]
pub(crate) struct RecentRequest {
    /// The peer who sent this request to us.
    pub(crate) from_peer: NodeAddr,
    /// When we received this request (Unix milliseconds).
    pub(crate) timestamp_ms: u64,
    /// Whether we've already forwarded a response for this request.
    /// Prevents response routing loops when convergent request paths
    /// create bidirectional entries in recent_requests.
    pub(crate) response_forwarded: bool,
}

impl RecentRequest {
    pub(crate) fn new(from_peer: NodeAddr, timestamp_ms: u64) -> Self {
        Self {
            from_peer,
            timestamp_ms,
            response_forwarded: false,
        }
    }

    /// Check if this entry has expired (older than expiry_ms).
    pub(crate) fn is_expired(&self, current_time_ms: u64, expiry_ms: u64) -> bool {
        current_time_ms.saturating_sub(self.timestamp_ms) > expiry_ms
    }
}

/// Key for addr_to_link reverse lookup.
type AddrKey = (TransportId, TransportAddr);

/// Per-transport kernel drop tracking for congestion detection.
///
/// Sampled every tick (1s). The `dropping` flag indicates whether new
/// kernel drops were observed since the previous sample.
#[derive(Debug, Default)]
struct TransportDropState {
    /// Previous `recv_drops` sample (cumulative counter).
    prev_drops: u64,
    /// True if drops increased since the last sample.
    dropping: bool,
}

/// State for a link waiting for transport-level connection establishment.
///
/// For connection-oriented transports (TCP, Tor), the transport connect runs
/// asynchronously. This struct holds the data needed to complete the handshake
/// once the connection is ready.
struct PendingConnect {
    /// The link that was created for this connection.
    link_id: LinkId,
    /// Which transport is being used.
    transport_id: TransportId,
    /// The remote address being connected to.
    remote_addr: TransportAddr,
    /// The peer identity (for handshake initiation).
    peer_identity: PeerIdentity,
}

/// A running FIPS node instance.
///
/// This is the top-level container holding all node state.
///
/// ## Peer Lifecycle
///
/// Peers go through two phases:
/// 1. **Connection phase** (`connections`): Handshake in progress, indexed by LinkId
/// 2. **Active phase** (`peers`): Authenticated, indexed by NodeAddr
///
/// The `addr_to_link` map enables dispatching incoming packets to the right
/// connection before authentication completes.
// Discovery lookup constants moved to config: node.discovery.attempt_timeouts_secs, node.discovery.ttl
pub struct Node {
    // === Identity ===
    /// This node's cryptographic identity.
    identity: Identity,

    /// Random epoch generated at startup for peer restart detection.
    /// Exchanged inside Noise handshake messages so peers can detect restarts.
    startup_epoch: [u8; 8],

    /// Instant when the node was created, for uptime reporting.
    started_at: std::time::Instant,

    // === Configuration ===
    /// Loaded configuration.
    config: Config,

    // === State ===
    /// Node operational state.
    state: NodeState,

    /// Whether this is a leaf-only node.
    is_leaf_only: bool,

    // === Spanning Tree ===
    /// Local spanning tree state.
    tree_state: TreeState,

    // === Bloom Filter ===
    /// Local Bloom filter state.
    bloom_state: BloomState,

    // === Routing ===
    /// Address -> coordinates cache (from session setup and discovery).
    coord_cache: CoordCache,
    /// Locally learned reverse-path next-hop hints.
    learned_routes: LearnedRouteTable,
    /// Destinations whose direct first-hop path is temporarily suspect because
    /// session-layer MMP observed sustained loss while using that direct path.
    session_direct_degraded_until_ms: HashMap<NodeAddr, u64>,
    /// Recent discovery requests (dedup + reverse-path forwarding).
    /// Maps request_id → RecentRequest.
    recent_requests: HashMap<u64, RecentRequest>,
    /// Per-destination path MTU lookup, keyed by FipsAddress (mirrors
    /// `coord_cache.entries[*].path_mtu`). Sync read-only access from
    /// the TUN reader/writer threads at TCP MSS clamp time so the
    /// SYN/SYN-ACK clamp can use the smaller of the local-egress floor
    /// and the learned per-destination path MTU.
    path_mtu_lookup: Arc<std::sync::RwLock<HashMap<crate::FipsAddress, u16>>>,

    // === Transports & Links ===
    /// Active transports (owned by Node).
    transports: HashMap<TransportId, TransportHandle>,
    /// Per-transport kernel drop tracking for congestion detection.
    transport_drops: HashMap<TransportId, TransportDropState>,
    /// Active links.
    links: HashMap<LinkId, Link>,
    /// Reverse lookup: (transport_id, remote_addr) -> link_id.
    addr_to_link: HashMap<AddrKey, LinkId>,

    // === Packet Channel ===
    /// Packet sender for transports.
    packet_tx: Option<PacketTx>,
    /// Packet receiver (for event loop).
    packet_rx: Option<PacketRx>,

    // === Connections (Handshake Phase) ===
    /// Pending connections (handshake in progress).
    /// Indexed by LinkId since we don't know the peer's identity yet.
    connections: HashMap<LinkId, PeerConnection>,

    // === Peers (Active Phase) ===
    /// Authenticated peers.
    /// Indexed by NodeAddr (verified identity).
    peers: HashMap<NodeAddr, ActivePeer>,

    // === End-to-End Sessions ===
    /// Session table for end-to-end encrypted sessions.
    /// Keyed by remote NodeAddr.
    sessions: HashMap<NodeAddr, SessionEntry>,

    // === Identity Cache ===
    /// Maps FipsAddress prefix bytes (bytes 1-15) to cached peer identity data.
    /// Enables reverse lookup from IPv6 destination to session/routing identity.
    identity_cache: HashMap<[u8; 15], IdentityCacheEntry>,

    // === Pending TUN Packets ===
    /// Packets queued while waiting for session establishment.
    /// Keyed by destination NodeAddr, bounded per-dest and total.
    pending_tun_packets: HashMap<NodeAddr, VecDeque<Vec<u8>>>,
    /// Endpoint data payloads queued while waiting for session establishment.
    pending_endpoint_data: HashMap<NodeAddr, VecDeque<Vec<u8>>>,
    // === Pending Discovery Lookups ===
    /// Tracks in-flight discovery lookups. Maps target NodeAddr to the
    /// initiation timestamp (Unix ms). Prevents duplicate flood queries.
    pending_lookups: HashMap<NodeAddr, handlers::discovery::PendingLookup>,

    // === Resource Limits ===
    /// Maximum connections (0 = unlimited).
    max_connections: usize,
    /// Maximum peers (0 = unlimited).
    max_peers: usize,
    /// Maximum links (0 = unlimited).
    max_links: usize,

    // === Counters ===
    /// Next link ID to allocate.
    next_link_id: u64,
    /// Next transport ID to allocate.
    next_transport_id: u32,

    // === Node Statistics ===
    /// Routing, forwarding, discovery, and error signal counters.
    stats: stats::NodeStats,

    /// Time-series history of node-level metrics (1s/1m rings).
    stats_history: stats_history::StatsHistory,

    // === TUN Interface ===
    /// TUN device state.
    tun_state: TunState,
    /// TUN interface name (for cleanup).
    tun_name: Option<String>,
    /// TUN packet sender channel.
    tun_tx: Option<TunTx>,
    /// Receiver for outbound packets from the TUN reader.
    tun_outbound_rx: Option<TunOutboundRx>,
    /// App-owned packet sink used by embedded/no-TUN integrations.
    external_packet_tx: Option<tokio::sync::mpsc::Sender<NodeDeliveredPacket>>,
    /// Endpoint data command receiver used by embedded/no-daemon integrations.
    endpoint_command_rx: Option<tokio::sync::mpsc::Receiver<NodeEndpointCommand>>,
    /// Endpoint data event sink used by embedded/no-daemon integrations.
    endpoint_event_tx: Option<tokio::sync::mpsc::UnboundedSender<NodeEndpointEvent>>,
    /// Off-task FMP-encrypt + UDP-send worker pool. `None` if not yet
    /// spawned (set up in `start()` once transports are running).
    /// `Some(pool)` once available; the pool internally holds
    /// per-worker mpsc senders and round-robins jobs across them.
    /// See `node::encrypt_worker` for the rationale and layout.
    encrypt_workers: Option<encrypt_worker::EncryptWorkerPool>,
    /// Off-task FMP + FSP decrypt + delivery worker pool. Mirror of
    /// `encrypt_workers` for the receive side.
    decrypt_workers: Option<decrypt_worker::DecryptWorkerPool>,
    /// Set of sessions that have been registered with the decrypt
    /// shard worker pool. Used by rx_loop to decide between fast-path
    /// dispatch (worker owns the session) and legacy in-place decrypt
    /// (worker doesn't have it yet). Per the data-plane restructure,
    /// the worker owns its session state directly — there's no shared
    /// `Arc<RwLock<HashMap>>` of cipher / replay state anymore, only
    /// this set tracks **whether** the worker has been told about a
    /// given session.
    decrypt_registered_sessions: std::collections::HashSet<(TransportId, u32)>,
    /// Fallback channel: decrypt worker bounces non-fast-path packets
    /// (anything that's not bulk EndpointData) back here for rx_loop
    /// to handle via the legacy path. Drained by a new rx_loop arm.
    decrypt_fallback_rx:
        Option<tokio::sync::mpsc::UnboundedReceiver<decrypt_worker::DecryptWorkerEvent>>,
    decrypt_fallback_tx: tokio::sync::mpsc::UnboundedSender<decrypt_worker::DecryptWorkerEvent>,
    /// TUN reader thread handle.
    tun_reader_handle: Option<JoinHandle<()>>,
    /// TUN writer thread handle.
    tun_writer_handle: Option<JoinHandle<()>>,
    /// Shutdown pipe: writing to this fd unblocks the TUN reader thread on macOS.
    /// On Linux, deleting the interface via netlink serves the same purpose.
    #[cfg(target_os = "macos")]
    tun_shutdown_fd: Option<std::os::unix::io::RawFd>,

    // === DNS Responder ===
    /// Receiver for resolved identities from the DNS responder.
    dns_identity_rx: Option<crate::upper::dns::DnsIdentityRx>,
    /// DNS responder task handle.
    dns_task: Option<tokio::task::JoinHandle<()>>,

    // === Index-Based Session Dispatch ===
    /// Allocator for session indices.
    index_allocator: IndexAllocator,
    /// O(1) lookup: (transport_id, our_index) → NodeAddr.
    /// This maps our session index to the peer that uses it.
    peers_by_index: HashMap<(TransportId, u32), NodeAddr>,
    /// Pending outbound handshakes by our sender_idx.
    /// Tracks which LinkId corresponds to which session index.
    pending_outbound: HashMap<(TransportId, u32), LinkId>,

    // === Rate Limiting ===
    /// Rate limiter for msg1 processing (DoS protection).
    msg1_rate_limiter: HandshakeRateLimiter,
    /// Rate limiter for ICMP Packet Too Big messages.
    icmp_rate_limiter: IcmpRateLimiter,
    /// Rate limiter for routing error signals (CoordsRequired / PathBroken).
    routing_error_rate_limiter: RoutingErrorRateLimiter,
    /// Rate limiter for source-side CoordsRequired/PathBroken responses.
    coords_response_rate_limiter: RoutingErrorRateLimiter,
    /// Backoff for failed discovery lookups (originator-side).
    discovery_backoff: DiscoveryBackoff,
    /// Rate limiter for forwarded discovery requests (transit-side).
    discovery_forward_limiter: DiscoveryForwardRateLimiter,

    // === Pending Transport Connects ===
    /// Links waiting for transport-level connection establishment before
    /// sending handshake msg1. For connection-oriented transports (TCP, Tor),
    /// the transport connect runs in the background; the tick handler polls
    /// connection_state() and initiates the handshake when connected.
    pending_connects: Vec<PendingConnect>,

    // === Connection Retry ===
    /// Retry state for peers whose outbound connections have failed.
    /// Keyed by NodeAddr. Entries are created when a handshake times out
    /// or fails, and removed on successful promotion or when max retries
    /// are exhausted.
    retry_pending: HashMap<NodeAddr, retry::RetryState>,

    /// Optional Nostr/STUN overlay discovery coordinator for `udp:nat` peers.
    nostr_discovery: Option<Arc<crate::discovery::nostr::NostrDiscovery>>,
    /// mDNS / DNS-SD responder + browser for local-link peer discovery.
    /// Identity is unverified at this layer — the Noise XX handshake
    /// initiated against an mDNS-observed endpoint is what proves the
    /// peer holds the matching private key.
    lan_discovery: Option<Arc<crate::discovery::lan::LanDiscovery>>,
    /// Same-host JSON registry under `~/.fips/instances`. Records are
    /// loopback routing hints only; peer identity is still verified by the
    /// Noise handshake.
    local_instance_registry: Option<crate::discovery::local::LocalInstanceRegistry>,
    local_instance_started_at_ms: Option<u64>,
    last_local_instance_publish_ms: Option<u64>,
    last_local_instance_scan_ms: Option<u64>,
    /// Wall-clock ms when Nostr discovery successfully started, used to
    /// schedule the one-shot startup advert sweep after a settle delay.
    /// `None` until discovery comes up; remains `None` if discovery is
    /// disabled or failed to start.
    nostr_discovery_started_at_ms: Option<u64>,
    /// Whether the one-shot startup advert sweep has run. Set to true
    /// after the first sweep fires (under `policy: open`); thereafter
    /// only the per-tick `queue_open_discovery_retries` continues.
    startup_open_discovery_sweep_done: bool,
    /// Per-peer UDP transports adopted from NAT traversal handoff.
    bootstrap_transports: HashSet<TransportId>,
    /// Originating peer npub (bech32) for each adopted bootstrap
    /// transport, captured at `adopt_established_traversal` time.
    /// Populated alongside `bootstrap_transports`; cleared in
    /// `cleanup_bootstrap_transport_if_unused`. Used by the rx loop to
    /// route fatal-protocol-mismatch observations back to the
    /// Nostr-discovery `failure_state` for long cooldown application.
    bootstrap_transport_npubs: HashMap<TransportId, String>,
    /// Peers that should not be used as reply-learned fallback transit for
    /// other destinations. Direct lookups to the peer are still permitted.
    discovery_fallback_transit_blocked_peers: HashSet<NodeAddr>,

    // === Periodic Parent Re-evaluation ===
    /// Timestamp of last periodic parent re-evaluation (for pacing).
    last_parent_reeval: Option<crate::time::Instant>,

    // === Congestion Logging ===
    /// Timestamp of last congestion detection log (rate-limited to 5s).
    last_congestion_log: Option<std::time::Instant>,

    // === Mesh Size Estimate ===
    /// Cached estimated mesh size (computed once per tick from bloom filters).
    estimated_mesh_size: Option<u64>,
    /// Timestamp of last mesh size log emission.
    last_mesh_size_log: Option<std::time::Instant>,

    // === Bloom Self-Plausibility ===
    /// Rate-limit state for the self-plausibility WARN. Fires at most
    /// once per 60s globally when our own outgoing FilterAnnounce has
    /// an FPR above `node.bloom.max_inbound_fpr`, signalling either
    /// aggregation drift or an ingress bypass.
    last_self_warn: Option<std::time::Instant>,

    // === Local Outbound Liveness ===
    /// Set per peer when a `transport.send` returned a local-side io error
    /// (`NetworkUnreachable` / `HostUnreachable` / `AddrNotAvailable`),
    /// cleared on the next successful send to that peer. Used by
    /// `check_link_heartbeats` to compress only that peer's dead-timeout to
    /// `fast_link_dead_timeout_secs` while its outbound is observed broken.
    local_send_failure_at_by_peer: HashMap<NodeAddr, std::time::Instant>,
    /// Set when the rx loop could not complete its 1s maintenance work
    /// inside the watchdog timeout. Link-dead detection may be valid during
    /// overload, but traversal cooldown should not punish a path just because
    /// our own scheduler/worker queue was late.
    last_rx_loop_maintenance_timeout_at: Option<std::time::Instant>,

    // === Display Names ===
    /// Human-readable names for configured peers (alias or short npub).
    /// Populated at startup from peer config.
    peer_aliases: HashMap<NodeAddr, String>,
    /// Scheduler weight for explicitly configured peers. Built when config
    /// changes so the packet hot path only does a NodeAddr hash lookup.
    configured_peer_send_weights: HashMap<NodeAddr, u8>,

    /// Reloadable peer ACL state from standard allow/deny files.
    peer_acl: acl::PeerAclReloader,

    // === Host Map ===
    /// Static hostname → npub mapping for DNS resolution.
    /// Built at construction from peer aliases and /etc/fips/hosts.
    host_map: Arc<HostMap>,
}

impl Node {
    /// Create a new node from configuration.
    pub fn new(config: Config) -> Result<Self, NodeError> {
        config.validate()?;
        let identity = config.create_identity()?;
        let node_addr = *identity.node_addr();
        let is_leaf_only = config.is_leaf_only();

        let (decrypt_fallback_tx, decrypt_fallback_rx) = tokio::sync::mpsc::unbounded_channel();
        let decrypt_fallback_rx = Some(decrypt_fallback_rx);

        let mut startup_epoch = [0u8; 8];
        rand::rng().fill_bytes(&mut startup_epoch);

        let mut bloom_state = if is_leaf_only {
            BloomState::leaf_only(node_addr)
        } else {
            BloomState::new(node_addr)
        };
        bloom_state.set_update_debounce_ms(config.node.bloom.update_debounce_ms);

        let tun_state = if config.tun.enabled {
            TunState::Configured
        } else {
            TunState::Disabled
        };

        // Initialize tree state with signed self-declaration
        let mut tree_state = TreeState::new(node_addr);
        tree_state.set_parent_hysteresis(config.node.tree.parent_hysteresis);
        tree_state.set_hold_down(config.node.tree.hold_down_secs);
        tree_state.set_flap_dampening(
            config.node.tree.flap_threshold,
            config.node.tree.flap_window_secs,
            config.node.tree.flap_dampening_secs,
        );
        tree_state
            .sign_declaration(&identity)
            .expect("signing own declaration should never fail");

        let coord_cache = CoordCache::new(
            config.node.cache.coord_size,
            config.node.cache.coord_ttl_secs * 1000,
        );
        let rl = &config.node.rate_limit;
        let msg1_rate_limiter = HandshakeRateLimiter::with_params(
            rate_limit::TokenBucket::with_params(rl.handshake_burst, rl.handshake_rate),
            config.node.limits.max_pending_inbound,
        );

        let max_connections = config.node.limits.max_connections;
        let max_peers = config.node.limits.max_peers;
        let max_links = config.node.limits.max_links;
        let coords_response_interval_ms = config.node.session.coords_response_interval_ms;
        let backoff_base_secs = config.node.discovery.backoff_base_secs;
        let backoff_max_secs = config.node.discovery.backoff_max_secs;
        let forward_min_interval_secs = config.node.discovery.forward_min_interval_secs;

        let (host_map, peer_acl) = Self::host_map_and_peer_acl(&config);
        let configured_peer_send_weights = Self::configured_peer_send_weights(&config);

        Ok(Self {
            identity,
            startup_epoch,
            started_at: std::time::Instant::now(),
            config,
            state: NodeState::Created,
            is_leaf_only,
            tree_state,
            bloom_state,
            coord_cache,
            learned_routes: LearnedRouteTable::default(),
            session_direct_degraded_until_ms: HashMap::new(),
            recent_requests: HashMap::new(),
            transports: HashMap::new(),
            transport_drops: HashMap::new(),
            links: HashMap::new(),
            addr_to_link: HashMap::new(),
            packet_tx: None,
            packet_rx: None,
            connections: HashMap::new(),
            peers: HashMap::new(),
            sessions: HashMap::new(),
            identity_cache: HashMap::new(),
            pending_tun_packets: HashMap::new(),
            pending_endpoint_data: HashMap::new(),
            pending_lookups: HashMap::new(),
            max_connections,
            max_peers,
            max_links,
            next_link_id: 1,
            next_transport_id: 1,
            stats: stats::NodeStats::new(),
            stats_history: stats_history::StatsHistory::new(),
            tun_state,
            tun_name: None,
            tun_tx: None,
            tun_outbound_rx: None,
            external_packet_tx: None,
            endpoint_command_rx: None,
            endpoint_event_tx: None,
            encrypt_workers: None,
            decrypt_workers: None,
            decrypt_registered_sessions: std::collections::HashSet::new(),
            decrypt_fallback_tx,
            decrypt_fallback_rx,
            tun_reader_handle: None,
            tun_writer_handle: None,
            #[cfg(target_os = "macos")]
            tun_shutdown_fd: None,
            dns_identity_rx: None,
            dns_task: None,
            index_allocator: IndexAllocator::new(),
            peers_by_index: HashMap::new(),
            pending_outbound: HashMap::new(),
            msg1_rate_limiter,
            icmp_rate_limiter: IcmpRateLimiter::new(),
            routing_error_rate_limiter: RoutingErrorRateLimiter::new(),
            coords_response_rate_limiter: RoutingErrorRateLimiter::with_interval(
                std::time::Duration::from_millis(coords_response_interval_ms),
            ),
            discovery_backoff: DiscoveryBackoff::with_params(backoff_base_secs, backoff_max_secs),
            discovery_forward_limiter: DiscoveryForwardRateLimiter::with_interval(
                std::time::Duration::from_secs(forward_min_interval_secs),
            ),
            pending_connects: Vec::new(),
            retry_pending: HashMap::new(),
            nostr_discovery: None,
            nostr_discovery_started_at_ms: None,
            lan_discovery: None,
            local_instance_registry: None,
            local_instance_started_at_ms: None,
            last_local_instance_publish_ms: None,
            last_local_instance_scan_ms: None,
            startup_open_discovery_sweep_done: false,
            bootstrap_transports: HashSet::new(),
            bootstrap_transport_npubs: HashMap::new(),
            discovery_fallback_transit_blocked_peers: HashSet::new(),
            last_parent_reeval: None,
            last_congestion_log: None,
            estimated_mesh_size: None,
            last_mesh_size_log: None,
            last_self_warn: None,
            local_send_failure_at_by_peer: HashMap::new(),
            last_rx_loop_maintenance_timeout_at: None,
            peer_aliases: HashMap::new(),
            configured_peer_send_weights,
            peer_acl,
            host_map,
            path_mtu_lookup: Arc::new(std::sync::RwLock::new(HashMap::new())),
        })
    }

    /// Create a node with a specific identity.
    ///
    /// This constructor validates cross-field config invariants before
    /// constructing the node, same as [`Node::new`].
    pub fn with_identity(identity: Identity, config: Config) -> Result<Self, NodeError> {
        config.validate()?;
        let node_addr = *identity.node_addr();

        let (decrypt_fallback_tx, decrypt_fallback_rx) = tokio::sync::mpsc::unbounded_channel();
        let decrypt_fallback_rx = Some(decrypt_fallback_rx);

        let mut startup_epoch = [0u8; 8];
        rand::rng().fill_bytes(&mut startup_epoch);

        let tun_state = if config.tun.enabled {
            TunState::Configured
        } else {
            TunState::Disabled
        };

        // Initialize tree state with signed self-declaration
        let mut tree_state = TreeState::new(node_addr);
        tree_state.set_parent_hysteresis(config.node.tree.parent_hysteresis);
        tree_state.set_hold_down(config.node.tree.hold_down_secs);
        tree_state.set_flap_dampening(
            config.node.tree.flap_threshold,
            config.node.tree.flap_window_secs,
            config.node.tree.flap_dampening_secs,
        );
        tree_state
            .sign_declaration(&identity)
            .expect("signing own declaration should never fail");

        let mut bloom_state = BloomState::new(node_addr);
        bloom_state.set_update_debounce_ms(config.node.bloom.update_debounce_ms);

        let coord_cache = CoordCache::new(
            config.node.cache.coord_size,
            config.node.cache.coord_ttl_secs * 1000,
        );
        let rl = &config.node.rate_limit;
        let msg1_rate_limiter = HandshakeRateLimiter::with_params(
            rate_limit::TokenBucket::with_params(rl.handshake_burst, rl.handshake_rate),
            config.node.limits.max_pending_inbound,
        );

        let max_connections = config.node.limits.max_connections;
        let max_peers = config.node.limits.max_peers;
        let max_links = config.node.limits.max_links;
        let coords_response_interval_ms = config.node.session.coords_response_interval_ms;

        let (host_map, peer_acl) = Self::host_map_and_peer_acl(&config);
        let configured_peer_send_weights = Self::configured_peer_send_weights(&config);

        Ok(Self {
            identity,
            startup_epoch,
            started_at: std::time::Instant::now(),
            config,
            state: NodeState::Created,
            is_leaf_only: false,
            tree_state,
            bloom_state,
            coord_cache,
            learned_routes: LearnedRouteTable::default(),
            session_direct_degraded_until_ms: HashMap::new(),
            recent_requests: HashMap::new(),
            transports: HashMap::new(),
            transport_drops: HashMap::new(),
            links: HashMap::new(),
            addr_to_link: HashMap::new(),
            packet_tx: None,
            packet_rx: None,
            connections: HashMap::new(),
            peers: HashMap::new(),
            sessions: HashMap::new(),
            identity_cache: HashMap::new(),
            pending_tun_packets: HashMap::new(),
            pending_endpoint_data: HashMap::new(),
            pending_lookups: HashMap::new(),
            max_connections,
            max_peers,
            max_links,
            next_link_id: 1,
            next_transport_id: 1,
            stats: stats::NodeStats::new(),
            stats_history: stats_history::StatsHistory::new(),
            tun_state,
            tun_name: None,
            tun_tx: None,
            tun_outbound_rx: None,
            external_packet_tx: None,
            endpoint_command_rx: None,
            endpoint_event_tx: None,
            encrypt_workers: None,
            decrypt_workers: None,
            decrypt_registered_sessions: std::collections::HashSet::new(),
            decrypt_fallback_tx,
            decrypt_fallback_rx,
            tun_reader_handle: None,
            tun_writer_handle: None,
            #[cfg(target_os = "macos")]
            tun_shutdown_fd: None,
            dns_identity_rx: None,
            dns_task: None,
            index_allocator: IndexAllocator::new(),
            peers_by_index: HashMap::new(),
            pending_outbound: HashMap::new(),
            msg1_rate_limiter,
            icmp_rate_limiter: IcmpRateLimiter::new(),
            routing_error_rate_limiter: RoutingErrorRateLimiter::new(),
            coords_response_rate_limiter: RoutingErrorRateLimiter::with_interval(
                std::time::Duration::from_millis(coords_response_interval_ms),
            ),
            discovery_backoff: DiscoveryBackoff::new(),
            discovery_forward_limiter: DiscoveryForwardRateLimiter::new(),
            pending_connects: Vec::new(),
            retry_pending: HashMap::new(),
            nostr_discovery: None,
            nostr_discovery_started_at_ms: None,
            lan_discovery: None,
            local_instance_registry: None,
            local_instance_started_at_ms: None,
            last_local_instance_publish_ms: None,
            last_local_instance_scan_ms: None,
            startup_open_discovery_sweep_done: false,
            bootstrap_transports: HashSet::new(),
            bootstrap_transport_npubs: HashMap::new(),
            discovery_fallback_transit_blocked_peers: HashSet::new(),
            last_parent_reeval: None,
            last_congestion_log: None,
            estimated_mesh_size: None,
            last_mesh_size_log: None,
            last_self_warn: None,
            local_send_failure_at_by_peer: HashMap::new(),
            last_rx_loop_maintenance_timeout_at: None,
            peer_aliases: HashMap::new(),
            configured_peer_send_weights,
            peer_acl,
            host_map,
            path_mtu_lookup: Arc::new(std::sync::RwLock::new(HashMap::new())),
        })
    }

    /// Create a leaf-only node (simplified state).
    pub fn leaf_only(config: Config) -> Result<Self, NodeError> {
        let mut node = Self::new(config)?;
        node.is_leaf_only = true;
        node.bloom_state = BloomState::leaf_only(*node.identity.node_addr());
        Ok(node)
    }

    fn host_map_and_peer_acl(config: &Config) -> (Arc<HostMap>, acl::PeerAclReloader) {
        let base_host_map = HostMap::from_peer_configs(config.peers());
        if !config.node.system_files_enabled {
            return (
                Arc::new(base_host_map.clone()),
                acl::PeerAclReloader::memory_only(base_host_map),
            );
        }

        let mut host_map = base_host_map.clone();
        let hosts_path = std::path::PathBuf::from(crate::upper::hosts::DEFAULT_HOSTS_PATH);
        let hosts_file = HostMap::load_hosts_file(std::path::Path::new(
            crate::upper::hosts::DEFAULT_HOSTS_PATH,
        ));
        host_map.merge(hosts_file);
        let peer_acl = acl::PeerAclReloader::with_alias_sources(
            std::path::PathBuf::from(acl::DEFAULT_PEERS_ALLOW_PATH),
            std::path::PathBuf::from(acl::DEFAULT_PEERS_DENY_PATH),
            base_host_map,
            hosts_path,
        );
        (Arc::new(host_map), peer_acl)
    }

    fn configured_peer_send_weights(config: &Config) -> HashMap<NodeAddr, u8> {
        config
            .peers()
            .iter()
            .filter_map(|peer| {
                PeerIdentity::from_npub(&peer.npub).ok().map(|identity| {
                    (
                        *identity.node_addr(),
                        encrypt_worker::EXPLICIT_PEER_SEND_WEIGHT,
                    )
                })
            })
            .collect()
    }

    #[cfg(unix)]
    fn send_weight_for_peer(&self, peer_addr: &NodeAddr) -> u8 {
        self.configured_peer_send_weights
            .get(peer_addr)
            .copied()
            .unwrap_or(encrypt_worker::DEFAULT_SEND_WEIGHT)
    }

    /// Create transport instances from configuration.
    ///
    /// Returns a vector of TransportHandles for all configured transports.
    async fn create_transports(&mut self, packet_tx: &PacketTx) -> Vec<TransportHandle> {
        let mut transports = Vec::new();

        // Collect UDP configs with optional names to avoid borrow conflicts
        let udp_instances: Vec<_> = self
            .config
            .transports
            .udp
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        // Create UDP transport instances
        for (name, udp_config) in udp_instances {
            let transport_id = self.allocate_transport_id();
            let udp = UdpTransport::new(transport_id, name, udp_config, packet_tx.clone());
            transports.push(TransportHandle::Udp(udp));
        }

        #[cfg(feature = "sim-transport")]
        {
            let sim_instances: Vec<_> = self
                .config
                .transports
                .sim
                .iter()
                .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
                .collect();

            for (name, sim_config) in sim_instances {
                let transport_id = self.allocate_transport_id();
                let sim = crate::transport::sim::SimTransport::new(
                    transport_id,
                    name,
                    sim_config,
                    packet_tx.clone(),
                );
                transports.push(TransportHandle::Sim(sim));
            }
        }

        // Create Ethernet transport instances where raw-socket support exists.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let eth_instances: Vec<_> = self
                .config
                .transports
                .ethernet
                .iter()
                .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
                .collect();
            let xonly = self.identity.pubkey();
            for (name, eth_config) in eth_instances {
                let mut eth_config = eth_config;
                if eth_config.discovery_scope.is_none() {
                    eth_config.discovery_scope = self.lan_discovery_scope();
                }
                let transport_id = self.allocate_transport_id();
                let mut eth =
                    EthernetTransport::new(transport_id, name, eth_config, packet_tx.clone());
                eth.set_local_pubkey(xonly);
                transports.push(TransportHandle::Ethernet(eth));
            }
        }

        // Create TCP transport instances
        let tcp_instances: Vec<_> = self
            .config
            .transports
            .tcp
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        for (name, tcp_config) in tcp_instances {
            let transport_id = self.allocate_transport_id();
            let tcp = TcpTransport::new(transport_id, name, tcp_config, packet_tx.clone());
            transports.push(TransportHandle::Tcp(tcp));
        }

        // Create Tor transport instances
        let tor_instances: Vec<_> = self
            .config
            .transports
            .tor
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        for (name, tor_config) in tor_instances {
            let transport_id = self.allocate_transport_id();
            let tor = TorTransport::new(transport_id, name, tor_config, packet_tx.clone());
            transports.push(TransportHandle::Tor(tor));
        }

        let webrtc_instances: Vec<_> = self
            .config
            .transports
            .webrtc
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        #[cfg(feature = "webrtc-transport")]
        {
            for (name, webrtc_config) in webrtc_instances {
                let transport_id = self.allocate_transport_id();
                match WebRtcTransport::new(
                    transport_id,
                    name,
                    webrtc_config,
                    packet_tx.clone(),
                    &self.identity,
                    &self.config.node.discovery.nostr,
                ) {
                    Ok(webrtc) => transports.push(TransportHandle::WebRtc(Box::new(webrtc))),
                    Err(err) => {
                        warn!(
                            transport_id = %transport_id,
                            error = %err,
                            "failed to initialize WebRTC transport"
                        );
                    }
                }
            }
        }
        #[cfg(not(feature = "webrtc-transport"))]
        if !webrtc_instances.is_empty() {
            warn!("WebRTC transport configured but this build lacks WebRTC transport support");
        }

        // Create BLE transport instances
        #[cfg(bluer_available)]
        {
            let ble_instances: Vec<_> = self
                .config
                .transports
                .ble
                .iter()
                .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
                .collect();

            #[cfg(all(bluer_available, not(test)))]
            for (name, ble_config) in ble_instances {
                let transport_id = self.allocate_transport_id();
                let adapter = ble_config.adapter().to_string();
                let mtu = ble_config.mtu();
                match crate::transport::ble::io::BluerIo::new(&adapter, mtu).await {
                    Ok(io) => {
                        let mut ble = crate::transport::ble::BleTransport::new(
                            transport_id,
                            name,
                            ble_config,
                            io,
                            packet_tx.clone(),
                        );
                        ble.set_local_pubkey(self.identity.pubkey().serialize());
                        transports.push(TransportHandle::Ble(ble));
                    }
                    Err(e) => {
                        tracing::warn!(adapter = %adapter, error = %e, "failed to initialize BLE adapter");
                    }
                }
            }

            #[cfg(any(not(bluer_available), test))]
            if !ble_instances.is_empty() {
                #[cfg(not(test))]
                tracing::warn!("BLE transport configured but this build lacks BlueZ support");
            }
        }

        transports
    }

    /// Find an operational transport that matches the given transport type name.
    ///
    /// Adopted UDP bootstrap transports are point-to-point sockets handed off
    /// from Nostr/STUN traversal. They must not be reused for ordinary
    /// `udp host:port` dials discovered through static config, mDNS, or overlay
    /// adverts: on macOS a `send_to` through the wrong adopted socket can fail
    /// with `EINVAL`, and even on platforms that allow it the packet would use
    /// the wrong 5-tuple/NAT mapping. Prefer configured transports and make the
    /// choice deterministic by lowest transport id instead of HashMap order.
    fn find_transport_for_type(&self, transport_type: &str) -> Option<TransportId> {
        self.transports
            .iter()
            .filter(|(id, handle)| {
                handle.transport_type().name == transport_type
                    && handle.is_operational()
                    && !self.bootstrap_transports.contains(id)
            })
            .min_by_key(|(id, _)| id.as_u32())
            .map(|(id, _)| *id)
    }

    /// Resolve an Ethernet peer address ("interface/mac") to a transport ID
    /// and binary TransportAddr.
    ///
    /// Finds the Ethernet transport instance bound to the named interface
    /// and parses the MAC portion into a 6-byte TransportAddr.
    #[allow(unused_variables)]
    fn resolve_ethernet_addr(
        &self,
        addr_str: &str,
    ) -> Result<(TransportId, TransportAddr), NodeError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let (iface, mac_str) = addr_str.split_once('/').ok_or_else(|| {
                NodeError::NoTransportForType(format!(
                    "invalid Ethernet address format '{}': expected 'interface/mac'",
                    addr_str
                ))
            })?;

            // Find the Ethernet transport bound to this interface
            let transport_id = self
                .transports
                .iter()
                .find(|(_, handle)| {
                    handle.transport_type().name == "ethernet"
                        && handle.is_operational()
                        && handle.interface_name() == Some(iface)
                })
                .map(|(id, _)| *id)
                .ok_or_else(|| {
                    NodeError::NoTransportForType(format!(
                        "no operational Ethernet transport for interface '{}'",
                        iface
                    ))
                })?;

            let mac = crate::transport::ethernet::parse_mac_string(mac_str).map_err(|e| {
                NodeError::NoTransportForType(format!("invalid MAC in '{}': {}", addr_str, e))
            })?;

            Ok((transport_id, TransportAddr::from_bytes(&mac)))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(NodeError::NoTransportForType(
                "Ethernet transport is not supported on this platform".to_string(),
            ))
        }
    }

    /// Resolve a BLE address string (`"adapter/AA:BB:CC:DD:EE:FF"`) to a
    /// (TransportId, TransportAddr) pair by finding the BLE transport
    /// instance matching the adapter name.
    #[cfg(bluer_available)]
    fn resolve_ble_addr(&self, addr_str: &str) -> Result<(TransportId, TransportAddr), NodeError> {
        let ta = TransportAddr::from_string(addr_str);
        let adapter = crate::transport::ble::addr::adapter_from_addr(&ta).ok_or_else(|| {
            NodeError::NoTransportForType(format!(
                "invalid BLE address format '{}': expected 'adapter/mac'",
                addr_str
            ))
        })?;

        // Find the BLE transport for this adapter
        let transport_id = self
            .transports
            .iter()
            .find(|(_, handle)| handle.transport_type().name == "ble" && handle.is_operational())
            .map(|(id, _)| *id)
            .ok_or_else(|| {
                NodeError::NoTransportForType(format!(
                    "no operational BLE transport for adapter '{}'",
                    adapter
                ))
            })?;

        // Validate the address format
        crate::transport::ble::addr::BleAddr::parse(addr_str).map_err(|e| {
            NodeError::NoTransportForType(format!("invalid BLE address '{}': {}", addr_str, e))
        })?;

        Ok((transport_id, TransportAddr::from_string(addr_str)))
    }

    // === Identity Accessors ===

    /// Get this node's identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Get this node's NodeAddr.
    pub fn node_addr(&self) -> &NodeAddr {
        self.identity.node_addr()
    }

    /// Get this node's npub.
    pub fn npub(&self) -> String {
        self.identity.npub()
    }

    /// Return a human-readable display name for a NodeAddr.
    ///
    /// Lookup order:
    /// 1. Host map hostname (from peer aliases + /etc/fips/hosts)
    /// 2. Configured peer alias or short npub (from startup map)
    /// 3. Active peer's short npub (e.g., inbound peer not in config)
    /// 4. Session endpoint's short npub (end-to-end, may not be direct peer)
    /// 5. Truncated NodeAddr hex (unknown address)
    pub(crate) fn peer_display_name(&self, addr: &NodeAddr) -> String {
        if let Some(hostname) = self.host_map.lookup_hostname(addr) {
            return hostname.to_string();
        }
        if let Some(name) = self.peer_aliases.get(addr) {
            return name.clone();
        }
        if let Some(peer) = self.peers.get(addr) {
            return peer.identity().short_npub();
        }
        if let Some(entry) = self.sessions.get(addr) {
            let (xonly, _) = entry.remote_pubkey().x_only_public_key();
            return PeerIdentity::from_pubkey(xonly).short_npub();
        }
        addr.short_hex()
    }

    /// Tear down a `peers_by_index` entry **and** keep the shard-owned
    /// decrypt-worker state coherent: removes the same `cache_key`
    /// from the registered-sessions tracking set and tells the
    /// assigned shard worker to drop its `OwnedSessionState` entry.
    ///
    /// Use this instead of a bare `self.peers_by_index.remove(&key)`
    /// at every session-lifecycle teardown site (rekey cross-connection
    /// swap, peer disconnect, dispatch session-rotation) so the worker
    /// doesn't keep stale ciphers / replay windows around. The
    /// follow-up `RegisterSession` for the NEW key (if any) will then
    /// install the fresh state on the same shard.
    pub(in crate::node) fn deregister_session_index(&mut self, cache_key: (TransportId, u32)) {
        // Find the peer that owns this index BEFORE removing it from
        // the index map, so we can decide whether the deregistration
        // also tears down the peer's connected UDP socket.
        let owning_peer = self.peers_by_index.get(&cache_key).copied();
        self.peers_by_index.remove(&cache_key);
        if self.decrypt_registered_sessions.remove(&cache_key)
            && let Some(workers) = self.decrypt_workers.as_ref()
        {
            workers.unregister_session(cache_key);
        }
        // Tear down the per-peer connected UDP socket *only* if no
        // other peers_by_index entry still resolves to this peer.
        // Rekey drain calls into this helper with the OLD session
        // index while the NEW index is already installed and points
        // at the same peer — there the connect()-ed 5-tuple is
        // still valid for the new session and we must not close it.
        // Peer-teardown sites (CrossConnection swap, stale-index
        // fall-through in encrypted.rs, disconnect handler) call
        // here when this is the peer's last index, so the connected
        // socket goes away with the peer.
        if let Some(peer_addr) = owning_peer {
            let peer_has_other_index = self
                .peers_by_index
                .values()
                .any(|other| *other == peer_addr);
            if !peer_has_other_index {
                self.clear_connected_udp_for_peer(&peer_addr);
            }
        }
    }

    /// Ensure the current FMP receive index resolves to this peer.
    ///
    /// Rekey msg1/msg2 handlers pre-register the pending index before
    /// cutover, but losing that registration in a debug build used to
    /// panic in the cutover path. Repairing the map here is safe: the
    /// peer has already promoted the pending session, and the decrypt
    /// worker registration immediately after cutover depends on the
    /// same `(transport_id, our_index)` key.
    pub(in crate::node) fn ensure_current_session_index_registered(
        &mut self,
        node_addr: &NodeAddr,
        context: &'static str,
    ) -> bool {
        let Some(peer) = self.peers.get(node_addr) else {
            return false;
        };
        let Some(transport_id) = peer.transport_id() else {
            warn!(
                peer = %self.peer_display_name(node_addr),
                context,
                "Cannot register current session index without transport id"
            );
            return false;
        };
        let Some(our_index) = peer.our_index() else {
            warn!(
                peer = %self.peer_display_name(node_addr),
                context,
                "Cannot register current session index without local index"
            );
            return false;
        };

        let cache_key = (transport_id, our_index.as_u32());
        match self.peers_by_index.get(&cache_key).copied() {
            Some(existing) if existing == *node_addr => true,
            Some(existing) => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    previous_owner = %self.peer_display_name(&existing),
                    transport_id = %transport_id,
                    our_index = %our_index,
                    context,
                    "Repairing current session index with stale owner"
                );
                self.peers_by_index.insert(cache_key, *node_addr);
                true
            }
            None => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    transport_id = %transport_id,
                    our_index = %our_index,
                    context,
                    "Repairing missing current session index"
                );
                self.peers_by_index.insert(cache_key, *node_addr);
                true
            }
        }
    }

    // === Configuration ===

    /// Get the configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Calculate the effective IPv6 MTU that can be sent over FIPS.
    ///
    /// Delegates to `upper::icmp::effective_ipv6_mtu()` with this node's
    /// transport MTU. Returns the maximum IPv6 packet size (including
    /// IPv6 header) that can be transmitted through the FIPS mesh.
    pub fn effective_ipv6_mtu(&self) -> u16 {
        crate::upper::icmp::effective_ipv6_mtu(self.transport_mtu())
    }

    /// Get the transport MTU governing the global TUN-boundary MSS clamp.
    ///
    /// Returns the **minimum** MTU across all operational transports, or
    /// 1280 (IPv6 minimum) as fallback. Used for initial TUN configuration
    /// where a specific egress transport isn't yet known: the resulting
    /// `effective_ipv6_mtu` (transport_mtu - 77) and `max_mss`
    /// (effective_mtu - 60) form a conservative ceiling that fits ANY
    /// configured-transport's egress, eliminating PMTU-D black holes that
    /// would otherwise occur when a flow's actual egress is smaller than
    /// the clamp ceiling assumed at TUN init.
    ///
    /// Returning the smallest (rather than the first-iterated, which used
    /// to vary across HashMap iteration order + async-startup race) makes
    /// the clamp deterministic across daemon restarts.
    ///
    /// See `ISSUE-2026-0011` for the empirical investigation.
    pub fn transport_mtu(&self) -> u16 {
        let min_operational = self
            .transports
            .values()
            .filter(|h| h.is_operational())
            .map(|h| h.mtu())
            .min();
        if let Some(mtu) = min_operational {
            return mtu;
        }
        // Fallback to config: try UDP first, then Ethernet
        if let Some((_, cfg)) = self.config.transports.udp.iter().next() {
            return cfg.mtu();
        }
        1280
    }

    // === State ===

    /// Get the node state.
    pub fn state(&self) -> NodeState {
        self.state
    }

    /// Get the node uptime.
    pub fn uptime(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }

    /// Check if node is operational.
    pub fn is_running(&self) -> bool {
        self.state.is_operational()
    }

    /// Check if this is a leaf-only node.
    pub fn is_leaf_only(&self) -> bool {
        self.is_leaf_only
    }

    // === Tree State ===

    /// Get the tree state.
    pub fn tree_state(&self) -> &TreeState {
        &self.tree_state
    }

    /// Get mutable tree state.
    pub fn tree_state_mut(&mut self) -> &mut TreeState {
        &mut self.tree_state
    }

    // === Bloom State ===

    /// Get the Bloom filter state.
    pub fn bloom_state(&self) -> &BloomState {
        &self.bloom_state
    }

    /// Get mutable Bloom filter state.
    pub fn bloom_state_mut(&mut self) -> &mut BloomState {
        &mut self.bloom_state
    }

    // === Mesh Size Estimate ===

    /// Get the cached estimated mesh size.
    pub fn estimated_mesh_size(&self) -> Option<u64> {
        self.estimated_mesh_size
    }

    /// Compute and cache the estimated mesh size from bloom filters.
    ///
    /// Uses the spanning tree partition: parent's filter covers nodes reachable
    /// upward, children's filters cover disjoint subtrees downward. The sum
    /// of estimated entry counts plus one (self) approximates total network size.
    pub(crate) fn compute_mesh_size(&mut self) {
        let my_addr = *self.tree_state.my_node_addr();
        let parent_id = *self.tree_state.my_declaration().parent_id();
        let is_root = self.tree_state.is_root();

        let max_fpr = self.config.node.bloom.max_inbound_fpr;
        let mut total: f64 = 1.0; // count self
        let mut child_count: u32 = 0;
        let mut has_data = false;

        // Parent's filter: nodes reachable upward through the tree.
        // If any contributing filter is above the FPR cap, we refuse to
        // estimate rather than substitute a partial/biased aggregate —
        // Node.estimated_mesh_size is already Option<u64> and consumers
        // (control socket, fipstop, periodic debug log) handle None.
        if !is_root
            && let Some(parent) = self.peers.get(&parent_id)
            && let Some(filter) = parent.inbound_filter()
        {
            match filter.estimated_count(max_fpr) {
                Some(n) => {
                    total += n;
                    has_data = true;
                }
                None => {
                    self.estimated_mesh_size = None;
                    return;
                }
            }
        }

        // Children's filters: each child's subtree is disjoint
        for (peer_addr, peer) in &self.peers {
            if peer_addr == &parent_id {
                continue;
            }
            if let Some(decl) = self.tree_state.peer_declaration(peer_addr)
                && *decl.parent_id() == my_addr
            {
                child_count += 1;
                if let Some(filter) = peer.inbound_filter() {
                    match filter.estimated_count(max_fpr) {
                        Some(n) => {
                            total += n;
                            has_data = true;
                        }
                        None => {
                            self.estimated_mesh_size = None;
                            return;
                        }
                    }
                }
            }
        }

        if !has_data {
            self.estimated_mesh_size = None;
            return;
        }

        let size = total.round() as u64;
        self.estimated_mesh_size = Some(size);

        // Periodic logging (reuse MMP default interval: 30s)
        let now = std::time::Instant::now();
        let should_log = match self.last_mesh_size_log {
            None => true,
            Some(last) => {
                now.duration_since(last)
                    >= std::time::Duration::from_secs(self.config.node.mmp.log_interval_secs)
            }
        };
        if should_log {
            tracing::debug!(
                estimated_mesh_size = size,
                peers = self.peers.len(),
                children = child_count,
                "Mesh size estimate"
            );
            self.last_mesh_size_log = Some(now);
        }
    }

    // === Coord Cache ===

    /// Get the coordinate cache.
    pub fn coord_cache(&self) -> &CoordCache {
        &self.coord_cache
    }

    /// Get mutable coordinate cache.
    pub fn coord_cache_mut(&mut self) -> &mut CoordCache {
        &mut self.coord_cache
    }

    // === Node Statistics ===

    /// Get the node statistics.
    pub fn stats(&self) -> &stats::NodeStats {
        &self.stats
    }

    /// Get mutable node statistics.
    pub(crate) fn stats_mut(&mut self) -> &mut stats::NodeStats {
        &mut self.stats
    }

    /// Get the stats history collector.
    pub fn stats_history(&self) -> &stats_history::StatsHistory {
        &self.stats_history
    }

    /// Sample the current node state into the stats history ring.
    /// Called once per tick from the RX loop.
    pub(crate) fn record_stats_history(&mut self) {
        let fwd = &self.stats.forwarding;
        let peers_with_mmp: Vec<f64> = self
            .peers
            .values()
            .filter_map(|p| p.mmp().map(|m| m.metrics.loss_rate()))
            .collect();
        let loss_rate = if peers_with_mmp.is_empty() {
            0.0
        } else {
            peers_with_mmp.iter().sum::<f64>() / peers_with_mmp.len() as f64
        };

        let snap = stats_history::Snapshot {
            mesh_size: self.estimated_mesh_size,
            tree_depth: self.tree_state.my_coords().depth() as u32,
            peer_count: self.peers.len() as u64,
            parent_switches_total: self.stats.tree.parent_switches,
            bytes_in_total: fwd.received_bytes,
            bytes_out_total: fwd.forwarded_bytes + fwd.originated_bytes,
            packets_in_total: fwd.received_packets,
            packets_out_total: fwd.forwarded_packets + fwd.originated_packets,
            loss_rate,
            active_sessions: self.sessions.len() as u64,
        };

        let now = std::time::Instant::now();
        let peer_snaps: Vec<stats_history::PeerSnapshot> = self
            .peers
            .values()
            .map(|p| {
                let stats = p.link_stats();
                let (srtt_ms, loss_rate, ecn_ce) = match p.mmp() {
                    Some(m) => (
                        m.metrics.srtt_ms(),
                        Some(m.metrics.loss_rate()),
                        m.receiver.ecn_ce_count() as u64,
                    ),
                    None => (None, None, 0),
                };
                stats_history::PeerSnapshot {
                    node_addr: *p.node_addr(),
                    last_seen: now,
                    srtt_ms,
                    loss_rate,
                    bytes_in_total: stats.bytes_recv,
                    bytes_out_total: stats.bytes_sent,
                    packets_in_total: stats.packets_recv,
                    packets_out_total: stats.packets_sent,
                    ecn_ce_total: ecn_ce,
                }
            })
            .collect();

        self.stats_history.tick(now, &snap, &peer_snaps);
    }

    // === TUN Interface ===

    /// Get the TUN state.
    pub fn tun_state(&self) -> TunState {
        self.tun_state
    }

    /// Get the TUN interface name, if active.
    pub fn tun_name(&self) -> Option<&str> {
        self.tun_name.as_deref()
    }

    // === Resource Limits ===

    /// Set the maximum number of connections (handshake phase).
    pub fn set_max_connections(&mut self, max: usize) {
        self.max_connections = max;
    }

    /// Set the maximum number of peers (authenticated).
    pub fn set_max_peers(&mut self, max: usize) {
        self.max_peers = max;
    }

    /// Returns false when starting more outbound work would exceed a resource
    /// cap. A cap of `0` means uncapped.
    pub(crate) fn outbound_admission_check(&self) -> bool {
        let connection_used = self
            .connections
            .len()
            .saturating_add(self.pending_connects.len());
        let peer_allowed = self.max_peers == 0 || self.peers.len() < self.max_peers;
        let connection_allowed =
            self.max_connections == 0 || connection_used < self.max_connections;
        let link_allowed = self.max_links == 0 || self.links.len() < self.max_links;
        peer_allowed && connection_allowed && link_allowed
    }

    /// Admission for public/open-discovery outbound work. This includes the
    /// general connection/link caps and, when open Nostr discovery is enabled,
    /// the configured non-peer budget.
    pub(crate) fn open_discovery_outbound_admission_check(&self) -> bool {
        if !self.outbound_admission_check() {
            return false;
        }

        let nostr = &self.config.node.discovery.nostr;
        if !nostr.enabled || nostr.policy != NostrDiscoveryPolicy::Open {
            return true;
        }

        let configured_npubs = self
            .config
            .peers()
            .iter()
            .map(|peer| peer.npub.clone())
            .collect::<HashSet<_>>();
        self.open_discovery_enqueue_budget(&configured_npubs) > 0
    }

    /// Like `outbound_admission_check`, but for racing a better path to a
    /// peer that is already authenticated. This may temporarily add a
    /// connection/link, but it does not consume a new peer slot.
    pub(crate) fn outbound_direct_refresh_admission_check(&self) -> bool {
        let connection_used = self
            .connections
            .len()
            .saturating_add(self.pending_connects.len());
        let connection_allowed =
            self.max_connections == 0 || connection_used < self.max_connections;
        let link_allowed = self.max_links == 0 || self.links.len() < self.max_links;
        connection_allowed && link_allowed
    }

    /// Set the maximum number of links.
    pub fn set_max_links(&mut self, max: usize) {
        self.max_links = max;
    }

    // === Counts ===

    /// Number of pending connections (handshake in progress).
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Number of authenticated peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Number of active links.
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Number of active transports.
    pub fn transport_count(&self) -> usize {
        self.transports.len()
    }

    // === Transport Management ===

    /// Allocate a new transport ID.
    pub fn allocate_transport_id(&mut self) -> TransportId {
        let id = TransportId::new(self.next_transport_id);
        self.next_transport_id += 1;
        id
    }

    /// Get a transport by ID.
    pub fn get_transport(&self, id: &TransportId) -> Option<&TransportHandle> {
        self.transports.get(id)
    }

    /// Get mutable transport by ID.
    pub fn get_transport_mut(&mut self, id: &TransportId) -> Option<&mut TransportHandle> {
        self.transports.get_mut(id)
    }

    /// Iterate over transport IDs.
    pub fn transport_ids(&self) -> impl Iterator<Item = &TransportId> {
        self.transports.keys()
    }

    /// Get the packet receiver for the event loop.
    pub fn packet_rx(&mut self) -> Option<&mut PacketRx> {
        self.packet_rx.as_mut()
    }

    // === Link Management ===

    /// Allocate a new link ID.
    pub fn allocate_link_id(&mut self) -> LinkId {
        let id = LinkId::new(self.next_link_id);
        self.next_link_id += 1;
        id
    }

    /// Add a link.
    pub fn add_link(&mut self, link: Link) -> Result<(), NodeError> {
        if self.max_links > 0 && self.links.len() >= self.max_links {
            return Err(NodeError::MaxLinksExceeded {
                max: self.max_links,
            });
        }
        let link_id = link.link_id();
        let transport_id = link.transport_id();
        let remote_addr = link.remote_addr().clone();

        self.links.insert(link_id, link);
        self.addr_to_link
            .insert((transport_id, remote_addr), link_id);
        Ok(())
    }

    /// Get a link by ID.
    pub fn get_link(&self, link_id: &LinkId) -> Option<&Link> {
        self.links.get(link_id)
    }

    /// Get a mutable link by ID.
    pub fn get_link_mut(&mut self, link_id: &LinkId) -> Option<&mut Link> {
        self.links.get_mut(link_id)
    }

    /// Find link ID by transport address.
    pub fn find_link_by_addr(
        &self,
        transport_id: TransportId,
        addr: &TransportAddr,
    ) -> Option<LinkId> {
        self.addr_to_link
            .get(&(transport_id, addr.clone()))
            .copied()
    }

    /// Remove a link.
    ///
    /// Only removes the addr_to_link reverse lookup if it still points to this
    /// link. In cross-connection scenarios, a newer link may have replaced the
    /// entry for the same address.
    pub fn remove_link(&mut self, link_id: &LinkId) -> Option<Link> {
        if let Some(link) = self.links.remove(link_id) {
            // Clean up reverse lookup only if it still maps to this link
            let key = (link.transport_id(), link.remote_addr().clone());
            if self.addr_to_link.get(&key) == Some(link_id) {
                self.addr_to_link.remove(&key);
            }
            Some(link)
        } else {
            None
        }
    }

    pub(crate) fn cleanup_bootstrap_transport_if_unused(&mut self, transport_id: TransportId) {
        if !self.bootstrap_transports.contains(&transport_id) {
            return;
        }

        let transport_in_use = self
            .links
            .values()
            .any(|link| link.transport_id() == transport_id)
            || self
                .connections
                .values()
                .any(|conn| conn.transport_id() == Some(transport_id))
            || self
                .peers
                .values()
                .any(|peer| peer.transport_id() == Some(transport_id))
            || self
                .pending_connects
                .iter()
                .any(|pending| pending.transport_id == transport_id);

        if transport_in_use {
            return;
        }

        tracing::debug!(
            transport_id = %transport_id,
            "bootstrap transport has no remaining references; dropping"
        );

        self.bootstrap_transports.remove(&transport_id);
        self.bootstrap_transport_npubs.remove(&transport_id);
        self.transport_drops.remove(&transport_id);
        self.transports.remove(&transport_id);
    }

    /// Iterate over all links.
    pub fn links(&self) -> impl Iterator<Item = &Link> {
        self.links.values()
    }

    // === Connection Management (Handshake Phase) ===

    /// Add a pending connection.
    pub fn add_connection(&mut self, connection: PeerConnection) -> Result<(), NodeError> {
        let link_id = connection.link_id();

        if self.connections.contains_key(&link_id) {
            return Err(NodeError::ConnectionAlreadyExists(link_id));
        }

        if self.max_connections > 0 && self.connections.len() >= self.max_connections {
            return Err(NodeError::MaxConnectionsExceeded {
                max: self.max_connections,
            });
        }

        self.connections.insert(link_id, connection);
        Ok(())
    }

    /// Get a connection by LinkId.
    pub fn get_connection(&self, link_id: &LinkId) -> Option<&PeerConnection> {
        self.connections.get(link_id)
    }

    /// Get a mutable connection by LinkId.
    pub fn get_connection_mut(&mut self, link_id: &LinkId) -> Option<&mut PeerConnection> {
        self.connections.get_mut(link_id)
    }

    /// Remove a connection.
    pub fn remove_connection(&mut self, link_id: &LinkId) -> Option<PeerConnection> {
        self.connections.remove(link_id)
    }

    /// Iterate over all connections.
    pub fn connections(&self) -> impl Iterator<Item = &PeerConnection> {
        self.connections.values()
    }

    // === Peer Management (Active Phase) ===

    /// Get a peer by NodeAddr.
    pub fn get_peer(&self, node_addr: &NodeAddr) -> Option<&ActivePeer> {
        self.peers.get(node_addr)
    }

    /// Get a mutable peer by NodeAddr.
    pub fn get_peer_mut(&mut self, node_addr: &NodeAddr) -> Option<&mut ActivePeer> {
        self.peers.get_mut(node_addr)
    }

    /// Remove a peer.
    pub fn remove_peer(&mut self, node_addr: &NodeAddr) -> Option<ActivePeer> {
        self.peers.remove(node_addr)
    }

    /// Iterate over all peers.
    pub fn peers(&self) -> impl Iterator<Item = &ActivePeer> {
        self.peers.values()
    }

    /// Reference to the Nostr discovery handle if discovery is enabled.
    /// Used by control queries (`show_peers` per-peer Nostr-traversal
    /// state) to read failure-state without taking shared ownership.
    pub fn nostr_discovery_handle(&self) -> Option<&crate::discovery::nostr::NostrDiscovery> {
        self.nostr_discovery.as_deref()
    }

    /// Iterate over all peer node IDs.
    pub fn peer_ids(&self) -> impl Iterator<Item = &NodeAddr> {
        self.peers.keys()
    }

    /// Iterate over peers that can send traffic.
    pub fn sendable_peers(&self) -> impl Iterator<Item = &ActivePeer> {
        self.peers.values().filter(|p| p.can_send())
    }

    /// Number of peers that can send traffic.
    pub fn sendable_peer_count(&self) -> usize {
        self.peers.values().filter(|p| p.can_send()).count()
    }

    pub(crate) fn set_discovery_fallback_transit_allowed(
        &mut self,
        peer_addr: NodeAddr,
        allowed: bool,
    ) {
        if allowed {
            self.discovery_fallback_transit_blocked_peers
                .remove(&peer_addr);
        } else {
            self.discovery_fallback_transit_blocked_peers
                .insert(peer_addr);
        }
    }

    pub(crate) fn configured_discovery_fallback_transit(
        &self,
        peer_addr: &NodeAddr,
    ) -> Option<bool> {
        self.configured_peer(peer_addr)
            .map(|peer| peer.discovery_fallback_transit)
    }

    pub(crate) fn configured_peer(&self, peer_addr: &NodeAddr) -> Option<&PeerConfig> {
        self.config.peers().iter().find(|peer| {
            PeerIdentity::from_npub(&peer.npub)
                .ok()
                .is_some_and(|identity| identity.node_addr() == peer_addr)
        })
    }

    pub(in crate::node) fn active_peer_uses_configured_static_udp_path(
        &self,
        peer_addr: &NodeAddr,
    ) -> bool {
        let Some(peer_config) = self.configured_peer(peer_addr) else {
            return false;
        };

        peer_config.addresses.iter().any(|candidate| {
            candidate.seen_at_ms.is_none()
                && candidate.transport.eq_ignore_ascii_case("udp")
                && self.active_peer_matches_candidate(peer_addr, candidate)
        })
    }

    pub(crate) fn discovery_fallback_transit_for_promotion(&self, peer_addr: &NodeAddr) -> bool {
        if let Some(retry_state) = self.retry_pending.get(peer_addr) {
            return retry_state.peer_config.discovery_fallback_transit;
        }

        if let Some(allowed) = self.configured_discovery_fallback_transit(peer_addr) {
            return allowed;
        }

        self.config.node.discovery.nostr.policy != crate::config::NostrDiscoveryPolicy::Open
    }

    // === End-to-End Sessions ===

    /// Get a session by remote NodeAddr.
    /// Disable the discovery forward rate limiter (for tests).
    #[cfg(test)]
    pub(crate) fn disable_discovery_forward_rate_limit(&mut self) {
        self.discovery_forward_limiter
            .set_interval(std::time::Duration::ZERO);
    }

    #[cfg(test)]
    pub(crate) fn get_session(&self, remote: &NodeAddr) -> Option<&SessionEntry> {
        self.sessions.get(remote)
    }

    /// Get a mutable session by remote NodeAddr.
    #[cfg(test)]
    pub(crate) fn get_session_mut(&mut self, remote: &NodeAddr) -> Option<&mut SessionEntry> {
        self.sessions.get_mut(remote)
    }

    /// Remove a session.
    #[cfg(test)]
    pub(crate) fn remove_session(&mut self, remote: &NodeAddr) -> Option<SessionEntry> {
        self.sessions.remove(remote)
    }

    /// Read the path_mtu_lookup entry for a destination FipsAddress.
    #[cfg(test)]
    pub(crate) fn path_mtu_lookup_get(&self, fips_addr: &crate::FipsAddress) -> Option<u16> {
        self.path_mtu_lookup
            .read()
            .ok()
            .and_then(|map| map.get(fips_addr).copied())
    }

    /// Write a path_mtu_lookup entry directly (for tests that pre-seed the map).
    #[cfg(test)]
    pub(crate) fn path_mtu_lookup_insert(&self, fips_addr: crate::FipsAddress, mtu: u16) {
        if let Ok(mut map) = self.path_mtu_lookup.write() {
            map.insert(fips_addr, mtu);
        }
    }

    /// Number of end-to-end sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Iterate over all session entries (for control queries).
    pub(crate) fn session_entries(&self) -> impl Iterator<Item = (&NodeAddr, &SessionEntry)> {
        self.sessions.iter()
    }

    // === Identity Cache ===

    /// Register a node in the identity cache for FipsAddress → NodeAddr lookup.
    pub(crate) fn register_identity(
        &mut self,
        node_addr: NodeAddr,
        pubkey: secp256k1::PublicKey,
    ) -> bool {
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&node_addr.as_bytes()[0..15]);
        if let Some(entry) = self.identity_cache.get(&prefix)
            && entry.node_addr == node_addr
            && entry.pubkey == pubkey
        {
            // Endpoint sends pass the same PeerIdentity on every packet. Once
            // validated, avoid re-deriving NodeAddr from the public key in the
            // data path; that hash showed up in macOS sender profiles.
            return true;
        }

        let (xonly, _) = pubkey.x_only_public_key();
        let derived_node_addr = NodeAddr::from_pubkey(&xonly);
        if derived_node_addr != node_addr {
            debug!(
                claimed_node_addr = %node_addr,
                derived_node_addr = %derived_node_addr,
                "Rejected identity cache entry with mismatched public key"
            );
            return false;
        }

        let now_ms = Self::now_ms();
        if let Some(entry) = self.identity_cache.get_mut(&prefix)
            && entry.node_addr == node_addr
        {
            entry.pubkey = pubkey;
            entry.last_seen_ms = now_ms;
            return true;
        }

        let npub = encode_npub(&xonly);
        self.identity_cache.insert(
            prefix,
            IdentityCacheEntry::new(node_addr, pubkey, npub, now_ms),
        );
        // LRU eviction
        let max = self.config.node.cache.identity_size;
        if self.identity_cache.len() > max
            && let Some(oldest_key) = self
                .identity_cache
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen_ms)
                .map(|(k, _)| *k)
        {
            self.identity_cache.remove(&oldest_key);
        }
        true
    }

    /// Look up a destination by FipsAddress prefix (bytes 1-15 of the IPv6 address).
    pub(crate) fn lookup_by_fips_prefix(
        &mut self,
        prefix: &[u8; 15],
    ) -> Option<(NodeAddr, secp256k1::PublicKey)> {
        if let Some(entry) = self.identity_cache.get_mut(prefix) {
            entry.last_seen_ms = Self::now_ms(); // LRU touch
            Some((entry.node_addr, entry.pubkey))
        } else {
            None
        }
    }

    /// Check if a node's identity is in the cache (without LRU touch).
    pub(crate) fn has_cached_identity(&self, addr: &NodeAddr) -> bool {
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&addr.as_bytes()[0..15]);
        self.identity_cache.contains_key(&prefix)
    }

    /// Number of identity cache entries.
    pub fn identity_cache_len(&self) -> usize {
        self.identity_cache.len()
    }

    /// Iterate over identity cache entries.
    ///
    /// Returns `(NodeAddr, PublicKey, last_seen_ms)` for each cached identity.
    /// Used by the `show_identity_cache` control query.
    pub fn identity_cache_iter(
        &self,
    ) -> impl Iterator<Item = (&NodeAddr, &secp256k1::PublicKey, u64)> {
        self.identity_cache
            .values()
            .map(|entry| (&entry.node_addr, &entry.pubkey, entry.last_seen_ms))
    }

    /// Configured maximum identity cache size.
    pub fn identity_cache_max(&self) -> usize {
        self.config.node.cache.identity_size
    }

    /// Number of pending discovery lookups.
    pub fn pending_lookup_count(&self) -> usize {
        self.pending_lookups.len()
    }

    /// Iterate over pending discovery lookups for diagnostics.
    pub fn pending_lookups_iter(
        &self,
    ) -> impl Iterator<Item = (&NodeAddr, &handlers::discovery::PendingLookup)> {
        self.pending_lookups.iter()
    }

    /// Number of recent discovery requests tracked.
    pub fn recent_request_count(&self) -> usize {
        self.recent_requests.len()
    }

    /// Count of destinations with queued TUN packets awaiting session setup.
    pub fn pending_tun_destinations(&self) -> usize {
        self.pending_tun_packets.len()
    }

    /// Total TUN packets queued across all destinations.
    pub fn pending_tun_total_packets(&self) -> usize {
        self.pending_tun_packets.values().map(|q| q.len()).sum()
    }

    /// Iterate over retry state for diagnostics.
    pub fn retry_state_iter(&self) -> impl Iterator<Item = (&NodeAddr, &retry::RetryState)> {
        self.retry_pending.iter()
    }

    // === Routing ===

    /// Check if a peer is a tree neighbor (parent or child in the spanning tree).
    ///
    /// Returns true if the peer is our current tree parent, or if the peer
    /// has declared us as their parent (making them our child).
    pub(crate) fn is_tree_peer(&self, peer_addr: &NodeAddr) -> bool {
        // Peer is our parent
        if !self.tree_state.is_root() && self.tree_state.my_declaration().parent_id() == peer_addr {
            return true;
        }
        // Peer is our child (their declaration names us as parent)
        if let Some(decl) = self.tree_state.peer_declaration(peer_addr)
            && decl.parent_id() == self.node_addr()
        {
            return true;
        }
        false
    }

    /// Find next hop for a destination node address.
    ///
    /// Routing priority:
    /// 1. Destination is self → `None` (local delivery)
    /// 2. Destination is a healthy direct peer → that peer, unless a known
    ///    fallback next-hop has a meaningful link-quality advantage.
    /// 3. Reply-learned routes in `reply_learned` mode. These are locally
    ///    observed reverse paths, selected with weighted multipath plus
    ///    periodic coordinate/tree exploration.
    /// 4. Bloom filter candidates with cached dest coords → among peers whose
    ///    bloom filter contains the destination, pick the one that minimizes
    ///    tree distance to the destination, with
    ///    `(link_cost, tree_distance_to_dest, node_addr)` tie-breaking.
    ///    The self-distance check ensures only peers strictly closer to the
    ///    destination than us are considered (prevents routing loops).
    /// 5. Greedy tree routing fallback (requires cached dest coords)
    /// 6. No route → `None`
    ///
    /// Both the bloom filter and tree routing paths require cached destination
    /// coordinates (checked in `coord_cache`). Without coordinates, the node
    /// cannot make loop-free forwarding decisions. The caller should signal
    /// `CoordsRequired` back to the source when `None` is returned for a
    /// non-local destination.
    pub fn find_next_hop(&mut self, dest_node_addr: &NodeAddr) -> Option<&ActivePeer> {
        // 1. Local delivery
        if dest_node_addr == self.node_addr() {
            return None;
        }
        let now_ms = Self::now_ms();
        let direct_session_degraded =
            self.session_direct_path_blocks_direct_payload(dest_node_addr, now_ms);

        let healthy_direct_route = self
            .peers
            .get(dest_node_addr)
            .filter(|peer| peer.is_healthy() && !direct_session_degraded)
            .map(|_| *dest_node_addr);
        if let Some(direct_addr) = healthy_direct_route
            && self
                .peers
                .get(&direct_addr)
                .is_some_and(|peer| peer.link_cost() <= 1.0 + ROUTING_FALLBACK_MIN_COST_ADVANTAGE)
        {
            return self.peers.get(&direct_addr);
        }
        let direct_payload_eligible = healthy_direct_route.is_some();
        let payload_candidate_can_send = |addr: &NodeAddr, peer: &ActivePeer| {
            if addr == dest_node_addr {
                direct_payload_eligible
            } else {
                peer.is_healthy()
            }
        };

        // A healthy direct path is not automatically the best path. A
        // hotspot/NAT hairpin can remain sendable with high RTT or mild loss;
        // in that case a lower-cost mesh next-hop should carry traffic while
        // direct probes continue in the background.
        let fallback_beats_direct = |node: &Self, fallback_addr: NodeAddr| {
            node.route_candidate_beats_direct(healthy_direct_route, fallback_addr)
        };

        let sendable_learned_peers = if self.config.node.routing.mode == RoutingMode::ReplyLearned {
            Some(
                self.peers
                    .iter()
                    .filter(|(addr, peer)| payload_candidate_can_send(addr, peer))
                    .map(|(addr, _)| *addr)
                    .collect::<HashSet<_>>(),
            )
        } else {
            None
        };

        // 3. Optional reply-learned routing. These entries are not peer
        // claims; they are local observations of which peer carried traffic
        // or a verified lookup response back from the destination. Most
        // packets use weighted multipath over learned routes, but periodic
        // fallback exploration lets coord/bloom/tree routes discover better
        // candidates.
        let explore_fallback = sendable_learned_peers.as_ref().is_some_and(|sendable| {
            self.learned_routes.should_explore_fallback(
                dest_node_addr,
                now_ms,
                self.config.node.routing.learned_fallback_explore_interval,
                |addr| sendable.contains(addr),
            )
        });
        if let Some(sendable) = &sendable_learned_peers
            && !explore_fallback
        {
            let eligible = sendable
                .iter()
                .copied()
                .filter(|addr| fallback_beats_direct(self, *addr))
                .collect::<HashSet<_>>();
            if !eligible.is_empty()
                && let Some(next_hop_addr) =
                    self.learned_routes
                        .select_next_hop(dest_node_addr, now_ms, |addr| eligible.contains(addr))
            {
                return self.peers.get(&next_hop_addr);
            }
        }

        // Look up cached destination coordinates (required by both bloom and tree paths).
        let Some(dest_coords) = self
            .coord_cache
            .get_and_touch(dest_node_addr, now_ms)
            .cloned()
        else {
            if (healthy_direct_route.is_none() || explore_fallback)
                && let Some(sendable) = &sendable_learned_peers
                && let Some(next_hop_addr) =
                    self.learned_routes
                        .select_next_hop(dest_node_addr, now_ms, |addr| sendable.contains(addr))
            {
                return self.peers.get(&next_hop_addr);
            }
            if let Some(direct_addr) = healthy_direct_route {
                return self.peers.get(&direct_addr);
            }
            return None;
        };

        // 4. Bloom filter candidates — requires dest_coords for loop-free selection.
        //    If no candidate is strictly closer, fall through to tree routing.
        let coordinate_route_addr = {
            let candidates: Vec<&ActivePeer> = self
                .peers
                .iter()
                .filter(|(addr, peer)| {
                    payload_candidate_can_send(addr, peer) && peer.may_reach(dest_node_addr)
                })
                .map(|(_, peer)| peer)
                .collect();
            if !candidates.is_empty() {
                self.select_best_candidate(&candidates, &dest_coords)
                    .map(|peer| *peer.node_addr())
            } else {
                None
            }
        };
        if let Some(next_hop_addr) = coordinate_route_addr
            && fallback_beats_direct(self, next_hop_addr)
        {
            return self.peers.get(&next_hop_addr);
        }

        // 5. Greedy tree routing fallback
        let tree_route_addr = self.select_tree_payload_candidate(
            &dest_coords,
            dest_node_addr,
            direct_payload_eligible,
        );
        if let Some(next_hop_addr) = tree_route_addr
            && fallback_beats_direct(self, next_hop_addr)
        {
            return self.peers.get(&next_hop_addr);
        }

        if explore_fallback {
            return sendable_learned_peers.as_ref().and_then(|sendable| {
                self.learned_routes
                    .select_next_hop(dest_node_addr, now_ms, |addr| sendable.contains(addr))
                    .and_then(|next_hop_addr| self.peers.get(&next_hop_addr))
            });
        }

        if let Some(direct_addr) = healthy_direct_route {
            return self.peers.get(&direct_addr);
        }

        if let Some(sendable) = &sendable_learned_peers
            && let Some(next_hop_addr) =
                self.learned_routes
                    .select_next_hop(dest_node_addr, now_ms, |addr| sendable.contains(addr))
        {
            return self.peers.get(&next_hop_addr);
        }

        None
    }

    pub(in crate::node) fn find_transit_next_hop(
        &mut self,
        dest_node_addr: &NodeAddr,
        previous_hop: &NodeAddr,
    ) -> Option<NodeAddr> {
        if dest_node_addr == self.node_addr() {
            return None;
        }

        if dest_node_addr != previous_hop
            && self
                .peers
                .get(dest_node_addr)
                .is_some_and(|peer| peer.is_healthy())
        {
            return Some(*dest_node_addr);
        }

        let next_hop_addr = *self.find_next_hop(dest_node_addr)?.node_addr();
        if &next_hop_addr == previous_hop {
            self.record_route_failure(*dest_node_addr, next_hop_addr);
            return None;
        }
        Some(next_hop_addr)
    }

    fn route_candidate_beats_direct(
        &self,
        healthy_direct_route: Option<NodeAddr>,
        candidate_addr: NodeAddr,
    ) -> bool {
        let Some(direct_addr) = healthy_direct_route else {
            return true;
        };
        if candidate_addr == direct_addr {
            return false;
        }

        let Some(direct) = self.peers.get(&direct_addr) else {
            return true;
        };
        let Some(candidate) = self.peers.get(&candidate_addr) else {
            return false;
        };
        if !candidate.is_healthy() {
            return false;
        }

        let direct_cost = direct.link_cost();
        let candidate_cost = candidate.link_cost();
        candidate_cost + ROUTING_FALLBACK_MIN_COST_ADVANTAGE < direct_cost
    }

    fn select_tree_payload_candidate(
        &self,
        dest_coords: &crate::tree::TreeCoordinate,
        direct_dest: &NodeAddr,
        direct_payload_eligible: bool,
    ) -> Option<NodeAddr> {
        if self.tree_state.my_coords().root_id() != dest_coords.root_id() {
            return None;
        }

        let my_distance = self.tree_state.my_coords().distance_to(dest_coords);
        let mut best: Option<(NodeAddr, usize)> = None;

        for (peer_addr, peer) in &self.peers {
            if peer_addr == direct_dest {
                if !direct_payload_eligible {
                    continue;
                }
            } else if !peer.is_healthy() {
                continue;
            }

            let Some(peer_coords) = self.tree_state.peer_coords(peer_addr) else {
                continue;
            };
            let distance = peer_coords.distance_to(dest_coords);
            if distance >= my_distance {
                continue;
            }

            let dominated = match &best {
                None => true,
                Some((best_id, best_dist)) => {
                    distance < *best_dist || (distance == *best_dist && peer_addr < best_id)
                }
            };
            if dominated {
                best = Some((*peer_addr, distance));
            }
        }

        best.map(|(peer_addr, _)| peer_addr)
    }

    pub(in crate::node) fn session_direct_path_is_degraded(
        &mut self,
        dest: &NodeAddr,
        now_ms: u64,
    ) -> bool {
        match self.session_direct_degraded_until_ms.get(dest).copied() {
            Some(until_ms) if until_ms > now_ms => true,
            Some(_) => {
                self.session_direct_degraded_until_ms.remove(dest);
                false
            }
            None => false,
        }
    }

    pub(in crate::node) fn session_direct_path_blocks_direct_payload(
        &mut self,
        dest: &NodeAddr,
        now_ms: u64,
    ) -> bool {
        self.session_direct_path_is_degraded(dest, now_ms)
            && !self.active_peer_uses_configured_static_udp_path(dest)
    }

    pub(in crate::node) fn mark_session_direct_path_degraded(
        &mut self,
        dest: NodeAddr,
        now_ms: u64,
    ) -> bool {
        let until_ms = now_ms.saturating_add(SESSION_DIRECT_DEGRADED_HOLD_MS);
        let entry = self
            .session_direct_degraded_until_ms
            .entry(dest)
            .or_insert(0);
        let was_degraded = *entry > now_ms;
        *entry = (*entry).max(until_ms);
        !was_degraded
    }

    pub(in crate::node) fn clear_session_direct_path_degraded(&mut self, dest: &NodeAddr) -> bool {
        self.session_direct_degraded_until_ms.remove(dest).is_some()
    }

    pub(in crate::node) fn learn_reverse_route(
        &mut self,
        destination: NodeAddr,
        next_hop: NodeAddr,
    ) {
        if self.config.node.routing.mode != RoutingMode::ReplyLearned
            || destination == *self.node_addr()
        {
            return;
        }
        let now_ms = Self::now_ms();
        self.learned_routes.learn(
            destination,
            next_hop,
            now_ms,
            self.config.node.routing.learned_ttl_secs,
            self.config.node.routing.max_learned_routes_per_dest,
        );
    }

    pub(in crate::node) fn record_route_failure(
        &mut self,
        destination: NodeAddr,
        next_hop: NodeAddr,
    ) {
        if self.config.node.routing.mode != RoutingMode::ReplyLearned {
            return;
        }
        self.learned_routes.record_failure(&destination, &next_hop);
    }

    pub(crate) fn learned_route_table_snapshot(&self, now_ms: u64) -> LearnedRouteTableSnapshot {
        self.learned_routes.snapshot(now_ms)
    }

    pub(in crate::node) fn purge_learned_routes(&mut self, now_ms: u64) {
        self.learned_routes.purge_expired(now_ms);
    }

    /// Select the best peer from a set of bloom filter candidates.
    ///
    /// Uses distance from each candidate's tree coordinates to the destination
    /// as the primary metric (after link_cost). Only selects peers that are
    /// strictly closer to the destination than we are (self-distance check
    /// prevents routing loops).
    ///
    /// Ordering: `(link_cost, distance_to_dest, node_addr)`.
    fn select_best_candidate<'a>(
        &'a self,
        candidates: &[&'a ActivePeer],
        dest_coords: &crate::tree::TreeCoordinate,
    ) -> Option<&'a ActivePeer> {
        let my_distance = self.tree_state.my_coords().distance_to(dest_coords);

        let mut best: Option<(&ActivePeer, f64, usize)> = None;

        for &candidate in candidates {
            if !candidate.can_send() {
                continue;
            }

            let cost = candidate.link_cost();

            let dist = self
                .tree_state
                .peer_coords(candidate.node_addr())
                .map(|pc| pc.distance_to(dest_coords))
                .unwrap_or(usize::MAX);

            // Self-distance check: only consider peers strictly closer
            // to the destination than we are (prevents routing loops)
            if dist >= my_distance {
                continue;
            }

            let dominated = match &best {
                None => true,
                Some((_, best_cost, best_dist)) => {
                    cost < *best_cost
                        || (cost == *best_cost && dist < *best_dist)
                        || (cost == *best_cost
                            && dist == *best_dist
                            && candidate.node_addr() < best.as_ref().unwrap().0.node_addr())
                }
            };

            if dominated {
                best = Some((candidate, cost, dist));
            }
        }

        best.map(|(peer, _, _)| peer)
    }

    /// Check if a destination is in any peer's bloom filter.
    pub fn destination_in_filters(&self, dest: &NodeAddr) -> Vec<&ActivePeer> {
        self.peers.values().filter(|p| p.may_reach(dest)).collect()
    }

    /// Get the TUN packet sender channel.
    ///
    /// Returns None if TUN is not active or the node hasn't been started.
    pub fn tun_tx(&self) -> Option<&TunTx> {
        self.tun_tx.as_ref()
    }

    /// Attach app-owned packet I/O for embedded operation without a system TUN.
    ///
    /// This must be called before [`Node::start`] and requires `tun.enabled =
    /// false`. Outbound packets sent to the returned sender are processed by the
    /// normal session pipeline. Inbound packets delivered by FIPS sessions are
    /// sent to the returned receiver with source attribution.
    pub fn attach_external_packet_io(
        &mut self,
        capacity: usize,
    ) -> Result<ExternalPacketIo, NodeError> {
        if self.state != NodeState::Created {
            return Err(NodeError::Config(ConfigError::Validation(
                "external packet I/O must be attached before node start".to_string(),
            )));
        }
        if self.config.tun.enabled {
            return Err(NodeError::Config(ConfigError::Validation(
                "external packet I/O requires tun.enabled=false".to_string(),
            )));
        }

        let capacity = capacity.max(1);
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(capacity);
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(capacity);
        self.tun_outbound_rx = Some(outbound_rx);
        self.external_packet_tx = Some(inbound_tx);

        Ok(ExternalPacketIo {
            outbound_tx,
            inbound_rx,
        })
    }

    /// Attach app-owned endpoint data I/O for embedded operation.
    ///
    /// Commands sent to the returned sender are processed by the node RX loop.
    /// Incoming endpoint data is emitted as source-attributed events.
    pub(crate) fn attach_endpoint_data_io(
        &mut self,
        capacity: usize,
    ) -> Result<EndpointDataIo, NodeError> {
        if self.state != NodeState::Created {
            return Err(NodeError::Config(ConfigError::Validation(
                "endpoint data I/O must be attached before node start".to_string(),
            )));
        }

        let command_capacity = endpoint_data_command_capacity(capacity);
        let (command_tx, command_rx) = tokio::sync::mpsc::channel(command_capacity);
        // Inbound endpoint-data events use an unbounded channel — see
        // `EndpointDataIo::event_rx` docs for the rationale (kills the
        // per-packet semaphore + the cross-task relay task that used to
        // sit on top of this channel).
        let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
        self.endpoint_command_rx = Some(command_rx);
        self.endpoint_event_tx = Some(event_tx.clone());

        Ok(EndpointDataIo {
            command_tx,
            event_rx,
            event_tx,
        })
    }

    pub(crate) fn pubkey_for_node_addr(&self, addr: &NodeAddr) -> Option<secp256k1::PublicKey> {
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&addr.as_bytes()[0..15]);
        self.identity_cache
            .get(&prefix)
            .filter(|entry| &entry.node_addr == addr)
            .map(|entry| entry.pubkey)
    }

    pub(crate) fn npub_for_node_addr(&self, addr: &NodeAddr) -> Option<String> {
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&addr.as_bytes()[0..15]);
        self.identity_cache
            .get(&prefix)
            .filter(|entry| &entry.node_addr == addr)
            .map(|entry| entry.npub.clone())
    }

    pub(in crate::node) fn deliver_external_ipv6_packet(
        &self,
        src_addr: &NodeAddr,
        packet: Vec<u8>,
    ) {
        let Some(external_packet_tx) = &self.external_packet_tx else {
            return;
        };
        if packet.len() < 40 {
            return;
        }
        let Ok(destination) = FipsAddress::from_slice(&packet[24..40]) else {
            return;
        };
        let delivered = NodeDeliveredPacket {
            source_node_addr: *src_addr,
            source_npub: self.npub_for_node_addr(src_addr),
            destination,
            packet,
        };
        if let Err(error) = external_packet_tx.try_send(delivered) {
            debug!(error = %error, "Failed to deliver packet to external app sink");
        }
    }

    // === Sending ===

    /// Encrypt and send a link-layer message to an authenticated peer.
    ///
    /// The plaintext should include the message type byte followed by the
    /// message-specific payload (e.g., `[0x50, reason]` for Disconnect).
    ///
    /// The send path prepends a 4-byte session-relative timestamp (inner
    /// header) before encryption. The full 16-byte outer header is used
    /// as AAD for the AEAD construction.
    ///
    /// This is the standard path for sending any link-layer control message
    /// to a peer over their encrypted Noise session.
    pub(super) async fn send_encrypted_link_message(
        &mut self,
        node_addr: &NodeAddr,
        plaintext: &[u8],
    ) -> Result<(), NodeError> {
        self.send_encrypted_link_message_with_ce(node_addr, plaintext, false)
            .await
    }

    /// Update one peer's local-outbound-broken signal from a `transport.send`
    /// outcome. Sets a per-peer timestamp on local-side io errors
    /// (NetworkUnreachable / HostUnreachable / AddrNotAvailable); clears that
    /// peer on success. The reaper consults this in `check_link_heartbeats` to
    /// switch only that peer to `fast_link_dead_timeout_secs`.
    pub(in crate::node) fn note_local_send_outcome(
        &mut self,
        node_addr: &NodeAddr,
        result: &Result<usize, TransportError>,
    ) {
        match result {
            Ok(_) => {
                self.local_send_failure_at_by_peer.remove(node_addr);
            }
            Err(error) if error.is_local_route_unavailable() => {
                self.local_send_failure_at_by_peer
                    .insert(*node_addr, std::time::Instant::now());
            }
            Err(_) => {}
        }
    }

    /// Return the active dead-timeout for one peer after considering recent
    /// local route failures. The fast-dead signal is intentionally short-lived:
    /// on the UDP worker path a send call can return before the kernel result
    /// is observed, so a stale route error must not compress liveness for the
    /// whole normal dead-timeout window.
    pub(in crate::node) fn local_send_failure_dead_timeout_for_peer(
        &self,
        node_addr: &NodeAddr,
        now: std::time::Instant,
        dead_timeout: std::time::Duration,
        fast_dead_timeout: std::time::Duration,
    ) -> std::time::Duration {
        match self.local_send_failure_at_by_peer.get(node_addr).copied() {
            Some(t) if now.duration_since(t) <= LOCAL_SEND_FAILURE_FAST_DEAD_WINDOW => {
                fast_dead_timeout.min(dead_timeout)
            }
            None => dead_timeout,
            Some(_) => dead_timeout,
        }
    }

    pub(in crate::node) fn purge_expired_local_send_failures(&mut self, now: std::time::Instant) {
        self.local_send_failure_at_by_peer
            .retain(|_, at| now.duration_since(*at) <= LOCAL_SEND_FAILURE_FAST_DEAD_WINDOW);
    }

    pub(in crate::node) fn mark_rx_loop_maintenance_timeout(&mut self) {
        self.last_rx_loop_maintenance_timeout_at = Some(std::time::Instant::now());
    }

    pub(in crate::node) fn rx_loop_maintenance_timed_out_recently(&self) -> bool {
        let Some(t) = self.last_rx_loop_maintenance_timeout_at else {
            return false;
        };
        let grace = std::time::Duration::from_secs(self.config.node.link_dead_timeout_secs.max(1));
        std::time::Instant::now().duration_since(t) <= grace
    }

    /// Like `send_encrypted_link_message` but allows setting the FMP CE flag.
    ///
    /// Used by the forwarding path to relay congestion signals hop-by-hop.
    pub(super) async fn send_encrypted_link_message_with_ce(
        &mut self,
        node_addr: &NodeAddr,
        plaintext: &[u8],
        ce_flag: bool,
    ) -> Result<(), NodeError> {
        let peer = self
            .peers
            .get_mut(node_addr)
            .ok_or(NodeError::PeerNotFound(*node_addr))?;

        let their_index = peer.their_index().ok_or_else(|| NodeError::SendFailed {
            node_addr: *node_addr,
            reason: "no their_index".into(),
        })?;
        let transport_id = peer.transport_id().ok_or_else(|| NodeError::SendFailed {
            node_addr: *node_addr,
            reason: "no transport_id".into(),
        })?;
        let remote_addr = peer
            .current_addr()
            .cloned()
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *node_addr,
                reason: "no current_addr".into(),
            })?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let connected_socket = peer.connected_udp();

        // Prepend 4-byte session-relative timestamp (inner header)
        let timestamp_ms = peer.session_elapsed_ms();

        // MMP: read spin bit value before entering session borrow
        let sp_flag = peer.mmp().map(|mmp| mmp.spin_bit.tx_bit()).unwrap_or(false);
        let mut flags = if sp_flag { FLAG_SP } else { 0 };
        if ce_flag {
            flags |= FLAG_CE;
        }
        if peer.current_k_bit() {
            flags |= FLAG_KEY_EPOCH;
        }

        let session = peer
            .noise_session_mut()
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *node_addr,
                reason: "no noise session".into(),
            })?;

        // Build 16-byte outer header upfront. The inner-plaintext
        // layout is `[ts:4 LE][plaintext...]`, so its length is exactly
        // `INNER_TS_LEN + plaintext.len()` — no need to build the Vec
        // just to measure it. The worker path uses this length to size
        // the wire buffer directly; the legacy path below still
        // materialises a separate `inner_plaintext` Vec for the inline
        // encrypt-and-send call.
        const INNER_TS_LEN: usize = 4;
        let counter = session.current_send_counter();
        let inner_len = INNER_TS_LEN + plaintext.len();
        let payload_len = inner_len as u16;
        let header = build_established_header(their_index, counter, flags, payload_len);

        // **Unix UDP send fast path.** On Unix, the encrypt-worker pool
        // is spawned at lifecycle start (workers = num_cpus) in
        // production, so this branch is taken for every authentic send on
        // every UDP-transported established session. The AEAD work +
        // sendmsg syscall run on a dedicated OS thread; the rx_loop only
        // builds the wire buffer + reserves the counter inline.
        //
        // Other transport kinds (BLE, TCP, sim, ethernet) fall
        // through to the inline encrypt + transport.send path
        // below — those don't have raw-fd / sendmmsg / UDP_GSO
        // benefits to expose through the worker pool, so the simpler
        // synchronous send is the right shape for them.
        //
        // Windows intentionally stays on the inline tokio UDP send path:
        // lifecycle::start does not spawn these raw-fd workers there, and
        // tests may still set `encrypt_workers` manually.
        //
        // The `encrypt_workers.is_some()` check below is true in Unix
        // production (lifecycle::start spawns the pool); it stays checked
        // rather than `expect()`-ed because unit tests construct `Node`
        // without calling `start()`.
        let transport_for_send = self
            .transports
            .get(&transport_id)
            .ok_or(NodeError::TransportNotFound(transport_id))?;
        match transport_for_send.connection_state(&remote_addr) {
            ConnectionState::Connected => {}
            other => {
                if matches!(other, ConnectionState::None) {
                    let _ = transport_for_send.connect(&remote_addr).await;
                }
                return Err(NodeError::SendFailed {
                    node_addr: *node_addr,
                    reason: format!("transport connection not ready: {:?}", other),
                });
            }
        }
        #[cfg(unix)]
        {
            let is_udp = matches!(transport_for_send, TransportHandle::Udp(_));
            if let Some(workers) = self.encrypt_workers.as_ref().cloned()
                && is_udp
                && let Some(cipher_clone) = session.send_cipher_clone()
            {
                // Reserve the counter on the session so subsequent
                // sends don't reuse it. `current_send_counter` only
                // peeks; we advance via `take_send_counter`.
                let reserved_counter =
                    session
                        .take_send_counter()
                        .map_err(|e| NodeError::SendFailed {
                            node_addr: *node_addr,
                            reason: format!("counter reservation failed: {}", e),
                        })?;
                debug_assert_eq!(reserved_counter, counter);
                // Re-derive the header with the now-locked-in counter
                // value (same value, but the call sequence is more
                // explicit).
                let header =
                    build_established_header(their_index, reserved_counter, flags, payload_len);
                let transport = transport_for_send;
                // Snapshot the per-peer connected UDP socket before
                // resolving the fallback address. On the established
                // steady-state path this socket already carries the
                // kernel peer address, so re-parsing the configured
                // transport address and touching the DNS cache on every
                // packet is pure overhead on the sender hot path.
                let send_target = {
                    if let TransportHandle::Udp(udp) = transport {
                        let socket_addr = {
                            #[cfg(any(target_os = "linux", target_os = "macos"))]
                            {
                                match connected_socket.as_ref() {
                                    Some(socket) => Some(socket.peer_addr()),
                                    None => udp.resolve_for_off_task(&remote_addr).await.ok(),
                                }
                            }
                            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                            {
                                udp.resolve_for_off_task(&remote_addr).await.ok()
                            }
                        };
                        match (udp.async_socket(), socket_addr) {
                            (Some(socket), Some(socket_addr)) => Some((socket, socket_addr)),
                            _ => None,
                        }
                    } else {
                        None
                    }
                };
                if let Some((socket, socket_addr)) = send_target {
                    // Build the wire buffer **directly** from
                    // `plaintext` with a single allocation:
                    //   `[16 header][4 ts][plaintext...]` with
                    // +16 trailing capacity for the AEAD tag.
                    // The worker seals `wire_buf[16..]` in
                    // place and appends the tag — no second
                    // alloc, no second memcpy.
                    //
                    // Previous design built `inner_plaintext`
                    // via `prepend_inner_header` (1 alloc + 1
                    // copy) and then let the worker memcpy
                    // header + plaintext into a fresh Vec
                    // (another alloc + copy). At ~100 kpps the
                    // saved alloc/copy is ~150 MB/sec of memory
                    // bandwidth on the hot rx_loop + worker.
                    let wire_capacity = ESTABLISHED_HEADER_SIZE + inner_len + 16;
                    let mut wire_buf = Vec::with_capacity(wire_capacity);
                    wire_buf.extend_from_slice(&header);
                    wire_buf.extend_from_slice(&timestamp_ms.to_le_bytes());
                    wire_buf.extend_from_slice(plaintext);
                    let predicted_bytes = wire_capacity;
                    // Stats / MMP update inline — predicted size
                    // is exact for ChaCha20-Poly1305 (tag is
                    // constant 16 bytes). When `connected_socket` is
                    // `Some`, the worker sends on it without a
                    // destination sockaddr — the kernel skips the
                    // per-packet sockaddr + route + neighbor resolve.
                    if let Some(peer) = self.peers.get_mut(node_addr) {
                        peer.link_stats_mut().record_sent(predicted_bytes);
                        if let Some(mmp) = peer.mmp_mut() {
                            mmp.sender
                                .record_sent(reserved_counter, timestamp_ms, predicted_bytes);
                        }
                    }
                    let scheduling_weight = self.send_weight_for_peer(node_addr);
                    let traffic_class = classify_fmp_plaintext_traffic(plaintext);
                    workers.dispatch(self::encrypt_worker::FmpSendJob {
                        cipher: cipher_clone,
                        counter: reserved_counter,
                        wire_buf,
                        fsp_seal: None,
                        socket,
                        dest_addr: socket_addr,
                        #[cfg(any(target_os = "linux", target_os = "macos"))]
                        connected_socket,
                        bulk_endpoint_data: traffic_class.bulk_endpoint_data,
                        drop_on_backpressure: traffic_class.drop_on_backpressure,
                        scheduling_weight,
                        queued_at: crate::perf_profile::stamp(),
                    });
                    return Ok(());
                }
            }
        }

        // Inline (legacy) path: encrypt + send on the rx_loop.
        // Build the inner plaintext lazily here — the worker path
        // above never reaches this point, so the prepend_inner_header
        // alloc is avoided in the fast path.
        let inner_plaintext = prepend_inner_header(timestamp_ms, plaintext);
        // Encrypt with AAD binding to the outer header
        let ciphertext = {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpEncrypt);
            session
                .encrypt_with_aad(&inner_plaintext, &header)
                .map_err(|e| NodeError::SendFailed {
                    node_addr: *node_addr,
                    reason: format!("encryption failed: {}", e),
                })?
        };

        let wire_packet = build_encrypted(&header, &ciphertext);

        // Re-borrow peer for stats update after sending
        let send_result = {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);
            let transport = self
                .transports
                .get(&transport_id)
                .ok_or(NodeError::TransportNotFound(transport_id))?;
            transport.send(&remote_addr, &wire_packet).await
        };
        self.note_local_send_outcome(node_addr, &send_result);
        let bytes_sent = send_result.map_err(|e| match e {
            TransportError::MtuExceeded { packet_size, mtu } => NodeError::MtuExceeded {
                node_addr: *node_addr,
                packet_size,
                mtu,
            },
            other => NodeError::SendFailed {
                node_addr: *node_addr,
                reason: format!("transport send: {}", other),
            },
        })?;

        // Update send statistics
        if let Some(peer) = self.peers.get_mut(node_addr) {
            peer.link_stats_mut().record_sent(bytes_sent);
            // MMP: record sent frame for sender report generation
            if let Some(mmp) = peer.mmp_mut() {
                mmp.sender.record_sent(counter, timestamp_ms, bytes_sent);
            }
        }

        Ok(())
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("node_addr", self.node_addr())
            .field("state", &self.state)
            .field("is_leaf_only", &self.is_leaf_only)
            .field("connections", &self.connection_count())
            .field("peers", &self.peer_count())
            .field("links", &self.link_count())
            .field("transports", &self.transport_count())
            .finish()
    }
}
