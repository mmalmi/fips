//! FIPS Node Entity
//!
//! Top-level structure representing a running FIPS instance. The Node
//! holds all state required for mesh routing: identity, tree state,
//! Bloom filters, coordinate caches, transports, links, and peers.

mod accessors_impl;
mod acl;
mod bloom;
mod core_impl;
mod dataplane_integration;
mod endpoint_channels;
mod endpoint_event;
mod endpoint_service;
mod endpoint_traffic;
mod error;
mod handlers;
mod identity_cache;
mod io_impl;
mod lifecycle;
mod link_registry;
mod peer_lifecycle;
mod peer_runtime;
mod rate_limit;
#[cfg(test)]
mod recent_requests;
mod retry;
mod route_impl;
pub(crate) mod session;
mod session_access_impl;
mod session_registry;
pub(crate) mod session_wire;
mod state;
pub(crate) mod stats;
pub(crate) mod stats_history;
mod support_state;
#[cfg(test)]
mod tests;
mod tree;
pub(crate) mod wire;

pub use endpoint_event::ExternalPacketIo;
pub use error::NodeError;
pub use identity_cache::NodeDeliveredPacket;
pub use state::NodeState;

pub(crate) use crate::proto::lookup_state::{RecentDiscoveryRequests, RecentResponseForward};
pub(crate) use endpoint_channels::{
    ENDPOINT_STALE_DATA_DROP_MS, EndpointDataBatchRx, EndpointDataBatchTx, EndpointDataPayload,
    NodeEndpointControlCommand, NodeEndpointDataBatch, endpoint_data_batch_channel,
};
pub(in crate::node) use endpoint_event::EndpointEventRuntime;
pub(crate) use endpoint_event::{
    EndpointDataDelivery, EndpointDataIo, EndpointDirectSink, EndpointEventReceiver,
    EndpointEventSender, FipsEndpointDirectPacketRunMeta, NodeEndpointEvent, NodeEndpointPeer,
    NodeEndpointRelayStatus, UpdatePeersOutcome,
};
pub use endpoint_event::{
    FIPS_ENDPOINT_DIRECT_PACKET_QUEUE_MAX_PACKETS, FIPS_ENDPOINT_DIRECT_PACKET_RUN_MAX_PACKETS,
    FipsEndpointDirectDeliveryError, FipsEndpointDirectPacketBatch, FipsEndpointDirectPacketRun,
    FipsEndpointDirectReceiver, FipsEndpointDirectSink,
};
pub(in crate::node) use endpoint_service::EndpointServiceRuntime;
pub(crate) use endpoint_service::{
    EndpointServiceDatagramDelivery, EndpointServiceEventReceiver, EndpointServiceEventSender,
    NodeEndpointServiceEvent,
};
pub(crate) use endpoint_traffic::{PendingEndpointData, PendingSessionTrafficQueues};
pub(in crate::node) use identity_cache::IdentityCache;
pub(in crate::node) use link_registry::{LinkRegistry, PendingConnect, TransportDropTracker};
pub(in crate::node) use peer_lifecycle::*;
pub(in crate::node) use peer_runtime::*;
pub(in crate::node) use session_registry::*;
pub(in crate::node) use support_state::{
    BootstrapTransports, DiscoveryFallbackTransit, LocalSendFailures, SessionDirectDegradation,
};

use self::rate_limit::HandshakeRateLimiter;
use self::wire::{FLAG_CE, FLAG_KEY_EPOCH};
use crate::bloom::{BloomFilter, BloomState};
use crate::cache::CoordCache;
use crate::config::{NostrDiscoveryPolicy, PeerConfig, RoutingMode};
use crate::dataplane::{
    AdmissionConfig, DATAPLANE_TRANSPORT_SEND_BATCH_PACKETS, DataplaneDirectFspSources,
    DataplaneFastIngressRx, DataplaneLiveNode, DataplaneLiveNodeTurn,
};
use crate::node::session::SessionEntry;
use crate::node::session_wire::{FSP_PHASE_ESTABLISHED, FspCommonPrefix};
use crate::peer::{ActivePeer, PeerConnection};
use crate::proto::lookup_limits::{DiscoveryBackoff, DiscoveryForwardRateLimiter};
use crate::proto::rate_limit::RoutingErrorRateLimiter;
use crate::proto::routing::{LearnedRouteTable, LearnedRouteTableSnapshot};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::transport::ethernet::EthernetTransport;
use crate::transport::tcp::TcpTransport;
use crate::transport::tor::TorTransport;
use crate::transport::udp::UdpTransport;
#[cfg(feature = "webrtc-transport")]
use crate::transport::webrtc::WebRtcTransport;
use crate::transport::{
    Link, LinkId, PacketRx, PacketTx, TransportAddr, TransportError, TransportHandle, TransportId,
};
use crate::tree::TreeState;
use crate::upper::hosts::HostMap;
use crate::upper::icmp_rate_limit::IcmpRateLimiter;
use crate::upper::tun::{TunError, TunOutboundRx, TunState, TunTx};
use crate::utils::index::{IndexAllocator, SessionIndex};
use crate::{
    Config, ConfigError, FipsAddress, Identity, IdentityError, LinkMessageType, NodeAddr,
    PeerIdentity, encode_npub,
};
use rand::Rng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex as StdMutex};
use std::thread::JoinHandle;
use thiserror::Error;
use tracing::{debug, warn};

type DataplaneNode = DataplaneLiveNode;

const LOCAL_SEND_FAILURE_FAST_DEAD_WINDOW: std::time::Duration = std::time::Duration::from_secs(3);
#[cfg(test)]
pub(crate) const ENDPOINT_EVENT_TEST_PAYLOAD_LEN: usize = 512;
const SESSION_DIRECT_DEGRADED_HOLD_MS: u64 = 20_000;
const SESSION_DIRECT_DEGRADED_MIN_SAMPLE: u64 = 16;
const SESSION_DIRECT_DEGRADED_LOSS_THRESHOLD: f64 = 0.08;
const SESSION_DIRECT_RECOVERY_LOSS_THRESHOLD: f64 = 0.02;
const SESSION_DIRECT_MIN_EXCLUSIVE_TRUST_MS: u64 = 6_500;
const ROUTING_FALLBACK_MIN_COST_ADVANTAGE: f64 = 0.25;
const ENDPOINT_EVENT_BACKLOG_HIGH_WATER: usize = 4096;

/// Half-range of the symmetric jitter applied to per-session rekey timers.
///
/// Each FMP/FSP session draws an offset uniformly from
/// `[-REKEY_JITTER_SECS, +REKEY_JITTER_SECS]` seconds at construction and
/// after each cutover. This preserves the configured mean interval while
/// reducing dual-initiation bursts in symmetric-start meshes.
pub(crate) const REKEY_JITTER_SECS: i64 = 15;

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
/// The link registry dispatches incoming packets to the right connection before
/// authentication completes.
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
    session_direct_degradation: SessionDirectDegradation,
    /// Recent discovery requests for dedup and reverse-path forwarding.
    recent_requests: RecentDiscoveryRequests,
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
    transport_drops: TransportDropTracker,
    /// Per-transport wildcard socket-local drop tracking for observability.
    transport_socket_drops: TransportDropTracker,
    /// Per-transport Linux namespace receive-buffer error tracking for observability.
    transport_namespace_drops: TransportDropTracker,
    /// Active links plus reverse address dispatch index.
    links: LinkRegistry,

    // === Packet Channel ===
    /// Packet sender for transports.
    packet_tx: Option<PacketTx>,
    /// Packet receiver (for event loop).
    packet_rx: Option<PacketRx>,

    // === Dataplane ===
    /// Canonical dataplane state owned by the node.
    dataplane: DataplaneNode,
    /// Control ingress surfaced while a synchronous dataplane send is waiting.
    deferred_dataplane_control_turns: VecDeque<DataplaneLiveNodeTurn>,
    /// Transit sends admitted to dataplane whose terminal receipts may arrive
    /// on a later receive-loop turn.
    deferred_session_forwards: handlers::forwarding::DeferredSessionForwards,
    /// Pre-routed established FMP packets accepted directly from UDP receive.
    dataplane_fast_ingress_rx: Option<DataplaneFastIngressRx>,
    /// Direct-FSP transport-address classifier published to packet ingress.
    dataplane_direct_fsp_sources: DataplaneDirectFspSources,
    /// True when peer path state changed since the classifier was built.
    dataplane_direct_fsp_sources_dirty: bool,
    /// Maximum same-destination UDP payloads sent in one dataplane batch.
    dataplane_transport_send_batch_packets: usize,

    // === Peer Lifecycle ===
    /// Pending handshake connections plus authenticated peers.
    peers: PeerLifecycleRegistry,

    // === End-to-End Sessions ===
    /// Session table for end-to-end encrypted sessions.
    /// Keyed by remote NodeAddr.
    sessions: SessionRegistry,

    // === Identity Cache ===
    /// Maps FipsAddress prefix bytes (bytes 1-15) to cached peer identity data.
    /// Enables reverse lookup from IPv6 destination to session/routing identity.
    identity_cache: IdentityCache,

    // === Pending TUN Packets ===
    /// TUN packets and endpoint payloads queued while waiting for session establishment.
    pending_session_traffic: PendingSessionTrafficQueues,
    // === Pending Discovery Lookups ===
    /// Tracks in-flight discovery lookups and owns dedupe/cap admission.
    pending_lookups: handlers::discovery::PendingDiscoveryLookups,

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
    /// Endpoint control receiver used by embedded/no-daemon integrations.
    endpoint_control_rx: Option<tokio::sync::mpsc::Receiver<NodeEndpointControlCommand>>,
    /// Endpoint data batch receiver used by embedded/no-daemon integrations.
    endpoint_data_rx: Option<EndpointDataBatchRx>,
    /// Endpoint data event delivery runtime used by embedded/no-daemon integrations.
    endpoint_events: EndpointEventRuntime,
    /// Registered FSP DataPacket services and their app delivery queue.
    endpoint_services: EndpointServiceRuntime,
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
    /// Pending outbound handshakes by our sender_idx.
    /// Tracks which LinkId corresponds to which session index.
    pending_outbound: PendingOutboundHandshakes,

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
    retry_pending: retry::PendingRouteRetries,

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
    /// Per-peer UDP transports adopted from NAT traversal handoff plus the
    /// originating peer npub for protocol-mismatch cooldown bookkeeping.
    bootstrap_transports: BootstrapTransports,
    /// Peers that should not be used as reply-learned fallback transit for
    /// other destinations. Direct lookups to the peer are still permitted.
    discovery_fallback_transit: DiscoveryFallbackTransit,

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
    local_send_failures: LocalSendFailures,
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
    configured_peer_send_weights: ConfiguredPeerSendWeights,

    /// Reloadable peer ACL state from standard allow/deny files.
    peer_acl: acl::PeerAclReloader,

    // === Host Map ===
    /// Static hostname → npub mapping for DNS resolution.
    /// Built at construction from peer aliases and /etc/fips/hosts.
    host_map: Arc<HostMap>,
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
