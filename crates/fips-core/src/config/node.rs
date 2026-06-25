//! Node configuration subsections.
//!
//! All the `node.*` configuration parameters: resource limits, rate limiting,
//! retry/backoff, cache sizing, discovery, spanning tree, bloom filters,
//! session management, and internal buffers.

use serde::{Deserialize, Serialize};

use super::IdentityConfig;
use crate::mmp::{DEFAULT_LOG_INTERVAL_SECS, DEFAULT_OWD_WINDOW_SIZE, MmpConfig, MmpMode};

// ============================================================================
// Node Configuration Subsections
// ============================================================================

/// Resource limits (`node.limits.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Max handshake-phase connections (`node.limits.max_connections`).
    #[serde(default = "LimitsConfig::default_max_connections")]
    pub max_connections: usize,
    /// Max authenticated peers (`node.limits.max_peers`).
    #[serde(default = "LimitsConfig::default_max_peers")]
    pub max_peers: usize,
    /// Max active links (`node.limits.max_links`).
    #[serde(default = "LimitsConfig::default_max_links")]
    pub max_links: usize,
    /// Max pending inbound handshakes (`node.limits.max_pending_inbound`).
    #[serde(default = "LimitsConfig::default_max_pending_inbound")]
    pub max_pending_inbound: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 256,
            max_peers: 128,
            max_links: 256,
            max_pending_inbound: 1000,
        }
    }
}

impl LimitsConfig {
    fn default_max_connections() -> usize {
        256
    }
    fn default_max_peers() -> usize {
        128
    }
    fn default_max_links() -> usize {
        256
    }
    fn default_max_pending_inbound() -> usize {
        1000
    }
}

/// Connected UDP fast-path configuration (`node.connected_udp.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedUdpConfig {
    /// Enable per-peer connected UDP sockets (`node.connected_udp.enabled`).
    ///
    /// Connected UDP stays default-on for Linux and default-off for macOS,
    /// where live mobile/NAT testing has shown the `SO_REUSEPORT` listener
    /// group can destabilize the wildcard receive path. Use this explicit
    /// config field for platform or operator policy instead of runtime env
    /// A/B selection.
    #[serde(default = "ConnectedUdpConfig::default_enabled")]
    pub enabled: bool,

    /// Maximum peers that may have connected UDP sockets installed
    /// (`node.connected_udp.max_peers`).
    ///
    /// This is an explicit escape hatch for large meshes while connected UDP
    /// still uses one receive-drain thread per installed peer. Set to `0` to
    /// disable the explicit cap and rely only on the fd budget and
    /// `node.limits.max_peers`.
    #[serde(default = "ConnectedUdpConfig::default_max_peers")]
    pub max_peers: usize,

    /// Number of process file descriptors to leave for non-connected-UDP use
    /// (`node.connected_udp.fd_reserve`).
    ///
    /// This is headroom, not a peer cap. Connected UDP uses three FDs per
    /// installed peer, so the effective fast-path peer budget is roughly
    /// `(RLIMIT_NOFILE - fd_reserve) / 3`, also bounded by `max_peers` when
    /// non-zero and by `node.limits.max_peers`.
    #[serde(default = "ConnectedUdpConfig::default_fd_reserve")]
    pub fd_reserve: usize,
}

impl Default for ConnectedUdpConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            max_peers: Self::default_max_peers(),
            fd_reserve: Self::default_fd_reserve(),
        }
    }
}

impl ConnectedUdpConfig {
    fn default_enabled() -> bool {
        #[cfg(target_os = "macos")]
        {
            return false;
        }

        #[cfg(not(target_os = "macos"))]
        true
    }

    fn default_max_peers() -> usize {
        0
    }

    fn default_fd_reserve() -> usize {
        128
    }
}

/// Rate limiting (`node.rate_limit.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Token bucket burst capacity (`node.rate_limit.handshake_burst`).
    #[serde(default = "RateLimitConfig::default_handshake_burst")]
    pub handshake_burst: u32,
    /// Tokens/sec refill rate (`node.rate_limit.handshake_rate`).
    #[serde(default = "RateLimitConfig::default_handshake_rate")]
    pub handshake_rate: f64,
    /// Stale handshake cleanup timeout in seconds (`node.rate_limit.handshake_timeout_secs`).
    #[serde(default = "RateLimitConfig::default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
    /// Initial handshake resend interval in ms (`node.rate_limit.handshake_resend_interval_ms`).
    /// Handshake messages are resent with exponential backoff within the timeout window.
    #[serde(default = "RateLimitConfig::default_handshake_resend_interval_ms")]
    pub handshake_resend_interval_ms: u64,
    /// Handshake resend backoff multiplier (`node.rate_limit.handshake_resend_backoff`).
    #[serde(default = "RateLimitConfig::default_handshake_resend_backoff")]
    pub handshake_resend_backoff: f64,
    /// Max handshake resends per attempt (`node.rate_limit.handshake_max_resends`).
    #[serde(default = "RateLimitConfig::default_handshake_max_resends")]
    pub handshake_max_resends: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            handshake_burst: 100,
            handshake_rate: 10.0,
            handshake_timeout_secs: 30,
            handshake_resend_interval_ms: 1000,
            handshake_resend_backoff: 2.0,
            handshake_max_resends: 5,
        }
    }
}

impl RateLimitConfig {
    fn default_handshake_burst() -> u32 {
        100
    }
    fn default_handshake_rate() -> f64 {
        10.0
    }
    fn default_handshake_timeout_secs() -> u64 {
        30
    }
    fn default_handshake_resend_interval_ms() -> u64 {
        1000
    }
    fn default_handshake_resend_backoff() -> f64 {
        2.0
    }
    fn default_handshake_max_resends() -> u32 {
        5
    }
}

/// Retry/backoff configuration (`node.retry.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Max connection retry attempts (`node.retry.max_retries`).
    #[serde(default = "RetryConfig::default_max_retries")]
    pub max_retries: u32,
    /// Base backoff interval in seconds (`node.retry.base_interval_secs`).
    #[serde(default = "RetryConfig::default_base_interval_secs")]
    pub base_interval_secs: u64,
    /// Cap on exponential backoff in seconds (`node.retry.max_backoff_secs`).
    #[serde(default = "RetryConfig::default_max_backoff_secs")]
    pub max_backoff_secs: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            base_interval_secs: 5,
            max_backoff_secs: 300,
        }
    }
}

impl RetryConfig {
    fn default_max_retries() -> u32 {
        5
    }
    fn default_base_interval_secs() -> u64 {
        5
    }
    fn default_max_backoff_secs() -> u64 {
        300
    }
}

/// Cache parameters (`node.cache.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Max entries in coord cache (`node.cache.coord_size`).
    #[serde(default = "CacheConfig::default_coord_size")]
    pub coord_size: usize,
    /// Coord cache entry TTL in seconds (`node.cache.coord_ttl_secs`).
    #[serde(default = "CacheConfig::default_coord_ttl_secs")]
    pub coord_ttl_secs: u64,
    /// Max entries in identity cache (`node.cache.identity_size`).
    #[serde(default = "CacheConfig::default_identity_size")]
    pub identity_size: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            coord_size: 50_000,
            coord_ttl_secs: 300,
            identity_size: 10_000,
        }
    }
}

impl CacheConfig {
    fn default_coord_size() -> usize {
        50_000
    }
    fn default_coord_ttl_secs() -> u64 {
        300
    }
    fn default_identity_size() -> usize {
        10_000
    }
}

mod discovery;

pub use discovery::{DiscoveryConfig, NostrDiscoveryConfig, NostrDiscoveryPolicy};

/// Spanning tree (`node.tree.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeConfig {
    /// Per-peer TreeAnnounce rate limit in ms (`node.tree.announce_min_interval_ms`).
    #[serde(default = "TreeConfig::default_announce_min_interval_ms")]
    pub announce_min_interval_ms: u64,
    /// Hysteresis factor for cost-based parent re-selection (`node.tree.parent_hysteresis`).
    ///
    /// Only switch parents when the candidate's effective_depth is better than
    /// `current_effective_depth * (1.0 - parent_hysteresis)`. Range: 0.0-1.0.
    /// Set to 0.0 to disable hysteresis (switch on any improvement).
    #[serde(default = "TreeConfig::default_parent_hysteresis")]
    pub parent_hysteresis: f64,
    /// Hold-down period after parent switch in seconds (`node.tree.hold_down_secs`).
    ///
    /// After switching parents, suppress re-evaluation for this duration to allow
    /// MMP metrics to stabilize on the new link. Set to 0 to disable.
    #[serde(default = "TreeConfig::default_hold_down_secs")]
    pub hold_down_secs: u64,
    /// Periodic parent re-evaluation interval in seconds (`node.tree.reeval_interval_secs`).
    ///
    /// How often to re-evaluate parent selection based on current MMP link costs,
    /// independent of TreeAnnounce traffic. Catches link degradation after the
    /// tree has stabilized. Set to 0 to disable.
    #[serde(default = "TreeConfig::default_reeval_interval_secs")]
    pub reeval_interval_secs: u64,
    /// Flap dampening: max parent switches before extended hold-down (`node.tree.flap_threshold`).
    #[serde(default = "TreeConfig::default_flap_threshold")]
    pub flap_threshold: u32,
    /// Flap dampening: window in seconds for counting switches (`node.tree.flap_window_secs`).
    #[serde(default = "TreeConfig::default_flap_window_secs")]
    pub flap_window_secs: u64,
    /// Flap dampening: extended hold-down duration in seconds (`node.tree.flap_dampening_secs`).
    #[serde(default = "TreeConfig::default_flap_dampening_secs")]
    pub flap_dampening_secs: u64,
}

impl Default for TreeConfig {
    fn default() -> Self {
        Self {
            announce_min_interval_ms: 500,
            parent_hysteresis: 0.2,
            hold_down_secs: 30,
            reeval_interval_secs: 60,
            flap_threshold: 4,
            flap_window_secs: 60,
            flap_dampening_secs: 120,
        }
    }
}

impl TreeConfig {
    fn default_announce_min_interval_ms() -> u64 {
        500
    }
    fn default_parent_hysteresis() -> f64 {
        0.2
    }
    fn default_hold_down_secs() -> u64 {
        30
    }
    fn default_reeval_interval_secs() -> u64 {
        60
    }
    fn default_flap_threshold() -> u32 {
        4
    }
    fn default_flap_window_secs() -> u64 {
        60
    }
    fn default_flap_dampening_secs() -> u64 {
        120
    }
}

/// Routing strategy selection (`node.routing.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Next-hop selection mode (`node.routing.mode`).
    #[serde(default)]
    pub mode: RoutingMode,
    /// TTL for learned reverse-path routes in seconds (`node.routing.learned_ttl_secs`).
    #[serde(default = "RoutingConfig::default_learned_ttl_secs")]
    pub learned_ttl_secs: u64,
    /// Maximum locally observed next-hop candidates kept per destination for
    /// reply-learned multipath/exploration
    /// (`node.routing.max_learned_routes_per_dest`).
    #[serde(default = "RoutingConfig::default_max_learned_routes_per_dest")]
    pub max_learned_routes_per_dest: usize,
    /// Every N learned-route selections, try the coordinate/bloom/tree route
    /// instead so new paths can be discovered (`0` disables fallback exploration).
    #[serde(default = "RoutingConfig::default_learned_fallback_explore_interval")]
    pub learned_fallback_explore_interval: u64,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            mode: RoutingMode::default(),
            learned_ttl_secs: 300,
            max_learned_routes_per_dest: 4,
            learned_fallback_explore_interval: 16,
        }
    }
}

impl RoutingConfig {
    fn default_learned_ttl_secs() -> u64 {
        300
    }

    fn default_max_learned_routes_per_dest() -> usize {
        4
    }

    fn default_learned_fallback_explore_interval() -> u64 {
        16
    }
}

/// Daemon routing mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    /// Current FIPS behavior: bloom-assisted greedy tree routing.
    #[default]
    Tree,
    /// Prefer locally learned reverse paths before falling back to tree routing.
    ///
    /// Learned routes are populated only from local evidence: inbound
    /// SessionDatagrams and verified LookupResponses.
    ReplyLearned,
}

impl std::fmt::Display for RoutingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoutingMode::Tree => write!(f, "tree"),
            RoutingMode::ReplyLearned => write!(f, "reply_learned"),
        }
    }
}

/// Bloom filter (`node.bloom.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomConfig {
    /// Debounce interval for filter updates in ms (`node.bloom.update_debounce_ms`).
    #[serde(default = "BloomConfig::default_update_debounce_ms")]
    pub update_debounce_ms: u64,
    /// Antipoison cap: reject inbound FilterAnnounce whose FPR exceeds
    /// this value (`node.bloom.max_inbound_fpr`). Valid range `(0.0, 1.0)`.
    /// Default `0.10` ≈ fill 0.631 at k=5 ≈ ~1,630 entries on the 1 KB
    /// filter. This leaves headroom for legitimate aggregates near the
    /// fixed-filter operating ceiling while still rejecting saturated or
    /// poisoned filters. Conceptually distinct from future autoscaling
    /// hysteresis setpoints — same unit, different knobs.
    #[serde(default = "BloomConfig::default_max_inbound_fpr")]
    pub max_inbound_fpr: f64,
}

impl Default for BloomConfig {
    fn default() -> Self {
        Self {
            update_debounce_ms: 500,
            max_inbound_fpr: 0.10,
        }
    }
}

impl BloomConfig {
    fn default_update_debounce_ms() -> u64 {
        500
    }
    fn default_max_inbound_fpr() -> f64 {
        0.10
    }
}

/// Session/data plane (`node.session.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Default SessionDatagram TTL (`node.session.default_ttl`).
    #[serde(default = "SessionConfig::default_ttl")]
    pub default_ttl: u8,
    /// Queue depth per dest during session establishment (`node.session.pending_packets_per_dest`).
    #[serde(default = "SessionConfig::default_pending_packets_per_dest")]
    pub pending_packets_per_dest: usize,
    /// Max destinations with pending packets (`node.session.pending_max_destinations`).
    #[serde(default = "SessionConfig::default_pending_max_destinations")]
    pub pending_max_destinations: usize,
    /// Idle session timeout in seconds (`node.session.idle_timeout_secs`).
    /// Established sessions with no application data for this duration are
    /// removed. MMP reports do not count as activity for this timer.
    #[serde(default = "SessionConfig::default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    /// Number of initial data packets per session that include COORDS_PRESENT
    /// for transit cache warmup (`node.session.coords_warmup_packets`).
    /// Also used as the reset count on CoordsRequired receipt.
    #[serde(default = "SessionConfig::default_coords_warmup_packets")]
    pub coords_warmup_packets: u8,
    /// Minimum interval (ms) between standalone CoordsWarmup responses to
    /// CoordsRequired/PathBroken signals, per destination
    /// (`node.session.coords_response_interval_ms`).
    #[serde(default = "SessionConfig::default_coords_response_interval_ms")]
    pub coords_response_interval_ms: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            default_ttl: 64,
            pending_packets_per_dest: 16,
            pending_max_destinations: 256,
            idle_timeout_secs: 90,
            coords_warmup_packets: 5,
            coords_response_interval_ms: 2000,
        }
    }
}

impl SessionConfig {
    fn default_ttl() -> u8 {
        64
    }
    fn default_pending_packets_per_dest() -> usize {
        16
    }
    fn default_pending_max_destinations() -> usize {
        256
    }
    fn default_idle_timeout_secs() -> u64 {
        90
    }
    fn default_coords_warmup_packets() -> u8 {
        5
    }
    fn default_coords_response_interval_ms() -> u64 {
        2000
    }
}

/// Session-layer Metrics Measurement Protocol (`node.session_mmp.*`).
///
/// Separate from link-layer `node.mmp.*` to allow independent mode/interval
/// configuration per layer. Session reports consume bandwidth on every transit
/// link, so operators may want a lighter mode (e.g., Lightweight) for sessions
/// while running Full mode on links.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMmpConfig {
    /// Operating mode (`node.session_mmp.mode`).
    #[serde(default)]
    pub mode: MmpMode,

    /// Periodic operator log interval in seconds (`node.session_mmp.log_interval_secs`).
    #[serde(default = "SessionMmpConfig::default_log_interval_secs")]
    pub log_interval_secs: u64,

    /// OWD trend ring buffer size (`node.session_mmp.owd_window_size`).
    #[serde(default = "SessionMmpConfig::default_owd_window_size")]
    pub owd_window_size: usize,
}

impl Default for SessionMmpConfig {
    fn default() -> Self {
        Self {
            mode: MmpMode::default(),
            log_interval_secs: DEFAULT_LOG_INTERVAL_SECS,
            owd_window_size: DEFAULT_OWD_WINDOW_SIZE,
        }
    }
}

impl SessionMmpConfig {
    fn default_log_interval_secs() -> u64 {
        DEFAULT_LOG_INTERVAL_SECS
    }
    fn default_owd_window_size() -> usize {
        DEFAULT_OWD_WINDOW_SIZE
    }
}

/// Control socket configuration (`node.control.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    /// Enable the control socket (`node.control.enabled`).
    #[serde(default = "ControlConfig::default_enabled")]
    pub enabled: bool,
    /// Unix socket path (`node.control.socket_path`).
    #[serde(default = "ControlConfig::default_socket_path")]
    pub socket_path: String,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            socket_path: Self::default_socket_path(),
        }
    }
}

impl ControlConfig {
    fn default_enabled() -> bool {
        true
    }

    /// Default control socket path.
    ///
    /// On Unix, returns the shared `/run/fips`, `XDG_RUNTIME_DIR`, then `/tmp`
    /// fallback used by fipsctl and fipstop. On Windows, returns a TCP port
    /// number as a string since Windows does not support Unix domain sockets;
    /// the control socket listens on localhost at this port.
    fn default_socket_path() -> String {
        #[cfg(unix)]
        {
            super::resolve_default_socket("control.sock")
        }
        #[cfg(windows)]
        {
            "21210".to_string()
        }
    }
}

const DEFAULT_PACKET_CHANNEL_CAPACITY: usize = 4096;

/// Internal buffers (`node.buffers.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuffersConfig {
    /// Transport→Node bulk packet capacity (`node.buffers.packet_channel`).
    ///
    /// Priority/control packets use a reserved lane. This bounds bulk packet
    /// backlog in packet units rather than receive-batch channel items.
    #[serde(default = "BuffersConfig::default_packet_channel")]
    pub packet_channel: usize,
    /// TUN→Node outbound channel capacity (`node.buffers.tun_channel`).
    #[serde(default = "BuffersConfig::default_tun_channel")]
    pub tun_channel: usize,
    /// DNS→Node identity channel capacity (`node.buffers.dns_channel`).
    #[serde(default = "BuffersConfig::default_dns_channel")]
    pub dns_channel: usize,
}

impl Default for BuffersConfig {
    fn default() -> Self {
        Self {
            packet_channel: DEFAULT_PACKET_CHANNEL_CAPACITY,
            tun_channel: 1024,
            dns_channel: 64,
        }
    }
}

impl BuffersConfig {
    fn default_packet_channel() -> usize {
        DEFAULT_PACKET_CHANNEL_CAPACITY
    }
    fn default_tun_channel() -> usize {
        1024
    }
    fn default_dns_channel() -> usize {
        64
    }
}

// ============================================================================
// ECN Congestion Signaling
// ============================================================================

/// Rekey / session rekeying configuration (`node.rekey.*`).
///
/// Controls periodic full rekey for both FMP (link layer) and FSP
/// (session layer) Noise sessions. Rekeying provides true forward secrecy
/// with fresh DH randomness, nonce reset, and session index rotation.
///
/// Keep the packet-count default high for packet-tunnel workloads. A low value
/// such as 65k packets can force multi-hundred-Mbit tunnels to rekey every few
/// seconds, which creates avoidable cutover churn and can dominate throughput.
/// Operators can still lower `node.rekey.after_messages` for CI stress tests or
/// very conservative deployments; the time-based `after_secs` default remains
/// the normal production rekey cadence.
const DEFAULT_REKEY_AFTER_MESSAGES: u64 = 1 << 48;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeyConfig {
    /// Enable periodic rekey (`node.rekey.enabled`).
    #[serde(default = "RekeyConfig::default_enabled")]
    pub enabled: bool,

    /// Initiate rekey after this many seconds (`node.rekey.after_secs`).
    #[serde(default = "RekeyConfig::default_after_secs")]
    pub after_secs: u64,

    /// Initiate rekey after this many messages sent (`node.rekey.after_messages`).
    #[serde(default = "RekeyConfig::default_after_messages")]
    pub after_messages: u64,
}

impl Default for RekeyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            after_secs: 120,
            after_messages: DEFAULT_REKEY_AFTER_MESSAGES,
        }
    }
}

impl RekeyConfig {
    fn default_enabled() -> bool {
        true
    }
    fn default_after_secs() -> u64 {
        120
    }
    fn default_after_messages() -> u64 {
        DEFAULT_REKEY_AFTER_MESSAGES
    }
}

/// ECN congestion signaling configuration (`node.ecn.*`).
///
/// Controls the FMP CE relay chain: transit nodes detect congestion on outgoing
/// links and set the CE flag in forwarded datagrams. The destination marks
/// IPv6 ECN-CE on ECN-capable packets before TUN delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcnConfig {
    /// Enable ECN congestion signaling (`node.ecn.enabled`).
    #[serde(default = "EcnConfig::default_enabled")]
    pub enabled: bool,

    /// Loss rate threshold for marking CE (`node.ecn.loss_threshold`).
    /// When the outgoing link's loss rate meets or exceeds this value,
    /// the transit node sets CE on forwarded datagrams.
    #[serde(default = "EcnConfig::default_loss_threshold")]
    pub loss_threshold: f64,

    /// ETX threshold for marking CE (`node.ecn.etx_threshold`).
    /// When the outgoing link's ETX meets or exceeds this value,
    /// the transit node sets CE on forwarded datagrams.
    #[serde(default = "EcnConfig::default_etx_threshold")]
    pub etx_threshold: f64,
}

impl Default for EcnConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            loss_threshold: 0.05,
            etx_threshold: 3.0,
        }
    }
}

impl EcnConfig {
    fn default_enabled() -> bool {
        true
    }
    fn default_loss_threshold() -> f64 {
        0.05
    }
    fn default_etx_threshold() -> f64 {
        3.0
    }
}

// ============================================================================
// Node Configuration (Root)
// ============================================================================

/// Node configuration (`node.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Identity configuration (`node.identity.*`).
    #[serde(default)]
    pub identity: IdentityConfig,

    /// Leaf-only mode (`node.leaf_only`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub leaf_only: bool,

    /// RX loop maintenance tick period in seconds (`node.tick_interval_secs`).
    #[serde(default = "NodeConfig::default_tick_interval_secs")]
    pub tick_interval_secs: u64,

    /// Initial RTT estimate for new links in ms (`node.base_rtt_ms`).
    #[serde(default = "NodeConfig::default_base_rtt_ms")]
    pub base_rtt_ms: u64,

    /// Link heartbeat send interval in seconds (`node.heartbeat_interval_secs`).
    #[serde(default = "NodeConfig::default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,

    /// Link dead timeout in seconds (`node.link_dead_timeout_secs`).
    /// Peers silent for this duration are removed.
    #[serde(default = "NodeConfig::default_link_dead_timeout_secs")]
    pub link_dead_timeout_secs: u64,

    /// Accelerated link dead timeout in seconds, used in place of
    /// `link_dead_timeout_secs` while a recent `transport.send` returned
    /// a local-side errno (`NetworkUnreachable` / `HostUnreachable` /
    /// `AddrNotAvailable`) — direct evidence our outbound path is broken
    /// right now (interface vanished, default route flapped, etc.). No
    /// reason to wait the full receive-silence window when the kernel
    /// already told us we can't send. Steady-state behavior is unchanged
    /// because the signal is cleared on the next successful send.
    /// (`node.fast_link_dead_timeout_secs`)
    #[serde(default = "NodeConfig::default_fast_link_dead_timeout_secs")]
    pub fast_link_dead_timeout_secs: u64,

    /// Resource limits (`node.limits.*`).
    #[serde(default)]
    pub limits: LimitsConfig,

    /// Connected UDP fast path (`node.connected_udp.*`).
    #[serde(default)]
    pub connected_udp: ConnectedUdpConfig,

    /// Rate limiting (`node.rate_limit.*`).
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Retry/backoff (`node.retry.*`).
    #[serde(default)]
    pub retry: RetryConfig,

    /// Cache parameters (`node.cache.*`).
    #[serde(default)]
    pub cache: CacheConfig,

    /// Discovery protocol (`node.discovery.*`).
    #[serde(default)]
    pub discovery: DiscoveryConfig,

    /// Spanning tree (`node.tree.*`).
    #[serde(default)]
    pub tree: TreeConfig,

    /// Routing strategy (`node.routing.*`).
    #[serde(default)]
    pub routing: RoutingConfig,

    /// Bloom filter (`node.bloom.*`).
    #[serde(default)]
    pub bloom: BloomConfig,

    /// Session/data plane (`node.session.*`).
    #[serde(default)]
    pub session: SessionConfig,

    /// Internal buffers (`node.buffers.*`).
    #[serde(default)]
    pub buffers: BuffersConfig,

    /// Control socket (`node.control.*`).
    #[serde(default)]
    pub control: ControlConfig,

    /// Metrics Measurement Protocol — link layer (`node.mmp.*`).
    #[serde(default)]
    pub mmp: MmpConfig,

    /// Metrics Measurement Protocol — session layer (`node.session_mmp.*`).
    #[serde(default)]
    pub session_mmp: SessionMmpConfig,

    /// ECN congestion signaling (`node.ecn.*`).
    #[serde(default)]
    pub ecn: EcnConfig,

    /// Rekey / session rekeying (`node.rekey.*`).
    #[serde(default)]
    pub rekey: RekeyConfig,

    /// Enable daemon-oriented system files such as `/etc/fips/hosts` and
    /// `/etc/fips/peers.{allow,deny}`. Embedded endpoints disable this.
    #[serde(default = "NodeConfig::default_system_files_enabled")]
    pub system_files_enabled: bool,

    /// Enable off-task Unix encrypt/decrypt worker pools (`node.worker_pools_enabled`).
    /// Embedded/mobile endpoints can disable this to keep crypto/send work inline
    /// with the rx loop when platform extension sandboxes make OS-thread pools
    /// unsuitable.
    #[serde(default = "NodeConfig::default_worker_pools_enabled")]
    pub worker_pools_enabled: bool,

    /// Log level (`node.log_level`). Case-insensitive.
    /// Valid values: trace, debug, info, warn, error. Default: info.
    #[serde(default)]
    pub log_level: Option<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            identity: IdentityConfig::default(),
            leaf_only: false,
            tick_interval_secs: 1,
            base_rtt_ms: 100,
            heartbeat_interval_secs: 10,
            link_dead_timeout_secs: 30,
            fast_link_dead_timeout_secs: 5,
            limits: LimitsConfig::default(),
            connected_udp: ConnectedUdpConfig::default(),
            rate_limit: RateLimitConfig::default(),
            retry: RetryConfig::default(),
            cache: CacheConfig::default(),
            discovery: DiscoveryConfig::default(),
            tree: TreeConfig::default(),
            routing: RoutingConfig::default(),
            bloom: BloomConfig::default(),
            session: SessionConfig::default(),
            buffers: BuffersConfig::default(),
            control: ControlConfig::default(),
            mmp: MmpConfig::default(),
            session_mmp: SessionMmpConfig::default(),
            ecn: EcnConfig::default(),
            rekey: RekeyConfig::default(),
            system_files_enabled: true,
            worker_pools_enabled: true,
            log_level: None,
        }
    }
}

impl NodeConfig {
    /// Get the log level as a tracing Level. Default: INFO.
    pub fn log_level(&self) -> tracing::Level {
        match self
            .log_level
            .as_deref()
            .map(|s| s.to_lowercase())
            .as_deref()
        {
            Some("trace") => tracing::Level::TRACE,
            Some("debug") => tracing::Level::DEBUG,
            Some("warn") | Some("warning") => tracing::Level::WARN,
            Some("error") => tracing::Level::ERROR,
            _ => tracing::Level::INFO,
        }
    }

    fn default_tick_interval_secs() -> u64 {
        1
    }
    fn default_base_rtt_ms() -> u64 {
        100
    }
    fn default_heartbeat_interval_secs() -> u64 {
        10
    }
    fn default_link_dead_timeout_secs() -> u64 {
        30
    }
    fn default_fast_link_dead_timeout_secs() -> u64 {
        5
    }
    fn default_system_files_enabled() -> bool {
        true
    }
    fn default_worker_pools_enabled() -> bool {
        true
    }
}

#[cfg(test)]
mod tests;
