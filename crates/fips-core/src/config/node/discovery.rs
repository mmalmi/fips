use super::*;

/// Discovery protocol (`node.discovery.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Hop limit for LookupRequest flood (`node.discovery.ttl`).
    #[serde(default = "DiscoveryConfig::default_ttl")]
    pub ttl: u8,
    /// Per-attempt timeouts in seconds (`node.discovery.attempt_timeouts_secs`).
    /// Each entry is the time to wait for a response before sending the next
    /// LookupRequest (with a fresh request_id). Sequence length determines the
    /// total number of attempts before declaring the destination unreachable.
    /// Default `[1, 2, 4, 8]` gives 4 attempts and a 15s total budget.
    #[serde(default = "DiscoveryConfig::default_attempt_timeouts_secs")]
    pub attempt_timeouts_secs: Vec<u64>,
    /// Dedup cache expiry in seconds (`node.discovery.recent_expiry_secs`).
    #[serde(default = "DiscoveryConfig::default_recent_expiry_secs")]
    pub recent_expiry_secs: u64,
    /// Base backoff after lookup failure in seconds (`node.discovery.backoff_base_secs`).
    /// Doubles per consecutive failure up to `backoff_max_secs`. Set both to
    /// 0 to disable post-failure suppression.
    #[serde(default = "DiscoveryConfig::default_backoff_base_secs")]
    pub backoff_base_secs: u64,
    /// Maximum backoff cap in seconds (`node.discovery.backoff_max_secs`).
    #[serde(default = "DiscoveryConfig::default_backoff_max_secs")]
    pub backoff_max_secs: u64,
    /// Minimum interval between forwarded lookups for the same target in seconds
    /// (`node.discovery.forward_min_interval_secs`).
    /// Defense-in-depth against misbehaving nodes.
    #[serde(default = "DiscoveryConfig::default_forward_min_interval_secs")]
    pub forward_min_interval_secs: u64,
    /// Nostr-mediated overlay endpoint discovery.
    #[serde(default = "DiscoveryConfig::default_nostr")]
    pub nostr: NostrDiscoveryConfig,
    /// mDNS / DNS-SD peer discovery on the local link. Identity surface
    /// is a strict subset of what `nostr.advertise` already publishes
    /// publicly, so there's no marginal privacy cost; the latency win
    /// for same-LAN peers is large (sub-second pairing, no relay).
    #[serde(default = "DiscoveryConfig::default_lan")]
    pub lan: crate::discovery::lan::LanDiscoveryConfig,
    /// Same-host process discovery through one fixed loopback UDP rendezvous.
    /// The socket is only a bootstrap hint; the normal Noise handshake still
    /// authenticates every local peer. It never changes application-owned
    /// outbound connectivity.
    #[serde(default = "DiscoveryConfig::default_local")]
    pub local: crate::discovery::local::LocalInstanceDiscoveryConfig,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            ttl: 64,
            attempt_timeouts_secs: vec![1, 2, 4, 8],
            recent_expiry_secs: 10,
            backoff_base_secs: 30,
            backoff_max_secs: 300,
            forward_min_interval_secs: 2,
            nostr: NostrDiscoveryConfig::default(),
            lan: crate::discovery::lan::LanDiscoveryConfig::default(),
            local: crate::discovery::local::LocalInstanceDiscoveryConfig::default(),
        }
    }
}

impl DiscoveryConfig {
    fn default_ttl() -> u8 {
        64
    }
    fn default_attempt_timeouts_secs() -> Vec<u64> {
        vec![1, 2, 4, 8]
    }
    fn default_recent_expiry_secs() -> u64 {
        10
    }
    fn default_backoff_base_secs() -> u64 {
        30
    }
    fn default_backoff_max_secs() -> u64 {
        300
    }
    fn default_forward_min_interval_secs() -> u64 {
        2
    }
    fn default_nostr() -> NostrDiscoveryConfig {
        NostrDiscoveryConfig::default()
    }
    fn default_lan() -> crate::discovery::lan::LanDiscoveryConfig {
        crate::discovery::lan::LanDiscoveryConfig::default()
    }
    fn default_local() -> crate::discovery::local::LocalInstanceDiscoveryConfig {
        crate::discovery::local::LocalInstanceDiscoveryConfig::default()
    }
}

/// Nostr advert discovery policy.
///
/// Controls how overlay endpoint adverts are consumed:
/// - `disabled`: ignore advert-derived endpoints for all peers
/// - `configured_only`: allow advert fallback for configured peers
/// - `open`: also consider adverts for non-configured peers
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NostrDiscoveryPolicy {
    Disabled,
    #[default]
    ConfiguredOnly,
    Open,
}

/// Source used to publish and receive Nostr peer adverts.
///
/// `relays` keeps the built-in relay client as the peerfinding provider.
/// `external` disables built-in advert relay publication, subscriptions, and
/// cache-miss queries so an adapter can route ordinary signed advert events
/// through a transport-neutral pubsub provider instead. Transport negotiation
/// is carried by authenticated FIPS sessions, not by a second relay plane.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NostrPeerfindingSource {
    #[default]
    Relays,
    External,
}

/// Nostr-mediated overlay endpoint discovery (`node.discovery.nostr.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NostrDiscoveryConfig {
    /// Enable signed Nostr peer adverts and FIPS-session transport upgrades.
    #[serde(default)]
    pub enabled: bool,
    /// Publish service advertisements so remote peers can bootstrap inbound.
    #[serde(default = "NostrDiscoveryConfig::default_advertise")]
    pub advertise: bool,
    /// Provider used for signed peer advert distribution and lookup.
    #[serde(default)]
    pub peerfinding_source: NostrPeerfindingSource,
    /// Relay URLs used for service advertisements.
    #[serde(default = "NostrDiscoveryConfig::default_advert_relays")]
    pub advert_relays: Vec<String>,
    /// STUN servers used for local reflexive address discovery.
    /// Outbound observation uses only this local list; peer-advertised STUN
    /// values are informational and are not treated as egress targets.
    #[serde(default = "NostrDiscoveryConfig::default_stun_servers")]
    pub stun_servers: Vec<String>,
    /// Whether to advertise local (RFC 1918 / ULA) interface addresses as
    /// host candidates in the traversal offer.
    ///
    /// Off by default: in most deployments the relevant peers are not on the
    /// same broadcast domain, and sharing private host candidates causes
    /// misleading punch successes when an asymmetric L3 path (corporate VPN,
    /// Tailscale subnet route, overlapping address space, etc.) makes a
    /// peer's private IP one-way reachable from this node. Enable only when
    /// peers are on the same physical LAN and same-LAN punching is wanted.
    #[serde(default)]
    pub share_local_candidates: bool,
    /// Traversal application namespace advertised in the Nostr protocol tag.
    #[serde(default = "NostrDiscoveryConfig::default_app")]
    pub app: String,
    /// Signaling TTL in seconds.
    #[serde(default = "NostrDiscoveryConfig::default_signal_ttl_secs")]
    pub signal_ttl_secs: u64,
    /// Policy for advert-derived endpoint discovery.
    #[serde(default)]
    pub policy: NostrDiscoveryPolicy,
    /// Max number of open-discovery peers queued for outbound retry/connection
    /// at once. Prevents unbounded queue growth from ambient advert traffic.
    #[serde(default = "NostrDiscoveryConfig::default_open_discovery_max_pending")]
    pub open_discovery_max_pending: usize,
    /// Sort open-discovery adverts by externally supplied peer trust scores.
    ///
    /// Off by default. When enabled, positive-rated peers are tried first,
    /// unknown peers get reserved probe slots, and negatively rated peers are
    /// deferred behind trusted and unknown peers.
    #[serde(default)]
    pub open_discovery_trust_ratings_enabled: bool,
    /// Number of scarce open-discovery enqueue slots reserved for unknown
    /// peers when trust sorting is enabled.
    #[serde(default = "NostrDiscoveryConfig::default_open_discovery_newcomer_probe_slots")]
    pub open_discovery_newcomer_probe_slots: usize,
    /// Rating fact scope accepted by the open-discovery trust cache.
    #[serde(default = "NostrDiscoveryConfig::default_open_discovery_rating_scope")]
    pub open_discovery_rating_scope: String,
    /// Historical rating fact lookback window for the relay subscription.
    /// A value of 0 subscribes without a `since` bound.
    #[serde(default = "NostrDiscoveryConfig::default_open_discovery_rating_lookback_secs")]
    pub open_discovery_rating_lookback_secs: u64,
    /// Signed rating fact authors accepted by the open-discovery trust cache.
    /// The local node identity is always trusted; this list is for peers or
    /// crawlers the operator explicitly trusts.
    #[serde(default)]
    pub open_discovery_trusted_rating_authors: Vec<String>,
    /// Local JSON files containing signed rating fact events to load into the
    /// open-discovery trust cache at startup. Files may be raw event arrays or
    /// objects with an `events` array, such as `fipsctl ratings export --format
    /// events` or `htree nostr-index query` output.
    #[serde(default)]
    pub open_discovery_rating_event_files: Vec<std::path::PathBuf>,
    /// Max concurrent inbound traversal offers processed at once.
    /// Acts as a rate limit against offer spam from relays.
    #[serde(default = "NostrDiscoveryConfig::default_max_concurrent_incoming_offers")]
    pub max_concurrent_incoming_offers: usize,
    /// Max cached overlay adverts retained from relay traffic.
    /// Bounds memory under ambient advert volume.
    #[serde(default = "NostrDiscoveryConfig::default_advert_cache_max_entries")]
    pub advert_cache_max_entries: usize,
    /// Max seen-session IDs retained for replay detection.
    /// Oldest entries are evicted when the cap is exceeded.
    #[serde(default = "NostrDiscoveryConfig::default_seen_sessions_max_entries")]
    pub seen_sessions_max_entries: usize,
    /// Overall punch attempt timeout in seconds.
    #[serde(default = "NostrDiscoveryConfig::default_attempt_timeout_secs")]
    pub attempt_timeout_secs: u64,
    /// Replay tracking retention window in seconds.
    #[serde(default = "NostrDiscoveryConfig::default_replay_window_secs")]
    pub replay_window_secs: u64,
    /// Delay before punch traffic starts.
    #[serde(default = "NostrDiscoveryConfig::default_punch_start_delay_ms")]
    pub punch_start_delay_ms: u64,
    /// Interval between punch packets.
    #[serde(default = "NostrDiscoveryConfig::default_punch_interval_ms")]
    pub punch_interval_ms: u64,
    /// How long to keep punching before failure.
    #[serde(default = "NostrDiscoveryConfig::default_punch_duration_ms")]
    pub punch_duration_ms: u64,
    /// Advert TTL in seconds.
    #[serde(default = "NostrDiscoveryConfig::default_advert_ttl_secs")]
    pub advert_ttl_secs: u64,
    /// How often adverts are refreshed in seconds.
    #[serde(default = "NostrDiscoveryConfig::default_advert_refresh_secs")]
    pub advert_refresh_secs: u64,
    /// Settle delay in seconds after Nostr discovery starts before the
    /// one-shot startup sweep of cached adverts runs. Allows the relay
    /// subscription backlog to populate the in-memory advert cache.
    /// Only used under `policy: open`. Default: 5.
    #[serde(default = "NostrDiscoveryConfig::default_startup_sweep_delay_secs")]
    pub startup_sweep_delay_secs: u64,
    /// Maximum age in seconds for cached adverts considered by the
    /// one-shot startup sweep. Adverts whose `created_at` is older than
    /// `now - startup_sweep_max_age_secs` are skipped. Only used under
    /// `policy: open`. Default: 3600 (1 hour).
    #[serde(default = "NostrDiscoveryConfig::default_startup_sweep_max_age_secs")]
    pub startup_sweep_max_age_secs: u64,
    /// Number of consecutive NAT-traversal failures against a peer before
    /// an extended cooldown is applied to throttle further offer publishes.
    /// At this threshold the daemon also actively re-fetches the peer's
    /// advert in built-in `relays` peerfinding mode to evict cache entries for
    /// peers that have gone away. External providers own refresh in
    /// `external` mode. Default: 5.
    #[serde(default = "NostrDiscoveryConfig::default_failure_streak_threshold")]
    pub failure_streak_threshold: u32,
    /// Cooldown applied to a peer once `failure_streak_threshold` is hit.
    /// Suppresses both open-discovery sweep enqueues and per-attempt
    /// retry firings until elapsed. Default: 1800 (30 minutes).
    #[serde(default = "NostrDiscoveryConfig::default_extended_cooldown_secs")]
    pub extended_cooldown_secs: u64,
    /// Minimum interval between `NAT traversal failed` WARN log lines for
    /// the same peer. Subsequent failures inside the window log at DEBUG.
    /// Reduces log spam on public-test nodes with many cache-learned
    /// peers. Default: 300 (5 minutes).
    #[serde(default = "NostrDiscoveryConfig::default_warn_log_interval_secs")]
    pub warn_log_interval_secs: u64,
    /// Maximum entries retained in the per-npub failure-state map.
    /// Bounds memory under high cache turnover. Oldest entries (by last
    /// failure time) evicted when the cap is exceeded. Default: 4096.
    #[serde(default = "NostrDiscoveryConfig::default_failure_state_max_entries")]
    pub failure_state_max_entries: usize,
    /// Cooldown applied after observing a fatal protocol mismatch on a
    /// Nostr-adopted bootstrap transport (e.g. `Unknown FMP version`
    /// from a peer running a different FMP-protocol version). Independent
    /// of `extended_cooldown_secs` and much longer because the mismatch
    /// is structural — re-traversing the peer is wasted effort until one
    /// side upgrades. Default: 86400 (24 hours).
    #[serde(default = "NostrDiscoveryConfig::default_protocol_mismatch_cooldown_secs")]
    pub protocol_mismatch_cooldown_secs: u64,
}

impl Default for NostrDiscoveryConfig {
    fn default() -> Self {
        let open_discovery_newcomer_probe_slots =
            Self::default_open_discovery_newcomer_probe_slots();
        let open_discovery_rating_lookback_secs =
            Self::default_open_discovery_rating_lookback_secs();
        Self {
            enabled: false,
            advertise: Self::default_advertise(),
            peerfinding_source: NostrPeerfindingSource::default(),
            advert_relays: Self::default_advert_relays(),
            stun_servers: Self::default_stun_servers(),
            share_local_candidates: false,
            app: Self::default_app(),
            signal_ttl_secs: Self::default_signal_ttl_secs(),
            policy: NostrDiscoveryPolicy::default(),
            open_discovery_max_pending: Self::default_open_discovery_max_pending(),
            open_discovery_trust_ratings_enabled: false,
            open_discovery_newcomer_probe_slots,
            open_discovery_rating_scope: Self::default_open_discovery_rating_scope(),
            open_discovery_rating_lookback_secs,
            open_discovery_trusted_rating_authors: Vec::new(),
            open_discovery_rating_event_files: Vec::new(),
            max_concurrent_incoming_offers: Self::default_max_concurrent_incoming_offers(),
            advert_cache_max_entries: Self::default_advert_cache_max_entries(),
            seen_sessions_max_entries: Self::default_seen_sessions_max_entries(),
            attempt_timeout_secs: Self::default_attempt_timeout_secs(),
            replay_window_secs: Self::default_replay_window_secs(),
            punch_start_delay_ms: Self::default_punch_start_delay_ms(),
            punch_interval_ms: Self::default_punch_interval_ms(),
            punch_duration_ms: Self::default_punch_duration_ms(),
            advert_ttl_secs: Self::default_advert_ttl_secs(),
            advert_refresh_secs: Self::default_advert_refresh_secs(),
            startup_sweep_delay_secs: Self::default_startup_sweep_delay_secs(),
            startup_sweep_max_age_secs: Self::default_startup_sweep_max_age_secs(),
            failure_streak_threshold: Self::default_failure_streak_threshold(),
            extended_cooldown_secs: Self::default_extended_cooldown_secs(),
            warn_log_interval_secs: Self::default_warn_log_interval_secs(),
            failure_state_max_entries: Self::default_failure_state_max_entries(),
            protocol_mismatch_cooldown_secs: Self::default_protocol_mismatch_cooldown_secs(),
        }
    }
}

impl NostrDiscoveryConfig {
    /// Whether FIPS itself should open relay paths for peer adverts.
    #[must_use]
    pub const fn uses_relay_peerfinding(&self) -> bool {
        matches!(self.peerfinding_source, NostrPeerfindingSource::Relays)
    }

    fn default_advertise() -> bool {
        true
    }

    fn default_advert_relays() -> Vec<String> {
        vec![
            "wss://relay.damus.io".to_string(),
            "wss://nos.lol".to_string(),
            "wss://offchain.pub".to_string(),
            "wss://temp.iris.to".to_string(),
        ]
    }

    fn default_stun_servers() -> Vec<String> {
        vec![
            "stun:stun.l.google.com:19302".to_string(),
            "stun:stun.cloudflare.com:3478".to_string(),
            "stun:global.stun.twilio.com:3478".to_string(),
        ]
    }

    fn default_app() -> String {
        "fips-overlay-v1".to_string()
    }

    fn default_signal_ttl_secs() -> u64 {
        120
    }

    fn default_open_discovery_max_pending() -> usize {
        64
    }

    fn default_open_discovery_newcomer_probe_slots() -> usize {
        1
    }

    fn default_open_discovery_rating_scope() -> String {
        "fips.peer".to_string()
    }

    fn default_open_discovery_rating_lookback_secs() -> u64 {
        604_800
    }

    fn default_max_concurrent_incoming_offers() -> usize {
        16
    }

    fn default_advert_cache_max_entries() -> usize {
        2048
    }

    fn default_seen_sessions_max_entries() -> usize {
        2048
    }

    fn default_attempt_timeout_secs() -> u64 {
        10
    }

    fn default_replay_window_secs() -> u64 {
        300
    }

    fn default_punch_start_delay_ms() -> u64 {
        2_000
    }

    fn default_punch_interval_ms() -> u64 {
        200
    }

    fn default_punch_duration_ms() -> u64 {
        10_000
    }

    fn default_advert_ttl_secs() -> u64 {
        3_600
    }

    fn default_advert_refresh_secs() -> u64 {
        1_800
    }

    fn default_startup_sweep_delay_secs() -> u64 {
        5
    }

    fn default_startup_sweep_max_age_secs() -> u64 {
        3_600
    }

    fn default_failure_streak_threshold() -> u32 {
        5
    }

    fn default_extended_cooldown_secs() -> u64 {
        1_800
    }

    fn default_warn_log_interval_secs() -> u64 {
        300
    }

    fn default_failure_state_max_entries() -> usize {
        4_096
    }

    fn default_protocol_mismatch_cooldown_secs() -> u64 {
        86_400
    }
}
