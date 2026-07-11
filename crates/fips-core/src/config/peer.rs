//! Peer configuration types.
//!
//! Known peer definitions with transport addresses and connection policies.

use serde::{Deserialize, Serialize};

/// Connection policy for a peer.
///
/// Determines when and how to establish a connection to a peer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectPolicy {
    /// Connect to this peer automatically on node startup.
    /// This is the only policy supported in the initial implementation.
    #[default]
    AutoConnect,

    /// Connect only when traffic needs to be routed through this peer (future).
    OnDemand,

    /// Wait for explicit API call to connect (future).
    Manual,
}

/// How a peer address became trusted for dialing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerAddressProvenance {
    /// The operator explicitly configured this address.
    #[default]
    Configured,
    /// The exact address previously authenticated as this peer's active path.
    Authenticated,
    /// The address was learned from a peer, advert, or active socket.
    Learned,
}

impl PeerAddressProvenance {
    fn is_configured(&self) -> bool {
        matches!(self, Self::Configured)
    }
}

/// A transport-specific address for reaching a peer.
///
/// Each peer can have multiple addresses across different transports,
/// allowing fallback if one transport is unavailable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAddress {
    /// Transport type (e.g., "udp", "tor", "ethernet").
    pub transport: String,

    /// Transport-specific address string.
    ///
    /// Format depends on transport type:
    /// - UDP/TCP: "host:port" — IP address or DNS hostname
    ///   (e.g., "192.168.1.1:2121" or "peer1.example.com:2121")
    /// - Ethernet: "interface/mac" (e.g., "eth0/aa:bb:cc:dd:ee:ff")
    pub addr: String,

    /// Priority for address selection (lower = preferred).
    /// When multiple addresses are available, lower priority addresses
    /// are tried first.
    #[serde(default = "default_priority")]
    pub priority: u8,

    /// Trust provenance for policies that distinguish operator routes from
    /// learned address hints.
    ///
    /// Omission means configured for compatibility with existing config files.
    /// Learned runtime values retain their provenance when serialized.
    #[serde(default, skip_serializing_if = "PeerAddressProvenance::is_configured")]
    pub provenance: PeerAddressProvenance,

    /// Wall-clock observation timestamp (Unix ms) for ranking by recency
    /// within the same priority.
    ///
    /// `None` means "no freshness signal". The dialer primarily honors
    /// explicit address priority and only uses this field to order
    /// otherwise-equal candidates. Skipped from serde so that round-tripping
    /// a config file doesn't produce noisy empty fields.
    ///
    /// Excluded from `PartialEq`: refreshing the timestamp on a peer that's
    /// otherwise unchanged should not flag it as "updated" in
    /// [`crate::endpoint::FipsEndpoint::update_peers`]'s diff.
    #[serde(default, skip_serializing_if = "Option::is_none", skip_deserializing)]
    pub seen_at_ms: Option<u64>,
}

impl PartialEq for PeerAddress {
    fn eq(&self, other: &Self) -> bool {
        self.transport == other.transport
            && self.addr == other.addr
            && self.priority == other.priority
            && self.provenance == other.provenance
    }
}

impl Eq for PeerAddress {}

fn default_priority() -> u8 {
    100
}

fn default_auto_reconnect() -> bool {
    true
}

fn default_discovery_fallback_transit() -> bool {
    true
}

impl PeerAddress {
    /// Create an explicitly configured peer address.
    pub fn new(transport: impl Into<String>, addr: impl Into<String>) -> Self {
        Self {
            transport: transport.into(),
            addr: addr.into(),
            priority: default_priority(),
            provenance: PeerAddressProvenance::Configured,
            seen_at_ms: None,
        }
    }

    /// Create an explicitly configured peer address with priority.
    pub fn with_priority(
        transport: impl Into<String>,
        addr: impl Into<String>,
        priority: u8,
    ) -> Self {
        Self {
            transport: transport.into(),
            addr: addr.into(),
            priority,
            provenance: PeerAddressProvenance::Configured,
            seen_at_ms: None,
        }
    }

    /// Mark this address as learned from discovery or an active path.
    pub fn learned(mut self) -> Self {
        self.provenance = PeerAddressProvenance::Learned;
        self
    }

    /// Mark this address as a previously authenticated active path.
    pub fn authenticated(mut self) -> Self {
        self.provenance = PeerAddressProvenance::Authenticated;
        self
    }

    /// Whether this address was explicitly operator-configured.
    pub fn is_configured(&self) -> bool {
        self.provenance == PeerAddressProvenance::Configured
    }

    /// Tag this address with a freshness timestamp. Used by the dialer to
    /// rank candidates from multiple sources (overlay advert, recent-peers
    /// cache, operator hints) by recency without caring where they came
    /// from. See [`crate::config::PeerAddress::seen_at_ms`].
    pub fn with_seen_at_ms(mut self, seen_at_ms: u64) -> Self {
        self.seen_at_ms = Some(seen_at_ms);
        self
    }
}

/// Configuration for a known peer.
///
/// Peers are identified by their Nostr public key (npub) and can have
/// multiple transport addresses for reaching them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    /// The peer's Nostr public key in npub (bech32) or hex format.
    pub npub: String,

    /// Human-readable alias for the peer (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,

    /// Transport addresses for reaching this peer.
    ///
    /// At least one address is required unless Nostr discovery is enabled,
    /// in which case the address list may be empty and endpoints are
    /// resolved from the peer's Nostr advert at dial time.
    #[serde(default)]
    pub addresses: Vec<PeerAddress>,

    /// Connection policy for this peer.
    #[serde(default)]
    pub connect_policy: ConnectPolicy,

    /// Whether to automatically reconnect after link-dead removal.
    /// When true (default), the node will retry connecting with exponential
    /// backoff after MMP removes this peer due to liveness timeout.
    #[serde(default = "default_auto_reconnect")]
    pub auto_reconnect: bool,

    /// Whether this peer may be used as an extra reply-learned lookup hop.
    ///
    /// Direct lookups to this peer are still allowed when false. This only
    /// controls opportunistic fallback fanout through the peer for other
    /// destinations.
    #[serde(default = "default_discovery_fallback_transit")]
    pub discovery_fallback_transit: bool,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            npub: String::new(),
            alias: None,
            addresses: Vec::new(),
            connect_policy: ConnectPolicy::default(),
            auto_reconnect: default_auto_reconnect(),
            discovery_fallback_transit: default_discovery_fallback_transit(),
        }
    }
}

impl PeerConfig {
    /// Create a new peer config with a single address.
    pub fn new(
        npub: impl Into<String>,
        transport: impl Into<String>,
        addr: impl Into<String>,
    ) -> Self {
        Self {
            npub: npub.into(),
            alias: None,
            addresses: vec![PeerAddress::new(transport, addr)],
            connect_policy: ConnectPolicy::default(),
            auto_reconnect: default_auto_reconnect(),
            discovery_fallback_transit: default_discovery_fallback_transit(),
        }
    }

    /// Set an alias for the peer.
    pub fn with_alias(mut self, alias: impl Into<String>) -> Self {
        self.alias = Some(alias.into());
        self
    }

    /// Add an additional address for the peer.
    pub fn with_address(mut self, addr: PeerAddress) -> Self {
        self.addresses.push(addr);
        self
    }

    /// Get addresses sorted by priority (lowest first).
    pub fn addresses_by_priority(&self) -> Vec<&PeerAddress> {
        let mut addrs: Vec<_> = self.addresses.iter().collect();
        addrs.sort_by_key(|a| a.priority);
        addrs
    }

    /// Check if this peer should auto-connect on startup.
    pub fn is_auto_connect(&self) -> bool {
        matches!(self.connect_policy, ConnectPolicy::AutoConnect)
    }
}
