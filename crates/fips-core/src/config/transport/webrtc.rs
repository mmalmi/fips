//! WebRTC transport configuration.

use serde::{Deserialize, Serialize};

/// Default WebRTC data-channel MTU.
const DEFAULT_WEBRTC_MTU: u16 = 1200;

/// Default WebRTC connection timeout in milliseconds.
const DEFAULT_WEBRTC_CONNECT_TIMEOUT_MS: u64 = 30_000;

/// Default non-trickle ICE gathering timeout in milliseconds.
const DEFAULT_WEBRTC_ICE_GATHER_TIMEOUT_MS: u64 = 2_000;

/// Default maximum simultaneous WebRTC peer connections.
const DEFAULT_WEBRTC_MAX_CONNECTIONS: usize = 6;

/// Default WebRTC data channel label.
const DEFAULT_WEBRTC_DATA_CHANNEL_LABEL: &str = "fips";

/// WebRTC transport instance configuration.
///
/// WebRTC negotiates over an existing authenticated FIPS session and carries
/// ordinary FIPS datagrams over an SCTP data channel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebRtcConfig {
    /// Whether this transport should be advertised on Nostr overlay discovery.
    /// Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertise_on_nostr: Option<bool>,

    /// Whether to automatically connect to discovered WebRTC peers.
    /// Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_connect: Option<bool>,

    /// Accept inbound WebRTC offers. Defaults to `advertise_on_nostr`: a
    /// non-advertising adapter has no inbound listener policy unless enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_connections: Option<bool>,

    /// Data-channel MTU. Defaults to 1200.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

    /// Maximum simultaneous WebRTC peer connections. Defaults to 6 and is
    /// additionally bounded by the configured ICE socket budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<usize>,

    /// Outbound connect timeout in milliseconds. Defaults to 30000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,

    /// Non-trickle ICE gathering timeout in milliseconds. Defaults to 2000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ice_gather_timeout_ms: Option<u64>,

    /// Data channel label. Defaults to "fips".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_channel_label: Option<String>,

    /// Ordered data channel delivery. Default: true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,

    /// Maximum retransmits for partial reliability. Default: unset, which uses
    /// WebRTC's reliable data-channel mode. Set to 0 for datagram-like delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retransmits: Option<u16>,

    /// Override STUN servers for this transport. Supports up to three `stun:`
    /// URLs. When unset, `node.discovery.nostr.stun_servers` is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stun_servers: Option<Vec<String>>,

    /// Resolve browser `.local` ICE candidates through one shared mDNS owner.
    /// Every peer connection keeps its own ICE mDNS mode disabled. Default:
    /// true. Disable this for environments where multicast DNS is unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolve_mdns_candidates: Option<bool>,
}

impl WebRtcConfig {
    /// Whether this WebRTC transport should be advertised on Nostr discovery.
    pub fn advertise_on_nostr(&self) -> bool {
        self.advertise_on_nostr.unwrap_or(false)
    }

    /// Whether this transport auto-connects to discovered peers.
    pub fn auto_connect(&self) -> bool {
        self.auto_connect.unwrap_or(false)
    }

    /// Whether this transport accepts inbound offers.
    pub fn accept_connections(&self) -> bool {
        self.accept_connections
            .unwrap_or_else(|| self.advertise_on_nostr())
    }

    /// Get the data-channel MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_WEBRTC_MTU)
    }

    /// Get the maximum number of peer connections.
    pub fn max_connections(&self) -> usize {
        self.max_connections
            .unwrap_or(DEFAULT_WEBRTC_MAX_CONNECTIONS)
    }

    /// Get the connect timeout in milliseconds.
    pub fn connect_timeout_ms(&self) -> u64 {
        self.connect_timeout_ms
            .unwrap_or(DEFAULT_WEBRTC_CONNECT_TIMEOUT_MS)
    }

    /// Get the ICE gathering timeout in milliseconds.
    pub fn ice_gather_timeout_ms(&self) -> u64 {
        self.ice_gather_timeout_ms
            .unwrap_or(DEFAULT_WEBRTC_ICE_GATHER_TIMEOUT_MS)
    }

    /// Get the data channel label.
    pub fn data_channel_label(&self) -> &str {
        self.data_channel_label
            .as_deref()
            .unwrap_or(DEFAULT_WEBRTC_DATA_CHANNEL_LABEL)
    }

    /// Whether the data channel is ordered.
    pub fn ordered(&self) -> bool {
        self.ordered.unwrap_or(true)
    }

    /// Get the configured max retransmits. None uses WebRTC's reliable mode.
    pub fn max_retransmits(&self) -> Option<u16> {
        self.max_retransmits
    }

    /// Whether browser `.local` ICE candidates should be resolved.
    pub fn resolve_mdns_candidates(&self) -> bool {
        self.resolve_mdns_candidates.unwrap_or(true)
    }

    /// Resolve STUN servers, falling back to node discovery STUN servers.
    pub fn stun_servers<'a>(&'a self, fallback: &'a [String]) -> Vec<String> {
        self.stun_servers
            .as_ref()
            .cloned()
            .unwrap_or_else(|| fallback.to_vec())
    }
}
