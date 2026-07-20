use crate::NodeAddr;
use crate::node::{NodeEndpointPeer, NodeEndpointRelayStatus};
use std::net::SocketAddr;

/// Authenticated FIPS peer state visible to an embedded application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsEndpointPeer {
    /// Peer Nostr public key.
    pub npub: String,
    /// Peer FIPS node address, derived from the public key and stable across npub encodings.
    pub node_addr: NodeAddr,
    /// Whether an authenticated link-layer peer is currently active.
    pub connected: bool,
    /// Current underlay transport address, when a link has authenticated.
    pub transport_addr: Option<String>,
    /// Current underlay transport kind, when known.
    pub transport_type: Option<String>,
    /// Authenticated link id.
    pub link_id: u64,
    /// Smoothed RTT in milliseconds, once measured by FIPS MMP.
    pub srtt_ms: Option<u64>,
    /// Age of the current SRTT sample in milliseconds.
    pub srtt_age_ms: Option<u64>,
    /// Link packets sent.
    pub packets_sent: u64,
    /// Link packets received.
    pub packets_recv: u64,
    /// Link bytes sent.
    pub bytes_sent: u64,
    /// Link bytes received.
    pub bytes_recv: u64,
    /// Whether a link-layer rekey is currently in progress.
    pub rekey_in_progress: bool,
    /// Whether this peer is draining an old key during rekey.
    pub rekey_draining: bool,
    /// Current link-layer key bit for active peers.
    pub current_k_bit: Option<bool>,
    /// Last outbound end-to-end session route: `direct` when the first hop was
    /// the destination peer, `fallback` when traffic went through another peer.
    pub last_outbound_route: Option<String>,
    /// Whether direct UDP probing is queued while this peer may still be
    /// reachable through a fallback transport.
    pub direct_probe_pending: bool,
    /// Millisecond timestamp when the queued direct probe becomes eligible.
    pub direct_probe_after_ms: Option<u64>,
    /// Number of direct probe/retry attempts accumulated for this peer.
    pub direct_probe_retry_count: u32,
    /// Whether the queued direct probe is an unlimited auto-reconnect.
    pub direct_probe_auto_reconnect: bool,
    /// Millisecond timestamp when a bounded direct probe/retry entry expires.
    pub direct_probe_expires_at_ms: Option<u64>,
    /// Consecutive Nostr traversal failures recorded for this peer.
    pub nostr_traversal_consecutive_failures: u32,
    /// Whether Nostr traversal is currently cooling down for this peer.
    pub nostr_traversal_in_cooldown: bool,
    /// Millisecond timestamp when Nostr traversal cooldown ends.
    pub nostr_traversal_cooldown_until_ms: Option<u64>,
    /// Last observed Nostr timestamp skew in milliseconds for this peer.
    pub nostr_traversal_last_observed_skew_ms: Option<i64>,
}

impl FipsEndpointPeer {
    /// Return a safe UDP restart candidate from this authenticated snapshot.
    ///
    /// A candidate is exposed only while the peer is connected over UDP and
    /// the reported address is a reusable [`SocketAddr`]. In particular, this
    /// never turns TCP source ports, synthetic WebSocket paths, WebRTC
    /// signaling identities, or BLE addresses into restart routes.
    pub fn authenticated_udp_restart_addr(&self) -> Option<SocketAddr> {
        if !self.connected || self.transport_type.as_deref() != Some("udp") {
            return None;
        }

        self.transport_addr
            .as_deref()?
            .parse()
            .ok()
            .filter(is_reusable_udp_socket_addr)
    }
}

pub(super) fn is_reusable_udp_socket_addr(addr: &SocketAddr) -> bool {
    addr.port() != 0 && !addr.ip().is_unspecified() && !addr.ip().is_multicast()
}

/// Live Nostr relay state visible to an embedded application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsEndpointRelayStatus {
    pub url: String,
    pub status: String,
}

impl From<NodeEndpointPeer> for FipsEndpointPeer {
    fn from(peer: NodeEndpointPeer) -> Self {
        Self {
            npub: peer.npub,
            node_addr: peer.node_addr,
            connected: peer.connected,
            transport_addr: peer.transport_addr,
            transport_type: peer.transport_type,
            link_id: peer.link_id,
            srtt_ms: peer.srtt_ms,
            srtt_age_ms: peer.srtt_age_ms,
            packets_sent: peer.packets_sent,
            packets_recv: peer.packets_recv,
            bytes_sent: peer.bytes_sent,
            bytes_recv: peer.bytes_recv,
            rekey_in_progress: peer.rekey_in_progress,
            rekey_draining: peer.rekey_draining,
            current_k_bit: peer.current_k_bit,
            last_outbound_route: peer.last_outbound_route,
            direct_probe_pending: peer.direct_probe_pending,
            direct_probe_after_ms: peer.direct_probe_after_ms,
            direct_probe_retry_count: peer.direct_probe_retry_count,
            direct_probe_auto_reconnect: peer.direct_probe_auto_reconnect,
            direct_probe_expires_at_ms: peer.direct_probe_expires_at_ms,
            nostr_traversal_consecutive_failures: peer.nostr_traversal_consecutive_failures,
            nostr_traversal_in_cooldown: peer.nostr_traversal_in_cooldown,
            nostr_traversal_cooldown_until_ms: peer.nostr_traversal_cooldown_until_ms,
            nostr_traversal_last_observed_skew_ms: peer.nostr_traversal_last_observed_skew_ms,
        }
    }
}

impl From<NodeEndpointRelayStatus> for FipsEndpointRelayStatus {
    fn from(relay: NodeEndpointRelayStatus) -> Self {
        Self {
            url: relay.url,
            status: relay.status,
        }
    }
}
