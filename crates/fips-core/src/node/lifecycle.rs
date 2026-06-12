//! Node lifecycle management: start, stop, and peer connection initiation.

use super::{ConfiguredPeerSendWeights, Node, NodeError, NodeState};
use crate::config::{ConnectPolicy, NostrDiscoveryPolicy, PeerAddress, PeerConfig};
use crate::discovery::nostr::{
    ADVERT_IDENTIFIER, ADVERT_VERSION, BootstrapEvent, MeshTraversalSignal, NostrDiscovery,
    OverlayAdvert, OverlayEndpointAdvert, OverlayTransportKind,
};
use crate::discovery::{BootstrapHandoffResult, EstablishedTraversal};
use crate::node::acl::PeerAclContext;
use crate::node::wire::build_msg1;
use crate::peer::PeerConnection;
use crate::protocol::{Disconnect, DisconnectReason, SessionMessageType};
use crate::transport::{Link, LinkDirection, LinkId, TransportAddr, TransportId, packet_channel};
use crate::upper::tun::{TunDevice, TunState, run_tun_reader, shutdown_tun_interface};
use crate::{NodeAddr, PeerIdentity};
use secp256k1::PublicKey;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::thread;
use std::time::Duration;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MeshSignalSessionAction {
    Send,
    Defer,
    Drop,
}

#[cfg(debug_assertions)]
fn node_start_debug_log(message: impl AsRef<str>) {
    use std::io::Write as _;

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(std::env::temp_dir().join("nvpn-fips-endpoint-debug.log"))
    {
        let _ = writeln!(
            file,
            "{:?} {}",
            std::time::SystemTime::now(),
            message.as_ref()
        );
    }
}

#[cfg(not(debug_assertions))]
fn node_start_debug_log(_message: impl AsRef<str>) {}

/// True if `ip` is not a viable canonical advert endpoint for peers off
/// the publisher's own LAN. Covers RFC1918, loopback, link-local, IPv4
/// CGNAT (100.64/10), unspecified, multicast/benchmark, and IPv6
/// unique-local/loopback/unspecified. We never publish these as the
/// peer's primary `runtime_endpoint`; an off-LAN consumer can't route
/// to them, and latching one in onto a slow overlay-relay fallback is
/// the original bug this guard exists to prevent.
fn is_unroutable_advert_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                // 100.64.0.0/10 — CGNAT, RFC 6598. Not routable on the
                // public internet; behaves like an extra NAT layer.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_multicast()
                // IPv6 link-local: fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn socket_addr_families_compatible(local: SocketAddr, remote: SocketAddr) -> bool {
    matches!(
        (local, remote),
        (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_))
    )
}

mod candidate_connect;
mod control;
mod discovery;
mod nostr;
mod paths;
mod peer_config;
mod runtime;

const OPEN_DISCOVERY_RETRY_LIFETIME_MULTIPLIER: u64 = 2;
const MAX_PARALLEL_PATH_CANDIDATES_PER_PEER: usize = 4;
const MAX_AUTO_CONNECT_GRAPH_WARMUPS_PER_TICK: usize = 16;
const MAX_DISCOVERY_CONNECTS_PER_TICK: usize = 16;
