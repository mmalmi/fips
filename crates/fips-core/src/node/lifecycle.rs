//! Node lifecycle management: start, stop, and peer connection initiation.

use super::{ConfiguredPeerLookup, Node, NodeError, NodeState};
use crate::config::{
    ConnectPolicy, NostrDiscoveryPolicy, PeerAddress, PeerAddressProvenance, PeerConfig,
};
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
use crate::upper::tun::{
    TunDevice, TunReaderRuntime, TunState, run_tun_reader, shutdown_tun_interface,
};
use crate::{NodeAddr, PeerIdentity};
use secp256k1::PublicKey;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::thread;
use std::time::Duration;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MeshSignalSessionAction {
    Send,
    Defer,
    Drop,
}

pub(super) struct PendingMeshSignal {
    msg_type: u8,
    payload: Vec<u8>,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::node) struct LocalInterfaceNetwork {
    pub(in crate::node) ip: IpAddr,
    pub(in crate::node) mask: IpAddr,
}

impl LocalInterfaceNetwork {
    fn contains(self, remote: IpAddr) -> bool {
        match (self.ip, self.mask, remote) {
            (IpAddr::V4(local), IpAddr::V4(mask), IpAddr::V4(remote)) => {
                let mask = u32::from(mask);
                (u32::from(local) & mask) == (u32::from(remote) & mask)
            }
            (IpAddr::V6(local), IpAddr::V6(mask), IpAddr::V6(remote)) => {
                let mask = u128::from_be_bytes(mask.octets());
                (u128::from_be_bytes(local.octets()) & mask)
                    == (u128::from_be_bytes(remote.octets()) & mask)
            }
            _ => false,
        }
    }
}

struct UdpRouteEvidence {
    networks: Vec<LocalInterfaceNetwork>,
    route_probe_local_ip: Option<IpAddr>,
}

impl UdpRouteEvidence {
    fn capture(remote_addr: SocketAddr, provenance: PeerAddressProvenance) -> Self {
        let needs_local_scope = provenance == PeerAddressProvenance::Learned
            && udp_remote_addr_requires_local_scope(remote_addr.ip());
        Self {
            networks: needs_local_scope
                .then(local_interface_networks)
                .unwrap_or_default(),
            route_probe_local_ip: needs_local_scope
                .then(|| udp_route_probe_local_ip(remote_addr))
                .flatten(),
        }
    }
}

/// Configured UDP endpoints may use an explicit private route. Learned private,
/// CGNAT, link-local, loopback, and ULA hints still require local-scope evidence.
fn udp_remote_addr_locally_plausible(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    provenance: PeerAddressProvenance,
    evidence: &UdpRouteEvidence,
) -> bool {
    if udp_remote_addr_invalid(remote_addr.ip()) {
        return false;
    }
    if provenance != PeerAddressProvenance::Learned {
        return true;
    }
    udp_remote_addr_locally_plausible_with_evidence(
        local_addr,
        remote_addr,
        &evidence.networks,
        evidence.route_probe_local_ip,
    )
}

pub(in crate::node) fn udp_remote_addr_locally_plausible_with_evidence(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    networks: &[LocalInterfaceNetwork],
    route_probe_local_ip: Option<IpAddr>,
) -> bool {
    let remote_ip = remote_addr.ip();
    if udp_remote_addr_invalid(remote_ip) {
        return false;
    }
    if !udp_remote_addr_requires_local_scope(remote_ip) {
        return true;
    }
    if local_ip_scope_matches_remote(local_addr.ip(), remote_ip) {
        return true;
    }
    if networks
        .iter()
        .copied()
        .any(|network| network.contains(remote_ip))
    {
        return true;
    }
    route_probe_local_ip.is_some_and(|local_ip| local_ip_scope_matches_remote(local_ip, remote_ip))
}

fn udp_remote_addr_invalid(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_multicast(),
    }
}

fn udp_remote_addr_requires_local_scope(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || ipv4_is_cgnat(v4)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unique_local()
                // IPv6 link-local: fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn local_ip_scope_matches_remote(local: IpAddr, remote: IpAddr) -> bool {
    match (local, remote) {
        (IpAddr::V4(local), IpAddr::V4(remote)) => {
            if local.is_unspecified() {
                return false;
            }
            if remote.is_loopback() {
                return local.is_loopback();
            }
            if remote.is_link_local() {
                return local.is_link_local() && same_ipv4_prefix(local, remote, 16);
            }
            if ipv4_is_cgnat(remote) {
                return ipv4_is_cgnat(local) && same_ipv4_prefix(local, remote, 24);
            }
            if remote.is_private() {
                return local.is_private() && same_ipv4_prefix(local, remote, 24);
            }
            false
        }
        (IpAddr::V6(local), IpAddr::V6(remote)) => {
            if local.is_unspecified() {
                return false;
            }
            if remote.is_loopback() {
                return local.is_loopback();
            }
            let remote_link_local = (remote.segments()[0] & 0xffc0) == 0xfe80;
            let local_link_local = (local.segments()[0] & 0xffc0) == 0xfe80;
            if remote_link_local {
                return local_link_local && same_ipv6_prefix(local, remote, 64);
            }
            if remote.is_unique_local() {
                return local.is_unique_local() && same_ipv6_prefix(local, remote, 64);
            }
            false
        }
        _ => false,
    }
}

fn same_ipv4_prefix(left: Ipv4Addr, right: Ipv4Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(left) & mask) == (u32::from(right) & mask)
}

fn same_ipv6_prefix(left: Ipv6Addr, right: Ipv6Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from_be_bytes(left.octets()) & mask) == (u128::from_be_bytes(right.octets()) & mask)
}

fn ipv4_is_cgnat(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64
}

fn udp_route_probe_local_ip(remote_addr: SocketAddr) -> Option<IpAddr> {
    let bind_addr = if remote_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = std::net::UdpSocket::bind(bind_addr).ok()?;
    socket.connect(remote_addr).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

#[cfg(unix)]
fn local_interface_networks() -> Vec<LocalInterfaceNetwork> {
    let mut output = Vec::new();
    let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();

    // SAFETY: `getifaddrs` initializes `ifaddrs` on success, and the linked
    // list is valid until `freeifaddrs` is called.
    let rc = unsafe { libc::getifaddrs(&mut ifaddrs) };
    if rc != 0 || ifaddrs.is_null() {
        return output;
    }

    let mut cursor = ifaddrs;
    while !cursor.is_null() {
        // SAFETY: `cursor` points at a valid node from the `getifaddrs` list.
        let entry = unsafe { &*cursor };
        let flags = entry.ifa_flags as i32;

        if interface_flags_allow_route_scope(flags)
            && !entry.ifa_addr.is_null()
            && !entry.ifa_netmask.is_null()
        {
            // SAFETY: `ifa_addr` and `ifa_netmask` are non-null and their
            // concrete type matches `sa_family` for this entry.
            let maybe_network = unsafe {
                match sockaddr_ip(entry.ifa_addr) {
                    Some(ip) => sockaddr_ip(entry.ifa_netmask)
                        .map(|mask| LocalInterfaceNetwork { ip, mask }),
                    None => None,
                }
            };
            if let Some(network) = maybe_network {
                output.push(network);
            }
        }

        cursor = entry.ifa_next;
    }

    // SAFETY: `ifaddrs` came from `getifaddrs` and has not yet been freed.
    unsafe { libc::freeifaddrs(ifaddrs) };
    output
}

#[cfg(not(unix))]
fn local_interface_networks() -> Vec<LocalInterfaceNetwork> {
    Vec::new()
}

#[cfg(unix)]
unsafe fn sockaddr_ip(addr: *const libc::sockaddr) -> Option<IpAddr> {
    // SAFETY: callers pass a valid `sockaddr` pointer from getifaddrs.
    unsafe {
        match (*addr).sa_family as i32 {
            libc::AF_INET => {
                let sockaddr = &*(addr as *const libc::sockaddr_in);
                Some(IpAddr::V4(Ipv4Addr::from(
                    sockaddr.sin_addr.s_addr.to_ne_bytes(),
                )))
            }
            libc::AF_INET6 => {
                let sockaddr = &*(addr as *const libc::sockaddr_in6);
                Some(IpAddr::V6(Ipv6Addr::from(sockaddr.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
}

#[cfg(unix)]
fn interface_flags_allow_route_scope(flags: i32) -> bool {
    let is_up = (flags & libc::IFF_UP) != 0;
    let is_loopback = (flags & libc::IFF_LOOPBACK) != 0;
    let is_point_to_point = (flags & libc::IFF_POINTOPOINT) != 0;
    is_up && !is_loopback && !is_point_to_point
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
