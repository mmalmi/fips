//! Transport configuration types.
//!
//! Generic transport instance handling (single vs. named) and
//! transport-specific configuration structs.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Parse an `external_addr` config string against a known bind port,
/// producing the absolute `SocketAddr` to advertise on Nostr.
///
/// Accepts either a bare IP (`"198.51.100.1"` or `"[::1]"`) — in which
/// case the bind port is appended — or a full `host:port` form
/// (`"198.51.100.1:443"` or `"[::1]:443"`). Returns `None` on any parse
/// error. IPv6 must use bracket notation when supplying a port.
fn parse_external_advert_addr(raw: &str, bind_port: u16) -> Option<SocketAddr> {
    if let Ok(sa) = raw.parse::<SocketAddr>() {
        return Some(sa);
    }
    let ip: IpAddr = raw.parse().ok()?;
    Some(SocketAddr::new(ip, bind_port))
}

/// Extract the port from a `bind_addr` string. Returns `None` if the
/// string can't be parsed (e.g. a bare hostname without port).
fn parse_bind_port(raw: &str) -> Option<u16> {
    raw.parse::<SocketAddr>().ok().map(|sa| sa.port())
}

/// Default UDP bind address.
const DEFAULT_UDP_BIND_ADDR: &str = "0.0.0.0:2121";

/// Default UDP MTU (IPv6 minimum).
const DEFAULT_UDP_MTU: u16 = 1280;

/// Default MTU for FIPS datagrams carried by ephemeral Nostr relay events.
const DEFAULT_NOSTR_RELAY_MTU: u16 = 1280;

/// Default number of signed relay events waiting for the application adapter.
const DEFAULT_NOSTR_RELAY_PENDING_EVENTS: usize = 1024;

/// Ephemeral Nostr relay fallback transport configuration.
///
/// Relay URLs deliberately do not live here. The embedding application owns
/// relay selection and delivery through the external Nostr relay adapter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NostrRelayConfig {
    /// Maximum FIPS wire datagram size before base64 encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

    /// Whether public Nostr adverts should auto-connect over this fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_connect: Option<bool>,

    /// Accept inbound FIPS handshakes received through relay events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_connections: Option<bool>,

    /// Maximum signed events waiting for the external relay adapter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_pending_events: Option<usize>,
}

impl NostrRelayConfig {
    pub fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_NOSTR_RELAY_MTU)
    }

    pub fn auto_connect(&self) -> bool {
        self.auto_connect.unwrap_or(true)
    }

    pub fn accept_connections(&self) -> bool {
        self.accept_connections.unwrap_or(true)
    }

    pub fn max_pending_events(&self) -> usize {
        self.max_pending_events
            .unwrap_or(DEFAULT_NOSTR_RELAY_PENDING_EVENTS)
            .max(1)
    }
}

/// Default UDP receive buffer size (16 MiB).
///
/// At sustained multi-Gbps single-stream the kernel UDP queue
/// drained ~113 kpps × ~1.5 KiB ≈ 170 MiB/s, so a few-hundred-ms
/// userspace stall would fill a 2 MiB buffer in <20 ms — small
/// enough that ordinary jitter (GC, allocator-coalesce, scheduler
/// context-switch on a busy host) trips RcvbufErrors and tanks TCP
/// throughput via cwnd-halving. 16 MiB gives ~100 ms of headroom.
///
/// On platforms whose `net.core.rmem_max` is smaller than this, the
/// UDP socket layer falls back to SO_RCVBUFFORCE (CAP_NET_ADMIN
/// required) before honouring the kernel ceiling. See
/// `transport/udp/socket.rs::UdpRawSocket::open`.
const DEFAULT_UDP_RECV_BUF: usize = 16 * 1024 * 1024;

/// Default UDP send buffer size (8 MiB). Mirrors the receive-side
/// reasoning at half the size — outbound burst absorption matters
/// less because we control the producer rate via the rx_loop's
/// per-drain sendmmsg flush.
const DEFAULT_UDP_SEND_BUF: usize = 8 * 1024 * 1024;

/// UDP transport instance configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpConfig {
    /// Bind address (`bind_addr`). Defaults to "0.0.0.0:2121".
    ///
    /// When `outbound_only = true`, this field is ignored and the transport
    /// binds to `0.0.0.0:0` (kernel-assigned ephemeral port) regardless.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_addr: Option<String>,

    /// UDP MTU (`mtu`). Defaults to 1280 (IPv6 minimum).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

    /// UDP receive buffer size in bytes (`recv_buf_size`). Defaults to 16 MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recv_buf_size: Option<usize>,

    /// UDP send buffer size in bytes (`send_buf_size`). Defaults to 8 MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_buf_size: Option<usize>,

    /// Whether this transport should be advertised on Nostr overlay discovery.
    /// Default: false. Implicitly forced false when `outbound_only = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertise_on_nostr: Option<bool>,

    /// Whether UDP should be advertised as directly reachable (`host:port`) on
    /// Nostr. When false and advertised, UDP is emitted as `addr: "nat"` to
    /// trigger rendezvous traversal.
    ///
    /// Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public: Option<bool>,
    /// Optional explicit public address to advertise when `public: true`
    /// is set. Takes precedence over both the bound address and any
    /// STUN-derived autodiscovery. Accepts either a bare IP
    /// (`"198.51.100.1"` — the configured `bind_addr` port is appended)
    /// or a full `host:port` (`"198.51.100.1:443"`). Useful when the
    /// public IP isn't on a local interface (e.g. AWS EIP / cloud 1:1
    /// NAT) and the operator wants to skip STUN autodiscovery for a
    /// deterministic value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_addr: Option<String>,
    /// Outbound-only mode. When true, the transport binds to a kernel-
    /// assigned ephemeral port (`0.0.0.0:0`) instead of the configured
    /// `bind_addr`, refuses inbound handshake msg1, and is never
    /// advertised on Nostr regardless of `advertise_on_nostr`. Use this
    /// to participate in the mesh as a pure client — initiate outbound
    /// links without exposing an inbound listener on a known port.
    /// Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_only: Option<bool>,

    /// Accept inbound handshake msg1 from new peers. Default: true.
    /// Setting this to false combined with `auto_connect: true` on
    /// peer-side configurations gives a "client" posture: this node
    /// initiates outbound links but refuses inbound handshakes from
    /// unfamiliar addresses. The Node-level gate at
    /// `src/node/handlers/handshake.rs` carves out msg1 from peers
    /// already established on this transport (so rekey continues to
    /// work) — see ISSUE-2026-0004.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_connections: Option<bool>,
}

impl UdpConfig {
    /// Get the bind address, using default if not configured.
    ///
    /// When `outbound_only = true`, returns `0.0.0.0:0` so the kernel picks
    /// an ephemeral source port and no listener is exposed on a known port.
    pub fn bind_addr(&self) -> &str {
        if self.outbound_only() {
            "0.0.0.0:0"
        } else {
            self.bind_addr.as_deref().unwrap_or(DEFAULT_UDP_BIND_ADDR)
        }
    }

    /// Get the UDP MTU, using default if not configured.
    pub fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_UDP_MTU)
    }

    /// Get the receive buffer size, using default if not configured.
    pub fn recv_buf_size(&self) -> usize {
        self.recv_buf_size.unwrap_or(DEFAULT_UDP_RECV_BUF)
    }

    /// Get the send buffer size, using default if not configured.
    pub fn send_buf_size(&self) -> usize {
        self.send_buf_size.unwrap_or(DEFAULT_UDP_SEND_BUF)
    }

    /// Whether this UDP transport should be advertised on Nostr discovery.
    /// Always false when `outbound_only = true`.
    pub fn advertise_on_nostr(&self) -> bool {
        if self.outbound_only() {
            false
        } else {
            self.advertise_on_nostr.unwrap_or(false)
        }
    }

    /// Whether this UDP transport should be advertised as directly reachable.
    pub fn is_public(&self) -> bool {
        self.public.unwrap_or(false)
    }

    /// Parse `external_addr` against the configured `bind_addr` port,
    /// returning the absolute `SocketAddr` to advertise on Nostr.
    /// Returns `None` if `external_addr` is unset or malformed, or if
    /// the port cannot be inferred.
    pub fn external_advert_addr(&self) -> Option<SocketAddr> {
        let raw = self.external_addr.as_deref()?;
        let bind_port = parse_bind_port(self.bind_addr())?;
        parse_external_advert_addr(raw, bind_port)
    }

    /// Whether this transport runs in outbound-only mode. Default: false.
    pub fn outbound_only(&self) -> bool {
        self.outbound_only.unwrap_or(false)
    }

    /// Whether this transport accepts inbound handshakes. Default: true.
    pub fn accept_connections(&self) -> bool {
        self.accept_connections.unwrap_or(true)
    }
}

/// Default simulated transport MTU (IPv6 minimum).
#[cfg(feature = "sim-transport")]
const DEFAULT_SIM_MTU: u16 = 1280;

/// Default simulated network registry name.
#[cfg(feature = "sim-transport")]
const DEFAULT_SIM_NETWORK: &str = "default";

/// In-memory simulated transport instance configuration.
///
/// This transport is intended for production-backed simulations. It uses the
/// normal node/session/routing stack, but delivers transport packets through a
/// registered in-process network that can model latency, throughput, loss, and
/// churn without binding real sockets.
#[cfg(feature = "sim-transport")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimTransportConfig {
    /// Registry name of the in-process simulated network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// Address of this simulated endpoint within the network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,

    /// Transport MTU. Defaults to 1280.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

    /// Whether discovery should auto-connect to discovered peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_connect: Option<bool>,

    /// Accept inbound handshake msg1 from new peers. Default: true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_connections: Option<bool>,
}

#[cfg(feature = "sim-transport")]
impl SimTransportConfig {
    /// Registry name of the in-process simulated network.
    pub fn network(&self) -> &str {
        self.network.as_deref().unwrap_or(DEFAULT_SIM_NETWORK)
    }

    /// Get the simulated MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_SIM_MTU)
    }

    /// Whether this transport auto-connects to discovered peers.
    pub fn auto_connect(&self) -> bool {
        self.auto_connect.unwrap_or(false)
    }

    /// Whether this transport accepts inbound handshakes.
    pub fn accept_connections(&self) -> bool {
        self.accept_connections.unwrap_or(true)
    }
}

/// Transport instances - either a single config or named instances.
///
/// Allows both simple single-instance config:
/// ```yaml
/// transports:
///   udp:
///     bind_addr: "0.0.0.0:2121"
/// ```
///
/// And multiple named instances:
/// ```yaml
/// transports:
///   udp:
///     main:
///       bind_addr: "0.0.0.0:2121"
///     backup:
///       bind_addr: "192.168.1.100:2122"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TransportInstances<T> {
    /// Single unnamed instance (config fields directly under transport type).
    Single(T),
    /// Multiple named instances.
    Named(HashMap<String, T>),
}

impl<T> TransportInstances<T> {
    /// Get the number of instances.
    pub fn len(&self) -> usize {
        match self {
            TransportInstances::Single(_) => 1,
            TransportInstances::Named(map) => map.len(),
        }
    }

    /// Check if there are no instances.
    pub fn is_empty(&self) -> bool {
        match self {
            TransportInstances::Single(_) => false,
            TransportInstances::Named(map) => map.is_empty(),
        }
    }

    /// Iterate over all instances as (name, config) pairs.
    ///
    /// Single instances have `None` as the name.
    /// Named instances have `Some(name)`.
    pub fn iter(&self) -> impl Iterator<Item = (Option<&str>, &T)> {
        match self {
            TransportInstances::Single(config) => vec![(None, config)].into_iter(),
            TransportInstances::Named(map) => map
                .iter()
                .map(|(k, v)| (Some(k.as_str()), v))
                .collect::<Vec<_>>()
                .into_iter(),
        }
    }
}

impl<T> Default for TransportInstances<T> {
    fn default() -> Self {
        TransportInstances::Named(HashMap::new())
    }
}

/// Default Ethernet EtherType (FIPS default).
const DEFAULT_ETHERNET_ETHERTYPE: u16 = 0x2121;

/// Default Ethernet receive buffer size (2 MB).
const DEFAULT_ETHERNET_RECV_BUF: usize = 2 * 1024 * 1024;

/// Default Ethernet send buffer size (2 MB).
const DEFAULT_ETHERNET_SEND_BUF: usize = 2 * 1024 * 1024;

/// Default beacon announcement interval in seconds.
const DEFAULT_BEACON_INTERVAL_SECS: u64 = 30;

/// Minimum beacon announcement interval in seconds.
const MIN_BEACON_INTERVAL_SECS: u64 = 10;

/// Ethernet transport instance configuration.
///
/// EthernetConfig is always compiled (for config parsing on any platform),
/// but the transport runtime currently requires Linux or macOS raw sockets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EthernetConfig {
    /// Network interface name (e.g., "eth0", "enp3s0"). Required.
    pub interface: String,

    /// Custom EtherType (default: 0x2121).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ethertype: Option<u16>,

    /// MTU override. Defaults to the interface's MTU minus 1 (for frame type prefix).
    /// Cannot exceed the interface's actual MTU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

    /// Receive buffer size in bytes. Default: 2 MB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recv_buf_size: Option<usize>,

    /// Send buffer size in bytes. Default: 2 MB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_buf_size: Option<usize>,

    /// Listen for discovery beacons from other nodes. Default: true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<bool>,

    /// Broadcast announcement beacons on the LAN. Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announce: Option<bool>,

    /// Auto-connect to discovered peers. Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_connect: Option<bool>,

    /// Accept incoming connection attempts. Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_connections: Option<bool>,

    /// Optional discovery scope carried in Ethernet beacons.
    ///
    /// When set, this transport ignores Ethernet beacons from other scopes.
    /// This is a discovery/noise filter, not an access-control mechanism. If
    /// unset, the node-level LAN discovery scope is used when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_scope: Option<String>,

    /// Announcement beacon interval in seconds. Default: 30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beacon_interval_secs: Option<u64>,
}

impl EthernetConfig {
    /// Get the EtherType, using default if not configured.
    pub fn ethertype(&self) -> u16 {
        self.ethertype.unwrap_or(DEFAULT_ETHERNET_ETHERTYPE)
    }

    /// Get the receive buffer size, using default if not configured.
    pub fn recv_buf_size(&self) -> usize {
        self.recv_buf_size.unwrap_or(DEFAULT_ETHERNET_RECV_BUF)
    }

    /// Get the send buffer size, using default if not configured.
    pub fn send_buf_size(&self) -> usize {
        self.send_buf_size.unwrap_or(DEFAULT_ETHERNET_SEND_BUF)
    }

    /// Whether to listen for discovery beacons. Default: true.
    pub fn discovery(&self) -> bool {
        self.discovery.unwrap_or(true)
    }

    /// Whether to broadcast announcement beacons. Default: false.
    pub fn announce(&self) -> bool {
        self.announce.unwrap_or(false)
    }

    /// Whether to auto-connect to discovered peers. Default: false.
    pub fn auto_connect(&self) -> bool {
        self.auto_connect.unwrap_or(false)
    }

    /// Whether to accept incoming connections. Default: false.
    pub fn accept_connections(&self) -> bool {
        self.accept_connections.unwrap_or(false)
    }

    /// Optional discovery scope for Ethernet beacons.
    pub fn discovery_scope(&self) -> Option<&str> {
        self.discovery_scope.as_deref().filter(|s| !s.is_empty())
    }

    /// Get the beacon interval, clamped to minimum. Default: 30s.
    pub fn beacon_interval_secs(&self) -> u64 {
        self.beacon_interval_secs
            .unwrap_or(DEFAULT_BEACON_INTERVAL_SECS)
            .max(MIN_BEACON_INTERVAL_SECS)
    }
}

// ============================================================================
// TCP Transport Configuration
// ============================================================================

/// Default TCP MTU (conservative, matches typical Ethernet MSS minus overhead).
const DEFAULT_TCP_MTU: u16 = 1400;

/// Default TCP connect timeout in milliseconds.
const DEFAULT_TCP_CONNECT_TIMEOUT_MS: u64 = 5000;

/// Default timeout for an accepted inbound TCP connection to deliver its
/// first complete FMP frame.
const DEFAULT_TCP_FIRST_FRAME_TIMEOUT_MS: u64 = 3000;

/// Default TCP keepalive interval in seconds.
const DEFAULT_TCP_KEEPALIVE_SECS: u64 = 30;

/// Default TCP receive buffer size (2 MB).
const DEFAULT_TCP_RECV_BUF: usize = 2 * 1024 * 1024;

/// Default TCP send buffer size (2 MB).
const DEFAULT_TCP_SEND_BUF: usize = 2 * 1024 * 1024;

/// Default maximum inbound TCP connections.
const DEFAULT_TCP_MAX_INBOUND: usize = 256;

/// TCP transport instance configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpConfig {
    /// Listen address (e.g., "0.0.0.0:443"). If not set, outbound-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_addr: Option<String>,

    /// Default MTU for TCP connections. Defaults to 1400.
    /// Per-connection MTU is derived from TCP_MAXSEG when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

    /// Outbound connect timeout in milliseconds. Defaults to 5000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,

    /// Inbound first-frame timeout in milliseconds. Accepted connections
    /// must deliver one complete FMP frame within this window or they are
    /// closed. Set to 0 to disable. Defaults to 3000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_frame_timeout_ms: Option<u64>,

    /// Enable TCP_NODELAY (disable Nagle). Defaults to true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodelay: Option<bool>,

    /// TCP keepalive interval in seconds. 0 = disabled. Defaults to 30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_secs: Option<u64>,

    /// TCP receive buffer size in bytes. Defaults to 2 MB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recv_buf_size: Option<usize>,

    /// TCP send buffer size in bytes. Defaults to 2 MB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_buf_size: Option<usize>,

    /// Maximum simultaneous inbound connections. Defaults to 256.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_inbound_connections: Option<usize>,

    /// Whether this transport should be advertised on Nostr overlay discovery.
    /// Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertise_on_nostr: Option<bool>,

    /// Optional explicit public address to advertise. Required when
    /// `bind_addr` is wildcard (e.g. `"0.0.0.0:443"`) and
    /// `advertise_on_nostr: true`, since TCP has no STUN equivalent
    /// for autodiscovery. Accepts either a bare IP (`"198.51.100.1"`
    /// — the configured `bind_addr` port is appended) or a full
    /// `host:port`. Common pattern on AWS EIP / cloud 1:1 NAT setups
    /// where the public IP isn't bindable on the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_addr: Option<String>,
}

impl TcpConfig {
    /// Get the default MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_TCP_MTU)
    }

    /// Get the connect timeout in milliseconds.
    pub fn connect_timeout_ms(&self) -> u64 {
        self.connect_timeout_ms
            .unwrap_or(DEFAULT_TCP_CONNECT_TIMEOUT_MS)
    }

    /// Get the inbound first-frame timeout in milliseconds. 0 disables it.
    pub fn first_frame_timeout_ms(&self) -> u64 {
        self.first_frame_timeout_ms
            .unwrap_or(DEFAULT_TCP_FIRST_FRAME_TIMEOUT_MS)
    }

    /// Whether TCP_NODELAY is enabled. Default: true.
    pub fn nodelay(&self) -> bool {
        self.nodelay.unwrap_or(true)
    }

    /// Get the keepalive interval in seconds. 0 = disabled. Default: 30.
    pub fn keepalive_secs(&self) -> u64 {
        self.keepalive_secs.unwrap_or(DEFAULT_TCP_KEEPALIVE_SECS)
    }

    /// Get the receive buffer size. Default: 2 MB.
    pub fn recv_buf_size(&self) -> usize {
        self.recv_buf_size.unwrap_or(DEFAULT_TCP_RECV_BUF)
    }

    /// Get the send buffer size. Default: 2 MB.
    pub fn send_buf_size(&self) -> usize {
        self.send_buf_size.unwrap_or(DEFAULT_TCP_SEND_BUF)
    }

    /// Get the maximum number of inbound connections. Default: 256.
    pub fn max_inbound_connections(&self) -> usize {
        self.max_inbound_connections
            .unwrap_or(DEFAULT_TCP_MAX_INBOUND)
    }

    /// Whether this TCP transport should be advertised on Nostr discovery.
    pub fn advertise_on_nostr(&self) -> bool {
        self.advertise_on_nostr.unwrap_or(false)
    }

    /// Parse `external_addr` against the configured `bind_addr` port,
    /// returning the absolute `SocketAddr` to advertise on Nostr.
    /// Returns `None` if `external_addr` is unset or malformed, or if
    /// `bind_addr` is unset / unparseable so no port can be inferred.
    pub fn external_advert_addr(&self) -> Option<SocketAddr> {
        let raw = self.external_addr.as_deref()?;
        let bind_port = parse_bind_port(self.bind_addr.as_deref()?)?;
        parse_external_advert_addr(raw, bind_port)
    }
}

// ============================================================================
// Tor Transport Configuration
// ============================================================================

/// Default Tor SOCKS5 proxy address.
const DEFAULT_TOR_SOCKS5_ADDR: &str = "127.0.0.1:9050";

/// Default Tor control port address.
const DEFAULT_TOR_CONTROL_ADDR: &str = "/run/tor/control";

/// Default Tor control cookie file path (Debian standard location).
const DEFAULT_TOR_COOKIE_PATH: &str = "/var/run/tor/control.authcookie";

/// Default Tor connect timeout in milliseconds (120s — Tor circuit
/// establishment can take 30-60s on first connect, plus SOCKS5 handshake).
const DEFAULT_TOR_CONNECT_TIMEOUT_MS: u64 = 120_000;

/// Default Tor MTU (same as TCP).
const DEFAULT_TOR_MTU: u16 = 1400;

/// Default max inbound connections via onion service.
const DEFAULT_TOR_MAX_INBOUND: usize = 64;

/// Default HiddenServiceDir hostname file path.
const DEFAULT_HOSTNAME_FILE: &str = "/var/lib/tor/fips_onion_service/hostname";

/// Default directory mode bind address.
const DEFAULT_DIRECTORY_BIND_ADDR: &str = "127.0.0.1:8443";

/// Default advertised onion port for Nostr overlay discovery. Matches the
/// Tor convention of `HiddenServicePort 443 127.0.0.1:<bind_port>` in torrc.
const DEFAULT_TOR_ADVERTISED_PORT: u16 = 443;

/// Tor transport instance configuration.
///
/// Supports three modes:
/// - `socks5`: Outbound-only connections through a Tor SOCKS5 proxy.
/// - `control_port`: Full bidirectional support — outbound via SOCKS5
///   plus inbound via Tor onion service managed through the control port.
/// - `directory`: Full bidirectional support — outbound via SOCKS5,
///   inbound via a Tor-managed `HiddenServiceDir` onion service. No
///   control port needed. Enables Tor `Sandbox 1` mode.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TorConfig {
    /// Tor access mode: "socks5", "control_port", or "directory".
    /// Default: "socks5".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// SOCKS5 proxy address (host:port). Defaults to "127.0.0.1:9050".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks5_addr: Option<String>,

    /// Outbound connect timeout in milliseconds. Defaults to 120000 (120s).
    /// Tor circuit establishment can take 30-60s, so this must be generous.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,

    /// Default MTU for Tor connections. Defaults to 1400.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

    /// Control port address: a Unix socket path (`/run/tor/control`) or
    /// TCP address (`host:port`). Unix sockets are preferred for security.
    /// Defaults to "/run/tor/control".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_addr: Option<String>,

    /// Control port authentication method:
    /// `"cookie"` (read from default path),
    /// `"cookie:/path/to/cookie"` (read from specified path), or
    /// `"password:secret"` (password auth). Default: `"cookie"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_auth: Option<String>,

    /// Path to the Tor control cookie file. Used when control_auth is "cookie".
    /// Defaults to "/var/run/tor/control.authcookie".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_path: Option<String>,

    /// Maximum number of inbound connections via onion service. Default: 64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_inbound_connections: Option<usize>,

    /// Directory-mode onion service configuration. Only valid in
    /// "directory" mode. Tor manages the onion service via HiddenServiceDir
    /// in torrc; fips reads the .onion hostname from a file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_service: Option<DirectoryServiceConfig>,

    /// Whether this transport should be advertised on Nostr overlay discovery.
    /// Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertise_on_nostr: Option<bool>,

    /// Public-facing onion port published in Nostr overlay adverts. Must
    /// match the virtual port in torrc's `HiddenServicePort <port>
    /// 127.0.0.1:<bind_port>` directive — that is the port other peers
    /// will use to reach this onion. Default: 443.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertised_port: Option<u16>,
}

/// Directory-mode onion service configuration.
///
/// In `directory` mode, Tor manages the onion service via `HiddenServiceDir`
/// in torrc. FIPS reads the `.onion` address from the hostname file and
/// binds a local TCP listener for Tor to forward inbound connections to.
/// This mode requires no control port and enables Tor's `Sandbox 1`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServiceConfig {
    /// Path to the Tor-managed hostname file containing the .onion address.
    /// Defaults to "/var/lib/tor/fips_onion_service/hostname".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname_file: Option<String>,

    /// Local bind address for the listener that Tor forwards inbound
    /// connections to. Must match the target in torrc's `HiddenServicePort`.
    /// Defaults to "127.0.0.1:8443".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_addr: Option<String>,
}

impl DirectoryServiceConfig {
    /// Path to the hostname file. Default: "/var/lib/tor/fips_onion_service/hostname".
    pub fn hostname_file(&self) -> &str {
        self.hostname_file
            .as_deref()
            .unwrap_or(DEFAULT_HOSTNAME_FILE)
    }

    /// Local bind address for the listener. Default: "127.0.0.1:8443".
    pub fn bind_addr(&self) -> &str {
        self.bind_addr
            .as_deref()
            .unwrap_or(DEFAULT_DIRECTORY_BIND_ADDR)
    }
}

impl TorConfig {
    /// Get the access mode. Default: "socks5".
    pub fn mode(&self) -> &str {
        self.mode.as_deref().unwrap_or("socks5")
    }

    /// Get the SOCKS5 proxy address. Default: "127.0.0.1:9050".
    pub fn socks5_addr(&self) -> &str {
        self.socks5_addr
            .as_deref()
            .unwrap_or(DEFAULT_TOR_SOCKS5_ADDR)
    }

    /// Get the control port address. Default: "/run/tor/control".
    pub fn control_addr(&self) -> &str {
        self.control_addr
            .as_deref()
            .unwrap_or(DEFAULT_TOR_CONTROL_ADDR)
    }

    /// Get the control auth string. Default: "cookie".
    pub fn control_auth(&self) -> &str {
        self.control_auth.as_deref().unwrap_or("cookie")
    }

    /// Get the cookie file path. Default: "/var/run/tor/control.authcookie".
    pub fn cookie_path(&self) -> &str {
        self.cookie_path
            .as_deref()
            .unwrap_or(DEFAULT_TOR_COOKIE_PATH)
    }

    /// Get the connect timeout in milliseconds. Default: 120000.
    pub fn connect_timeout_ms(&self) -> u64 {
        self.connect_timeout_ms
            .unwrap_or(DEFAULT_TOR_CONNECT_TIMEOUT_MS)
    }

    /// Get the default MTU. Default: 1400.
    pub fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_TOR_MTU)
    }

    /// Get the max inbound connections. Default: 64.
    pub fn max_inbound_connections(&self) -> usize {
        self.max_inbound_connections
            .unwrap_or(DEFAULT_TOR_MAX_INBOUND)
    }

    /// Whether this Tor transport should be advertised on Nostr discovery.
    pub fn advertise_on_nostr(&self) -> bool {
        self.advertise_on_nostr.unwrap_or(false)
    }

    /// Public-facing onion port published in Nostr overlay adverts.
    /// Default: 443.
    pub fn advertised_port(&self) -> u16 {
        self.advertised_port.unwrap_or(DEFAULT_TOR_ADVERTISED_PORT)
    }
}

// ============================================================================
// WebRTC Transport Configuration
// ============================================================================

/// Default WebRTC data-channel MTU.
const DEFAULT_WEBRTC_MTU: u16 = 1200;

/// Default WebRTC connection timeout in milliseconds.
const DEFAULT_WEBRTC_CONNECT_TIMEOUT_MS: u64 = 30_000;

/// Default non-trickle ICE gathering timeout in milliseconds.
const DEFAULT_WEBRTC_ICE_GATHER_TIMEOUT_MS: u64 = 2_000;

/// Default maximum simultaneous WebRTC peer connections.
const DEFAULT_WEBRTC_MAX_CONNECTIONS: usize = 32;

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

    /// Maximum simultaneous WebRTC peer connections. Defaults to 32.
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

    /// Override STUN servers for this transport. When unset,
    /// `node.discovery.nostr.stun_servers` is used.
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
            .filter(|servers| !servers.is_empty())
            .cloned()
            .unwrap_or_else(|| fallback.to_vec())
    }
}

mod aggregate;
mod ble;
#[cfg(test)]
mod tests;

pub use aggregate::TransportsConfig;
pub use ble::BleConfig;
