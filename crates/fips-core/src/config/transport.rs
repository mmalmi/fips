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

/// Default TCP dataplane/path budget.
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

/// Default WebSocket path accepted by the native plain-WS listener.
const DEFAULT_WEBSOCKET_PATH: &str = "/fips";

/// Default WebSocket FIPS path MTU.
const DEFAULT_WEBSOCKET_MTU: u16 = 1400;

/// Largest legal FIPS record plus conservative header room.
const DEFAULT_WEBSOCKET_MAX_FRAME_BYTES: usize = 66 * 1024;

const DEFAULT_WEBSOCKET_CONNECT_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_WEBSOCKET_KEY_HINT_TIMEOUT_MS: u64 = 3_000;
const DEFAULT_WEBSOCKET_RECONNECT_INITIAL_MS: u64 = 1_000;
const DEFAULT_WEBSOCKET_RECONNECT_MAX_MS: u64 = 30_000;
const DEFAULT_WEBSOCKET_MAX_CONNECTIONS: usize = 256;
const DEFAULT_WEBSOCKET_MAX_INBOUND: usize = 128;
const DEFAULT_WEBSOCKET_MAX_SEND_QUEUE: usize = 256;
const DEFAULT_WEBSOCKET_PING_INTERVAL_SECS: u64 = 20;
const DEFAULT_WEBSOCKET_IDLE_TIMEOUT_SECS: u64 = 90;

/// TCP transport instance configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpConfig {
    /// Listen address (e.g., "0.0.0.0:443"). If not set, outbound-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_addr: Option<String>,

    /// Dataplane/path budget advertised for TCP routes. Defaults to 1400.
    /// TCP byte-stream framing is independent of TCP_MAXSEG and is bounded by
    /// the FMP/FSP wire record's u16 payload length.
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

/// WebSocket physical transport configuration.
///
/// The native listener intentionally speaks plain WebSocket so deployments can
/// bind it to localhost or a private interface and terminate TLS in a reverse
/// proxy. Clients use explicit `wss://` seed URLs; plaintext `ws://` seeds are
/// accepted only for loopback development and tests. A bounded nonce/key-hint
/// exchange identifies a URL-only seed before Noise IK; after that exchange,
/// every binary WebSocket message carries exactly one bounded FIPS physical
/// record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketConfig {
    /// Optional native plain-WS listener address. Unset means client-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_addr: Option<String>,

    /// Public `wss://` URL advertised for this listener, separate from bind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,

    /// One or more explicit first-adjacency seed URLs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seed_urls: Vec<String>,

    /// HTTP path accepted by the native listener. Defaults to `/fips`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Dataplane/path budget. Defaults to 1400 bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

    /// Maximum binary WebSocket message size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_frame_bytes: Option<usize>,

    /// Maximum queued outbound records per connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_send_queue: Option<usize>,

    /// Maximum total WebSocket connections for this transport instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<usize>,

    /// Maximum simultaneous inbound WebSocket connections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_inbound_connections: Option<usize>,

    /// Outbound TCP/TLS/WebSocket connect timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,

    /// Time allowed for the untrusted seed-key hint exchange.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_hint_timeout_ms: Option<u64>,

    /// Initial reconnect delay for configured seeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_initial_ms: Option<u64>,

    /// Maximum reconnect delay for configured seeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_max_ms: Option<u64>,

    /// WebSocket ping interval. Zero disables transport pings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping_interval_secs: Option<u64>,

    /// Close connections with no received frame for this long. Zero disables.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_secs: Option<u64>,

    /// Accept fresh inbound Noise IK handshakes. Defaults to true whenever the
    /// transport has a listener or seed URL. WebSocket dial direction does not
    /// constrain FIPS session direction on an established routed adjacency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_connections: Option<bool>,
}

impl WebSocketConfig {
    pub fn path(&self) -> &str {
        self.path.as_deref().unwrap_or(DEFAULT_WEBSOCKET_PATH)
    }

    pub fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_WEBSOCKET_MTU)
    }

    pub fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
            .unwrap_or(DEFAULT_WEBSOCKET_MAX_FRAME_BYTES)
    }

    pub fn max_send_queue(&self) -> usize {
        self.max_send_queue
            .unwrap_or(DEFAULT_WEBSOCKET_MAX_SEND_QUEUE)
            .max(1)
    }

    pub fn max_connections(&self) -> usize {
        self.max_connections
            .unwrap_or(DEFAULT_WEBSOCKET_MAX_CONNECTIONS)
            .max(1)
    }

    pub fn max_inbound_connections(&self) -> usize {
        self.max_inbound_connections
            .unwrap_or(DEFAULT_WEBSOCKET_MAX_INBOUND)
            .max(1)
            .min(self.max_connections())
    }

    pub fn connect_timeout_ms(&self) -> u64 {
        self.connect_timeout_ms
            .unwrap_or(DEFAULT_WEBSOCKET_CONNECT_TIMEOUT_MS)
            .max(1)
    }

    pub fn key_hint_timeout_ms(&self) -> u64 {
        self.key_hint_timeout_ms
            .unwrap_or(DEFAULT_WEBSOCKET_KEY_HINT_TIMEOUT_MS)
            .max(1)
    }

    pub fn reconnect_initial_ms(&self) -> u64 {
        self.reconnect_initial_ms
            .unwrap_or(DEFAULT_WEBSOCKET_RECONNECT_INITIAL_MS)
            .max(1)
    }

    pub fn reconnect_max_ms(&self) -> u64 {
        self.reconnect_max_ms
            .unwrap_or(DEFAULT_WEBSOCKET_RECONNECT_MAX_MS)
            .max(self.reconnect_initial_ms())
    }

    pub fn ping_interval_secs(&self) -> u64 {
        self.ping_interval_secs
            .unwrap_or(DEFAULT_WEBSOCKET_PING_INTERVAL_SECS)
    }

    pub fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
            .unwrap_or(DEFAULT_WEBSOCKET_IDLE_TIMEOUT_SECS)
    }

    pub fn accept_connections(&self) -> bool {
        self.accept_connections
            .unwrap_or_else(|| self.bind_addr.is_some() || !self.seed_urls.is_empty())
    }

    pub fn validate(&self) -> Result<(), String> {
        if let Some(bind_addr) = self.bind_addr.as_deref() {
            bind_addr
                .parse::<SocketAddr>()
                .map_err(|error| format!("invalid bind_addr {bind_addr:?}: {error}"))?;
        }
        if !self.path().starts_with('/') || self.path().contains('?') || self.path().contains('#') {
            return Err("path must be an absolute HTTP path without query or fragment".into());
        }
        if let Some(public_url) = self.public_url.as_deref() {
            validate_websocket_url(public_url, false)?;
            let uri = public_url
                .parse::<tokio_tungstenite::tungstenite::http::Uri>()
                .map_err(|error| format!("invalid public_url: {error}"))?;
            if uri.path() != self.path() {
                return Err(format!(
                    "public_url path {:?} does not match configured path {:?}",
                    uri.path(),
                    self.path()
                ));
            }
            if self.bind_addr.is_none() {
                return Err("public_url requires bind_addr".into());
            }
        }
        let mut unique = std::collections::HashSet::new();
        for seed_url in &self.seed_urls {
            validate_websocket_url(seed_url, true)?;
            if !unique.insert(seed_url) {
                return Err(format!("duplicate seed URL {seed_url:?}"));
            }
        }
        let minimum_frame = usize::from(self.mtu()).saturating_add(64);
        if self.max_frame_bytes() < minimum_frame || self.max_frame_bytes() > 1024 * 1024 {
            return Err(format!(
                "max_frame_bytes must be between {minimum_frame} and 1048576"
            ));
        }
        if self.max_send_queue() > 4096 {
            return Err("max_send_queue must not exceed 4096".into());
        }
        if self.max_connections() > 4096 {
            return Err("max_connections must not exceed 4096".into());
        }
        if self.max_inbound_connections() > self.max_connections() {
            return Err("max_inbound_connections must not exceed max_connections".into());
        }
        if self.ping_interval_secs() > 0
            && self.idle_timeout_secs() > 0
            && self.idle_timeout_secs() <= self.ping_interval_secs()
        {
            return Err("idle_timeout_secs must exceed ping_interval_secs".into());
        }
        Ok(())
    }
}

fn validate_websocket_url(raw: &str, allow_loopback_plaintext: bool) -> Result<(), String> {
    let uri = raw
        .parse::<tokio_tungstenite::tungstenite::http::Uri>()
        .map_err(|error| format!("invalid WebSocket URL {raw:?}: {error}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| format!("WebSocket URL {raw:?} is missing a scheme"))?;
    let host = uri
        .host()
        .ok_or_else(|| format!("WebSocket URL {raw:?} is missing a host"))?;
    if uri.authority().is_none() || uri.path().is_empty() {
        return Err(format!("invalid WebSocket URL {raw:?}"));
    }
    match scheme {
        "wss" => Ok(()),
        "ws" if allow_loopback_plaintext && websocket_host_is_loopback(host) => Ok(()),
        "ws" => Err(format!(
            "plaintext WebSocket URL {raw:?} is allowed only for loopback seeds"
        )),
        _ => Err(format!("WebSocket URL {raw:?} must use wss://")),
    }
}

fn websocket_host_is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

mod aggregate;
mod ble;
#[cfg(test)]
mod tests;
mod tor;
mod webrtc;

pub use aggregate::TransportsConfig;
pub use ble::BleConfig;
pub use tor::{DirectoryServiceConfig, TorConfig};
pub use webrtc::WebRtcConfig;
