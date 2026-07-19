//! Tor transport configuration.

use serde::{Deserialize, Serialize};

/// Default Tor SOCKS5 proxy address.
const DEFAULT_TOR_SOCKS5_ADDR: &str = "127.0.0.1:9050";

/// Default Tor control port address.
const DEFAULT_TOR_CONTROL_ADDR: &str = "/run/tor/control";

/// Default Tor control cookie file path (Debian standard location).
const DEFAULT_TOR_COOKIE_PATH: &str = "/var/run/tor/control.authcookie";

/// Default Tor connect timeout in milliseconds (120s — Tor circuit
/// establishment can take 30-60s on first connect, plus SOCKS5 handshake).
const DEFAULT_TOR_CONNECT_TIMEOUT_MS: u64 = 120_000;

/// Default Tor dataplane/path budget (same as TCP).
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

    /// Dataplane/path budget advertised for Tor routes. Defaults to 1400.
    /// Tor byte-stream framing is bounded by the FMP/FSP wire record's u16
    /// payload length, independently of this budget.
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
