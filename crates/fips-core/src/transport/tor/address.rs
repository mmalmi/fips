use crate::transport::{TransportAddr, TransportError};
use std::net::SocketAddr;

// ============================================================================
// Tor Address Types
// ============================================================================

/// Tor-specific address type for SOCKS5 CONNECT.
#[derive(Clone, Debug)]
pub enum TorAddr {
    /// .onion hidden service address (hostname, port).
    Onion(String, u16),
    /// Clearnet address routed through Tor (IP, port).
    Clearnet(SocketAddr),
    /// Clearnet hostname routed through Tor (hostname, port).
    /// Passed as hostname to SOCKS5 so Tor resolves it — avoids local
    /// DNS leaks and is compatible with SafeSocks 1.
    ClearnetHostname(String, u16),
}

/// Parse a TransportAddr string into a TorAddr.
///
/// If the address contains ".onion:", parse as an onion address.
/// If it parses as a numeric IP:port, use Clearnet.
/// Otherwise, treat as a clearnet hostname:port for Tor-side DNS resolution.
pub(super) fn parse_tor_addr(addr: &TransportAddr) -> Result<TorAddr, TransportError> {
    let s = addr.as_str().ok_or_else(|| {
        TransportError::InvalidAddress("Tor address must be a valid UTF-8 string".into())
    })?;

    if s.contains(".onion:") {
        // Parse "hostname.onion:port"
        let (host, port_str) = s.rsplit_once(':').ok_or_else(|| {
            TransportError::InvalidAddress(format!("invalid onion address: {}", s))
        })?;
        let port: u16 = port_str.parse().map_err(|_| {
            TransportError::InvalidAddress(format!("invalid port in onion address: {}", s))
        })?;
        Ok(TorAddr::Onion(host.to_string(), port))
    } else if let Ok(socket_addr) = s.parse::<SocketAddr>() {
        // Numeric IP:port
        Ok(TorAddr::Clearnet(socket_addr))
    } else {
        // Hostname:port — pass through SOCKS5 for Tor-side DNS resolution
        let (host, port_str) = s.rsplit_once(':').ok_or_else(|| {
            TransportError::InvalidAddress(format!("invalid address (expected host:port): {}", s))
        })?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| TransportError::InvalidAddress(format!("invalid port: {}", s)))?;
        if !host.contains('.') {
            return Err(TransportError::InvalidAddress(format!(
                "hostname must be fully qualified (contain a dot): {}",
                host
            )));
        }
        Ok(TorAddr::ClearnetHostname(host.to_string(), port))
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Validate that a string is in host:port format.
pub(super) fn validate_host_port(addr: &str, field_name: &str) -> Result<(), TransportError> {
    if addr.parse::<SocketAddr>().is_ok() {
        return Ok(());
    }
    // Not a raw IP:port — check it's at least host:port format
    let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
    if parts.len() != 2 || parts[0].parse::<u16>().is_err() || parts[1].is_empty() {
        return Err(TransportError::StartFailed(format!(
            "invalid {} '{}': expected host:port or IP:port",
            field_name, addr
        )));
    }
    Ok(())
}
