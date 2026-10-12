use super::{TransportAddr, TransportError};
use std::net::SocketAddr;

// ============================================================================
// DNS Resolution
// ============================================================================

/// Resolve a TransportAddr to a SocketAddr.
///
/// Fast path: if the address parses as a numeric IP:port, returns
/// immediately with no DNS lookup. Otherwise, treats the address as
/// `hostname:port` and performs async DNS resolution via the system
/// resolver.
pub(crate) async fn resolve_socket_addr(
    addr: &TransportAddr,
) -> Result<SocketAddr, TransportError> {
    resolve_socket_addr_with_network(addr, None).await
}

pub(crate) async fn resolve_socket_addr_with_network(
    addr: &TransportAddr,
    network: Option<&dyn crate::host_network::HostNetwork>,
) -> Result<SocketAddr, TransportError> {
    resolve_socket_addrs_with_network(addr, network)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| {
            TransportError::InvalidAddress(format!(
                "DNS resolution returned no addresses for {}",
                addr.as_str().unwrap_or("<non-utf8>")
            ))
        })
}

/// Resolve a TransportAddr to every SocketAddr returned by the resolver.
///
/// Numeric IP addresses still bypass DNS. Hostnames keep the resolver's
/// address order, and callers that establish connections should try more than
/// one address so dual-stack hosts still work when one address family is
/// temporarily broken.
pub(crate) async fn resolve_socket_addrs_with_network(
    addr: &TransportAddr,
    network: Option<&dyn crate::host_network::HostNetwork>,
) -> Result<Vec<SocketAddr>, TransportError> {
    let s = addr
        .as_str()
        .ok_or_else(|| TransportError::InvalidAddress("not valid UTF-8".into()))?;

    // Fast path: numeric IP address — no DNS lookup
    if let Ok(sock_addr) = s.parse::<SocketAddr>() {
        return Ok(vec![sock_addr]);
    }

    // Slow path: DNS resolution
    let addrs = crate::host_network::resolve(network, s)
        .await
        .map_err(|e| {
            TransportError::InvalidAddress(format!("DNS resolution failed for {}: {}", s, e))
        })?;
    if addrs.is_empty() {
        return Err(TransportError::InvalidAddress(format!(
            "DNS resolution returned no addresses for {}",
            s
        )));
    }
    Ok(addrs)
}
