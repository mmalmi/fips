//! Host-owned routing and DNS for outer transport sockets.
//!
//! This policy applies before a socket can send a handshake or payload. It does
//! not change FIPS addresses, packets, peer selection, or forwarding policy.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

mod nostr;
#[cfg(feature = "webrtc-transport")]
mod webrtc;
pub use nostr::NostrHostTransport;
#[cfg(feature = "webrtc-transport")]
pub(crate) use webrtc::native_network;

#[cfg(test)]
mod tests;

/// Network access supplied by an embedding host, such as a VPN with an
/// independent route for its encrypted carrier connections.
pub trait HostNetwork: std::fmt::Debug + Send + Sync {
    /// Protect a socket before connect, listen, or send. UDP sockets may
    /// already be bound when adopted from another protected host subsystem.
    /// Errors prevent the socket from being used; callers never fall back to
    /// an unprotected socket. Accepted sockets must inherit this protection.
    fn protect_socket(&self, socket: &socket2::SockRef<'_>) -> io::Result<()>;

    /// Resolve a transport address (`hostname:port`) using the host's carrier
    /// network. Preserve the desired address ordering and both IP families.
    fn resolve<'a>(
        &'a self,
        address: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + Sync + 'a>>;
}

pub(crate) fn mdns_daemon(
    policy: Option<&std::sync::Arc<dyn HostNetwork>>,
) -> io::Result<mdns_sd::ServiceDaemon> {
    match policy {
        Some(policy) => {
            let policy = policy.clone();
            mdns_sd::ServiceDaemon::new_with_socket_protector(
                mdns_sd::MDNS_PORT,
                std::sync::Arc::new(move |socket| {
                    policy.protect_socket(&socket2::SockRef::from(socket))
                }),
            )
            .map_err(io::Error::other)
        }
        None => mdns_sd::ServiceDaemon::new().map_err(io::Error::other),
    }
}

pub(crate) async fn resolve(
    policy: Option<&dyn HostNetwork>,
    address: &str,
) -> io::Result<Vec<SocketAddr>> {
    if let Ok(address) = address.parse::<SocketAddr>() {
        return Ok(vec![address]);
    }
    match policy {
        Some(policy) => policy.resolve(address).await,
        None => tokio::net::lookup_host(address)
            .await
            .map(Iterator::collect),
    }
}

pub(crate) async fn connect_tcp(
    policy: Option<&dyn HostNetwork>,
    address: SocketAddr,
) -> io::Result<tokio::net::TcpStream> {
    let Some(policy) = policy else {
        return tokio::net::TcpStream::connect(address).await;
    };
    let socket = if address.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    policy.protect_socket(&socket2::SockRef::from(&socket))?;
    socket.connect(address).await
}

pub(crate) async fn connect_tcp_host(
    policy: Option<&dyn HostNetwork>,
    address: &str,
) -> io::Result<tokio::net::TcpStream> {
    let mut last_error = io::Error::new(
        io::ErrorKind::NotFound,
        "host resolver returned no addresses",
    );
    for address in resolve(policy, address).await? {
        match connect_tcp(policy, address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

pub(crate) async fn listen_tcp_host(
    policy: Option<&dyn HostNetwork>,
    address: &str,
) -> io::Result<tokio::net::TcpListener> {
    let mut last_error = io::Error::new(
        io::ErrorKind::NotFound,
        "host resolver returned no addresses",
    );
    for address in resolve(policy, address).await? {
        match listen_tcp(policy, address).await {
            Ok(listener) => return Ok(listener),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

pub(crate) async fn listen_tcp(
    policy: Option<&dyn HostNetwork>,
    address: SocketAddr,
) -> io::Result<tokio::net::TcpListener> {
    let Some(policy) = policy else {
        return tokio::net::TcpListener::bind(address).await;
    };
    let socket = if address.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    policy.protect_socket(&socket2::SockRef::from(&socket))?;
    // Match Tokio's ordinary listener setup on each platform.
    #[cfg(not(windows))]
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(1024)
}

/// Establish an outer WebSocket using the host's DNS and protected TCP socket.
/// The original request supplies the TLS hostname, Host header and path.
pub async fn connect_websocket(
    policy: Option<&dyn HostNetwork>,
    url: &str,
    config: Option<tokio_tungstenite::tungstenite::protocol::WebSocketConfig>,
    connector: Option<tokio_tungstenite::Connector>,
) -> Result<
    (
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tokio_tungstenite::tungstenite::handshake::client::Response,
    ),
    tokio_tungstenite::tungstenite::Error,
> {
    use tokio_tungstenite::tungstenite::{Error, client::IntoClientRequest, error::UrlError};
    let Some(policy) = policy else {
        return tokio_tungstenite::connect_async_tls_with_config(url, config, false, connector)
            .await;
    };
    let request = url.into_client_request()?;
    let uri = request.uri();
    let default_port = match uri.scheme_str() {
        Some("ws") => 80,
        Some("wss") => 443,
        _ => return Err(Error::Url(UrlError::UnsupportedUrlScheme)),
    };
    let host = uri.host().ok_or(Error::Url(UrlError::NoHostName))?;
    let port = uri.port_u16().unwrap_or(default_port);
    let address = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let stream = connect_tcp_host(Some(policy), &address).await?;
    tokio_tungstenite::client_async_tls_with_config(request, stream, config, connector).await
}
