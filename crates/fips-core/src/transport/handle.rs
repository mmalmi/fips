//! Enum wrapper for concrete transport implementations.

#[cfg(target_os = "linux")]
use super::ble::DefaultBleTransport;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::ethernet::EthernetTransport;
use super::nostr_relay::NostrRelayTransport;
#[cfg(feature = "sim-transport")]
use super::sim::SimTransport;
use super::tcp::TcpTransport;
use super::tor::TorTransport;
use super::tor::control::TorMonitoringInfo;
use super::udp::UdpTransport;
#[cfg(feature = "webrtc-transport")]
use super::webrtc::WebRtcTransport;
use super::{
    ConnectionState, DiscoveredPeer, Transport, TransportAddr, TransportCongestion, TransportError,
    TransportId, TransportState, TransportType,
};

const TCP_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// Wrapper enum for concrete transport implementations.
///
/// This enables polymorphic transport handling without trait objects,
/// supporting async methods that the sync Transport trait cannot express.
pub enum TransportHandle {
    /// UDP/IP transport.
    Udp(UdpTransport),
    /// Encrypted FIPS datagrams carried by ephemeral Nostr relay events.
    NostrRelay(Box<NostrRelayTransport>),
    /// In-memory simulated packet transport.
    #[cfg(feature = "sim-transport")]
    Sim(SimTransport),
    /// Raw Ethernet transport.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Ethernet(EthernetTransport),
    /// TCP/IP transport.
    Tcp(TcpTransport),
    /// Tor transport (via SOCKS5).
    Tor(TorTransport),
    /// WebRTC DataChannel transport.
    #[cfg(feature = "webrtc-transport")]
    WebRtc(Box<WebRtcTransport>),
    /// BLE L2CAP transport.
    #[cfg(target_os = "linux")]
    Ble(DefaultBleTransport),
}

impl TransportHandle {
    /// Normalize transport-specific addresses before Node stores or compares
    /// them. Most transports have one textual identity; WebRTC uses Nostr's
    /// x-only identity and therefore collapses legacy 02/03 compressed forms.
    pub(crate) fn canonical_addr(
        &self,
        addr: &TransportAddr,
    ) -> Result<TransportAddr, TransportError> {
        match self {
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(_) => super::webrtc::canonical_webrtc_addr(addr),
            _ => Ok(addr.clone()),
        }
    }

    /// Drain adapter negotiations that must travel over the standard FSP
    /// link-negotiation service.
    #[cfg(feature = "webrtc-transport")]
    pub(crate) fn drain_link_negotiations(
        &mut self,
        limit: usize,
    ) -> Vec<super::link_negotiation::OutboundLinkNegotiation> {
        match self {
            TransportHandle::WebRtc(transport) => transport.drain_link_negotiations(limit),
            _ => Vec::new(),
        }
    }

    /// Deliver an authenticated negotiation to the enabled matching adapter.
    #[cfg(feature = "webrtc-transport")]
    pub(crate) fn ingest_link_negotiation(
        &self,
        source: secp256k1::PublicKey,
        message: super::link_negotiation::LinkNegotiationMessage,
    ) -> Result<(), TransportError> {
        match self {
            TransportHandle::WebRtc(transport) if message.link_type == "webrtc" => {
                transport.ingest_link_negotiation(source, message)
            }
            _ => Err(TransportError::NotSupported(
                "no enabled adapter accepts this link negotiation".into(),
            )),
        }
    }

    /// Start the transport asynchronously.
    pub async fn start(&mut self) -> Result<(), TransportError> {
        match self {
            TransportHandle::Udp(t) => t.start_async().await,
            TransportHandle::NostrRelay(t) => t.start(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.start_async().await,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.start_async().await,
            TransportHandle::Tcp(t) => t.start_async().await,
            TransportHandle::Tor(t) => t.start_async().await,
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.start_async().await,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.start_async().await,
        }
    }

    /// Stop the transport asynchronously.
    pub async fn stop(&mut self) -> Result<(), TransportError> {
        match self {
            TransportHandle::Udp(t) => t.stop_async().await,
            TransportHandle::NostrRelay(t) => t.stop(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.stop_async().await,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.stop_async().await,
            TransportHandle::Tcp(t) => t.stop_async().await,
            TransportHandle::Tor(t) => t.stop_async().await,
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.stop_async().await,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.stop_async().await,
        }
    }

    /// Send data to a remote address asynchronously.
    pub async fn send(&self, addr: &TransportAddr, data: &[u8]) -> Result<usize, TransportError> {
        match self {
            TransportHandle::Udp(t) => t.send_async(addr, data).await,
            TransportHandle::NostrRelay(t) => t.send(addr, data).map(|()| data.len()),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.send_async(addr, data).await,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.send_async(addr, data).await,
            TransportHandle::Tcp(t) => {
                tokio::time::timeout(TCP_SEND_TIMEOUT, t.send_async(addr, data))
                    .await
                    .unwrap_or(Err(TransportError::Timeout))
            }
            TransportHandle::Tor(t) => t.send_async(addr, data).await,
            #[cfg(feature = "webrtc-transport")]
            // Keep this optional adapter's large future out of every transport send frame.
            TransportHandle::WebRtc(t) => Box::pin(t.send_async(addr, data)).await,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.send_async(addr, data).await,
        }
    }

    /// Get the transport ID.
    pub fn transport_id(&self) -> TransportId {
        match self {
            TransportHandle::Udp(t) => t.transport_id(),
            TransportHandle::NostrRelay(t) => t.transport_id(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.transport_id(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.transport_id(),
            TransportHandle::Tcp(t) => t.transport_id(),
            TransportHandle::Tor(t) => t.transport_id(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.transport_id(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.transport_id(),
        }
    }

    /// Get the instance name (if configured as a named instance).
    pub fn name(&self) -> Option<&str> {
        match self {
            TransportHandle::Udp(t) => t.name(),
            TransportHandle::NostrRelay(t) => t.name(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.name(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.name(),
            TransportHandle::Tcp(t) => t.name(),
            TransportHandle::Tor(t) => t.name(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.name(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.name(),
        }
    }

    /// Get the transport type metadata.
    pub fn transport_type(&self) -> &TransportType {
        match self {
            TransportHandle::Udp(t) => t.transport_type(),
            TransportHandle::NostrRelay(t) => t.transport_type(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.transport_type(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.transport_type(),
            TransportHandle::Tcp(t) => t.transport_type(),
            TransportHandle::Tor(t) => t.transport_type(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.transport_type(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.transport_type(),
        }
    }

    /// Get current transport state.
    pub fn state(&self) -> TransportState {
        match self {
            TransportHandle::Udp(t) => t.state(),
            TransportHandle::NostrRelay(t) => t.state(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.state(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.state(),
            TransportHandle::Tcp(t) => t.state(),
            TransportHandle::Tor(t) => t.state(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.state(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.state(),
        }
    }

    /// Get the transport MTU.
    pub fn mtu(&self) -> u16 {
        match self {
            TransportHandle::Udp(t) => t.mtu(),
            TransportHandle::NostrRelay(t) => t.mtu(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.mtu(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.mtu(),
            TransportHandle::Tcp(t) => t.mtu(),
            TransportHandle::Tor(t) => t.mtu(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.mtu(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.mtu(),
        }
    }

    /// Get the MTU for a specific link address.
    ///
    /// Falls back to transport-wide MTU if the transport doesn't
    /// support per-link MTU or the address is unknown.
    pub fn link_mtu(&self, addr: &TransportAddr) -> u16 {
        match self {
            TransportHandle::Udp(t) => t.link_mtu(addr),
            TransportHandle::NostrRelay(t) => t.link_mtu(addr),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.link_mtu(addr),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.link_mtu(addr),
            TransportHandle::Tcp(t) => t.link_mtu(addr),
            TransportHandle::Tor(t) => t.link_mtu(addr),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.link_mtu(addr),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.link_mtu(addr),
        }
    }

    /// Get the local bound address (UDP/TCP only, returns None for other transports).
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            TransportHandle::Udp(t) => t.local_addr(),
            TransportHandle::NostrRelay(_) => None,
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(_) => None,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(_) => None,
            TransportHandle::Tcp(t) => t.local_addr(),
            TransportHandle::Tor(_) => None,
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(_) => None,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(_) => None,
        }
    }

    /// Resolve a UDP target only if doing so cannot block on DNS.
    ///
    /// Numeric UDP addresses are returned directly; hostnames are returned
    /// only when the UDP transport already has a fresh cached resolution.
    pub(crate) fn resolved_udp_socket_addr_if_cached(
        &self,
        addr: &TransportAddr,
    ) -> Option<std::net::SocketAddr> {
        match self {
            TransportHandle::Udp(t) => t.resolved_socket_addr_if_cached(addr),
            _ => None,
        }
    }

    /// Get the interface name (Ethernet only, returns None for other transports).
    pub fn interface_name(&self) -> Option<&str> {
        match self {
            TransportHandle::Udp(_) => None,
            TransportHandle::NostrRelay(_) => None,
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(_) => None,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => Some(t.interface_name()),
            TransportHandle::Tcp(_) => None,
            TransportHandle::Tor(_) => None,
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(_) => None,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(_) => None,
        }
    }

    /// Get the onion service address (Tor only, returns None for other transports).
    pub fn onion_address(&self) -> Option<&str> {
        match self {
            TransportHandle::Tor(t) => t.onion_address(),
            _ => None,
        }
    }

    /// Get cached Tor daemon monitoring info (Tor only).
    pub fn tor_monitoring(&self) -> Option<TorMonitoringInfo> {
        match self {
            TransportHandle::Tor(t) => t.cached_monitoring(),
            _ => None,
        }
    }

    /// Get the Tor transport mode (Tor only).
    pub fn tor_mode(&self) -> Option<&str> {
        match self {
            TransportHandle::Tor(t) => Some(t.mode()),
            _ => None,
        }
    }

    /// Drain discovered peers from this transport.
    pub fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        match self {
            TransportHandle::Udp(t) => t.discover(),
            TransportHandle::NostrRelay(t) => t.discover(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.discover(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.discover(),
            TransportHandle::Tcp(t) => t.discover(),
            TransportHandle::Tor(t) => t.discover(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.discover(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.discover(),
        }
    }

    /// Whether this transport auto-connects to discovered peers.
    pub fn auto_connect(&self) -> bool {
        match self {
            TransportHandle::Udp(t) => t.auto_connect(),
            TransportHandle::NostrRelay(t) => t.auto_connect(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.auto_connect(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.auto_connect(),
            TransportHandle::Tcp(t) => t.auto_connect(),
            TransportHandle::Tor(t) => t.auto_connect(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.auto_connect(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.auto_connect(),
        }
    }

    /// Whether this transport accepts inbound connections.
    pub fn accept_connections(&self) -> bool {
        match self {
            TransportHandle::Udp(t) => t.accept_connections(),
            TransportHandle::NostrRelay(t) => t.accept_connections(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.accept_connections(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.accept_connections(),
            TransportHandle::Tcp(t) => t.accept_connections(),
            TransportHandle::Tor(t) => t.accept_connections(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.accept_connections(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.accept_connections(),
        }
    }

    /// Initiate a non-blocking connection to a remote address.
    ///
    /// For connection-oriented transports (TCP, Tor), spawns a background
    /// task to establish the connection. For connectionless transports
    /// (UDP, Ethernet), this is a no-op that returns Ok immediately.
    ///
    /// Poll `connection_state()` to check when the connection is ready.
    pub async fn connect(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        match self {
            TransportHandle::Udp(_) => Ok(()),        // connectionless
            TransportHandle::NostrRelay(_) => Ok(()), // connectionless
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(_) => Ok(()), // connectionless
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(_) => Ok(()), // connectionless
            TransportHandle::Tcp(t) => t.connect_async(addr).await,
            TransportHandle::Tor(t) => t.connect_async(addr).await,
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.connect_async(addr).await,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.connect_async(addr).await,
        }
    }

    /// Query the state of a connection attempt to a remote address.
    ///
    /// For connectionless transports, always returns `ConnectionState::Connected`
    /// (they are always "connected"). For connection-oriented transports, returns
    /// the current state of the background connection attempt.
    pub fn connection_state(&self, addr: &TransportAddr) -> ConnectionState {
        match self {
            TransportHandle::Udp(_) => ConnectionState::Connected,
            TransportHandle::NostrRelay(_) => ConnectionState::Connected,
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(_) => ConnectionState::Connected,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(_) => ConnectionState::Connected,
            TransportHandle::Tcp(t) => t.connection_state_sync(addr),
            TransportHandle::Tor(t) => t.connection_state_sync(addr),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.connection_state_sync(addr),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.connection_state_sync(addr),
        }
    }

    /// Close a specific connection on this transport.
    ///
    /// No-op for connectionless transports. For TCP/Tor, removes the
    /// connection from the pool and drops the stream.
    pub async fn close_connection(&self, addr: &TransportAddr) {
        match self {
            TransportHandle::Udp(t) => t.close_connection(addr),
            TransportHandle::NostrRelay(t) => t.close_connection(addr),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => t.close_connection(addr),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.close_connection(addr),
            TransportHandle::Tcp(t) => t.close_connection_async(addr).await,
            TransportHandle::Tor(t) => t.close_connection_async(addr).await,
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => t.close_connection_async(addr).await,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.close_connection_async(addr).await,
        }
    }

    /// Schedule cleanup for a connection removed by a synchronous node path.
    pub fn close_connection_detached(&self, _addr: &TransportAddr) {
        #[cfg(feature = "webrtc-transport")]
        if let TransportHandle::WebRtc(transport) = self {
            transport.close_connection_detached(_addr);
        }
    }

    /// Check if transport is operational.
    pub fn is_operational(&self) -> bool {
        self.state().is_operational()
    }

    /// Query transport-local congestion indicators.
    ///
    /// Returns a snapshot of congestion signals that the transport can
    /// observe locally (e.g., kernel receive buffer drops). Fields are
    /// `None` when the transport doesn't support that signal.
    pub fn congestion(&self) -> TransportCongestion {
        match self {
            TransportHandle::Udp(t) => t.congestion(),
            TransportHandle::NostrRelay(_) => TransportCongestion::default(),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(_) => TransportCongestion::default(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(_) => TransportCongestion::default(),
            TransportHandle::Tcp(_) => TransportCongestion::default(),
            TransportHandle::Tor(_) => TransportCongestion::default(),
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(_) => TransportCongestion::default(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(_) => TransportCongestion::default(),
        }
    }

    /// Get transport-specific stats as a JSON value.
    ///
    /// Returns a snapshot of counters for the specific transport type.
    pub fn transport_stats(&self) -> serde_json::Value {
        match self {
            TransportHandle::Udp(t) => {
                serde_json::to_value(t.stats().snapshot()).unwrap_or_default()
            }
            TransportHandle::NostrRelay(t) => serde_json::json!({
                "mtu": t.mtu(),
                "state": t.state().to_string(),
            }),
            #[cfg(feature = "sim-transport")]
            TransportHandle::Sim(t) => serde_json::to_value(t.stats()).unwrap_or_default(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => {
                let snap = t.stats().snapshot();
                serde_json::json!({
                    "frames_sent": snap.frames_sent,
                    "frames_recv": snap.frames_recv,
                    "bytes_sent": snap.bytes_sent,
                    "bytes_recv": snap.bytes_recv,
                    "send_errors": snap.send_errors,
                    "recv_errors": snap.recv_errors,
                    "beacons_sent": snap.beacons_sent,
                    "beacons_recv": snap.beacons_recv,
                    "frames_too_short": snap.frames_too_short,
                    "frames_too_long": snap.frames_too_long,
                })
            }
            TransportHandle::Tcp(t) => {
                serde_json::to_value(t.stats().snapshot()).unwrap_or_default()
            }
            TransportHandle::Tor(t) => {
                serde_json::to_value(t.stats().snapshot()).unwrap_or_default()
            }
            #[cfg(feature = "webrtc-transport")]
            TransportHandle::WebRtc(t) => serde_json::json!({
                "mtu": t.mtu(),
                "state": t.state().to_string(),
            }),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => {
                serde_json::to_value(t.stats().snapshot()).unwrap_or_default()
            }
        }
    }
}
