use super::{Node, NodeError};
use crate::NodeAddr;
use std::net::{IpAddr, SocketAddr};

const MAX_LOCAL_UDP_LISTENERS: usize = 16;

impl Node {
    pub(in crate::node) fn bound_udp_listener_snapshot(&self) -> Vec<SocketAddr> {
        let mut addrs = self
            .transports
            .iter()
            .filter(|(id, transport)| {
                !self.is_local_rendezvous_transport(id)
                    && transport.is_operational()
                    && transport.transport_type().name == "udp"
                    && transport.accept_connections()
            })
            .filter_map(|(_, transport)| transport.local_addr())
            .collect::<Vec<_>>();
        addrs.sort_unstable();
        addrs.dedup();
        addrs
    }

    fn authenticated_loopback_ip(&self, addr: &NodeAddr) -> Option<IpAddr> {
        let peer = self.peers.get(addr)?;
        if !peer.can_send() || !peer.has_session() {
            return None;
        }
        let remote = peer.current_addr()?.as_str()?.parse::<SocketAddr>().ok()?;
        remote.ip().is_loopback().then_some(remote.ip())
    }

    #[cfg(test)]
    pub(in crate::node) fn authenticated_local_udp_listeners(
        &self,
        addr: &NodeAddr,
    ) -> Vec<SocketAddr> {
        self.local_udp_listener_snapshot(addr).0
    }

    pub(in crate::node) fn local_udp_listener_snapshot(
        &self,
        addr: &NodeAddr,
    ) -> (Vec<SocketAddr>, bool) {
        if self.authenticated_loopback_ip(addr).is_none() {
            return self.rostered_local_udp_listeners(addr);
        }
        let peer = self.peers.get(addr).unwrap();
        (
            peer.local_udp_listeners.clone(),
            !peer.local_udp_listeners_received,
        )
    }

    pub(in crate::node) async fn send_local_udp_listeners(
        &mut self,
        addr: &NodeAddr,
    ) -> Result<(), NodeError> {
        if !self.config.node.discovery.local.enabled {
            return Ok(());
        }
        let Some(ip) = self.authenticated_loopback_ip(addr) else {
            return Ok(());
        };
        let Some(peer) = self.peers.get(addr) else {
            return Ok(());
        };
        if !peer.client_only_supported {
            return self.send_client_support(addr, false).await;
        }
        let namespaced = peer.namespaced_link_extensions;
        let mut ports = self
            .bound_udp_listener_snapshot()
            .into_iter()
            .filter(|socket| {
                socket.ip().is_ipv4() == ip.is_ipv4()
                    && (socket.ip().is_unspecified() || socket.ip() == ip)
            })
            .map(|socket| socket.port())
            .collect::<Vec<_>>();
        ports.sort_unstable();
        ports.dedup();
        ports.truncate(MAX_LOCAL_UDP_LISTENERS);
        let mut body = vec![ports.len() as u8];
        for port in ports {
            body.extend_from_slice(&port.to_le_bytes());
        }
        let message = if namespaced {
            crate::protocol::LinkExtension::LocalUdpListeners(&body).encode()
        } else {
            let mut message = vec![crate::protocol::LinkMessageType::LocalUdpListeners.to_byte()];
            message.extend_from_slice(&body);
            message
        };
        self.send_dataplane_fmp_link_plaintext(addr, &message, false)
            .await
    }

    pub(in crate::node) fn handle_local_udp_listeners(&mut self, addr: &NodeAddr, body: &[u8]) {
        let Some(ip) = self.authenticated_loopback_ip(addr) else {
            return;
        };
        let Some(&count) = body.first() else {
            return;
        };
        if usize::from(count) > MAX_LOCAL_UDP_LISTENERS || body.len() != 1 + 2 * usize::from(count)
        {
            return;
        }
        let mut addrs = Vec::with_capacity(usize::from(count));
        for bytes in body[1..].chunks_exact(2) {
            let port = u16::from_le_bytes([bytes[0], bytes[1]]);
            if port == 0 {
                return;
            }
            addrs.push(SocketAddr::new(ip, port));
        }
        addrs.sort_unstable();
        addrs.dedup();
        let peer = self.peers.get_mut(addr).unwrap();
        let changed = !peer.local_udp_listeners_received || peer.local_udp_listeners != addrs;
        peer.local_udp_listeners = addrs;
        peer.local_udp_listeners_received = true;
        if changed {
            self.local_udp_listener_state_changed();
        }
    }
}
