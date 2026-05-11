//! Lifecycle for per-peer connected UDP sockets.
//!
//! Tick-driven, idempotent, **always on** for established UDP peers:
//!
//! - **Tick-driven:** every node tick, scan established UDP peers
//!   that don't yet have a connected socket installed and try to
//!   open one. No need to thread an activation call through every
//!   handshake-completion code path.
//! - **Idempotent:** if `peer.connected_udp()` is already `Some`,
//!   skip. Replaces stale sockets lazily by clearing them on
//!   address change / rekey from elsewhere (see
//!   `deregister_session_index` and the rekey handler).
//!
//! Implementation note: only the **listen socket → wildcard** demux
//! path delivers the very first packets of a session (handshakes).
//! Once the peer's session is established, we install the connected
//! socket; from that moment on the kernel routes that peer's traffic
//! to it (most-specific 5-tuple match wins under SO_REUSEPORT), and
//! the drain thread feeds the existing `packet_tx` just like the
//! wildcard listen socket does. The rx_loop dispatch sees no
//! difference.

#[cfg(target_os = "linux")]
use crate::transport::TransportHandle;
use crate::node::Node;
use crate::NodeAddr;
#[cfg(target_os = "linux")]
use tracing::{debug, info};

impl Node {
    /// Tick-driven activation of per-peer connected UDP sockets.
    /// Scans established UDP peers that don't yet have a connected
    /// socket and opens one. No-op when there are no eligible peers
    /// (e.g. only non-UDP transports). Linux-only — no-op on macOS
    /// and Windows where the SO_REUSEPORT + connected-socket demux
    /// behaviour we rely on isn't available equivalently.
    pub(in crate::node) async fn activate_connected_udp_sessions(&mut self) {
        #[cfg(not(target_os = "linux"))]
        {
            return;
        }
        #[cfg(target_os = "linux")]
        {
            // Collect candidate NodeAddrs first so we can iterate
            // without holding the &mut on self.peers across awaits.
            let candidates: Vec<NodeAddr> = self
                .peers
                .iter()
                .filter_map(|(addr, peer)| {
                    let has_session = peer.noise_session().is_some();
                    let has_transport = peer.transport_id().is_some();
                    let has_addr = peer.current_addr().is_some();
                    let already_active = peer.connected_udp().is_some();
                    if has_session && has_transport && has_addr && !already_active {
                        Some(*addr)
                    } else {
                        None
                    }
                })
                .collect();
            for addr in candidates {
                if let Err(e) = self.activate_connected_udp_for_peer(&addr).await {
                    debug!(peer = %addr, error = %e, "connected UDP activation deferred");
                }
            }
        }
    }

    /// Open the connected UDP socket + spawn its drain thread for
    /// one peer. Idempotent — re-checks the eligibility conditions
    /// inside the &mut so a race with peer drop doesn't install on a
    /// freshly-removed peer. Returns `Ok(())` on success or if the
    /// peer is no longer eligible (treated as benign).
    #[cfg(target_os = "linux")]
    async fn activate_connected_udp_for_peer(
        &mut self,
        node_addr: &NodeAddr,
    ) -> Result<(), String> {
        // Read-only pass: figure out which transport + remote addr we need.
        let (transport_id, peer_transport_addr) = {
            let Some(peer) = self.peers.get(node_addr) else {
                return Ok(());
            };
            if peer.connected_udp().is_some() {
                return Ok(()); // already activated
            }
            let Some(tid) = peer.transport_id() else {
                return Ok(());
            };
            let Some(addr) = peer.current_addr().cloned() else {
                return Ok(());
            };
            (tid, addr)
        };

        // Resolve the peer's TransportAddr → kernel SocketAddr via
        // the UDP transport's DNS cache. This may await on a DNS
        // lookup the very first time we see a hostname; subsequent
        // calls hit the cache.
        let (peer_socket_addr, local_addr, recv_buf, send_buf, packet_tx) = {
            let Some(transport) = self.transports.get(&transport_id) else {
                return Ok(());
            };
            let udp = match transport {
                TransportHandle::Udp(u) => u,
                _ => return Ok(()), // not a UDP transport — feature N/A
            };
            let peer_sa = udp
                .resolve_for_off_task(&peer_transport_addr)
                .await
                .map_err(|e| format!("address resolve: {e}"))?;
            let local = udp
                .local_addr()
                .ok_or_else(|| "udp transport not started".to_string())?;
            let recv_buf = udp.recv_buf_size();
            let send_buf = udp.send_buf_size();
            let tx = udp.clone_packet_tx();
            (peer_sa, local, recv_buf, send_buf, tx)
        };

        // Open the connected socket on the kernel side.
        let socket = std::sync::Arc::new(
            crate::transport::udp::connected_peer::ConnectedPeerSocket::open(
                local_addr,
                peer_socket_addr,
                recv_buf,
                send_buf,
            )
            .map_err(|e| format!("ConnectedPeerSocket::open: {e}"))?,
        );

        // Spawn the drain thread. It feeds `packet_tx` exactly like
        // the wildcard listen socket — rx_loop dispatches identically.
        let drain = crate::transport::udp::peer_drain::PeerRecvDrain::spawn(
            socket.clone(),
            transport_id,
            peer_socket_addr,
            packet_tx,
        )
        .map_err(|e| format!("PeerRecvDrain::spawn: {e}"))?;

        // Install on the peer, idempotent re-check.
        if let Some(peer) = self.peers.get_mut(node_addr) {
            if peer.connected_udp().is_some() {
                // Lost the race — somebody else activated us first.
                // Drop the new socket + drain so we don't leak.
                drop(drain);
                drop(socket);
                return Ok(());
            }
            peer.set_connected_udp(socket, drain);
            info!(
                peer = %self.peer_display_name(node_addr),
                peer_addr = %peer_socket_addr,
                "connected UDP socket installed"
            );
        } else {
            // Peer disappeared between read-only pass and now.
            drop(drain);
            drop(socket);
        }
        Ok(())
    }

    /// Clear the per-peer connected UDP socket + drain for a peer.
    /// Called on peer disconnect / removal. The drain thread exits
    /// via self-pipe; the kernel fd closes when the last `Arc`
    /// drops.
    #[cfg(target_os = "linux")]
    pub(in crate::node) fn clear_connected_udp_for_peer(&mut self, node_addr: &NodeAddr) {
        if let Some(peer) = self.peers.get_mut(node_addr)
            && peer.connected_udp().is_some()
        {
            peer.clear_connected_udp();
            debug!(peer = %self.peer_display_name(node_addr), "connected UDP socket cleared");
        }
    }

    /// No-op shim for non-Linux builds so the rx_loop tick site can
    /// call us unconditionally.
    #[cfg(not(target_os = "linux"))]
    pub(in crate::node) fn clear_connected_udp_for_peer(&mut self, _node_addr: &NodeAddr) {}
}
