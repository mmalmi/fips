//! Lifecycle for per-peer connected UDP sockets.
//!
//! Tick-driven, idempotent, **on by default** for established UDP peers on
//! Linux and macOS:
//!
//! - **Tick-driven:** every node tick, scan healthy established UDP peers
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
//! Once the peer's session is established, Linux/macOS install the connected
//! socket; from that moment on the kernel routes that peer's traffic
//! to it (most-specific 5-tuple match wins under `SO_REUSEPORT`), and
//! the drain thread feeds the existing `packet_tx` just like the
//! wildcard listen socket does. The rx_loop dispatch sees no
//! difference.
//!
//! macOS originally defaulted to the wildcard UDP socket because early
//! Darwin tests found liveness regressions under load. Later testing
//! showed the problem was mismatched listener/peer `SO_REUSE*` state:
//! with the live listener and connected sibling in the same reuse group,
//! the connected `send(2)` path improves the MacBook Wi-Fi sender case
//! and is now the default. Operators can configure it through
//! `node.connected_udp.*`; `FIPS_CONNECTED_UDP` and
//! `FIPS_CONNECTED_UDP_FD_RESERVE` remain environment overrides for A/B
//! tests. The old macOS-specific `FIPS_MACOS_CONNECTED_UDP=0` is ignored
//! so stale launchd plists do not disable the now-default fast path.

use crate::NodeAddr;
use crate::node::Node;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::transport::TransportHandle;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tracing::{debug, info, warn};

#[cfg(any(target_os = "linux", target_os = "macos"))]
const CONNECTED_UDP_FDS_PER_PEER: usize = 3;

impl Node {
    /// Tick-driven activation of per-peer connected UDP sockets.
    /// Scans healthy established UDP peers that don't yet have a connected
    /// socket and opens one. No-op when there are no eligible peers
    /// (e.g. only non-UDP transports). Enabled on Linux and macOS:
    /// both kernels route a matching peer 5-tuple to the connected
    /// socket when it shares the wildcard listen port via SO_REUSEPORT.
    pub(in crate::node) async fn activate_connected_udp_sessions(&mut self) {
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            // No-op on platforms without the connected-UDP fast path.
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if !connected_udp_enabled(self.config.node.connected_udp.enabled) {
                return;
            }

            // Collect candidate NodeAddrs first so we can iterate
            // without holding the &mut on self.peers across awaits.
            let mut candidates: Vec<NodeAddr> = self
                .peers
                .iter()
                .filter_map(|(addr, peer)| {
                    connected_udp_activation_candidate(peer).then_some(*addr)
                })
                .collect();
            candidates.sort_by_key(|addr| self.configured_peer(addr).is_none());
            for addr in candidates {
                if let Err(e) = self.activate_connected_udp_for_peer(&addr).await {
                    static FAILURES: AtomicU64 = AtomicU64::new(0);
                    crate::perf_profile::record_event(
                        crate::perf_profile::Event::ConnectedUdpActivationFailed,
                    );
                    let n = FAILURES.fetch_add(1, Relaxed);
                    if n < 8 || n.is_multiple_of(1000) {
                        warn!(peer = %addr, error = %e, failures = n + 1, "connected UDP activation deferred");
                    } else {
                        debug!(peer = %addr, error = %e, "connected UDP activation deferred");
                    }
                }
            }
        }
    }

    /// Open the connected UDP socket + spawn its drain thread for
    /// one peer. Idempotent — re-checks the eligibility conditions
    /// inside the &mut so a race with peer drop doesn't install on a
    /// freshly-removed peer. Returns `Ok(())` on success or if the
    /// peer is no longer eligible (treated as benign).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn activate_connected_udp_for_peer(
        &mut self,
        node_addr: &NodeAddr,
    ) -> Result<(), String> {
        // Read-only pass: figure out which transport + remote addr we need.
        let (transport_id, peer_transport_addr) = {
            let Some(peer) = self.peers.get(node_addr) else {
                return Ok(());
            };
            if !connected_udp_activation_candidate(peer) {
                return Ok(());
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
            let installed_count = self.connected_udp_installed_count();
            let fd_reserve = connected_udp_fd_reserve(self.config.node.connected_udp.fd_reserve);
            let fd_soft_limit = connected_udp_fd_soft_limit();
            if !connected_udp_fd_budget_allows(installed_count, fd_soft_limit, fd_reserve) {
                return Err(match fd_soft_limit {
                    Some(limit) => format!(
                        "fd budget exhausted: connected_udp_peers={}, soft_limit={}, reserve={}, fds_per_peer={}",
                        installed_count, limit, fd_reserve, CONNECTED_UDP_FDS_PER_PEER
                    ),
                    None => format!(
                        "fd budget exhausted: connected_udp_peers={}, reserve={}, fds_per_peer={}",
                        installed_count, fd_reserve, CONNECTED_UDP_FDS_PER_PEER
                    ),
                });
            }
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
            if !connected_udp_activation_candidate(peer) {
                // Lost the race — somebody else activated us first.
                // Drop the new socket + drain so we don't leak.
                drop(drain);
                drop(socket);
                return Ok(());
            }
            peer.set_connected_udp(socket, drain);
            crate::perf_profile::record_event(crate::perf_profile::Event::ConnectedUdpInstalled);
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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn connected_udp_installed_count(&self) -> usize {
        self.peers
            .values()
            .filter(|peer| peer.connected_udp().is_some())
            .count()
    }

    /// Clear the per-peer connected UDP socket + drain for a peer.
    /// Called on peer disconnect / removal. The drain thread exits
    /// via self-pipe; the kernel fd closes when the last `Arc`
    /// drops.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
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
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(in crate::node) fn clear_connected_udp_for_peer(&mut self, _node_addr: &NodeAddr) {}
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn connected_udp_activation_candidate(peer: &crate::peer::ActivePeer) -> bool {
    peer.is_healthy()
        && peer.noise_session().is_some()
        && peer.transport_id().is_some()
        && peer.current_addr().is_some()
        && peer.connected_udp().is_none()
}

#[cfg(target_os = "linux")]
fn connected_udp_enabled(config_enabled: bool) -> bool {
    env_flag("FIPS_CONNECTED_UDP").unwrap_or(config_enabled)
}

#[cfg(target_os = "macos")]
fn connected_udp_enabled(config_enabled: bool) -> bool {
    env_flag("FIPS_CONNECTED_UDP")
        .or_else(|| env_flag("FIPS_MACOS_CONNECTED_UDP").filter(|enabled| *enabled))
        .unwrap_or(config_enabled)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn env_flag(name: &str) -> Option<bool> {
    let value = std::env::var(name).ok()?;
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn connected_udp_fd_reserve(config_reserve: usize) -> usize {
    std::env::var("FIPS_CONNECTED_UDP_FD_RESERVE")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(config_reserve)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn connected_udp_fd_soft_limit() -> Option<usize> {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    let limit = unsafe { limit.assume_init() };
    if limit.rlim_cur == libc::RLIM_INFINITY {
        None
    } else {
        Some((limit.rlim_cur as u128).min(usize::MAX as u128) as usize)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn connected_udp_fd_budget_allows(
    installed_peers: usize,
    soft_limit: Option<usize>,
    reserve: usize,
) -> bool {
    let Some(soft_limit) = soft_limit else {
        return true;
    };
    let available = soft_limit.saturating_sub(reserve);
    installed_peers
        .saturating_add(1)
        .saturating_mul(CONNECTED_UDP_FDS_PER_PEER)
        <= available
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use crate::noise::HandshakeState;
    use crate::peer::ActivePeer;
    use crate::transport::{LinkId, LinkStats, TransportAddr, TransportId};
    use crate::utils::index::SessionIndex;
    use crate::{Identity, PeerIdentity};

    fn make_noise_session(local: &Identity, peer: &Identity) -> crate::noise::NoiseSession {
        let mut initiator = HandshakeState::new_initiator(local.keypair(), peer.pubkey_full());
        let mut responder = HandshakeState::new_responder(peer.keypair());
        initiator.set_local_epoch([1; 8]);
        responder.set_local_epoch([2; 8]);
        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();
        let msg2 = responder.write_message_2().unwrap();
        initiator.read_message_2(&msg2).unwrap();
        initiator.into_session().unwrap()
    }

    fn make_established_udp_peer() -> ActivePeer {
        let local = Identity::generate();
        let peer = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        ActivePeer::with_session(
            peer_identity,
            LinkId::new(7),
            1_000,
            make_noise_session(&local, &peer),
            SessionIndex::new(11),
            SessionIndex::new(12),
            TransportId::new(1),
            TransportAddr::from_string("127.0.0.1:2121"),
            LinkStats::new(),
            true,
            &crate::mmp::MmpConfig::default(),
            Some([2; 8]),
        )
    }

    #[test]
    fn fd_budget_reserves_headroom_for_other_sockets() {
        assert!(connected_udp_fd_budget_allows(0, Some(131), 128));
        assert!(!connected_udp_fd_budget_allows(1, Some(131), 128));
    }

    #[test]
    fn fd_budget_treats_unlimited_or_unknown_limit_as_allowed() {
        assert!(connected_udp_fd_budget_allows(10_000, None, 128));
    }

    #[test]
    fn fd_budget_saturates_when_reserve_exceeds_limit() {
        assert!(!connected_udp_fd_budget_allows(0, Some(64), 128));
    }

    #[test]
    fn stale_peer_is_not_connected_udp_activation_candidate() {
        let mut peer = make_established_udp_peer();
        assert!(
            connected_udp_activation_candidate(&peer),
            "healthy established UDP peer should get the connected-UDP fast path"
        );

        peer.mark_stale();

        assert!(
            !connected_udp_activation_candidate(&peer),
            "link-dead paths stay probeable but must not regain a trusted connected-UDP payload socket"
        );
    }
}
