//! Lifecycle for per-peer connected UDP sockets.
//!
//! Tick-driven and idempotent for established UDP peers. It is default-on for
//! Linux and opt-in on macOS:
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
//! to it (most-specific 5-tuple match wins under `SO_REUSEPORT`).
//! The drain still feeds `packet_tx`; rx_loop remains the canonical owner for
//! session lookup, pending-session promotion, decrypt-worker dispatch, and
//! path/liveness bookkeeping.
//!
//! macOS originally defaulted to the wildcard UDP socket because early
//! Darwin tests found liveness regressions under load. Later performance work
//! made the connected path available, but mobile/hotspot testing showed the
//! `SO_REUSEPORT` listener group can still destabilize the wildcard receive
//! path when the application has not opted into the connected socket path. Keep macOS
//! opt-in so listener setup, socket activation, and app config agree. Peers
//! with a configured static UDP endpoint stay on wildcard UDP because NAT/VM
//! paths can drift between the configured endpoint and observed source tuples,
//! and liveness recovery must accept either path. Operators can configure it
//! through `node.connected_udp.*`; `FIPS_CONNECTED_UDP_FD_RESERVE`,
//! `FIPS_CONNECTED_UDP_MAX_PEERS`, and the connected-UDP buffer env vars remain
//! sizing overrides for controlled load tests. `node.connected_udp.max_peers`
//! caps the one-drain-thread-per-peer socket path for large meshes without
//! disabling wildcard UDP delivery. Peer-cap and fd-budget skips are reported
//! as perf events so a large mesh can show why some peers stayed on wildcard
//! UDP without looking like activation failures.

use crate::NodeAddr;
use crate::node::Node;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::node::{ConnectedUdpClearResult, ConnectedUdpInstallResult};
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
            // No-op on platforms without the connected-UDP socket path.
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if !connected_udp_enabled(self.config.node.connected_udp.enabled) {
                return;
            }

            // Collect candidate NodeAddrs first so we can iterate
            // without holding the &mut on self.peers across awaits.
            let plan = self
                .peers
                .connected_udp_activation_plan(&self.configured_peer_cache);
            let candidates = plan.candidates;
            let peer_cap = connected_udp_peer_cap(self.config.node.connected_udp.max_peers);
            let fd_reserve = connected_udp_fd_reserve(self.config.node.connected_udp.fd_reserve);
            let fd_soft_limit = connected_udp_fd_soft_limit();
            let mut installed_count = plan.installed_count;
            let mut peer_cap_skipped = 0usize;
            let mut fd_budget_skipped = 0usize;
            let total_candidates = candidates.len();
            for (idx, addr) in candidates.into_iter().enumerate() {
                let candidates_waiting = total_candidates.saturating_sub(idx);
                if !connected_udp_peer_budget_allows(installed_count, peer_cap) {
                    peer_cap_skipped =
                        peer_cap_skipped.saturating_add(connected_udp_peer_cap_skipped_candidates(
                            installed_count,
                            peer_cap,
                            candidates_waiting,
                        ));
                    break;
                }
                if !connected_udp_fd_budget_allows(installed_count, fd_soft_limit, fd_reserve) {
                    fd_budget_skipped = fd_budget_skipped.saturating_add(
                        connected_udp_fd_budget_skipped_candidates(
                            installed_count,
                            fd_soft_limit,
                            fd_reserve,
                            candidates_waiting,
                        ),
                    );
                    break;
                }
                match self
                    .activate_connected_udp_for_peer(&addr, installed_count)
                    .await
                {
                    Ok(true) => {
                        installed_count = installed_count.saturating_add(1);
                    }
                    Ok(false) => {}
                    Err(e) => {
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
            if peer_cap_skipped > 0 {
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::ConnectedUdpPeerCapSkipped,
                    peer_cap_skipped as u64,
                );
                debug!(
                    skipped = peer_cap_skipped,
                    installed = installed_count,
                    max_peers = peer_cap,
                    "connected UDP peer cap reached; remaining peers stay on wildcard UDP"
                );
            }
            if fd_budget_skipped > 0 {
                crate::perf_profile::record_event_count(
                    crate::perf_profile::Event::ConnectedUdpFdBudgetSkipped,
                    fd_budget_skipped as u64,
                );
                debug!(
                    skipped = fd_budget_skipped,
                    installed = installed_count,
                    soft_limit = ?fd_soft_limit,
                    fd_reserve,
                    fds_per_peer = CONNECTED_UDP_FDS_PER_PEER,
                    "connected UDP fd budget reached; remaining peers stay on wildcard UDP"
                );
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
        installed_count: usize,
    ) -> Result<bool, String> {
        // Read-only pass: figure out which transport + remote addr we need.
        let (transport_id, peer_transport_addr) = {
            let Some(peer) = self.peers.get(node_addr) else {
                return Ok(false);
            };
            if !crate::node::PeerLifecycleRegistry::connected_udp_activation_candidate(peer) {
                return Ok(false);
            }
            let Some(tid) = peer.transport_id() else {
                return Ok(false);
            };
            let Some(addr) = peer.current_addr().cloned() else {
                return Ok(false);
            };
            if let Some(configured_addr) = self
                .configured_static_udp_path_for_peer(node_addr, tid)
                .as_ref()
            {
                let current_matches_configured = &addr == configured_addr;
                debug!(
                    peer = %self.peer_display_name(node_addr),
                    current_addr = %addr,
                    configured_addr = %configured_addr,
                    current_matches_configured,
                    "connected UDP skipped for peer with configured static UDP endpoint"
                );
                return Ok(false);
            }
            (tid, addr)
        };

        // Resolve the peer's TransportAddr → kernel SocketAddr via
        // the UDP transport's DNS cache. This may await on a DNS
        // lookup the very first time we see a hostname; subsequent
        // calls hit the cache.
        let (peer_socket_addr, local_addr, recv_buf, send_buf, packet_tx) = {
            let Some(transport) = self.transports.get(&transport_id) else {
                return Ok(false);
            };
            let udp = match transport {
                TransportHandle::Udp(u) => u,
                _ => return Ok(false), // not a UDP transport — feature N/A
            };
            let peer_cap = connected_udp_peer_cap(self.config.node.connected_udp.max_peers);
            if !connected_udp_peer_budget_allows(installed_count, peer_cap) {
                return Err(format!(
                    "peer cap exhausted: connected_udp_peers={}, max_peers={}",
                    installed_count, peer_cap
                ));
            }
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
            let recv_buf = connected_udp_recv_buf(udp.recv_buf_size());
            let send_buf = connected_udp_send_buf(udp.send_buf_size());
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

        // Install on the peer through the lifecycle owner, which re-checks
        // eligibility so stale activation races cannot replace a valid pair.
        let peer = self.peer_display_name(node_addr);
        let requested_recv_buf = socket.requested_recv_buf();
        let actual_recv_buf = socket.actual_recv_buf();
        let requested_send_buf = socket.requested_send_buf();
        let actual_send_buf = socket.actual_send_buf();
        match self
            .peers
            .install_connected_udp_if_eligible(node_addr, socket, drain)
        {
            ConnectedUdpInstallResult::Installed => {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::ConnectedUdpInstalled,
                );
                info!(
                    peer = %peer,
                    peer_addr = %peer_socket_addr,
                    requested_recv_buf,
                    actual_recv_buf,
                    requested_send_buf,
                    actual_send_buf,
                    "connected UDP socket installed"
                );
                Ok(true)
            }
            ConnectedUdpInstallResult::MissingPeer | ConnectedUdpInstallResult::NotEligible => {
                Ok(false)
            }
        }
    }

    /// Clear the per-peer connected UDP socket + drain for a peer.
    /// Called on peer disconnect / removal. The drain thread exits
    /// via self-pipe; the kernel fd closes when the last `Arc`
    /// drops.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(in crate::node) fn clear_connected_udp_for_peer(&mut self, node_addr: &NodeAddr) {
        if self.peers.clear_connected_udp_for_peer(node_addr) == ConnectedUdpClearResult::Cleared {
            debug!(peer = %self.peer_display_name(node_addr), "connected UDP socket cleared");
        }
    }

    /// No-op shim for non-Linux builds so the rx_loop tick site can
    /// call us unconditionally.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(in crate::node) fn clear_connected_udp_for_peer(&mut self, _node_addr: &NodeAddr) {}
}

#[cfg(target_os = "linux")]
fn connected_udp_enabled(config_enabled: bool) -> bool {
    config_enabled
}

#[cfg(target_os = "macos")]
fn connected_udp_enabled(config_enabled: bool) -> bool {
    crate::transport::udp::socket::macos_connected_udp_enabled(config_enabled)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn connected_udp_fd_reserve(config_reserve: usize) -> usize {
    std::env::var("FIPS_CONNECTED_UDP_FD_RESERVE")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(config_reserve)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn connected_udp_peer_cap(config_max_peers: usize) -> usize {
    std::env::var("FIPS_CONNECTED_UDP_MAX_PEERS")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(config_max_peers)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn connected_udp_recv_buf(config_recv_buf: usize) -> usize {
    connected_udp_buf_override("FIPS_CONNECTED_UDP_RECV_BUF_BYTES").unwrap_or(config_recv_buf)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn connected_udp_send_buf(config_send_buf: usize) -> usize {
    connected_udp_buf_override("FIPS_CONNECTED_UDP_SEND_BUF_BYTES").unwrap_or(config_send_buf)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn connected_udp_buf_override(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|value| parse_connected_udp_buf_override(&value))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn parse_connected_udp_buf_override(raw: &str) -> Option<usize> {
    raw.trim()
        .parse::<usize>()
        .ok()
        .map(|value| value.clamp(64 * 1024, 512 * 1024 * 1024))
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn connected_udp_peer_budget_allows(installed_peers: usize, max_peers: usize) -> bool {
    max_peers == 0 || installed_peers < max_peers
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn connected_udp_peer_cap_skipped_candidates(
    installed_peers: usize,
    max_peers: usize,
    candidates_waiting: usize,
) -> usize {
    if connected_udp_peer_budget_allows(installed_peers, max_peers) {
        0
    } else {
        candidates_waiting
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn connected_udp_fd_budget_skipped_candidates(
    installed_peers: usize,
    soft_limit: Option<usize>,
    reserve: usize,
    candidates_waiting: usize,
) -> usize {
    if connected_udp_fd_budget_allows(installed_peers, soft_limit, reserve) {
        0
    } else {
        candidates_waiting
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;

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
    fn peer_budget_zero_is_unlimited() {
        assert!(connected_udp_peer_budget_allows(10_000, 0));
    }

    #[test]
    fn peer_budget_stops_at_explicit_cap() {
        assert!(connected_udp_peer_budget_allows(0, 1));
        assert!(!connected_udp_peer_budget_allows(1, 1));
    }

    #[test]
    fn peer_cap_skip_count_is_zero_while_budget_remains() {
        assert_eq!(connected_udp_peer_cap_skipped_candidates(0, 2, 50), 0);
        assert_eq!(
            connected_udp_peer_cap_skipped_candidates(10_000, 0, 50),
            0,
            "max_peers=0 keeps the explicit peer cap disabled"
        );
    }

    #[test]
    fn peer_cap_skip_count_covers_current_and_remaining_candidates() {
        assert_eq!(
            connected_udp_peer_cap_skipped_candidates(2, 2, 37),
            37,
            "large-mesh cap exhaustion should report the whole skipped tail once"
        );
    }

    #[test]
    fn fd_budget_skip_count_is_zero_while_budget_remains() {
        assert_eq!(
            connected_udp_fd_budget_skipped_candidates(0, Some(131), 128, 50),
            0
        );
        assert_eq!(
            connected_udp_fd_budget_skipped_candidates(10_000, None, 128, 50),
            0,
            "unknown or unlimited fd limits rely on actual socket-open errors"
        );
    }

    #[test]
    fn fd_budget_skip_count_covers_current_and_remaining_candidates() {
        assert_eq!(
            connected_udp_fd_budget_skipped_candidates(1, Some(131), 128, 37),
            37,
            "fd-budget exhaustion should report the whole skipped tail once"
        );
        assert_eq!(
            connected_udp_fd_budget_skipped_candidates(0, Some(64), 128, 11),
            11,
            "reserve above the soft limit leaves no connected-UDP fd budget"
        );
    }

    #[test]
    fn connected_udp_buffer_override_parser_is_bounded() {
        assert_eq!(parse_connected_udp_buf_override(""), None);
        assert_eq!(parse_connected_udp_buf_override("not-a-number"), None);
        assert_eq!(parse_connected_udp_buf_override("1"), Some(64 * 1024));
        assert_eq!(
            parse_connected_udp_buf_override("67108864"),
            Some(64 * 1024 * 1024)
        );
        assert_eq!(
            parse_connected_udp_buf_override("9999999999"),
            Some(512 * 1024 * 1024)
        );
    }
}
