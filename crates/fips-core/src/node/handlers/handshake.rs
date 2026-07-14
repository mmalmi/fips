//! Handshake handlers and connection promotion.

use crate::PeerIdentity;
use crate::node::acl::PeerAclContext;
use crate::node::wire::{Msg1Header, Msg2Header, build_msg2};
use crate::node::{Node, NodeError};
use crate::peer::{
    ActivePeer, ActivePeerSession, PeerConnection, PromotionResult, cross_connection_winner,
};
use crate::transport::{Link, LinkDirection, LinkId, ReceivedPacket};
use std::time::Duration;
use tracing::{debug, info, warn};

impl Node {
    /// Returns true if an inbound msg1 should be admitted past the
    /// `accept_connections` gate.
    ///
    /// Rekey/restart msg1 from an established peer is always admitted (the
    /// gate is meant to filter fresh handshakes from strangers, not
    /// maintenance traffic on established sessions). Two predicates cover
    /// "established peer at this transport+addr":
    ///
    /// 1. The link registry has an address-index entry for
    ///    `(transport_id, remote_addr)`. This is the fast path and matches
    ///    when the peer registered with the same `TransportAddr` form we
    ///    observe on inbound packets (e.g., both numeric when peer config uses
    ///    a numeric IP).
    ///
    /// 2. An active peer's `current_addr()` matches `(transport_id,
    ///    remote_addr)`. `current_addr` is updated from inbound encrypted-
    ///    frame source addrs (always numeric `SocketAddr`-form), so this
    ///    catches established peers whose address-index key is hostname-form
    ///    (because `initiate_connection` populated it from a hostname-bearing
    ///    peer config) while inbound rekey msg1 arrives in numeric form.
    ///    Without this second predicate, the carve-out misses any deployment
    ///    that combines a hostname-based peer config with
    ///    `udp.accept_connections: false` or `udp.outbound_only: true` (the
    ///    production trigger for the 2026-04-30 bug).
    ///
    /// Otherwise the transport's `accept_connections` config decides;
    /// absence of a registered transport admits (no gate to apply).
    pub(in crate::node) fn should_admit_msg1(
        &self,
        transport_id: crate::transport::TransportId,
        remote_addr: &crate::transport::TransportAddr,
    ) -> bool {
        if self
            .links
            .contains_addr(&(transport_id, remote_addr.clone()))
        {
            return true;
        }
        if self.peers.values().any(|p| {
            p.transport_id() == Some(transport_id) && p.current_addr() == Some(remote_addr)
        }) {
            return true;
        }
        self.transports
            .get(&transport_id)
            .is_none_or(|t| t.accept_connections())
    }

    /// Handle handshake message 1 (phase 0x1).
    ///
    /// This creates a new inbound connection. Rate limiting is applied
    /// before any expensive crypto operations.
    pub(in crate::node) async fn handle_msg1(&mut self, packet: ReceivedPacket) {
        debug!(
            transport_id = %packet.transport_id,
            remote_addr = %packet.remote_addr,
            bytes = packet.data.len(),
            "Received msg1"
        );
        // === RATE LIMITING (before any processing) ===
        if !self.msg1_rate_limiter.start_handshake() {
            debug!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                "Msg1 rate limited"
            );
            return;
        }

        // accept_connections gate. Rekey/restart msg1 on an existing link
        // is always admitted; the gate only filters truly-fresh connections
        // from strangers. Without this carve-out, the dual-init tie-breaker
        // deadlocks when the larger-NodeAddr side has accept_connections=false.
        if !self.should_admit_msg1(packet.transport_id, &packet.remote_addr) {
            self.msg1_rate_limiter.complete_handshake();
            debug!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                "Msg1 rejected by accept-connections gate"
            );
            return;
        }

        // Parse header
        let header = match Msg1Header::parse(packet.data.as_slice()) {
            Some(h) => h,
            None => {
                self.msg1_rate_limiter.complete_handshake();
                debug!("Invalid msg1 header");
                return;
            }
        };

        // Check for existing connection from this address.
        //
        // If we already have an *inbound* link from this address, this could be:
        // 1. A duplicate msg1 (our msg2 was lost) — resend msg2
        // 2. A restarted peer (different epoch) — tear down and reprocess
        //
        // If we have an *outbound* link to this address (we initiated to them
        // AND they initiated to us), this is a cross-connection — allow it.
        //
        // Epoch-based restart detection: if the sender already has an inbound
        // link AND is an active peer in self.peers, fall through to decrypt
        // the msg1 and check the epoch. Otherwise, treat as duplicate.
        let mut possible_restart = false;
        if let Some(existing_link_id) = self
            .links
            .lookup_addr(packet.transport_id, &packet.remote_addr)
            && let Some(link) = self.links.get(&existing_link_id)
        {
            if link.direction() == LinkDirection::Inbound {
                // Check if this link belongs to an already-promoted active peer
                let is_active_peer = self.peers.values().any(|p| p.link_id() == existing_link_id);

                if is_active_peer {
                    // Possible restart — fall through to decrypt and check epoch
                    possible_restart = true;
                } else {
                    // Genuinely pending handshake — resend msg2
                    let msg2_bytes = self.find_stored_msg2(existing_link_id);
                    if let Some(msg2) = msg2_bytes {
                        if let Some(transport) = self.transports.get(&packet.transport_id) {
                            match transport.send(&packet.remote_addr, &msg2).await {
                                Ok(_) => debug!(
                                    remote_addr = %packet.remote_addr,
                                    "Resent msg2 for duplicate msg1"
                                ),
                                Err(e) => debug!(
                                    remote_addr = %packet.remote_addr,
                                    error = %e,
                                    "Failed to resend msg2"
                                ),
                            }
                        }
                    } else {
                        debug!(
                            remote_addr = %packet.remote_addr,
                            "Duplicate msg1 but no stored msg2 to resend"
                        );
                    }
                    self.msg1_rate_limiter.complete_handshake();
                    return;
                }
            } else {
                // Outbound link to this address. If it belongs to an active
                // peer, this may be a rekey msg1 (same epoch) or a
                // restart (different epoch). Set possible_restart to enable
                // the epoch/rekey check below.
                let is_active_peer = self.peers.values().any(|p| p.link_id() == existing_link_id);
                if is_active_peer {
                    possible_restart = true;
                } else {
                    debug!(
                        transport_id = %packet.transport_id,
                        remote_addr = %packet.remote_addr,
                        existing_link_id = %existing_link_id,
                        "Cross-connection detected: have outbound, received inbound msg1"
                    );
                }
            }
        }

        // === CRYPTO COST PAID HERE ===
        let link_id = self.allocate_link_id();
        let mut conn = PeerConnection::inbound_with_transport(
            link_id,
            packet.transport_id,
            packet.remote_addr.clone(),
            packet.timestamp_ms,
        );

        let our_keypair = self.identity.keypair();
        let noise_msg1 = &packet.data.as_slice()[header.noise_msg1_offset..];
        let msg2_response = match conn.receive_handshake_init(
            our_keypair,
            self.startup_epoch,
            noise_msg1,
            packet.timestamp_ms,
        ) {
            Ok(m) => m,
            Err(e) => {
                self.msg1_rate_limiter.complete_handshake();
                debug!(
                    error = %e,
                    "Failed to process msg1"
                );
                return;
            }
        };

        // Learn peer identity from msg1
        let peer_identity = match conn.expected_identity() {
            Some(id) => *id,
            None => {
                self.msg1_rate_limiter.complete_handshake();
                warn!("Identity not learned from msg1");
                return;
            }
        };

        let peer_node_addr = *peer_identity.node_addr();

        // Identity-based restart/rekey detection: if the peer is already
        // active but address-index dispatch didn't match (different source
        // address, e.g., TCP from a different port), we still need to check
        // for restart/rekey.
        if !possible_restart && self.peers.contains_key(&peer_node_addr) {
            possible_restart = true;
        }

        if self.max_peers > 0 && self.peers.len() >= self.max_peers {
            let is_known_active = self.peers.contains_key(&peer_node_addr);
            let is_pending_outbound = self.peers.connection_iter().any(|(_, conn)| {
                conn.expected_identity()
                    .map(|id| *id.node_addr() == peer_node_addr)
                    .unwrap_or(false)
            });
            if !is_known_active && !is_pending_outbound {
                debug!(
                    peer = %self.peer_display_name(&peer_node_addr),
                    max = self.max_peers,
                    "Silent-dropping Msg1 at max_peers cap (early gate; no Msg2 sent)"
                );
                self.msg1_rate_limiter.complete_handshake();
                return;
            }
        }

        // Epoch-based restart detection and duplicate msg1 handling.
        //
        // If we fell through from the address-index check above with
        // possible_restart=true, we now have the decrypted epoch from msg1.
        // Compare it against the stored epoch for this peer.
        if possible_restart && let Some(existing_peer) = self.peers.get(&peer_node_addr) {
            let new_epoch = conn.remote_epoch();
            let existing_epoch = existing_peer.remote_epoch();

            match (existing_epoch, new_epoch) {
                (Some(existing), Some(new)) if existing != new => {
                    // Epoch mismatch — peer restarted. Tear down stale session.
                    info!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        "Peer restart detected (epoch mismatch), removing stale session"
                    );
                    let now_ms = Self::now_ms();
                    self.schedule_reconnect(peer_node_addr, now_ms);
                    self.remove_active_peer(&peer_node_addr);
                    // Fall through to process as new connection
                }
                _ => {
                    // Same epoch (or no epoch stored).
                    //
                    // If liveness has already marked the active path stale,
                    // a same-epoch msg1 is recovery traffic, not a duplicate
                    // initial handshake. Falling through lets promotion
                    // install the freshly authenticated path instead of
                    // resending an old msg2 whose receiver index belongs to
                    // the dead session.
                    if !existing_peer.is_healthy() {
                        debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            "Same-epoch msg1 received from stale peer; processing as direct-path recovery"
                        );
                    } else {
                        // If the peer has an active session and rekey is enabled,
                        // this is a rekey msg1 (not a duplicate initial msg1).
                        // Guard: the session must be at least 30s old to avoid
                        // misidentifying a cross-connection msg1 as a rekey.
                        // During simultaneous connection, both sides promote
                        // within the same tick and the peer's msg1 arrives
                        // immediately — a genuine rekey can't fire that fast.
                        let session_age_secs =
                            existing_peer.session_established_at().elapsed().as_secs();
                        if self.config.node.rekey.enabled
                            && existing_peer.has_session()
                            && existing_peer.is_healthy()
                            && session_age_secs >= 30
                        {
                            // Guard: already have a pending session from a completed
                            // rekey (waiting for K-bit cutover). Don't overwrite it
                            // with a new handshake — drop this msg1.
                            if existing_peer.pending_new_session().is_some() {
                                debug!(
                                    peer = %self.peer_display_name(&peer_node_addr),
                                    "Rekey msg1 received but already have pending session, dropping"
                                );
                                self.peers.remove_connection(&link_id);
                                self.links.remove(&link_id);
                                self.msg1_rate_limiter.complete_handshake();
                                return;
                            }
                            let pending_fmp_k_bit = !existing_peer.current_k_bit();

                            // Dual-initiation detection: both sides sent msg1
                            // simultaneously. Apply tie-breaker — smaller NodeAddr
                            // wins as initiator (same as cross-connection resolution).
                            if existing_peer.rekey_in_progress() {
                                let our_addr = self.identity.node_addr();
                                if our_addr < &peer_node_addr {
                                    // We win as initiator — drop their msg1.
                                    // Our msg2 will arrive at peer, who completes
                                    // as our responder.
                                    debug!(
                                        peer = %self.peer_display_name(&peer_node_addr),
                                        "Dual rekey initiation: we win (smaller addr), dropping their msg1"
                                    );
                                    self.peers.remove_connection(&link_id);
                                    self.links.remove(&link_id);
                                    self.msg1_rate_limiter.complete_handshake();
                                    return;
                                }
                                // We lose — abandon our rekey, become responder below.
                                debug!(
                                    peer = %self.peer_display_name(&peer_node_addr),
                                    "Dual rekey initiation: we lose (larger addr), abandoning ours"
                                );
                                if let Some(peer) = self.peers.get_mut(&peer_node_addr)
                                    && let Some(idx) = peer.abandon_rekey()
                                {
                                    if let Some(tid) = peer.transport_id() {
                                        self.deregister_session_index((tid, idx.as_u32()));
                                        self.pending_outbound.remove(&(tid, idx.as_u32()));
                                    }
                                    let _ = self.index_allocator.free(idx);
                                }
                                // Fall through to respond as responder
                            }

                            // Rekey: process as responder, store new session as pending
                            let noise_session = conn.take_session();
                            let our_new_index = match self.index_allocator.allocate() {
                                Ok(idx) => idx,
                                Err(e) => {
                                    warn!(error = %e, "Failed to allocate index for rekey");
                                    self.msg1_rate_limiter.complete_handshake();
                                    return;
                                }
                            };

                            let noise_session = match noise_session {
                                Some(s) => s,
                                None => {
                                    warn!("Rekey msg1: no session from handshake");
                                    let _ = self.index_allocator.free(our_new_index);
                                    self.msg1_rate_limiter.complete_handshake();
                                    return;
                                }
                            };
                            let pending_fmp_open = noise_session.recv_cipher_clone();

                            // Send msg2 response using the new handshake
                            let wire_msg2 =
                                build_msg2(our_new_index, header.sender_idx, &msg2_response);
                            if let Some(transport) = self.transports.get(&packet.transport_id) {
                                match transport.send(&packet.remote_addr, &wire_msg2).await {
                                    Ok(_) => {
                                        debug!(
                                            peer = %self.peer_display_name(&peer_node_addr),
                                            new_our_index = %our_new_index,
                                            "Sent rekey msg2 response"
                                        );
                                    }
                                    Err(e) => {
                                        warn!(
                                            peer = %self.peer_display_name(&peer_node_addr),
                                            error = %e,
                                            "Failed to send rekey msg2"
                                        );
                                        let _ = self.index_allocator.free(our_new_index);
                                        self.msg1_rate_limiter.complete_handshake();
                                        return;
                                    }
                                }
                            }

                            let Some(registered) =
                                self.peers.install_pending_rekey_session_and_index(
                                    &peer_node_addr,
                                    noise_session,
                                    our_new_index,
                                    header.sender_idx,
                                    false,
                                    None,
                                )
                            else {
                                warn!(
                                    peer = %self.peer_display_name(&peer_node_addr),
                                    "Could not install responder pending rekey session"
                                );
                                let _ = self.index_allocator.free(our_new_index);
                                self.peers.remove_connection(&link_id);
                                self.links.remove(&link_id);
                                self.msg1_rate_limiter.complete_handshake();
                                return;
                            };
                            self.log_registered_peer_session_index_result(
                                &peer_node_addr,
                                &registered,
                                "responder_pending_rekey",
                            );
                            let _ = self.sync_dataplane_fmp_owner(&peer_node_addr);
                            if let Some(open) = pending_fmp_open {
                                let _ = self.install_dataplane_fmp_pending_receive_epoch(
                                    &peer_node_addr,
                                    pending_fmp_k_bit,
                                    open,
                                );
                            }

                            // Clean up any temporary connection/link state from this path.
                            // The active peer's link registry entry must keep recognizing
                            // future msg1s from this address as rekeys, not new connections.
                            self.peers.remove_connection(&link_id);
                            self.links.remove(&link_id);

                            self.msg1_rate_limiter.complete_handshake();
                            return;
                        }

                        // Not a rekey. A stored msg2 is reusable only when the
                        // sender index matches the active handshake. A direct
                        // path refresh has a fresh sender index even when the
                        // node epoch is unchanged; replaying the bootstrap
                        // path's msg2 would address the wrong pending handshake
                        // and permanently stall the upgrade.
                        if existing_peer.their_index() == Some(header.sender_idx)
                            && let Some(msg2) = existing_peer.handshake_msg2().map(|m| m.to_vec())
                            && let Some(transport) = self.transports.get(&packet.transport_id)
                        {
                            match transport.send(&packet.remote_addr, &msg2).await {
                                Ok(_) => debug!(
                                    peer = %self.peer_display_name(&peer_node_addr),
                                    "Resent msg2 for duplicate msg1 (same epoch)"
                                ),
                                Err(e) => debug!(
                                    peer = %self.peer_display_name(&peer_node_addr),
                                    error = %e,
                                    "Failed to resend msg2"
                                ),
                            }
                            self.msg1_rate_limiter.complete_handshake();
                            return;
                        }
                        debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            sender_index = %header.sender_idx,
                            active_sender_index = ?existing_peer.their_index(),
                            "Same-epoch msg1 has a fresh sender index; processing as an alternate-path handshake"
                        );
                    }
                }
            }
        }
        // If possible_restart was true but peer is no longer in self.peers
        // (removed by another path), fall through to process as new connection.

        if self
            .authorize_peer(
                &peer_identity,
                PeerAclContext::InboundHandshake,
                packet.transport_id,
                &packet.remote_addr,
            )
            .is_err()
        {
            self.msg1_rate_limiter.complete_handshake();
            return;
        }

        // Note: we don't early-return if peer is already in self.peers here.
        // promote_connection handles cross-connection resolution via tie-breaker.

        // Allocate our session index
        let our_index = match self.index_allocator.allocate() {
            Ok(idx) => idx,
            Err(e) => {
                self.msg1_rate_limiter.complete_handshake();
                warn!(error = %e, "Failed to allocate session index for inbound");
                return;
            }
        };

        conn.set_our_index(our_index);
        conn.set_their_index(header.sender_idx);

        // Create link
        let link = Link::connectionless(
            link_id,
            packet.transport_id,
            packet.remote_addr.clone(),
            LinkDirection::Inbound,
            Duration::from_millis(self.config.node.base_rtt_ms),
        );

        self.links.insert(link_id, link);
        self.peers.insert_connection(link_id, conn);

        // Build and send msg2 response, storing for potential resend
        let wire_msg2 = build_msg2(our_index, header.sender_idx, &msg2_response);
        if let Some(conn) = self.peers.get_connection_mut(&link_id) {
            conn.set_handshake_msg2(wire_msg2.clone());
        }

        if let Some(transport) = self.transports.get(&packet.transport_id) {
            match transport.send(&packet.remote_addr, &wire_msg2).await {
                Ok(bytes) => {
                    debug!(
                        link_id = %link_id,
                        our_index = %our_index,
                        their_index = %header.sender_idx,
                        bytes,
                        "Sent msg2 response"
                    );
                }
                Err(e) => {
                    warn!(
                        link_id = %link_id,
                        error = %e,
                        "Failed to send msg2"
                    );
                    // Clean up on failure
                    self.peers.remove_connection(&link_id);
                    self.links.remove(&link_id);
                    let _ = self.index_allocator.free(our_index);
                    self.msg1_rate_limiter.complete_handshake();
                    return;
                }
            }
        }

        // Responder handshake is complete after receive_handshake_init (Noise IK
        // pattern: responder processes msg1 and generates msg2 in one step).
        // Promote the connection to active peer now.
        match self.promote_connection(link_id, peer_identity, packet.timestamp_ms) {
            Ok(result) => {
                match result {
                    PromotionResult::Promoted(node_addr) => {
                        // Store msg2 on peer for resend on duplicate msg1
                        if let Some(peer) = self.peers.get_mut(&node_addr) {
                            peer.set_handshake_msg2(wire_msg2.clone());
                        }
                        debug!(
                            peer = %self.peer_display_name(&node_addr),
                            link_id = %link_id,
                            our_index = %our_index,
                            "Inbound peer promoted to active"
                        );
                        // Send initial tree announce to new peer
                        if let Err(e) = self.send_tree_announce_to_peer(&node_addr).await {
                            debug!(peer = %self.peer_display_name(&node_addr), error = %e, "Failed to send initial TreeAnnounce");
                        }
                        // Schedule filter announce (sent on next tick via debounce)
                        self.bloom_state.mark_update_needed(node_addr);
                        self.reset_discovery_backoff();
                    }
                    PromotionResult::CrossConnectionWon {
                        loser_link_id,
                        node_addr,
                    } => {
                        // Store msg2 on peer for resend on duplicate msg1
                        if let Some(peer) = self.peers.get_mut(&node_addr) {
                            peer.set_handshake_msg2(wire_msg2.clone());
                        }
                        // Close the losing TCP connection (no-op for connectionless)
                        if let Some(loser_link) = self.links.get(&loser_link_id) {
                            let loser_tid = loser_link.transport_id();
                            let loser_addr = loser_link.remote_addr().clone();
                            if let Some(transport) = self.transports.get(&loser_tid) {
                                transport.close_connection(&loser_addr).await;
                            }
                        }
                        // Clean up the losing connection's link
                        self.remove_link(&loser_link_id);
                        debug!(
                            peer = %self.peer_display_name(&node_addr),
                            loser_link_id = %loser_link_id,
                            "Inbound cross-connection won, loser link cleaned up"
                        );
                        // Send initial tree announce to peer (new or reconnected)
                        if let Err(e) = self.send_tree_announce_to_peer(&node_addr).await {
                            debug!(peer = %self.peer_display_name(&node_addr), error = %e, "Failed to send initial TreeAnnounce");
                        }
                        // Schedule filter announce (sent on next tick via debounce)
                        self.bloom_state.mark_update_needed(node_addr);
                        self.reset_discovery_backoff();
                    }
                    PromotionResult::CrossConnectionLost { winner_link_id } => {
                        // Close the losing TCP connection (no-op for connectionless)
                        if let Some(transport) = self.transports.get(&packet.transport_id) {
                            transport.close_connection(&packet.remote_addr).await;
                        }
                        // This connection lost — clean up its link
                        self.remove_link(&link_id);
                        // Restore address dispatch for the winner's link
                        self.links.insert_addr(
                            (packet.transport_id, packet.remote_addr.clone()),
                            winner_link_id,
                        );
                        debug!(
                            winner_link_id = %winner_link_id,
                            "Inbound cross-connection lost, keeping existing"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    link_id = %link_id,
                    error = %e,
                    "Failed to promote inbound connection"
                );
                // Clean up on promotion failure
                self.remove_link(&link_id);
                let _ = self.index_allocator.free(our_index);
            }
        }

        self.msg1_rate_limiter.complete_handshake();
    }

    /// Find stored msg2 bytes for a given link (pre- or post-promotion).
    ///
    /// Checks the PeerConnection (if still pending) and then the ActivePeer
    /// (if already promoted).
    fn find_stored_msg2(&self, link_id: LinkId) -> Option<Vec<u8>> {
        // Check pending connection first
        if let Some(conn) = self.peers.get_connection(&link_id)
            && let Some(msg2) = conn.handshake_msg2()
        {
            return Some(msg2.to_vec());
        }
        // Check promoted peer
        for peer in self.peers.values() {
            if peer.link_id() == link_id
                && let Some(msg2) = peer.handshake_msg2()
            {
                return Some(msg2.to_vec());
            }
        }
        None
    }
}

mod msg2;
mod promotion;
