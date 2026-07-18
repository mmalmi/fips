use super::*;
use crate::node::ActivePeerCurrentSessionReplacement;

impl Node {
    /// Promote a connection to active peer after successful authentication.
    ///
    /// Handles cross-connection detection and resolution using tie-breaker rules.
    pub(in crate::node) fn promote_connection(
        &mut self,
        link_id: LinkId,
        verified_identity: PeerIdentity,
        current_time_ms: u64,
    ) -> Result<PromotionResult, NodeError> {
        // Remove the connection from pending
        let mut connection = self
            .peers
            .remove_connection(&link_id)
            .ok_or(NodeError::ConnectionNotFound(link_id))?;

        // Verify handshake is complete and extract session
        if !connection.has_session() {
            return Err(NodeError::HandshakeIncomplete(link_id));
        }

        let noise_session = connection
            .take_session()
            .ok_or(NodeError::NoSession(link_id))?;

        let our_index = connection
            .our_index()
            .ok_or_else(|| NodeError::PromotionFailed {
                link_id,
                reason: "missing our_index".into(),
            })?;
        let their_index = connection
            .their_index()
            .ok_or_else(|| NodeError::PromotionFailed {
                link_id,
                reason: "missing their_index".into(),
            })?;
        let transport_id = connection
            .transport_id()
            .ok_or_else(|| NodeError::PromotionFailed {
                link_id,
                reason: "missing transport_id".into(),
            })?;
        let observed_addr = connection
            .source_addr()
            .ok_or_else(|| NodeError::PromotionFailed {
                link_id,
                reason: "missing source_addr".into(),
            })?
            .clone();
        let link_stats = connection.link_stats().clone();
        let remote_epoch = connection.remote_epoch();
        let preferred_send_addr = connection.preferred_send_addr().cloned();

        let peer_node_addr = *verified_identity.node_addr();
        let is_outbound = connection.is_outbound();
        let current_addr = observed_addr;
        let discovery_fallback_transit_allowed = self.discovery_fallback_transit_for_promotion(
            &peer_node_addr,
            transport_id,
            &current_addr,
        );

        // Check for cross-connection
        if let Some(existing_peer) = self.peers.get(&peer_node_addr) {
            let existing_link_id = existing_peer.link_id();
            let existing_path_unusable = !existing_peer.is_healthy() || !existing_peer.can_send();
            let connection_oriented_cross_connection = self
                .is_connection_oriented_cross_connection(existing_peer, transport_id, is_outbound);
            let outbound_alternate_path = is_outbound
                && !connection_oriented_cross_connection
                && (existing_peer.transport_id() != Some(transport_id)
                    || existing_peer.current_addr() != Some(&current_addr));
            let inbound_alternate_path = !is_outbound
                && !connection_oriented_cross_connection
                && (existing_peer.transport_id() != Some(transport_id)
                    || existing_peer.current_addr() != Some(&current_addr));
            let late_inbound_refresh_for_active_outbound = inbound_alternate_path
                && existing_peer.fmp_mmp_is_initiator()
                && existing_peer.handshake_msg2().is_none()
                && self.alternate_path_priority_allows_replace(
                    &peer_node_addr,
                    transport_id,
                    &current_addr,
                );

            let remote_epoch_changed = matches!((existing_peer.remote_epoch(), remote_epoch), (Some(old), Some(new)) if old != new);
            let existing_path_unusable = existing_path_unusable
                || self.session_direct_path_blocks_direct_payload(&peer_node_addr, current_time_ms)
                || self
                    .session_direct_path_exclusive_trust_expired(&peer_node_addr, current_time_ms);
            let outbound_alternate_path_wins = outbound_alternate_path
                && self.alternate_path_priority_allows_replace(
                    &peer_node_addr,
                    transport_id,
                    &current_addr,
                );
            let inbound_alternate_path_wins = inbound_alternate_path
                && self.alternate_path_priority_allows_replace(
                    &peer_node_addr,
                    transport_id,
                    &current_addr,
                );

            // Determine which connection wins. A peer restart (different
            // startup epoch) is not a normal cross-connection: the old link
            // and FSP sessions are cryptographically stale, so the freshly
            // authenticated connection must replace them regardless of the
            // tie-breaker direction.
            //
            // Likewise, a link-dead path is kept as a reconnecting peer so
            // higher-level sessions and routes survive. A fresh authenticated
            // connection is proof of a usable replacement path, so it should
            // win instead of applying the simultaneous-handshake tie-breaker to
            // a path we already marked unusable.
            //
            // A completed handshake on a genuinely different path is also not
            // a symmetric cross-connection when it is an explicit alternate-
            // path refresh. For connection-oriented transports, however, the
            // listener and accepted-stream source tuples naturally differ; an
            // opposite-direction candidate on the same transport still uses
            // the deterministic NodeAddr tie-breaker. UDP tuple changes remain
            // eligible path refreshes.
            let this_wins = remote_epoch_changed
                || existing_path_unusable
                || late_inbound_refresh_for_active_outbound
                || if outbound_alternate_path {
                    outbound_alternate_path_wins
                } else if inbound_alternate_path {
                    inbound_alternate_path_wins
                } else {
                    cross_connection_winner(self.identity.node_addr(), &peer_node_addr, is_outbound)
                };

            if this_wins {
                if remote_epoch_changed {
                    // A peer restart is not a session handoff; the previous FMP
                    // owner is cryptographically stale and should not drain.
                    let old_peer = self.peers.remove(&peer_node_addr).unwrap();
                    let loser_link_id = old_peer.link_id();

                    if let (Some(old_tid), Some(old_idx)) =
                        (old_peer.transport_id(), old_peer.our_index())
                    {
                        self.deregister_session_index((old_tid, old_idx.as_u32()));
                        let _ = self.index_allocator.free(old_idx);
                    }

                    self.remove_dataplane_fsp_owner(&peer_node_addr);
                    if self.sessions.remove(&peer_node_addr).is_some() {
                        debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            "Cleared stale FSP session after peer restart during promotion"
                        );
                    }
                    info!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        winner_link = %link_id,
                        loser_link = %loser_link_id,
                        "Peer restart detected during promotion, replacing stale active peer"
                    );

                    self.seed_path_mtu_for_link_peer(&peer_node_addr, transport_id, &current_addr);

                    let mut new_peer = ActivePeer::with_session(
                        verified_identity,
                        link_id,
                        current_time_ms,
                        ActivePeerSession {
                            session: noise_session,
                            our_index,
                            their_index,
                            transport_id,
                            current_addr,
                            link_stats,
                            is_initiator: is_outbound,
                            remote_epoch,
                        },
                    );
                    if let Some(addr) = preferred_send_addr.clone() {
                        new_peer.set_preferred_send_addr(addr);
                    }
                    new_peer.set_tree_announce_min_interval_ms(
                        self.config.node.tree.announce_min_interval_ms,
                    );

                    let inserted = self
                        .peers
                        .insert_with_current_session_index(peer_node_addr, new_peer);
                    self.log_active_peer_insert_result(
                        &peer_node_addr,
                        &inserted,
                        "cross_connection_won_restart",
                    );
                    self.sync_dataplane_fmp_owner(&peer_node_addr);
                    self.clear_session_direct_path_degraded_after_promotion(
                        &peer_node_addr,
                        current_time_ms,
                    );
                    self.clear_retry_unless_direct_refresh_needed(&peer_node_addr);
                    self.set_discovery_fallback_transit_allowed(
                        peer_node_addr,
                        discovery_fallback_transit_allowed,
                    );
                    self.register_identity(peer_node_addr, verified_identity.pubkey_full());

                    self.sync_dataplane_fmp_owner(&peer_node_addr);

                    debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        winner_link = %link_id,
                        loser_link = %loser_link_id,
                        "Cross-connection resolved: this connection won after peer restart"
                    );

                    Ok(PromotionResult::CrossConnectionWon {
                        loser_link_id,
                        node_addr: peer_node_addr,
                    })
                } else {
                    let loser_link_id = existing_link_id;

                    self.seed_path_mtu_for_link_peer(&peer_node_addr, transport_id, &current_addr);
                    let replacement = self
                        .peers
                        .replace_current_session_and_path(
                            &peer_node_addr,
                            ActivePeerCurrentSessionReplacement {
                                session: noise_session,
                                our_index,
                                their_index,
                                link_id,
                                transport_id,
                                addr: &current_addr,
                                is_initiator: is_outbound,
                                remote_epoch_update: remote_epoch,
                                connected_at_ms: current_time_ms,
                            },
                        )
                        .ok_or(NodeError::PeerNotFound(peer_node_addr))?;
                    self.log_active_peer_session_replacement_result(
                        &peer_node_addr,
                        &replacement,
                        "cross_connection_won",
                    );
                    if let Some(addr) = preferred_send_addr.clone()
                        && let Some(peer) = self.peers.get_mut(&peer_node_addr)
                    {
                        peer.set_preferred_send_addr(addr);
                    }
                    self.sync_dataplane_fmp_owner(&peer_node_addr);
                    self.clear_session_direct_path_degraded_after_promotion(
                        &peer_node_addr,
                        current_time_ms,
                    );
                    self.clear_retry_unless_direct_refresh_needed(&peer_node_addr);
                    self.set_discovery_fallback_transit_allowed(
                        peer_node_addr,
                        discovery_fallback_transit_allowed,
                    );
                    self.register_identity(peer_node_addr, verified_identity.pubkey_full());
                    self.sync_dataplane_fmp_owner(&peer_node_addr);

                    debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        winner_link = %link_id,
                        loser_link = %loser_link_id,
                        "Cross-connection resolved: this connection won"
                    );

                    Ok(PromotionResult::CrossConnectionWon {
                        loser_link_id,
                        node_addr: peer_node_addr,
                    })
                }
            } else {
                // This connection loses, keep existing
                // Free the index we allocated
                let _ = self.index_allocator.free(our_index);

                debug!(
                    peer = %self.peer_display_name(&peer_node_addr),
                    winner_link = %existing_link_id,
                    loser_link = %link_id,
                    "Cross-connection resolved: this connection lost"
                );

                Ok(PromotionResult::CrossConnectionLost {
                    winner_link_id: existing_link_id,
                })
            }
        } else {
            // No existing promoted peer. There may be a pending outbound
            // connection to the same peer (cross-connection in progress).
            // Do NOT clean it up yet — we need the outbound to stay alive
            // so that when the peer's msg2 arrives, we can learn the peer's
            // inbound session index and update their_index on the promoted
            // peer. The outbound will be cleaned up in handle_msg2 or by
            // the 30s handshake timeout.
            let pending_to_same_peer: Vec<LinkId> = self
                .peers
                .connection_iter()
                .filter(|(_, conn)| {
                    conn.expected_identity()
                        .map(|id| *id.node_addr() == peer_node_addr)
                        .unwrap_or(false)
                })
                .map(|(lid, _)| *lid)
                .collect();

            for pending_link_id in &pending_to_same_peer {
                debug!(
                    peer = %self.peer_display_name(&peer_node_addr),
                    pending_link_id = %pending_link_id,
                    promoted_link_id = %link_id,
                    "Deferring cleanup of pending outbound (awaiting msg2 for index update)"
                );
            }

            // Normal promotion
            if self.max_peers > 0 && self.peers.len() >= self.max_peers {
                let _ = self.index_allocator.free(our_index);
                return Err(NodeError::MaxPeersExceeded {
                    max: self.max_peers,
                });
            }

            // Preserve tree announce rate-limit state from old peer (if reconnecting).
            // Without this, reconnection resets the rate limit window to zero,
            // allowing an immediate announce that can feed an announce loop.
            let old_announce_ts = self
                .peers
                .get(&peer_node_addr)
                .map(|p| p.last_tree_announce_sent_ms());

            self.seed_path_mtu_for_link_peer(&peer_node_addr, transport_id, &current_addr);

            let mut new_peer = ActivePeer::with_session(
                verified_identity,
                link_id,
                current_time_ms,
                ActivePeerSession {
                    session: noise_session,
                    our_index,
                    their_index,
                    transport_id,
                    current_addr,
                    link_stats,
                    is_initiator: is_outbound,
                    remote_epoch,
                },
            );
            if let Some(addr) = preferred_send_addr {
                new_peer.set_preferred_send_addr(addr);
            }
            new_peer
                .set_tree_announce_min_interval_ms(self.config.node.tree.announce_min_interval_ms);
            if let Some(ts) = old_announce_ts {
                new_peer.set_last_tree_announce_sent_ms(ts);
            }

            let inserted = self
                .peers
                .insert_with_current_session_index(peer_node_addr, new_peer);
            self.log_active_peer_insert_result(&peer_node_addr, &inserted, "promoted");
            self.sync_dataplane_fmp_owner(&peer_node_addr);
            self.clear_session_direct_path_degraded_after_promotion(
                &peer_node_addr,
                current_time_ms,
            );
            self.clear_retry_unless_direct_refresh_needed(&peer_node_addr);
            self.set_discovery_fallback_transit_allowed(
                peer_node_addr,
                discovery_fallback_transit_allowed,
            );
            self.register_identity(peer_node_addr, verified_identity.pubkey_full());

            // Eagerly hand the FMP recv state to the dataplane owner.
            // From this point on the owner is the authoritative
            // FMP-replay-window writer for this peer.
            self.sync_dataplane_fmp_owner(&peer_node_addr);

            info!(
                peer = %self.peer_display_name(&peer_node_addr),
                link_id = %link_id,
                our_index = %our_index,
                their_index = %their_index,
                "Connection promoted to active peer"
            );

            Ok(PromotionResult::Promoted(peer_node_addr))
        }
    }
}
