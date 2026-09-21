use super::*;
use crate::node::ActivePeerCurrentSessionReplacement;

const AUTHENTICATED_UDP_ROAM_QUIET_MS: u64 = 1_000;
const SIMULTANEOUS_CROSS_CONNECTION_GRACE_MS: u32 = 1_000;

impl Node {
    /// A winning outbound can leave the opposite inbound parked at capacity.
    /// Retire only that same-epoch, same-carrier losing half; a restart or an
    /// alternate path must still authenticate through its normal lifecycle.
    pub(in crate::node) async fn retire_losing_inbound_handshakes(&mut self, peer: &NodeAddr) {
        let Some(active) = self.peers.get(peer) else {
            return;
        };
        if !active.fmp_mmp_is_initiator() || !cross_connection_winner(self.node_addr(), peer, true)
        {
            return;
        }
        let (Some(transport), Some(address), Some(epoch)) = (
            active.transport_id(),
            active.current_addr().cloned(),
            active.remote_epoch(),
        ) else {
            return;
        };
        let losers: Vec<_> = self
            .peers
            .connection_iter()
            .filter(|(_, conn)| {
                conn.is_inbound()
                    && conn.is_complete()
                    && conn
                        .expected_identity()
                        .is_some_and(|id| id.node_addr() == peer)
                    && conn.remote_epoch() == Some(epoch)
                    && conn.transport_id() == Some(transport)
                    && conn.source_addr() == Some(&address)
            })
            .map(|(link, _)| *link)
            .collect();
        for link in losers {
            self.retire_connection_candidate(link, Some((transport, address.clone())))
                .await;
        }
    }

    /// Promote a connection to active peer after successful authentication.
    ///
    /// Handles cross-connection detection and resolution using tie-breaker rules.
    #[cfg(test)]
    pub(in crate::node) fn promote_connection(
        &mut self,
        link_id: LinkId,
        verified_identity: PeerIdentity,
        current_time_ms: u64,
    ) -> Result<PromotionResult, NodeError> {
        let rotation = self.choose_neighbor_rotation_promotion(link_id, &verified_identity);
        self.promote_connection_with_rotation(link_id, verified_identity, current_time_ms, rotation)
    }

    pub(in crate::node) fn promote_connection_with_rotation(
        &mut self,
        link_id: LinkId,
        verified_identity: PeerIdentity,
        current_time_ms: u64,
        rotation: Option<crate::node::neighbor_rotation::PreparedNeighborRotation>,
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
            is_outbound,
        );

        // Check for cross-connection
        if let Some(existing_peer) = self.peers.get(&peer_node_addr) {
            let existing_link_id = existing_peer.link_id();
            let existing_carrier_unusable =
                !existing_peer.is_healthy() || !existing_peer.can_send();
            let opposite_direction_cross_connection =
                existing_peer.fmp_mmp_is_initiator() != is_outbound;
            let connection_oriented_cross_connection = self
                .is_connection_oriented_cross_connection(existing_peer, transport_id, is_outbound);
            let same_carrier_cross_connection = opposite_direction_cross_connection
                && existing_peer.transport_id() == Some(transport_id)
                && (connection_oriented_cross_connection
                    || existing_peer.current_addr() == Some(&current_addr));
            // Under startup load, one half of a simultaneous static dial can
            // finish just before the opposite Msg1 is dispatched. Endpoint
            // traffic on that new session may immediately expire exclusive
            // payload trust because no receiver report can have returned yet.
            // That soft signal must not override the deterministic NodeAddr
            // decision and leave both endpoints owning unrelated responder
            // sessions. Limit the exception to a newly established owner on
            // the exact same carrier; hard carrier failure and later recovery
            // handshakes still replace it normally.
            let fresh_same_carrier_cross_connection = same_carrier_cross_connection
                && existing_peer.session_elapsed_ms() < SIMULTANEOUS_CROSS_CONNECTION_GRACE_MS;
            let outbound_alternate_path = is_outbound
                && !connection_oriented_cross_connection
                && (existing_peer.transport_id() != Some(transport_id)
                    || existing_peer.current_addr() != Some(&current_addr));
            let inbound_alternate_path = !is_outbound
                && !connection_oriented_cross_connection
                && (existing_peer.transport_id() != Some(transport_id)
                    || existing_peer.current_addr() != Some(&current_addr));
            let authenticated_inbound_udp_roam = inbound_alternate_path
                && existing_peer.transport_id() == Some(transport_id)
                && existing_peer.idle_time(current_time_ms) >= AUTHENTICATED_UDP_ROAM_QUIET_MS
                && self.transports.get(&transport_id).is_some_and(|transport| {
                    transport.transport_type() == &crate::transport::TransportType::UDP
                });
            let authenticated_inbound_connection_refresh = inbound_alternate_path
                && existing_peer.transport_id() == Some(transport_id)
                && self
                    .transports
                    .get(&transport_id)
                    .is_some_and(|transport| transport.transport_type().connection_oriented);
            let late_inbound_refresh_for_active_outbound = inbound_alternate_path
                && existing_peer.fmp_mmp_is_initiator()
                && existing_peer.handshake_msg2().is_none()
                && self.alternate_path_priority_allows_replace(
                    &peer_node_addr,
                    transport_id,
                    &current_addr,
                );

            let remote_epoch_changed = matches!((existing_peer.remote_epoch(), remote_epoch), (Some(old), Some(new)) if old != new);
            let existing_payload_path_unusable = self
                .session_direct_path_blocks_direct_payload(&peer_node_addr, current_time_ms)
                || self
                    .session_direct_path_exclusive_trust_expired(&peer_node_addr, current_time_ms);
            let existing_path_unusable = existing_carrier_unusable
                || (existing_payload_path_unusable && !fresh_same_carrier_cross_connection);
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
            // eligible path refreshes. A freshly authenticated inbound UDP
            // handshake also proves that a peer which went quiet on its old
            // source tuple has roamed. Accept that same-carrier migration after
            // a short quiet interval instead of waiting for the stationary
            // endpoint's generic link-dead timeout. The equivalent signal for
            // a connection-oriented listener is an authenticated fresh inbound
            // stream from the same identity: a client cannot migrate a TCP-
            // backed carrier in place, and keeping the previous inbound stream
            // splits the two endpoints across different Noise sessions until
            // the listener's link-dead timeout.
            let this_wins = remote_epoch_changed
                || existing_path_unusable
                || authenticated_inbound_udp_roam
                || authenticated_inbound_connection_refresh
                || late_inbound_refresh_for_active_outbound
                || if outbound_alternate_path {
                    outbound_alternate_path_wins
                } else if inbound_alternate_path {
                    inbound_alternate_path_wins
                } else if opposite_direction_cross_connection {
                    cross_connection_winner(self.identity.node_addr(), &peer_node_addr, is_outbound)
                } else {
                    // The NodeAddr rule arbitrates the two opposite halves of
                    // one cross-connection. Applying it to a second handshake
                    // in the same direction can replace only one endpoint's
                    // Noise owner while the peer keeps the first matching
                    // owner. A healthy same-carrier duplicate therefore loses.
                    false
                };

            if this_wins {
                if remote_epoch_changed {
                    self.reset_peer_routing_after_restart(&peer_node_addr);
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

                    self.clear_stale_fsp_unless_recovered_to_remote_epoch(
                        &peer_node_addr,
                        remote_epoch,
                        "promotion",
                    );
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
                    self.finish_active_peer_session_replacement(
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
            // An inbound promotion retains pending outbound work until Msg2
            // supplies the remote index. A winning outbound promotion retires
            // only its proven losing inbound halves in the Msg2 handler.

            // Normal promotion
            if self.neighbor_roster_full()
                && !self.commit_neighbor_rotation(&peer_node_addr, link_id, rotation)
            {
                let _ = self.index_allocator.free(our_index);
                return Err(NodeError::MaxPeersExceeded {
                    max: self.max_peers,
                });
            }

            // Rotation may retain FSP after adjacency is gone. Its startup
            // epoch still distinguishes a rejoin from an actual peer restart.
            if self
                .sessions
                .get(&peer_node_addr)
                .is_some_and(|session| session.remote_epoch_changed(remote_epoch))
            {
                self.reset_peer_routing_after_restart(&peer_node_addr);
                self.clear_stale_fsp_unless_recovered_to_remote_epoch(
                    &peer_node_addr,
                    remote_epoch,
                    "normal_promotion",
                );
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

    /// A completed authenticated handshake proved a new startup epoch. Sequence
    /// numbers and cached tree state from the old process cannot reject the new
    /// process's first announcements. Never call this for an unaccepted Msg1.
    pub(in crate::node) fn reset_peer_routing_after_restart(&mut self, peer: &NodeAddr) {
        if let Some(active) = self.peers.get_mut(peer) {
            active.clear_filter();
        }
        self.handle_peer_removal_tree_cleanup(peer);
        self.coord_cache.invalidate_via_node(peer);
        self.refresh_tree_application_routes();
        self.bloom_state.remove_peer_state(peer);
        self.mark_all_tree_announces_pending();
        self.bloom_state
            .mark_all_updates_needed(self.peers.keys().copied());
    }

    pub(in crate::node) fn clear_stale_fsp_unless_recovered_to_remote_epoch(
        &mut self,
        peer_node_addr: &NodeAddr,
        remote_epoch: Option<[u8; 8]>,
        context: &'static str,
    ) -> bool {
        if self
            .sessions
            .get(peer_node_addr)
            .is_some_and(|session| session.established_remote_epoch_matches(remote_epoch))
        {
            debug!(
                peer = %self.peer_display_name(peer_node_addr),
                context,
                "Preserved FSP session already recovered to restarted peer epoch"
            );
            return false;
        }

        self.remove_dataplane_fsp_owner(peer_node_addr);
        if self.sessions.remove(peer_node_addr).is_some() {
            debug!(
                peer = %self.peer_display_name(peer_node_addr),
                context,
                "Cleared stale FSP session after peer restart"
            );
        }
        true
    }
}
