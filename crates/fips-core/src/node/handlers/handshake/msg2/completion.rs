use super::*;

impl Node {
    pub(in crate::node) async fn finish_completed_outbound_handshake(
        &mut self,
        link_id: LinkId,
        packet: ReceivedPacket,
    ) {
        let Some(header) = Msg2Header::parse(packet.data.as_slice()) else {
            return;
        };
        let Some((key, owner)) = self
            .pending_outbound
            .match_msg2(packet.transport_id, header.receiver_idx.as_u32())
        else {
            return;
        };
        if owner != link_id {
            return;
        }
        let Some(conn) = self.peers.get_connection(&link_id) else {
            return;
        };
        if !conn.is_outbound()
            || !conn.is_complete()
            || !conn.has_session()
            || conn.our_index() != Some(header.receiver_idx)
            || conn.their_index() != Some(header.sender_idx)
            || conn.source_addr() != Some(&packet.remote_addr)
        {
            return;
        }
        let Some(peer_identity) = conn.expected_identity().copied() else {
            return;
        };
        let retained = conn.completed_handshake_response().is_some();
        // A saved reply predates any peer authenticated while it waited. It
        // must not reinterpret that peer's newer startup epoch as a restart
        // back to the obsolete process represented by this old proof.
        let obsolete_epoch = retained
            && self
                .peers
                .get(peer_identity.node_addr())
                .is_some_and(|active| {
                    matches!(
                        (active.remote_epoch(), conn.remote_epoch()),
                        (Some(current), Some(saved)) if current != saved
                    )
                });
        let now_ms = Self::now_ms();
        if obsolete_epoch
            || self.packet_predates_carrier_rebind(packet.transport_id, packet.timestamp_ms)
            || (retained
                && conn.is_timed_out(
                    now_ms,
                    self.config
                        .node
                        .rate_limit
                        .handshake_timeout_secs
                        .saturating_mul(1000),
                ))
        {
            self.cleanup_stale_connection(link_id, now_ms).await;
            return;
        }
        // Carrier validity uses original receipt time. A held exchange gets
        // its neighbor age and liveness from the actual activation below.
        let admitted_at_ms = if retained {
            now_ms
        } else {
            packet.timestamp_ms
        };

        if self
            .authorize_peer(
                &peer_identity,
                PeerAclContext::OutboundHandshake,
                packet.transport_id,
                &packet.remote_addr,
            )
            .is_err()
        {
            // This arm removes the pending machine immediately, so the normal
            // stale-handshake sweep cannot observe the failure and schedule
            // another configured dial. Re-arm it here so relaxing a reloaded
            // ACL does not leave the peer permanently disconnected.
            self.schedule_retry_after_handshake_timeout(peer_identity, packet.timestamp_ms);
            self.cleanup_stale_connection(link_id, now_ms).await;
            return;
        }

        let peer_node_addr = *peer_identity.node_addr();
        if self
            .retain_outbound_neighbor_response(link_id, &peer_node_addr, &packet)
            .await
        {
            return;
        }
        self.retire_replaced_local_anchor(
            &peer_node_addr,
            packet.transport_id,
            &packet.remote_addr,
        );

        // Cross-connection resolution: if the peer was already promoted via
        // our inbound handshake (we processed their msg1), both nodes initially
        // use mismatched sessions. The tie-breaker determines which handshake
        // wins: smaller node_addr's outbound.
        //
        // - Winner (smaller node): swap to outbound session + outbound indices
        // - Loser (larger node): keep inbound session + original their_index
        //
        // This ensures both nodes use the same Noise handshake (the winner's
        // outbound = the loser's inbound).
        if self.peers.contains_key(&peer_node_addr) {
            let our_outbound_wins = cross_connection_winner(
                self.identity.node_addr(),
                &peer_node_addr,
                true, // this IS our outbound
            );

            // Extract the outbound connection
            self.unregister_handshake_candidate(link_id);
            let mut conn = match self.peers.remove_connection(&link_id) {
                Some(c) => c,
                None => {
                    self.pending_outbound.remove(&key);
                    return;
                }
            };
            let preferred_send_addr = conn.preferred_send_addr().cloned();
            let outbound_started_at = conn.started_at();

            let outbound_transport_id = conn
                .completed_handshake_response()
                .map(|reply| reply.transport_id)
                .or_else(|| conn.transport_id())
                .unwrap_or(packet.transport_id);
            let outbound_addr = conn
                .source_addr()
                .cloned()
                .unwrap_or_else(|| packet.remote_addr.clone());
            let outbound_remote_epoch = conn.remote_epoch();
            let (
                outbound_path_differs,
                connection_oriented_cross_connection,
                remote_epoch_changed,
                active_peer_unusable,
            ) = self
                .peers
                .get(&peer_node_addr)
                .map(|peer| {
                    (
                        peer.transport_id() != Some(outbound_transport_id)
                            || peer.current_addr() != Some(&outbound_addr),
                        self.is_connection_oriented_cross_connection(
                            peer,
                            outbound_transport_id,
                            true,
                        ),
                        matches!(
                            (peer.remote_epoch(), outbound_remote_epoch),
                            (Some(old), Some(new)) if old != new
                        ),
                        !peer.is_healthy()
                            || !peer.can_send()
                            // Cutover alone cannot make an old carrier usable:
                            // its remote pending keys may have been replaced.
                            || self.fmp_cutover_is_unconfirmed(&peer_node_addr),
                    )
                })
                .unwrap_or((false, false, false, false));
            // A retained Msg2 proves simultaneity only when it was generated
            // after this outbound dial started. Msg2 is deliberately retained
            // for retransmission, so its presence alone must not turn a much
            // later refresh into a cross-connection race and replace an
            // already matched carrier.
            let simultaneous_inbound_session =
                self.peers.get(&peer_node_addr).is_some_and(|peer| {
                    peer.handshake_msg2_generated_at()
                        .is_some_and(|generated_at| generated_at >= outbound_started_at)
                });
            let existing_path_unusable = !simultaneous_inbound_session
                && (active_peer_unusable
                    // Discovery can redial a quiet peer before link-dead
                    // removal, including one with no application session.
                    // Admit its fresh reply under the same stale-path rule.
                    || (!outbound_path_differs
                        && self.active_peer_needs_same_path_refresh_at(
                            &peer_node_addr,
                            admitted_at_ms,
                        ))
                    || self.session_direct_path_blocks_direct_payload(
                        &peer_node_addr,
                        admitted_at_ms,
                    )
                    || self.session_direct_path_exclusive_trust_expired(
                        &peer_node_addr,
                        admitted_at_ms,
                    ));
            let outbound_alternate_path = remote_epoch_changed
                || existing_path_unusable
                || (outbound_path_differs && !connection_oriented_cross_connection);
            let reply_transport_handoff =
                packet.transport_id != conn.transport_id().unwrap_or(packet.transport_id);
            let authenticated_live_carrier =
                self.active_peer_has_fresh_carrier_liveness(&peer_node_addr);
            // Link negotiation itself carries authenticated FSP traffic over
            // WSS. That activity must not pin the bootstrap over its direct
            // upgrade; the normal priority check still rejects worse paths.
            let websocket_direct_upgrade = self.active_peer_uses_websocket(&peer_node_addr)
                && self
                    .transports
                    .get(&outbound_transport_id)
                    .is_some_and(|transport| {
                        !matches!(transport, crate::transport::TransportHandle::WebSocket(_))
                    });
            let preserve_authenticated_live_carrier = !remote_epoch_changed
                && !simultaneous_inbound_session
                && !active_peer_unusable
                && !existing_path_unusable
                && !reply_transport_handoff
                && !websocket_direct_upgrade
                && authenticated_live_carrier;
            let late_duplicate_carrier = !simultaneous_inbound_session
                && (!outbound_path_differs || connection_oriented_cross_connection);
            let preserve_late_duplicate_carrier = !remote_epoch_changed
                && !active_peer_unusable
                && !existing_path_unusable
                && !reply_transport_handoff
                && late_duplicate_carrier;
            if outbound_alternate_path
                || preserve_authenticated_live_carrier
                || preserve_late_duplicate_carrier
            {
                let alternate_disallowed_by_priority = !remote_epoch_changed
                    && !existing_path_unusable
                    && !reply_transport_handoff
                    && !self.alternate_path_priority_allows_replace(
                        &peer_node_addr,
                        outbound_transport_id,
                        &outbound_addr,
                    );
                if preserve_authenticated_live_carrier
                    || preserve_late_duplicate_carrier
                    || alternate_disallowed_by_priority
                {
                    debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        authenticated_live_carrier,
                        late_duplicate_carrier,
                        endpoint_payload_degraded = existing_path_unusable,
                        candidate_transport_id = %outbound_transport_id,
                        candidate_addr = %outbound_addr,
                        "Discarding late alternate path while current carrier remains authenticated"
                    );
                    let outbound_our_index = conn.our_index();
                    self.preserve_completed_static_send_addr(
                        &peer_node_addr,
                        preferred_send_addr,
                        "discarded_outbound_alternate_path",
                    );
                    self.pending_outbound.remove(&key);
                    if let Some(idx) = outbound_our_index {
                        let _ = self.index_allocator.free(idx);
                    }
                    let winner_link_id = self.peers.get(&peer_node_addr).map(|peer| peer.link_id());
                    self.close_cross_connection_loser_physical_path(link_id, winner_link_id)
                        .await;
                    if let Some(link) = self.remove_link(&link_id) {
                        self.cleanup_bootstrap_transport_if_unused(link.transport_id());
                    }
                    if let Some(winner_link_id) = winner_link_id {
                        self.restore_link_address(winner_link_id);
                    }
                    return;
                }

                // This is not a simultaneous connection race: we already had
                // a usable peer and explicitly dialed a different concrete
                // transport tuple as a path refresh. A completed authenticated
                // outbound handshake is enough proof to promote the new path,
                // even if the normal cross-connection tie-breaker would keep
                // the old session.
                let outbound_our_index = conn.our_index();
                let outbound_session = conn.take_session();

                let (outbound_session, outbound_our_index) = match (
                    outbound_session,
                    outbound_our_index,
                ) {
                    (Some(s), Some(idx)) => (s, idx),
                    _ => {
                        warn!(peer = %self.peer_display_name(&peer_node_addr), "Incomplete outbound alternate-path connection");
                        self.pending_outbound.remove(&key);
                        if let Some(link) = self.remove_link(&link_id) {
                            self.cleanup_bootstrap_transport_if_unused(link.transport_id());
                        }
                        return;
                    }
                };

                let display_name = self.peer_display_name(&peer_node_addr);
                let replacement = match self.peers.replace_current_session_and_path(
                    &peer_node_addr,
                    ActivePeerCurrentSessionReplacement {
                        session: outbound_session,
                        our_index: outbound_our_index,
                        their_index: header.sender_idx,
                        link_id,
                        transport_id: outbound_transport_id,
                        addr: &outbound_addr,
                        is_initiator: true,
                        remote_epoch_update: outbound_remote_epoch,
                        connected_at_ms: admitted_at_ms,
                    },
                ) {
                    Some(replacement) => replacement,
                    None => {
                        warn!(peer = %display_name, "Active peer missing during outbound alternate-path promotion");
                        self.pending_outbound.remove(&key);
                        if let Some(link) = self.remove_link(&link_id) {
                            self.cleanup_bootstrap_transport_if_unused(link.transport_id());
                        }
                        return;
                    }
                };
                self.finish_active_peer_session_replacement(
                    &peer_node_addr,
                    &replacement,
                    "outbound_alternate_path_refresh",
                );
                if let Some(addr) = preferred_send_addr.clone()
                    && let Some(peer) = self.peers.get_mut(&peer_node_addr)
                {
                    peer.set_preferred_send_addr(addr);
                }
                if let Err(error) = self.sync_promoted_handshake(&peer_node_addr, &mut conn, true) {
                    warn!(%error, "Outbound alternate-path activation failed");
                    self.pending_outbound.remove(&key);
                    self.cleanup_failed_promotion(link_id).await;
                    return;
                }

                self.seed_path_mtu_for_link_peer(
                    &peer_node_addr,
                    outbound_transport_id,
                    &outbound_addr,
                );
                self.links
                    .insert_addr((outbound_transport_id, outbound_addr.clone()), link_id);
                self.clear_session_direct_path_degraded_after_promotion(
                    &peer_node_addr,
                    admitted_at_ms,
                );
                self.clear_retry_unless_direct_refresh_needed(&peer_node_addr);
                self.register_identity(peer_node_addr, peer_identity.pubkey_full());
                self.sync_dataplane_fmp_owner(&peer_node_addr);

                if remote_epoch_changed {
                    self.reset_peer_routing_after_restart(&peer_node_addr);
                }
                if remote_epoch_changed
                    && self.clear_stale_fsp_unless_recovered_to_remote_epoch(
                        &peer_node_addr,
                        outbound_remote_epoch,
                        "outbound path refresh",
                    )
                {
                    info!(
                        peer = %display_name,
                        "Peer restart detected during outbound path refresh, replacing stale endpoint session"
                    );
                }

                self.pending_outbound.remove(&key);
                let loser_link_id = replacement.old_link_id;
                self.close_cross_connection_loser_physical_path(loser_link_id, Some(link_id))
                    .await;
                if let Some(loser_link) = self.remove_link(&loser_link_id) {
                    self.cleanup_bootstrap_transport_if_unused(loser_link.transport_id());
                }
                self.restore_link_address(link_id);

                debug!(
                    peer = %display_name,
                    link_id = %link_id,
                    transport_id = %outbound_transport_id,
                    remote_addr = %outbound_addr,
                    "Promoted outbound alternate-path refresh"
                );

                self.complete_outbound_handshake_bootstrap(&peer_node_addr)
                    .await;
                self.retry_degraded_session_routes_after_peer_authenticated(
                    peer_node_addr,
                    admitted_at_ms,
                )
                .await;
                return;
            }

            if our_outbound_wins {
                // We're the smaller node. Swap to outbound session + indices.
                // The peer will keep their inbound session (complement of ours).
                let outbound_our_index = conn.our_index();
                let outbound_session = conn.take_session();
                let outbound_transport_id = conn
                    .completed_handshake_response()
                    .map(|reply| reply.transport_id)
                    .or_else(|| conn.transport_id())
                    .unwrap_or(packet.transport_id);
                let outbound_addr = conn
                    .source_addr()
                    .cloned()
                    .unwrap_or_else(|| packet.remote_addr.clone());

                let (outbound_session, outbound_our_index) = match (
                    outbound_session,
                    outbound_our_index,
                ) {
                    (Some(s), Some(idx)) => (s, idx),
                    _ => {
                        warn!(peer = %self.peer_display_name(&peer_node_addr), "Incomplete outbound connection");
                        self.pending_outbound.remove(&key);
                        return;
                    }
                };

                let replacement = match self.peers.replace_current_session_and_path(
                    &peer_node_addr,
                    ActivePeerCurrentSessionReplacement {
                        session: outbound_session,
                        our_index: outbound_our_index,
                        their_index: header.sender_idx,
                        link_id,
                        transport_id: outbound_transport_id,
                        addr: &outbound_addr,
                        is_initiator: true,
                        remote_epoch_update: None,
                        connected_at_ms: admitted_at_ms,
                    },
                ) {
                    Some(replacement) => replacement,
                    None => {
                        warn!(peer = %self.peer_display_name(&peer_node_addr), "Active peer missing during outbound cross-connection swap");
                        self.pending_outbound.remove(&key);
                        return;
                    }
                };
                self.finish_active_peer_session_replacement(
                    &peer_node_addr,
                    &replacement,
                    "outbound_cross_connection_swap",
                );
                if let Some(addr) = preferred_send_addr
                    && let Some(peer) = self.peers.get_mut(&peer_node_addr)
                {
                    peer.set_preferred_send_addr(addr);
                }
                if let Err(error) = self.sync_promoted_handshake(&peer_node_addr, &mut conn, true) {
                    warn!(%error, "Outbound cross-connection activation failed");
                    self.pending_outbound.remove(&key);
                    self.cleanup_failed_promotion(link_id).await;
                    return;
                }
                self.links
                    .insert_addr((outbound_transport_id, outbound_addr.clone()), link_id);
                self.sync_dataplane_fmp_owner(&peer_node_addr);

                debug!(
                    peer = %self.peer_display_name(&peer_node_addr),
                    new_our_index = %outbound_our_index,
                    new_their_index = %header.sender_idx,
                    transport_id = %outbound_transport_id,
                    remote_addr = %outbound_addr,
                    "Cross-connection: swapped to outbound session (our outbound wins)"
                );

                self.pending_outbound.remove(&key);
                let loser_link_id = replacement.old_link_id;
                self.close_cross_connection_loser_physical_path(loser_link_id, Some(link_id))
                    .await;
                if let Some(loser_link) = self.remove_link(&loser_link_id) {
                    self.cleanup_bootstrap_transport_if_unused(loser_link.transport_id());
                }
                self.restore_link_address(link_id);
            } else {
                // We're the larger node. Keep our inbound session (it pairs
                // with the peer's outbound, which is the winning handshake).
                //
                // Do NOT update their_index here. Our their_index was set during
                // promote_connection() from the peer's msg1 sender_idx, which is
                // the peer's outbound our_index. After the peer (winner) swaps to
                // their outbound session, that index is exactly what they'll use.
                // The msg2 sender_idx we see here is the peer's INBOUND our_index,
                // which becomes stale after the peer swaps.
                let outbound_our_index = conn.our_index();

                if let Some(peer) = self.peers.get(&peer_node_addr) {
                    debug!(
                        peer = %self.peer_display_name(&peer_node_addr),
                        kept_their_index = ?peer.their_index(),
                        "Cross-connection: keeping inbound session and original their_index (peer outbound wins)"
                    );
                }

                // Free the outbound's session index since we're not using it
                if let Some(idx) = outbound_our_index {
                    let _ = self.index_allocator.free(idx);
                }

                self.preserve_completed_static_send_addr(
                    &peer_node_addr,
                    preferred_send_addr,
                    "outbound_cross_connection_lost",
                );

                self.pending_outbound.remove(&key);
                let winner_link_id = self.peers.get(&peer_node_addr).map(|peer| peer.link_id());
                self.close_cross_connection_loser_physical_path(link_id, winner_link_id)
                    .await;
                if let Some(link) = self.remove_link(&link_id) {
                    self.cleanup_bootstrap_transport_if_unused(link.transport_id());
                }
                if let Some(winner_link_id) = winner_link_id {
                    self.restore_link_address(winner_link_id);
                }
            }

            // Send TreeAnnounce now that sessions are aligned
            self.complete_outbound_handshake_bootstrap(&peer_node_addr)
                .await;
            return;
        }

        // Normal path: promote to active peer
        let rotation = self
            .prepare_neighbor_rotation_promotion(link_id, &peer_identity)
            .await;
        match self.promote_connection_with_rotation(
            link_id,
            peer_identity,
            admitted_at_ms,
            rotation,
        ) {
            Ok(result) => {
                // Clean up pending_outbound
                self.pending_outbound.remove(&key);

                let authenticated_path_updated = match result {
                    PromotionResult::Promoted(node_addr) => {
                        self.retire_losing_inbound_handshakes(&node_addr).await;
                        info!(
                            peer = %self.peer_display_name(&node_addr),
                            "Peer promoted to active"
                        );
                        // Send initial tree announce to new peer
                        self.complete_outbound_handshake_bootstrap(&node_addr).await;
                        Some(node_addr)
                    }
                    PromotionResult::CrossConnectionWon {
                        loser_link_id,
                        node_addr,
                    } => {
                        self.close_cross_connection_loser_physical_path(
                            loser_link_id,
                            Some(link_id),
                        )
                        .await;
                        // Clean up the losing connection's link
                        if let Some(loser_link) = self.remove_link(&loser_link_id) {
                            self.cleanup_bootstrap_transport_if_unused(loser_link.transport_id());
                        }
                        // Ensure address dispatch points to the winning link
                        self.links.insert_addr(
                            (packet.transport_id, packet.remote_addr.clone()),
                            link_id,
                        );
                        debug!(
                            peer = %self.peer_display_name(&node_addr),
                            loser_link_id = %loser_link_id,
                            "Outbound cross-connection won, loser link cleaned up"
                        );
                        // Send initial tree announce to peer (new or reconnected)
                        self.complete_outbound_handshake_bootstrap(&node_addr).await;
                        Some(node_addr)
                    }
                    PromotionResult::CrossConnectionLost { winner_link_id } => {
                        self.close_cross_connection_loser_physical_path(
                            link_id,
                            Some(winner_link_id),
                        )
                        .await;
                        // This connection lost — clean up its link
                        if let Some(link) = self.remove_link(&link_id) {
                            self.cleanup_bootstrap_transport_if_unused(link.transport_id());
                        }
                        // Ensure address dispatch points to the winner's link
                        self.links.insert_addr(
                            (packet.transport_id, packet.remote_addr.clone()),
                            winner_link_id,
                        );
                        debug!(
                            winner_link_id = %winner_link_id,
                            "Outbound cross-connection lost, keeping existing"
                        );
                        None
                    }
                };
                if let Some(node_addr) = authenticated_path_updated {
                    self.retry_degraded_session_routes_after_peer_authenticated(
                        node_addr,
                        admitted_at_ms,
                    )
                    .await;
                }
            }
            Err(e) => {
                // Promotion consumed the candidate and releases its index on
                // capacity rejection. Retire its remaining admission state
                // before awaiting physical closure, preserving any live owner.
                self.pending_outbound.remove(&key);
                self.cleanup_failed_promotion(link_id).await;
                warn!(
                    link_id = %link_id,
                    error = %e,
                    "Failed to promote connection"
                );
            }
        }
    }
}
