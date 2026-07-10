use super::*;
use crate::node::ActivePeerCurrentSessionReplacement;

impl Node {
    fn preserve_completed_static_send_addr(
        &mut self,
        peer_node_addr: &crate::NodeAddr,
        preferred_send_addr: Option<crate::transport::TransportAddr>,
        reason: &'static str,
    ) -> bool {
        let Some(addr) = preferred_send_addr else {
            return false;
        };
        let Some(peer) = self.peers.get_mut(peer_node_addr) else {
            return false;
        };
        let changed = peer.set_preferred_send_addr(addr.clone());
        if changed {
            let _ = self.sync_dataplane_fmp_owner(peer_node_addr);
        }
        debug!(
            peer = %self.peer_display_name(peer_node_addr),
            preferred_send_addr = %addr,
            changed,
            reason,
            "Preserved authenticated static UDP send address on active peer"
        );
        changed
    }

    /// Handle handshake message 2 (phase 0x2).
    ///
    /// This completes an outbound handshake we initiated.
    pub(in crate::node) async fn handle_msg2(&mut self, packet: ReceivedPacket) {
        // Parse header
        let header = match Msg2Header::parse(packet.data.as_slice()) {
            Some(h) => h,
            None => {
                debug!("Invalid msg2 header");
                return;
            }
        };

        // Look up our pending handshake by our sender_idx (receiver_idx in msg2).
        //
        // The sender index is allocated globally, but older code also keyed
        // the lookup by the receive-side transport id. That is normally the
        // same transport we used for msg1, but UDP replies can surface through
        // an equivalent/adopted transport id after NAT traversal or local
        // socket changes. In that case the index is still authoritative; only
        // fall back when it names a single pending outbound handshake.
        let (key, link_id) = match self
            .pending_outbound
            .match_msg2(packet.transport_id, header.receiver_idx.as_u32())
        {
            Some((key, link_id)) => {
                if key.0 != packet.transport_id {
                    debug!(
                        receiver_idx = %header.receiver_idx,
                        received_transport_id = %packet.transport_id,
                        pending_transport_id = %key.0,
                        "Matched pending outbound handshake by sender index across transport ids"
                    );
                }
                (key, link_id)
            }
            None => {
                debug!(
                    receiver_idx = %header.receiver_idx,
                    transport_id = %packet.transport_id,
                    "No pending outbound handshake for index"
                );
                return;
            }
        };

        // Check if this is a rekey msg2: the handshake state is on the
        // ActivePeer (not a pending PeerConnection), so the lifecycle registry
        // will not have it in the connection phase.
        // Look for a peer with matching rekey_our_index.
        if !self.peers.contains_connection(&link_id) {
            let noise_msg2 = &packet.data.as_slice()[header.noise_msg2_offset..];

            // Find peer with rekey in progress for this index
            let peer_addr = self.peers.iter().find_map(|(addr, peer)| {
                if peer.rekey_in_progress() && peer.rekey_our_index() == Some(header.receiver_idx) {
                    Some(*addr)
                } else {
                    None
                }
            });

            if let Some(peer_node_addr) = peer_addr {
                let display_name = self.peer_display_name(&peer_node_addr);

                let mut abandoned_rekey = None;
                let completed_rekey = if let Some(peer) = self.peers.get_mut(&peer_node_addr) {
                    match peer.complete_rekey_msg2(noise_msg2) {
                        Ok((session, remote_epoch)) => {
                            let our_index = peer.rekey_our_index().unwrap_or(header.receiver_idx);
                            let remote_epoch_changed = matches!(
                                (peer.remote_epoch(), remote_epoch),
                                (Some(old), Some(new)) if old != new
                            );
                            let pending_fmp_k_bit = !peer.current_k_bit();
                            let pending_fmp_open = session.recv_cipher_clone();
                            Some((
                                session,
                                remote_epoch,
                                our_index,
                                remote_epoch_changed,
                                pending_fmp_k_bit,
                                pending_fmp_open,
                            ))
                        }
                        Err(e) => {
                            warn!(
                                peer = %display_name,
                                error = %e,
                                "Rekey msg2 processing failed"
                            );
                            abandoned_rekey =
                                peer.abandon_rekey().map(|idx| (peer.transport_id(), idx));
                            None
                        }
                    }
                } else {
                    warn!(
                        peer = %display_name,
                        "Rekey msg2 matched a peer that disappeared before completion"
                    );
                    None
                };

                if let Some((transport_id, idx)) = abandoned_rekey {
                    if let Some(tid) = transport_id {
                        self.deregister_session_index((tid, idx.as_u32()));
                    }
                    let _ = self.index_allocator.free(idx);
                }

                if let Some((
                    session,
                    remote_epoch,
                    our_index,
                    remote_epoch_changed,
                    pending_fmp_k_bit,
                    pending_fmp_open,
                )) = completed_rekey
                {
                    if let Some(registered) = self.peers.install_pending_rekey_session_and_index(
                        &peer_node_addr,
                        session,
                        our_index,
                        header.sender_idx,
                        true,
                        remote_epoch,
                    ) {
                        self.log_registered_peer_session_index_result(
                            &peer_node_addr,
                            &registered,
                            "initiator_pending_rekey",
                        );
                        let _ = self.sync_dataplane_fmp_owner(&peer_node_addr);
                        if let Some(open) = pending_fmp_open {
                            let _ = self.install_dataplane_fmp_pending_receive_epoch(
                                &peer_node_addr,
                                pending_fmp_k_bit,
                                open,
                            );
                        }

                        if remote_epoch_changed {
                            self.remove_dataplane_fsp_owner(&peer_node_addr);
                            if self.sessions.remove(&peer_node_addr).is_some() {
                                debug!(
                                    peer = %display_name,
                                    "Cleared stale FSP session after peer restart during FMP rekey"
                                );
                            }
                            info!(
                                peer = %display_name,
                                "Peer restart detected during FMP rekey, replacing stale endpoint session"
                            );
                        }

                        debug!(
                            peer = %display_name,
                            new_our_index = %our_index,
                            new_their_index = %header.sender_idx,
                            "Rekey completed (initiator), pending K-bit cutover"
                        );
                    } else {
                        warn!(
                            peer = %display_name,
                            "Could not install initiator pending rekey session"
                        );
                        if let Some(peer) = self.peers.get_mut(&peer_node_addr)
                            && let Some(idx) = peer.abandon_rekey()
                        {
                            let transport_id = peer.transport_id();
                            if let Some(tid) = transport_id {
                                self.deregister_session_index((tid, idx.as_u32()));
                            }
                            let _ = self.index_allocator.free(idx);
                        }
                    }
                }

                self.pending_outbound.remove(&key);
                return;
            }

            // Not a rekey — stale pending_outbound entry
            self.pending_outbound.remove(&key);
            return;
        }

        let (peer_identity, our_index, dial_transport_id, dial_addr) = {
            let conn = self.peers.get_connection_mut(&link_id).unwrap();
            let dial_transport_id = conn.transport_id();
            let dial_addr = conn.source_addr().cloned();

            let noise_msg2 = &packet.data.as_slice()[header.noise_msg2_offset..];
            if let Err(e) = conn.complete_handshake(noise_msg2, packet.timestamp_ms) {
                warn!(
                    link_id = %link_id,
                    error = %e,
                    "Handshake completion failed"
                );
                conn.mark_failed();
                return;
            }

            conn.set_their_index(header.sender_idx);
            conn.set_source_addr(packet.remote_addr.clone());

            let peer_identity = match conn.expected_identity() {
                Some(id) => *id,
                None => {
                    warn!(link_id = %link_id, "No identity after handshake");
                    return;
                }
            };

            (
                peer_identity,
                conn.our_index(),
                dial_transport_id,
                dial_addr,
            )
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
            self.pending_outbound.remove(&key);
            if let Some(link) = self.links.get(&link_id) {
                let tid = link.transport_id();
                let addr = link.remote_addr().clone();
                if let Some(transport) = self.transports.get(&tid) {
                    transport.close_connection(&addr).await;
                }
            }
            self.peers.remove_connection(&link_id);
            self.remove_link(&link_id);
            if let Some(idx) = our_index {
                let _ = self.index_allocator.free(idx);
            }
            return;
        }

        let peer_node_addr = *peer_identity.node_addr();
        let peer_npub = peer_identity.npub();
        let preferred_send_addr =
            dial_transport_id
                .zip(dial_addr)
                .and_then(|(transport_id, addr)| {
                    if addr == packet.remote_addr {
                        return None;
                    }
                    let indexed_static_match = self
                        .configured_static_udp_path_for_peer(&peer_node_addr, transport_id)
                        .as_ref()
                        == Some(&addr);
                    let transport_is_udp = self
                        .transports
                        .get(&transport_id)
                        .is_some_and(|transport| transport.transport_type().name == "udp");
                    let direct_static_match = transport_is_udp
                        && self
                            .config
                            .peers
                            .iter()
                            .filter(|peer| peer.npub == peer_npub)
                            .flat_map(|peer| peer.addresses.iter())
                            .any(|candidate| {
                                candidate.seen_at_ms.is_none()
                                    && candidate.transport.eq_ignore_ascii_case("udp")
                                    && crate::transport::TransportAddr::from_string(&candidate.addr)
                                        == addr
                            });
                    (indexed_static_match || direct_static_match).then_some(addr)
                });
        if let Some(addr) = preferred_send_addr {
            if let Some(conn) = self.peers.get_connection_mut(&link_id) {
                conn.set_preferred_send_addr(addr.clone());
            }
            debug!(
                peer = %self.peer_display_name(&peer_node_addr),
                observed_addr = %packet.remote_addr,
                preferred_send_addr = %addr,
                "Preserved asymmetric UDP send address from completed static dial"
            );
        }

        debug!(
            peer = %self.peer_display_name(&peer_node_addr),
            link_id = %link_id,
            their_index = %header.sender_idx,
            "Outbound handshake completed"
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
            let mut conn = match self.peers.remove_connection(&link_id) {
                Some(c) => c,
                None => {
                    self.pending_outbound.remove(&key);
                    return;
                }
            };
            let preferred_send_addr = conn.preferred_send_addr().cloned();

            let outbound_transport_id = conn.transport_id().unwrap_or(packet.transport_id);
            let outbound_addr = conn
                .source_addr()
                .cloned()
                .unwrap_or_else(|| packet.remote_addr.clone());
            let outbound_alternate_path = self.peers.get(&peer_node_addr).is_some_and(|peer| {
                peer.transport_id() != Some(outbound_transport_id)
                    || peer.current_addr() != Some(&outbound_addr)
            });

            if outbound_alternate_path {
                let outbound_remote_epoch = conn.remote_epoch();
                let remote_epoch_changed = self.peers.get(&peer_node_addr).is_some_and(|peer| {
                    matches!(
                        (peer.remote_epoch(), outbound_remote_epoch),
                        (Some(old), Some(new)) if old != new
                    )
                });
                let existing_path_unusable = self
                    .peers
                    .get(&peer_node_addr)
                    .is_some_and(|peer| !peer.is_healthy() || !peer.can_send())
                    || self.session_direct_path_blocks_direct_payload(
                        &peer_node_addr,
                        packet.timestamp_ms,
                    )
                    || self.session_direct_path_exclusive_trust_expired(
                        &peer_node_addr,
                        packet.timestamp_ms,
                    );
                let reply_transport_handoff = packet.transport_id != outbound_transport_id;
                if !remote_epoch_changed
                    && !existing_path_unusable
                    && !reply_transport_handoff
                    && !self.alternate_path_priority_allows_replace(
                        &peer_node_addr,
                        outbound_transport_id,
                        &outbound_addr,
                    )
                {
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
                    if let Some(transport) = self.transports.get(&outbound_transport_id) {
                        transport.close_connection(&outbound_addr).await;
                    }
                    if let Some(link) = self.remove_link(&link_id) {
                        self.cleanup_bootstrap_transport_if_unused(link.transport_id());
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
                        connected_at_ms: packet.timestamp_ms,
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
                self.log_active_peer_session_replacement_result(
                    &peer_node_addr,
                    &replacement,
                    "outbound_alternate_path_refresh",
                );
                if let Some(addr) = preferred_send_addr.clone()
                    && let Some(peer) = self.peers.get_mut(&peer_node_addr)
                {
                    peer.set_preferred_send_addr(addr);
                }
                self.sync_dataplane_fmp_owner(&peer_node_addr);

                self.seed_path_mtu_for_link_peer(
                    &peer_node_addr,
                    outbound_transport_id,
                    &outbound_addr,
                );
                self.links
                    .insert_addr((outbound_transport_id, outbound_addr.clone()), link_id);
                self.clear_session_direct_path_degraded_after_promotion(
                    &peer_node_addr,
                    packet.timestamp_ms,
                );
                self.clear_retry_unless_direct_refresh_needed(&peer_node_addr);
                self.register_identity(peer_node_addr, peer_identity.pubkey_full());
                self.sync_dataplane_fmp_owner(&peer_node_addr);

                if remote_epoch_changed {
                    self.remove_dataplane_fsp_owner(&peer_node_addr);
                    if self.sessions.remove(&peer_node_addr).is_some() {
                        debug!(
                            peer = %display_name,
                            "Cleared stale FSP session after peer restart during outbound path refresh"
                        );
                    }
                    info!(
                        peer = %display_name,
                        "Peer restart detected during outbound path refresh, replacing stale endpoint session"
                    );
                }

                self.pending_outbound.remove(&key);
                let loser_link_id = replacement.old_link_id;
                if let Some(loser_link) = self.links.get(&loser_link_id) {
                    let loser_tid = loser_link.transport_id();
                    let loser_addr = loser_link.remote_addr().clone();
                    if let Some(transport) = self.transports.get(&loser_tid) {
                        transport.close_connection(&loser_addr).await;
                    }
                }
                if let Some(loser_link) = self.remove_link(&loser_link_id) {
                    self.cleanup_bootstrap_transport_if_unused(loser_link.transport_id());
                }

                debug!(
                    peer = %display_name,
                    link_id = %link_id,
                    transport_id = %outbound_transport_id,
                    remote_addr = %outbound_addr,
                    "Promoted outbound alternate-path refresh"
                );

                if let Err(e) = self.send_tree_announce_to_peer(&peer_node_addr).await {
                    debug!(peer = %display_name, error = %e, "Failed to send TreeAnnounce after outbound path refresh");
                }
                self.bloom_state.mark_update_needed(peer_node_addr);
                self.reset_discovery_backoff();
                return;
            }

            if our_outbound_wins {
                // We're the smaller node. Swap to outbound session + indices.
                // The peer will keep their inbound session (complement of ours).
                let outbound_our_index = conn.our_index();
                let outbound_session = conn.take_session();
                let outbound_transport_id = conn.transport_id().unwrap_or(packet.transport_id);
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
                        connected_at_ms: packet.timestamp_ms,
                    },
                ) {
                    Some(replacement) => replacement,
                    None => {
                        warn!(peer = %self.peer_display_name(&peer_node_addr), "Active peer missing during outbound cross-connection swap");
                        self.pending_outbound.remove(&key);
                        return;
                    }
                };
                self.log_active_peer_session_replacement_result(
                    &peer_node_addr,
                    &replacement,
                    "outbound_cross_connection_swap",
                );
                if let Some(addr) = preferred_send_addr
                    && let Some(peer) = self.peers.get_mut(&peer_node_addr)
                {
                    peer.set_preferred_send_addr(addr);
                }
                self.sync_dataplane_fmp_owner(&peer_node_addr);
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
                if let Some(loser_link) = self.links.get(&loser_link_id) {
                    let loser_tid = loser_link.transport_id();
                    let loser_addr = loser_link.remote_addr().clone();
                    if let Some(transport) = self.transports.get(&loser_tid) {
                        transport.close_connection(&loser_addr).await;
                    }
                }
                if let Some(loser_link) = self.remove_link(&loser_link_id) {
                    self.cleanup_bootstrap_transport_if_unused(loser_link.transport_id());
                }
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
                // Close the losing TCP connection (no-op for connectionless)
                if let Some(link) = self.links.get(&link_id) {
                    let tid = link.transport_id();
                    let addr = link.remote_addr().clone();
                    if let Some(transport) = self.transports.get(&tid) {
                        transport.close_connection(&addr).await;
                    }
                }
                if let Some(link) = self.remove_link(&link_id) {
                    self.cleanup_bootstrap_transport_if_unused(link.transport_id());
                }
            }

            // Send TreeAnnounce now that sessions are aligned
            if let Err(e) = self.send_tree_announce_to_peer(&peer_node_addr).await {
                debug!(peer = %self.peer_display_name(&peer_node_addr), error = %e, "Failed to send TreeAnnounce after cross-connection resolution");
            }
            // Schedule filter announce (sent on next tick via debounce)
            self.bloom_state.mark_update_needed(peer_node_addr);
            self.reset_discovery_backoff();
            return;
        }

        // Normal path: promote to active peer
        match self.promote_connection(link_id, peer_identity, packet.timestamp_ms) {
            Ok(result) => {
                // Clean up pending_outbound
                self.pending_outbound.remove(&key);

                match result {
                    PromotionResult::Promoted(node_addr) => {
                        info!(
                            peer = %self.peer_display_name(&node_addr),
                            "Peer promoted to active"
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
                        // Ensure address dispatch points to the winner's link
                        self.links.insert_addr(
                            (packet.transport_id, packet.remote_addr.clone()),
                            winner_link_id,
                        );
                        debug!(
                            winner_link_id = %winner_link_id,
                            "Outbound cross-connection lost, keeping existing"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    link_id = %link_id,
                    error = %e,
                    "Failed to promote connection"
                );
            }
        }
    }
}
