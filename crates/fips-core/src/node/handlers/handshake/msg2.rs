use super::*;
use crate::node::ActivePeerCurrentSessionReplacement;

impl Node {
    async fn complete_outbound_handshake_bootstrap(&mut self, node_addr: &NodeAddr) {
        // TreeAnnounce may be paced after a reconnect. Confirm the new keys
        // before queued direct FSP traffic can use the replacement carrier.
        if let Err(error) = self
            .send_dataplane_fmp_link_plaintext(
                node_addr,
                &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
                false,
            )
            .await
        {
            debug!(peer = %self.peer_display_name(node_addr), %error, "Failed to send handshake confirmation");
        }
        self.complete_owned_msg2_bootstrap(node_addr).await;
    }

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
        if self.packet_predates_carrier_rebind(packet.transport_id, packet.timestamp_ms) {
            debug!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                packet_timestamp_ms = packet.timestamp_ms,
                "Dropping msg2 queued by a previous carrier incarnation"
            );
            return;
        }
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
                            self.reset_peer_routing_after_restart(&peer_node_addr);
                        }
                        if remote_epoch_changed
                            && self.clear_stale_fsp_unless_recovered_to_remote_epoch(
                                &peer_node_addr,
                                remote_epoch,
                                "FMP rekey",
                            )
                        {
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

        let (peer_identity, dial_transport_id, dial_addr) = {
            let conn = self.peers.get_connection_mut(&link_id).unwrap();
            // A completed exchange can wait for local admission. Its original
            // authenticated reply owns the keys, path and deadline; duplicates
            // must neither re-run Noise nor replace that retained response.
            if conn.is_complete() && conn.has_session() {
                return;
            }
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

            (peer_identity, dial_transport_id, dial_addr)
        };

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
                                candidate.is_configured()
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

        self.finish_completed_outbound_handshake(link_id, packet)
            .await;
    }
}

mod completion;
