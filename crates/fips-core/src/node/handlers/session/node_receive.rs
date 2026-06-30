impl Node {
    fn apply_authenticated_fsp_receive_sync(
        &mut self,
        source_addr: NodeAddr,
        sync: crate::node::session::FspReceiveSync,
        now: Instant,
    ) -> bool {
        let apply = {
            let Some(entry) = self.sessions.get_mut(&source_addr) else {
                return false;
            };
            entry.apply_fsp_receive_sync_result(sync, Self::now_ms(), now)
        };
        if apply.refresh_packet_mover2_owner() {
            self.sync_packet_mover2_fsp_owner(&source_addr);
        }
        apply.is_applied()
    }

    /// Handle a locally-delivered session datagram payload.
    ///
    /// Called from `handle_session_datagram()` when `dest_addr == self.node_addr()`.
    /// Dispatches based on the 4-byte FSP common prefix:
    ///
    /// - Phase 0x1 → SessionSetup (handshake msg1)
    /// - Phase 0x2 → SessionAck (handshake msg2)
    /// - Phase 0x3 → SessionMsg3 (XK handshake msg3)
    /// - Phase 0x0 + U flag → plaintext error signal (CoordsRequired/PathBroken)
    /// - Phase 0x0 + !U → packet_mover2 authenticated receive only
    pub(in crate::node) async fn handle_session_payload(
        &mut self,
        delivery: LocalSessionPayload<'_>,
    ) {
        let src_addr = *delivery.source_addr();
        let payload = delivery.payload();
        let prefix = match FspCommonPrefix::parse(payload) {
            Some(p) => p,
            None => {
                debug!(
                    len = payload.len(),
                    "Session payload too short for FSP prefix"
                );
                return;
            }
        };

        let inner = &payload[FSP_COMMON_PREFIX_SIZE..];

        match prefix.phase {
            FSP_PHASE_MSG1 => {
                self.handle_session_setup(&src_addr, inner).await;
            }
            FSP_PHASE_MSG2 => {
                self.handle_session_ack(&src_addr, inner).await;
            }
            FSP_PHASE_MSG3 => {
                self.handle_session_msg3(&src_addr, inner).await;
            }
            FSP_PHASE_ESTABLISHED if prefix.is_unencrypted() => {
                // Plaintext error signals: read msg_type from first byte after prefix
                if inner.is_empty() {
                    debug!("Empty plaintext error signal");
                    return;
                }
                let error_type = inner[0];
                let error_body = &inner[1..];
                match SessionMessageType::from_byte(error_type) {
                    Some(SessionMessageType::CoordsRequired) => {
                        self.handle_coords_required(error_body).await;
                    }
                    Some(SessionMessageType::PathBroken) => {
                        self.handle_path_broken(error_body).await;
                    }
                    Some(SessionMessageType::MtuExceeded) => {
                        self.handle_mtu_exceeded(error_body).await;
                    }
                    _ => {
                        debug!(error_type, "Unknown plaintext error signal type");
                    }
                }
            }
            FSP_PHASE_ESTABLISHED => {
                debug!(
                    src = %self.peer_display_name(&src_addr),
                    "Dropping established FSP payload outside packet_mover2 receive path"
                );
                return;
            }
            _ => {
                debug!(phase = prefix.phase, "Unknown FSP phase");
            }
        }
    }

    pub(in crate::node) async fn process_packet_mover2_authenticated_session(
        &mut self,
        ingress: crate::packet_mover2::PacketMover2FspSessionIngress,
    ) -> bool {
        let (
            source_addr,
            previous_hop_addr,
            ce_flag,
            receive_sync,
            timestamp_ms,
            msg_type,
            inner_flags,
            plaintext,
        ) = ingress.into_parts();
        let now = Instant::now();
        let receive_applied =
            self.apply_authenticated_fsp_receive_sync(source_addr, receive_sync, now);
        if !receive_applied {
            debug!(
                src = %self.peer_display_name(&source_addr),
                "Dropping packet-mover2 authenticated session message for missing or stale session"
            );
            return false;
        }
        let Some(source_peer) = self.packet_mover2_session_source_peer(&source_addr) else {
            debug!(
                src = %self.peer_display_name(&source_addr),
                "Dropping packet-mover2 authenticated session message for unknown source identity"
            );
            return false;
        };

        let body_len = plaintext
            .len()
            .saturating_sub(crate::node::session_wire::FSP_INNER_HEADER_SIZE);
        debug!(
            src = %self.peer_display_name(&source_addr),
            previous_hop = %self.peer_display_name(&previous_hop_addr),
            msg_type,
            msg_kind = ?SessionMessageType::from_byte(msg_type),
            plaintext_len = plaintext.len(),
            body_len,
            endpoint_data = msg_type == SessionMessageType::EndpointData.to_byte(),
            "Dispatching packet mover2 authenticated session"
        );

        let message =
            AuthenticatedSessionMessage::new(source_peer, plaintext, msg_type, inner_flags, timestamp_ms);
        let dispatch =
            AuthenticatedSessionDispatch::new(source_addr, previous_hop_addr, ce_flag, message);
        if dispatch.is_endpoint_data() {
            let finish = dispatch.dispatch_endpoint_data_fast(self);
            if let Some(dest_addr) = finish.pending_flush_dest() {
                self.flush_pending_packets(&dest_addr).await;
            }
            return true;
        }
        dispatch.dispatch(self).await;
        true
    }

    fn packet_mover2_session_source_peer(&self, source_addr: &NodeAddr) -> Option<PeerIdentity> {
        if let Some(identity) = self
            .sessions
            .get(source_addr)
            .and_then(|entry| entry.remote_identity())
        {
            return Some(identity);
        }
        if let Some(identity) = self.peers.get(source_addr).map(|peer| *peer.identity()) {
            return Some(identity);
        }
        self.identity_cache
            .iter()
            .find_map(|(addr, pubkey, _)| {
                (addr == source_addr).then(|| PeerIdentity::from_pubkey_full(*pubkey))
            })
    }

    pub(in crate::node) fn record_authenticated_fmp_receive_facts(
        &mut self,
        fmp: crate::node::AuthenticatedFmpReceiveFacts<'_>,
        previous_hop: Option<&NodeAddr>,
    ) {
        let now = Instant::now();
        let source_addr = fmp.source_node_addr();
        let arrived_from_source = previous_hop.is_none_or(|hop| hop == source_addr);
        let path_bookkeeping_allowed = self.authenticated_packet_path_allows_bookkeeping(
            source_addr,
            fmp.transport_id,
            fmp.remote_addr,
            fmp.packet_timestamp_ms,
        ) && arrived_from_source;
        let bookkeeping = self.peers.record_authenticated_fmp_receive(
            source_addr,
            fmp.transport_id,
            &fmp.remote_addr,
            fmp.packet_timestamp_ms,
            fmp.packet_len,
            fmp.fmp_counter,
            fmp.inner_timestamp_ms,
            fmp.fmp_flags & FLAG_CE != 0,
            fmp.fmp_flags & FLAG_SP != 0,
            now,
            path_bookkeeping_allowed,
        );
        if let Some(update) = bookkeeping {
            if update.path_bookkeeping_recorded {
                self.clear_retry_unless_direct_refresh_needed(source_addr);
            }
            if update.address_changed {
                self.sync_packet_mover2_fmp_owner(source_addr);
            }
        }
    }

    pub(in crate::node) async fn handle_packet_mover2_fsp_decrypt_failure(
        &mut self,
        source_addr: NodeAddr,
        counter: u64,
        received_k_bit: bool,
    ) -> bool {
        self.handle_reported_fsp_decrypt_failure(
            source_addr,
            counter,
            received_k_bit,
            "packet_mover2",
        )
        .await
    }

    async fn handle_reported_fsp_decrypt_failure(
        &mut self,
        src_addr: NodeAddr,
        counter: u64,
        received_k_bit: bool,
        source: &'static str,
    ) -> bool {
        let Some(entry) = self.sessions.get_mut(&src_addr) else {
            debug!(
                src = %self.peer_display_name(&src_addr),
                counter,
                source,
                "FSP AEAD failure for unknown session"
            );
            return false;
        };
        if should_ignore_stale_epoch_drain_failure(entry, received_k_bit) {
            trace!(
                src = %self.peer_display_name(&src_addr),
                counter,
                source,
                "Ignoring FSP AEAD failure from stale previous key epoch during drain"
            );
            return true;
        }
        let consecutive = entry.record_decrypt_failure();
        let recover_session = should_start_decrypt_failure_rekey(entry, consecutive, Self::now_ms());
        debug!(
            src = %self.peer_display_name(&src_addr),
            counter,
            consecutive_failures = consecutive,
            source,
            "FSP AEAD decryption failed"
        );
        if recover_session {
            warn!(
                peer = %self.peer_display_name(&src_addr),
                consecutive_failures = consecutive,
                "Session AEAD failures exceeded threshold; starting recovery rekey"
            );
            if !self.initiate_session_rekey(&src_addr).await {
                debug!(
                    peer = %self.peer_display_name(&src_addr),
                    source,
                    "Failed to start recovery rekey after FSP decrypt-failure threshold"
                );
            }
        }
        true
    }

    async fn handle_mesh_traversal_offer(&mut self, src_addr: &NodeAddr, body: &[u8]) {
        let Some(bootstrap) = self.nostr_discovery.clone() else {
            trace!(
                src = %self.peer_display_name(src_addr),
                "Ignoring mesh traversal offer without Nostr discovery runtime"
            );
            return;
        };
        if self.configured_peer(src_addr).is_none() {
            debug!(
                src = %self.peer_display_name(src_addr),
                "Ignoring mesh traversal offer from unconfigured peer"
            );
            return;
        }
        let Some(sender_npub) = self.npub_for_node_addr(src_addr) else {
            debug!(
                src = %self.peer_display_name(src_addr),
                "Ignoring mesh traversal offer without known sender npub"
            );
            return;
        };
        let offer = match serde_json::from_slice::<TraversalOffer>(body) {
            Ok(offer) => offer,
            Err(error) => {
                debug!(
                    src = %self.peer_display_name(src_addr),
                    error = %error,
                    "Malformed mesh traversal offer"
                );
                return;
            }
        };
        if offer.sender_npub != sender_npub {
            debug!(
                src = %self.peer_display_name(src_addr),
                claimed = %offer.sender_npub,
                actual = %sender_npub,
                "Ignoring mesh traversal offer with sender mismatch"
            );
            return;
        }
        bootstrap
            .receive_mesh_traversal_offer(offer, sender_npub)
            .await;
    }

    async fn handle_mesh_traversal_answer(&mut self, src_addr: &NodeAddr, body: &[u8]) {
        let Some(bootstrap) = self.nostr_discovery.clone() else {
            trace!(
                src = %self.peer_display_name(src_addr),
                "Ignoring mesh traversal answer without Nostr discovery runtime"
            );
            return;
        };
        if self.configured_peer(src_addr).is_none() {
            debug!(
                src = %self.peer_display_name(src_addr),
                "Ignoring mesh traversal answer from unconfigured peer"
            );
            return;
        }
        let Some(sender_npub) = self.npub_for_node_addr(src_addr) else {
            debug!(
                src = %self.peer_display_name(src_addr),
                "Ignoring mesh traversal answer without known sender npub"
            );
            return;
        };
        let answer = match serde_json::from_slice::<TraversalAnswer>(body) {
            Ok(answer) => answer,
            Err(error) => {
                debug!(
                    src = %self.peer_display_name(src_addr),
                    error = %error,
                    "Malformed mesh traversal answer"
                );
                return;
            }
        };
        if answer.sender_npub != sender_npub {
            debug!(
                src = %self.peer_display_name(src_addr),
                claimed = %answer.sender_npub,
                actual = %sender_npub,
                "Ignoring mesh traversal answer with sender mismatch"
            );
            return;
        }
        bootstrap
            .receive_mesh_traversal_answer(answer, sender_npub)
            .await;
    }

}
