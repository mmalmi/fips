impl Node {
    /// Handle an incoming SessionSetup (Noise XK msg1).
    ///
    /// The remote node wants to establish an end-to-end session with us.
    /// We create an XK responder handshake, process msg1, send SessionAck with msg2,
    /// and transition to AwaitingMsg3.
    async fn handle_session_setup(&mut self, src_addr: &NodeAddr, inner: &[u8]) {
        let setup = match SessionSetup::decode(inner) {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "Malformed SessionSetup");
                return;
            }
        };

        if setup.handshake_payload.len() != XK_HANDSHAKE_MSG1_SIZE {
            debug!(
                len = setup.handshake_payload.len(),
                expected = XK_HANDSHAKE_MSG1_SIZE,
                "Invalid handshake payload size in SessionSetup"
            );
            return;
        }
        self.coord_cache
            .insert(*src_addr, setup.src_coords.clone(), Self::now_ms());

        // Check for existing session with this remote
        if let Some(existing) = self.sessions.get(src_addr) {
            if existing.is_initiating() {
                // Simultaneous initiation: smaller NodeAddr wins as initiator
                if self.identity.node_addr() < src_addr {
                    // We win — drop their setup, they'll process ours
                    debug!(
                        src = %self.peer_display_name(src_addr),
                        "Simultaneous session initiation: we win (smaller addr), dropping their setup"
                    );
                    return;
                }
                // We lose — discard our pending handshake, become responder below
                debug!(
                    src = %self.peer_display_name(src_addr),
                    "Simultaneous session initiation: we lose, becoming responder"
                );
            } else if existing.is_awaiting_msg3() {
                // Duplicate setup while we already sent msg2 — resend stored ack
                if let Some(payload) = existing.handshake_payload() {
                    debug!(src = %self.peer_display_name(src_addr), "Duplicate SessionSetup, resending SessionAck");
                    let my_addr = *self.node_addr();
                    let mut datagram = SessionDatagram::new(my_addr, *src_addr, payload.to_vec())
                        .with_ttl(self.config.node.session.default_ttl);
                    if let Err(e) = self.send_session_datagram(&mut datagram).await {
                        debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to resend SessionAck");
                    }
                } else {
                    debug!(src = %self.peer_display_name(src_addr), "Duplicate SessionSetup, no stored ack to resend");
                }
                return;
            } else if existing.is_established() {
                // Rekey: if rekey enabled, treat as rekey for key rotation.
                // The existing established session remains active for traffic.
                if self.config.node.rekey.enabled {
                    let rekey_in_progress = existing.has_rekey_in_progress();
                    let has_pending = existing.pending_new_session().is_some();

                    // Dual-initiation detection: both sides sent SessionSetup
                    // simultaneously. Apply tie-breaker — smaller NodeAddr
                    // wins as initiator (same as initial session setup).
                    if rekey_in_progress {
                        if let Some(payload) = duplicate_rekey_responder_ack(existing) {
                            debug!(
                                src = %self.peer_display_name(src_addr),
                                "Duplicate FSP rekey msg1, resending SessionAck"
                            );
                            let my_addr = *self.node_addr();
                            let mut datagram = SessionDatagram::new(my_addr, *src_addr, payload)
                                .with_ttl(self.config.node.session.default_ttl);
                            let sent = match self.send_session_datagram(&mut datagram).await {
                                Ok(()) => true,
                                Err(e) => {
                                    debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to resend rekey SessionAck");
                                    false
                                }
                            };
                            if sent {
                                let now_ms = Self::now_ms();
                                let interval =
                                    self.config.node.rate_limit.handshake_resend_interval_ms;
                                self.sessions
                                    .record_handshake_resend(src_addr, now_ms + interval);
                            }
                            return;
                        }
                        if self.identity.node_addr() < src_addr {
                            // We win as initiator — drop their msg1.
                            debug!(
                                src = %self.peer_display_name(src_addr),
                                "Dual FSP rekey initiation: we win (smaller addr), dropping their msg1"
                            );
                            return;
                        }
                        // We lose — abandon our rekey, become responder below.
                        debug!(
                            src = %self.peer_display_name(src_addr),
                            "Dual FSP rekey initiation: we lose (larger addr), abandoning ours"
                        );
                        self.sessions.abandon_rekey(src_addr);
                    } else if has_pending {
                        if pending_rekey_wins_tiebreak(
                            self.identity.node_addr(),
                            src_addr,
                            existing,
                        ) {
                            debug!(
                                src = %self.peer_display_name(src_addr),
                                "FSP rekey msg1 received while local pending rekey wins tiebreak, dropping"
                            );
                            return;
                        }

                        debug!(
                            src = %self.peer_display_name(src_addr),
                            local_pending_initiator = existing.is_rekey_initiator(),
                            "FSP rekey msg1 received with stale pending rekey, abandoning pending and responding"
                        );
                        self.sessions.abandon_rekey(src_addr);
                    }
                    let our_keypair = self.identity.keypair();
                    let mut handshake = HandshakeState::new_xk_responder(our_keypair);
                    handshake.set_local_epoch(self.startup_epoch);

                    if let Err(e) = handshake.read_xk_message_1(&setup.handshake_payload) {
                        debug!(error = %e, "Failed to process rekey XK msg1");
                        return;
                    }

                    // Generate msg2
                    let msg2 = match handshake.write_xk_message_2() {
                        Ok(m) => m,
                        Err(e) => {
                            debug!(error = %e, "Failed to generate rekey XK msg2");
                            return;
                        }
                    };

                    // Build and send SessionAck
                    let our_coords = self.tree_state.my_coords().clone();
                    let ack = SessionAck::new(our_coords, setup.src_coords).with_handshake(msg2);
                    let ack_payload = ack.encode();
                    let my_addr = *self.node_addr();
                    let mut datagram =
                        SessionDatagram::new(my_addr, *src_addr, ack_payload.clone())
                            .with_ttl(self.config.node.session.default_ttl);

                    if let Err(e) = self.send_session_datagram(&mut datagram).await {
                        debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to send rekey SessionAck");
                        return;
                    }

                    // Store rekey state on the existing entry
                    let now_ms = Self::now_ms();
                    let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
                    self.sessions.install_rekey_responder_awaiting_msg3(
                        src_addr,
                        handshake,
                        ack_payload,
                        now_ms,
                        resend_interval,
                    );

                    debug!(
                        src = %self.peer_display_name(src_addr),
                        "FSP rekey: processed peer's msg1, sent msg2, awaiting msg3"
                    );
                    return;
                }

                // Re-establishment: replace existing session below
                debug!(src = %self.peer_display_name(src_addr), "Session re-establishment from peer");
            }
        }

        // Create XK responder handshake and process msg1
        let our_keypair = self.identity.keypair();
        let mut handshake = HandshakeState::new_xk_responder(our_keypair);
        handshake.set_local_epoch(self.startup_epoch);

        if let Err(e) = handshake.read_xk_message_1(&setup.handshake_payload) {
            debug!(error = %e, "Failed to process Noise XK msg1 in SessionSetup");
            return;
        }

        // XK: responder does NOT learn initiator's identity until msg3
        // Use a placeholder pubkey from src_addr for the session entry.
        // The real pubkey will be registered when msg3 arrives.

        // Generate msg2
        let msg2 = match handshake.write_xk_message_2() {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Failed to generate Noise XK msg2 for SessionAck");
                return;
            }
        };

        // Build and send SessionAck (include initiator's coords for return-path warming)
        let our_coords = self.tree_state.my_coords().clone();
        let ack = SessionAck::new(our_coords, setup.src_coords).with_handshake(msg2);
        let ack_payload = ack.encode();
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *src_addr, ack_payload.clone())
            .with_ttl(self.config.node.session.default_ttl);

        // Route the ack back to the initiator
        if let Err(e) = self.send_session_datagram(&mut datagram).await {
            debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to send SessionAck");
            return;
        }

        // Store session entry in AwaitingMsg3 state with ack payload for potential resend.
        // Use a dummy pubkey since we don't know the initiator's identity yet.
        // We use our own pubkey as placeholder; it will be replaced in handle_session_msg3.
        let placeholder_pubkey = self.identity.keypair().public_key();
        let now_ms = Self::now_ms();
        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        self.sessions.install_awaiting_msg3_session(
            *src_addr,
            placeholder_pubkey,
            handshake,
            ack_payload,
            now_ms,
            resend_interval,
        );

        debug!(src = %self.peer_display_name(src_addr), "SessionSetup processed (XK), SessionAck sent, awaiting msg3");
    }

    /// Handle an incoming SessionAck (Noise XK msg2).
    ///
    /// Processes msg2, generates and sends msg3, then transitions to Established.
    async fn handle_session_ack(&mut self, src_addr: &NodeAddr, inner: &[u8]) {
        let ack = match SessionAck::decode(inner) {
            Ok(a) => a,
            Err(e) => {
                debug!(error = %e, "Malformed SessionAck");
                return;
            }
        };

        if ack.handshake_payload.len() != XK_HANDSHAKE_MSG2_SIZE {
            debug!(
                len = ack.handshake_payload.len(),
                expected = XK_HANDSHAKE_MSG2_SIZE,
                "Invalid handshake payload size in SessionAck"
            );
            return;
        }
        self.coord_cache
            .insert(*src_addr, ack.src_coords.clone(), Self::now_ms());

        // Remove the entry to take ownership of the handshake state
        let mut entry = match self.sessions.remove(src_addr) {
            Some(e) => e,
            None => {
                debug!(src = %self.peer_display_name(src_addr), "SessionAck for unknown session");
                return;
            }
        };

        // Rekey path: entry is Established with rekey_state
        if entry.is_established() && entry.has_rekey_in_progress() && entry.is_rekey_initiator() {
            let mut handshake = match entry.take_rekey_state() {
                Some(hs) => hs,
                None => {
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            // Process XK msg2
            if let Err(e) = handshake.read_xk_message_2(&ack.handshake_payload) {
                debug!(error = %e, "Failed to process rekey XK msg2");
                entry.abandon_rekey();
                self.sessions.insert(*src_addr, entry);
                return;
            }

            // Generate XK msg3
            let msg3 = match handshake.write_xk_message_3() {
                Ok(m) => m,
                Err(e) => {
                    debug!(error = %e, "Failed to generate rekey XK msg3");
                    entry.abandon_rekey();
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            // Send SessionMsg3
            let msg3_wire = SessionMsg3::new(msg3);
            let msg3_payload = msg3_wire.encode();
            let msg3_resend_payload = msg3_payload.clone();
            let my_addr = *self.node_addr();
            let mut datagram = SessionDatagram::new(my_addr, *src_addr, msg3_payload)
                .with_ttl(self.config.node.session.default_ttl);

            if let Err(e) = self.send_session_datagram(&mut datagram).await {
                debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to send rekey SessionMsg3");
                entry.abandon_rekey();
                self.sessions.insert(*src_addr, entry);
                return;
            }

            // Complete handshake → store as pending new session
            let session = match handshake.into_session() {
                Ok(s) => s,
                Err(e) => {
                    debug!(error = %e, "Failed to create session from rekey XK");
                    entry.abandon_rekey();
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            let now_ms = Self::now_ms();
            let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
            let pending_receive =
                session
                    .recv_cipher_clone()
                    .map(|open| (!entry.current_k_bit(), open));
            self.sessions.install_rekey_initiator_pending_session(
                *src_addr,
                entry,
                session,
                msg3_resend_payload,
                now_ms,
                resend_interval,
            );
            if let Some((pending_k_bit, open)) = pending_receive {
                self.install_dataplane_fsp_pending_receive_epoch(src_addr, pending_k_bit, open);
            }
            self.refresh_dataplane_fsp_owner_routes(src_addr);

            debug!(
                src = %self.peer_display_name(src_addr),
                "FSP rekey: completed XK as initiator, pending cutover"
            );
            return;
        }

        if entry.is_established() {
            if let Some(payload) = entry.handshake_payload().map(<[u8]>::to_vec) {
                if entry.resend_count() < self.config.node.rate_limit.handshake_max_resends {
                    let my_addr = *self.node_addr();
                    let mut datagram = SessionDatagram::new(my_addr, *src_addr, payload)
                        .with_ttl(self.config.node.session.default_ttl);
                    let sent = match self.send_session_datagram(&mut datagram).await {
                        Ok(()) => true,
                        Err(e) => {
                            debug!(
                                src = %self.peer_display_name(src_addr),
                                error = %e,
                                "Failed to resend final SessionMsg3 after duplicate SessionAck"
                            );
                            false
                        }
                    };
                    if sent {
                        let now_ms = Self::now_ms();
                        let interval = self.config.node.rate_limit.handshake_resend_interval_ms;
                        entry.record_resend(now_ms + interval);
                        debug!(
                            src = %self.peer_display_name(src_addr),
                            "Duplicate SessionAck after establishment, resent final SessionMsg3"
                        );
                    }
                } else {
                    entry.clear_handshake_payload();
                }
            } else {
                debug!(src = %self.peer_display_name(src_addr), "SessionAck for already-established session");
            }
            self.sessions.insert(*src_addr, entry);
            return;
        }

        // Must be in Initiating state — check before take to avoid poisoning
        if !entry.is_initiating() {
            debug!(src = %self.peer_display_name(src_addr), "SessionAck but session not in Initiating state");
            self.sessions.insert(*src_addr, entry);
            return;
        }
        let mut handshake = match entry.take_state() {
            Some(EndToEndState::Initiating(hs)) => hs,
            _ => unreachable!("checked is_initiating above"),
        };

        // Process XK msg2: read_xk_message_2 (extracts responder's epoch)
        if let Err(e) = handshake.read_xk_message_2(&ack.handshake_payload) {
            debug!(error = %e, "Failed to process Noise XK msg2 in SessionAck");
            return; // Entry was already removed, don't put back a broken session
        }

        // Generate XK msg3: write_xk_message_3 (sends encrypted static + epoch)
        let msg3 = match handshake.write_xk_message_3() {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Failed to generate Noise XK msg3");
                return;
            }
        };

        // Send SessionMsg3 (phase 0x3)
        let msg3_wire = SessionMsg3::new(msg3);
        let msg3_payload = msg3_wire.encode();
        let msg3_resend_payload = msg3_payload.clone();
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *src_addr, msg3_payload)
            .with_ttl(self.config.node.session.default_ttl);

        if let Err(e) = self.send_session_datagram(&mut datagram).await {
            debug!(error = %e, dest = %self.peer_display_name(src_addr), "Failed to send SessionMsg3");
            return;
        }

        // Complete the handshake: into_session()
        let session = match handshake.into_session() {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "Failed to create session after XK msg3");
                return;
            }
        };

        let now_ms = Self::now_ms();
        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        entry.establish(session, now_ms);
        entry.set_handshake_payload(msg3_resend_payload, now_ms + resend_interval);
        self.sessions.insert(*src_addr, entry);
        self.pending_lookups.remove(src_addr);
        self.discovery_backoff.record_success(src_addr);
        self.sync_dataplane_fsp_owner_from_current_session(
            src_addr,
            self.config.node.session.coords_warmup_packets,
        );

        // Flush any queued outbound packets for this destination
        self.flush_pending_packets(src_addr).await;

        info!(src = %self.peer_display_name(src_addr), "Session established (initiator, XK)");
    }

    /// Handle an incoming SessionMsg3 (Noise XK msg3).
    ///
    /// The initiator reveals their encrypted static key. The responder
    /// processes msg3, learns the initiator's identity, and transitions
    /// to Established.
    async fn handle_session_msg3(&mut self, src_addr: &NodeAddr, inner: &[u8]) {
        let msg3 = match SessionMsg3::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed SessionMsg3");
                return;
            }
        };

        if msg3.handshake_payload.len() != XK_HANDSHAKE_MSG3_SIZE {
            debug!(
                len = msg3.handshake_payload.len(),
                expected = XK_HANDSHAKE_MSG3_SIZE,
                "Invalid handshake payload size in SessionMsg3"
            );
            return;
        }

        // Remove the entry to take ownership of the handshake state
        let mut entry = match self.sessions.remove(src_addr) {
            Some(e) => e,
            None => {
                debug!(src = %self.peer_display_name(src_addr), "SessionMsg3 for unknown session");
                return;
            }
        };

        // Rekey path: entry is Established with rekey_state (responder side)
        if entry.is_established() && entry.has_rekey_in_progress() && !entry.is_rekey_initiator() {
            let mut handshake = match entry.take_rekey_state() {
                Some(hs) => hs,
                None => {
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            // Process XK msg3
            if let Err(e) = handshake.read_xk_message_3(&msg3.handshake_payload) {
                debug!(error = %e, "Failed to process rekey XK msg3");
                entry.abandon_rekey();
                self.sessions.insert(*src_addr, entry);
                return;
            }

            // Complete the handshake → store as pending new session
            let session = match handshake.into_session() {
                Ok(s) => s,
                Err(e) => {
                    debug!(error = %e, "Failed to create session from rekey XK msg3");
                    entry.abandon_rekey();
                    self.sessions.insert(*src_addr, entry);
                    return;
                }
            };

            let pending_receive =
                session
                    .recv_cipher_clone()
                    .map(|open| (!entry.current_k_bit(), open));
            self.sessions
                .install_rekey_responder_pending_session(*src_addr, entry, session);
            if let Some((pending_k_bit, open)) = pending_receive {
                self.install_dataplane_fsp_pending_receive_epoch(src_addr, pending_k_bit, open);
            }
            self.refresh_dataplane_fsp_owner_routes(src_addr);

            debug!(
                src = %self.peer_display_name(src_addr),
                "FSP rekey: completed XK as responder, pending cutover"
            );
            return;
        }

        // Must be in AwaitingMsg3 state
        if !entry.is_awaiting_msg3() {
            debug!(src = %self.peer_display_name(src_addr), "SessionMsg3 but session not in AwaitingMsg3 state");
            self.sessions.insert(*src_addr, entry);
            return;
        }
        let mut handshake = match entry.take_state() {
            Some(EndToEndState::AwaitingMsg3(hs)) => hs,
            _ => unreachable!("checked is_awaiting_msg3 above"),
        };

        // Process XK msg3: read_xk_message_3 (extracts initiator's static key and epoch)
        if let Err(e) = handshake.read_xk_message_3(&msg3.handshake_payload) {
            debug!(error = %e, "Failed to process Noise XK msg3");
            return; // Entry was already removed
        }

        // Extract the initiator's static public key (now available after msg3)
        let remote_pubkey = match handshake.remote_static() {
            Some(pk) => *pk,
            None => {
                debug!("No remote static key after processing XK msg3");
                return;
            }
        };

        // Register the initiator's identity for future TUN → session routing
        self.register_identity(*src_addr, remote_pubkey);

        // Complete the handshake
        let session = match handshake.into_session() {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "Failed to create session from XK handshake");
                return;
            }
        };

        let now_ms = Self::now_ms();
        // Replace the placeholder pubkey with the real one
        let entry = SessionEntry::new_established(
            *src_addr,
            remote_pubkey,
            session,
            now_ms,
            false,
        );
        self.sessions.insert(*src_addr, entry);
        self.pending_lookups.remove(src_addr);
        self.discovery_backoff.record_success(src_addr);
        self.sync_dataplane_fsp_owner_from_current_session(
            src_addr,
            self.config.node.session.coords_warmup_packets,
        );

        // Flush any pending packets
        self.flush_pending_packets(src_addr).await;

        info!(src = %self.peer_display_name(src_addr), "Session established (responder, XK)");
    }

}
