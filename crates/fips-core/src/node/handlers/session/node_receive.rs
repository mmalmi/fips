impl Node {
    /// Handle a locally-delivered session datagram payload.
    ///
    /// Called from `handle_session_datagram()` when `dest_addr == self.node_addr()`.
    /// Dispatches based on the 4-byte FSP common prefix:
    ///
    /// - Phase 0x1 → SessionSetup (handshake msg1)
    /// - Phase 0x2 → SessionAck (handshake msg2)
    /// - Phase 0x3 → SessionMsg3 (XK handshake msg3)
    /// - Phase 0x0 + U flag → plaintext error signal (CoordsRequired/PathBroken)
    /// - Phase 0x0 + !U → dataplane authenticated receive only
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
                    "Dropping established FSP payload outside dataplane receive path"
                );
            }
            _ => {
                debug!(phase = prefix.phase, "Unknown FSP phase");
            }
        }
    }

    pub(in crate::node) async fn process_dataplane_authenticated_sessions(
        &mut self,
        ingress_batch: &mut Vec<crate::dataplane::DataplaneFspSessionIngress>,
    ) -> usize {
        let mut processed = 0usize;
        let mut endpoint_deliveries = Vec::new();
        let mut endpoint_commit = SessionReceiveBatchCommit::default();
        let mut service_deliveries = Vec::new();
        let mut service_commit = SessionReceiveBatchCommit::default();
        let mut tun_packets = Vec::new();
        let mut tun_commit = SessionReceiveBatchCommit::default();

        for ingress in ingress_batch.drain(..) {
            let Some(dispatch) = self.dataplane_authenticated_session_dispatch(ingress) else {
                continue;
            };

            if dispatch.is_endpoint_data() {
                self.flush_dataplane_tun_session_batch(&mut tun_packets, &mut tun_commit)
                    .await;
                self.flush_dataplane_service_session_batch(
                    &mut service_deliveries,
                    &mut service_commit,
                )
                .await;
                let deliveries =
                    dispatch.dispatch_endpoint_data_batched(self, &mut endpoint_commit);
                processed = processed.saturating_add(deliveries.len());
                endpoint_deliveries.extend(deliveries);
                continue;
            }

            if dispatch.is_ipv6_shim_data_packet() {
                self.flush_dataplane_endpoint_session_batch(
                    &mut endpoint_deliveries,
                    &mut endpoint_commit,
                )
                .await;
                self.flush_dataplane_service_session_batch(
                    &mut service_deliveries,
                    &mut service_commit,
                )
                .await;
                dispatch.dispatch_ipv6_shim_batched(self, &mut tun_packets, &mut tun_commit);
                processed = processed.saturating_add(1);
                continue;
            }

            if dispatch.is_service_data_packet() {
                self.flush_dataplane_endpoint_session_batch(
                    &mut endpoint_deliveries,
                    &mut endpoint_commit,
                )
                .await;
                self.flush_dataplane_tun_session_batch(&mut tun_packets, &mut tun_commit)
                    .await;
                if let Some(delivery) =
                    dispatch.dispatch_service_datagram_batched(self, &mut service_commit)
                {
                    service_deliveries.push(delivery);
                }
                processed = processed.saturating_add(1);
                continue;
            }

            self.flush_dataplane_endpoint_session_batch(
                &mut endpoint_deliveries,
                &mut endpoint_commit,
            )
            .await;
            self.flush_dataplane_tun_session_batch(&mut tun_packets, &mut tun_commit)
                .await;
            self.flush_dataplane_service_session_batch(
                &mut service_deliveries,
                &mut service_commit,
            )
            .await;
            dispatch.dispatch(self).await;
            processed = processed.saturating_add(1);
        }

        self.flush_dataplane_endpoint_session_batch(&mut endpoint_deliveries, &mut endpoint_commit)
            .await;
        self.flush_dataplane_tun_session_batch(&mut tun_packets, &mut tun_commit)
            .await;
        self.flush_dataplane_service_session_batch(
            &mut service_deliveries,
            &mut service_commit,
        )
        .await;
        processed
    }

    pub(in crate::node) async fn process_dataplane_authenticated_ingress(
        &mut self,
        ingress_batch: crate::dataplane::DataplaneFspAuthenticatedIngress,
    ) -> usize {
        let mut processed = 0usize;
        let mut endpoint_batches = Vec::new();
        let mut endpoint_message_count = 0usize;
        let mut session_ingress = Vec::new();
        let (runs, endpoint_data_batches, sessions) = ingress_batch.into_parts();
        let mut endpoint_data_batches = endpoint_data_batches.into_iter();
        let mut sessions = sessions.into_iter();

        for run in runs {
            match run {
                crate::dataplane::DataplaneFspAuthenticatedIngressRun::EndpointDataBatch => {
                    processed = processed.saturating_add(
                        self.process_dataplane_authenticated_sessions(&mut session_ingress)
                        .await,
                    );
                    let endpoint_batch = endpoint_data_batches
                        .next()
                        .expect("endpoint-data run has a batch");
                    endpoint_message_count =
                        endpoint_message_count.saturating_add(endpoint_batch.len());
                    endpoint_batches.push(endpoint_batch);
                }
                crate::dataplane::DataplaneFspAuthenticatedIngressRun::Sessions { count } => {
                    processed = processed.saturating_add(
                        self.process_dataplane_compact_endpoint_data(
                            &mut endpoint_batches,
                            &mut endpoint_message_count,
                        )
                        .await,
                    );
                    for _ in 0..count {
                        session_ingress
                            .push(sessions.next().expect("session run has session ingress"));
                    }
                }
            }
        }
        debug_assert!(
            endpoint_data_batches.next().is_none(),
            "authenticated ingress runs consumed all endpoint-data batches"
        );
        debug_assert!(
            sessions.next().is_none(),
            "authenticated ingress runs consumed all session ingress"
        );

        processed = processed.saturating_add(
            self.process_dataplane_compact_endpoint_data(
                &mut endpoint_batches,
                &mut endpoint_message_count,
            )
            .await,
        );
        processed = processed.saturating_add(
            self.process_dataplane_authenticated_sessions(&mut session_ingress)
                .await,
        );
        processed
    }

    pub(in crate::node) async fn process_dataplane_compact_endpoint_data(
        &mut self,
        endpoint_batches: &mut Vec<crate::dataplane::DataplaneEndpointDataBatch>,
        message_count: &mut usize,
    ) -> usize {
        let message_count = std::mem::take(message_count);
        if endpoint_batches.is_empty() {
            debug_assert_eq!(
                message_count, 0,
                "empty compact endpoint-data batch should not carry messages"
            );
            return 0;
        }
        debug_assert_eq!(
            message_count,
            endpoint_batches
                .iter()
                .map(crate::dataplane::DataplaneEndpointDataBatch::len)
                .sum::<usize>(),
            "compact endpoint-data message count must match carried batches"
        );

        let mut endpoint_commit = SessionReceiveBatchCommit::default();
        for batch in endpoint_batches.iter() {
            for run in batch.commit_runs() {
                let commit = run.commit();
                let source_addr = commit.source_addr();
                let previous_hop_addr = commit.previous_hop_addr();
                if self.promote_dataplane_authenticated_pending_fsp_epoch(
                    &source_addr,
                    commit.received_k_bit(),
                ) {
                    debug!(
                        src = %self.peer_display_name(&source_addr),
                        received_k_bit = commit.received_k_bit(),
                        run_len = run.len(),
                        "FSP rekey cutover complete after dataplane compact endpoint-data receive commit"
                    );
                }
                self.learn_reverse_route(source_addr, previous_hop_addr);
                endpoint_commit.push_receive_completion(SessionReceiveCompletion {
                    source_addr,
                    previous_hop_addr,
                    direct_path: commit.direct_path(),
                });
            }
        }

        let pending_flush_destinations = endpoint_commit.finish(self);
        for dest_addr in pending_flush_destinations {
            self.flush_pending_packets(&dest_addr).await;
        }
        endpoint_batches.clear();
        message_count
    }

    async fn flush_dataplane_tun_session_batch(
        &mut self,
        packets: &mut Vec<crate::transport::PacketBuffer>,
        commit: &mut SessionReceiveBatchCommit,
    ) {
        if packets.is_empty() && commit.is_empty() {
            return;
        }

        if let Some(tun_tx) = &self.tun_tx {
            if !packets.is_empty() {
                let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::TunWrite);
                let dropped = tun_tx.send_batch(packets.drain(..));
                if dropped != 0 {
                    debug!(
                        dropped,
                        "Failed to deliver decompressed IPv6 packet batch to TUN"
                    );
                }
            }
        } else {
            packets.clear();
        }

        let pending_flush_destinations = std::mem::take(commit).finish(self);
        for dest_addr in pending_flush_destinations {
            self.flush_pending_packets(&dest_addr).await;
        }
    }

    fn dataplane_authenticated_session_dispatch(
        &mut self,
        ingress: crate::dataplane::DataplaneFspSessionIngress,
    ) -> Option<AuthenticatedSessionDispatch> {
        let received_k_bit = ingress.received_k_bit();
        let (
            source_addr,
            source_peer,
            previous_hop_addr,
            ce_flag,
            _activity_tick,
            _timestamp_ms,
            msg_type,
            _inner_flags,
            plaintext,
        ) = ingress.into_parts();
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
            "Dispatching dataplane authenticated session"
        );

        if self.promote_dataplane_authenticated_pending_fsp_epoch(
            &source_addr,
            received_k_bit,
        ) {
            debug!(
                src = %self.peer_display_name(&source_addr),
                received_k_bit,
                "FSP rekey cutover complete after dataplane authenticated pending epoch"
            );
        }

        let message = AuthenticatedSessionMessage::new(source_peer, plaintext, msg_type);
        Some(AuthenticatedSessionDispatch::new(
            source_addr,
            previous_hop_addr,
            ce_flag,
            message,
        ))
    }

    async fn flush_dataplane_endpoint_session_batch(
        &mut self,
        endpoint_deliveries: &mut Vec<EndpointDataDelivery>,
        endpoint_commit: &mut SessionReceiveBatchCommit,
    ) {
        if endpoint_deliveries.is_empty() && endpoint_commit.is_empty() {
            return;
        }

        let pending_flush_destinations = std::mem::take(endpoint_commit).finish(self);
        if !endpoint_deliveries.is_empty() {
            self.deliver_endpoint_data_batch(std::mem::take(endpoint_deliveries));
        }
        for dest_addr in pending_flush_destinations {
            self.flush_pending_packets(&dest_addr).await;
        }
    }

    async fn flush_dataplane_service_session_batch(
        &mut self,
        deliveries: &mut Vec<EndpointServiceDatagramDelivery>,
        commit: &mut SessionReceiveBatchCommit,
    ) {
        if deliveries.is_empty() && commit.is_empty() {
            return;
        }

        let pending_flush_destinations = std::mem::take(commit).finish(self);
        if !deliveries.is_empty() {
            self.deliver_endpoint_service_datagram_batch(std::mem::take(deliveries));
        }
        for dest_addr in pending_flush_destinations {
            self.flush_pending_packets(&dest_addr).await;
        }
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
        let liveness_bookkeeping_allowed = arrived_from_source;
        let received_k_bit = fmp.fmp_flags & crate::node::wire::FLAG_KEY_EPOCH != 0;
        let _ = self.promote_dataplane_authenticated_pending_fmp_epoch(source_addr, received_k_bit);
        if liveness_bookkeeping_allowed {
            let _ = self.dataplane.record_authenticated_fmp_mmp_receive(
                crate::dataplane::DataplaneAuthenticatedFmpMmpReceive::new(
                    *source_addr,
                    fmp.fmp_counter,
                    fmp.inner_timestamp_ms,
                    fmp.packet_len,
                    fmp.fmp_flags & FLAG_CE != 0,
                    fmp.fmp_flags & FLAG_SP != 0,
                    now,
                ),
            );
        }
        let bookkeeping = self.peers.record_authenticated_fmp_receive(
            fmp,
            liveness_bookkeeping_allowed,
            path_bookkeeping_allowed,
        );
        if let Some(update) = bookkeeping {
            if update.path_bookkeeping_recorded || update.liveness_bookkeeping_recorded {
                self.clear_retry_unless_direct_refresh_needed(source_addr);
            }
            if update.address_changed {
                self.sync_dataplane_fmp_owner(source_addr);
            }
        }
    }

    pub(in crate::node) async fn handle_dataplane_fsp_decrypt_failure(
        &mut self,
        source_addr: NodeAddr,
        counter: u64,
        received_k_bit: bool,
    ) -> bool {
        self.handle_reported_fsp_decrypt_failure(
            source_addr,
            counter,
            received_k_bit,
            "dataplane",
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
        let now_ms = Self::now_ms();
        let owner_activity = self.dataplane.fsp_owner_activity(&src_addr);
        let authenticated_inbound_age_ms =
            owner_activity.and_then(|activity| activity.last_rx_age_ms(now_ms));
        if owner_activity.is_some_and(|activity| {
            activity.should_ignore_stale_epoch_decrypt_failure(received_k_bit)
        }) {
            trace!(
                src = %self.peer_display_name(&src_addr),
                counter,
                source,
                "Ignoring FSP AEAD failure from stale previous key epoch during dataplane-owned drain"
            );
            return true;
        }
        let Some(entry) = self.sessions.get(&src_addr) else {
            debug!(
                src = %self.peer_display_name(&src_addr),
                counter,
                source,
                "FSP AEAD failure for unknown session"
            );
            return false;
        };
        let entry_can_recover = entry.is_established()
            && !entry.has_rekey_in_progress()
            && entry.pending_new_session().is_none();
        let Some(consecutive) = self.dataplane.record_fsp_decrypt_failure(src_addr) else {
            debug!(
                src = %self.peer_display_name(&src_addr),
                counter,
                source,
                "FSP AEAD failure for missing dataplane owner"
            );
            return false;
        };
        let recover_session =
            should_start_decrypt_failure_rekey(entry_can_recover, consecutive, authenticated_inbound_age_ms);
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
