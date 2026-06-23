#[derive(Clone, Copy)]
struct WorkerReceiveClock {
    now_ms: u64,
    now: Instant,
}

impl WorkerReceiveClock {
    fn now() -> Self {
        let now = Instant::now();
        let now_ms = Node::now_ms();
        Self { now_ms, now }
    }
}

impl Node {
    async fn flush_pending_destinations(&mut self, dests: &mut Vec<NodeAddr>) {
        for dest_addr in std::mem::take(dests) {
            self.flush_pending_packets(&dest_addr).await;
        }
    }

    fn note_pending_flush_dest(dests: &mut Vec<NodeAddr>, finish: SessionDispatchFinish) {
        if let Some(dest_addr) = finish.pending_flush_dest() {
            if !dests.contains(&dest_addr) {
                dests.push(dest_addr);
            }
        }
    }

    fn apply_worker_fsp_receive_sync_at(
        &mut self,
        source_addr: NodeAddr,
        sync: crate::node::session::FspReceiveSync,
        clock: WorkerReceiveClock,
    ) -> bool {
        let apply = {
            let Some(entry) = self.sessions.get_mut(&source_addr) else {
                return false;
            };
            entry.apply_fsp_receive_sync_result(sync, clock.now_ms, clock.now)
        };
        if apply.refresh_worker_session() {
            self.register_decrypt_worker_fsp_session(&source_addr);
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
    /// - Phase 0x0 + !U → encrypted session message (data, reports, etc.)
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
                self.handle_encrypted_session_msg(delivery.into_encrypted())
                    .await;
            }
            _ => {
                debug!(phase = prefix.phase, "Unknown FSP phase");
            }
        }
    }

    /// Handle an encrypted session message (phase 0x0, U flag clear).
    ///
    /// Full FSP receive pipeline:
    /// 1. Parse FspEncryptedHeader (12 bytes) → counter, flags, header_bytes
    /// 2. If CP flag: parse cleartext coords, cache them
    /// 3. Session lookup (must be Established)
    /// 4. AEAD decrypt with AAD = header_bytes
    /// 5. Strip FSP inner header → timestamp, msg_type, inner_flags
    /// 6. Dispatch by msg_type
    async fn handle_encrypted_session_msg(&mut self, delivery: EncryptedSessionPayload<'_>) {
        let _t_fsp_handle =
            crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspHandle);
        let src_addr = delivery.source_addr();
        let payload = delivery.payload();
        let mut wire = match EstablishedFspWire::parse(payload, *src_addr, *self.node_addr()) {
            Ok(wire) => wire,
            Err(EstablishedFspWireError::BadHeader) => {
                debug!(
                    len = payload.len(),
                    "Encrypted session message too short for FSP header"
                );
                return;
            }
            Err(EstablishedFspWireError::BadCoords(e)) => {
                debug!(error = %e, "Failed to parse coords from encrypted session message");
                return;
            }
        };

        if wire.has_coord_warmup() {
            wire.apply_coord_warmup(&mut self.coord_cache, Self::now_ms());
        }

        // The session registry owns the mutable lookup plus FSP open/replay,
        // K-bit handling, failure accounting, MMP receive bookkeeping, and
        // dispatch metadata. The rx loop supplies the parsed wire facts but no
        // longer peeks into the session map directly on this hot edge.
        let outcome = self.sessions.open_established_fsp_frame(
            src_addr,
            wire.receive(delivery.path_mtu(), delivery.ce_flag(), Self::now_ms()),
        );

        // The &mut entry borrow on self.sessions has dropped. Handle
        // slow-path outcomes and dispatch by msg_type (which calls
        // other &mut self handlers).
        let session_message = match outcome {
            FspFrameOutcome::Authentic(session_message) => session_message,
            FspFrameOutcome::UnknownSession => {
                debug!(src = %self.peer_display_name(src_addr), "Encrypted session message for unknown session");
                return;
            }
            FspFrameOutcome::NotEstablished => {
                debug!(
                    src = %self.peer_display_name(src_addr),
                    "Encrypted message but session not established (awaiting handshake completion)"
                );
                self.resend_handshake_after_early_encrypted_data(src_addr)
                    .await;
                return;
            }
            FspFrameOutcome::BadInnerHeader => {
                debug!(src = %self.peer_display_name(src_addr), "Decrypted payload too short for FSP inner header");
                return;
            }
            FspFrameOutcome::MissingRemoteIdentity => {
                debug!(
                    src = %self.peer_display_name(src_addr),
                    "Established session missing authenticated remote identity"
                );
                return;
            }
            FspFrameOutcome::DecryptFailed {
                error,
                counter,
                consecutive,
                recover_session,
            } => {
                debug!(
                    error = %error, src = %self.peer_display_name(src_addr),
                    counter, consecutive_failures = consecutive,
                    "Session AEAD decryption failed"
                );
                if recover_session {
                    warn!(
                        peer = %self.peer_display_name(src_addr),
                        consecutive_failures = consecutive,
                        "Session AEAD failures exceeded threshold; starting recovery rekey"
                    );
                    if !self.initiate_session_rekey(src_addr).await {
                        debug!(
                            peer = %self.peer_display_name(src_addr),
                            "Failed to start recovery rekey after decrypt-failure threshold"
                        );
                    }
                }
                return;
            }
            FspFrameOutcome::StaleEpochDrainFailure { counter } => {
                trace!(
                    src = %self.peer_display_name(src_addr),
                    counter,
                    "Ignoring stale FSP packet from previous key epoch during drain"
                );
                return;
            }
        };
        self.register_decrypt_worker_fsp_session(src_addr);
        let dispatch = AuthenticatedSessionDispatch::new(
            *src_addr,
            *delivery.previous_hop_addr(),
            delivery.ce_flag(),
            session_message,
        );
        if dispatch.is_endpoint_data() {
            let finish = dispatch.dispatch_endpoint_data_fast(self);
            if let Some(dest_addr) = finish.pending_flush_dest() {
                self.flush_pending_packets(&dest_addr).await;
            }
            return;
        }
        dispatch.dispatch(self).await;
    }

    fn record_worker_authenticated_fmp_receive(
        &mut self,
        fmp: &crate::node::decrypt_worker::DecryptFmpBookkeeping,
        previous_hop: Option<&NodeAddr>,
    ) {
        self.record_worker_authenticated_fmp_receive_at(fmp, previous_hop, WorkerReceiveClock::now());
    }

    fn record_worker_authenticated_fmp_receive_at(
        &mut self,
        fmp: &crate::node::decrypt_worker::DecryptFmpBookkeeping,
        previous_hop: Option<&NodeAddr>,
        clock: WorkerReceiveClock,
    ) {
        let source_addr = fmp.source_peer.node_addr();
        let arrived_from_source = previous_hop.is_none_or(|hop| hop == source_addr);
        let path_bookkeeping_allowed = self.authenticated_packet_path_allows_bookkeeping(
            source_addr,
            fmp.transport_id,
            &fmp.remote_addr,
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
            clock.now,
            path_bookkeeping_allowed,
        );
        if bookkeeping.is_some_and(|update| update.path_bookkeeping_recorded) {
            self.clear_retry_unless_direct_refresh_needed(source_addr);
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if bookkeeping.is_some_and(|update| update.address_changed) {
            self.clear_connected_udp_for_peer(source_addr);
        }
    }

    pub(in crate::node) fn process_authenticated_fmp_receive_from_worker(
        &mut self,
        receive: DecryptAuthenticatedFmpReceive,
    ) {
        self.record_worker_authenticated_fmp_receive(
            &receive.fmp,
            receive
                .previous_hop_peer
                .as_ref()
                .map(|peer| peer.node_addr()),
        );
    }

    pub(in crate::node) async fn process_authenticated_session_from_worker(
        &mut self,
        authenticated: DecryptAuthenticatedSession,
    ) {
        let Some(dispatch) =
            self.authenticated_session_dispatch_from_worker_at(authenticated, WorkerReceiveClock::now())
        else {
            return;
        };
        if dispatch.is_endpoint_data() {
            let finish = dispatch.dispatch_endpoint_data_fast(self);
            if let Some(dest_addr) = finish.pending_flush_dest() {
                self.flush_pending_packets(&dest_addr).await;
            }
            return;
        }
        dispatch.dispatch(self).await;
    }

    pub(in crate::node) async fn process_authenticated_session_batch_from_worker(
        &mut self,
        sessions: Vec<DecryptAuthenticatedSession>,
    ) {
        let mut pending_flush_dests = Vec::new();
        let clock = WorkerReceiveClock::now();
        for authenticated in sessions {
            let Some(dispatch) =
                self.authenticated_session_dispatch_from_worker_at(authenticated, clock)
            else {
                continue;
            };
            if dispatch.is_endpoint_data() {
                Self::note_pending_flush_dest(
                    &mut pending_flush_dests,
                    dispatch.dispatch_endpoint_data_fast(self),
                );
                continue;
            }

            self.flush_pending_destinations(&mut pending_flush_dests)
                .await;
            dispatch.dispatch(self).await;
        }
        self.flush_pending_destinations(&mut pending_flush_dests)
            .await;
    }

    fn authenticated_session_dispatch_from_worker_at(
        &mut self,
        authenticated: DecryptAuthenticatedSession,
        clock: WorkerReceiveClock,
    ) -> Option<AuthenticatedSessionDispatch> {
        let source_addr = authenticated.source_addr;
        let previous_hop_addr = *authenticated.previous_hop_peer.node_addr();
        self.record_worker_authenticated_fmp_receive_at(
            &authenticated.fmp,
            Some(&previous_hop_addr),
            clock,
        );

        let receive_applied =
            self.apply_worker_fsp_receive_sync_at(source_addr, authenticated.receive_sync, clock);
        if !receive_applied {
            debug!(
                src = %self.peer_display_name(&source_addr),
                "Dropping worker-authenticated session message for missing or stale session"
            );
            return None;
        }

        Some(AuthenticatedSessionDispatch::new(
            source_addr,
            previous_hop_addr,
            authenticated.ce_flag,
            authenticated.message,
        ))
    }

    pub(in crate::node) async fn process_direct_session_data_from_worker(
        &mut self,
        direct: DecryptDirectSessionData,
    ) {
        let Some(finish) =
            self.process_direct_session_data_from_worker_at(direct, WorkerReceiveClock::now())
        else {
            return;
        };

        if let Some(dest_addr) = finish.pending_flush_dest() {
            self.flush_pending_packets(&dest_addr).await;
        }
    }

    fn deliver_direct_session_delivery_from_worker(
        &mut self,
        source_addr: NodeAddr,
        ce_flag: bool,
        delivery: DecryptDirectSessionDelivery,
    ) {
        match delivery {
            DecryptDirectSessionDelivery::Ipv6Packet(mut packet) => {
                if ce_flag {
                    mark_ipv6_ecn_ce(&mut packet);
                    self.stats_mut().congestion.record_ce_received();
                }
                if self.external_packet_tx.is_some() {
                    self.deliver_external_ipv6_packet(&source_addr, packet);
                } else if let Some(tun_tx) = &self.tun_tx {
                    let _t =
                        crate::perf_profile::Timer::start(crate::perf_profile::Stage::TunWrite);
                    if let Err(error) = tun_tx.send(packet) {
                        debug!(error = %error, "Failed to deliver worker-decoded IPv6 packet to TUN");
                    }
                } else {
                    trace!(
                        src = %self.peer_display_name(&source_addr),
                        "Worker-decoded IPv6 packet ready (no TUN interface)"
                    );
                }
            }
            DecryptDirectSessionDelivery::EndpointData(delivery) => {
                self.deliver_endpoint_data(delivery);
            }
        }
    }

    pub(in crate::node) async fn process_direct_session_data_batch_from_worker(
        &mut self,
        directs: Vec<DecryptDirectSessionData>,
    ) {
        let mut pending_flush_dests = Vec::new();
        let clock = WorkerReceiveClock::now();
        for direct in directs {
            let Some(finish) = self.process_direct_session_data_from_worker_at(direct, clock)
            else {
                continue;
            };
            Self::note_pending_flush_dest(&mut pending_flush_dests, finish);
        }
        self.flush_pending_destinations(&mut pending_flush_dests)
            .await;
    }

    fn process_direct_session_data_from_worker_at(
        &mut self,
        direct: DecryptDirectSessionData,
        clock: WorkerReceiveClock,
    ) -> Option<SessionDispatchFinish> {
        let finish = self.commit_direct_session_data_from_worker_at(
            &direct.fmp,
            direct.source_addr,
            direct.previous_hop_peer,
            direct.receive_sync,
            direct.body_len,
            clock,
        )?;

        self.deliver_direct_session_delivery_from_worker(
            direct.source_addr,
            direct.ce_flag,
            direct.delivery,
        );
        Some(finish)
    }

    pub(in crate::node) async fn process_direct_session_commit_from_worker(
        &mut self,
        commit: DecryptDirectSessionCommit,
    ) {
        let Some(finish) = self.commit_direct_session_data_from_worker_at(
            &commit.fmp,
            commit.source_addr,
            commit.previous_hop_peer,
            commit.receive_sync,
            commit.body_len,
            WorkerReceiveClock::now(),
        ) else {
            return;
        };

        if commit.ce_flag && commit.delivered_ipv6 {
            self.stats_mut().congestion.record_ce_received();
        }

        if let Some(dest_addr) = finish.pending_flush_dest() {
            self.flush_pending_packets(&dest_addr).await;
        }
    }

    pub(in crate::node) async fn process_direct_session_commit_batch_from_worker(
        &mut self,
        commits: Vec<DecryptDirectSessionCommit>,
    ) {
        let mut pending_flush_dests = Vec::new();
        let clock = WorkerReceiveClock::now();
        let mut start = 0;
        while start < commits.len() {
            let mut end = start + 1;
            while end < commits.len()
                && Self::direct_session_commit_batch_key_matches(&commits[start], &commits[end])
            {
                end += 1;
            }

            let Some(finish) =
                self.commit_direct_session_commit_run_from_worker_at(&commits[start..end], clock)
            else {
                start = end;
                continue;
            };

            Self::note_pending_flush_dest(&mut pending_flush_dests, finish);
            start = end;
        }
        self.flush_pending_destinations(&mut pending_flush_dests)
            .await;
    }

    fn direct_session_commit_batch_key_matches(
        first: &DecryptDirectSessionCommit,
        next: &DecryptDirectSessionCommit,
    ) -> bool {
        first.source_addr == next.source_addr
            && first.previous_hop_peer.node_addr() == next.previous_hop_peer.node_addr()
    }

    fn commit_direct_session_data_from_worker_at(
        &mut self,
        fmp: &crate::node::decrypt_worker::DecryptFmpBookkeeping,
        source_addr: NodeAddr,
        previous_hop_peer: PeerIdentity,
        receive_sync: crate::node::session::FspReceiveSync,
        body_len: usize,
        clock: WorkerReceiveClock,
    ) -> Option<SessionDispatchFinish> {
        self.record_worker_authenticated_fmp_receive_at(
            fmp,
            Some(previous_hop_peer.node_addr()),
            clock,
        );

        let receive_applied =
            self.apply_worker_fsp_receive_sync_at(source_addr, receive_sync, clock);
        if !receive_applied {
            debug!(
                src = %self.peer_display_name(&source_addr),
                "Dropping worker-decoded direct session data for missing or stale session"
            );
            return None;
        }

        self.learn_reverse_route_at(source_addr, *previous_hop_peer.node_addr(), clock.now_ms);
        let direct_path = previous_hop_peer.node_addr() == &source_addr;
        let finish = SessionDispatchCommit {
            source_addr,
            receive_completion: Some(SessionReceiveCompletion {
                source_addr,
                previous_hop_addr: *previous_hop_peer.node_addr(),
                body_len,
                direct_path,
            }),
        }
        .finish_receive_at(self, clock.now_ms);

        Some(finish)
    }

    fn commit_direct_session_commit_run_from_worker_at(
        &mut self,
        commits: &[DecryptDirectSessionCommit],
        clock: WorkerReceiveClock,
    ) -> Option<SessionDispatchFinish> {
        let first = commits.first()?;
        let source_addr = first.source_addr;
        let previous_hop_peer = first.previous_hop_peer;
        let previous_hop_addr = *previous_hop_peer.node_addr();
        for commit in commits {
            self.record_worker_authenticated_fmp_receive_at(
                &commit.fmp,
                Some(commit.previous_hop_peer.node_addr()),
                clock,
            );
        }

        let mut refresh_worker_session = false;
        let mut received_packets = 0usize;
        let mut received_bytes = 0usize;
        let mut ce_ipv6_packets = 0usize;
        let source_display = self.peer_display_name(&source_addr).to_string();
        {
            let Some(entry) = self.sessions.get_mut(&source_addr) else {
                debug!(
                    src = %source_display,
                    "Dropping worker-decoded direct session commit batch for missing session"
                );
                return None;
            };
            for commit in commits {
                let apply = entry.apply_fsp_receive_sync_result(
                    commit.receive_sync,
                    clock.now_ms,
                    clock.now,
                );
                if !apply.is_applied() {
                    debug!(
                        src = %source_display,
                        "Dropping worker-decoded direct session commit for stale session"
                    );
                    continue;
                }
                refresh_worker_session |= apply.refresh_worker_session();
                received_packets += 1;
                received_bytes += commit.body_len;
                if commit.ce_flag && commit.delivered_ipv6 {
                    ce_ipv6_packets += 1;
                }
            }
            if received_packets == 0 {
                return None;
            }
            entry.record_recv_batch(received_packets, received_bytes);
            if previous_hop_addr == source_addr {
                entry.touch_inbound_data_frame(clock.now_ms);
            }
            entry.touch(clock.now_ms);
        }

        if refresh_worker_session {
            self.register_decrypt_worker_fsp_session(&source_addr);
        }
        for _ in 0..ce_ipv6_packets {
            self.stats_mut().congestion.record_ce_received();
        }

        self.learn_reverse_route_at(source_addr, previous_hop_addr, clock.now_ms);
        if let Some(peer) = self.peers.get_mut(&previous_hop_addr) {
            peer.touch(clock.now_ms);
        }

        let direct_path = previous_hop_addr == source_addr;
        if direct_path && self.clear_session_direct_path_degraded(&source_addr) {
            debug!(
                src = %self.peer_display_name(&source_addr),
                "Authenticated direct endpoint data restored direct payload routing"
            );
        }

        let retry_peer = if direct_path {
            source_addr
        } else {
            previous_hop_addr
        };
        self.clear_retry_unless_direct_refresh_needed(&retry_peer);

        Some(SessionDispatchFinish {
            pending_flush_dest: self
                .pending_session_traffic
                .has_traffic_for(&source_addr)
                .then_some(source_addr),
        })
    }

    pub(in crate::node) async fn process_fsp_decrypt_failure_from_worker(
        &mut self,
        report: DecryptFspFailureReport,
    ) {
        self.record_worker_authenticated_fmp_receive(&report.fmp, None);
        let src_addr = report.source_addr;
        let Some(entry) = self.sessions.get_mut(&src_addr) else {
            debug!(
                src = %self.peer_display_name(&src_addr),
                counter = report.counter,
                "Worker FSP AEAD failure for unknown session"
            );
            return;
        };
        if should_ignore_stale_epoch_drain_failure(entry, report.received_k_bit) {
            trace!(
                src = %self.peer_display_name(&src_addr),
                counter = report.counter,
                "Ignoring worker FSP AEAD failure from stale previous key epoch during drain"
            );
            return;
        }
        let consecutive = entry.record_decrypt_failure();
        let recover_session = should_start_decrypt_failure_rekey(entry, consecutive, Self::now_ms());
        debug!(
            src = %self.peer_display_name(&src_addr),
            counter = report.counter,
            consecutive_failures = consecutive,
            "Worker FSP AEAD decryption failed"
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
                    "Failed to start recovery rekey after worker FSP decrypt-failure threshold"
                );
            }
        }
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
