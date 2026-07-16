use super::*;

#[path = "lan_discovery.rs"]
mod lan_discovery;

impl Node {
    /// Poll all transports for discovered peers and auto-connect.
    ///
    /// Called from the tick handler. Iterates operational transports,
    /// drains their discovery buffers, and initiates connections to
    /// newly discovered peers (if auto_connect is enabled).
    pub(in crate::node) async fn poll_transport_discovery(&mut self) {
        // Collect discoveries first to avoid borrow conflict with self
        let mut to_connect = Vec::new();
        let mut queued_per_peer: HashMap<NodeAddr, usize> = HashMap::new();
        let mut connect_budget = self.discovery_connect_budget();
        let mut skipped_budget = 0usize;

        for transport in self.transports.values() {
            if !transport.is_operational() {
                continue;
            }
            if !transport.auto_connect() {
                // Still drain the buffer so it doesn't grow unbounded
                let _ = transport.discover();
                continue;
            }
            let discovered = match transport.discover() {
                Ok(peers) => peers,
                Err(_) => continue,
            };
            for peer in discovered {
                let discovered_transport_id = peer.transport_id;
                let pubkey = match peer.pubkey_hint {
                    Some(pk) => pk,
                    None => continue,
                };
                let identity = PeerIdentity::from_pubkey(pubkey);
                let node_addr = *identity.node_addr();

                // Skip self
                if node_addr == *self.identity.node_addr() {
                    continue;
                }

                let Some((candidate_transport_id, remote_addr, transport_name)) =
                    self.transport_discovery_candidate(discovered_transport_id, peer.addr)
                else {
                    continue;
                };

                if self.peers.contains_key(&node_addr) {
                    let candidate = PeerAddress::new(
                        transport_name,
                        self.peer_address_string_for_transport_candidate(
                            candidate_transport_id,
                            transport_name,
                            &remote_addr,
                        ),
                    )
                    .learned();
                    if self.active_peer_candidate_is_fresh_enough_to_skip(
                        &node_addr,
                        std::slice::from_ref(&candidate),
                    ) {
                        continue;
                    }
                    if self.is_connecting_to_peer_on_path(
                        &node_addr,
                        candidate_transport_id,
                        &remote_addr,
                    ) {
                        continue;
                    }
                    let queued_for_peer = queued_per_peer.get(&node_addr).copied().unwrap_or(0);
                    if connect_budget == 0
                        || self
                            .path_candidate_attempt_budget(&node_addr)
                            .saturating_sub(queued_for_peer)
                            == 0
                    {
                        skipped_budget = skipped_budget.saturating_add(1);
                        continue;
                    }
                    to_connect.push((candidate_transport_id, remote_addr, identity, true));
                    *queued_per_peer.entry(node_addr).or_default() += 1;
                    connect_budget = connect_budget.saturating_sub(1);
                    continue;
                }

                if self.is_connecting_to_peer_on_path(
                    &node_addr,
                    candidate_transport_id,
                    &remote_addr,
                ) {
                    continue;
                }

                let queued_for_peer = queued_per_peer.get(&node_addr).copied().unwrap_or(0);
                if connect_budget == 0
                    || self
                        .path_candidate_attempt_budget(&node_addr)
                        .saturating_sub(queued_for_peer)
                        == 0
                {
                    skipped_budget = skipped_budget.saturating_add(1);
                    continue;
                }
                to_connect.push((candidate_transport_id, remote_addr, identity, false));
                *queued_per_peer.entry(node_addr).or_default() += 1;
                connect_budget = connect_budget.saturating_sub(1);
            }
        }

        if skipped_budget > 0 {
            debug!(
                skipped = skipped_budget,
                queued = to_connect.len(),
                "Transport discovery connect budget exhausted"
            );
        }

        for (transport_id, remote_addr, identity, active_refresh) in to_connect {
            info!(
                peer = %self.peer_display_name(identity.node_addr()),
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                active_refresh,
                "Auto-connecting to discovered peer"
            );
            if let Err(e) = self
                .initiate_connection(transport_id, remote_addr, identity)
                .await
            {
                warn!(error = %e, "Failed to auto-connect to discovered peer");
            }
        }
    }

    pub(in crate::node) async fn poll_nostr_discovery(&mut self) {
        #[cfg(feature = "webrtc-transport")]
        self.drain_webrtc_session_signals().await;
        self.flush_pending_mesh_signals().await;

        let Some(bootstrap) = self.nostr_discovery.clone() else {
            return;
        };

        bootstrap.set_outbound_admission(self.open_discovery_outbound_admission_check());
        bootstrap.set_direct_refresh_admission(self.outbound_direct_refresh_admission_check());

        self.drain_nostr_mesh_signals(&bootstrap).await;

        for event in bootstrap.drain_events().await {
            match event {
                BootstrapEvent::Established { traversal } => {
                    let peer_identity = match PeerIdentity::from_npub(&traversal.peer_npub) {
                        Ok(identity) => identity,
                        Err(err) => {
                            debug!(
                                peer_npub = %traversal.peer_npub,
                                error = %err,
                                "Dropping established NAT traversal: invalid peer identity"
                            );
                            continue;
                        }
                    };
                    if self.enforces_configured_only_peer_admission()
                        && !self.is_configured_peer_identity(&peer_identity)
                    {
                        debug!(
                            peer = %self.peer_display_name(peer_identity.node_addr()),
                            npub = %peer_identity.npub(),
                            "Dropping established NAT traversal for non-configured peer"
                        );
                        continue;
                    }

                    let active_refresh = self.peers.contains_key(peer_identity.node_addr());
                    let admission_allowed = if active_refresh {
                        self.outbound_direct_refresh_admission_check()
                    } else {
                        self.outbound_admission_check()
                    };
                    if !admission_allowed {
                        debug!(
                            peer_npub = %traversal.peer_npub,
                            peers = self.peers.len(),
                            max_peers = self.max_peers,
                            active_refresh,
                            "Dropping established NAT traversal: at capacity"
                        );
                        continue;
                    }
                    let peer_npub = traversal.peer_npub.clone();
                    let fresh_active_path = !self
                        .active_peer_uses_nostr_relay(peer_identity.node_addr())
                        && (self.active_peer_has_fresh_endpoint_data_liveness(
                            peer_identity.node_addr(),
                        ) || (!self
                            .active_peer_uses_bootstrap_transport(peer_identity.node_addr())
                            && self
                                .active_peer_has_fresh_link_liveness(peer_identity.node_addr())));
                    if active_refresh && fresh_active_path {
                        debug!(
                            peer_npub = %peer_npub,
                            "Ignoring established NAT traversal for already-connected peer on fresh active path"
                        );
                        continue;
                    }
                    match self.adopt_established_traversal(traversal).await {
                        Ok(_) => {
                            info!(peer_npub = %peer_npub, "Adopted NAT traversal socket");
                        }
                        Err(err) => {
                            warn!(peer_npub = %peer_npub, error = %err, "Failed to adopt NAT traversal");
                            if let Ok(peer_identity) = PeerIdentity::from_npub(&peer_npub) {
                                self.schedule_retry(*peer_identity.node_addr(), Self::now_ms());
                            }
                        }
                    }
                }
                BootstrapEvent::Failed {
                    peer_config,
                    reason,
                } => {
                    let peer_identity = match PeerIdentity::from_npub(&peer_config.npub) {
                        Ok(identity) => identity,
                        Err(_) => continue,
                    };
                    let node_addr = *peer_identity.node_addr();
                    let now_ms = Self::now_ms();
                    if self.peers.contains_key(&node_addr) {
                        if self.active_peer_should_keep_direct_retry(&node_addr, &peer_config) {
                            let decision =
                                bootstrap.record_traversal_failure_for_peer(peer_identity, now_ms);
                            if decision.should_warn {
                                warn!(
                                    npub = %peer_config.npub,
                                    error = %reason,
                                    consecutive_failures = decision.consecutive_failures,
                                    cooldown_secs = decision
                                        .cooldown_until_ms
                                        .map(|t| t.saturating_sub(now_ms) / 1000),
                                    "Direct-path NAT traversal upgrade failed"
                                );
                            } else {
                                debug!(
                                    npub = %peer_config.npub,
                                    error = %reason,
                                    consecutive_failures = decision.consecutive_failures,
                                    "Direct-path NAT traversal upgrade failed (suppressed by warn-rate-limit)"
                                );
                            }
                            if decision.crossed_threshold {
                                bootstrap
                                    .request_advert_stale_check(peer_config.npub.clone())
                                    .await;
                            }
                            self.schedule_link_dead_reprobe(node_addr, now_ms);
                        } else {
                            debug!(
                                npub = %peer_config.npub,
                                error = %reason,
                                "Ignoring failed NAT traversal for already-connected peer on fresh direct path"
                            );
                        }
                        continue;
                    }
                    if self.is_connecting_to_peer(&node_addr) {
                        debug!(
                            npub = %peer_config.npub,
                            error = %reason,
                            "Ignoring failed NAT traversal while peer handshake is already in progress"
                        );
                        continue;
                    }

                    let decision =
                        bootstrap.record_traversal_failure_for_peer(peer_identity, now_ms);
                    if decision.should_warn {
                        warn!(
                            npub = %peer_config.npub,
                            error = %reason,
                            consecutive_failures = decision.consecutive_failures,
                            cooldown_secs = decision
                                .cooldown_until_ms
                                .map(|t| t.saturating_sub(now_ms) / 1000),
                            "NAT traversal failed"
                        );
                    } else {
                        debug!(
                            npub = %peer_config.npub,
                            error = %reason,
                            consecutive_failures = decision.consecutive_failures,
                            "NAT traversal failed (suppressed by warn-rate-limit)"
                        );
                    }

                    // B6: stale-advert eviction on the streak-threshold
                    // crossing. Fire-and-forget; the outcome is logged so
                    // operators can see when peers get cleaned up.
                    if decision.crossed_threshold {
                        bootstrap
                            .request_advert_stale_check(peer_config.npub.clone())
                            .await;
                    }

                    if self
                        .try_peer_addresses(&peer_config, peer_identity, false)
                        .await
                        .is_ok()
                    {
                        continue;
                    }

                    self.schedule_retry(node_addr, now_ms);
                    if self.nostr_cooldown_applies_to_peer_config(&peer_config)
                        && let Some(cooldown_until_ms) = decision.cooldown_until_ms
                        && let Some(state) = self.retry_pending.get_mut(&node_addr)
                    {
                        // Push the next retry past the cooldown so the
                        // open-discovery sweep doesn't re-enqueue and the
                        // per-attempt backoff doesn't fire sooner.
                        state.retry_after_ms = state.retry_after_ms.max(cooldown_until_ms);
                    }
                }
            }
        }

        self.maybe_run_startup_open_discovery_sweep(&bootstrap)
            .await;
        self.queue_open_discovery_retries(&bootstrap).await;
        self.queue_active_fallback_direct_retries();

        // Advert refresh can touch STUN/public-endpoint discovery on some
        // configs. Drain traversal events and queue direct retries first so a
        // slow refresh cannot delay path recovery work already waiting on us.
        if let Err(err) = self.refresh_overlay_advert(&bootstrap).await {
            debug!(error = %err, "Failed to refresh local Nostr overlay advert");
        }
    }

    #[cfg(feature = "webrtc-transport")]
    async fn drain_webrtc_session_signals(&mut self) {
        const MAX_WEBRTC_SIGNALS_PER_TICK: usize = 64;
        let mut signals = Vec::new();
        for transport in self.transports.values_mut() {
            let remaining = MAX_WEBRTC_SIGNALS_PER_TICK.saturating_sub(signals.len());
            if remaining == 0 {
                break;
            }
            signals.extend(transport.drain_link_negotiations(remaining));
        }

        for signal in signals {
            let Some(pubkey) = self.pubkey_for_node_addr(&signal.recipient) else {
                debug!(
                    peer = %self.peer_display_name(&signal.recipient),
                    "Cannot send WebRTC signal without authenticated peer identity"
                );
                continue;
            };
            let mut payload = Vec::with_capacity(4 + signal.payload.len());
            let port = crate::transport::link_negotiation::LINK_NEGOTIATION_SERVICE_PORT;
            payload.extend_from_slice(&port.to_le_bytes());
            payload.extend_from_slice(&port.to_le_bytes());
            payload.extend_from_slice(&signal.payload);
            match self
                .mesh_signal_session_action(signal.recipient, pubkey)
                .await
            {
                MeshSignalSessionAction::Send => {}
                MeshSignalSessionAction::Defer => {
                    self.pending_mesh_signals
                        .entry(signal.recipient)
                        .or_default()
                        .push(super::PendingMeshSignal {
                            msg_type: SessionMessageType::DataPacket.to_byte(),
                            payload,
                        });
                    continue;
                }
                MeshSignalSessionAction::Drop => continue,
            }
            if let Err(error) = self
                .send_session_msg(
                    &signal.recipient,
                    SessionMessageType::DataPacket.to_byte(),
                    &payload,
                )
                .await
            {
                debug!(
                    peer = %self.peer_display_name(&signal.recipient),
                    error = %error,
                    "Failed to send WebRTC signal over FIPS session"
                );
            }
        }
    }

    pub(super) async fn drain_nostr_mesh_signals(
        &mut self,
        bootstrap: &std::sync::Arc<NostrDiscovery>,
    ) {
        for signal in bootstrap.drain_mesh_signals().await {
            let (peer_npub, msg_type, payload) = match &signal {
                MeshTraversalSignal::Offer { peer_npub, offer } => {
                    let payload = match serde_json::to_vec(&offer) {
                        Ok(payload) => payload,
                        Err(error) => {
                            debug!(
                                peer = %peer_npub,
                                error = %error,
                                "Failed to encode mesh traversal offer"
                            );
                            continue;
                        }
                    };
                    (
                        peer_npub.clone(),
                        SessionMessageType::TraversalOffer.to_byte(),
                        payload,
                    )
                }
                MeshTraversalSignal::Answer { peer_npub, answer } => {
                    let payload = match serde_json::to_vec(&answer) {
                        Ok(payload) => payload,
                        Err(error) => {
                            debug!(
                                peer = %peer_npub,
                                error = %error,
                                "Failed to encode mesh traversal answer"
                            );
                            continue;
                        }
                    };
                    (
                        peer_npub.clone(),
                        SessionMessageType::TraversalAnswer.to_byte(),
                        payload,
                    )
                }
            };

            let peer_identity = match PeerIdentity::from_npub(&peer_npub) {
                Ok(identity) => identity,
                Err(error) => {
                    debug!(
                        peer = %peer_npub,
                        error = %error,
                        "Cannot send mesh traversal signal to invalid peer npub"
                    );
                    continue;
                }
            };
            let peer_addr = *peer_identity.node_addr();
            match self
                .mesh_signal_session_action(peer_addr, peer_identity.pubkey_full())
                .await
            {
                MeshSignalSessionAction::Send => {}
                MeshSignalSessionAction::Defer => {
                    self.pending_mesh_signals
                        .entry(peer_addr)
                        .or_default()
                        .push(super::PendingMeshSignal { msg_type, payload });
                    continue;
                }
                MeshSignalSessionAction::Drop => continue,
            }

            if let Err(error) = self.send_session_msg(&peer_addr, msg_type, &payload).await {
                debug!(
                    peer = %self.peer_display_name(&peer_addr),
                    error = %error,
                    "Failed to send mesh traversal signal"
                );
            }
        }
    }

    async fn flush_pending_mesh_signals(&mut self) {
        let ready = self
            .pending_mesh_signals
            .keys()
            .copied()
            .filter(|peer_addr| {
                self.sessions
                    .get(peer_addr)
                    .is_some_and(|entry| entry.is_established())
            })
            .collect::<Vec<_>>();
        for peer_addr in ready {
            let Some(signals) = self.pending_mesh_signals.remove(&peer_addr) else {
                continue;
            };
            let mut failed = Vec::new();
            for signal in signals {
                if self
                    .send_session_msg(&peer_addr, signal.msg_type, &signal.payload)
                    .await
                    .is_err()
                {
                    failed.push(signal);
                }
            }
            if !failed.is_empty() {
                self.pending_mesh_signals.insert(peer_addr, failed);
            }
        }
    }

    pub(super) async fn mesh_signal_session_action(
        &mut self,
        peer_addr: NodeAddr,
        peer_pubkey: PublicKey,
    ) -> MeshSignalSessionAction {
        if let Some(entry) = self.sessions.get(&peer_addr) {
            if entry.is_established() {
                return MeshSignalSessionAction::Send;
            }
            if entry.is_initiating() || entry.is_awaiting_msg3() {
                debug!(
                    peer = %self.peer_display_name(&peer_addr),
                    "Deferring mesh traversal signal until end-to-end session is established"
                );
                return MeshSignalSessionAction::Defer;
            }
        }

        if self.find_next_hop(&peer_addr).is_none() {
            debug!(
                peer = %self.peer_display_name(&peer_addr),
                "Cannot warm mesh traversal signal session without a FIPS route"
            );
            self.maybe_initiate_lookup(&peer_addr).await;
            return MeshSignalSessionAction::Drop;
        }

        self.register_identity(peer_addr, peer_pubkey);
        match self.initiate_session(peer_addr, peer_pubkey).await {
            Ok(()) => {
                debug!(
                    peer = %self.peer_display_name(&peer_addr),
                    "Warming end-to-end session for mesh traversal signal"
                );
                MeshSignalSessionAction::Defer
            }
            Err(NodeError::SendFailed { node_addr, reason })
                if node_addr == peer_addr && reason == "no route to destination" =>
            {
                debug!(
                    peer = %self.peer_display_name(&peer_addr),
                    "Cannot warm mesh traversal signal session without a FIPS route"
                );
                self.maybe_initiate_lookup(&peer_addr).await;
                MeshSignalSessionAction::Drop
            }
            Err(error) => {
                debug!(
                    peer = %self.peer_display_name(&peer_addr),
                    error = %error,
                    "Failed to warm end-to-end session for mesh traversal signal"
                );
                MeshSignalSessionAction::Drop
            }
        }
    }

    /// Resolve the LAN-only discovery scope. Applications with explicit
    /// connectivity config can set `node.discovery.lan.scope` without
    /// changing the public Nostr discovery `app` tag. The older fallback
    /// extracts a scope from the Nostr app tag used by default scoped
    /// discovery.
    pub(in crate::node) fn lan_discovery_scope(&self) -> Option<String> {
        crate::discovery::local::lan_discovery_scope(&self.config)
    }
}
