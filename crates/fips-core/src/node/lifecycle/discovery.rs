use super::*;

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
                    );
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
                    if active_refresh
                        && !self.active_peer_uses_bootstrap_transport(peer_identity.node_addr())
                        && self.active_peer_has_fresh_link_liveness(peer_identity.node_addr())
                    {
                        debug!(
                            peer_npub = %peer_npub,
                            "Ignoring established NAT traversal for already-connected peer on fresh direct path"
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
        self.queue_active_fallback_direct_retries(&bootstrap);

        // Advert refresh can touch STUN/public-endpoint discovery on some
        // configs. Drain traversal events and queue direct retries first so a
        // slow refresh cannot delay path recovery work already waiting on us.
        if let Err(err) = self.refresh_overlay_advert(&bootstrap).await {
            debug!(error = %err, "Failed to refresh local Nostr overlay advert");
        }
    }

    pub(super) async fn drain_nostr_mesh_signals(
        &mut self,
        bootstrap: &std::sync::Arc<NostrDiscovery>,
    ) {
        let mut deferred = Vec::new();

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
                    deferred.push(signal);
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

        for signal in deferred {
            bootstrap.requeue_mesh_signal(signal);
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
        if let Some(scope) = self.config.node.discovery.lan.scope.as_deref() {
            let scope = scope.trim();
            if !scope.is_empty() {
                return Some(scope.to_string());
            }
        }

        let app = self.config.node.discovery.nostr.app.trim();
        if app.is_empty() {
            return None;
        }
        if let Some(rest) = app.strip_prefix("fips-overlay-v1:") {
            let scope = rest.trim();
            if scope.is_empty() {
                None
            } else {
                Some(scope.to_string())
            }
        } else {
            Some(app.to_string())
        }
    }

    pub(in crate::node) fn start_local_instance_discovery(&mut self) {
        if !self.config.node.discovery.local.enabled {
            return;
        }
        let Some(scope) = self.lan_discovery_scope() else {
            debug!("local instance discovery not started: no discovery scope");
            return;
        };
        let now_ms = Self::now_ms();
        match crate::discovery::local::LocalInstanceRegistry::new(
            self.identity.npub(),
            scope,
            &self.config.node.discovery.local,
            now_ms,
        ) {
            Ok(registry) => {
                self.local_instance_registry = Some(registry);
                self.local_instance_started_at_ms = Some(now_ms);
                self.last_local_instance_publish_ms = None;
                self.last_local_instance_scan_ms = None;
                self.publish_local_instance_record(now_ms);
                info!("Same-host FIPS instance discovery enabled");
            }
            Err(crate::discovery::local::LocalInstanceRegistryError::Disabled) => {
                debug!("same-host FIPS instance discovery disabled");
            }
            Err(err) => {
                debug!(error = %err, "same-host FIPS instance discovery not started");
            }
        }
    }

    pub(super) fn local_instance_contacts(
        &self,
    ) -> Vec<crate::discovery::local::LocalInstanceContact> {
        let mut contacts = Vec::new();
        for handle in self.transports.values() {
            if !handle.is_operational() || !handle.accept_connections() {
                continue;
            }
            let transport = handle.transport_type().name;
            if transport != "udp" && transport != "tcp" {
                continue;
            }
            let Some(local_addr) = handle.local_addr() else {
                continue;
            };
            let Some(contact) =
                crate::discovery::local::contact_for_transport_addr(transport, local_addr)
            else {
                continue;
            };
            if contacts
                .iter()
                .any(|existing: &crate::discovery::local::LocalInstanceContact| {
                    existing.transport == contact.transport && existing.addr == contact.addr
                })
            {
                continue;
            }
            contacts.push(contact);
        }
        contacts
    }

    pub(super) fn publish_local_instance_record(&mut self, now_ms: u64) {
        let Some(registry) = self.local_instance_registry.clone() else {
            return;
        };
        let contacts = self.local_instance_contacts();
        match registry.publish(contacts, now_ms) {
            Ok(()) => {
                self.last_local_instance_publish_ms = Some(now_ms);
            }
            Err(err) => {
                debug!(error = %err, "failed to publish same-host FIPS instance record");
            }
        }
    }

    pub(super) fn maybe_publish_local_instance_record(&mut self, now_ms: u64) {
        if self.local_instance_registry.is_none() {
            return;
        }
        let interval_ms = self.config.node.discovery.local.publish_interval_ms();
        let due = self
            .last_local_instance_publish_ms
            .map(|last| now_ms.saturating_sub(last) >= interval_ms)
            .unwrap_or(true);
        if due {
            self.publish_local_instance_record(now_ms);
        }
    }

    pub(super) fn local_instance_scan_due(&self, now_ms: u64) -> bool {
        if self.local_instance_registry.is_none() {
            return false;
        }
        let cfg = &self.config.node.discovery.local;
        let interval_ms = if self
            .local_instance_started_at_ms
            .map(|started| now_ms.saturating_sub(started) <= cfg.startup_scan_duration_ms())
            .unwrap_or(false)
        {
            cfg.startup_scan_interval_ms()
        } else {
            cfg.scan_interval_ms()
        };
        self.last_local_instance_scan_ms
            .map(|last| now_ms.saturating_sub(last) >= interval_ms)
            .unwrap_or(true)
    }

    pub(super) fn local_instance_peer_allowed(&self, identity: &PeerIdentity) -> bool {
        if self.configured_peer(identity.node_addr()).is_some() {
            return true;
        }
        self.config.node.discovery.nostr.policy == NostrDiscoveryPolicy::Open
    }

    pub(super) fn local_instance_peer_addresses(
        &self,
        record: &crate::discovery::local::LocalInstanceRecord,
    ) -> Vec<PeerAddress> {
        let mut addresses = Vec::new();
        for contact in &record.contacts {
            if contact.transport != "udp" && contact.transport != "tcp" {
                continue;
            }
            let Ok(socket_addr) = contact.addr.parse::<SocketAddr>() else {
                debug!(
                    npub = %record.npub,
                    transport = %contact.transport,
                    addr = %contact.addr,
                    "local instance discovery: skip non-socket contact"
                );
                continue;
            };
            if !socket_addr.ip().is_loopback() {
                debug!(
                    npub = %record.npub,
                    addr = %contact.addr,
                    "local instance discovery: skip non-loopback contact"
                );
                continue;
            }
            let address =
                PeerAddress::with_priority(contact.transport.clone(), contact.addr.clone(), 10)
                    .with_seen_at_ms(record.updated_at_ms);
            if addresses.iter().any(|existing: &PeerAddress| {
                existing.transport == address.transport && existing.addr == address.addr
            }) {
                continue;
            }
            addresses.push(address);
        }
        addresses
    }

    /// Scan the same-host registry only on startup and then at a low cadence.
    /// This avoids a per-second filesystem poll while preserving the fast path
    /// for processes launched around the same time.
    pub(in crate::node) async fn poll_local_instance_discovery(&mut self) {
        let Some(registry) = self.local_instance_registry.clone() else {
            return;
        };
        let now_ms = Self::now_ms();
        self.maybe_publish_local_instance_record(now_ms);
        if !self.local_instance_scan_due(now_ms) {
            return;
        }
        self.last_local_instance_scan_ms = Some(now_ms);

        let records = match registry.scan(now_ms, self.config.node.discovery.local.stale_after_ms())
        {
            Ok(records) => records,
            Err(err) => {
                debug!(error = %err, "same-host FIPS instance scan failed");
                return;
            }
        };
        if records.is_empty() {
            return;
        }

        let mut connect_budget = self.discovery_connect_budget();
        let mut skipped_budget = 0usize;
        for record in records {
            let identity = match PeerIdentity::from_npub(&record.npub) {
                Ok(identity) => identity,
                Err(err) => {
                    debug!(npub = %record.npub, error = %err, "local instance discovery: skip bad npub");
                    continue;
                }
            };
            let peer_node_addr = *identity.node_addr();
            if peer_node_addr == *self.identity.node_addr() {
                continue;
            }
            if !self.local_instance_peer_allowed(&identity) {
                debug!(
                    npub = %identity.short_npub(),
                    "local instance discovery: skip unconfigured peer"
                );
                continue;
            }

            let addresses = self.local_instance_peer_addresses(&record);
            if addresses.is_empty() {
                continue;
            }

            if self.peers.contains_key(&peer_node_addr)
                && self.active_peer_candidate_is_fresh_enough_to_skip(&peer_node_addr, &addresses)
            {
                continue;
            }

            for address in addresses {
                let Some((transport_id, remote_addr)) =
                    self.resolve_peer_address_for_match(&address)
                else {
                    continue;
                };
                if self.is_connecting_to_peer_on_path(&peer_node_addr, transport_id, &remote_addr) {
                    continue;
                }
                if connect_budget == 0 || self.path_candidate_attempt_budget(&peer_node_addr) == 0 {
                    skipped_budget = skipped_budget.saturating_add(1);
                    continue;
                }
                info!(
                    npub = %identity.short_npub(),
                    transport = %address.transport,
                    addr = %address.addr,
                    "same-host FIPS instance discovery: initiating handshake"
                );
                if let Err(err) = self
                    .initiate_connection(transport_id, remote_addr, identity)
                    .await
                {
                    debug!(
                        npub = %record.npub,
                        error = %err,
                        "same-host FIPS instance discovery: failed to initiate connection"
                    );
                }
                connect_budget = connect_budget.saturating_sub(1);
            }
        }
        if skipped_budget > 0 {
            debug!(
                skipped = skipped_budget,
                "same-host FIPS instance discovery connect budget exhausted"
            );
        }
    }

    /// Drain mDNS-discovered peers and initiate Noise XX handshakes. For
    /// active peers this is a non-disruptive alternate-path refresh: the
    /// current link stays live until a new handshake authenticates and
    /// promotes. The handshake itself is the authentication — a spoofed
    /// mDNS advert with someone else's npub fails the XX exchange and
    /// is dropped.
    pub(in crate::node) async fn poll_lan_discovery(&mut self) {
        let Some(runtime) = self.lan_discovery.clone() else {
            return;
        };
        let events = runtime.drain_events().await;
        if events.is_empty() {
            return;
        }
        let mut connect_budget = self.discovery_connect_budget();
        let mut skipped_budget = 0usize;
        for event in events {
            let crate::discovery::lan::LanEvent::Discovered(peer) = event;
            let Some((transport_id, local_addr)) =
                self.find_udp_transport_for_remote_addr(peer.addr)
            else {
                debug!(
                    addr = %peer.addr,
                    "lan: skip discovered peer with no compatible UDP transport"
                );
                continue;
            };
            let identity = match crate::PeerIdentity::from_npub(&peer.npub) {
                Ok(id) => id,
                Err(err) => {
                    debug!(npub = %peer.npub, error = %err, "lan: skip bad npub");
                    continue;
                }
            };
            let peer_node_addr = *identity.node_addr();
            let remote_addr = crate::transport::TransportAddr::from_string(&peer.addr.to_string());
            if self.peers.contains_key(&peer_node_addr) {
                let candidate = PeerAddress::new("udp", peer.addr.to_string());
                if self.active_peer_candidate_is_fresh_enough_to_skip(
                    &peer_node_addr,
                    std::slice::from_ref(&candidate),
                ) {
                    continue;
                }
                if self.is_connecting_to_peer_on_path(&peer_node_addr, transport_id, &remote_addr) {
                    continue;
                }
                if connect_budget == 0 || self.path_candidate_attempt_budget(&peer_node_addr) == 0 {
                    skipped_budget = skipped_budget.saturating_add(1);
                    continue;
                }
                info!(
                    npub = %identity.short_npub(),
                    addr = %peer.addr,
                    local_addr = %local_addr,
                    "lan: initiating alternate-path handshake to active peer"
                );
                if let Err(err) = self
                    .initiate_connection(transport_id, remote_addr, identity)
                    .await
                {
                    debug!(
                        npub = %peer.npub,
                        error = %err,
                        "lan: failed to initiate active peer alternate-path handshake"
                    );
                }
                connect_budget = connect_budget.saturating_sub(1);
                continue;
            }
            if self.is_connecting_to_peer_on_path(&peer_node_addr, transport_id, &remote_addr) {
                continue;
            }
            if connect_budget == 0 || self.path_candidate_attempt_budget(&peer_node_addr) == 0 {
                skipped_budget = skipped_budget.saturating_add(1);
                continue;
            }
            info!(
                npub = %identity.short_npub(),
                addr = %peer.addr,
                local_addr = %local_addr,
                "lan: initiating handshake to discovered peer"
            );
            if let Err(err) = self
                .initiate_connection(transport_id, remote_addr, identity)
                .await
            {
                debug!(
                    npub = %peer.npub,
                    error = %err,
                    "lan: failed to initiate connection to discovered peer"
                );
            }
            connect_budget = connect_budget.saturating_sub(1);
        }
        if skipped_budget > 0 {
            debug!(
                skipped = skipped_budget,
                "lan: discovery connect budget exhausted"
            );
        }
    }

    /// Poll pending transport connects and initiate handshakes for ready ones.
    ///
    /// Called from the tick handler. For each pending connect, queries the
    /// transport's connection state. When a connection is established,
    /// marks the link as Connected and starts the Noise handshake.
    /// Failed connections are cleaned up and scheduled for retry.
    pub(in crate::node) async fn poll_pending_connects(&mut self) {
        if self.pending_connects.is_empty() {
            return;
        }

        let mut completed = Vec::new();

        for (i, pending) in self.pending_connects.iter().enumerate() {
            let state = if let Some(transport) = self.transports.get(&pending.transport_id) {
                transport.connection_state(&pending.remote_addr)
            } else {
                crate::transport::ConnectionState::Failed("transport removed".into())
            };

            match state {
                crate::transport::ConnectionState::Connected => {
                    completed.push((i, true, None));
                }
                crate::transport::ConnectionState::Failed(reason) => {
                    completed.push((i, false, Some(reason)));
                }
                crate::transport::ConnectionState::Connecting => {
                    // Still in progress, check on next tick
                }
                crate::transport::ConnectionState::None => {
                    // Shouldn't happen — treat as failure
                    completed.push((i, false, Some("no connection attempt found".into())));
                }
            }
        }

        // Process completions in reverse order to preserve indices
        for (i, success, reason) in completed.into_iter().rev() {
            let pending = self.pending_connects.remove(i);

            if success {
                // Mark link as Connected
                if let Some(link) = self.links.get_mut(&pending.link_id) {
                    link.set_connected();
                }

                debug!(
                    peer = %self.peer_display_name(pending.peer_identity.node_addr()),
                    transport_id = %pending.transport_id,
                    remote_addr = %pending.remote_addr,
                    link_id = %pending.link_id,
                    "Transport connected, starting handshake"
                );

                // Start the handshake now that the transport is connected
                if let Err(e) = self
                    .start_handshake(
                        pending.link_id,
                        pending.transport_id,
                        pending.remote_addr.clone(),
                        pending.peer_identity,
                    )
                    .await
                {
                    warn!(
                        link_id = %pending.link_id,
                        error = %e,
                        "Failed to start handshake after transport connect"
                    );
                    // Clean up link on handshake failure
                    self.remove_link(&pending.link_id);
                }
            } else {
                let reason = reason.unwrap_or_default();
                warn!(
                    peer = %self.peer_display_name(pending.peer_identity.node_addr()),
                    transport_id = %pending.transport_id,
                    remote_addr = %pending.remote_addr,
                    link_id = %pending.link_id,
                    reason = %reason,
                    "Transport connect failed"
                );

                // Clean up link and schedule retry
                self.remove_link(&pending.link_id);
                self.links.remove(&pending.link_id);
                self.schedule_retry(*pending.peer_identity.node_addr(), Self::now_ms());
            }
        }
    }
}
