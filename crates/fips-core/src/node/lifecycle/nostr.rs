use super::*;

type OpenDiscoveryCandidate = (String, Vec<OverlayEndpointAdvert>, u64);

impl Node {
    pub(in crate::node) fn static_peer_addresses(
        &self,
        peer_config: &PeerConfig,
    ) -> Vec<PeerAddress> {
        peer_config
            .addresses_by_priority()
            .into_iter()
            .cloned()
            .collect()
    }

    pub(super) async fn nostr_peer_fallback_addresses(
        &self,
        peer_config: &PeerConfig,
        existing: &[PeerAddress],
    ) -> Vec<PeerAddress> {
        if !self.config.node.discovery.nostr.enabled
            || self.config.node.discovery.nostr.policy
                == crate::config::NostrDiscoveryPolicy::Disabled
        {
            return Vec::new();
        }

        let Some(bootstrap) = self.nostr_discovery.clone() else {
            return Vec::new();
        };
        if self.nostr_cooldown_applies_to_peer_config(peer_config)
            && bootstrap
                .cooldown_until(&peer_config.npub, Self::now_ms())
                .is_some()
        {
            debug!(
                npub = %peer_config.npub,
                "Skipping cached Nostr fallback endpoints while peer is in traversal cooldown"
            );
            return Vec::new();
        }
        let (endpoints, created_at_secs) = match bootstrap
            .cached_advert_endpoints_with_created_at_for_peer(&peer_config.npub)
            .await
        {
            Some(cached) => cached,
            None => {
                debug!(
                    npub = %peer_config.npub,
                    "No cached Nostr advert endpoints for configured peer"
                );
                return Vec::new();
            }
        };

        let mut fallback = Vec::new();
        let fallback_priority = Self::overlay_fallback_priority(existing);
        // Preserve the advert event timestamp as the candidate freshness
        // signal. Restamping cached adverts on every read makes stale LAN
        // endpoints look fresh forever after a peer roams.
        let seen_at_ms = created_at_secs.saturating_mul(1000);
        for endpoint in endpoints {
            let Some(candidate) =
                Self::overlay_endpoint_to_peer_address(&endpoint, fallback_priority, seen_at_ms)
            else {
                continue;
            };
            if existing
                .iter()
                .any(|addr| addr.transport == candidate.transport && addr.addr == candidate.addr)
                || fallback.iter().any(|addr: &PeerAddress| {
                    addr.transport == candidate.transport && addr.addr == candidate.addr
                })
            {
                continue;
            }
            fallback.push(candidate);
        }
        fallback
    }

    pub(in crate::node) fn overlay_fallback_priority(existing: &[PeerAddress]) -> u8 {
        const DEFAULT_ADDRESS_PRIORITY: u8 = 100;

        let best_existing = existing
            .iter()
            .map(|addr| addr.priority)
            .min()
            .unwrap_or(DEFAULT_ADDRESS_PRIORITY);

        if let Some(best_static) = existing
            .iter()
            .filter(|addr| addr.is_configured())
            .map(|addr| addr.priority)
            .min()
            .filter(|priority| *priority < DEFAULT_ADDRESS_PRIORITY)
        {
            return best_static.saturating_add(1);
        }

        best_existing.min(DEFAULT_ADDRESS_PRIORITY)
    }

    pub(in crate::node) async fn request_nostr_bootstrap(&self, peer_config: &PeerConfig) -> bool {
        if !self.config.node.discovery.nostr.enabled
            || self.config.node.discovery.nostr.policy
                == crate::config::NostrDiscoveryPolicy::Disabled
        {
            return false;
        }
        let Some(bootstrap) = self.nostr_discovery.clone() else {
            return false;
        };
        let now_ms = Self::now_ms();
        if self.nostr_cooldown_applies_to_peer_config(peer_config)
            && let Some(cooldown_until_ms) = bootstrap.cooldown_until(&peer_config.npub, now_ms)
        {
            debug!(
                npub = %peer_config.npub,
                cooldown_secs = cooldown_until_ms.saturating_sub(now_ms) / 1000,
                "Skipping Nostr traversal request while peer is in cooldown"
            );
            return false;
        }
        bootstrap.set_outbound_admission(self.open_discovery_outbound_admission_check());
        bootstrap.set_direct_refresh_admission(self.outbound_direct_refresh_admission_check());
        let mesh_signaling_allowed = self.mesh_signaling_allowed_for_peer(peer_config);
        let started = bootstrap
            .request_connect_with_mesh_signaling(peer_config.clone(), mesh_signaling_allowed)
            .await;
        if started {
            info!(
                npub = %peer_config.npub,
                mesh_signaling_allowed,
                "Started background UDP NAT traversal attempt"
            );
        } else {
            debug!(
                npub = %peer_config.npub,
                mesh_signaling_allowed,
                "Background UDP NAT traversal attempt already in progress"
            );
        }
        true
    }

    pub(super) fn nostr_cooldown_applies_to_peer_config(&self, peer_config: &PeerConfig) -> bool {
        !self.mesh_signaling_allowed_for_peer(peer_config)
    }

    pub(in crate::node) fn mesh_signaling_allowed_for_peer(
        &self,
        peer_config: &PeerConfig,
    ) -> bool {
        self.configured_peer_send_weights
            .peer_addr_for_npub(&peer_config.npub)
            .is_some()
    }

    pub(super) fn overlay_endpoint_to_peer_address(
        endpoint: &OverlayEndpointAdvert,
        priority: u8,
        seen_at_ms: u64,
    ) -> Option<PeerAddress> {
        let transport = match endpoint.transport {
            OverlayTransportKind::Udp => "udp",
            OverlayTransportKind::Tcp => "tcp",
            OverlayTransportKind::Tor => "tor",
            OverlayTransportKind::WebRtc => "webrtc",
        };
        Some(
            PeerAddress::with_priority(transport, endpoint.addr.clone(), priority)
                .with_seen_at_ms(seen_at_ms),
        )
    }

    pub(super) async fn attempt_peer_address_list(
        &mut self,
        peer_config: &PeerConfig,
        peer_identity: PeerIdentity,
        allow_bootstrap_nat: bool,
        addresses: &[PeerAddress],
    ) -> Result<(), NodeError> {
        let mut attempted = false;
        let mut local_route_error = None;
        let peer_node_addr = *peer_identity.node_addr();
        let mut concrete_budget = self.path_candidate_attempt_budget(&peer_node_addr);
        let mut started_candidate_this_pass = false;

        for addr in addresses {
            if addr.transport == "udp" && addr.addr.eq_ignore_ascii_case("nat") {
                if !allow_bootstrap_nat {
                    continue;
                }
                if self.request_nostr_bootstrap(peer_config).await {
                    attempted = true;
                    continue;
                }
                debug!(npub = %peer_config.npub, "No Nostr overlay runtime for udp:nat address");
                continue;
            }

            let (transport_id, remote_addr) = if addr.transport == "ethernet" {
                match self.resolve_ethernet_addr(&addr.addr) {
                    Ok(result) => result,
                    Err(e) => {
                        debug!(
                            transport = %addr.transport,
                            addr = %addr.addr,
                            error = %e,
                            "Failed to resolve Ethernet address"
                        );
                        continue;
                    }
                }
            } else if addr.transport == "ble" {
                #[cfg(bluer_available)]
                {
                    match self.resolve_ble_addr(&addr.addr) {
                        Ok(result) => result,
                        Err(e) => {
                            debug!(
                                transport = %addr.transport,
                                addr = %addr.addr,
                                error = %e,
                                "Failed to resolve BLE address"
                            );
                            continue;
                        }
                    }
                }
                #[cfg(not(bluer_available))]
                {
                    debug!(transport = %addr.transport, "BLE transport not available on this build");
                    continue;
                }
            } else {
                let tid = if addr.transport == "udp"
                    && let Ok(remote_socket_addr) = addr.addr.parse::<SocketAddr>()
                {
                    match self
                        .find_udp_transport_for_remote_addr(remote_socket_addr, addr.provenance)
                    {
                        Some((id, _)) => id,
                        None => {
                            debug!(
                                transport = %addr.transport,
                                addr = %addr.addr,
                                "No compatible operational UDP transport for address"
                            );
                            continue;
                        }
                    }
                } else {
                    match self.find_transport_for_type(&addr.transport) {
                        Some(id) => id,
                        None => {
                            debug!(
                                transport = %addr.transport,
                                addr = %addr.addr,
                                "No operational transport for address type"
                            );
                            continue;
                        }
                    }
                };
                (tid, TransportAddr::from_string(&addr.addr))
            };

            if self.is_connecting_to_peer_on_path(&peer_node_addr, transport_id, &remote_addr) {
                attempted = true;
                debug!(
                    npub = %peer_config.npub,
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    "Skipping duplicate in-flight candidate path"
                );
                continue;
            }

            if concrete_budget == 0 && self.active_peer_matches_candidate(&peer_node_addr, addr) {
                debug!(
                    npub = %peer_config.npub,
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    "Skipping active current path while candidate race budget is exhausted"
                );
                continue;
            }

            if concrete_budget == 0
                && !started_candidate_this_pass
                && self.reclaim_lower_priority_inflight_candidate_for_peer(&peer_node_addr, addr)
            {
                concrete_budget = self.path_candidate_attempt_budget(&peer_node_addr);
            }

            if concrete_budget == 0 {
                debug!(
                    npub = %peer_config.npub,
                    max_candidates = MAX_PARALLEL_PATH_CANDIDATES_PER_PEER,
                    "Path candidate race budget exhausted"
                );
                break;
            }

            match self
                .initiate_connection(transport_id, remote_addr, peer_identity)
                .await
            {
                Ok(()) => {
                    attempted = true;
                    started_candidate_this_pass = true;
                    concrete_budget = concrete_budget.saturating_sub(1);
                }
                Err(e @ NodeError::AccessDenied(_)) => return Err(e),
                Err(e) => {
                    if e.is_local_route_unavailable() && local_route_error.is_none() {
                        local_route_error = Some(e.to_string());
                    }
                    debug!(
                        npub = %peer_config.npub,
                        transport_id = %transport_id,
                        error = %e,
                        "Connection attempt failed, trying next address"
                    );
                }
            }
        }

        if attempted {
            return Ok(());
        }

        if let Some(error) = local_route_error {
            return Err(NodeError::LocalRouteUnavailable(error));
        }

        Err(NodeError::NoTransportForType(format!(
            "no operational transport for any of {}'s addresses",
            peer_config.npub
        )))
    }

    pub(super) async fn queue_open_discovery_retries(
        &mut self,
        bootstrap: &std::sync::Arc<NostrDiscovery>,
    ) {
        self.run_open_discovery_sweep(bootstrap, None, "per-tick")
            .await;
    }

    pub(in crate::node) fn queue_active_fallback_direct_retries(&mut self) {
        let now_ms = Self::now_ms();
        let peer_configs = self
            .configured_peer_send_weights
            .auto_connect_peer_configs()
            .map(|(node_addr, peer_config)| (*node_addr, peer_config.clone()))
            .collect::<Vec<_>>();

        for (node_addr, peer_config) in peer_configs {
            if self.retry_pending.contains_key(&node_addr)
                || !self.peers.contains_key(&node_addr)
                || self.is_connecting_to_peer(&node_addr)
                || !self.active_peer_should_keep_direct_retry(&node_addr, &peer_config)
            {
                continue;
            }

            let mut state = crate::node::retry::RetryState::new(peer_config.clone());
            state.reconnect = true;
            state.retry_after_ms = now_ms;
            self.retry_pending.insert(node_addr, state);

            debug!(
                peer = %self.peer_display_name(&node_addr),
                "Queued direct-path retry for active fallback peer"
            );
        }
    }

    /// Open-discovery cache sweep. Iterates the cached overlay adverts and
    /// queues retries for non-configured, not-yet-connected peers.
    ///
    /// `max_age_secs`, if set, filters out adverts whose `created_at` is
    /// older than `now - max_age_secs`. The per-tick sweep passes `None`
    /// (relies on the cache's own `valid_until_ms` filter); the one-shot
    /// startup sweep passes `Some(startup_sweep_max_age_secs)`.
    ///
    /// `caller` is a short label included in log lines so per-tick and
    /// startup sweeps are distinguishable in operator-facing logs.
    pub(in crate::node) async fn run_open_discovery_sweep(
        &mut self,
        bootstrap: &std::sync::Arc<NostrDiscovery>,
        max_age_secs: Option<u64>,
        caller: &'static str,
    ) {
        if !self.config.node.discovery.nostr.enabled
            || self.config.node.discovery.nostr.policy != crate::config::NostrDiscoveryPolicy::Open
        {
            return;
        }

        let configured_npubs = self
            .config
            .peers()
            .iter()
            .map(|peer| peer.npub.clone())
            .collect::<HashSet<_>>();
        let now_ms = Self::now_ms();
        let now_secs = now_ms / 1000;
        let mut enqueue_budget = self.open_discovery_enqueue_budget(&configured_npubs);
        if enqueue_budget == 0 {
            debug!(
                caller = %caller,
                "open-discovery sweep: enqueue budget is 0, skipping"
            );
            return;
        }

        let mut candidates = bootstrap.cached_open_discovery_candidates(64).await;
        if self
            .config
            .node
            .discovery
            .nostr
            .open_discovery_trust_ratings_enabled
        {
            let candidate_npubs = candidates
                .iter()
                .map(|(npub, _, _)| npub.clone())
                .collect::<Vec<_>>();
            let trust_scores = bootstrap.trust_scores_for_npubs(&candidate_npubs).await;
            candidates = order_open_discovery_candidates(
                candidates,
                &trust_scores,
                enqueue_budget,
                self.config
                    .node
                    .discovery
                    .nostr
                    .open_discovery_newcomer_probe_slots,
            );
        }
        let cached_count = candidates.len();
        let mut enqueued = 0usize;
        let mut skipped_age = 0usize;
        let mut skipped_configured = 0usize;
        let mut skipped_self = 0usize;
        let mut skipped_connected = 0usize;
        let mut skipped_retry_pending = 0usize;
        let mut skipped_connecting = 0usize;
        let mut skipped_no_endpoints = 0usize;
        let mut skipped_invalid_npub = 0usize;
        let mut skipped_cooldown = 0usize;

        for (npub, endpoints, created_at_secs) in candidates {
            if enqueue_budget == 0 {
                break;
            }

            if let Some(max_age) = max_age_secs
                && now_secs.saturating_sub(created_at_secs) > max_age
            {
                skipped_age = skipped_age.saturating_add(1);
                continue;
            }

            if configured_npubs.contains(&npub) {
                // Configured peers don't go through the open-discovery
                // enqueue path — their `PeerConfig` is already in
                // `self.config.peers()`, so the regular retry queue is
                // what drives their reconnect. But on cold start with
                // NAT'd peers, every initial `initiate_peer_connection`
                // fails (no overlay data yet, static cache hints empty
                // or stale), each pushes the peer into `retry_pending`
                // with exponential backoff (5/10/20/40/80s), and by the
                // time the next backoff slot fires the Nostr advert is
                // already cached — we just don't act on it for ~80s.
                //
                // The arrival of an advert (which this sweep sees) means
                // we now have a path to dial. If the peer's retry is
                // scheduled in the future, pull it forward to "now" so
                // the next `process_pending_retries` tick fires it
                // immediately. The retry path (`initiate_peer_retry_
                // connection` → `try_peer_addresses`) then refetches
                // the advert and dials it — no behavioral change
                // beyond schedule timing.
                if let Ok(identity) = PeerIdentity::from_npub(&npub) {
                    let configured_addr = *identity.node_addr();
                    if bootstrap.cooldown_until_peer(identity, now_ms).is_some() {
                        skipped_cooldown = skipped_cooldown.saturating_add(1);
                        skipped_configured = skipped_configured.saturating_add(1);
                        continue;
                    }
                    if let Some(state) = self.retry_pending.get_mut(&configured_addr)
                        && state.retry_after_ms > now_ms
                    {
                        state.retry_after_ms = now_ms;
                        debug!(
                            caller = %caller,
                            peer = %self.peer_display_name(&configured_addr),
                            advert_age_secs = now_secs.saturating_sub(created_at_secs),
                            "Expediting configured-peer retry after fresh overlay advert"
                        );
                    }
                }
                skipped_configured = skipped_configured.saturating_add(1);
                continue;
            }

            let peer_identity = match PeerIdentity::from_npub(&npub) {
                Ok(identity) => identity,
                Err(_) => {
                    skipped_invalid_npub = skipped_invalid_npub.saturating_add(1);
                    continue;
                }
            };
            let node_addr = *peer_identity.node_addr();
            if node_addr == *self.identity.node_addr() {
                skipped_self = skipped_self.saturating_add(1);
                continue;
            }
            if self.peers.contains_key(&node_addr) {
                skipped_connected = skipped_connected.saturating_add(1);
                continue;
            }
            if self.retry_pending.contains_key(&node_addr) {
                skipped_retry_pending = skipped_retry_pending.saturating_add(1);
                continue;
            }
            if bootstrap
                .cooldown_until_peer(peer_identity, now_ms)
                .is_some()
            {
                skipped_cooldown = skipped_cooldown.saturating_add(1);
                continue;
            }
            let connecting = self.peers.connection_values().any(|conn| {
                conn.expected_identity()
                    .map(|id| id.node_addr() == &node_addr)
                    .unwrap_or(false)
            });
            if connecting {
                skipped_connecting = skipped_connecting.saturating_add(1);
                continue;
            }

            let mut addresses = Vec::new();
            let mut priority = 120u8;
            let seen_at_ms = Self::now_ms();
            for endpoint in endpoints {
                let Some(candidate) =
                    Self::overlay_endpoint_to_peer_address(&endpoint, priority, seen_at_ms)
                else {
                    continue;
                };
                if addresses.iter().any(|existing: &PeerAddress| {
                    existing.transport == candidate.transport && existing.addr == candidate.addr
                }) {
                    continue;
                }
                addresses.push(candidate);
                priority = priority.saturating_add(1);
            }
            if addresses.is_empty() {
                skipped_no_endpoints = skipped_no_endpoints.saturating_add(1);
                continue;
            }

            self.peer_aliases
                .entry(node_addr)
                .or_insert_with(|| peer_identity.short_npub());
            self.register_identity(node_addr, peer_identity.pubkey_full());

            let mut state = crate::node::retry::RetryState::new(PeerConfig {
                npub: npub.clone(),
                alias: None,
                addresses,
                connect_policy: ConnectPolicy::AutoConnect,
                auto_reconnect: true,
                discovery_fallback_transit: false,
            });
            state.reconnect = false;
            state.retry_after_ms = now_ms;
            state.expires_at_ms = Some(self.open_discovery_retry_expires_at_ms(now_ms));
            self.retry_pending.insert(node_addr, state);
            info!(
                caller = %caller,
                peer = %peer_identity.short_npub(),
                advert_age_secs = now_secs.saturating_sub(created_at_secs),
                "open-discovery sweep: queued retry for cached advert"
            );
            enqueue_budget = enqueue_budget.saturating_sub(1);
            enqueued = enqueued.saturating_add(1);
        }

        // Always log a one-line summary on the startup sweep so operators
        // can verify it ran. Per-tick sweeps are noisier; only summarize
        // when something happened.
        let total_skipped = skipped_age
            + skipped_configured
            + skipped_self
            + skipped_connected
            + skipped_retry_pending
            + skipped_connecting
            + skipped_no_endpoints
            + skipped_invalid_npub
            + skipped_cooldown;
        let should_summarize = caller == "startup" || enqueued > 0;
        if should_summarize {
            info!(
                caller = %caller,
                cached = cached_count,
                queued = enqueued,
                skipped_age = skipped_age,
                skipped_configured = skipped_configured,
                skipped_self = skipped_self,
                skipped_connected = skipped_connected,
                skipped_retry_pending = skipped_retry_pending,
                skipped_connecting = skipped_connecting,
                skipped_no_endpoints = skipped_no_endpoints,
                skipped_invalid_npub = skipped_invalid_npub,
                skipped_cooldown = skipped_cooldown,
                skipped_total = total_skipped,
                "open-discovery sweep complete"
            );
        }
    }

    /// One-shot startup sweep: runs once after the configured settle
    /// delay, iterating the cached overlay adverts and queueing retries
    /// for any peer with a recent enough advert that we haven't already
    /// configured statically or established a link to.
    ///
    /// Gated identically to [`run_open_discovery_sweep`]: requires
    /// `node.discovery.nostr.enabled` and `policy == open`.
    pub(super) async fn maybe_run_startup_open_discovery_sweep(
        &mut self,
        bootstrap: &std::sync::Arc<NostrDiscovery>,
    ) {
        if self.startup_open_discovery_sweep_done {
            return;
        }
        if !self.config.node.discovery.nostr.enabled
            || self.config.node.discovery.nostr.policy != crate::config::NostrDiscoveryPolicy::Open
        {
            // Mark done so we don't keep re-checking on every tick.
            self.startup_open_discovery_sweep_done = true;
            return;
        }
        let Some(started_at_ms) = self.nostr_discovery_started_at_ms else {
            return;
        };
        let now_ms = Self::now_ms();
        let delay_ms = self
            .config
            .node
            .discovery
            .nostr
            .startup_sweep_delay_secs
            .saturating_mul(1000);
        if now_ms < started_at_ms.saturating_add(delay_ms) {
            return;
        }

        let max_age_secs = self.config.node.discovery.nostr.startup_sweep_max_age_secs;
        self.run_open_discovery_sweep(bootstrap, Some(max_age_secs), "startup")
            .await;
        self.startup_open_discovery_sweep_done = true;
    }

    pub(super) fn available_outbound_slots(&self) -> usize {
        let connection_used = self
            .peers
            .connection_len()
            .saturating_add(self.pending_connects.len());
        let connection_slots = if self.max_connections == 0 {
            usize::MAX
        } else {
            self.max_connections.saturating_sub(connection_used)
        };

        let peer_slots = if self.max_peers == 0 {
            usize::MAX
        } else {
            self.max_peers.saturating_sub(self.peers.len())
        };

        let link_slots = if self.max_links == 0 {
            usize::MAX
        } else {
            self.max_links.saturating_sub(self.links.len())
        };

        connection_slots.min(peer_slots).min(link_slots)
    }

    pub(in crate::node) fn open_discovery_enqueue_budget(
        &self,
        configured_npubs: &HashSet<String>,
    ) -> usize {
        let current_open_discovery_active = self
            .peers
            .values()
            .filter(|peer| !configured_npubs.contains(&peer.npub()))
            .count();
        let current_open_discovery_pending = self
            .retry_pending
            .values()
            .filter(|state| !configured_npubs.contains(&state.peer_config.npub))
            .count();

        let cap_remaining = self
            .config
            .node
            .discovery
            .nostr
            .open_discovery_max_pending
            .saturating_sub(current_open_discovery_active)
            .saturating_sub(current_open_discovery_pending);

        cap_remaining.min(self.available_outbound_slots())
    }

    pub(super) fn open_discovery_retry_expires_at_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_add(
            self.config
                .node
                .discovery
                .nostr
                .advert_ttl_secs
                .saturating_mul(1000)
                .saturating_mul(OPEN_DISCOVERY_RETRY_LIFETIME_MULTIPLIER),
        )
    }

    pub(super) async fn build_overlay_advert(
        &self,
        bootstrap: &std::sync::Arc<NostrDiscovery>,
    ) -> Option<OverlayAdvert> {
        if !self.config.node.discovery.nostr.enabled {
            return None;
        }

        let mut endpoints = Vec::new();
        let mut has_udp_nat = false;
        let mut has_webrtc = false;

        for handle in self.transports.values() {
            if !handle.is_operational() {
                continue;
            }

            match handle.transport_type().name {
                "udp" => {
                    let Some(cfg) = self.lookup_udp_config(handle.name()) else {
                        continue;
                    };
                    if !cfg.advertise_on_nostr() {
                        continue;
                    }
                    if cfg.is_public() {
                        // Precedence:
                        // 1. operator-supplied `external_addr` (skips STUN)
                        // 2. non-wildcard *public* `local_addr` (operator
                        //    bound to a specific public IP directly)
                        // 3. STUN auto-discovery against ephemeral socket
                        //    (also taken when bind is wildcard *or* private —
                        //    a private bind is not peer-reachable, so we
                        //    must publish the public reflexive instead)
                        // 4. loud warn + omit endpoint
                        if let Some(explicit) = cfg.external_advert_addr() {
                            endpoints.push(OverlayEndpointAdvert {
                                transport: OverlayTransportKind::Udp,
                                addr: explicit.to_string(),
                            });
                        } else {
                            match handle.local_addr() {
                                Some(addr)
                                    if !addr.ip().is_unspecified()
                                        && !is_unroutable_advert_ip(addr.ip()) =>
                                {
                                    endpoints.push(OverlayEndpointAdvert {
                                        transport: OverlayTransportKind::Udp,
                                        addr: addr.to_string(),
                                    });
                                }
                                Some(addr) => {
                                    let key = handle.transport_id().as_u32();
                                    let port = addr.port();
                                    if let Some(public) =
                                        bootstrap.learn_public_udp_addr(key, port).await
                                    {
                                        endpoints.push(OverlayEndpointAdvert {
                                            transport: OverlayTransportKind::Udp,
                                            addr: public.to_string(),
                                        });
                                    } else {
                                        warn!(
                                            transport_id = key,
                                            bind_addr = %addr,
                                            "advert: udp public=true but bind is wildcard \
                                            or private and STUN observation failed; \
                                            advertising no UDP endpoint. Either set \
                                            transports.udp.external_addr, bind to a \
                                            specific *public* IP, or ensure \
                                            node.discovery.nostr.stun_servers is reachable"
                                        );
                                    }
                                }
                                None => {}
                            }
                        }
                    } else {
                        endpoints.push(OverlayEndpointAdvert {
                            transport: OverlayTransportKind::Udp,
                            addr: "nat".to_string(),
                        });
                        has_udp_nat = true;
                    }
                }
                "webrtc" => {
                    let Some(cfg) = self.lookup_webrtc_config(handle.name()) else {
                        continue;
                    };
                    if !cfg.advertise_on_nostr() {
                        continue;
                    }
                    endpoints.push(OverlayEndpointAdvert {
                        transport: OverlayTransportKind::WebRtc,
                        addr: hex::encode(self.identity.pubkey_full().serialize()),
                    });
                    has_webrtc = true;
                }
                "tcp" => {
                    let Some(cfg) = self.lookup_tcp_config(handle.name()) else {
                        continue;
                    };
                    if !cfg.advertise_on_nostr() {
                        continue;
                    }
                    // Precedence:
                    // 1. operator-supplied `external_addr` (only path that
                    //    works on cloud-NAT setups where the public IP is
                    //    not on a host interface).
                    // 2. non-wildcard *public* `local_addr` (operator bound
                    //    to a specific public IP directly).
                    // 3. loud warn + omit endpoint (no TCP STUN equivalent).
                    //
                    // A wildcard *or* private bind is never advertised as-is
                    // — peers off-LAN can't reach a private bind, and there
                    // is no TCP STUN to discover a public reflexive.
                    if let Some(explicit) = cfg.external_advert_addr() {
                        endpoints.push(OverlayEndpointAdvert {
                            transport: OverlayTransportKind::Tcp,
                            addr: explicit.to_string(),
                        });
                    } else {
                        match handle.local_addr() {
                            Some(addr)
                                if !addr.ip().is_unspecified()
                                    && !is_unroutable_advert_ip(addr.ip()) =>
                            {
                                endpoints.push(OverlayEndpointAdvert {
                                    transport: OverlayTransportKind::Tcp,
                                    addr: addr.to_string(),
                                });
                            }
                            Some(addr) => {
                                warn!(
                                    bind_addr = %addr,
                                    "advert: tcp advertise_on_nostr=true bound to wildcard \
                                    or private IP and no transports.tcp.external_addr set; \
                                    advertising no TCP endpoint. Either set external_addr \
                                    to the public IP (recommended for cloud 1:1-NAT setups) \
                                    or bind explicitly to the public IP"
                                );
                            }
                            None => {}
                        }
                    }
                }
                "tor" => {
                    let Some(cfg) = self.lookup_tor_config(handle.name()) else {
                        continue;
                    };
                    if !cfg.advertise_on_nostr() {
                        continue;
                    }
                    if let Some(addr) = handle.onion_address() {
                        endpoints.push(OverlayEndpointAdvert {
                            transport: OverlayTransportKind::Tor,
                            addr: format!("{}:{}", addr, cfg.advertised_port()),
                        });
                    }
                }
                _ => {}
            }
        }

        if endpoints.is_empty() {
            return None;
        }

        Some(OverlayAdvert {
            identifier: ADVERT_IDENTIFIER.to_string(),
            version: ADVERT_VERSION,
            endpoints,
            signal_relays: (has_udp_nat || has_webrtc)
                .then(|| self.config.node.discovery.nostr.dm_relays.clone()),
            stun_servers: (has_udp_nat || has_webrtc)
                .then(|| self.config.node.discovery.nostr.stun_servers.clone()),
        })
    }

    pub(super) async fn refresh_overlay_advert(
        &self,
        bootstrap: &std::sync::Arc<NostrDiscovery>,
    ) -> Result<(), crate::discovery::nostr::BootstrapError> {
        let advert = self.build_overlay_advert(bootstrap).await;
        bootstrap.update_local_advert(advert).await
    }

    pub(super) fn lookup_udp_config(
        &self,
        transport_name: Option<&str>,
    ) -> Option<&crate::config::UdpConfig> {
        match (&self.config.transports.udp, transport_name) {
            (crate::config::TransportInstances::Single(cfg), None) => Some(cfg),
            (crate::config::TransportInstances::Named(configs), Some(name)) => configs.get(name),
            _ => None,
        }
    }

    pub(super) fn lookup_tcp_config(
        &self,
        transport_name: Option<&str>,
    ) -> Option<&crate::config::TcpConfig> {
        match (&self.config.transports.tcp, transport_name) {
            (crate::config::TransportInstances::Single(cfg), None) => Some(cfg),
            (crate::config::TransportInstances::Named(configs), Some(name)) => configs.get(name),
            _ => None,
        }
    }

    pub(super) fn lookup_tor_config(
        &self,
        transport_name: Option<&str>,
    ) -> Option<&crate::config::TorConfig> {
        match (&self.config.transports.tor, transport_name) {
            (crate::config::TransportInstances::Single(cfg), None) => Some(cfg),
            (crate::config::TransportInstances::Named(configs), Some(name)) => configs.get(name),
            _ => None,
        }
    }

    pub(super) fn lookup_webrtc_config(
        &self,
        transport_name: Option<&str>,
    ) -> Option<&crate::config::WebRtcConfig> {
        match (&self.config.transports.webrtc, transport_name) {
            (crate::config::TransportInstances::Single(cfg), None) => Some(cfg),
            (crate::config::TransportInstances::Named(configs), Some(name)) => configs.get(name),
            _ => None,
        }
    }
}

fn order_open_discovery_candidates(
    candidates: Vec<OpenDiscoveryCandidate>,
    trust_scores: &std::collections::HashMap<String, i64>,
    enqueue_budget: usize,
    newcomer_probe_slots: usize,
) -> Vec<OpenDiscoveryCandidate> {
    if candidates.len() <= 1 || enqueue_budget == 0 {
        return candidates;
    }

    let mut positive = Vec::new();
    let mut unknown = Vec::new();
    let mut negative = Vec::new();
    for candidate in candidates {
        match trust_scores.get(&candidate.0).copied() {
            Some(score) if score > 0 => positive.push((score, candidate)),
            Some(score) if score < 0 => negative.push((score, candidate)),
            _ => unknown.push(candidate),
        }
    }

    positive.sort_by(|(left_score, left), (right_score, right)| {
        right_score
            .cmp(left_score)
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| left.0.cmp(&right.0))
    });
    unknown.sort_by(|left, right| right.2.cmp(&left.2).then_with(|| left.0.cmp(&right.0)));
    negative.sort_by(|(left_score, left), (right_score, right)| {
        right_score
            .cmp(left_score)
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| left.0.cmp(&right.0))
    });

    let reserved_newcomers = newcomer_probe_slots.min(enqueue_budget).min(unknown.len());
    let trusted_slots = enqueue_budget.saturating_sub(reserved_newcomers);

    let mut ordered = Vec::new();
    let mut positive = positive.into_iter();
    for _ in 0..trusted_slots {
        let Some((_, candidate)) = positive.next() else {
            break;
        };
        ordered.push(candidate);
    }
    let mut unknown = unknown.into_iter();
    for _ in 0..reserved_newcomers {
        let Some(candidate) = unknown.next() else {
            break;
        };
        ordered.push(candidate);
    }
    ordered.extend(positive.map(|(_, candidate)| candidate));
    ordered.extend(unknown);
    ordered.extend(negative.into_iter().map(|(_, candidate)| candidate));
    ordered
}
