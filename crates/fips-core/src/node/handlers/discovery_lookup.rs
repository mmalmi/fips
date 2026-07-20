impl Node {
    /// Initiate a discovery lookup for a target node.
    ///
    /// Creates a LookupRequest and sends it to tree peers whose bloom
    /// filters contain the target. Returns the number of peers sent to.
    /// The originator does NOT record the request_id in recent_requests,
    /// so when the response arrives, it's recognized as "our request".
    pub(in crate::node) async fn initiate_lookup(&mut self, target: &NodeAddr, ttl: u8) -> usize {
        self.stats_mut().discovery.req_initiated += 1;

        let origin = *self.node_addr();
        let origin_coords = self.tree_state().my_coords().clone();
        let request = LookupRequest::generate(*target, origin, origin_coords, ttl, 0);

        let candidates = self.lookup_peer_candidates(target);
        let reply_learned_fallback_enabled = self.config.node.routing.mode
            == RoutingMode::ReplyLearned
            && self.should_use_reply_learned_lookup_fallback_for_target(target);
        let plan = plan_initiate_peers(
            self.config.node.routing.mode,
            reply_learned_fallback_enabled,
            &candidates,
            MAX_REPLY_LEARNED_EXTRA_LOOKUP_PEERS,
        );
        let peer_addrs = plan.peers;

        let peer_count = peer_addrs.len();

        debug!(
            target = %self.peer_display_name(target),
            candidates = ?candidates
                .iter()
                .map(|candidate| (
                    self.peer_display_name(&candidate.addr),
                    candidate.can_send,
                    candidate.is_healthy,
                    candidate.is_tree_peer,
                    candidate.may_reach_target,
                    candidate.reply_learned_fallback_allowed,
                ))
                .collect::<Vec<_>>(),
            selected = ?peer_addrs
                .iter()
                .map(|peer| self.peer_display_name(peer))
                .collect::<Vec<_>>(),
            "Discovery lookup peer plan"
        );

        info!(
                request_id = request.request_id,
                target = %self.peer_display_name(target),
                ttl = ttl,
                peer_count = peer_count,
                total_peers = self.peers.len(),
            fallback = plan.used_fallback,
            "Discovery lookup initiated"
        );

        if peer_count == 0 {
            return 0;
        }

        let encoded = request.encode();

        for peer_addr in peer_addrs {
            if let Err(e) = self
                .send_dataplane_fmp_link_plaintext(&peer_addr, &encoded, false)
                .await
            {
                debug!(
                    peer = %self.peer_display_name(&peer_addr),
                    error = %e,
                    "Failed to send LookupRequest to peer"
                );
            }
        }

        peer_count
    }

    fn should_use_reply_learned_lookup_fallback_peer(
        &self,
        peer_addr: &NodeAddr,
        peer: &crate::peer::ActivePeer,
        target: &NodeAddr,
    ) -> bool {
        // A full `.fips` name is an explicit, locally authenticated target
        // selection. Let that lookup leave over any established physical
        // adjacency, including an Open-discovery adjacency that is otherwise
        // excluded from ambient fallback transit.
        if self.is_dns_resolved_identity(target) {
            return true;
        }

        // An explicitly configured transit peer remains an operator-selected
        // physical router when its direct UDP path was established through
        // authenticated NAT traversal. `bootstrap_transports` distinguishes
        // ephemeral adopted sockets from ordinary listeners, but it must not
        // override an explicit per-peer transit grant.
        if self.configured_discovery_fallback_transit(peer_addr) == Some(true) {
            return true;
        }

        self.discovery_fallback_transit.allows_lookup_fallback_peer(
            peer_addr,
            target,
            peer.transport_id(),
            |transport_id| self.bootstrap_transports.contains(&transport_id),
        )
    }

    fn should_use_reply_learned_lookup_fallback_for_origin_target(
        &self,
        from: &NodeAddr,
        origin: &NodeAddr,
        target: &NodeAddr,
    ) -> bool {
        let nostr = &self.config.node.discovery.nostr;
        match nostr.policy {
            crate::config::NostrDiscoveryPolicy::Open => {
                // A configured WebSocket listener is an operator-selected
                // physical router. Let its authenticated clients find one
                // another without treating ambient Open-discovery peers as
                // fallback transit.
                (self.configured_discovery_fallback_transit(origin).is_some()
                    && self.configured_discovery_fallback_transit(target).is_some())
                    || self.peer_is_configured_websocket_adjacency(from)
            }
            crate::config::NostrDiscoveryPolicy::ConfiguredOnly if nostr.enabled => {
                self.configured_discovery_fallback_transit(origin).is_some()
                    && self.configured_discovery_fallback_transit(target).is_some()
            }
            crate::config::NostrDiscoveryPolicy::ConfiguredOnly
            | crate::config::NostrDiscoveryPolicy::Disabled => true,
        }
    }

    fn should_use_reply_learned_lookup_fallback_for_target(&self, target: &NodeAddr) -> bool {
        let nostr = &self.config.node.discovery.nostr;
        match nostr.policy {
            crate::config::NostrDiscoveryPolicy::Open => {
                self.configured_discovery_fallback_transit(target).is_some()
                    || self.is_dns_resolved_identity(target)
            }
            crate::config::NostrDiscoveryPolicy::ConfiguredOnly if nostr.enabled => {
                self.configured_discovery_fallback_transit(target).is_some()
                    || self.is_dns_resolved_identity(target)
            }
            crate::config::NostrDiscoveryPolicy::ConfiguredOnly
            | crate::config::NostrDiscoveryPolicy::Disabled => true,
        }
    }

    /// Initiate a discovery lookup if one is not already pending for this target.
    ///
    /// Checks: pending dedup, post-failure backoff (off by default), bloom
    /// filter pre-check. If all pass, sends the first attempt's LookupRequest.
    /// Subsequent attempts (with fresh request_ids) are scheduled by
    /// [`Self::check_pending_lookups`] when each attempt's per-attempt timeout
    /// expires, using the sequence in `node.discovery.attempt_timeouts_secs`.
    pub(in crate::node) async fn maybe_initiate_lookup(&mut self, dest: &NodeAddr) {
        let now_ms = Self::now_ms();

        let max_pending = self.config.node.session.pending_max_destinations;
        let admission = self.pending_lookups.admission_for(dest, max_pending);
        if admission.deduplicated() {
            self.stats_mut().discovery.req_deduplicated += 1;
            debug!(
                target_node = %self.peer_display_name(dest),
                "Discovery lookup deduplicated, already pending"
            );
            return;
        }

        if admission.queue_full() {
            debug!(
                target_node = %self.peer_display_name(dest),
                max_pending,
                "Discovery lookup suppressed, pending lookup queue full"
            );
            return;
        }
        if !admission.accepted() {
            return;
        }

        // Post-failure suppression stops offline destinations from triggering
        // a fresh network-wide discovery cycle immediately after timeout.
        // Operators can disable it by setting both backoff values to 0.
        if self.discovery_backoff.is_suppressed(dest) {
            self.stats_mut().discovery.req_backoff_suppressed += 1;
            debug!(
                target_node = %self.peer_display_name(dest),
                failures = self.discovery_backoff.failure_count(dest),
                "Discovery lookup suppressed by backoff"
            );
            return;
        }

        // Bloom filter pre-check: original routing skips if no peer's filter
        // contains the target. Reply-learned mode intentionally allows a
        // first-contact tree flood when bloom reachability is missing.
        let reachable = self.peers.values().any(|peer| peer.may_reach(dest));
        if !reachable && self.config.node.routing.mode != RoutingMode::ReplyLearned {
            self.stats_mut().discovery.req_bloom_miss += 1;
            self.discovery_backoff.record_failure(dest);
            debug!(
                target_node = %self.peer_display_name(dest),
                "Discovery skipped, target not in any peer bloom filter"
            );
            return;
        }

        self.pending_lookups.insert_new(*dest, now_ms);
        let ttl = self.config.node.discovery.ttl;
        let sent = self.initiate_lookup(dest, ttl).await;

        // If no peer was eligible, no LookupRequest left this node. Treat it as
        // topology not warm yet rather than a destination failure; startup can
        // race the first endpoint-data/control ping ahead of transit handshakes.
        if sent == 0 {
            self.pending_lookups.remove(dest);
            debug!(
                target_node = %self.peer_display_name(dest),
                "Discovery deferred, no eligible lookup peers"
            );
        }
    }

    /// Initiate discovery after an established payload path becomes suspect.
    ///
    /// This is narrower than first-contact discovery: if there is no alternate
    /// mesh neighbor that could carry a fallback route, asking the direct peer
    /// about itself only churns control traffic and cannot improve routing.
    pub(in crate::node) async fn maybe_initiate_path_recovery_lookup(&mut self, dest: &NodeAddr) {
        if !self.has_sendable_fallback_lookup_peer(dest) {
            debug!(
                target_node = %self.peer_display_name(dest),
                "Skipping path-recovery lookup, no sendable fallback peer"
            );
            return;
        }

        if self.retry_pending.contains_key(dest) {
            self.maybe_initiate_direct_path_fallback_lookup(dest).await;
        } else {
            self.maybe_initiate_lookup(dest).await;
        }
    }

    pub(in crate::node) fn has_sendable_fallback_lookup_peer(&self, dest: &NodeAddr) -> bool {
        self.peers.iter().any(|(addr, peer)| {
            *addr != *dest
                && peer.can_send()
                && (self.config.node.routing.mode != RoutingMode::ReplyLearned
                    || self.should_use_reply_learned_lookup_fallback_peer(addr, peer, dest))
        })
    }

    /// Ask existing mesh neighbors for a route after a direct path becomes suspect.
    ///
    /// MMP link-dead is evidence about the selected path, not proof that the
    /// peer is unreachable. Direct retry state is scheduled separately; this
    /// lookup keeps fallback routing warm so traffic can move through a live
    /// transit peer while UDP candidates keep being re-probed.
    pub(in crate::node) async fn maybe_initiate_direct_path_fallback_lookup(
        &mut self,
        dest: &NodeAddr,
    ) {
        if !self.retry_pending.contains_key(dest) {
            return;
        }

        if !self.has_sendable_fallback_lookup_peer(dest) {
            debug!(
                target_node = %self.peer_display_name(dest),
                "Skipping direct-path fallback lookup, no sendable fallback peer"
            );
            return;
        }

        self.discovery_backoff.record_success(dest);

        if self.find_next_hop(dest).is_some()
            && !self
                .sessions
                .get(dest)
                .is_some_and(|entry| entry.is_established() || entry.is_initiating())
        {
            if let Some(pubkey) = self.pubkey_for_node_addr(dest) {
                match self.initiate_session(*dest, pubkey).await {
                    Ok(()) => {
                        debug!(
                            target_node = %self.peer_display_name(dest),
                            "Warmed fallback session after suspect direct path"
                        );
                        return;
                    }
                    Err(NodeError::SendFailed { node_addr, reason })
                        if node_addr == *dest && reason == "no route to destination" =>
                    {
                        debug!(
                            target_node = %self.peer_display_name(dest),
                            "Fallback route disappeared while warming direct-path fallback session"
                        );
                    }
                    Err(error) => {
                        debug!(
                            target_node = %self.peer_display_name(dest),
                            error = %error,
                            "Failed to warm fallback session after suspect direct path"
                        );
                    }
                }
            } else {
                debug!(
                    target_node = %self.peer_display_name(dest),
                    "Cannot warm fallback session after suspect direct path without cached identity"
                );
            }
        }

        self.maybe_initiate_lookup(dest).await;
    }

    /// Check pending lookups for next-attempt or final timeout.
    ///
    /// Called periodically from the tick handler. The lookup state machine
    /// runs through `node.discovery.attempt_timeouts_secs` (default
    /// `[1, 2, 4, 8]`): each entry is the deadline for one attempt. When the
    /// current attempt's deadline elapses:
    /// - If more entries remain: send the next attempt with a fresh
    ///   `request_id`.
    /// - Otherwise: if an FSP handshake owns the destination, stop discovery
    ///   and let the handshake lifecycle retain or time out its queued traffic.
    /// - Without an FSP handshake: declare the destination unreachable, drop
    ///   queued packets, and emit ICMPv6 destination-unreachable for each.
    pub(in crate::node) async fn check_pending_lookups(&mut self, now_ms: u64) {
        let timeouts = self.config.node.discovery.attempt_timeouts_secs.clone();
        let max_attempts = timeouts.len() as u8;

        // Collect targets needing action
        let mut to_complete: Vec<NodeAddr> = Vec::new();
        let mut to_retry: Vec<NodeAddr> = Vec::new();
        let mut to_session_handshake: Vec<NodeAddr> = Vec::new();
        let mut to_timeout: Vec<NodeAddr> = Vec::new();

        for (&target, entry) in self.pending_lookups.iter() {
            if self
                .sessions
                .get(&target)
                .is_some_and(|entry| entry.is_established())
            {
                to_complete.push(target);
                continue;
            }
            let attempt_idx = (entry.attempt as usize).saturating_sub(1);
            let attempt_timeout_ms = timeouts.get(attempt_idx).copied().unwrap_or(0) * 1000;
            if now_ms.saturating_sub(entry.last_sent_ms) >= attempt_timeout_ms {
                if entry.attempt >= max_attempts {
                    if self
                        .sessions
                        .get(&target)
                        .is_some_and(|session| !session.is_established())
                    {
                        to_session_handshake.push(target);
                    } else {
                        to_timeout.push(target);
                    }
                } else {
                    to_retry.push(target);
                }
            }
        }

        for target in to_complete {
            self.pending_lookups.remove(&target);
            self.discovery_backoff.record_success(&target);
            debug!(
                target_node = %self.peer_display_name(&target),
                "Discovery lookup completed by established session"
            );
        }

        for target in to_session_handshake {
            self.pending_lookups.remove(&target);
            debug!(
                target_node = %self.peer_display_name(&target),
                "Discovery lookup exhausted while FSP handshake retains queued traffic"
            );
        }

        // Process retries
        for target in to_retry {
            if let Some(entry) = self.pending_lookups.get_mut(&target) {
                entry.attempt += 1;
                entry.last_sent_ms = now_ms;
                let attempt = entry.attempt;

                let ttl = self.config.node.discovery.ttl;
                let sent = self.initiate_lookup(&target, ttl).await;
                if sent > 0 {
                    info!(
                        target_node = %self.peer_display_name(&target),
                        attempt = attempt,
                        "Discovery retry sent"
                    );
                }
            }
        }

        // Process timeouts
        for addr in to_timeout {
            self.stats_mut().discovery.resp_timed_out += 1;
            self.pending_lookups.remove(&addr);

            // Record failure for optional backoff
            self.discovery_backoff.record_failure(&addr);
            let failures = self.discovery_backoff.failure_count(&addr);

            let queued = self.pending_session_traffic.remove_destination(&addr);
            let pkt_count = queued.tun_packets().map_or(0, |p| p.len());
            let endpoint_count = queued.endpoint_data().map_or(0, |p| p.len());
            info!(
                target_node = %self.peer_display_name(&addr),
                queued_packets = pkt_count,
                queued_endpoint_payloads = endpoint_count,
                failures = failures,
                "Discovery lookup timed out, destination unreachable"
            );
            if let Some(packets) = queued.into_tun_packets() {
                for pkt in packets.into_packets() {
                    self.send_icmpv6_dest_unreachable(&pkt);
                }
            }
        }
    }

    /// Reset discovery backoff on topology changes.
    pub(in crate::node) fn reset_discovery_backoff(&mut self) {
        if !self.discovery_backoff.is_empty() {
            debug!(
                entries = self.discovery_backoff.entry_count(),
                "Resetting discovery backoff on topology change"
            );
            self.discovery_backoff.reset_all();
        }
    }

    /// Remove expired entries from the recent_requests cache.
    fn purge_expired_requests(&mut self, current_time_ms: u64) {
        let expiry_ms = self.config.node.discovery.recent_expiry_secs * 1000;
        self.recent_requests
            .purge_expired(current_time_ms, expiry_ms);
    }

    /// Min-fold our outgoing-link MTU into a LookupResponse's `path_mtu`.
    ///
    /// Used at both transit-side reverse-path forward and at the target's
    /// own send_lookup_response. The link MTU we apply is the MTU of the
    /// transport+addr we'll use to deliver the response toward `next_hop`.
    /// No-op when `next_hop` is not a directly-connected peer or its
    /// transport is not registered.
    pub(in crate::node) fn apply_outgoing_link_mtu_to_response(
        &self,
        response: &mut LookupResponse,
        next_hop: &NodeAddr,
    ) {
        if let Some(peer) = self.peers.get(next_hop)
            && let Some(tid) = peer.transport_id()
            && let Some(transport) = self.transports.get(&tid)
        {
            let link_mtu = if let Some(addr) = peer.current_addr() {
                transport.link_mtu(addr)
            } else {
                transport.mtu()
            };
            response.path_mtu = response.path_mtu.min(link_mtu);
        }
    }

    /// Seed `path_mtu_lookup` for a directly-connected peer.
    ///
    /// Called when an FMP link-layer peer is promoted to active. The seed
    /// value is the local outgoing-link MTU on the peer's transport, which
    /// is the actual link constraint for direct-link traffic. Stored only
    /// when no tighter value exists: discovery's reverse-path bottleneck
    /// or MMP `MtuExceeded` reactive learning take precedence when smaller.
    ///
    /// Without this seed, configured/auto-connect peers (which establish
    /// sessions without going through the discovery Lookup flow) leave
    /// `path_mtu_lookup` empty for their FipsAddress, causing
    /// `per_flow_max_mss` to fall back to the global ceiling and the
    /// SYN-time TCP MSS clamp to over-estimate the effective path.
    pub(in crate::node) fn seed_path_mtu_for_link_peer(
        &self,
        peer_addr: &NodeAddr,
        transport_id: TransportId,
        addr: &TransportAddr,
    ) {
        let Some(transport) = self.transports.get(&transport_id) else {
            debug!(
                peer = %self.peer_display_name(peer_addr),
                transport_id = %transport_id,
                "seed_path_mtu_for_link_peer: transport not registered, skipping seed"
            );
            return;
        };
        let link_mtu = transport.link_mtu(addr);
        let fips_addr = crate::FipsAddress::from_node_addr(peer_addr);
        let Ok(mut map) = self.path_mtu_lookup.write() else {
            warn!(
                peer = %self.peer_display_name(peer_addr),
                "seed_path_mtu_for_link_peer: path_mtu_lookup write lock poisoned"
            );
            return;
        };
        match map.get(&fips_addr).copied() {
            Some(existing) if existing <= link_mtu => {
                // Keep the tighter learned value; never loosen the clamp.
                debug!(
                    peer = %self.peer_display_name(peer_addr),
                    fips_addr = %fips_addr,
                    link_mtu = link_mtu,
                    existing = existing,
                    "seed_path_mtu_for_link_peer: keeping tighter existing value"
                );
            }
            other => {
                map.insert(fips_addr, link_mtu);
                debug!(
                    peer = %self.peer_display_name(peer_addr),
                    fips_addr = %fips_addr,
                    link_mtu = link_mtu,
                    prior = ?other,
                    map_len = map.len(),
                    "seed_path_mtu_for_link_peer: wrote link MTU"
                );
            }
        }
    }
}
