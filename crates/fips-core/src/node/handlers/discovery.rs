//! LookupRequest/LookupResponse discovery protocol handlers.
//!
//! Handles coordinate discovery via bloom-filter-guided tree routing.
//! Requests are forwarded only to tree peers (parent + children) whose
//! bloom filter contains the target. TTL and request_id dedup provide
//! safety bounds.

use crate::config::RoutingMode;
use crate::node::{Node, RecentResponseForward};
use crate::proto::lookup::{LookupPeerCandidate, plan_forward_peers, plan_initiate_peers};
use crate::protocol::{LookupRequest, LookupResponse};
use crate::transport::{TransportAddr, TransportId};
use crate::{NodeAddr, NodeError, PeerIdentity};
use tracing::{debug, info, trace, warn};

const MAX_RECENT_DISCOVERY_REQUESTS: usize = 4096;
const MAX_REPLY_LEARNED_EXTRA_LOOKUP_PEERS: usize = 16;

enum LookupForwardOutcome {
    Forwarded,
    RateLimited,
    NoPeer,
}

mod pending_lookup;

pub(crate) use pending_lookup::PendingDiscoveryLookups;
pub use pending_lookup::PendingLookup;

impl Node {
    /// Handle an incoming LookupRequest from a peer.
    ///
    /// Processing steps:
    /// 1. Decode and validate
    /// 2. Check request_id for duplicates (dedup / reverse-path routing)
    /// 3. Record request for reverse-path forwarding
    /// 4. Lazy purge expired entries
    /// 5. If we're the target, generate and send response
    /// 6. If TTL > 0, forward to tree peers whose bloom filter matches
    pub(in crate::node) async fn handle_lookup_request(&mut self, from: &NodeAddr, payload: &[u8]) {
        self.stats_mut().discovery.req_received += 1;

        let request = match LookupRequest::decode(payload) {
            Ok(req) => req,
            Err(e) => {
                self.stats_mut().discovery.req_decode_error += 1;
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed LookupRequest");
                return;
            }
        };

        let now_ms = Self::now_ms();
        self.purge_expired_requests(now_ms);

        // Dedup: drop if we've already seen this request_id.
        // Also serves as loop protection — tree routing is loop-free,
        // but request_id dedup catches edge cases during tree restructuring.
        let admission = self.recent_requests.record_request(
            request.request_id,
            *from,
            now_ms,
            MAX_RECENT_DISCOVERY_REQUESTS,
        );
        if admission.deduplicated() {
            self.stats_mut().discovery.req_duplicate += 1;
            debug!(
                request_id = request.request_id,
                from = %self.peer_display_name(from),
                "Duplicate LookupRequest, dropping"
            );
            return;
        }

        if admission.cache_full() {
            debug!(
                request_id = request.request_id,
                from = %self.peer_display_name(from),
                recent_requests = self.recent_requests.len(),
                max_recent_requests = MAX_RECENT_DISCOVERY_REQUESTS,
                "Discovery request dedup cache full, dropping LookupRequest"
            );
            return;
        }
        if !admission.accepted() {
            return;
        }

        // Are we the target?
        if request.target == *self.node_addr() {
            self.stats_mut().discovery.req_target_is_us += 1;
            debug!(
                request_id = request.request_id,
                origin = %self.peer_display_name(&request.origin),
                "We are the lookup target, generating response"
            );
            self.send_lookup_response(&request).await;
            return;
        }

        // Forward if TTL permits
        if request.can_forward() {
            match self.forward_lookup_request(from, request).await {
                LookupForwardOutcome::Forwarded => {
                    self.stats_mut().discovery.req_forwarded += 1;
                }
                LookupForwardOutcome::RateLimited => {
                    self.stats_mut().discovery.req_forward_rate_limited += 1;
                }
                LookupForwardOutcome::NoPeer => {}
            }
        } else {
            self.stats_mut().discovery.req_ttl_exhausted += 1;
            debug!(
                request_id = request.request_id,
                target = %self.peer_display_name(&request.target),
                "LookupRequest TTL exhausted"
            );
        }
    }

    /// Handle an incoming LookupResponse from a peer.
    ///
    /// Processing steps:
    /// 1. Decode and validate
    /// 2. Check recent_requests to determine if we originated or are forwarding
    /// 3. If originator: verify proof signature, then cache target_coords and path_mtu in coord_cache
    /// 4. If transit: apply path_mtu min(outgoing_link_mtu), reverse-path forward to from_peer
    pub(in crate::node) async fn handle_lookup_response(
        &mut self,
        from: &NodeAddr,
        payload: &[u8],
    ) {
        self.stats_mut().discovery.resp_received += 1;

        let mut response = match LookupResponse::decode(payload) {
            Ok(resp) => resp,
            Err(e) => {
                self.stats_mut().discovery.resp_decode_error += 1;
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed LookupResponse");
                return;
            }
        };

        let now_ms = Self::now_ms();

        // Check if we forwarded this request (transit node) or originated it
        match self
            .recent_requests
            .claim_response_forward(response.request_id)
        {
            RecentResponseForward::Forward { from_peer } => {
                // Transit node: reverse-path forward
                self.stats_mut().discovery.resp_forwarded += 1;

                // Apply path_mtu min() from the outgoing link's transport MTU
                self.apply_outgoing_link_mtu_to_response(&mut response, &from_peer);

                info!(
                    request_id = response.request_id,
                    target = %self.peer_display_name(&response.target),
                    next_hop = %self.peer_display_name(&from_peer),
                    path_mtu = response.path_mtu,
                    "Reverse-path forwarding LookupResponse"
                );

                let encoded = response.encode();
                if let Err(e) = self
                    .send_dataplane_fmp_link_plaintext(&from_peer, &encoded, false)
                    .await
                {
                    debug!(
                        next_hop = %self.peer_display_name(&from_peer),
                        error = %e,
                        "Failed to forward LookupResponse"
                    );
                }
            }
            RecentResponseForward::AlreadyForwarded => {
                debug!(
                    request_id = response.request_id,
                    target = %self.peer_display_name(&response.target),
                    "Response already forwarded for this request, dropping"
                );
            }
            RecentResponseForward::Missing => {
                // We originated this request — verify proof before caching
                let target = response.target;
                let path_mtu = response.path_mtu;

                // Look up the target's public key from identity_cache
                let mut prefix = [0u8; 15];
                prefix.copy_from_slice(&target.as_bytes()[0..15]);
                let target_pubkey = match self.lookup_by_fips_prefix(&prefix) {
                    Some((_addr, pubkey)) => pubkey,
                    None => {
                        self.stats_mut().discovery.resp_identity_miss += 1;
                        warn!(
                            request_id = response.request_id,
                            target = %self.peer_display_name(&target),
                            "identity_cache miss for lookup target, cannot verify proof"
                        );
                        return;
                    }
                };

                // Verify the proof signature
                let (xonly, _parity) = target_pubkey.x_only_public_key();
                let peer_id = PeerIdentity::from_pubkey(xonly);
                let proof_data = LookupResponse::proof_bytes(
                    response.request_id,
                    &target,
                    &response.target_coords,
                );
                if !peer_id.verify(&proof_data, &response.proof) {
                    self.stats_mut().discovery.resp_proof_failed += 1;
                    warn!(
                        request_id = response.request_id,
                        target = %self.peer_display_name(&target),
                        "LookupResponse proof verification failed, discarding"
                    );
                    return;
                }

                self.stats_mut().discovery.resp_accepted += 1;

                // Clear backoff on success — target is reachable
                self.discovery_backoff.record_success(&target);

                info!(
                    request_id = response.request_id,
                    target = %self.peer_display_name(&target),
                    depth = response.target_coords.depth(),
                    path_mtu = path_mtu,
                    "Discovery succeeded, proof verified, route cached"
                );

                self.coord_cache.insert_with_path_mtu(
                    target,
                    response.target_coords,
                    now_ms,
                    path_mtu,
                );
                self.learn_reverse_route(target, *from);

                // Mirror path_mtu into the FipsAddress-keyed read-only lookup
                // map used by the TUN reader/writer at TCP MSS clamp time.
                let fips_addr = crate::FipsAddress::from_node_addr(&target);
                match self.path_mtu_lookup.write() {
                    Ok(mut map) => {
                        let prior = map.insert(fips_addr, path_mtu);
                        debug!(
                            target = %self.peer_display_name(&target),
                            fips_addr = %fips_addr,
                            path_mtu = path_mtu,
                            prior = ?prior,
                            map_len = map.len(),
                            "Wrote path_mtu_lookup from discovery LookupResponse"
                        );
                    }
                    Err(e) => {
                        warn!(
                            target = %self.peer_display_name(&target),
                            fips_addr = %fips_addr,
                            path_mtu = path_mtu,
                            error = %e,
                            "path_mtu_lookup write lock poisoned; clamp will not see this update"
                        );
                    }
                }

                // Clean up pending lookup tracking
                self.pending_lookups.remove(&target);

                let has_queued_traffic = self.pending_session_traffic.has_traffic_for(&target);
                let session_established = self
                    .sessions
                    .get(&target)
                    .is_some_and(|entry| entry.is_established());

                // If an established session exists, reset the dataplane owner warmup budget.
                if session_established {
                    let n = self.config.node.session.coords_warmup_packets;
                    self.refresh_dataplane_fsp_owner_routes_with_coords_warmup(&target, n);
                    debug!(
                        dest = %self.peer_display_name(&target),
                        warmup_packets = n,
                        "Reset coords warmup after discovery for existing session"
                    );
                }

                if session_established
                    && !has_queued_traffic
                    && let Err(e) = self.send_coords_warmup(&target).await
                {
                    debug!(
                        dest = %self.peer_display_name(&target),
                        error = %e,
                        "Failed to send immediate fallback coords warmup after discovery"
                    );
                }

                // If we have queued application traffic for this target, or the
                // target is a configured auto-connect peer we are proactively
                // warming, retry session initiation or flush the existing session.
                // The coord_cache now has coords, so find_next_hop() should
                // succeed. Established sessions need a flush, not a re-handshake:
                // retry_session_after_discovery intentionally leaves established
                // sessions alone.
                let should_warm_session = !has_queued_traffic
                    && self.should_warm_auto_connect_session(&target)
                    && self.graph_session_warmup_budget() > 0;
                if has_queued_traffic || should_warm_session {
                    let endpoint_payloads = self
                        .pending_session_traffic
                        .endpoint_data_for(&target)
                        .map_or(0, |p| p.len());
                    let tun_packets = self
                        .pending_session_traffic
                        .tun_packets_for(&target)
                        .map_or(0, |p| p.len());
                    debug!(
                        dest = %self.peer_display_name(&target),
                        queued_tun_packets = tun_packets,
                        queued_endpoint_payloads = endpoint_payloads,
                        proactive_warm = should_warm_session,
                        "Retrying session after discovery"
                    );
                    if has_queued_traffic && session_established {
                        self.flush_pending_packets(&target).await;
                    } else {
                        self.retry_session_after_discovery(target).await;
                    }
                }
            }
        }
    }

    /// Generate and send a LookupResponse when we are the target.
    async fn send_lookup_response(&mut self, request: &LookupRequest) {
        let our_coords = self.tree_state().my_coords().clone();

        // Sign proof: Identity::sign hashes with SHA-256 internally
        let proof_data =
            LookupResponse::proof_bytes(request.request_id, &request.target, &our_coords);
        let proof = self.identity().sign(&proof_data);

        let mut response =
            LookupResponse::new(request.request_id, request.target, our_coords, proof);

        // Route toward origin via reverse path.
        let next_hop_addr = if let Some(recent) = self.recent_requests.get(&request.request_id) {
            recent.from_peer
        } else {
            // Fallback: try greedy tree routing toward origin
            match self.find_next_hop(&request.origin) {
                Some(peer) => *peer.node_addr(),
                None => {
                    debug!(
                        origin = %self.peer_display_name(&request.origin),
                        "Cannot route LookupResponse: no reverse path or tree route to origin"
                    );
                    return;
                }
            }
        };

        // Fold our outgoing-link MTU into path_mtu so the target-edge link
        // appears in the bottleneck calculation. Without this, the response
        // leaves the target with path_mtu = u16::MAX and only intermediate
        // transits min-fold; the target's first reverse-path hop is missed.
        self.apply_outgoing_link_mtu_to_response(&mut response, &next_hop_addr);

        info!(
                request_id = request.request_id,
                origin = %self.peer_display_name(&request.origin),
                next_hop = %self.peer_display_name(&next_hop_addr),
                path_mtu = response.path_mtu,
                "Sending LookupResponse"
        );

        let encoded = response.encode();
        if let Err(e) = self
            .send_dataplane_fmp_link_plaintext(&next_hop_addr, &encoded, false)
            .await
        {
            debug!(
                next_hop = %self.peer_display_name(&next_hop_addr),
                error = %e,
                "Failed to send LookupResponse"
            );
        }
    }

    /// Forward a LookupRequest to eligible peers.
    ///
    /// Primary path: tree peers (parent + children) whose bloom filter
    /// contains the target. Restricting to tree peers follows the spanning
    /// tree partition, producing a single directed path.
    ///
    /// Fallback: if no tree peer's bloom matches, original routing tries
    /// non-tree bloom-matching peers. Reply-learned routing floods sendable
    /// peers instead, which avoids trusting reachability claims for first-contact
    /// discovery at the cost of more traffic. Transit forwarding excludes the
    /// previous hop and the originator so request IDs keep their originator vs.
    /// relay meaning.
    async fn forward_lookup_request(
        &mut self,
        from: &NodeAddr,
        mut request: LookupRequest,
    ) -> LookupForwardOutcome {
        if !request.forward() {
            return LookupForwardOutcome::NoPeer;
        }
        let mut forward_limiter_checked = false;

        let candidates = self.lookup_peer_candidates(&request.target);
        let reply_learned_fallback_enabled = self.config.node.routing.mode
            == RoutingMode::ReplyLearned
            && self.should_use_reply_learned_lookup_fallback_for_origin_target(
                &request.origin,
                &request.target,
            );
        let plan = plan_forward_peers(
            *from,
            request.origin,
            request.target,
            self.config.node.routing.mode,
            reply_learned_fallback_enabled,
            &candidates,
            MAX_REPLY_LEARNED_EXTRA_LOOKUP_PEERS,
        );
        let forward_to = plan.peers;

        // If the target is a direct active peer, hand the lookup to it even
        // when it is not part of our current tree neighborhood. Stale direct
        // targets remain probeable, but reply-learned routing lets a planned
        // healthy fallback carry the request instead of giving the stale target
        // exclusive request-id ownership.
        let stale_direct_probe_allowed =
            self.config.node.routing.mode != RoutingMode::ReplyLearned || forward_to.is_empty();
        let direct_target_sendable = request.target != *from
            && self.peers.get(&request.target).is_some_and(|peer| {
                peer.can_send() && (peer.is_healthy() || stale_direct_probe_allowed)
            });
        if direct_target_sendable {
            if !self.should_forward_lookup_for_target(&request) {
                return LookupForwardOutcome::RateLimited;
            }
            forward_limiter_checked = true;
            let encoded = request.encode();
            match self
                .send_dataplane_fmp_link_plaintext(&request.target, &encoded, false)
                .await
            {
                Ok(()) => {
                    info!(
                        request_id = request.request_id,
                        target = %self.peer_display_name(&request.target),
                        "Forwarded LookupRequest to direct target peer"
                    );
                    return LookupForwardOutcome::Forwarded;
                }
                Err(error) => {
                    debug!(
                        request_id = request.request_id,
                        target = %self.peer_display_name(&request.target),
                        error = %error,
                        "Failed to forward LookupRequest to direct target peer"
                    );
                }
            }
        }

        if forward_to.is_empty() {
            self.stats_mut().discovery.req_no_tree_peer += 1;
            trace!(
                request_id = request.request_id,
                "No eligible peers to forward LookupRequest"
            );
            return LookupForwardOutcome::NoPeer;
        }

        if !forward_limiter_checked && !self.should_forward_lookup_for_target(&request) {
            return LookupForwardOutcome::RateLimited;
        }

        if plan.used_fallback {
            self.stats_mut().discovery.req_fallback_forwarded += 1;
            debug!(
                request_id = request.request_id,
                target = %self.peer_display_name(&request.target),
                ttl = request.ttl,
                peer_count = forward_to.len(),
                "Forwarding LookupRequest via fallback discovery"
            );
        } else {
            debug!(
                request_id = request.request_id,
                target = %self.peer_display_name(&request.target),
                ttl = request.ttl,
                peer_count = forward_to.len(),
                "Forwarding LookupRequest"
            );
        }

        let encoded = request.encode();

        for peer_addr in forward_to {
            if let Err(e) = self
                .send_dataplane_fmp_link_plaintext(&peer_addr, &encoded, false)
                .await
            {
                debug!(
                    peer = %self.peer_display_name(&peer_addr),
                    error = %e,
                    "Failed to forward LookupRequest to peer"
                );
            }
        }

        LookupForwardOutcome::Forwarded
    }

    fn should_forward_lookup_for_target(&mut self, request: &LookupRequest) -> bool {
        if self
            .discovery_forward_limiter
            .should_forward(&request.target)
        {
            return true;
        }

        debug!(
            request_id = request.request_id,
            target = %self.peer_display_name(&request.target),
            "Forward rate limited, suppressing LookupRequest"
        );
        false
    }

    fn lookup_peer_candidates(&self, target: &NodeAddr) -> Vec<LookupPeerCandidate> {
        self.peers
            .iter()
            .map(|(addr, peer)| LookupPeerCandidate {
                addr: *addr,
                can_send: peer.can_send(),
                is_healthy: peer.is_healthy(),
                is_tree_peer: self.is_tree_peer(addr),
                may_reach_target: peer.may_reach(target),
                reply_learned_fallback_allowed: self
                    .should_use_reply_learned_lookup_fallback_peer(addr, peer, target),
            })
            .collect()
    }

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
        self.discovery_fallback_transit.allows_lookup_fallback_peer(
            peer_addr,
            target,
            peer.transport_id(),
            |transport_id| self.bootstrap_transports.contains(&transport_id),
        )
    }

    fn should_use_reply_learned_lookup_fallback_for_origin_target(
        &self,
        origin: &NodeAddr,
        target: &NodeAddr,
    ) -> bool {
        let nostr = &self.config.node.discovery.nostr;
        match nostr.policy {
            crate::config::NostrDiscoveryPolicy::Open => {
                self.configured_discovery_fallback_transit(origin).is_some()
                    && self.configured_discovery_fallback_transit(target).is_some()
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
            }
            crate::config::NostrDiscoveryPolicy::ConfiguredOnly if nostr.enabled => {
                self.configured_discovery_fallback_transit(target).is_some()
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
    /// - Otherwise: declare the destination unreachable, drop queued packets,
    ///   and emit ICMPv6 destination-unreachable for each.
    pub(in crate::node) async fn check_pending_lookups(&mut self, now_ms: u64) {
        let timeouts = self.config.node.discovery.attempt_timeouts_secs.clone();
        let max_attempts = timeouts.len() as u8;

        // Collect targets needing action
        let mut to_complete: Vec<NodeAddr> = Vec::new();
        let mut to_retry: Vec<NodeAddr> = Vec::new();
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
                    to_timeout.push(target);
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
