//! LookupRequest/LookupResponse discovery protocol handlers.
//!
//! Handles coordinate discovery via bloom-filter-guided tree routing.
//! Requests are forwarded only to tree peers (parent + children) whose
//! bloom filter contains the target. TTL and request_id dedup provide
//! safety bounds.

use crate::config::RoutingMode;
use crate::node::{Node, PathMtuUpdate, RecentResponseForward};
use crate::proto::lookup::{LookupPeerCandidate, plan_forward_peers, plan_initiate_peers};
use crate::protocol::{LookupRequest, LookupResponse};
use crate::transport::{TransportAddr, TransportId};
use crate::{NodeAddr, NodeError, PeerIdentity};
use tracing::{debug, info, trace, warn};

pub(in crate::node) const MAX_RECENT_DISCOVERY_REQUESTS: usize = 4096;
pub(in crate::node) const MIN_RECENT_DISCOVERY_REQUESTS_PER_PEER: usize = 64;
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
            request.target,
            now_ms,
            crate::node::RecentDiscoveryRequestLimits::new(
                MAX_RECENT_DISCOVERY_REQUESTS,
                self.peers.len(),
                MIN_RECENT_DISCOVERY_REQUESTS_PER_PEER,
            ),
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

        if admission.evicted() {
            self.stats_mut().discovery.req_dedup_evicted += 1;
            debug!(
                request_id = request.request_id,
                from = %self.peer_display_name(from),
                recent_requests = self.recent_requests.len(),
                max_recent_requests = MAX_RECENT_DISCOVERY_REQUESTS,
                "Evicted an older discovery reverse path to admit LookupRequest"
            );
        }
        if !admission.accepted() {
            return;
        }

        // Are we the target?
        if request.target == *self.node_addr() {
            if !self.discovery_sign_limiter.should_sign(from) {
                self.stats_mut().discovery.req_sign_rate_limited += 1;
                debug!(
                    request_id = request.request_id,
                    from = %self.peer_display_name(from),
                    "Lookup response signing budget exhausted for ingress peer"
                );
                return;
            }
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
    /// 2. Prefer a matching locally originated request, then check whether we
    ///    are forwarding it
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

        // A peer that sees our request also knows its random ID and can reflect
        // it back as a LookupRequest. Local origin correlation must win that
        // collision or the real signed response would be misclassified as
        // transit traffic and forwarded back to the reflecting peer.
        let originated_here = self
            .pending_lookups
            .matches_origin_request(&response.target, response.request_id);
        let reverse_path = if originated_here {
            // Discard both the reflected entry and its per-peer admission index;
            // a later duplicate response must not revive the poisoned path.
            self.recent_requests.remove(response.request_id);
            RecentResponseForward::Missing
        } else {
            self.recent_requests
                .claim_response_forward(response.request_id, response.target)
        };

        match reverse_path {
            RecentResponseForward::Forward { from_peer } => {
                // Transit node: reverse-path forward
                self.stats_mut().discovery.resp_forwarded += 1;

                // The next end-to-end session follows this response. Retain
                // the target coordinates and the response's incoming next hop
                // so that session traffic can traverse the same learned path
                // instead of immediately eliciting CoordsRequired here.
                if response.target_coords.node_addr() == &response.target {
                    // Coordinates are meaningful only inside our current tree
                    // component. Caching a foreign-root response would make
                    // transit routing reject the freshly learned reply path as
                    // non-progressing and return PathBroken. Keep the response
                    // path, but wait for compatible coordinates before using
                    // strict tree-distance routing.
                    if response.target_coords.root_id() == self.tree_state.my_coords().root_id() {
                        self.coord_cache.insert_with_path_mtu(
                            response.target,
                            response.target_coords.clone(),
                            now_ms,
                            response.path_mtu,
                        );
                    }
                    // A claimed reverse-path response is the route proof for
                    // the end-to-end handshake that immediately follows it.
                    // Pin that bounded handshake path; ordinary learned
                    // traffic remains subject to transit loop checks.
                    self.pin_handshake_reverse_route(response.target, *from);
                }

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
                // A valid proof is replayable. Require both the target and a
                // fresh request ID that this node actually issued before any
                // identity lookup, signature work, cache refresh, backoff
                // reset, route pin, or queued-traffic flush.
                if !self
                    .pending_lookups
                    .matches_origin_request(&target, response.request_id)
                {
                    self.stats_mut().discovery.resp_unsolicited += 1;
                    debug!(
                        request_id = response.request_id,
                        target = %self.peer_display_name(&target),
                        next_hop = %self.peer_display_name(from),
                        "Ignoring lookup response that does not match an outstanding request"
                    );
                    return;
                }
                let session_established = self
                    .sessions
                    .get(&target)
                    .is_some_and(|entry| entry.is_established());

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
                    next_hop = %self.peer_display_name(from),
                    depth = response.target_coords.depth(),
                    path_mtu = path_mtu,
                    "Discovery succeeded, proof verified, route cached"
                );

                // `path_mtu` is a hop annotation outside the signed proof.
                // A forwarder may lower it, so values below the minimum that
                // can describe a usable path are treated as absent. The
                // signed coordinates remain useful and must still be cached.
                let path_mtu_actionable = path_mtu >= crate::mmp::MIN_ACTIONABLE_PATH_MTU;
                if path_mtu_actionable {
                    self.coord_cache.insert_verified_with_path_mtu(
                        target,
                        response.target_coords,
                        now_ms,
                        path_mtu,
                    );
                } else {
                    self.stats_mut().errors.lookup_resp_mtu_below_floor += 1;
                    warn!(
                        target = %self.peer_display_name(&target),
                        path_mtu,
                        floor = crate::mmp::MIN_ACTIONABLE_PATH_MTU,
                        "LookupResponse path MTU is below the actionable floor; caching coordinates only"
                    );
                    self.coord_cache
                        .insert_verified(target, response.target_coords, now_ms);
                }
                let response_hop_quarantined = session_established
                    && self
                        .learned_routes
                        .failed_next_hops(&target, now_ms)
                        .contains(from);
                let path_recovery_lookup = self.pending_lookups.is_path_recovery(&target);
                let indirect_recovery_hop_proven = session_established
                    && !response_hop_quarantined
                    && *from != target
                    && (path_recovery_lookup || self.retry_pending.contains_key(&target));
                if response_hop_quarantined {
                    debug!(
                        target = %self.peer_display_name(&target),
                        next_hop = %self.peer_display_name(from),
                        "Keeping established payload route failure after control-plane lookup"
                    );
                } else {
                    // The target signature authenticates this response, and the
                    // FMP ingress authenticates its new transit hop. Reuse the
                    // established FSP session on that proven branch while
                    // retaining any separately quarantined failed branch.
                    self.pin_handshake_reverse_route(target, *from);
                }
                if indirect_recovery_hop_proven {
                    // A path-recovery lookup (or still-pending direct retry)
                    // means direct payload stopped authenticating its return
                    // traffic. The target-signed response and authenticated
                    // FMP ingress prove this indirect branch now. Remembering
                    // the lookup purpose is important because a delayed
                    // receiver report from the previous loaded flow can make
                    // direct delivery evidence look fresh again while this
                    // response is in flight.
                    let newly_degraded = self.mark_session_direct_path_degraded(target, now_ms);
                    if newly_degraded || !self.retry_pending.contains_key(&target) {
                        self.schedule_link_dead_reprobe(target, now_ms);
                    }
                    debug!(
                        target = %self.peer_display_name(&target),
                        next_hop = %self.peer_display_name(from),
                        newly_degraded,
                        "Adopting authenticated indirect recovery hop for established payload"
                    );
                }

                // Mirror path_mtu into the FipsAddress-keyed read-only lookup
                // map used by the TUN reader/writer at TCP MSS clamp time.
                let fips_addr = crate::FipsAddress::from_node_addr(&target);
                if path_mtu_actionable {
                    match self.record_discovery_path_mtu(fips_addr, path_mtu, now_ms) {
                        PathMtuUpdate::Kept { current } => debug!(
                            target = %self.peer_display_name(&target),
                            fips_addr = %fips_addr,
                            path_mtu,
                            existing = current.mtu,
                            "LookupResponse: keeping tighter existing path_mtu_lookup value"
                        ),
                        PathMtuUpdate::Updated { prior, .. } => debug!(
                            target = %self.peer_display_name(&target),
                            fips_addr = %fips_addr,
                            path_mtu,
                            prior = ?prior,
                            "Wrote path_mtu_lookup from discovery LookupResponse"
                        ),
                        PathMtuUpdate::Unavailable => warn!(
                            target = %self.peer_display_name(&target),
                            fips_addr = %fips_addr,
                            path_mtu,
                            "path_mtu_lookup unavailable; clamp will not see this update"
                        ),
                    }
                }

                // Clean up pending lookup tracking
                self.pending_lookups.remove(&target);

                let has_queued_traffic = self.pending_session_traffic.has_traffic_for(&target);

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
                from,
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
            if !self.should_forward_lookup_for_target(from, &request) {
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

        if !forward_limiter_checked && !self.should_forward_lookup_for_target(from, &request) {
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

    fn should_forward_lookup_for_target(
        &mut self,
        from: &NodeAddr,
        request: &LookupRequest,
    ) -> bool {
        if self
            .discovery_forward_limiter
            .should_forward(from, &request.target)
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
                configured_reply_learned_fallback_transit: self
                    .configured_discovery_fallback_transit(addr)
                    == Some(true),
            })
            .collect()
    }
}

include!("discovery_lookup.rs");
