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
                    self.learn_reverse_route(response.target, *from);
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
}

include!("discovery_lookup.rs");
