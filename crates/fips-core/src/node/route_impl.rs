use super::*;

pub(in crate::node) enum TransitNextHopPlan {
    Route(NodeAddr),
    Loop(NodeAddr),
    NoRoute,
}

impl Node {
    // === Routing ===

    pub(in crate::node) fn cache_current_root_coords(
        &mut self,
        node_addr: NodeAddr,
        coords: crate::tree::TreeCoordinate,
        now_ms: u64,
    ) -> bool {
        if coords.node_addr() != &node_addr
            || coords.root_id() != self.tree_state.my_coords().root_id()
        {
            return false;
        }
        self.coord_cache.insert(node_addr, coords, now_ms);
        true
    }

    /// Check if a peer is a tree neighbor (parent or child in the spanning tree).
    ///
    /// Returns true if the peer is our current tree parent, or if the peer
    /// has declared us as their parent (making them our child).
    pub(crate) fn is_tree_peer(&self, peer_addr: &NodeAddr) -> bool {
        // Peer is our parent
        if !self.tree_state.is_root() && self.tree_state.my_declaration().parent_id() == peer_addr {
            return true;
        }
        // Peer is our child (their declaration names us as parent)
        if let Some(decl) = self.tree_state.peer_declaration(peer_addr)
            && decl.parent_id() == self.node_addr()
        {
            return true;
        }
        false
    }

    /// Find next hop for a destination node address.
    ///
    /// Routing priority:
    /// 1. Destination is self → `None` (local delivery)
    /// 2. Destination is a healthy direct peer → that peer. A known fallback
    ///    next-hop may beat a non-static direct path when it has a meaningful
    ///    link-quality advantage; operator-configured static UDP peers stay
    ///    pinned to direct while healthy and endpoint traffic is getting
    ///    authenticated return traffic.
    /// 3. Reply-learned routes in `reply_learned` mode. These are locally
    ///    observed reverse paths, selected with weighted multipath plus
    ///    periodic coordinate/tree exploration.
    /// 4. Bloom filter candidates with cached dest coords → among peers whose
    ///    bloom filter contains the destination, pick the one that minimizes
    ///    tree distance to the destination, with
    ///    `(link_cost, tree_distance_to_dest, node_addr)` tie-breaking.
    ///    The self-distance check ensures only peers strictly closer to the
    ///    destination than us are considered (prevents routing loops).
    /// 5. Greedy tree routing fallback (requires cached dest coords)
    /// 6. No route → `None`
    ///
    /// Both the bloom filter and tree routing paths require cached destination
    /// coordinates (checked in `coord_cache`). Without coordinates, the node
    /// cannot make loop-free forwarding decisions. The caller should signal
    /// `CoordsRequired` back to the source when `None` is returned for a
    /// non-local destination.
    pub fn find_next_hop(&mut self, dest_node_addr: &NodeAddr) -> Option<&ActivePeer> {
        // 1. Local delivery
        if dest_node_addr == self.node_addr() {
            return None;
        }
        let now_ms = Self::now_ms();
        let direct_path_hard_degraded =
            self.session_direct_path_is_degraded(dest_node_addr, now_ms);
        let direct_path_soft_degraded = !direct_path_hard_degraded
            && self.session_direct_discovered_endpoint_trust_expired(dest_node_addr, now_ms);
        let fallback_peer_available = self.has_sendable_fallback_lookup_peer(dest_node_addr);
        let direct_session_degraded =
            fallback_peer_available && (direct_path_hard_degraded || direct_path_soft_degraded);
        let direct_session_untrusted = !direct_session_degraded
            && self.session_direct_path_exclusive_trust_expired(dest_node_addr, now_ms);
        let stale_traversal_direct_route = self
            .peers
            .get(dest_node_addr)
            .filter(|peer| {
                !direct_path_hard_degraded
                    && !direct_session_degraded
                    && !peer.is_healthy()
                    && peer.can_send()
            })
            .and_then(|_| {
                self.configured_peer(dest_node_addr)
                    .and_then(|peer_config| {
                        (peer_config.is_auto_connect()
                            && self.active_peer_uses_traversal_path(dest_node_addr, peer_config))
                        .then_some(*dest_node_addr)
                    })
            });

        let healthy_direct_route = self
            .peers
            .get(dest_node_addr)
            .filter(|peer| peer.is_healthy() && !direct_session_degraded)
            .map(|_| *dest_node_addr);
        let direct_session_has_recent_data_return =
            self.session_direct_path_has_recent_data_return(dest_node_addr, now_ms);
        if let Some(direct_addr) = healthy_direct_route
            && direct_session_has_recent_data_return
        {
            return self.peers.get(&direct_addr);
        }
        if let Some(direct_addr) = healthy_direct_route
            && !direct_session_untrusted
            && self.dataplane_fmp_link_cost(&direct_addr)
                <= 1.0 + ROUTING_FALLBACK_MIN_COST_ADVANTAGE
        {
            return self.peers.get(&direct_addr);
        }
        let direct_payload_eligible = healthy_direct_route.is_some();
        let payload_candidate_can_send = |addr: &NodeAddr, peer: &ActivePeer| {
            if addr == dest_node_addr {
                direct_payload_eligible
            } else {
                peer.is_healthy()
            }
        };

        // A healthy direct path is not automatically the best path. A
        // hotspot/NAT hairpin can remain sendable with high RTT or mild loss;
        // in that case a lower-cost mesh next-hop should carry traffic while
        // direct probes continue in the background.
        let fallback_beats_direct = |node: &Self, fallback_addr: NodeAddr| {
            if direct_session_untrusted {
                return healthy_direct_route != Some(fallback_addr)
                    && node
                        .peers
                        .get(&fallback_addr)
                        .is_some_and(|peer| peer.is_healthy());
            }
            node.route_candidate_beats_direct(healthy_direct_route, fallback_addr)
        };

        let sendable_learned_peers = if self.config.node.routing.mode == RoutingMode::ReplyLearned {
            Some(
                self.peers
                    .iter()
                    .filter(|(addr, peer)| payload_candidate_can_send(addr, peer))
                    .map(|(addr, _)| *addr)
                    .collect::<HashSet<_>>(),
            )
        } else {
            None
        };

        let explore_fallback = sendable_learned_peers.as_ref().is_some_and(|sendable| {
            self.learned_routes.should_explore_fallback(
                dest_node_addr,
                now_ms,
                self.config.node.routing.learned_fallback_explore_interval,
                |addr| sendable.contains(addr),
            )
        });
        if let Some(next_hop_addr) = sendable_learned_peers.as_ref().and_then(|sendable| {
            let activity = self.dataplane.fsp_owner_activity(dest_node_addr)?;
            let next_hop_addr = activity.last_outbound_next_hop()?;
            if next_hop_addr == *dest_node_addr
                || !activity.has_recent_outbound_activity(
                    now_ms,
                    self.session_direct_path_exclusive_trust_timeout_ms(),
                )
                || !sendable.contains(&next_hop_addr)
                || !fallback_beats_direct(self, next_hop_addr)
            {
                return None;
            }
            Some(next_hop_addr)
        }) {
            self.learned_routes
                .record_selected(dest_node_addr, &next_hop_addr, now_ms);
            return self.peers.get(&next_hop_addr);
        }

        // 3. Optional reply-learned routing. These entries are not peer
        // claims; they are local observations of which peer carried traffic
        // or a verified lookup response back from the destination. Most
        // packets use weighted multipath over learned routes, but periodic
        // fallback exploration lets coord/bloom/tree routes discover better
        // candidates.
        if let Some(sendable) = &sendable_learned_peers
            && !explore_fallback
        {
            let eligible = sendable
                .iter()
                .copied()
                .filter(|addr| fallback_beats_direct(self, *addr))
                .collect::<HashSet<_>>();
            if !eligible.is_empty()
                && let Some(next_hop_addr) =
                    self.learned_routes
                        .select_next_hop(dest_node_addr, now_ms, |addr| eligible.contains(addr))
            {
                return self.peers.get(&next_hop_addr);
            }
        }

        // Look up cached destination coordinates (required by both bloom and tree paths).
        let Some(dest_coords) = self
            .coord_cache
            .get_and_touch(dest_node_addr, now_ms)
            .cloned()
        else {
            if (healthy_direct_route.is_none() || explore_fallback)
                && let Some(sendable) = &sendable_learned_peers
                && let Some(next_hop_addr) =
                    self.learned_routes
                        .select_next_hop(dest_node_addr, now_ms, |addr| sendable.contains(addr))
            {
                return self.peers.get(&next_hop_addr);
            }
            if let Some(direct_addr) = healthy_direct_route {
                return self.peers.get(&direct_addr);
            }
            if let Some(direct_addr) = stale_traversal_direct_route {
                return self.peers.get(&direct_addr);
            }
            return None;
        };

        // 4. Bloom filter candidates — requires dest_coords for loop-free selection.
        //    If no candidate is strictly closer, fall through to tree routing.
        let coordinate_route_addr = {
            let candidates: Vec<&ActivePeer> = self
                .peers
                .iter()
                .filter(|(addr, peer)| {
                    payload_candidate_can_send(addr, peer) && peer.may_reach(dest_node_addr)
                })
                .map(|(_, peer)| peer)
                .collect();
            if !candidates.is_empty() {
                self.select_best_candidate(&candidates, &dest_coords)
                    .map(|peer| *peer.node_addr())
            } else {
                None
            }
        };
        if let Some(next_hop_addr) = coordinate_route_addr
            && fallback_beats_direct(self, next_hop_addr)
        {
            return self.peers.get(&next_hop_addr);
        }

        // 5. Greedy tree routing fallback
        let tree_route_addr = self.select_tree_payload_candidate(
            &dest_coords,
            dest_node_addr,
            direct_payload_eligible,
        );
        if let Some(next_hop_addr) = tree_route_addr
            && fallback_beats_direct(self, next_hop_addr)
        {
            return self.peers.get(&next_hop_addr);
        }

        if explore_fallback
            && let Some(peer) = sendable_learned_peers.as_ref().and_then(|sendable| {
                self.learned_routes
                    .select_next_hop(dest_node_addr, now_ms, |addr| sendable.contains(addr))
                    .and_then(|next_hop_addr| self.peers.get(&next_hop_addr))
            })
        {
            return Some(peer);
        }

        if let Some(direct_addr) = healthy_direct_route {
            return self.peers.get(&direct_addr);
        }

        if let Some(sendable) = &sendable_learned_peers
            && let Some(next_hop_addr) =
                self.learned_routes
                    .select_next_hop(dest_node_addr, now_ms, |addr| sendable.contains(addr))
        {
            return self.peers.get(&next_hop_addr);
        }

        if let Some(direct_addr) = stale_traversal_direct_route {
            return self.peers.get(&direct_addr);
        }

        None
    }

    pub(in crate::node) fn plan_transit_next_hop(
        &mut self,
        dest_node_addr: &NodeAddr,
        previous_hop: &NodeAddr,
    ) -> TransitNextHopPlan {
        if dest_node_addr == self.node_addr() {
            return TransitNextHopPlan::NoRoute;
        }

        if dest_node_addr != previous_hop
            && self
                .peers
                .get(dest_node_addr)
                .is_some_and(|peer| peer.is_healthy())
        {
            return TransitNextHopPlan::Route(*dest_node_addr);
        }

        let Some(next_hop_addr) = self
            .find_next_hop(dest_node_addr)
            .map(|peer| *peer.node_addr())
        else {
            return TransitNextHopPlan::NoRoute;
        };
        if next_hop_addr == *dest_node_addr && &next_hop_addr != previous_hop {
            return TransitNextHopPlan::Route(next_hop_addr);
        }

        let now_ms = Self::now_ms();
        let dest_coords = self
            .coord_cache
            .get_and_touch(dest_node_addr, now_ms)
            .cloned();
        let selected_strictly_progresses = dest_coords.as_ref().is_some_and(|dest_coords| {
            self.tree_state.my_coords().root_id() == dest_coords.root_id()
                && self
                    .tree_state
                    .peer_coords(&next_hop_addr)
                    .is_some_and(|peer_coords| {
                        peer_coords.distance_to(dest_coords)
                            < self.tree_state.my_coords().distance_to(dest_coords)
                    })
        });

        if &next_hop_addr != previous_hop && (dest_coords.is_none() || selected_strictly_progresses)
        {
            return TransitNextHopPlan::Route(next_hop_addr);
        }

        let coordinate_fallback = dest_coords.and_then(|dest_coords| {
            self.select_tree_payload_candidate_avoiding(
                &dest_coords,
                dest_node_addr,
                false,
                Some(previous_hop),
            )
        });
        if let Some(next_hop_addr) = coordinate_fallback {
            return TransitNextHopPlan::Route(next_hop_addr);
        }
        TransitNextHopPlan::Loop(next_hop_addr)
    }

    #[cfg(test)]
    pub(in crate::node) fn find_transit_next_hop(
        &mut self,
        dest_node_addr: &NodeAddr,
        previous_hop: &NodeAddr,
    ) -> Option<NodeAddr> {
        match self.plan_transit_next_hop(dest_node_addr, previous_hop) {
            TransitNextHopPlan::Route(next_hop_addr) => Some(next_hop_addr),
            TransitNextHopPlan::Loop(next_hop_addr) => {
                self.record_route_failure(*dest_node_addr, next_hop_addr);
                None
            }
            TransitNextHopPlan::NoRoute => None,
        }
    }

    pub(super) fn route_candidate_beats_direct(
        &self,
        healthy_direct_route: Option<NodeAddr>,
        candidate_addr: NodeAddr,
    ) -> bool {
        let Some(direct_addr) = healthy_direct_route else {
            return true;
        };
        if candidate_addr == direct_addr {
            return false;
        }

        if !self.peers.contains_key(&direct_addr) {
            return true;
        }
        if self.active_peer_uses_configured_static_udp_path(&direct_addr) {
            return false;
        }
        let Some(candidate) = self.peers.get(&candidate_addr) else {
            return false;
        };
        if !candidate.is_healthy() {
            return false;
        }

        let direct_cost = self.dataplane_fmp_link_cost(&direct_addr);
        let candidate_cost = self.dataplane_fmp_link_cost(&candidate_addr);
        candidate_cost + ROUTING_FALLBACK_MIN_COST_ADVANTAGE < direct_cost
    }

    pub(super) fn select_tree_payload_candidate(
        &self,
        dest_coords: &crate::tree::TreeCoordinate,
        direct_dest: &NodeAddr,
        direct_payload_eligible: bool,
    ) -> Option<NodeAddr> {
        self.select_tree_payload_candidate_avoiding(
            dest_coords,
            direct_dest,
            direct_payload_eligible,
            None,
        )
    }

    fn select_tree_payload_candidate_avoiding(
        &self,
        dest_coords: &crate::tree::TreeCoordinate,
        direct_dest: &NodeAddr,
        direct_payload_eligible: bool,
        excluded: Option<&NodeAddr>,
    ) -> Option<NodeAddr> {
        if self.tree_state.my_coords().root_id() != dest_coords.root_id() {
            return None;
        }

        let my_distance = self.tree_state.my_coords().distance_to(dest_coords);
        let mut best: Option<(NodeAddr, usize)> = None;

        for (peer_addr, peer) in &self.peers {
            if excluded == Some(peer_addr) {
                continue;
            }
            if peer_addr == direct_dest {
                if !direct_payload_eligible {
                    continue;
                }
            } else if !peer.is_healthy() {
                continue;
            }

            let Some(peer_coords) = self.tree_state.peer_coords(peer_addr) else {
                continue;
            };
            let distance = peer_coords.distance_to(dest_coords);
            if distance >= my_distance {
                continue;
            }

            let dominated = match &best {
                None => true,
                Some((best_id, best_dist)) => {
                    distance < *best_dist || (distance == *best_dist && peer_addr < best_id)
                }
            };
            if dominated {
                best = Some((*peer_addr, distance));
            }
        }

        best.map(|(peer_addr, _)| peer_addr)
    }

    pub(in crate::node) fn session_direct_path_is_degraded(
        &mut self,
        dest: &NodeAddr,
        now_ms: u64,
    ) -> bool {
        self.session_direct_degradation.is_degraded(dest, now_ms)
    }

    pub(in crate::node) fn session_direct_path_degradation_active(
        &self,
        dest: &NodeAddr,
        now_ms: u64,
    ) -> bool {
        self.session_direct_degradation.is_degraded_at(dest, now_ms)
    }

    pub(in crate::node) fn session_direct_path_blocks_direct_payload(
        &mut self,
        dest: &NodeAddr,
        now_ms: u64,
    ) -> bool {
        self.session_direct_path_is_degraded(dest, now_ms)
            || self.session_direct_discovered_endpoint_trust_expired(dest, now_ms)
    }

    pub(in crate::node) fn session_direct_path_exclusive_trust_timeout_ms(&self) -> u64 {
        self.config
            .node
            .heartbeat_interval_secs
            .saturating_mul(1000)
            .saturating_add(1_500)
            .max(SESSION_DIRECT_MIN_EXCLUSIVE_TRUST_MS)
    }

    pub(in crate::node) fn session_direct_path_exclusive_trust_expired(
        &self,
        dest: &NodeAddr,
        now_ms: u64,
    ) -> bool {
        if !self
            .peers
            .get(dest)
            .is_some_and(|peer| peer.is_healthy() && peer.can_send())
        {
            return false;
        }
        let Some(activity) = self.dataplane.fsp_owner_activity(dest) else {
            return false;
        };
        activity.has_recent_outbound_without_data_return_from(
            dest,
            now_ms,
            self.session_direct_path_exclusive_trust_timeout_ms(),
        )
    }

    pub(in crate::node) fn session_direct_path_has_recent_data_return(
        &self,
        dest: &NodeAddr,
        now_ms: u64,
    ) -> bool {
        self.dataplane
            .fsp_owner_activity(dest)
            .is_some_and(|activity| {
                activity.has_recent_data_return_from(
                    dest,
                    now_ms,
                    self.session_direct_path_exclusive_trust_timeout_ms(),
                )
            })
    }

    fn session_direct_discovered_endpoint_trust_expired(
        &self,
        dest: &NodeAddr,
        now_ms: u64,
    ) -> bool {
        self.session_direct_path_exclusive_trust_expired(dest, now_ms)
            && self.configured_peer(dest).is_some_and(|peer_config| {
                peer_config.is_auto_connect()
                    && self.active_peer_uses_traversal_path(dest, peer_config)
            })
    }

    pub(in crate::node) fn mark_session_direct_path_degraded(
        &mut self,
        dest: NodeAddr,
        now_ms: u64,
    ) -> bool {
        let changed = self.session_direct_degradation.mark_degraded(
            dest,
            now_ms,
            SESSION_DIRECT_DEGRADED_HOLD_MS,
        );
        if changed {
            let _ = self.refresh_dataplane_fsp_owner_routes(&dest);
        }
        changed
    }

    pub(in crate::node) fn clear_session_direct_path_degraded(&mut self, dest: &NodeAddr) -> bool {
        let changed = self.session_direct_degradation.clear(dest);
        if changed {
            let _ = self.refresh_dataplane_fsp_owner_routes(dest);
        }
        changed
    }

    pub(in crate::node) fn clear_session_direct_path_degraded_after_promotion(
        &mut self,
        dest: &NodeAddr,
        now_ms: u64,
    ) {
        let keep_degraded = self.session_direct_path_blocks_direct_payload(dest, now_ms);
        if !keep_degraded {
            self.clear_session_direct_path_degraded(dest);
        } else if self.promoted_path_matches_configured_static_peer(dest) {
            debug!(
                peer = %self.peer_display_name(dest),
                "Clearing direct payload degradation after configured direct-path promotion"
            );
            self.clear_session_direct_path_degraded(dest);
        } else {
            debug!(
                peer = %self.peer_display_name(dest),
                "Keeping direct payload degraded after direct-path promotion"
            );
        }
    }

    fn promoted_path_matches_configured_static_peer(&self, peer_node_addr: &NodeAddr) -> bool {
        self.config
            .auto_connect_peers()
            .filter(|peer_config| {
                PeerIdentity::from_npub(&peer_config.npub)
                    .ok()
                    .is_some_and(|identity| identity.node_addr() == peer_node_addr)
            })
            .any(|peer_config| {
                self.static_peer_addresses(peer_config)
                    .iter()
                    .any(|candidate| self.active_peer_matches_candidate(peer_node_addr, candidate))
            })
    }

    pub(in crate::node) fn learn_reverse_route(
        &mut self,
        destination: NodeAddr,
        next_hop: NodeAddr,
    ) {
        if self.config.node.routing.mode != RoutingMode::ReplyLearned
            || destination == *self.node_addr()
        {
            return;
        }
        let now_ms = Self::now_ms();
        self.learned_routes.learn(
            destination,
            next_hop,
            now_ms,
            self.config.node.routing.learned_ttl_secs,
            self.config.node.routing.max_learned_routes_per_dest,
        );
        let _ = self.refresh_dataplane_fsp_owner_routes(&destination);
    }

    pub(in crate::node) fn record_route_failure(
        &mut self,
        destination: NodeAddr,
        next_hop: NodeAddr,
    ) {
        if self.config.node.routing.mode != RoutingMode::ReplyLearned {
            return;
        }
        self.learned_routes.record_failure(&destination, &next_hop);
        let _ = self.refresh_dataplane_fsp_owner_routes(&destination);
    }

    pub(crate) fn learned_route_table_snapshot(&self, now_ms: u64) -> LearnedRouteTableSnapshot {
        self.learned_routes.snapshot(now_ms)
    }

    pub(in crate::node) fn purge_learned_routes(&mut self, now_ms: u64) {
        self.learned_routes.purge_expired(now_ms);
    }

    /// Select the best peer from a set of bloom filter candidates.
    ///
    /// Uses distance from each candidate's tree coordinates to the destination
    /// as the primary metric (after link_cost). Only selects peers that are
    /// strictly closer to the destination than we are (self-distance check
    /// prevents routing loops).
    ///
    /// Ordering: `(link_cost, distance_to_dest, node_addr)`.
    pub(super) fn select_best_candidate<'a>(
        &'a self,
        candidates: &[&'a ActivePeer],
        dest_coords: &crate::tree::TreeCoordinate,
    ) -> Option<&'a ActivePeer> {
        let my_distance = self.tree_state.my_coords().distance_to(dest_coords);

        let mut best: Option<(&ActivePeer, f64, usize)> = None;

        for &candidate in candidates {
            if !candidate.can_send() {
                continue;
            }

            let cost = self.dataplane_fmp_link_cost(candidate.node_addr());

            let dist = self
                .tree_state
                .peer_coords(candidate.node_addr())
                .map(|pc| pc.distance_to(dest_coords))
                .unwrap_or(usize::MAX);

            // Self-distance check: only consider peers strictly closer
            // to the destination than we are (prevents routing loops)
            if dist >= my_distance {
                continue;
            }

            let dominated = match &best {
                None => true,
                Some((_, best_cost, best_dist)) => {
                    cost < *best_cost
                        || (cost == *best_cost && dist < *best_dist)
                        || (cost == *best_cost
                            && dist == *best_dist
                            && candidate.node_addr() < best.as_ref().unwrap().0.node_addr())
                }
            };

            if dominated {
                best = Some((candidate, cost, dist));
            }
        }

        best.map(|(peer, _, _)| peer)
    }

    /// Check if a destination is in any peer's bloom filter.
    pub fn destination_in_filters(&self, dest: &NodeAddr) -> Vec<&ActivePeer> {
        self.peers.values().filter(|p| p.may_reach(dest)).collect()
    }
}
