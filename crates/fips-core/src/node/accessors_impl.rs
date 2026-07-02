use super::*;

impl Node {
    // === Identity Accessors ===

    /// Get this node's identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Get this node's NodeAddr.
    pub fn node_addr(&self) -> &NodeAddr {
        self.identity.node_addr()
    }

    /// Get this node's npub.
    pub fn npub(&self) -> String {
        self.identity.npub()
    }

    /// Return a human-readable display name for a NodeAddr.
    ///
    /// Lookup order:
    /// 1. Host map hostname (from peer aliases + /etc/fips/hosts)
    /// 2. Configured peer alias or short npub (from startup map)
    /// 3. Active peer's short npub (e.g., inbound peer not in config)
    /// 4. Session endpoint's short npub (end-to-end, may not be direct peer)
    /// 5. Truncated NodeAddr hex (unknown address)
    pub(crate) fn peer_display_name(&self, addr: &NodeAddr) -> String {
        if let Some(hostname) = self.host_map.lookup_hostname(addr) {
            return hostname.to_string();
        }
        if let Some(name) = self.peer_aliases.get(addr) {
            return name.clone();
        }
        if let Some(peer) = self.peers.get(addr) {
            return peer.identity().short_npub();
        }
        if let Some(entry) = self.sessions.get(addr) {
            let (xonly, _) = entry.remote_pubkey().x_only_public_key();
            return PeerIdentity::from_pubkey(xonly).short_npub();
        }
        addr.short_hex()
    }

    /// Tear down a receiver-index entry.
    pub(in crate::node) fn deregister_session_index(&mut self, cache_key: (TransportId, u32)) {
        // Remove the index and ask the peer registry for the remaining-owner
        // state in one step. Rekey drain depends on seeing the NEW index that
        // was already installed for the same peer.
        let removed_index = self.peers.remove_session_index_with_owner_state(&cache_key);
        let _ = removed_index;
    }

    /// Ensure the current FMP receive index resolves to this peer.
    ///
    /// Rekey msg1/msg2 handlers pre-register the pending index before
    /// cutover, but losing that registration in a debug build used to
    /// panic in the cutover path. Repairing the map here is safe: the
    /// peer has already promoted the pending session, and the decrypt
    /// worker registration immediately after cutover depends on the
    /// same `(transport_id, our_index)` key.
    pub(in crate::node) fn ensure_current_session_index_registered(
        &mut self,
        node_addr: &NodeAddr,
        context: &'static str,
    ) -> bool {
        match self
            .peers
            .ensure_current_session_index_registered(node_addr)
        {
            CurrentSessionIndexRegistration::MissingActivePeer => false,
            CurrentSessionIndexRegistration::MissingTransportId => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    context,
                    "Cannot register current session index without transport id"
                );
                false
            }
            CurrentSessionIndexRegistration::MissingLocalIndex => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    context,
                    "Cannot register current session index without local index"
                );
                false
            }
            CurrentSessionIndexRegistration::AlreadyRegistered(_) => true,
            CurrentSessionIndexRegistration::Repaired(registered) => {
                if let Some(existing) = registered.previous_owner {
                    warn!(
                        peer = %self.peer_display_name(node_addr),
                        previous_owner = %self.peer_display_name(&existing),
                        transport_id = %registered.session_index.key.0,
                        our_index = %registered.session_index.index,
                        context,
                        "Repairing current session index with stale owner"
                    );
                } else {
                    warn!(
                        peer = %self.peer_display_name(node_addr),
                        transport_id = %registered.session_index.key.0,
                        our_index = %registered.session_index.index,
                        context,
                        "Repairing missing current session index"
                    );
                }
                true
            }
        }
    }

    pub(in crate::node) fn log_active_peer_insert_result(
        &self,
        node_addr: &NodeAddr,
        inserted: &InsertedActivePeer,
        context: &'static str,
    ) {
        if let Some(previous_peer) = inserted.previous_peer.as_ref() {
            debug!(
                peer = %self.peer_display_name(node_addr),
                previous_link_id = %previous_peer.link_id(),
                context,
                "Replaced active peer storage during lifecycle insert"
            );
        }

        match inserted.current_session_index {
            Some(registered) => {
                if let Some(previous_owner) = registered.previous_owner {
                    debug!(
                        peer = %self.peer_display_name(node_addr),
                        previous_owner = %self.peer_display_name(&previous_owner),
                        transport_id = %registered.session_index.key.0,
                        our_index = %registered.session_index.index,
                        context,
                        "Replaced current session-index owner during lifecycle insert"
                    );
                }
            }
            None => {
                warn!(
                    peer = %self.peer_display_name(node_addr),
                    context,
                    "Inserted active peer without a current session index"
                );
            }
        }
    }

    pub(in crate::node) fn log_active_peer_session_replacement_result(
        &self,
        node_addr: &NodeAddr,
        replacement: &ReplacedActivePeerCurrentSession,
        context: &'static str,
    ) {
        if replacement.replay_suppressed_count > 0 {
            debug!(
                peer = %self.peer_display_name(node_addr),
                count = replacement.replay_suppressed_count,
                context,
                "Suppressed replay detections during link transition"
            );
        }

        if let Some(previous_owner) = replacement.new_session_index.previous_owner {
            debug!(
                peer = %self.peer_display_name(node_addr),
                previous_owner = %self.peer_display_name(&previous_owner),
                transport_id = %replacement.new_session_index.session_index.key.0,
                our_index = %replacement.new_session_index.session_index.index,
                context,
                "Replaced current session-index owner during session replacement"
            );
        }
    }

    pub(in crate::node) fn log_registered_peer_session_index_result(
        &self,
        node_addr: &NodeAddr,
        registered: &RegisteredPeerSessionIndex,
        context: &'static str,
    ) {
        if let Some(previous_owner) = registered.previous_owner {
            debug!(
                peer = %self.peer_display_name(node_addr),
                previous_owner = %self.peer_display_name(&previous_owner),
                transport_id = %registered.session_index.key.0,
                our_index = %registered.session_index.index,
                index_kind = ?registered.session_index.kind,
                context,
                "Replaced session-index owner during lifecycle registration"
            );
        }
    }

    // === Configuration ===

    /// Get the configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Calculate the effective IPv6 MTU that can be sent over FIPS.
    ///
    /// Delegates to `upper::icmp::effective_ipv6_mtu()` with this node's
    /// transport MTU. Returns the maximum IPv6 packet size (including
    /// IPv6 header) that can be transmitted through the FIPS mesh.
    pub fn effective_ipv6_mtu(&self) -> u16 {
        crate::upper::icmp::effective_ipv6_mtu(self.transport_mtu())
    }

    /// Get the transport MTU governing the global TUN-boundary MSS clamp.
    ///
    /// Returns the **minimum** MTU across all operational transports, or
    /// 1280 (IPv6 minimum) as fallback. Used for initial TUN configuration
    /// where a specific egress transport isn't yet known: the resulting
    /// `effective_ipv6_mtu` (transport_mtu - 77) and `max_mss`
    /// (effective_mtu - 60) form a conservative ceiling that fits ANY
    /// configured-transport's egress, eliminating PMTU-D black holes that
    /// would otherwise occur when a flow's actual egress is smaller than
    /// the clamp ceiling assumed at TUN init.
    ///
    /// Returning the smallest (rather than the first-iterated, which used
    /// to vary across HashMap iteration order + async-startup race) makes
    /// the clamp deterministic across daemon restarts.
    ///
    /// See `ISSUE-2026-0011` for the empirical investigation.
    pub fn transport_mtu(&self) -> u16 {
        let min_operational = self
            .transports
            .values()
            .filter(|h| h.is_operational())
            .map(|h| h.mtu())
            .min();
        if let Some(mtu) = min_operational {
            return mtu;
        }
        // Fallback to config: try UDP first, then Ethernet
        if let Some((_, cfg)) = self.config.transports.udp.iter().next() {
            return cfg.mtu();
        }
        1280
    }

    // === State ===

    /// Get the node state.
    pub fn state(&self) -> NodeState {
        self.state
    }

    /// Get the node uptime.
    pub fn uptime(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }

    /// Check if node is operational.
    pub fn is_running(&self) -> bool {
        self.state.is_operational()
    }

    /// Check if this is a leaf-only node.
    pub fn is_leaf_only(&self) -> bool {
        self.is_leaf_only
    }

    // === Tree State ===

    /// Get the tree state.
    pub fn tree_state(&self) -> &TreeState {
        &self.tree_state
    }

    /// Get mutable tree state.
    pub fn tree_state_mut(&mut self) -> &mut TreeState {
        &mut self.tree_state
    }

    // === Bloom State ===

    /// Get the Bloom filter state.
    pub fn bloom_state(&self) -> &BloomState {
        &self.bloom_state
    }

    /// Get mutable Bloom filter state.
    pub fn bloom_state_mut(&mut self) -> &mut BloomState {
        &mut self.bloom_state
    }

    // === Mesh Size Estimate ===

    /// Get the cached estimated mesh size.
    pub fn estimated_mesh_size(&self) -> Option<u64> {
        self.estimated_mesh_size
    }

    /// Compute and cache the estimated mesh size from bloom filters.
    ///
    /// Uses the spanning tree partition: parent's filter covers nodes reachable
    /// upward, children's filters cover subtrees downward. The OR-union of
    /// those filters plus self approximates total network size without
    /// double-counting overlapping filters.
    pub(crate) fn compute_mesh_size(&mut self) {
        let my_addr = *self.tree_state.my_node_addr();
        let parent_id = *self.tree_state.my_declaration().parent_id();
        let is_root = self.tree_state.is_root();

        let max_fpr = self.config.node.bloom.max_inbound_fpr;
        let mut child_count: u32 = 0;
        let mut union: Option<BloomFilter> = None;

        let add_to_union = |union: &mut Option<BloomFilter>, filter: &BloomFilter| match union {
            None => *union = Some(filter.clone()),
            Some(existing) => {
                // Size-class mismatch is skipped rather than fatal.
                let _ = existing.merge(filter);
            }
        };

        // Parent's filter: nodes reachable upward through the tree.
        if !is_root
            && let Some(parent) = self.peers.get(&parent_id)
            && let Some(filter) = parent.inbound_filter()
        {
            add_to_union(&mut union, filter);
        }

        // Children's filters: each child's subtree is ideally disjoint; OR is
        // idempotent when filters overlap.
        for (peer_addr, peer) in &self.peers {
            if peer_addr == &parent_id {
                continue;
            }
            if let Some(decl) = self.tree_state.peer_declaration(peer_addr)
                && *decl.parent_id() == my_addr
            {
                child_count += 1;
                if let Some(filter) = peer.inbound_filter() {
                    add_to_union(&mut union, filter);
                }
            }
        }

        let Some(mut union) = union else {
            self.estimated_mesh_size = None;
            return;
        };
        union.insert(&my_addr);

        // If the union is saturated or above the FPR cap, refuse to estimate
        // rather than publish a biased aggregate.
        let Some(union_estimate) = union.estimated_count(max_fpr) else {
            self.estimated_mesh_size = None;
            return;
        };

        let size = union_estimate.round() as u64;
        self.estimated_mesh_size = Some(size);

        // Periodic logging (reuse MMP default interval: 30s)
        let now = std::time::Instant::now();
        let should_log = match self.last_mesh_size_log {
            None => true,
            Some(last) => {
                now.duration_since(last)
                    >= std::time::Duration::from_secs(self.config.node.mmp.log_interval_secs)
            }
        };
        if should_log {
            tracing::debug!(
                estimated_mesh_size = size,
                peers = self.peers.len(),
                children = child_count,
                "Mesh size estimate"
            );
            self.last_mesh_size_log = Some(now);
        }
    }

    // === Coord Cache ===

    /// Get the coordinate cache.
    pub fn coord_cache(&self) -> &CoordCache {
        &self.coord_cache
    }

    /// Get mutable coordinate cache.
    pub fn coord_cache_mut(&mut self) -> &mut CoordCache {
        &mut self.coord_cache
    }

    // === Node Statistics ===

    /// Get the node statistics.
    pub fn stats(&self) -> &stats::NodeStats {
        &self.stats
    }

    /// Get mutable node statistics.
    pub(crate) fn stats_mut(&mut self) -> &mut stats::NodeStats {
        &mut self.stats
    }

    /// Get the stats history collector.
    pub fn stats_history(&self) -> &stats_history::StatsHistory {
        &self.stats_history
    }

    /// Sample the current node state into the stats history ring.
    /// Called once per tick from the RX loop.
    pub(crate) fn record_stats_history(&mut self) {
        let fwd = &self.stats.forwarding;
        let now = std::time::Instant::now();
        let peers_with_mmp: Vec<f64> = self
            .peers
            .keys()
            .filter_map(|addr| {
                self.packet_mover2
                    .fmp_link_metrics(addr, now)
                    .map(|metrics| metrics.loss_rate)
            })
            .collect();
        let loss_rate = if peers_with_mmp.is_empty() {
            0.0
        } else {
            peers_with_mmp.iter().sum::<f64>() / peers_with_mmp.len() as f64
        };

        let snap = stats_history::Snapshot {
            mesh_size: self.estimated_mesh_size,
            tree_depth: self.tree_state.my_coords().depth() as u32,
            peer_count: self.peers.len() as u64,
            parent_switches_total: self.stats.tree.parent_switches,
            bytes_in_total: fwd.received_bytes,
            bytes_out_total: fwd.forwarded_bytes + fwd.originated_bytes,
            packets_in_total: fwd.received_packets,
            packets_out_total: fwd.forwarded_packets + fwd.originated_packets,
            loss_rate,
            active_sessions: self.sessions.len() as u64,
        };

        let peer_snaps: Vec<stats_history::PeerSnapshot> = self
            .peers
            .values()
            .map(|p| {
                let stats = p.link_stats();
                let metrics = self.packet_mover2.fmp_link_metrics(p.node_addr(), now);
                let srtt_ms = metrics.and_then(|metrics| metrics.srtt_ms);
                let loss_rate = metrics.map(|metrics| metrics.loss_rate);
                let ecn_ce = metrics.map_or(0, |metrics| metrics.ecn_ce_count as u64);
                stats_history::PeerSnapshot {
                    node_addr: *p.node_addr(),
                    last_seen: now,
                    srtt_ms,
                    loss_rate,
                    bytes_in_total: stats.bytes_recv,
                    bytes_out_total: stats.bytes_sent,
                    packets_in_total: stats.packets_recv,
                    packets_out_total: stats.packets_sent,
                    ecn_ce_total: ecn_ce,
                }
            })
            .collect();

        self.stats_history.tick(now, &snap, &peer_snaps);
    }

    // === TUN Interface ===

    /// Get the TUN state.
    pub fn tun_state(&self) -> TunState {
        self.tun_state
    }

    /// Get the TUN interface name, if active.
    pub fn tun_name(&self) -> Option<&str> {
        self.tun_name.as_deref()
    }

    // === Resource Limits ===

    /// Set the maximum number of connections (handshake phase).
    pub fn set_max_connections(&mut self, max: usize) {
        self.max_connections = max;
    }

    /// Set the maximum number of peers (authenticated).
    pub fn set_max_peers(&mut self, max: usize) {
        self.max_peers = max;
    }

    /// Returns false when starting more outbound work would exceed a resource
    /// cap. A cap of `0` means uncapped.
    pub(crate) fn outbound_admission_check(&self) -> bool {
        let connection_used = self
            .peers
            .connection_len()
            .saturating_add(self.pending_connects.len());
        let peer_allowed = self.max_peers == 0 || self.peers.len() < self.max_peers;
        let connection_allowed =
            self.max_connections == 0 || connection_used < self.max_connections;
        let link_allowed = self.max_links == 0 || self.links.len() < self.max_links;
        peer_allowed && connection_allowed && link_allowed
    }

    /// Admission for public/open-discovery outbound work. This includes the
    /// general connection/link caps and, when open Nostr discovery is enabled,
    /// the configured non-peer budget.
    pub(crate) fn open_discovery_outbound_admission_check(&self) -> bool {
        if !self.outbound_admission_check() {
            return false;
        }

        let nostr = &self.config.node.discovery.nostr;
        if !nostr.enabled || nostr.policy != NostrDiscoveryPolicy::Open {
            return true;
        }

        let configured_npubs = self
            .config
            .peers()
            .iter()
            .map(|peer| peer.npub.clone())
            .collect::<HashSet<_>>();
        self.open_discovery_enqueue_budget(&configured_npubs) > 0
    }

    /// Like `outbound_admission_check`, but for racing a better path to a
    /// peer that is already authenticated. This may temporarily add a
    /// connection/link, but it does not consume a new peer slot.
    pub(crate) fn outbound_direct_refresh_admission_check(&self) -> bool {
        let connection_used = self
            .peers
            .connection_len()
            .saturating_add(self.pending_connects.len());
        let connection_allowed =
            self.max_connections == 0 || connection_used < self.max_connections;
        let link_allowed = self.max_links == 0 || self.links.len() < self.max_links;
        connection_allowed && link_allowed
    }

    /// Set the maximum number of links.
    pub fn set_max_links(&mut self, max: usize) {
        self.max_links = max;
    }

    // === Counts ===

    /// Number of pending connections (handshake in progress).
    pub fn connection_count(&self) -> usize {
        self.peers.connection_len()
    }

    /// Number of authenticated peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Number of active links.
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Number of active transports.
    pub fn transport_count(&self) -> usize {
        self.transports.len()
    }

    // === Transport Management ===

    /// Allocate a new transport ID.
    pub fn allocate_transport_id(&mut self) -> TransportId {
        let id = TransportId::new(self.next_transport_id);
        self.next_transport_id += 1;
        id
    }

    /// Get a transport by ID.
    pub fn get_transport(&self, id: &TransportId) -> Option<&TransportHandle> {
        self.transports.get(id)
    }

    /// Get mutable transport by ID.
    pub fn get_transport_mut(&mut self, id: &TransportId) -> Option<&mut TransportHandle> {
        self.transports.get_mut(id)
    }

    /// Iterate over transport IDs.
    pub fn transport_ids(&self) -> impl Iterator<Item = &TransportId> {
        self.transports.keys()
    }

    /// Get the packet receiver for the event loop.
    pub fn packet_rx(&mut self) -> Option<&mut PacketRx> {
        self.packet_rx.as_mut()
    }

    // === Link Management ===

    /// Allocate a new link ID.
    pub fn allocate_link_id(&mut self) -> LinkId {
        let id = LinkId::new(self.next_link_id);
        self.next_link_id += 1;
        id
    }

    /// Add a link.
    pub fn add_link(&mut self, link: Link) -> Result<(), NodeError> {
        if self.max_links > 0 && self.links.len() >= self.max_links {
            return Err(NodeError::MaxLinksExceeded {
                max: self.max_links,
            });
        }
        let link_id = link.link_id();

        self.links.insert(link_id, link);
        Ok(())
    }

    /// Get a link by ID.
    pub fn get_link(&self, link_id: &LinkId) -> Option<&Link> {
        self.links.get(link_id)
    }

    /// Get a mutable link by ID.
    pub fn get_link_mut(&mut self, link_id: &LinkId) -> Option<&mut Link> {
        self.links.get_mut(link_id)
    }

    /// Find link ID by transport address.
    pub fn find_link_by_addr(
        &self,
        transport_id: TransportId,
        addr: &TransportAddr,
    ) -> Option<LinkId> {
        self.links.lookup_addr(transport_id, addr)
    }

    /// Remove a link.
    ///
    /// Only removes the reverse address dispatch entry if it still points to this
    /// link. In cross-connection scenarios, a newer link may have replaced the
    /// entry for the same address.
    pub fn remove_link(&mut self, link_id: &LinkId) -> Option<Link> {
        self.links.remove(link_id)
    }

    pub(crate) fn cleanup_bootstrap_transport_if_unused(&mut self, transport_id: TransportId) {
        if !self.bootstrap_transports.contains(&transport_id) {
            return;
        }

        let transport_in_use = self
            .links
            .values()
            .any(|link| link.transport_id() == transport_id)
            || self
                .peers
                .connection_values()
                .any(|conn| conn.transport_id() == Some(transport_id))
            || self
                .peers
                .values()
                .any(|peer| peer.transport_id() == Some(transport_id))
            || self
                .pending_connects
                .iter()
                .any(|pending| pending.transport_id == transport_id);

        if transport_in_use {
            return;
        }

        tracing::debug!(
            transport_id = %transport_id,
            "bootstrap transport has no remaining references; dropping"
        );

        self.bootstrap_transports.remove(&transport_id);
        self.transport_drops.remove(&transport_id);
        self.transport_socket_drops.remove(&transport_id);
        self.transport_namespace_drops.remove(&transport_id);
        self.transports.remove(&transport_id);
        self.udp_transport_resolution_cache.clear();
    }

    /// Iterate over all links.
    pub fn links(&self) -> impl Iterator<Item = &Link> {
        self.links.values()
    }

    // === Connection Management (Handshake Phase) ===

    /// Add a pending connection.
    pub fn add_connection(&mut self, connection: PeerConnection) -> Result<(), NodeError> {
        let link_id = connection.link_id();

        if self.peers.contains_connection(&link_id) {
            return Err(NodeError::ConnectionAlreadyExists(link_id));
        }

        if self.max_connections > 0 && self.peers.connection_len() >= self.max_connections {
            return Err(NodeError::MaxConnectionsExceeded {
                max: self.max_connections,
            });
        }

        self.peers.insert_connection(link_id, connection);
        Ok(())
    }

    /// Get a connection by LinkId.
    pub fn get_connection(&self, link_id: &LinkId) -> Option<&PeerConnection> {
        self.peers.get_connection(link_id)
    }

    /// Get a mutable connection by LinkId.
    pub fn get_connection_mut(&mut self, link_id: &LinkId) -> Option<&mut PeerConnection> {
        self.peers.get_connection_mut(link_id)
    }

    /// Remove a connection.
    pub fn remove_connection(&mut self, link_id: &LinkId) -> Option<PeerConnection> {
        self.peers.remove_connection(link_id)
    }

    /// Iterate over all connections.
    pub fn connections(&self) -> impl Iterator<Item = &PeerConnection> {
        self.peers.connection_values()
    }

    // === Peer Management (Active Phase) ===

    /// Get a peer by NodeAddr.
    pub fn get_peer(&self, node_addr: &NodeAddr) -> Option<&ActivePeer> {
        self.peers.get(node_addr)
    }

    /// Get a mutable peer by NodeAddr.
    pub fn get_peer_mut(&mut self, node_addr: &NodeAddr) -> Option<&mut ActivePeer> {
        self.peers.get_mut(node_addr)
    }

    /// Remove a peer.
    pub fn remove_peer(&mut self, node_addr: &NodeAddr) -> Option<ActivePeer> {
        self.peers.remove(node_addr)
    }

    /// Iterate over all peers.
    pub fn peers(&self) -> impl Iterator<Item = &ActivePeer> {
        self.peers.values()
    }

    /// Reference to the Nostr discovery handle if discovery is enabled.
    /// Used by control queries (`show_peers` per-peer Nostr-traversal
    /// state) to read failure-state without taking shared ownership.
    pub fn nostr_discovery_handle(&self) -> Option<&crate::discovery::nostr::NostrDiscovery> {
        self.nostr_discovery.as_deref()
    }

    /// Iterate over all peer node IDs.
    pub fn peer_ids(&self) -> impl Iterator<Item = &NodeAddr> {
        self.peers.keys()
    }

    /// Iterate over peers that can send traffic.
    pub fn sendable_peers(&self) -> impl Iterator<Item = &ActivePeer> {
        self.peers.values().filter(|p| p.can_send())
    }

    /// Number of peers that can send traffic.
    pub fn sendable_peer_count(&self) -> usize {
        self.peers.values().filter(|p| p.can_send()).count()
    }

    pub(crate) fn set_discovery_fallback_transit_allowed(
        &mut self,
        peer_addr: NodeAddr,
        allowed: bool,
    ) {
        self.discovery_fallback_transit
            .set_allowed(peer_addr, allowed);
    }

    pub(crate) fn configured_discovery_fallback_transit(
        &self,
        peer_addr: &NodeAddr,
    ) -> Option<bool> {
        self.configured_peer(peer_addr)
            .map(|peer| peer.discovery_fallback_transit)
    }

    pub(crate) fn configured_peer(&self, peer_addr: &NodeAddr) -> Option<&PeerConfig> {
        self.configured_peer_send_weights.peer_config(peer_addr)
    }

    pub(in crate::node) fn active_peer_uses_configured_static_udp_path(
        &self,
        peer_addr: &NodeAddr,
    ) -> bool {
        let Some(peer_config) = self.configured_peer(peer_addr) else {
            return false;
        };

        peer_config.addresses.iter().any(|candidate| {
            candidate.seen_at_ms.is_none()
                && candidate.transport.eq_ignore_ascii_case("udp")
                && self.active_peer_matches_candidate(peer_addr, candidate)
        })
    }

    pub(crate) fn discovery_fallback_transit_for_promotion(&self, peer_addr: &NodeAddr) -> bool {
        if let Some(retry_state) = self.retry_pending.get(peer_addr) {
            return retry_state.peer_config.discovery_fallback_transit;
        }

        if let Some(allowed) = self.configured_discovery_fallback_transit(peer_addr) {
            return allowed;
        }

        self.config.node.discovery.nostr.policy != crate::config::NostrDiscoveryPolicy::Open
    }
}
