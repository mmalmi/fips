use super::*;

impl Node {
    // === End-to-End Sessions ===

    /// Get a session by remote NodeAddr.
    /// Disable the discovery forward rate limiter (for tests).
    #[cfg(test)]
    pub(crate) fn disable_discovery_forward_rate_limit(&mut self) {
        self.discovery_forward_limiter
            .set_interval(std::time::Duration::ZERO);
    }

    #[cfg(test)]
    pub(crate) fn get_session(&self, remote: &NodeAddr) -> Option<&SessionEntry> {
        self.sessions.get(remote)
    }

    /// Remove a session.
    #[cfg(test)]
    pub(crate) fn remove_session(&mut self, remote: &NodeAddr) -> Option<SessionEntry> {
        self.sessions.remove(remote)
    }

    /// Read the path_mtu_lookup entry for a destination FipsAddress.
    #[cfg(test)]
    pub(crate) fn path_mtu_lookup_get(&self, fips_addr: &crate::FipsAddress) -> Option<u16> {
        self.path_mtu_lookup
            .read()
            .ok()
            .and_then(|map| map.get(fips_addr).copied())
    }

    /// Write a path_mtu_lookup entry directly (for tests that pre-seed the map).
    #[cfg(test)]
    pub(crate) fn path_mtu_lookup_insert(&self, fips_addr: crate::FipsAddress, mtu: u16) {
        if let Ok(mut map) = self.path_mtu_lookup.write() {
            map.insert(fips_addr, mtu);
        }
    }

    /// Number of end-to-end sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Iterate over all session entries (for control queries).
    pub(crate) fn session_entries(&self) -> impl Iterator<Item = (&NodeAddr, &SessionEntry)> {
        self.sessions.iter()
    }

    pub(crate) fn session_dataplane_counters(&self, addr: &NodeAddr) -> (u64, u64, u64, u64) {
        self.dataplane
            .fsp_owner_activity(addr)
            .map_or((0, 0, 0, 0), |activity| activity.traffic_counters())
    }

    pub(crate) fn session_dataplane_activity_ms(&self, addr: &NodeAddr) -> Option<u64> {
        self.dataplane
            .fsp_owner_activity(addr)
            .and_then(|activity| activity.session_idle_activity_ms())
    }

    pub(crate) fn session_dataplane_epoch(&self, addr: &NodeAddr) -> Option<(u64, bool, bool)> {
        let activity = self.dataplane.fsp_owner_activity(addr)?;
        Some((
            activity.fsp_session_start_ms()?,
            activity.current_k_bit(),
            activity.is_draining(),
        ))
    }

    pub(crate) fn session_mmp_snapshot(
        &self,
        addr: &NodeAddr,
    ) -> Option<crate::dataplane::DataplaneFspMmpSnapshot> {
        self.dataplane.fsp_mmp_snapshot(addr)
    }

    // === Identity Cache ===

    /// Register a node in the identity cache for FipsAddress → NodeAddr lookup.
    pub(crate) fn register_identity(
        &mut self,
        node_addr: NodeAddr,
        pubkey: secp256k1::PublicKey,
    ) -> bool {
        // Endpoint sends pass the same PeerIdentity on every packet. Once
        // validated, avoid re-deriving NodeAddr from the public key in the
        // data path; that hash showed up in macOS sender profiles.
        self.identity_cache.register(
            node_addr,
            pubkey,
            Self::now_ms(),
            self.config.node.cache.identity_size,
        )
    }

    /// Register an identity explicitly resolved through the authenticated
    /// `.fips` DNS namespace.
    pub(crate) fn register_dns_identity(
        &mut self,
        node_addr: NodeAddr,
        pubkey: secp256k1::PublicKey,
    ) -> bool {
        self.register_endpoint_identity(node_addr, pubkey)
    }

    /// Register an identity explicitly selected by the embedding application.
    ///
    /// Unlike an identity learned from ambient mesh traffic, an endpoint
    /// destination is authoritative local intent and may use configured
    /// transit when no tree or learned route is ready yet.
    pub(crate) fn register_endpoint_identity(
        &mut self,
        node_addr: NodeAddr,
        pubkey: secp256k1::PublicKey,
    ) -> bool {
        self.identity_cache.register_explicit_target(
            node_addr,
            pubkey,
            Self::now_ms(),
            self.config.node.cache.identity_size,
        )
    }

    pub(crate) fn is_explicit_target_identity(&self, node_addr: &NodeAddr) -> bool {
        self.identity_cache.is_explicit_target(node_addr)
    }

    /// Look up a destination by FipsAddress prefix (bytes 1-15 of the IPv6 address).
    pub(crate) fn lookup_by_fips_prefix(
        &mut self,
        prefix: &[u8; 15],
    ) -> Option<(NodeAddr, secp256k1::PublicKey)> {
        self.identity_cache.lookup_by_prefix(prefix, Self::now_ms())
    }

    /// Check if a node's identity is in the cache (without LRU touch).
    pub(crate) fn has_cached_identity(&self, addr: &NodeAddr) -> bool {
        self.identity_cache.has_prefix_for(addr)
    }

    /// Number of identity cache entries.
    pub fn identity_cache_len(&self) -> usize {
        self.identity_cache.len()
    }

    /// Iterate over identity cache entries.
    ///
    /// Returns `(NodeAddr, PublicKey, last_seen_ms)` for each cached identity.
    /// Used by the `show_identity_cache` control query.
    pub fn identity_cache_iter(
        &self,
    ) -> impl Iterator<Item = (&NodeAddr, &secp256k1::PublicKey, u64)> {
        self.identity_cache.iter()
    }

    /// Configured maximum identity cache size.
    pub fn identity_cache_max(&self) -> usize {
        self.config.node.cache.identity_size
    }

    /// Number of pending discovery lookups.
    pub fn pending_lookup_count(&self) -> usize {
        self.pending_lookups.len()
    }

    /// Iterate over pending discovery lookups for diagnostics.
    pub fn pending_lookups_iter(
        &self,
    ) -> impl Iterator<Item = (&NodeAddr, &handlers::discovery::PendingLookup)> {
        self.pending_lookups.iter()
    }

    /// Number of recent discovery requests tracked.
    pub fn recent_request_count(&self) -> usize {
        self.recent_requests.len()
    }

    /// Count of destinations with queued TUN packets awaiting session setup.
    pub fn pending_tun_destinations(&self) -> usize {
        self.pending_session_traffic.tun_destination_count()
    }

    /// Total TUN packets queued across all destinations.
    pub fn pending_tun_total_packets(&self) -> usize {
        self.pending_session_traffic.tun_packet_count()
    }

    /// Iterate over retry state for diagnostics.
    pub fn retry_state_iter(&self) -> impl Iterator<Item = (&NodeAddr, &retry::RetryState)> {
        self.retry_pending.iter()
    }
}
