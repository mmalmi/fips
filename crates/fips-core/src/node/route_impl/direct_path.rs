use super::*;

impl Node {
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
            .saturating_add(500)
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

    pub(super) fn session_direct_discovered_endpoint_trust_expired(
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

    pub(in crate::node) fn restart_session_direct_path_validation(
        &mut self,
        dest: NodeAddr,
        now_ms: u64,
    ) {
        self.session_direct_degradation.restart_validation(
            dest,
            now_ms,
            SESSION_DIRECT_DEGRADED_HOLD_MS,
        );
        let _ = self.refresh_dataplane_fsp_owner_routes(&dest);
    }

    pub(in crate::node) fn authenticated_direct_session_validates_route(
        &mut self,
        dest: &NodeAddr,
        now_ms: u64,
    ) -> bool {
        self.session_direct_degradation
            .record_authenticated_payload_progress(dest, now_ms)
    }

    #[cfg(test)]
    pub(in crate::node) fn authenticated_direct_payload_validates_route(
        &mut self,
        dest: &NodeAddr,
        now_ms: u64,
    ) -> bool {
        self.session_direct_path_has_recent_data_return(dest, now_ms)
            && self.authenticated_direct_session_validates_route(dest, now_ms)
    }

    pub(in crate::node) fn clear_session_direct_path_degraded(&mut self, dest: &NodeAddr) -> bool {
        let changed = self.session_direct_degradation.clear(dest);
        if changed {
            // The direct FMP/FSP carrier has now authenticated payload again.
            // A rekey started only to recover this degraded carrier is no
            // longer useful; letting it complete later can flip epochs during
            // a subsequent roam and turn otherwise valid recovery traffic into
            // replay. Retire it at the same point that retires the direct-path
            // validation marker.
            let _ = self.abandon_fmp_rekey_for_peer(
                dest,
                "authenticated direct payload made recovery rekey obsolete",
            );
            if !self.active_peer_uses_websocket(dest)
                && !self.active_peer_uses_bootstrap_transport(dest)
            {
                // This is authenticated payload on the ordinary direct
                // carrier. Do not leave a stale retry entry reporting
                // `direct_probe_pending` or starting another recovery rekey
                // from older aggregate liveness samples.
                self.retry_pending.remove(dest);
            }
            let _ = self.refresh_dataplane_fsp_owner_routes(dest);
        }
        changed
    }

    pub(in crate::node) fn clear_session_direct_path_degraded_after_promotion(
        &mut self,
        dest: &NodeAddr,
        now_ms: u64,
    ) {
        let direct_was_degraded = self.session_direct_path_degradation_active(dest, now_ms);
        let active_fallback_next_hop = self
            .dataplane
            .fsp_owner_activity(dest)
            .and_then(|activity| activity.last_outbound_next_hop())
            .filter(|next_hop| next_hop != dest);
        let direct_validation_pending =
            self.session_direct_degradation.has_pending_validation(dest);
        if direct_validation_pending || active_fallback_next_hop.is_some() {
            let _ = self
                .session_direct_degradation
                .release_hold_for_validation(dest, now_ms);
            let _ = self.refresh_dataplane_fsp_owner_routes_via(dest, Some(*dest));
            debug!(
                peer = %self.peer_display_name(dest),
                direct_was_degraded,
                preserved_fallback_affinity = active_fallback_next_hop.is_some(),
                "Authenticated direct-path promotion started payload validation"
            );
            return;
        }

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

    pub(in crate::node) fn make_direct_payload_eligible_for_validation_after_fmp_recovery(
        &mut self,
        dest: &NodeAddr,
    ) {
        // FMP control proves only that the direct link recovered. It does not
        // prove that end-to-end FSP payload has returned to the direct path;
        // routed fallback traffic can remain healthy at the same time. Keep
        // the degradation marker and retry loop until authenticated direct FSP
        // receive activity clears them, but stage one direct FSP route now.
        // The previous fallback activity and learned route remain intact until
        // the staged direct payload is actually sent, so ordinary direct-path
        // trust expiry can immediately return traffic to the fallback if that
        // bounded validation gets no authenticated response.
        let authenticated_direct_udp = (self.active_peer_current_udp_candidate(dest).is_some()
            || self.promoted_path_matches_configured_static_peer(dest))
            && !self.active_peer_uses_bootstrap_transport(dest)
            && self
                .peers
                .get(dest)
                .is_some_and(|peer| peer.is_healthy() && peer.can_send());
        if !authenticated_direct_udp {
            return;
        }

        let fallback_next_hop = self
            .dataplane
            .fsp_owner_activity(dest)
            .and_then(|activity| activity.last_outbound_next_hop())
            .filter(|next_hop| next_hop != dest);
        let _ = self
            .session_direct_degradation
            .release_hold_for_validation(dest, Self::now_ms());
        let refreshed = self.refresh_dataplane_fsp_owner_routes_via(dest, Some(*dest));
        let pending_payload_validation =
            self.session_direct_degradation.has_pending_validation(dest);
        debug!(
            peer = %self.peer_display_name(dest),
            preserved_fallback_affinity = fallback_next_hop.is_some(),
            refreshed,
            pending_payload_validation,
            "Authenticated FMP recovery made direct FSP payload eligible for validation"
        );
        if !pending_payload_validation {
            self.clear_retry_unless_direct_refresh_needed(dest);
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
}
