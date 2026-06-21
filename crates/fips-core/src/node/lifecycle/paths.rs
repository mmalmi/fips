use super::*;

impl Node {
    pub(in crate::node) async fn try_peer_addresses(
        &mut self,
        peer_config: &PeerConfig,
        peer_identity: PeerIdentity,
        allow_bootstrap_nat: bool,
    ) -> Result<(), NodeError> {
        let peer_node_addr = *peer_identity.node_addr();
        if self.peers.contains_key(&peer_node_addr) {
            debug!(
                npub = %peer_config.npub,
                "Peer already exists, skipping address attempts"
            );
            return Ok(());
        }

        let candidates = self.peer_address_candidates(peer_config).await;

        if candidates.is_empty() {
            if allow_bootstrap_nat && self.request_nostr_bootstrap(peer_config).await {
                return Ok(());
            }
            return Err(NodeError::NoTransportForType(format!(
                "no addresses known for {}",
                peer_config.npub
            )));
        }

        if self
            .attempt_peer_address_list(peer_config, peer_identity, allow_bootstrap_nat, &candidates)
            .await
            .is_ok()
        {
            if allow_bootstrap_nat {
                self.request_nostr_bootstrap(peer_config).await;
            }
            return Ok(());
        }

        if allow_bootstrap_nat && self.request_nostr_bootstrap(peer_config).await {
            return Ok(());
        }

        Err(NodeError::NoTransportForType(format!(
            "no operational transport for any of {}'s addresses",
            peer_config.npub
        )))
    }

    pub(super) async fn try_active_peer_alternative_addresses(
        &mut self,
        peer_config: &PeerConfig,
        peer_identity: PeerIdentity,
        allow_same_path_refresh: bool,
    ) -> Result<bool, NodeError> {
        let peer_node_addr = *peer_identity.node_addr();
        let mut candidates = self.peer_address_candidates(peer_config).await;
        let same_path_refresh_needed = allow_same_path_refresh
            && self.peers.get(&peer_node_addr).is_some_and(|peer| {
                !peer.is_healthy() || self.active_peer_needs_same_path_refresh(&peer_node_addr)
            });
        if same_path_refresh_needed
            && let Some(candidate) = self.active_peer_current_udp_candidate(&peer_node_addr)
            && !candidates.iter().any(|existing| {
                existing.transport == candidate.transport && existing.addr == candidate.addr
            })
        {
            candidates.push(candidate);
            Self::sort_peer_address_candidates(&mut candidates);
        }
        let should_try_nostr =
            self.active_peer_should_keep_direct_retry(&peer_node_addr, peer_config);

        if candidates.is_empty() {
            if should_try_nostr && self.request_nostr_bootstrap(peer_config).await {
                return Ok(true);
            }
            return Err(NodeError::NoTransportForType(format!(
                "no addresses known for {}",
                peer_config.npub
            )));
        }

        let alternatives: Vec<_> = candidates
            .into_iter()
            .filter(|addr| {
                same_path_refresh_needed
                    || !self.active_peer_matches_candidate(&peer_node_addr, addr)
            })
            .collect();

        if alternatives.is_empty() {
            if should_try_nostr && self.request_nostr_bootstrap(peer_config).await {
                return Ok(true);
            }
            return Ok(false);
        }

        let needs_separate_nostr_attempt = should_try_nostr
            && !alternatives
                .iter()
                .any(|addr| addr.transport == "udp" && addr.addr.eq_ignore_ascii_case("nat"));
        let address_result = self
            .attempt_peer_address_list(peer_config, peer_identity, true, &alternatives)
            .await;
        let nostr_attempted =
            needs_separate_nostr_attempt && self.request_nostr_bootstrap(peer_config).await;

        match address_result {
            Ok(()) => Ok(true),
            Err(err) if nostr_attempted => {
                debug!(
                    npub = %peer_config.npub,
                    error = %err,
                    "Static active-peer direct-path alternatives failed; Nostr traversal still queued"
                );
                Ok(true)
            }
            Err(err) => Err(err),
        }
    }

    pub(in crate::node) async fn peer_address_candidates(
        &self,
        peer_config: &PeerConfig,
    ) -> Vec<PeerAddress> {
        // Merge every candidate from every source we have for this peer.
        // Explicitly configured addresses keep first shot, then freshly
        // fetched overlay adverts are appended as fallback candidates. This
        // lets native peers try known LAN/nvpn/static UDP routes before
        // slower WebRTC/Nostr-discovered paths, while still racing every
        // concrete candidate that fits in the per-peer budget.
        let static_addresses = self.static_peer_addresses(peer_config);
        let overlay_addresses = self
            .nostr_peer_fallback_addresses(peer_config, &static_addresses)
            .await;

        let mut candidates = Vec::with_capacity(overlay_addresses.len() + static_addresses.len());
        for addr in overlay_addresses.into_iter().chain(static_addresses) {
            if !candidates.iter().any(|existing: &PeerAddress| {
                existing.transport == addr.transport && existing.addr == addr.addr
            }) {
                candidates.push(addr);
            }
        }

        Self::sort_peer_address_candidates(&mut candidates);

        candidates
    }

    pub(super) fn sort_peer_address_candidates(candidates: &mut [PeerAddress]) {
        // Stable sort: explicit priority is the contract, and freshness only
        // breaks ties inside one priority tier. Overlay-discovered endpoints
        // are assigned lower priority than configured/static hints when both
        // exist, so operator-provided LAN routes keep first shot without
        // dropping fresh overlay candidates from the race.
        candidates.sort_by(|a, b| {
            if a.priority != b.priority {
                return a.priority.cmp(&b.priority);
            }
            match (a.seen_at_ms, b.seen_at_ms) {
                (Some(a_ts), Some(b_ts)) => b_ts.cmp(&a_ts),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        });
    }

    pub(super) fn active_peer_matches_any_candidate(
        &self,
        peer_node_addr: &NodeAddr,
        candidates: &[PeerAddress],
    ) -> bool {
        candidates
            .iter()
            .any(|candidate| self.active_peer_matches_candidate(peer_node_addr, candidate))
    }

    pub(in crate::node) fn active_peer_candidate_is_fresh_enough_to_skip(
        &self,
        peer_node_addr: &NodeAddr,
        candidates: &[PeerAddress],
    ) -> bool {
        if !self
            .peers
            .get(peer_node_addr)
            .is_some_and(|peer| peer.can_send())
        {
            return false;
        }
        if !self.active_peer_matches_any_candidate(peer_node_addr, candidates) {
            return false;
        }
        !self.active_peer_needs_same_path_refresh(peer_node_addr)
    }

    pub(in crate::node) fn active_peer_should_keep_direct_retry(
        &self,
        peer_node_addr: &NodeAddr,
        peer_config: &PeerConfig,
    ) -> bool {
        if !peer_config.auto_reconnect {
            return false;
        }

        let Some(peer) = self.peers.get(peer_node_addr) else {
            return false;
        };

        let static_addresses = self.static_peer_addresses(peer_config);
        if !static_addresses.is_empty() {
            let Some(peer) = self.peers.get(peer_node_addr) else {
                return true;
            };
            if peer
                .transport_id()
                .is_some_and(|transport_id| self.bootstrap_transports.contains(&transport_id))
            {
                return true;
            }
            let same_path_refresh_needed = self.active_peer_needs_same_path_refresh(peer_node_addr);
            if !self.active_peer_matches_any_candidate(peer_node_addr, &static_addresses)
                && peer.is_healthy()
                && peer.can_send()
                && !same_path_refresh_needed
            {
                return false;
            }
            if peer.can_send() && !same_path_refresh_needed {
                return false;
            }
            return !self
                .active_peer_candidate_is_fresh_enough_to_skip(peer_node_addr, &static_addresses);
        }

        if peer_config.npub.is_empty() {
            return false;
        }

        if !self.config.node.discovery.nostr.enabled
            || self.config.node.discovery.nostr.policy == NostrDiscoveryPolicy::Disabled
        {
            return false;
        }

        let Some(transport_id) = peer.transport_id() else {
            return true;
        };

        if self.bootstrap_transports.contains(&transport_id) {
            return self.active_peer_needs_same_path_refresh(peer_node_addr);
        }

        let Some(transport) = self.transports.get(&transport_id) else {
            return true;
        };

        if transport.transport_type().name != "udp" {
            return true;
        }

        self.active_peer_needs_same_path_refresh(peer_node_addr)
    }

    pub(in crate::node) fn clear_retry_unless_direct_refresh_needed(
        &mut self,
        peer_node_addr: &NodeAddr,
    ) {
        let keep_retry = self
            .retry_pending
            .get(peer_node_addr)
            .map(|state| state.peer_config.clone())
            .is_some_and(|peer_config| {
                self.active_peer_should_keep_direct_retry(peer_node_addr, &peer_config)
            });

        if !keep_retry {
            self.retry_pending.remove(peer_node_addr);
        }
    }

    pub(in crate::node) fn active_peer_needs_same_path_refresh(
        &self,
        peer_node_addr: &NodeAddr,
    ) -> bool {
        let Some(peer) = self.peers.get(peer_node_addr) else {
            return false;
        };
        let now_ms = Self::now_ms();
        if self.sessions.iter().any(|(_, entry)| {
            entry.is_established()
                && entry.last_outbound_next_hop() == Some(*peer_node_addr)
                && entry.has_recent_outbound_without_inbound(
                    now_ms,
                    self.session_direct_path_exclusive_trust_timeout_ms(),
                )
        }) {
            return true;
        }
        let stale_after_ms = self
            .config
            .node
            .heartbeat_interval_secs
            .saturating_mul(1000)
            .max(1000);
        let mut idle_ms = peer.idle_time(now_ms);
        if let Some(session_age_ms) = self
            .sessions
            .iter()
            .filter(|(_, entry)| {
                entry.is_established() && entry.last_outbound_next_hop() == Some(*peer_node_addr)
            })
            .filter_map(|(_, entry)| entry.last_authenticated_inbound_data_age_ms(now_ms))
            .min()
        {
            idle_ms = idle_ms.min(session_age_ms);
        }
        idle_ms > stale_after_ms
    }

    pub(in crate::node) fn active_peer_current_udp_candidate(
        &self,
        peer_node_addr: &NodeAddr,
    ) -> Option<PeerAddress> {
        let peer = self.peers.get(peer_node_addr)?;
        let current_addr = peer.current_addr()?;
        if let Some(transport_id) = peer.transport_id() {
            if let Some(transport) = self.transports.get(&transport_id) {
                if transport.transport_type().name != "udp" {
                    return None;
                }
            } else if !self
                .transports
                .values()
                .any(|transport| transport.transport_type().name == "udp")
            {
                return None;
            }
        } else if !self
            .transports
            .values()
            .any(|transport| transport.transport_type().name == "udp")
        {
            return None;
        }
        let socket_addr = current_addr.as_str()?.parse::<SocketAddr>().ok()?;

        // A healthy current endpoint has already authenticated for this peer,
        // so prefer it over older static/overlay hints during idle refresh.
        // Once liveness has marked the peer stale, keep the old tuple
        // probeable but stop presenting it as fresh; newer advert/traversal
        // candidates should get the limited race budget first after roaming.
        if peer.is_healthy() {
            Some(
                PeerAddress::with_priority("udp", socket_addr.to_string(), 0)
                    .with_seen_at_ms(Self::now_ms()),
            )
        } else {
            Some(PeerAddress::with_priority(
                "udp",
                socket_addr.to_string(),
                u8::MAX,
            ))
        }
    }

    pub(super) fn active_peer_current_path_priority(
        &self,
        peer_node_addr: &NodeAddr,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) -> Option<u8> {
        let peer = self.peers.get(peer_node_addr)?;
        if !peer.is_healthy() {
            return None;
        }
        if peer.transport_id() != Some(transport_id) || peer.current_addr() != Some(remote_addr) {
            return None;
        }
        let transport = self.transports.get(&transport_id)?;
        (transport.transport_type().name == "udp").then_some(0)
    }

    pub(in crate::node) fn active_peer_matches_candidate(
        &self,
        peer_node_addr: &NodeAddr,
        candidate: &PeerAddress,
    ) -> bool {
        let Some(peer) = self.peers.get(peer_node_addr) else {
            return false;
        };
        let Some(current_addr) = peer.current_addr() else {
            return false;
        };
        if let Some(peer_transport_id) = peer.transport_id()
            && let Some((candidate_transport_id, candidate_addr)) =
                self.resolve_peer_address_for_match(candidate)
        {
            return peer_transport_id == candidate_transport_id && current_addr == &candidate_addr;
        }
        if peer
            .transport_id()
            .map(|id| self.bootstrap_transports.contains(&id))
            .unwrap_or(false)
        {
            return false;
        }
        let current_addr = current_addr.to_string();
        let current_transport = peer
            .transport_id()
            .and_then(|id| self.transports.get(&id))
            .map(|transport| transport.transport_type().name);

        candidate.addr == current_addr
            && current_transport
                .map(|transport| transport == candidate.transport)
                .unwrap_or(true)
    }

    pub(super) fn configured_path_priority(
        &self,
        peer_node_addr: &NodeAddr,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) -> Option<u8> {
        self.configured_peer(peer_node_addr)?
            .addresses
            .iter()
            .filter_map(|candidate| {
                let (candidate_transport_id, candidate_addr) =
                    self.resolve_peer_address_for_match(candidate)?;
                (candidate_transport_id == transport_id && &candidate_addr == remote_addr)
                    .then_some(candidate.priority)
            })
            .min()
    }

    pub(in crate::node) fn configured_static_udp_path_for_peer(
        &self,
        peer_node_addr: &NodeAddr,
        transport_id: TransportId,
    ) -> Option<TransportAddr> {
        self.configured_peer(peer_node_addr)?
            .addresses
            .iter()
            .filter_map(|candidate| {
                if candidate.seen_at_ms.is_some()
                    || !candidate.transport.eq_ignore_ascii_case("udp")
                {
                    return None;
                }
                let (candidate_transport_id, candidate_addr) =
                    self.resolve_peer_address_for_match(candidate)?;
                (candidate_transport_id == transport_id)
                    .then_some((candidate.priority, candidate_addr))
            })
            .min_by_key(|(priority, _)| *priority)
            .map(|(_, addr)| addr)
    }

    pub(in crate::node) fn alternate_path_priority_allows_replace(
        &self,
        peer_node_addr: &NodeAddr,
        candidate_transport_id: TransportId,
        candidate_addr: &TransportAddr,
    ) -> bool {
        const UNKNOWN_PATH_PRIORITY: u16 = u8::MAX as u16 + 1;

        let Some(peer) = self.peers.get(peer_node_addr) else {
            return true;
        };
        let Some(current_transport_id) = peer.transport_id() else {
            return true;
        };
        let Some(current_addr) = peer.current_addr() else {
            return true;
        };

        let current_priority = self
            .configured_path_priority(peer_node_addr, current_transport_id, current_addr)
            .map(u16::from)
            .unwrap_or(UNKNOWN_PATH_PRIORITY);
        let candidate_priority = self
            .configured_path_priority(peer_node_addr, candidate_transport_id, candidate_addr)
            .map(u16::from)
            .unwrap_or(UNKNOWN_PATH_PRIORITY);

        if candidate_priority < current_priority {
            return true;
        }

        debug!(
            peer = %self.peer_display_name(peer_node_addr),
            current_transport_id = %current_transport_id,
            current_addr = %current_addr,
            current_priority,
            candidate_transport_id = %candidate_transport_id,
            candidate_addr = %candidate_addr,
            candidate_priority,
            "Suppressing lower-priority alternate path while current path remains healthy"
        );
        false
    }

    pub(in crate::node) fn authenticated_packet_path_allows_bookkeeping(
        &mut self,
        peer_node_addr: &NodeAddr,
        candidate_transport_id: TransportId,
        candidate_addr: &TransportAddr,
        now_ms: u64,
    ) -> bool {
        let Some(peer) = self.peers.get(peer_node_addr) else {
            return true;
        };

        if peer.transport_id() == Some(candidate_transport_id)
            && peer.current_addr() == Some(candidate_addr)
        {
            return true;
        }

        let current_path_sendable = peer.can_send();
        if !current_path_sendable
            || self.session_direct_path_blocks_direct_payload(peer_node_addr, now_ms)
        {
            return true;
        }

        debug!(
            peer = %self.peer_display_name(peer_node_addr),
            candidate_transport_id = %candidate_transport_id,
            candidate_addr = %candidate_addr,
            "Accepting authenticated direct-path rotation"
        );
        true
    }

    pub(in crate::node) fn active_peer_uses_recent_endpoint_path(
        &self,
        peer_node_addr: &NodeAddr,
        peer_config: &PeerConfig,
    ) -> bool {
        peer_config.addresses.iter().any(|addr| {
            addr.seen_at_ms.is_some() && self.active_peer_matches_candidate(peer_node_addr, addr)
        })
    }

    pub(in crate::node) fn active_peer_uses_traversal_path(
        &self,
        peer_node_addr: &NodeAddr,
        peer_config: &PeerConfig,
    ) -> bool {
        let via_bootstrap_transport = self
            .peers
            .get(peer_node_addr)
            .and_then(|peer| peer.transport_id())
            .map(|id| self.bootstrap_transports.contains(&id))
            .unwrap_or(false);

        via_bootstrap_transport
            || self.active_peer_uses_recent_endpoint_path(peer_node_addr, peer_config)
    }
}
