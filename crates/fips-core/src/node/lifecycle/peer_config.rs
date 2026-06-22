use super::*;

impl Node {
    /// Initiate connections to configured static peers.
    ///
    /// For each peer configured with AutoConnect policy, creates a link and
    /// peer entry, then starts the Noise handshake by sending the first message.
    /// Replace the runtime peer list. Newly added auto-connect peers get
    /// `initiate_peer_connection` immediately; removed peers are dropped from
    /// the retry queue (the regular liveness timeout reaps any active session
    /// — we don't proactively disconnect, since the same npub might be on its
    /// way back via a fresh advert). Existing auto-connect entries with new
    /// direct addresses are dialed immediately, and retry state is refreshed
    /// so later attempts also use the latest hints.
    pub(in crate::node) async fn update_peers(
        &mut self,
        new_peers: Vec<crate::config::PeerConfig>,
    ) -> Result<crate::node::UpdatePeersOutcome, crate::node::NodeError> {
        use std::collections::{HashMap, HashSet};

        let mut new_by_addr: HashMap<crate::identity::NodeAddr, crate::config::PeerConfig> =
            HashMap::with_capacity(new_peers.len());
        let mut new_order = Vec::with_capacity(new_peers.len());
        for peer in new_peers {
            let identity = match self.configured_or_parsed_peer_identity(&peer.npub) {
                Ok(id) => id,
                Err(e) => {
                    return Err(crate::node::NodeError::InvalidPeerNpub {
                        npub: peer.npub.clone(),
                        reason: e,
                    });
                }
            };
            // Last-write-wins on duplicates so callers passing a multi-source
            // candidate list (e.g. operator hints + recent-peers cache for
            // the same npub) get the merge they meant.
            let node_addr = *identity.node_addr();
            if !new_by_addr.contains_key(&node_addr) {
                new_order.push(node_addr);
            }
            new_by_addr.insert(node_addr, peer);
        }

        let current_by_addr: HashMap<crate::identity::NodeAddr, crate::config::PeerConfig> = self
            .config
            .peers()
            .iter()
            .filter_map(|pc| {
                self.configured_or_parsed_peer_identity(&pc.npub)
                    .ok()
                    .map(|id| (*id.node_addr(), pc.clone()))
            })
            .collect();

        let new_addrs: HashSet<_> = new_by_addr.keys().copied().collect();
        let current_addrs: HashSet<_> = current_by_addr.keys().copied().collect();

        let removed: Vec<_> = current_addrs.difference(&new_addrs).copied().collect();
        let added: Vec<_> = new_addrs.difference(&current_addrs).copied().collect();
        let kept: Vec<_> = new_addrs.intersection(&current_addrs).copied().collect();

        let mut outcome = crate::node::UpdatePeersOutcome::default();

        for node_addr in &removed {
            if self.retry_pending.remove(node_addr).is_some() {
                debug!(
                    peer = %self.peer_display_name(node_addr),
                    "Dropping retry entry for peer removed from runtime peer list"
                );
            }
            self.peer_aliases.remove(node_addr);
            self.set_discovery_fallback_transit_allowed(*node_addr, false);
            outcome.removed += 1;
        }

        let mut auto_connect_refresh_configs = Vec::new();
        for node_addr in &kept {
            let new_pc = &new_by_addr[node_addr];
            let current_pc = &current_by_addr[node_addr];
            if new_pc.addresses != current_pc.addresses
                || new_pc.alias != current_pc.alias
                || new_pc.connect_policy != current_pc.connect_policy
                || new_pc.auto_reconnect != current_pc.auto_reconnect
                || new_pc.discovery_fallback_transit != current_pc.discovery_fallback_transit
            {
                outcome.updated += 1;
                self.set_discovery_fallback_transit_allowed(
                    *node_addr,
                    new_pc.discovery_fallback_transit,
                );
                if let Some(state) = self.retry_pending.get_mut(node_addr) {
                    state.peer_config = new_pc.clone();
                    state.reconnect = new_pc.auto_reconnect;
                    state.retry_after_ms = Self::now_ms();
                }
                if let Some(alias) = new_pc.alias.clone() {
                    self.peer_aliases.insert(*node_addr, alias);
                }
                if new_pc.is_auto_connect() && !new_pc.addresses.is_empty() {
                    auto_connect_refresh_configs.push(new_pc.clone());
                }
            } else {
                outcome.unchanged += 1;
                self.set_discovery_fallback_transit_allowed(
                    *node_addr,
                    new_pc.discovery_fallback_transit,
                );
                if let Some(state) = self.retry_pending.get_mut(node_addr) {
                    state.peer_config = new_pc.clone();
                    state.reconnect = new_pc.auto_reconnect;
                }
                if new_pc.is_auto_connect() && !new_pc.addresses.is_empty() {
                    auto_connect_refresh_configs.push(new_pc.clone());
                }
            }
        }

        let added_configs: Vec<crate::config::PeerConfig> = new_order
            .iter()
            .filter(|addr| added.contains(addr))
            .map(|addr| new_by_addr[addr].clone())
            .collect();

        // Replace the live config peer list before initiating connections so
        // any helper that consults `self.config.peers()` during the dial
        // (alias lookup, retry-state seeding) sees the new entries.
        self.config.peers = new_order
            .iter()
            .filter_map(|addr| new_by_addr.get(addr).cloned())
            .collect();
        self.refresh_configured_peer_cache();

        for peer_config in added_configs {
            outcome.added += 1;
            let Some(identity) = self.configured_peer_identity_for_npub(&peer_config.npub) else {
                continue;
            };
            let name = peer_config
                .alias
                .clone()
                .unwrap_or_else(|| identity.short_npub());
            self.peer_aliases.insert(*identity.node_addr(), name);
            self.set_discovery_fallback_transit_allowed(
                *identity.node_addr(),
                peer_config.discovery_fallback_transit,
            );
            self.register_identity(*identity.node_addr(), identity.pubkey_full());

            if !peer_config.is_auto_connect() {
                continue;
            }

            match self
                .try_auto_connect_graph_session(&peer_config, identity)
                .await
            {
                Ok(true) => continue,
                Ok(false) => {}
                Err(err) => {
                    debug!(
                        npub = %peer_config.npub,
                        error = %err,
                        "Existing FIPS graph did not warm newly added peer"
                    );
                }
            }

            if let Err(e) = self.initiate_peer_connection(&peer_config).await {
                warn!(
                    npub = %peer_config.npub,
                    error = %e,
                    "Failed to initiate connection for newly added peer"
                );
                self.schedule_retry_after_error(*identity.node_addr(), Self::now_ms(), &e);
                if matches!(e, crate::node::NodeError::NoTransportForType(_))
                    && let Some(bootstrap) = self.nostr_discovery.clone()
                {
                    bootstrap
                        .request_advert_stale_check(peer_config.npub.clone())
                        .await;
                }
            }
        }

        for peer_config in auto_connect_refresh_configs {
            let Some(peer_identity) = self.configured_peer_identity_for_npub(&peer_config.npub)
            else {
                continue;
            };
            let node_addr = *peer_identity.node_addr();

            if self.peers.contains_key(&node_addr) {
                match self
                    .initiate_active_peer_alternative_connection(&peer_config)
                    .await
                {
                    Ok(attempted) => {
                        if attempted {
                            debug!(
                                peer = %self.peer_display_name(&node_addr),
                                "Started non-disruptive alternate-path handshake for active peer"
                            );
                        }
                    }
                    Err(e) => {
                        debug!(
                            npub = %peer_config.npub,
                            error = %e,
                            "Active peer alternate-path refresh did not start"
                        );
                    }
                }
                continue;
            }

            match self
                .try_auto_connect_graph_session(&peer_config, peer_identity)
                .await
            {
                Ok(true) => continue,
                Ok(false) => {}
                Err(err) => {
                    debug!(
                        npub = %peer_config.npub,
                        error = %err,
                        "Existing FIPS graph did not warm refreshed peer"
                    );
                }
            }

            match self.initiate_peer_connection(&peer_config).await {
                Ok(()) => {
                    let hs_timeout_ms = self.config.node.rate_limit.handshake_timeout_secs * 1000;
                    if let Some(state) = self.retry_pending.get_mut(&node_addr) {
                        state.peer_config = peer_config;
                        state.retry_after_ms = Self::now_ms().saturating_add(hs_timeout_ms);
                    }
                }
                Err(e) => {
                    debug!(
                        npub = %peer_config.npub,
                        error = %e,
                        "Refreshed peer addresses did not initiate a direct connection"
                    );
                    self.schedule_retry_after_error(node_addr, Self::now_ms(), &e);
                }
            }
        }

        self.warm_auto_connect_graph_sessions().await;

        Ok(outcome)
    }

    pub(in crate::node) async fn refresh_peer_paths(
        &mut self,
        npubs: Vec<String>,
    ) -> Result<usize, crate::node::NodeError> {
        let mut refreshed = 0usize;
        let now_ms = Self::now_ms();

        for npub in npubs {
            let identity = self
                .configured_or_parsed_peer_identity(&npub)
                .map_err(|e| NodeError::InvalidPeerNpub {
                    npub: npub.clone(),
                    reason: e,
                })?;
            let node_addr = *identity.node_addr();
            let peer_config = self
                .configured_auto_connect_peer_config(&node_addr)
                .or_else(|| {
                    self.config
                        .auto_connect_peers()
                        .find(|peer_config| peer_config.npub == npub)
                        .cloned()
                });
            let Some(peer_config) = peer_config else {
                debug!(
                    peer = %identity.short_npub(),
                    "Skipping peer path refresh for peer not in auto-connect config"
                );
                continue;
            };

            if let Some(state) = self.retry_pending.get_mut(&node_addr) {
                state.peer_config = peer_config.clone();
                state.reconnect = peer_config.auto_reconnect;
            }

            let attempted = if self.peers.contains_key(&node_addr) {
                self.initiate_active_peer_direct_refresh_connection(&peer_config)
                    .await?
            } else {
                match self.initiate_peer_connection(&peer_config).await {
                    Ok(()) => true,
                    Err(error) => {
                        self.schedule_retry_after_error(node_addr, now_ms, &error);
                        return Err(error);
                    }
                }
            };

            if attempted {
                refreshed = refreshed.saturating_add(1);
            }

            if peer_config.auto_reconnect {
                self.schedule_link_dead_reprobe(node_addr, now_ms);
            }
        }

        Ok(refreshed)
    }

    pub(in crate::node) async fn initiate_peer_connections(&mut self) {
        // Build display name map from all configured peers (alias or short npub),
        // and pre-seed the identity cache from each peer's npub so that TUN packets
        // addressed to a configured peer can be dispatched (and trigger session
        // initiation) immediately on startup — without waiting for the link-layer
        // handshake to complete first.
        let peer_identities: Vec<(PeerIdentity, Option<String>)> = self
            .config
            .peers()
            .iter()
            .filter_map(|pc| {
                self.configured_peer_identity_for_npub(&pc.npub)
                    .map(|identity| (identity, pc.alias.clone()))
            })
            .collect();

        for (identity, alias) in peer_identities {
            let name = alias.unwrap_or_else(|| identity.short_npub());
            self.peer_aliases.insert(*identity.node_addr(), name);
            // Pre-seed identity cache. The parity may be wrong (npub is x-only)
            // but will be corrected to the real value when the peer is promoted
            // after a successful Noise handshake.
            self.register_identity(*identity.node_addr(), identity.pubkey_full());
        }

        // Collect peer configs to avoid borrow conflicts
        let peer_configs: Vec<_> = self.config.auto_connect_peers().cloned().collect();

        if peer_configs.is_empty() {
            debug!("No static peers configured");
            return;
        }

        debug!(
            count = peer_configs.len(),
            "Initiating static peer connections"
        );

        for peer_config in peer_configs {
            let Some(peer_identity) = self.configured_peer_identity_for_npub(&peer_config.npub)
            else {
                continue;
            };
            match self
                .try_auto_connect_graph_session(&peer_config, peer_identity)
                .await
            {
                Ok(true) => continue,
                Ok(false) => {}
                Err(err) => {
                    debug!(
                        npub = %peer_config.npub,
                        error = %err,
                        "Existing FIPS graph did not warm auto-connect peer"
                    );
                }
            }
            if let Err(e) = self.initiate_peer_connection(&peer_config).await {
                warn!(
                    npub = %peer_config.npub,
                    alias = ?peer_config.alias,
                    error = %e,
                    "Failed to initiate peer connection"
                );
                // Schedule a retry so transient address-resolution failures
                // (e.g. cached endpoints stale, NAT rebinds, all addresses
                // currently unreachable) recover without a daemon restart.
                self.schedule_retry_after_error(*peer_identity.node_addr(), Self::now_ms(), &e);
                // No-transport failures most often mean the cached overlay
                // advert is pointing at a dead post-NAT-rebind address. The
                // advert cache is read-only inside fetch_advert, so retries
                // would loop on the same dead address until expiry. Force a
                // re-fetch so the next retry tick picks up fresh endpoints.
                if matches!(e, crate::node::NodeError::NoTransportForType(_))
                    && let Some(bootstrap) = self.nostr_discovery.clone()
                {
                    bootstrap
                        .request_advert_stale_check(peer_config.npub.clone())
                        .await;
                }
            }
        }

        self.warm_auto_connect_graph_sessions().await;
    }

    pub(in crate::node) async fn try_auto_connect_graph_session(
        &mut self,
        peer_config: &PeerConfig,
        peer_identity: PeerIdentity,
    ) -> Result<bool, NodeError> {
        if !peer_config.is_auto_connect() {
            return Ok(false);
        }

        let peer_node_addr = *peer_identity.node_addr();
        if self
            .peers
            .get(&peer_node_addr)
            .is_some_and(|peer| peer.can_send())
        {
            return Ok(false);
        }
        if self.auto_connect_should_race_direct_path(peer_config) {
            return Ok(false);
        }
        if self
            .sessions
            .get(&peer_node_addr)
            .is_some_and(|entry| entry.is_established() || entry.is_initiating())
        {
            return Ok(true);
        }
        if self.find_next_hop(&peer_node_addr).is_none() {
            return Ok(false);
        }

        self.register_identity(peer_node_addr, peer_identity.pubkey_full());
        match self
            .initiate_session(peer_node_addr, peer_identity.pubkey_full())
            .await
        {
            Ok(()) => {
                debug!(
                    peer = %self.peer_display_name(&peer_node_addr),
                    "Warmed auto-connect peer session over existing FIPS graph"
                );
                Ok(true)
            }
            Err(NodeError::SendFailed { node_addr, reason })
                if node_addr == peer_node_addr && reason == "no route to destination" =>
            {
                self.maybe_initiate_lookup(&peer_node_addr).await;
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }

    pub(super) fn auto_connect_should_race_direct_path(&self, peer_config: &PeerConfig) -> bool {
        !peer_config.addresses.is_empty() || self.config.node.discovery.nostr.enabled
    }

    /// Initiate a connection to a single peer.
    ///
    /// Creates a link, starts the Noise handshake, and sends the first message.
    pub(in crate::node) async fn initiate_peer_connection(
        &mut self,
        peer_config: &crate::config::PeerConfig,
    ) -> Result<(), NodeError> {
        self.initiate_peer_connection_inner(peer_config).await
    }

    /// Initiate a connection from the retry path. Identical to
    /// [`initiate_peer_connection`] today — both paths fan out across every
    /// known address (explicit priority first, then freshness) in a single
    /// pass. The two entry points stay separate so callers can be distinguished
    /// in tracing.
    pub(in crate::node) async fn initiate_peer_retry_connection(
        &mut self,
        peer_config: &crate::config::PeerConfig,
    ) -> Result<(), NodeError> {
        self.initiate_peer_connection_inner(peer_config).await
    }

    pub(in crate::node) async fn initiate_active_peer_alternative_connection(
        &mut self,
        peer_config: &crate::config::PeerConfig,
    ) -> Result<bool, NodeError> {
        self.initiate_active_peer_alternative_connection_inner(peer_config, false)
            .await
    }

    pub(in crate::node) async fn initiate_active_peer_direct_refresh_connection(
        &mut self,
        peer_config: &crate::config::PeerConfig,
    ) -> Result<bool, NodeError> {
        self.initiate_active_peer_alternative_connection_inner(peer_config, true)
            .await
    }

    pub(super) async fn initiate_active_peer_alternative_connection_inner(
        &mut self,
        peer_config: &crate::config::PeerConfig,
        allow_same_path_refresh: bool,
    ) -> Result<bool, NodeError> {
        let peer_identity = self
            .configured_or_parsed_peer_identity(&peer_config.npub)
            .map_err(|e| NodeError::InvalidPeerNpub {
                npub: peer_config.npub.clone(),
                reason: e,
            })?;
        let peer_node_addr = *peer_identity.node_addr();

        if !self.peers.contains_key(&peer_node_addr) {
            self.initiate_peer_connection(peer_config).await?;
            return Ok(true);
        }

        // Keep the current link live and race fresh concrete candidates.
        // Cross-connection resolution still decides which replacement link
        // wins if both peers try the same upgrade; the important part here is
        // that a stale path does not depend on the remote peer receiving our
        // hint first before either side attempts the better address.
        self.try_active_peer_alternative_addresses(
            peer_config,
            peer_identity,
            allow_same_path_refresh,
        )
        .await
    }

    pub(super) async fn initiate_peer_connection_inner(
        &mut self,
        peer_config: &crate::config::PeerConfig,
    ) -> Result<(), NodeError> {
        let peer_identity = self
            .configured_or_parsed_peer_identity(&peer_config.npub)
            .map_err(|e| NodeError::InvalidPeerNpub {
                npub: peer_config.npub.clone(),
                reason: e,
            })?;

        let peer_node_addr = *peer_identity.node_addr();

        // Check if peer already exists (fully authenticated)
        if self.peers.contains_key(&peer_node_addr) {
            debug!(
                npub = %peer_config.npub,
                "Peer already exists, skipping"
            );
            return Ok(());
        }

        self.try_peer_addresses(peer_config, peer_identity, true)
            .await
    }
}
