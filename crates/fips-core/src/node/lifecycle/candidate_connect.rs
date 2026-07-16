use super::*;

impl Node {
    pub(super) fn canonical_transport_addr(
        &self,
        transport_id: TransportId,
        addr: TransportAddr,
    ) -> Result<TransportAddr, crate::transport::TransportError> {
        match self.transports.get(&transport_id) {
            Some(transport) => transport.canonical_addr(&addr),
            None => Ok(addr),
        }
    }

    async fn recover_udp_transport_after_local_route_failure(&mut self, transport_id: TransportId) {
        let Some(crate::transport::TransportHandle::Udp(transport)) =
            self.transports.get_mut(&transport_id)
        else {
            return;
        };

        match transport.recover_local_route_socket().await {
            Ok(true) => {
                info!(
                    transport_id = %transport_id,
                    "Recovered UDP transport after local route failure"
                );
            }
            Ok(false) => {}
            Err(error) => {
                warn!(
                    transport_id = %transport_id,
                    %error,
                    "Failed to recover UDP transport after local route failure"
                );
            }
        }
    }

    pub(super) fn is_connecting_to_peer(&self, peer_node_addr: &NodeAddr) -> bool {
        self.peers.connection_values().any(|conn| {
            conn.expected_identity()
                .map(|id| id.node_addr() == peer_node_addr)
                .unwrap_or(false)
        })
    }

    pub(in crate::node) fn is_connecting_to_peer_on_path(
        &self,
        peer_node_addr: &NodeAddr,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) -> bool {
        self.peers.connection_values().any(|conn| {
            conn.expected_identity()
                .map(|id| id.node_addr() == peer_node_addr)
                .unwrap_or(false)
                && conn.transport_id() == Some(transport_id)
                && conn.source_addr() == Some(remote_addr)
        }) || self.pending_connects.iter().any(|pending| {
            pending.peer_identity.node_addr() == peer_node_addr
                && pending.transport_id == transport_id
                && &pending.remote_addr == remote_addr
        })
    }

    pub(in crate::node) fn should_warm_auto_connect_session(
        &self,
        peer_node_addr: &NodeAddr,
    ) -> bool {
        if self
            .peers
            .get(peer_node_addr)
            .is_some_and(|peer| peer.can_send())
            || self
                .sessions
                .get(peer_node_addr)
                .is_some_and(|entry| entry.is_established())
        {
            return false;
        }

        self.configured_peer(peer_node_addr)
            .is_some_and(PeerConfig::is_auto_connect)
    }

    pub(in crate::node) async fn warm_auto_connect_graph_sessions(&mut self) -> usize {
        if !self.peers.values().any(|peer| peer.can_send()) {
            return 0;
        }

        let mut budget = self.graph_session_warmup_budget();
        if budget == 0 {
            return 0;
        }

        let peer_identities: Vec<_> = self
            .config
            .auto_connect_peers()
            .filter_map(|peer| PeerIdentity::from_npub(&peer.npub).ok())
            .collect();

        let mut warmed = 0;
        for identity in peer_identities {
            if budget == 0 {
                break;
            }

            let peer_node_addr = *identity.node_addr();
            if peer_node_addr == *self.identity.node_addr()
                || !self.should_warm_auto_connect_session(&peer_node_addr)
                || self
                    .sessions
                    .get(&peer_node_addr)
                    .is_some_and(|entry| entry.is_initiating())
            {
                continue;
            }

            self.register_identity(peer_node_addr, identity.pubkey_full());

            if self.find_next_hop(&peer_node_addr).is_some() {
                match self
                    .initiate_session(peer_node_addr, identity.pubkey_full())
                    .await
                {
                    Ok(()) => {
                        warmed += 1;
                        budget = budget.saturating_sub(1);
                        debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            "Warmed auto-connect peer session over existing FIPS graph"
                        );
                    }
                    Err(NodeError::SendFailed { node_addr, reason })
                        if node_addr == peer_node_addr && reason == "no route to destination" =>
                    {
                        self.maybe_initiate_lookup(&peer_node_addr).await;
                        warmed += 1;
                        budget = budget.saturating_sub(1);
                    }
                    Err(err) => {
                        debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            error = %err,
                            "Failed to warm auto-connect peer session"
                        );
                    }
                }
            } else {
                self.maybe_initiate_lookup(&peer_node_addr).await;
                warmed += 1;
                budget = budget.saturating_sub(1);
            }
        }

        warmed
    }

    pub(in crate::node) fn graph_session_warmup_budget(&self) -> usize {
        let max_destinations = self.config.node.session.pending_max_destinations;
        if max_destinations == 0 {
            return 0;
        }

        let pending_sessions = self
            .sessions
            .values()
            .filter(|entry| !entry.is_established())
            .count();
        let pending_total = pending_sessions.saturating_add(self.pending_lookups.len());
        max_destinations
            .saturating_sub(pending_total)
            .min(MAX_AUTO_CONNECT_GRAPH_WARMUPS_PER_TICK)
    }

    pub(super) fn outbound_handshake_slots(&self) -> usize {
        let used = self
            .peers
            .connection_len()
            .saturating_add(self.pending_connects.len());
        if self.max_connections == 0 {
            usize::MAX
        } else {
            self.max_connections.saturating_sub(used)
        }
    }

    pub(super) fn outbound_link_slots(&self) -> usize {
        if self.max_links == 0 {
            usize::MAX
        } else {
            self.max_links.saturating_sub(self.links.len())
        }
    }

    pub(super) fn path_candidate_attempt_budget(&self, peer_node_addr: &NodeAddr) -> usize {
        if !self.peers.contains_key(peer_node_addr)
            && self.max_peers > 0
            && self.peers.len() >= self.max_peers
        {
            return 0;
        }

        let in_flight_for_peer = self
            .peers
            .connection_values()
            .filter(|conn| {
                conn.expected_identity()
                    .map(|id| id.node_addr() == peer_node_addr)
                    .unwrap_or(false)
            })
            .count()
            .saturating_add(
                self.pending_connects
                    .iter()
                    .filter(|pending| pending.peer_identity.node_addr() == peer_node_addr)
                    .count(),
            );

        self.outbound_handshake_slots()
            .min(self.outbound_link_slots())
            .min(MAX_PARALLEL_PATH_CANDIDATES_PER_PEER.saturating_sub(in_flight_for_peer))
    }

    pub(super) fn reclaim_lower_priority_inflight_candidate_for_peer(
        &mut self,
        peer_node_addr: &NodeAddr,
        candidate: &PeerAddress,
    ) -> bool {
        const UNKNOWN_PATH_PRIORITY: u16 = u8::MAX as u16 + 1;

        let Some((candidate_transport_id, candidate_addr)) =
            self.resolve_peer_address_for_match(candidate)
        else {
            return false;
        };
        let candidate_priority = self
            .configured_path_priority(peer_node_addr, candidate_transport_id, &candidate_addr)
            .or_else(|| {
                self.active_peer_current_path_priority(
                    peer_node_addr,
                    candidate_transport_id,
                    &candidate_addr,
                )
            })
            .map(u16::from)
            .unwrap_or_else(|| u16::from(candidate.priority));

        let victim = self
            .peers
            .connection_iter()
            .filter_map(|(link_id, conn)| {
                let identity = conn.expected_identity()?;
                if identity.node_addr() != peer_node_addr {
                    return None;
                }
                let transport_id = conn.transport_id()?;
                let remote_addr = conn.source_addr()?;
                if transport_id == candidate_transport_id && remote_addr == &candidate_addr {
                    return None;
                }
                let priority = self
                    .configured_path_priority(peer_node_addr, transport_id, remote_addr)
                    .or_else(|| {
                        self.active_peer_current_path_priority(
                            peer_node_addr,
                            transport_id,
                            remote_addr,
                        )
                    })
                    .map(u16::from)
                    .unwrap_or(UNKNOWN_PATH_PRIORITY);
                (priority > candidate_priority).then_some((
                    *link_id,
                    priority,
                    conn.started_at(),
                    transport_id,
                    remote_addr.clone(),
                ))
            })
            .max_by_key(|(_, priority, started_at, _, _)| {
                (*priority, std::cmp::Reverse(*started_at))
            });

        let Some((link_id, victim_priority, _, victim_transport_id, victim_addr)) = victim else {
            return false;
        };

        let Some(conn) = self.peers.remove_connection(&link_id) else {
            return false;
        };
        if let Some(idx) = conn.our_index()
            && let Some(transport_id) = conn.transport_id()
        {
            self.pending_outbound.remove(&(transport_id, idx.as_u32()));
            let _ = self.index_allocator.free(idx);
        }
        self.remove_link(&link_id);
        self.cleanup_bootstrap_transport_if_unused(victim_transport_id);

        debug!(
            peer = %self.peer_display_name(peer_node_addr),
            candidate_transport_id = %candidate_transport_id,
            candidate_addr = %candidate_addr,
            candidate_priority,
            victim_link_id = %link_id,
            victim_transport_id = %victim_transport_id,
            victim_addr = %victim_addr,
            victim_priority,
            "Reclaimed lower-priority in-flight candidate slot for configured direct path"
        );

        true
    }

    pub(super) fn discovery_connect_budget(&self) -> usize {
        self.outbound_handshake_slots()
            .min(self.outbound_link_slots())
            .min(MAX_DISCOVERY_CONNECTS_PER_TICK)
    }

    /// Find a UDP transport whose bound socket can send to `remote_addr`.
    ///
    /// LAN discovery can surface both IPv4 and IPv6 addresses for the same
    /// service. A wildcard IPv4 socket cannot send to an IPv6 link-local
    /// target, and vice versa, so callers must choose by socket family rather
    /// than by transport type alone.
    pub(in crate::node) fn find_udp_transport_for_remote_addr(
        &self,
        remote_addr: SocketAddr,
        provenance: PeerAddressProvenance,
    ) -> Option<(TransportId, SocketAddr)> {
        if udp_remote_addr_invalid(remote_addr.ip()) {
            return None;
        }
        let evidence = UdpRouteEvidence::capture(remote_addr, provenance);
        self.transports
            .iter()
            .filter(|(id, handle)| {
                handle.transport_type().name == "udp"
                    && handle.is_operational()
                    && !self.bootstrap_transports.contains(id)
                    && !self.is_local_rendezvous_transport(id)
            })
            .filter_map(|(id, handle)| {
                let local_addr = handle.local_addr()?;
                (socket_addr_families_compatible(local_addr, remote_addr)
                    && udp_remote_addr_locally_plausible(
                        local_addr,
                        remote_addr,
                        provenance,
                        &evidence,
                    ))
                .then_some((*id, local_addr))
            })
            .min_by_key(|(id, _)| id.as_u32())
    }

    pub(in crate::node) fn transport_discovery_candidate(
        &self,
        discovered_transport_id: TransportId,
        discovered_addr: TransportAddr,
    ) -> Option<(TransportId, TransportAddr, &'static str)> {
        let transport = self.transports.get(&discovered_transport_id)?;
        let transport_name = transport.transport_type().name;

        if transport_name != "udp" {
            return Some((discovered_transport_id, discovered_addr, transport_name));
        }

        let Some(remote_socket_addr) = discovered_addr
            .as_str()
            .and_then(|addr| addr.parse::<SocketAddr>().ok())
        else {
            if self.bootstrap_transports.contains(&discovered_transport_id) {
                debug!(
                    transport_id = %discovered_transport_id,
                    remote_addr = %discovered_addr,
                    "transport discovery: skip non-numeric UDP address from bootstrap transport"
                );
                return None;
            }
            return Some((discovered_transport_id, discovered_addr, transport_name));
        };

        let Some((transport_id, local_addr)) = self
            .find_udp_transport_for_remote_addr(remote_socket_addr, PeerAddressProvenance::Learned)
        else {
            debug!(
                transport_id = %discovered_transport_id,
                remote_addr = %discovered_addr,
                "transport discovery: skip UDP peer with no compatible local socket"
            );
            return None;
        };

        if transport_id != discovered_transport_id {
            debug!(
                discovered_transport_id = %discovered_transport_id,
                selected_transport_id = %transport_id,
                local_addr = %local_addr,
                remote_addr = %remote_socket_addr,
                "transport discovery: selected compatible UDP transport"
            );
        }

        Some((
            transport_id,
            TransportAddr::from_socket_addr(remote_socket_addr),
            transport_name,
        ))
    }

    pub(super) fn peer_address_string_for_transport_candidate(
        &self,
        transport_id: TransportId,
        transport_name: &str,
        remote_addr: &TransportAddr,
    ) -> String {
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = (transport_id, transport_name);

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if transport_name == "ethernet"
            && remote_addr.as_bytes().len() == 6
            && let Some(interface) = self
                .transports
                .get(&transport_id)
                .and_then(|transport| transport.interface_name())
        {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(remote_addr.as_bytes());
            return format!(
                "{interface}/{}",
                crate::transport::ethernet::format_mac(&mac)
            );
        }

        remote_addr.to_string()
    }

    pub(super) fn resolve_peer_address_for_match(
        &self,
        candidate: &PeerAddress,
    ) -> Option<(TransportId, TransportAddr)> {
        if candidate.transport == "udp" && candidate.addr.eq_ignore_ascii_case("nat") {
            return None;
        }

        if candidate.transport == "ethernet" {
            return self.resolve_ethernet_addr(&candidate.addr).ok();
        }

        if candidate.transport == "ble" {
            #[cfg(bluer_available)]
            {
                return self.resolve_ble_addr(&candidate.addr).ok();
            }
            #[cfg(not(bluer_available))]
            {
                return None;
            }
        }

        let transport_id = if candidate.transport == "udp"
            && let Ok(remote_socket_addr) = candidate.addr.parse::<SocketAddr>()
        {
            self.find_udp_transport_for_remote_addr(remote_socket_addr, candidate.provenance)
                .map(|(id, _)| id)?
        } else {
            self.find_transport_for_type(&candidate.transport)?
        };

        let addr = TransportAddr::from_string(&candidate.addr);
        let addr = self.canonical_transport_addr(transport_id, addr).ok()?;
        Some((transport_id, addr))
    }

    /// Initiate a connection to a peer on a specific transport and address.
    ///
    /// For connectionless transports (UDP, Ethernet): allocates a link, starts
    /// the Noise IK handshake, sends msg1, and registers the connection for
    /// msg2 dispatch.
    ///
    /// For connection-oriented transports (TCP, Tor): allocates a link and
    /// starts a non-blocking transport connect. The handshake is deferred
    /// until the transport connection is established — the tick handler
    /// polls `connection_state()` and initiates the handshake when ready.
    pub(in crate::node) async fn initiate_connection(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        peer_identity: PeerIdentity,
    ) -> Result<(), NodeError> {
        let remote_addr = self
            .canonical_transport_addr(transport_id, remote_addr)
            .map_err(NodeError::from_transport_error)?;
        let peer_node_addr = *peer_identity.node_addr();

        if self.is_connecting_to_peer_on_path(&peer_node_addr, transport_id, &remote_addr) {
            debug!(
                peer = %self.peer_display_name(&peer_node_addr),
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                "Connection already in progress for candidate path"
            );
            return Ok(());
        }

        if self.outbound_handshake_slots() == 0 {
            return Err(NodeError::MaxConnectionsExceeded {
                max: self.max_connections,
            });
        }

        if self.outbound_link_slots() == 0 {
            return Err(NodeError::MaxLinksExceeded {
                max: self.max_links,
            });
        }

        if !self.peers.contains_key(&peer_node_addr)
            && self.max_peers > 0
            && self.peers.len() >= self.max_peers
        {
            return Err(NodeError::MaxPeersExceeded {
                max: self.max_peers,
            });
        }

        self.authorize_peer(
            &peer_identity,
            PeerAclContext::OutboundConnect,
            transport_id,
            &remote_addr,
        )?;

        let is_connection_oriented = self
            .transports
            .get(&transport_id)
            .map(|t| t.transport_type().connection_oriented)
            .unwrap_or(false);

        // Allocate link ID and create link
        let link_id = self.allocate_link_id();

        let link = if is_connection_oriented {
            Link::new(
                link_id,
                transport_id,
                remote_addr.clone(),
                LinkDirection::Outbound,
                Duration::from_millis(self.config.node.base_rtt_ms),
            )
        } else {
            Link::connectionless(
                link_id,
                transport_id,
                remote_addr.clone(),
                LinkDirection::Outbound,
                Duration::from_millis(self.config.node.base_rtt_ms),
            )
        };

        self.links.insert(link_id, link);

        if is_connection_oriented {
            // Connection-oriented: start non-blocking connect, defer handshake
            if let Some(transport) = self.transports.get(&transport_id) {
                match transport.connect(&remote_addr).await {
                    Ok(()) => {
                        debug!(
                            peer = %self.peer_display_name(&peer_node_addr),
                            transport_id = %transport_id,
                            remote_addr = %remote_addr,
                            link_id = %link_id,
                            "Transport connect initiated (non-blocking)"
                        );
                        self.pending_connects.push(crate::node::PendingConnect {
                            link_id,
                            transport_id,
                            remote_addr,
                            peer_identity,
                        });
                    }
                    Err(e) => {
                        // Clean up link
                        self.links.remove(&link_id);
                        return Err(NodeError::from_transport_error(e));
                    }
                }
            }
            Ok(())
        } else {
            // Connectionless: proceed with immediate handshake
            self.start_handshake(link_id, transport_id, remote_addr, peer_identity)
                .await
        }
    }

    /// Start the Noise handshake on a link and send msg1.
    ///
    /// Called immediately for connectionless transports, or after the
    /// transport connection is established for connection-oriented transports.
    pub(in crate::node) async fn start_handshake(
        &mut self,
        link_id: LinkId,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        peer_identity: PeerIdentity,
    ) -> Result<(), NodeError> {
        let peer_node_addr = *peer_identity.node_addr();

        // Create connection in handshake phase (outbound knows expected identity)
        let current_time_ms = Self::now_ms();
        let mut connection = PeerConnection::outbound(link_id, peer_identity, current_time_ms);

        // Allocate a session index for this handshake
        let our_index = match self.index_allocator.allocate() {
            Ok(idx) => idx,
            Err(e) => {
                // Clean up the link we just created
                self.links.remove(&link_id);
                return Err(NodeError::IndexAllocationFailed(e.to_string()));
            }
        };

        // Start the Noise handshake and get message 1
        let our_keypair = self.identity.keypair();
        let noise_msg1 =
            match connection.start_handshake(our_keypair, self.startup_epoch, current_time_ms) {
                Ok(msg) => msg,
                Err(e) => {
                    // Clean up the index and link
                    let _ = self.index_allocator.free(our_index);
                    self.links.remove(&link_id);
                    return Err(NodeError::HandshakeFailed(e.to_string()));
                }
            };

        // Set index and transport info on the connection
        connection.set_our_index(our_index);
        connection.set_transport_id(transport_id);
        connection.set_source_addr(remote_addr.clone());

        // Build wire format msg1: [0x01][sender_idx:4 LE][noise_msg1:82]
        let wire_msg1 = build_msg1(our_index, &noise_msg1);

        debug!(
            peer = %self.peer_display_name(&peer_node_addr),
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            link_id = %link_id,
            our_index = %our_index,
            "Connection initiated"
        );

        // Store msg1 for resend and schedule first resend
        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        connection.set_handshake_msg1(wire_msg1.clone(), current_time_ms + resend_interval);

        // Track in pending_outbound for msg2 dispatch
        self.pending_outbound
            .insert((transport_id, our_index.as_u32()), link_id);
        self.peers.insert_connection(link_id, connection);

        // Send the wire format handshake message. If the very first send fails
        // synchronously (for example an IPv6 candidate on an IPv4-only UDP
        // socket), undo this candidate so the caller can try the next address
        // in the same dial pass.
        let send_result = match self.transports.get(&transport_id) {
            Some(transport) => Some(transport.send(&remote_addr, &wire_msg1).await),
            None => None,
        };
        match send_result {
            Some(send_result) => {
                self.note_candidate_send_outcome(&peer_node_addr, &remote_addr, &send_result);
                match send_result {
                    Ok(bytes) => {
                        debug!(
                            link_id = %link_id,
                            our_index = %our_index,
                            bytes,
                            "Sent Noise handshake message 1 (wire format)"
                        );
                    }
                    Err(e) => {
                        let local_route_unavailable = e.is_local_route_unavailable();
                        warn!(
                            link_id = %link_id,
                            transport_id = %transport_id,
                            remote_addr = %remote_addr,
                            our_index = %our_index,
                            error = %e,
                            "Failed to send handshake message"
                        );
                        self.pending_outbound
                            .remove(&(transport_id, our_index.as_u32()));
                        self.peers.remove_connection(&link_id);
                        self.links.remove(&link_id);
                        let _ = self.index_allocator.free(our_index);
                        if local_route_unavailable {
                            self.recover_udp_transport_after_local_route_failure(transport_id)
                                .await;
                        }
                        return Err(NodeError::from_transport_error(e));
                    }
                }
            }
            None => {
                self.pending_outbound
                    .remove(&(transport_id, our_index.as_u32()));
                self.peers.remove_connection(&link_id);
                self.links.remove(&link_id);
                let _ = self.index_allocator.free(our_index);
                return Err(NodeError::TransportError(format!(
                    "transport {transport_id} disappeared before first handshake send"
                )));
            }
        }

        Ok(())
    }
}
