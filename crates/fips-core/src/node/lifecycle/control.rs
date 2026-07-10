use super::*;

impl Node {
    // === Control API methods ===

    /// Connect to a peer via the control API.
    ///
    /// Creates an ephemeral peer connection (not persisted to config, no
    /// auto-reconnect). Reuses the same connection path as auto-connect
    /// peers. Returns JSON data on success or an error message.
    pub(crate) async fn api_connect(
        &mut self,
        npub: &str,
        address: &str,
        transport: &str,
    ) -> Result<serde_json::Value, String> {
        let peer_config = PeerConfig {
            npub: npub.to_string(),
            alias: None,
            addresses: vec![PeerAddress::new(transport, address).configured()],
            connect_policy: ConnectPolicy::Manual,
            auto_reconnect: false,
            discovery_fallback_transit: true,
        };

        // Pre-seed identity cache (same as initiate_peer_connections does)
        if let Ok(identity) = PeerIdentity::from_npub(npub) {
            self.peer_aliases
                .insert(*identity.node_addr(), identity.short_npub());
            self.register_identity(*identity.node_addr(), identity.pubkey_full());
        }

        self.initiate_peer_connection(&peer_config)
            .await
            .map(|()| {
                info!(
                    npub = %npub,
                    address = %address,
                    transport = %transport,
                    "API connect initiated"
                );
                serde_json::json!({
                    "npub": npub,
                    "address": address,
                    "transport": transport,
                })
            })
            .map_err(|e| e.to_string())
    }

    /// Disconnect a peer via the control API.
    ///
    /// Notifies the peer, removes it locally, and suppresses auto-reconnect.
    pub(crate) async fn api_disconnect(&mut self, npub: &str) -> Result<serde_json::Value, String> {
        let peer_identity =
            PeerIdentity::from_npub(npub).map_err(|e| format!("invalid npub '{npub}': {e}"))?;
        let node_addr = *peer_identity.node_addr();

        if !self.peers.contains_key(&node_addr) {
            return Err(format!("peer not found: {npub}"));
        }

        self.send_disconnect_to_peer(&node_addr, DisconnectReason::ConfigurationChange)
            .await;

        // Remove the peer (full cleanup: sessions, indices, links, tree, bloom)
        self.remove_active_peer(&node_addr);

        // Suppress any pending auto-reconnect
        self.retry_pending.remove(&node_addr);

        info!(npub = %npub, "API disconnect completed");

        Ok(serde_json::json!({
            "npub": npub,
            "disconnected": true,
        }))
    }

    /// Adopt an already-established UDP traversal and start the normal FIPS
    /// Noise handshake over it.
    ///
    /// This is intended for integration with an external rendezvous runtime
    /// that has already completed relay signaling, STUN observation, and UDP
    /// hole punching. After handoff, the adopted socket is owned by FIPS.
    pub async fn adopt_established_traversal(
        &mut self,
        traversal: EstablishedTraversal,
    ) -> Result<BootstrapHandoffResult, NodeError> {
        debug!(
            peer_npub = %traversal.peer_npub,
            session_id = %traversal.session_id,
            remote_addr = %traversal.remote_addr,
            "adopting established traversal socket"
        );

        if !self.state.is_operational() {
            return Err(NodeError::NotStarted);
        }

        let packet_tx = self.packet_tx.clone().ok_or(NodeError::NotStarted)?;
        let peer_identity = PeerIdentity::from_npub(&traversal.peer_npub).map_err(|e| {
            NodeError::InvalidPeerNpub {
                npub: traversal.peer_npub.clone(),
                reason: e.to_string(),
            }
        })?;
        let peer_node_addr = *peer_identity.node_addr();
        if self.peers.contains_key(&peer_node_addr) {
            debug!(
                peer_npub = %traversal.peer_npub,
                "Adopting NAT traversal handoff as alternate path for already-connected peer"
            );
        }

        self.peer_aliases
            .insert(peer_node_addr, peer_identity.short_npub());
        self.register_identity(peer_node_addr, peer_identity.pubkey_full());

        let transport_id = self.allocate_transport_id();
        // Adopted ephemeral UDP transports inherit MTU + socket-buffer sizing
        // (and accept_connections / advertise flags) from the operator's
        // configured [transports.udp] when the bootstrap runtime doesn't
        // pass an explicit override. Lookup tries `transport_name` first
        // (covers the `Named` multi-listener variant) and falls back to the
        // unnamed `Single` listener, so single- and named-listener configs
        // both inherit cleanly.
        //
        // Tradeoff: `UdpConfig::default()` sets MTU 1280 (IPv6 minimum), the
        // only value guaranteed to survive arbitrary middlebox paths.
        // Inheriting a higher operator-chosen MTU means NAT-traversed flows
        // initially attempt that MTU and may black-hole on tighter paths
        // until reactive `MtuExceeded` recovery kicks in. Operators who
        // raise the primary MTU based on known-clean topology accept that
        // tradeoff; the silent drop on a too-low default was strictly
        // worse for the common case where the primary MTU is reachable.
        //
        // Bind / external address fields are cleared since the socket is
        // already bound.
        let inherited_config = traversal.transport_config.clone().unwrap_or_else(|| {
            let mut cfg = self
                .lookup_udp_config(traversal.transport_name.as_deref())
                .or_else(|| self.lookup_udp_config(None))
                .cloned()
                .unwrap_or_default();
            cfg.bind_addr = None;
            cfg.external_addr = None;
            cfg
        });
        let mut transport = crate::transport::udp::UdpTransport::new(
            transport_id,
            traversal.transport_name.clone(),
            inherited_config,
            packet_tx,
        );

        transport
            .adopt_socket_async(traversal.socket)
            .await
            .map_err(|e| NodeError::BootstrapHandoff(e.to_string()))?;

        let local_addr = transport.local_addr().ok_or_else(|| {
            NodeError::BootstrapHandoff("adopted UDP transport has no local address".into())
        })?;

        self.transports.insert(
            transport_id,
            crate::transport::TransportHandle::Udp(transport),
        );
        self.bootstrap_transports
            .register(transport_id, traversal.peer_npub.clone());

        let remote_addr = TransportAddr::from_string(&traversal.remote_addr.to_string());
        if let Err(err) = self
            .initiate_connection(transport_id, remote_addr.clone(), peer_identity)
            .await
        {
            self.bootstrap_transports.remove(&transport_id);
            if let Some(mut handle) = self.transports.remove(&transport_id) {
                let _ = handle.stop().await;
            }
            return Err(err);
        }

        info!(
            peer = %self.peer_display_name(&peer_node_addr),
            transport_id = %transport_id,
            local_addr = %local_addr,
            remote_addr = %traversal.remote_addr,
            session_id = %traversal.session_id,
            "adopted NAT traversal socket; handshake initiated"
        );

        Ok(BootstrapHandoffResult {
            transport_id,
            local_addr,
            remote_addr: traversal.remote_addr,
            peer_node_addr,
            session_id: traversal.session_id,
        })
    }
}
