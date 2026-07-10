impl Node {
    // === Session Initiation (Send Path) ===

    /// Initiate an end-to-end session with a remote node.
    ///
    /// Creates a Noise XK handshake as initiator, wraps msg1 in a
    /// SessionSetup, encapsulates in a SessionDatagram, and routes
    /// toward the destination.
    pub(in crate::node) async fn initiate_session(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: PublicKey,
    ) -> Result<(), NodeError> {
        if self.sessions.should_skip_session_initiation(&dest_addr) {
            return Ok(());
        }

        // Create Noise XK initiator handshake
        let our_keypair = self.identity.keypair();
        let mut handshake = HandshakeState::new_xk_initiator(our_keypair, dest_pubkey);
        handshake.set_local_epoch(self.startup_epoch);
        let msg1 = handshake
            .write_xk_message_1()
            .map_err(|e| NodeError::SendFailed {
                node_addr: dest_addr,
                reason: format!("Noise XK msg1 generation failed: {}", e),
            })?;

        // Build SessionSetup with coordinates
        let our_coords = self.tree_state.my_coords().clone();
        let dest_coords = self.get_dest_coords(&dest_addr);
        let setup = SessionSetup::new(our_coords, dest_coords).with_handshake(msg1);
        let setup_payload = setup.encode();

        // Wrap in SessionDatagram
        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, dest_addr, setup_payload.clone())
            .with_ttl(self.config.node.session.default_ttl);

        // Route toward destination
        self.send_session_datagram(&mut datagram).await?;

        // Register destination identity for TUN → session routing
        self.register_identity(dest_addr, dest_pubkey);

        // Store session entry with handshake payload for potential resend
        let now_ms = Self::now_ms();
        let resend_interval = self.config.node.rate_limit.handshake_resend_interval_ms;
        self.sessions.install_initiating_session(
            dest_addr,
            dest_pubkey,
            handshake,
            setup_payload,
            now_ms,
            resend_interval,
        );

        debug!(dest = %self.peer_display_name(&dest_addr), "Session initiation started");
        Ok(())
    }

    pub(in crate::node) async fn handle_endpoint_data_batch_no_established_flush(
        &mut self,
        batch: NodeEndpointDataBatch,
    ) {
        let (remote, payloads, _, enqueued_at_ms) = batch.into_parts();
        self.queue_dataplane_unrouted_endpoint_batch(
            remote,
            payloads,
            enqueued_at_ms,
        )
        .await;
    }

    pub(in crate::node) async fn handle_endpoint_control(
        &mut self,
        command: NodeEndpointControlCommand,
    ) {
        match command {
            NodeEndpointControlCommand::UpdatePeers { peers, response_tx } => {
                let result = self.update_peers(peers).await;
                let _ = response_tx.send(result);
            }
            NodeEndpointControlCommand::RefreshPeerPaths { npubs, response_tx } => {
                let result = self.refresh_peer_paths(npubs).await;
                let _ = response_tx.send(result);
            }
            NodeEndpointControlCommand::RegisterService {
                port,
                sender,
                response_tx,
            } => {
                let _ = response_tx.send(self.endpoint_services.register(port, sender));
            }
            NodeEndpointControlCommand::IngestNostrPubsubEvent { event, response_tx } => {
                let accepted = if let Some(discovery) = self.nostr_discovery_handle() {
                    discovery.ingest_advert_event(&event).await.cached()
                        || discovery.process_rating_fact_event(&event).await
                } else {
                    false
                };
                let _ = response_tx.send(accepted);
            }
            NodeEndpointControlCommand::PeerSnapshot { response_tx } => {
                let snapshot_now = Instant::now();
                let nostr_failure_state: std::collections::HashMap<String, _> = self
                    .nostr_discovery_handle()
                    .map(|discovery| {
                        discovery
                            .failure_state_snapshot()
                            .into_iter()
                            .map(|state| (state.npub.clone(), state))
                            .collect()
                    })
                    .unwrap_or_default();
                let mut peers = self
                    .peers()
                    .map(|peer| {
                        let link_id = peer.link_id();
                        let retry_state = self.retry_pending.get(peer.node_addr());
                        let npub = peer.npub();
                        let nostr_state = nostr_failure_state.get(&npub);
                        let nostr_traversal_cooldown_until_ms =
                            nostr_state.and_then(|state| state.cooldown_until_ms);
                        let transport_type = self.get_link(&link_id).and_then(|link| {
                            self.get_transport(&link.transport_id())
                                .map(|handle| handle.transport_type().name.to_string())
                        });
                        let stats = peer.link_stats();
                        let direct_probe_pending = retry_state.is_some();
                        let last_outbound_route = self
                            .sessions
                            .iter()
                            .find(|(dest_addr, _)| {
                                self.dataplane
                                    .fsp_owner_activity(dest_addr)
                                    .and_then(|activity| activity.last_outbound_next_hop())
                                    == Some(*peer.node_addr())
                            })
                            .map(|(dest_addr, _)| {
                                if dest_addr == peer.node_addr() {
                                    "direct".to_string()
                                } else {
                                    "fallback".to_string()
                                }
                            });
                        let srtt = self
                            .dataplane
                            .fmp_link_metrics(peer.node_addr(), snapshot_now)
                            .and_then(|metrics| {
                                metrics
                                    .srtt_ms
                                    .map(|value| (value.round() as u64, metrics.srtt_age_ms))
                            });
                        let connected = peer.can_send()
                            && stats.time_since_recv(Self::now_ms())
                                <= self.session_direct_path_exclusive_trust_timeout_ms();
                        NodeEndpointPeer {
                            npub,
                            node_addr: *peer.node_addr(),
                            connected,
                            transport_addr: peer.current_addr().map(|addr| addr.to_string()),
                            transport_type,
                            link_id: link_id.as_u64(),
                            srtt_ms: srtt.map(|(value, _)| value),
                            srtt_age_ms: srtt.and_then(|(_, age)| age),
                            packets_sent: stats.packets_sent,
                            packets_recv: stats.packets_recv,
                            bytes_sent: stats.bytes_sent,
                            bytes_recv: stats.bytes_recv,
                            rekey_in_progress: peer.rekey_in_progress(),
                            rekey_draining: peer.is_draining(),
                            current_k_bit: Some(peer.current_k_bit()),
                            last_outbound_route,
                            direct_probe_pending,
                            direct_probe_after_ms: retry_state.map(|state| state.retry_after_ms),
                            direct_probe_retry_count: retry_state
                                .map_or(0, |state| state.retry_count),
                            direct_probe_auto_reconnect: retry_state
                                .is_some_and(|state| state.reconnect),
                            direct_probe_expires_at_ms: retry_state
                                .and_then(|state| state.expires_at_ms),
                            nostr_traversal_consecutive_failures: nostr_state
                                .map_or(0, |state| state.consecutive_failures),
                            nostr_traversal_in_cooldown: nostr_traversal_cooldown_until_ms
                                .is_some(),
                            nostr_traversal_cooldown_until_ms,
                            nostr_traversal_last_observed_skew_ms: nostr_state
                                .and_then(|state| state.last_observed_skew_ms),
                        }
                    })
                    .collect::<Vec<_>>();

                for (node_addr, retry_state) in self.retry_pending.iter() {
                    if self.peers.contains_key(node_addr)
                        || !self
                            .config
                            .peers
                            .iter()
                            .any(|peer| peer.npub == retry_state.peer_config.npub)
                    {
                        continue;
                    }

                    let npub = retry_state.peer_config.npub.clone();
                    let nostr_state = nostr_failure_state.get(&npub);
                    let nostr_traversal_cooldown_until_ms =
                        nostr_state.and_then(|state| state.cooldown_until_ms);
                    peers.push(NodeEndpointPeer {
                        npub,
                        node_addr: *node_addr,
                        connected: false,
                        transport_addr: None,
                        transport_type: None,
                        link_id: 0,
                        srtt_ms: None,
                        srtt_age_ms: None,
                        packets_sent: 0,
                        packets_recv: 0,
                        bytes_sent: 0,
                        bytes_recv: 0,
                        rekey_in_progress: false,
                        rekey_draining: false,
                        current_k_bit: None,
                        last_outbound_route: None,
                        direct_probe_pending: true,
                        direct_probe_after_ms: Some(retry_state.retry_after_ms),
                        direct_probe_retry_count: retry_state.retry_count,
                        direct_probe_auto_reconnect: retry_state.reconnect,
                        direct_probe_expires_at_ms: retry_state.expires_at_ms,
                        nostr_traversal_consecutive_failures: nostr_state
                            .map_or(0, |state| state.consecutive_failures),
                        nostr_traversal_in_cooldown: nostr_traversal_cooldown_until_ms.is_some(),
                        nostr_traversal_cooldown_until_ms,
                        nostr_traversal_last_observed_skew_ms: nostr_state
                            .and_then(|state| state.last_observed_skew_ms),
                    });
                }

                let _ = response_tx.send(peers);
            }
            NodeEndpointControlCommand::LocalAdvertSnapshot { response_tx } => {
                let endpoints = if let Some(discovery) = self.nostr_discovery_handle() {
                    discovery.local_advert_endpoints().await
                } else {
                    Vec::new()
                };
                let _ = response_tx.send(endpoints);
            }
            NodeEndpointControlCommand::RelaySnapshot { response_tx } => {
                let relays = if let Some(discovery) = self.nostr_discovery_handle() {
                    discovery
                        .relay_statuses()
                        .await
                        .into_iter()
                        .map(|relay| NodeEndpointRelayStatus {
                            url: relay.url,
                            status: relay.status,
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                let _ = response_tx.send(relays);
            }
            NodeEndpointControlCommand::UpdateRelays {
                advert_relays,
                dm_relays,
                response_tx,
            } => {
                let result = if let Some(discovery) = self.nostr_discovery_handle() {
                    discovery
                        .update_relays(advert_relays, dm_relays)
                        .await
                        .map_err(|error| NodeError::Discovery(error.to_string()))
                } else {
                    Err(NodeError::Discovery(
                        "Nostr discovery is not running".to_string(),
                    ))
                };
                let _ = response_tx.send(result);
            }
        }
    }

}
