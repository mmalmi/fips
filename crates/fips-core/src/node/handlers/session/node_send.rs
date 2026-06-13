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

    /// Send application data over an established session.
    ///
    /// Uses the FSP pipeline: builds a 12-byte cleartext header (used as AAD),
    /// prepends the 6-byte inner header to the plaintext, encrypts with AAD,
    /// optionally inserts cleartext coords, and wraps in a SessionDatagram.
    ///
    /// The `src_port` and `dst_port` identify the service. A 4-byte port header
    /// `[src_port:2 LE][dst_port:2 LE]` is prepended to `payload` inside the
    /// AEAD envelope. The receiver dispatches by `dst_port`.
    pub(in crate::node) async fn send_session_data(
        &mut self,
        dest_addr: &NodeAddr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        let now_ms = Self::now_ms();
        let send_context = self
            .sessions
            .session_fsp_send_context(dest_addr, now_ms)
            .map_err(|error| error.into_node_error(*dest_addr))?;
        let wants_coords = send_context.wants_coords();
        let timestamp = send_context.timestamp;

        // Build port-prefixed plaintext: [src_port:2 LE][dst_port:2 LE][payload...]
        let mut port_payload = Vec::with_capacity(FSP_PORT_HEADER_SIZE + payload.len());
        port_payload.extend_from_slice(&src_port.to_le_bytes());
        port_payload.extend_from_slice(&dst_port.to_le_bytes());
        port_payload.extend_from_slice(payload);

        // Build inner plaintext (doesn't depend on counter)
        let msg_type = SessionMessageType::DataPacket.to_byte(); // 0x10
        let inner_flags = send_context.inner_flags_byte();
        let inner_plaintext =
            fsp_prepend_inner_header(timestamp, msg_type, inner_flags, &port_payload);

        // Determine whether coords fit within transport MTU.
        // If not, send standalone CoordsWarmup before the data packet.
        let (include_coords, my_coords, dest_coords) = if wants_coords {
            let src = self.tree_state.my_coords().clone();
            let dst = self.get_dest_coords(dest_addr);
            let coords_size = coords_wire_size(&src) + coords_wire_size(&dst);
            let total_wire =
                FIPS_OVERHEAD as usize + FSP_PORT_HEADER_SIZE + coords_size + payload.len();
            if total_wire <= self.transport_mtu() as usize {
                (true, Some(src), Some(dst))
            } else {
                // Coords don't fit piggybacked — send standalone CoordsWarmup first
                if let Err(e) = self.send_coords_warmup(dest_addr).await {
                    debug!(dest = %self.peer_display_name(dest_addr), error = %e,
                        "Failed to send standalone CoordsWarmup before data packet");
                }
                (false, None, None)
            }
        } else {
            (false, None, None)
        };

        // Consume one warmup opportunity for either piggybacked coords or the
        // standalone warmup attempt, preserving the previous retry behavior.
        if wants_coords {
            self.sessions.consume_coords_warmup_packet(dest_addr);
        }

        // Build FSP flags (CP flag if coords, K-bit for key epoch)
        let flags = send_context.fsp_flags(include_coords);

        let coords = my_coords.as_ref().zip(dest_coords.as_ref());
        self.send_session_fsp_plan(SessionFspSendPlan::new(
            *dest_addr,
            timestamp,
            flags,
            &inner_plaintext,
            coords,
            SessionFspSendBookkeeping::Data {
                payload_len: payload.len(),
                now_ms,
            },
        ))
        .await
    }

    async fn send_session_fsp_plan(
        &mut self,
        plan: SessionFspSendPlan<'_>,
    ) -> Result<(), NodeError> {
        let dest_addr = plan.dest_addr();
        let sealed = self.sessions.seal_session_fsp_send(plan)?;
        let (mut datagram, bookkeeping) =
            sealed.into_datagram(*self.node_addr(), self.config.node.session.default_ttl);
        self.send_session_datagram(&mut datagram).await?;

        let _ = self
            .sessions
            .record_fsp_send_bookkeeping(&dest_addr, bookkeeping);
        Ok(())
    }

    /// Send an IPv6 packet through the IPv6 shim (port 256) with header compression.
    ///
    /// Compresses the IPv6 header (format 0x00), then sends via `send_session_data`
    /// with `src_port=256, dst_port=256`.
    pub(in crate::node) async fn send_ipv6_packet(
        &mut self,
        dest_addr: &NodeAddr,
        ipv6_packet: &[u8],
    ) -> Result<(), NodeError> {
        let compressed = crate::upper::ipv6_shim::compress_ipv6(ipv6_packet).ok_or_else(|| {
            NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "IPv6 header compression failed".into(),
            }
        })?;
        self.send_session_data(
            dest_addr,
            FSP_PORT_IPV6_SHIM,
            FSP_PORT_IPV6_SHIM,
            &compressed,
        )
        .await
    }

    /// Handle an embedded endpoint data command.
    pub(in crate::node) async fn handle_endpoint_data_command(
        &mut self,
        command: NodeEndpointCommand,
        drain_stages: EndpointCommandDrainStages,
    ) {
        match command {
            NodeEndpointCommand::Send {
                command,
                response_tx,
            } => {
                let result = self
                    .handle_endpoint_send_command(command, drain_stages)
                    .await;
                let _ = response_tx.send(result);
            }
            NodeEndpointCommand::SendOneway { command } => {
                // Result deliberately discarded — caller wanted
                // fire-and-forget. Errors still get logged inside
                // `send_endpoint_data` so they're not silent.
                let _ = self
                    .handle_endpoint_send_command(command, drain_stages)
                    .await;
            }
            NodeEndpointCommand::SendBatchOneway { command, .. } => {
                self.handle_endpoint_send_batch_command(command, drain_stages)
                    .await;
            }
            NodeEndpointCommand::UpdatePeers { peers, response_tx } => {
                let result = self.update_peers(peers).await;
                let _ = response_tx.send(result);
            }
            NodeEndpointCommand::PeerSnapshot { response_tx } => {
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
                        let srtt = peer.mmp().and_then(|mmp| {
                            mmp.metrics.srtt_ms().map(|value| {
                                (value.round() as u64, mmp.metrics.srtt_age_ms(snapshot_now))
                            })
                        });
                        NodeEndpointPeer {
                            npub,
                            node_addr: *peer.node_addr(),
                            connected: true,
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
            NodeEndpointCommand::RelaySnapshot { response_tx } => {
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
            NodeEndpointCommand::UpdateRelays {
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

    async fn handle_endpoint_send_command(
        &mut self,
        command: EndpointSendCommand,
        drain_stages: EndpointCommandDrainStages,
    ) -> Result<(), NodeError> {
        let lane = command.lane();
        let (send, queued_at) = command.into_parts();
        record_endpoint_command_wait(queued_at, lane, 1, drain_stages);
        let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::EndpointSend);
        self.send_endpoint_data_send(send).await
    }

    async fn handle_endpoint_send_batch_command(
        &mut self,
        command: EndpointSendBatchCommand,
        drain_stages: EndpointCommandDrainStages,
    ) {
        let lane = command.lane();
        let count = command.len() as u64;
        let (remote, payloads, queued_at) = command.into_parts();
        let (priority_count, bulk_count) = match lane {
            EndpointCommandLane::Priority => (count as usize, 0),
            EndpointCommandLane::Bulk => (0, count as usize),
        };
        crate::perf_profile::record_endpoint_send_batch(
            count as usize,
            priority_count,
            bulk_count,
            crate::endpoint::ENDPOINT_SEND_BATCH_COMMAND_MAX,
        );
        // The command queue wait ends when rx_loop starts handling the batch.
        // Count one sample per payload without charging earlier payload send
        // work to later payloads' queue residence.
        record_endpoint_command_wait(queued_at, lane, count, drain_stages);
        let _batch_service = crate::perf_profile::BatchTimer::start(
            crate::perf_profile::Stage::EndpointSendBatchService,
            count as usize,
        );
        let dest_addr = *remote.node_addr();
        let dest_pubkey = remote.pubkey_full();
        self.register_identity(dest_addr, dest_pubkey);

        #[cfg(unix)]
        if self.encrypt_workers.is_some()
            && self
                .sessions
                .get(&dest_addr)
                .is_some_and(|entry| entry.is_established())
        {
            self.handle_established_endpoint_send_batch(dest_addr, dest_pubkey, payloads)
                .await;
            return;
        }

        self.handle_endpoint_send_batch_slow_path(dest_addr, dest_pubkey, payloads)
            .await;
    }

}
