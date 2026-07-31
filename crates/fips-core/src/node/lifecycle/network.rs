use super::*;
use crate::transport::udp::UdpNetworkRebindProbe;
use crate::transport::{Transport, TransportError};

pub(in crate::node) struct NetworkRebindRequest {
    bind_interface: Option<String>,
    response_tx: tokio::sync::oneshot::Sender<Result<usize, NodeError>>,
}

impl NetworkRebindRequest {
    pub(in crate::node) fn new(
        bind_interface: Option<String>,
        response_tx: tokio::sync::oneshot::Sender<Result<usize, NodeError>>,
    ) -> Self {
        Self {
            bind_interface,
            response_tx,
        }
    }

    pub(in crate::node) fn reject(self, error: NodeError) {
        let _ = self.response_tx.send(Err(error));
    }
}

pub(in crate::node) struct NetworkRebindCompletion {
    request: NetworkRebindRequest,
    preparation: Result<(), NodeError>,
}

struct AppliedNetworkRebind {
    refreshed: usize,
    affected_transport_ids: Vec<crate::transport::TransportId>,
    affected_udp_transport_ids: Vec<crate::transport::TransportId>,
    changed_interface_udp_transport_ids: Vec<crate::transport::TransportId>,
}

enum CarrierRebindRollback {
    Udp {
        transport_id: crate::transport::TransportId,
        bind_interface: Option<String>,
    },
    WebSocketStart {
        transport_id: crate::transport::TransportId,
        state: crate::transport::TransportState,
    },
}

impl Node {
    pub(in crate::node) fn spawn_network_rebind_preparation(
        &self,
        request: NetworkRebindRequest,
        completion_tx: tokio::sync::mpsc::Sender<NetworkRebindCompletion>,
    ) {
        let probes = self.network_rebind_probes(request.bind_interface.clone());
        tokio::spawn(async move {
            let preparation = match probes {
                Ok(probes) => futures::future::try_join_all(
                    probes.into_iter().map(UdpNetworkRebindProbe::prepare),
                )
                .await
                .map(drop)
                .map_err(NodeError::from_transport_error),
                Err(error) => Err(NodeError::from_transport_error(error)),
            };
            let _ = completion_tx
                .send(NetworkRebindCompletion {
                    request,
                    preparation,
                })
                .await;
        });
    }

    fn network_rebind_probes(
        &self,
        bind_interface: Option<String>,
    ) -> Result<Vec<UdpNetworkRebindProbe>, TransportError> {
        let bind_interface = udp_bind_interface(bind_interface);
        self.transports
            .values()
            .filter_map(|transport| match transport {
                crate::transport::TransportHandle::Udp(udp) => {
                    Some(udp.network_rebind_probe(bind_interface.clone()))
                }
                _ => None,
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|probes| probes.into_iter().flatten().collect())
    }

    pub(in crate::node) async fn complete_network_rebind(
        &mut self,
        completion: NetworkRebindCompletion,
    ) {
        let NetworkRebindCompletion {
            request,
            preparation,
        } = completion;
        let result = match preparation {
            Ok(()) => {
                self.apply_prepared_network_rebind(request.bind_interface.clone())
                    .await
            }
            Err(error) => Err(error),
        };
        let _ = request.response_tx.send(result);
    }

    /// Rebind configured UDP carriers after an observed underlay change.
    ///
    /// Transport IDs, authenticated peers, and end-to-end sessions remain
    /// intact. UDP sockets move to the new underlay, direct payload is held
    /// behind validated mesh fallback, and fresh direct candidates race in
    /// parallel.
    pub(in crate::node) async fn apply_prepared_network_rebind(
        &mut self,
        bind_interface: Option<String>,
    ) -> Result<usize, NodeError> {
        let rebind_started_at_ms = Self::now_ms();
        let udp_bind_interface = udp_bind_interface(bind_interface.clone());
        let AppliedNetworkRebind {
            refreshed,
            affected_transport_ids,
            affected_udp_transport_ids,
            changed_interface_udp_transport_ids,
        } = self
            .apply_carrier_network_rebinds(udp_bind_interface.clone())
            .await?;

        // Carrier changes are reversible while discovery and desired config
        // still describe the old network. Commit those shared settings only
        // after every fallible carrier apply has succeeded.
        self.config.node.discovery.nostr.bind_interface = bind_interface.clone();
        if let Some(discovery) = self.nostr_discovery.clone() {
            discovery.rebind_network(bind_interface.clone()).await;
        }
        match &mut self.config.transports.udp {
            crate::config::TransportInstances::Single(config) => {
                config.bind_interface.clone_from(&udp_bind_interface);
            }
            crate::config::TransportInstances::Named(configs) => {
                for config in configs.values_mut() {
                    config.bind_interface.clone_from(&udp_bind_interface);
                }
            }
        }

        if !affected_transport_ids.is_empty() {
            for transport_id in &affected_transport_ids {
                self.transport_rebind_packet_cutoffs_ms
                    .insert(*transport_id, rebind_started_at_ms);
            }
            let rebound_peers: Vec<_> = self
                .peers
                .values()
                .filter_map(|peer| {
                    let transport_id = peer.transport_id()?;
                    let has_configured_websocket_path = self
                        .configured_peer(peer.node_addr())
                        .is_some_and(|configured| {
                            configured.addresses.iter().any(|address| {
                                address.is_configured()
                                    && address.transport.eq_ignore_ascii_case("websocket")
                            })
                        });
                    affected_transport_ids.contains(&transport_id).then_some((
                        *peer.node_addr(),
                        affected_udp_transport_ids.contains(&transport_id)
                            && !changed_interface_udp_transport_ids.contains(&transport_id)
                            && peer.is_healthy()
                            && peer.can_send()
                            // A configured WebSocket seed can opportunistically
                            // upgrade to UDP. That UDP tuple dies with the
                            // underlay, while leaving it "healthy" rejects the
                            // rebuilt WebSocket carrier and strands fallback
                            // routing. Re-authenticate the configured carrier.
                            && !has_configured_websocket_path,
                    ))
                })
                .collect();
            let rebound_carrier_peer_addrs = rebound_peers
                .iter()
                .map(|(peer_addr, _)| *peer_addr)
                .collect::<Vec<_>>();
            let routed_fsp_destinations = self
                .dataplane
                .fsp_owner_destinations()
                .into_iter()
                .filter(|dest| {
                    self.dataplane
                        .fsp_owner_next_hop(dest)
                        .is_some_and(|next_hop| {
                            next_hop != *dest && rebound_carrier_peer_addrs.contains(&next_hop)
                        })
                })
                .collect::<Vec<_>>();
            let now_ms = Self::now_ms();
            for dest in &routed_fsp_destinations {
                self.restart_session_direct_path_validation(*dest, now_ms);
            }
            for dest in self.dataplane.fsp_owner_destinations() {
                // Route activity is evidence about one concrete carrier
                // incarnation. Keeping it across a UDP or WebSocket rebuild
                // can pin an established FSP owner to an old fallback while
                // direct and transit adjacencies reauthenticate. Keep the
                // end-to-end session and recompute its output route, but
                // discard that pre-rebind affinity first.
                let _ = self
                    .dataplane
                    .invalidate_fsp_carrier_activity(dest, &rebound_carrier_peer_addrs);
            }
            let mut invalidated_peers = Vec::new();
            let mut preserved_udp_peers = Vec::new();
            for (peer_addr, can_preserve_udp_session) in rebound_peers {
                self.pending_lookups.remove(&peer_addr);
                if can_preserve_udp_session {
                    let has_pending_rekey = self.peers.get(&peer_addr).is_some_and(|peer| {
                        peer.rekey_in_progress() || peer.pending_new_session().is_some()
                    });
                    if has_pending_rekey {
                        self.abandon_fmp_rekey_for_peer(
                            &peer_addr,
                            "carrier rebind invalidated pending key epoch",
                        );
                    }
                    if self.sync_dataplane_fmp_owner(&peer_addr) {
                        self.restart_session_direct_path_validation(peer_addr, now_ms);
                        preserved_udp_peers.push(peer_addr);
                        continue;
                    }
                }
                invalidated_peers.push(peer_addr);
                if let Some(peer) = self.peers.get_mut(&peer_addr) {
                    peer.mark_stale();
                }
            }
            if !preserved_udp_peers.is_empty() {
                debug!(
                    count = preserved_udp_peers.len(),
                    "Preserved authenticated UDP sessions while routing payload through validated fallback paths"
                );
            }
            let heartbeat = [crate::protocol::LinkMessageType::Heartbeat.to_byte()];
            for peer_addr in &preserved_udp_peers {
                match self
                    .send_dataplane_fmp_link_plaintext(peer_addr, &heartbeat, false)
                    .await
                {
                    Ok(()) => {
                        if let Some(peer) = self.peers.get_mut(peer_addr) {
                            peer.mark_heartbeat_sent(std::time::Instant::now());
                        }
                    }
                    Err(error) => {
                        debug!(
                            peer = %self.peer_display_name(peer_addr),
                            %error,
                            "Failed to probe preserved UDP session after network rebind"
                        );
                    }
                }
            }
            for peer_addr in &invalidated_peers {
                let has_pending_rekey = self.peers.get(peer_addr).is_some_and(|peer| {
                    peer.rekey_in_progress() || peer.pending_new_session().is_some()
                });
                if has_pending_rekey {
                    self.abandon_fmp_rekey_for_peer(
                        peer_addr,
                        "carrier rebind invalidated pending key epoch",
                    );
                }
                self.remove_dataplane_fmp_owner(peer_addr);
                self.restart_session_direct_path_validation(*peer_addr, now_ms);
                self.refresh_dataplane_fsp_owner_routes_after_fmp_owner_update(peer_addr);
            }
            self.maybe_recover_degraded_session_routes(now_ms).await;
            debug!(
                count = invalidated_peers.len(),
                "Invalidated direct session payload and rebound UDP peer tuples for authenticated path replacement"
            );

            let stale_connections: Vec<_> = self
                .peers
                .connection_iter()
                .filter(|(_, connection)| {
                    connection
                        .transport_id()
                        .is_some_and(|id| affected_transport_ids.contains(&id))
                })
                .map(|(link_id, connection)| {
                    let expected_identity = if connection.is_outbound() {
                        connection.expected_identity().copied()
                    } else {
                        None
                    };
                    (*link_id, expected_identity)
                })
                .collect();
            let mut rebind_reprobe_peers = preserved_udp_peers
                .iter()
                .chain(invalidated_peers.iter())
                .copied()
                .collect::<Vec<_>>();
            for (link_id, expected_identity) in &stale_connections {
                self.cleanup_stale_connection(*link_id, now_ms);
                if let Some(identity) = expected_identity {
                    rebind_reprobe_peers.push(*identity.node_addr());
                }
            }
            rebind_reprobe_peers.sort_unstable();
            rebind_reprobe_peers.dedup();
            for peer_addr in rebind_reprobe_peers {
                self.schedule_network_rebind_reprobe(peer_addr, now_ms);
            }
            if !changed_interface_udp_transport_ids.is_empty() {
                self.process_pending_retries(now_ms).await;
            }
            if !stale_connections.is_empty() {
                debug!(
                    count = stale_connections.len(),
                    "Discarded in-flight handshakes created on rebuilt carriers"
                );
            }
        }

        if let Some(discovery) = self.nostr_discovery.clone()
            && let Err(error) = self.refresh_overlay_advert(&discovery).await
        {
            debug!(%error, "Failed to refresh local advert after network rebind");
        }

        Ok(refreshed)
    }

    async fn apply_carrier_network_rebinds(
        &mut self,
        udp_bind_interface: Option<String>,
    ) -> Result<AppliedNetworkRebind, NodeError> {
        let mut transport_ids = self.transports.keys().copied().collect::<Vec<_>>();
        transport_ids.sort_unstable_by_key(crate::transport::TransportId::as_u32);
        let live_websocket_ids = transport_ids
            .iter()
            .copied()
            .filter(|transport_id| {
                matches!(
                    self.transports.get(transport_id),
                    Some(crate::transport::TransportHandle::WebSocket(websocket))
                        if websocket.state().is_operational()
                )
            })
            .collect::<Vec<_>>();

        let mut refreshed = 0usize;
        let mut affected_transport_ids = Vec::new();
        let mut affected_udp_transport_ids = Vec::new();
        let mut changed_interface_udp_transport_ids = Vec::new();
        let mut rollbacks = Vec::new();

        // Apply UDP and inactive WebSocket carriers first. Both can fail, and
        // each successful change has enough state captured here to undo it.
        // Live WebSocket stream refreshes are deferred because they cannot
        // fail and do not replace their listener.
        for transport_id in transport_ids.iter().copied() {
            let Some(transport) = self.transports.get_mut(&transport_id) else {
                continue;
            };
            let (refresh_result, rollback) = match transport {
                crate::transport::TransportHandle::Udp(udp) => {
                    let previous_bind_interface = udp.network_bind_interface();
                    (
                        udp.rebind_after_prepared_network_change(udp_bind_interface.clone())
                            .await,
                        Some(CarrierRebindRollback::Udp {
                            transport_id,
                            bind_interface: previous_bind_interface,
                        }),
                    )
                }
                crate::transport::TransportHandle::WebSocket(websocket)
                    if !websocket.state().is_operational() =>
                {
                    let previous_state = websocket.state();
                    (
                        websocket.restart_after_network_change().await,
                        Some(CarrierRebindRollback::WebSocketStart {
                            transport_id,
                            state: previous_state,
                        }),
                    )
                }
                _ => continue,
            };

            match refresh_result {
                Ok(true) => {
                    refreshed = refreshed.saturating_add(1);
                    affected_transport_ids.push(transport_id);
                    if let Some(CarrierRebindRollback::Udp { bind_interface, .. }) = &rollback {
                        affected_udp_transport_ids.push(transport_id);
                        if bind_interface != &udp_bind_interface {
                            changed_interface_udp_transport_ids.push(transport_id);
                        }
                    }
                    if let Some(rollback) = rollback {
                        rollbacks.push(rollback);
                    }
                    info!(
                        transport_id = %transport_id,
                        transport = transport.transport_type().name,
                        "Refreshed configured carrier for network change"
                    );
                }
                Ok(false) => {}
                Err(error) => {
                    warn!(
                        transport_id = %transport_id,
                        transport = transport.transport_type().name,
                        %error,
                        "Carrier failed during prepared network rebind"
                    );
                    return Err(self
                        .rollback_carrier_network_rebinds(error, rollbacks)
                        .await);
                }
            }
        }

        for transport_id in live_websocket_ids {
            let Some(crate::transport::TransportHandle::WebSocket(websocket)) =
                self.transports.get_mut(&transport_id)
            else {
                continue;
            };
            if !websocket.state().is_operational() {
                continue;
            }
            match websocket.restart_after_network_change().await {
                Ok(true) => {
                    refreshed = refreshed.saturating_add(1);
                    affected_transport_ids.push(transport_id);
                    info!(
                        transport_id = %transport_id,
                        transport = websocket.transport_type().name,
                        "Refreshed configured carrier for network change"
                    );
                }
                Ok(false) => {}
                Err(error) => {
                    warn!(
                        transport_id = %transport_id,
                        transport = websocket.transport_type().name,
                        %error,
                        "Carrier failed during prepared network rebind"
                    );
                    return Err(self
                        .rollback_carrier_network_rebinds(error, rollbacks)
                        .await);
                }
            }
        }

        Ok(AppliedNetworkRebind {
            refreshed,
            affected_transport_ids,
            affected_udp_transport_ids,
            changed_interface_udp_transport_ids,
        })
    }

    async fn rollback_carrier_network_rebinds(
        &mut self,
        apply_error: TransportError,
        rollbacks: Vec<CarrierRebindRollback>,
    ) -> NodeError {
        let mut rollback_errors = Vec::new();
        for rollback in rollbacks.into_iter().rev() {
            let (transport_id, result) = match rollback {
                CarrierRebindRollback::Udp {
                    transport_id,
                    bind_interface,
                } => {
                    let result = match self.transports.get_mut(&transport_id) {
                        Some(crate::transport::TransportHandle::Udp(udp)) => udp
                            .rebind_after_prepared_network_change(bind_interface)
                            .await
                            .map(drop),
                        _ => Err(TransportError::NotStarted),
                    };
                    (transport_id, result)
                }
                CarrierRebindRollback::WebSocketStart {
                    transport_id,
                    state,
                } => {
                    let result = match self.transports.get_mut(&transport_id) {
                        Some(crate::transport::TransportHandle::WebSocket(websocket)) => {
                            websocket.rollback_network_change_start(state).await
                        }
                        _ => Err(TransportError::NotStarted),
                    };
                    (transport_id, result)
                }
            };
            match result {
                Ok(()) => {
                    info!(
                        transport_id = %transport_id,
                        "Rolled back carrier after network rebind failure"
                    );
                }
                Err(error) => {
                    warn!(
                        transport_id = %transport_id,
                        %error,
                        "Carrier rollback failed after network rebind failure"
                    );
                    rollback_errors.push(format!("{transport_id}: {error}"));
                }
            }
        }

        if rollback_errors.is_empty() {
            NodeError::from_transport_error(apply_error)
        } else {
            NodeError::from_transport_error(TransportError::StartFailed(format!(
                "network rebind failed: {apply_error}; rollback failed: {}",
                rollback_errors.join("; ")
            )))
        }
    }

    pub(in crate::node) fn packet_predates_carrier_rebind(
        &self,
        transport_id: crate::transport::TransportId,
        packet_timestamp_ms: u64,
    ) -> bool {
        self.transport_rebind_packet_cutoffs_ms
            .get(&transport_id)
            .is_some_and(|cutoff_ms| packet_timestamp_ms <= *cutoff_ms)
    }
}

fn udp_bind_interface(bind_interface: Option<String>) -> Option<String> {
    #[cfg(windows)]
    {
        let _ = bind_interface;
        None
    }
    #[cfg(not(windows))]
    {
        bind_interface
    }
}
