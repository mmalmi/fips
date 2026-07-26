use super::*;

impl Node {
    /// Rebind configured UDP carriers after an observed underlay change.
    ///
    /// Transport IDs, authenticated peers, and end-to-end sessions remain
    /// intact. Adopted NAT-traversal sockets are left alone; the normal direct
    /// path refresh races fresh candidates over the rebound configured carrier.
    pub(in crate::node) async fn rebind_network_transports(
        &mut self,
        bind_interface: Option<String>,
    ) -> Result<usize, NodeError> {
        let rebind_started_at_ms = Self::now_ms();
        self.config.node.discovery.nostr.bind_interface = bind_interface.clone();
        match &mut self.config.transports.udp {
            crate::config::TransportInstances::Single(config) => {
                config.bind_interface.clone_from(&bind_interface);
            }
            crate::config::TransportInstances::Named(configs) => {
                for config in configs.values_mut() {
                    config.bind_interface.clone_from(&bind_interface);
                }
            }
        }

        let mut refreshed = 0usize;
        let mut refreshed_transport_ids = Vec::new();

        for (transport_id, transport) in &mut self.transports {
            let refresh_result = match transport {
                crate::transport::TransportHandle::Udp(udp) => {
                    udp.rebind_after_network_change(bind_interface.clone())
                        .await
                }
                crate::transport::TransportHandle::WebSocket(websocket) => {
                    websocket.restart_after_network_change().await
                }
                _ => Ok(false),
            };
            match refresh_result {
                Ok(true) => {
                    refreshed = refreshed.saturating_add(1);
                    refreshed_transport_ids.push(*transport_id);
                    info!(
                        transport_id = %transport_id,
                        transport = transport.transport_type().name,
                        "Refreshed configured carrier for network change"
                    );
                }
                Ok(false) => {}
                Err(error) => return Err(NodeError::from_transport_error(error)),
            }
        }

        if !refreshed_transport_ids.is_empty() {
            for transport_id in &refreshed_transport_ids {
                self.transport_rebind_packet_cutoffs_ms
                    .insert(*transport_id, rebind_started_at_ms);
            }
            let mut invalidated_peers = Vec::new();
            for peer in self.peers.values_mut() {
                if peer
                    .transport_id()
                    .is_some_and(|id| refreshed_transport_ids.contains(&id))
                {
                    invalidated_peers.push(*peer.node_addr());
                    peer.mark_stale();
                }
            }
            let now_ms = Self::now_ms();
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
                self.mark_session_direct_path_degraded(*peer_addr, now_ms);
                self.refresh_dataplane_fsp_owner_routes_after_fmp_owner_update(peer_addr);
                self.schedule_link_dead_reprobe(*peer_addr, now_ms);
            }
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
                        .is_some_and(|id| refreshed_transport_ids.contains(&id))
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
            for (link_id, expected_identity) in &stale_connections {
                self.cleanup_stale_connection(*link_id, now_ms);
                if let Some(identity) = expected_identity {
                    self.schedule_local_route_retry(*identity.node_addr(), now_ms);
                }
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
