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
                self.mark_session_direct_path_degraded(*peer_addr, now_ms);
                self.schedule_link_dead_reprobe(*peer_addr, now_ms);
            }
            debug!(
                count = invalidated_peers.len(),
                "Invalidated direct session payload and rebound UDP peer tuples for authenticated path replacement"
            );

            let due_connections: Vec<_> = self
                .peers
                .connection_iter()
                .filter(|(_, connection)| {
                    connection.is_outbound()
                        && connection
                            .transport_id()
                            .is_some_and(|id| refreshed_transport_ids.contains(&id))
                        && connection.handshake_state() == crate::peer::HandshakeState::SentMsg1
                        && connection.handshake_msg1().is_some()
                })
                .map(|(link_id, _)| *link_id)
                .collect();
            for link_id in &due_connections {
                if let Some(connection) = self.peers.get_connection_mut(link_id) {
                    connection.restart_handshake_resends(now_ms);
                }
            }
            self.resend_pending_handshakes(now_ms).await;
            if !due_connections.is_empty() {
                debug!(
                    count = due_connections.len(),
                    "Retried in-flight UDP handshakes on rebound carrier"
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
}
