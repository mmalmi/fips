use super::*;

impl Node {
    /// Drain mDNS-discovered peers and initiate Noise IK handshakes. For
    /// active peers this is a non-disruptive alternate-path refresh: the
    /// current link stays live until a new handshake authenticates and
    /// promotes. The handshake itself is the authentication — a spoofed
    /// mDNS advert with someone else's npub fails the IK exchange and
    /// is dropped.
    pub(in crate::node) async fn poll_lan_discovery(&mut self) {
        let Some(runtime) = self.lan_discovery.clone() else {
            return;
        };
        let events = runtime.drain_events().await;
        if events.is_empty() {
            return;
        }
        let mut connect_budget = self.discovery_connect_budget();
        let mut skipped_budget = 0usize;
        for event in events {
            let crate::discovery::lan::LanEvent::Discovered(peer) = event;
            let Some((transport_id, local_addr)) =
                self.find_udp_transport_for_remote_addr(peer.addr, PeerAddressProvenance::Learned)
            else {
                debug!(
                    addr = %peer.addr,
                    "lan: skip discovered peer with no compatible UDP transport"
                );
                continue;
            };
            let identity = match crate::PeerIdentity::from_npub(&peer.npub) {
                Ok(id) => id,
                Err(err) => {
                    debug!(npub = %peer.npub, error = %err, "lan: skip bad npub");
                    continue;
                }
            };
            let peer_node_addr = *identity.node_addr();
            let remote_addr = crate::transport::TransportAddr::from_string(&peer.addr.to_string());
            if self.peers.contains_key(&peer_node_addr) {
                let candidate = PeerAddress::new("udp", peer.addr.to_string()).learned();
                if self.active_peer_candidate_is_fresh_enough_to_skip(
                    &peer_node_addr,
                    std::slice::from_ref(&candidate),
                ) {
                    continue;
                }
                if self.is_connecting_to_peer_on_path(&peer_node_addr, transport_id, &remote_addr) {
                    continue;
                }
                if connect_budget == 0 || self.path_candidate_attempt_budget(&peer_node_addr) == 0 {
                    skipped_budget = skipped_budget.saturating_add(1);
                    continue;
                }
                info!(
                    npub = %identity.short_npub(),
                    addr = %peer.addr,
                    local_addr = %local_addr,
                    "lan: initiating alternate-path handshake to active peer"
                );
                if let Err(err) = self
                    .initiate_connection(transport_id, remote_addr, identity)
                    .await
                {
                    debug!(
                        npub = %peer.npub,
                        error = %err,
                        "lan: failed to initiate active peer alternate-path handshake"
                    );
                }
                connect_budget = connect_budget.saturating_sub(1);
                continue;
            }
            if self.is_connecting_to_peer_on_path(&peer_node_addr, transport_id, &remote_addr) {
                continue;
            }
            if connect_budget == 0 || self.path_candidate_attempt_budget(&peer_node_addr) == 0 {
                skipped_budget = skipped_budget.saturating_add(1);
                continue;
            }
            info!(
                npub = %identity.short_npub(),
                addr = %peer.addr,
                local_addr = %local_addr,
                "lan: initiating handshake to discovered peer"
            );
            if let Err(err) = self
                .initiate_connection(transport_id, remote_addr, identity)
                .await
            {
                debug!(
                    npub = %peer.npub,
                    error = %err,
                    "lan: failed to initiate connection to discovered peer"
                );
            }
            connect_budget = connect_budget.saturating_sub(1);
        }
        if skipped_budget > 0 {
            debug!(
                skipped = skipped_budget,
                "lan: discovery connect budget exhausted"
            );
        }
    }
}
