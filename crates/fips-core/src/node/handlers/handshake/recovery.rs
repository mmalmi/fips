use super::*;

impl Node {
    pub(in crate::node) fn same_epoch_msg1_is_direct_path_recovery(
        &mut self,
        peer_node_addr: &NodeAddr,
        now_ms: u64,
    ) -> bool {
        let Some(peer_unhealthy) = self
            .peers
            .get(peer_node_addr)
            .map(|peer| !peer.is_healthy())
        else {
            return false;
        };
        peer_unhealthy
            || self.session_direct_path_blocks_direct_payload(peer_node_addr, now_ms)
            || self.session_direct_path_exclusive_trust_expired(peer_node_addr, now_ms)
    }

    pub(in crate::node) fn same_path_msg1_is_established_rekey(
        &self,
        peer_node_addr: &NodeAddr,
        transport_id: crate::transport::TransportId,
        remote_addr: &crate::transport::TransportAddr,
    ) -> bool {
        // A pending outbound PeerConnection on this exact tuple means both
        // endpoints are performing a full carrier refresh. Resolve those two
        // Noise handshakes with the normal deterministic cross-connection
        // rule. FMP rekeys live on ActivePeer instead, so treating this Msg1
        // as a rekey would make both sides install unrelated responder
        // indexes while their outbound halves are still in flight.
        let simultaneous_same_path_connection = self.peers.connection_values().any(|connection| {
            connection.is_outbound()
                && connection.transport_id() == Some(transport_id)
                && connection.source_addr() == Some(remote_addr)
                && connection
                    .expected_identity()
                    .is_some_and(|identity| identity.node_addr() == peer_node_addr)
        });
        if simultaneous_same_path_connection {
            return false;
        }

        let direct_payload_validation_pending = self
            .session_direct_degradation
            .has_pending_validation(peer_node_addr);
        // A real frame accepted by the current epoch proves the remote has
        // installed matching keys. Configured timer/counter thresholds may
        // legitimately rotate this session before the initial 30s window.
        // Unauthenticated arrivals and a previous epoch's traffic cannot
        // supply this evidence.
        let current_epoch_authenticated = self
            .dataplane_fmp_link_metrics(peer_node_addr, Instant::now())
            .is_some_and(|metrics| metrics.current_epoch_authenticated);
        self.config.node.rekey.enabled
            && self.peers.get(peer_node_addr).is_some_and(|peer| {
                peer.has_session()
                    && peer.can_send()
                    && (current_epoch_authenticated
                        || direct_payload_validation_pending
                        || peer.is_draining()
                        || peer.session_established_at().elapsed().as_secs() >= 30)
                    && peer.transport_id() == Some(transport_id)
                    && peer.current_addr() == Some(remote_addr)
            })
    }
}
