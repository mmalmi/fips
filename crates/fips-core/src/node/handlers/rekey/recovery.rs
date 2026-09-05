use super::*;

impl Node {
    pub(in crate::node) fn abandon_fmp_rekey_for_peer(
        &mut self,
        node_addr: &NodeAddr,
        reason: &'static str,
    ) -> bool {
        let peer_name = self.peer_display_name(node_addr);
        let cleanup = self.peers.get_mut(node_addr).and_then(|peer| {
            let transport_id = peer.transport_id();
            peer.clear_handshake_msg2();
            peer.abandon_rekey().map(|idx| (transport_id, idx))
        });

        let Some((transport_id, idx)) = cleanup else {
            return false;
        };

        if let Some(tid) = transport_id {
            self.pending_outbound.remove(&(tid, idx.as_u32()));
            self.deregister_session_index((tid, idx.as_u32()));
        }
        let _ = self.index_allocator.free(idx);
        let _ = self.clear_dataplane_fmp_pending_receive_epoch(node_addr);
        let _ = self.sync_dataplane_fmp_owner(node_addr);
        debug!(
            peer = %peer_name,
            reason,
            "Abandoned FMP rekey state"
        );
        true
    }

    pub(in crate::node) fn expire_unconfirmed_fmp_rekeys(&mut self, now: std::time::Instant) {
        let timeout = Duration::from_secs(self.config.node.rate_limit.handshake_timeout_secs);
        let expired = self
            .peers
            .iter()
            .filter_map(|(addr, peer)| {
                peer.unconfirmed_rekey_expired(now, timeout)
                    .then_some(*addr)
            })
            .collect::<Vec<_>>();
        for addr in expired {
            // A lost Msg2 or a delayed crossed Msg1 can leave a responder
            // pending forever. Retire only that unconfirmed receiver index;
            // the authenticated current epoch and its drain stay intact.
            self.abandon_fmp_rekey_for_peer(&addr, "unconfirmed responder rekey timed out");
        }
    }
}
