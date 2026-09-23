use super::*;

impl Node {
    /// An authenticated destination needs no lookup before first contact.
    /// Keep explicitly selected carriers and existing session recovery intact.
    pub(super) async fn resume_queued_direct_session(&mut self, destination: &NodeAddr) {
        if !self.pending_session_traffic.has_traffic_for(destination)
            || self.sessions.contains_key(destination)
        {
            return;
        }
        let Some(peer) = self
            .find_next_hop(destination)
            .filter(|peer| peer.node_addr() == destination)
        else {
            return;
        };
        let public_key = peer.identity().pubkey_full();
        if let Err(error) = self.initiate_session(*destination, public_key).await {
            debug!(peer = %destination, %error, "Queued direct session initiation failed");
        }
        // A failed/uncertain first send may still own an initiating generation.
        // Its existing retransmission and timeout lifecycle now owns the queue.
        if self.sessions.contains_key(destination) {
            self.pending_lookups.remove(destination);
        }
    }

    /// Transfer only the winning session's pending traffic before any active
    /// send or replay. Fresh peers already own the connection's link totals;
    /// replacing an existing session must add those physical writes once.
    pub(super) fn sync_promoted_handshake(
        &mut self,
        node: &NodeAddr,
        connection: &mut PeerConnection,
        merge_link_stats: bool,
    ) -> Result<(), NodeError> {
        let pending = connection.take_ready_heartbeat_accounting();
        if let Some((origin, _)) = &pending
            && let Some(peer) = self.peers.get_mut(node)
        {
            peer.adopt_pending_fmp_timestamp_origin(*origin);
            if merge_link_stats {
                let sent = connection.link_stats();
                let totals = peer.link_stats_mut();
                totals.packets_sent = totals.packets_sent.saturating_add(sent.packets_sent);
                totals.bytes_sent = totals.bytes_sent.saturating_add(sent.bytes_sent);
            }
        }
        let reply_carrier_handoff = connection
            .completed_handshake_response()
            .is_some_and(|reply| Some(reply.transport_id) != connection.transport_id());
        if reply_carrier_handoff
            && let Some(peer) = self.peers.get(node)
            && let (Some(transport), Some(remote)) = (peer.transport_id(), peer.current_addr())
        {
            // Only the winning session reaches this point. Rebind its owning
            // Link as well as reverse dispatch, preserving lifetime link state.
            self.links
                .rebind_path(peer.link_id(), transport, remote.clone());
        }
        let synced = self.sync_dataplane_fmp_owner(node);
        let installed = if let Some((_, sender)) = pending {
            synced
                && self.peers.get(node).is_some_and(|peer| {
                    self.dataplane
                        .install_pending_fmp_sender(node, peer.session_generation(), sender)
                        .is_ok()
                })
        } else {
            synced || connection.handshake_confirmation().is_none()
        };
        if !installed {
            // A mismatched owner must not emit bootstrap traffic with
            // incomplete accounting. Retire it through normal cleanup.
            warn!(peer = %node, "Rejecting promoted session: pending state could not transfer");
            self.remove_neighbor_for_rotation(node);
            return Err(NodeError::PromotionFailed {
                link_id: connection.link_id(),
                reason: "pending state could not transfer".into(),
            });
        }
        // Promotion consumed the connection. Retain its initial routing work
        // before carrier cleanup or bootstrap can suspend and be canceled.
        self.bloom_state.mark_update_needed(*node);
        if connection.is_outbound()
            && let Some(proof) = connection.handshake_confirmation()
        {
            // The candidate is already consumed. Keep its first authenticated
            // frame across cancellation of later carrier cleanup/bootstrap.
            self.dataplane.defer_fmp_handshake_proof(proof.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
