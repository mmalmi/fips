use super::*;

impl Node {
    /// An authenticated request may take an unanswered outgoing attempt's slot.
    /// This is only eligibility; the inbound ACL must pass before any transfer.
    pub(in crate::node) fn can_receive_neighbor_rotation(
        &self,
        peer: &NodeAddr,
        now_ms: u64,
    ) -> bool {
        self.unanswered_rotation_for_transfer(peer, now_ms)
            .is_some()
            || self.can_attempt_neighbor_rotation(peer, false, now_ms)
    }

    fn unanswered_rotation_for_transfer(&self, peer: &NodeAddr, now_ms: u64) -> Option<LinkId> {
        if self.rotation_new_peer_rejection(peer, now_ms).is_some()
            || now_ms < self.neighbor_rotation.next_attempt_ms
        {
            return None;
        }
        let attempt = self.neighbor_rotation.attempt.as_ref()?;
        if attempt.peer == *peer
            || attempt.confirmed_inbound.is_some()
            || !self.rotation_attempt_is_fresh(attempt, now_ms)
            || self
                .pending_connects
                .iter()
                .any(|pending| !self.peers.contains_key(pending.peer_identity.node_addr()))
        {
            return None;
        }
        let mut outgoing = None;
        for (link, conn) in self.peers.connection_iter() {
            let Some(identity) = conn.expected_identity() else {
                continue;
            };
            if self.peers.contains_key(identity.node_addr()) {
                continue;
            }
            // Msg1 is replayable. Permit only one outgoing-to-incoming transfer,
            // never an incoming-to-incoming takeover or a confirmed exchange.
            if outgoing.is_some()
                || identity.node_addr() != &attempt.peer
                || self.is_configured_peer_identity(identity)
                || !conn.is_outbound()
                || conn.has_session()
                || conn.handshake_state() != crate::peer::HandshakeState::SentMsg1
            {
                return None;
            }
            outgoing = Some(*link);
        }
        let outgoing = outgoing?;
        self.rotation_victim(now_ms).map(|_| outgoing)
    }

    /// Called after Noise identity and the inbound ACL have been checked.
    pub(in crate::node) async fn begin_inbound_neighbor_rotation(
        &mut self,
        peer: NodeAddr,
        transport: TransportId,
        remote: &TransportAddr,
    ) -> bool {
        let now_ms = Self::now_ms();
        let Some(outgoing) = self.unanswered_rotation_for_transfer(&peer, now_ms) else {
            return self.begin_neighbor_rotation(peer, false, now_ms);
        };
        // Keep the old attempt and native resources owned while physical close
        // can yield. Cancellation leaves an ordinary retryable outgoing attempt.
        self.retire_connection_candidate(outgoing, Some((transport, remote.clone())))
            .await;
        let now_ms = Self::now_ms();
        if self.rotation_new_peer_rejection(&peer, now_ms).is_some()
            || !self
                .neighbor_rotation
                .attempt
                .as_ref()
                .is_some_and(|attempt| self.rotation_attempt_is_fresh(attempt, now_ms))
            || self.rotation_victim(now_ms).is_none()
        {
            return false;
        }
        let interval_ms = self
            .config
            .node
            .neighbor_rotation
            .as_ref()
            .unwrap()
            .interval_secs
            .saturating_mul(1000);
        let attempt = self.neighbor_rotation.attempt.as_mut().unwrap();
        let previous = attempt.peer;
        attempt.peer = peer;
        // Preserve the original deadline and local discovery cursor. The new
        // identity still consumes the configured minimum attempt interval.
        self.neighbor_rotation.next_attempt_ms = self
            .neighbor_rotation
            .next_attempt_ms
            .max(now_ms.saturating_add(interval_ms));
        tracing::debug!(
            node = %self.node_addr(),
            previous_peer = %previous,
            candidate = %peer,
            "Transferred unanswered neighbor attempt to authenticated incoming request"
        );
        true
    }

    pub(in crate::node) fn neighbor_rotation_started_at(&self, peer: &NodeAddr) -> Option<u64> {
        self.neighbor_rotation_awaits_confirmation(peer)
            .then(|| self.neighbor_rotation.attempt.as_ref().unwrap().started_ms)
    }
}
