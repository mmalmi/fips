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
        let idle_ms = self
            .config
            .node
            .neighbor_rotation
            .as_ref()?
            .idle_secs
            .saturating_mul(1000);
        // Leave room for a remote roster to age, while reserving half the
        // original attempt timeout for a possible incoming exchange.
        let incoming_turn_ms = attempt
            .started_ms
            .saturating_add(attempt.deadline_ms.saturating_sub(attempt.started_ms) / 2);
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
                || now_ms
                    < conn
                        .started_at()
                        .saturating_add(idle_ms)
                        .min(incoming_turn_ms)
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
        replacing: Option<LinkId>,
    ) -> bool {
        let now_ms = Self::now_ms();
        if let Some(link) = replacing {
            // Decide while the old candidate still owns its index and deadline.
            // A same-path restart continues that attempt without a new cooldown.
            return self.peers.get_connection(&link).is_some_and(|conn| {
                !conn.is_outbound()
                    && conn.has_session()
                    && conn.transport_id() == Some(transport)
                    && conn.source_addr() == Some(remote)
                    && conn
                        .expected_identity()
                        .is_some_and(|identity| *identity.node_addr() == peer)
            }) && self
                .neighbor_rotation_rejection(&peer, false, now_ms, Some(link))
                .is_none();
        }
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
        // Only the original outgoing attempt earns one retry. A transferred
        // retry is consumed, even if its new incoming owner later succeeds.
        self.neighbor_rotation.interrupted_outgoing =
            (!attempt.is_retry).then_some(InterruptedOutgoing {
                peer: previous,
                started_ms: attempt.started_ms,
                deadline_ms: attempt.deadline_ms,
            });
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

    pub(in crate::node) fn neighbor_rotation_response_ready(
        &self,
        link: LinkId,
        now_ms: u64,
    ) -> bool {
        let Some(peer) = self
            .peers
            .get_connection(&link)
            .and_then(|conn| conn.expected_identity())
        else {
            return false;
        };
        // Promotion into a slot freed by a disconnect can leave exploration
        // bookkeeping behind. It must not gate ordinary peer maintenance.
        if !self.neighbor_roster_full() || self.peers.contains_key(peer.node_addr()) {
            return true;
        }
        let Some(attempt) = self
            .neighbor_rotation
            .attempt
            .as_ref()
            .filter(|attempt| &attempt.peer == peer.node_addr())
        else {
            return true;
        };
        if !self.rotation_attempt_is_fresh(attempt, now_ms) {
            return false;
        }
        // Msg2 acknowledges bounded handshake ownership, not a ready route.
        // Fresh encrypted proof and current eligibility still gate promotion.
        self.config.node.neighbor_rotation.is_some()
    }

    /// Release only the retained response owned by the current attempt. A
    /// successful advertisement returns to ordinary duplicate-Msg1 handling.
    pub(in crate::node) async fn resend_prepared_neighbor_response(&mut self, now_ms: u64) {
        let Some(attempt) = &self.neighbor_rotation.attempt else {
            return;
        };
        let link = self.peers.connection_iter().find_map(|(link, conn)| {
            (!conn.is_outbound()
                && conn.has_session()
                && conn
                    .expected_identity()
                    .is_some_and(|id| id.node_addr() == &attempt.peer)
                && conn.next_resend_at_ms() > 0
                && now_ms >= conn.next_resend_at_ms())
            .then_some(*link)
        });
        if let Some(link) = link {
            self.send_retained_handshake_response(link).await;
        }
    }

    pub(in crate::node) async fn retry_prepared_inbound_neighbors(&mut self) {
        // The exact connection owns the first frame across cancellation. The
        // normal confirmation path rechecks its source, keys, epoch, deadline,
        // ACL and current admission before replaying it through the dataplane.
        let proofs: Vec<_> = self
            .peers
            .connection_values()
            .filter(|conn| !conn.is_outbound())
            .filter_map(|conn| conn.handshake_confirmation().cloned())
            .collect();
        for proof in proofs {
            self.confirm_pending_handshake(proof).await;
        }
    }
}
