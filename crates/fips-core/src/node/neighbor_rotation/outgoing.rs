use super::*;
use crate::transport::ReceivedPacket;

impl Node {
    /// A crossed Msg1 may be the first indication that the other side is ready.
    /// Answer on the owned outbound carrier, never the replay's source address.
    pub(in crate::node) async fn resend_crossed_rotation_request(&mut self, peer: &NodeAddr) {
        let now = Self::now_ms();
        let node_addr = *self.node_addr();
        let deadline = self.neighbor_rotation_deadline(peer);
        if !crate::peer::cross_connection_winner(self.node_addr(), peer, true)
            || deadline.is_none_or(|deadline| now >= deadline)
        {
            return;
        }
        let Some(link) = self.peers.connection_iter().find_map(|(link, conn)| {
            (conn.is_outbound()
                && conn
                    .expected_identity()
                    .is_some_and(|id| id.node_addr() == peer))
            .then_some(*link)
        }) else {
            return;
        };
        let policy = &self.config.node.rate_limit;
        let conn = self.peers.get_connection_mut(&link).unwrap();
        if conn.is_timed_out(now, policy.handshake_timeout_secs.saturating_mul(1000)) {
            return;
        }
        let Some((transport_id, remote)) = conn.transport_id().zip(conn.source_addr().cloned())
        else {
            return;
        };
        let delay = policy.handshake_resend_interval_ms as f64
            * policy
                .handshake_resend_backoff
                .powi(conn.resend_count().saturating_add(1) as i32);
        let mut next_due = now.saturating_add(delay as u64);
        // An early response must not postpone an already-scheduled opportunity.
        if conn.next_resend_at_ms() > now {
            next_due = next_due.min(conn.next_resend_at_ms());
        }
        // Consume the allowance before I/O; cancellation and send errors cannot
        // enable another immediate reply or extend the original attempt.
        let Some(wire) = conn
            .reserve_crossed_msg1_resend(policy.handshake_max_resends, next_due)
            .map(<[u8]>::to_vec)
        else {
            return;
        };
        tracing::debug!(
            node = %node_addr, peer = %peer, %link, sender_index = ?conn.our_index(),
            resend = conn.resend_count(), deadline_ms = ?deadline, reserved_ms = now,
            "Reserved crossed handshake request resend"
        );
        if let Some(transport) = self.transports.get(&transport_id) {
            match transport.send(&remote, &wire).await {
                Ok(bytes) => tracing::debug!(
                    node = %node_addr, peer = %peer, %link, bytes,
                    "Sent crossed handshake request resend"
                ),
                Err(error) => tracing::debug!(
                    node = %node_addr, peer = %peer, %link, %error,
                    "Crossed handshake request resend failed"
                ),
            }
        }
    }

    pub(in crate::node) async fn retain_outbound_neighbor_response(
        &mut self,
        link: LinkId,
        peer: &NodeAddr,
        packet: &ReceivedPacket,
    ) -> bool {
        if self.peers.contains_key(peer) {
            return false;
        }
        let Some(conn) = self.peers.get_connection(&link) else {
            return false;
        };
        let retained = conn.completed_handshake_response().is_some();
        if !retained && !self.neighbor_rotation_awaits_confirmation(peer) {
            return false;
        }
        let now = Self::now_ms();
        let ready = !self.neighbor_roster_full()
            || (self.rotation_replacement_ready(peer, now) && self.rotation_victim(now).is_some());
        let started_ms = self
            .neighbor_rotation
            .attempt
            .as_ref()
            .filter(|attempt| attempt.peer == *peer)
            .map_or(conn.started_at(), |attempt| attempt.started_ms);
        let our_index = conn.our_index().unwrap();
        let confirmed = conn.handshake_confirmation().is_some();
        let conn = self.peers.get_connection_mut(&link).unwrap();
        conn.retain_completed_handshake_response(packet, started_ms);
        if !retained {
            conn.start_confirmation_retries(now);
        }
        // The authenticated reply binds the receive carrier, including a UDP
        // reply accepted on a different local listener from the original dial.
        self.dataplane.register_fmp_handshake_candidate(
            packet.transport_id,
            &packet.remote_addr,
            our_index.as_u32(),
        );
        if ready && !confirmed {
            self.send_prepared_neighbor_confirmation(link).await;
        }
        !ready || !confirmed
    }

    async fn send_prepared_neighbor_confirmation(&mut self, link: LinkId) {
        let now = Self::now_ms();
        let policy = &self.config.node.rate_limit;
        let Some(conn) = self.peers.get_connection_mut(&link) else {
            return;
        };
        if now < conn.next_resend_at_ms() || conn.resend_count() > policy.handshake_max_resends {
            return;
        }
        let Some(reply) = conn.completed_handshake_response() else {
            return;
        };
        let transport_id = reply.transport_id;
        let remote = reply.remote_addr.clone();
        let wire = match conn.prepare_ready_heartbeat() {
            Ok(wire) => wire.to_vec(),
            Err(error) => {
                tracing::debug!(%link, %error, "Could not prepare neighbor readiness heartbeat");
                return;
            }
        };
        let delay = policy.handshake_resend_interval_ms as f64
            * policy
                .handshake_resend_backoff
                .powi(conn.resend_count() as i32);
        // Scheduling precedes I/O: cancellation cannot create an unbounded
        // retry loop, renew the attempt, or allocate another encryption nonce.
        conn.record_resend(now.saturating_add(delay as u64));
        if let Some(transport) = self.transports.get(&transport_id) {
            match transport.send(&remote, &wire).await {
                Ok(bytes) => {
                    if let Some(conn) = self.peers.get_connection_mut(&link) {
                        conn.record_ready_heartbeat_sent(bytes);
                    }
                }
                Err(error) => tracing::debug!(%link, %error, "Neighbor readiness send failed"),
            }
        }
    }

    pub(in crate::node) async fn retry_prepared_outbound_neighbors(&mut self) {
        // Keep each authoritative reply on its exact connection across awaits.
        // Ordinary promotion/retirement consumes it with that connection, even
        // when a crossed incoming promotion has already cleared the attempt.
        let replies: Vec<_> = self
            .peers
            .connection_iter()
            .filter_map(|(link, conn)| {
                conn.completed_handshake_response()
                    .map(|reply| (*link, reply.clone()))
            })
            .collect();
        for (link, reply) in replies {
            self.finish_completed_outbound_handshake(link, reply).await;
        }
    }
}
