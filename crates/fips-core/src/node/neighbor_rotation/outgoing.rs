use super::*;
use crate::transport::ReceivedPacket;

impl Node {
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
