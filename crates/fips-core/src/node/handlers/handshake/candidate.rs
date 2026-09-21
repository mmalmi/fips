use super::*;
use crate::dataplane::FmpWireHeader;
use crate::transport::{TransportAddr, TransportId};

impl Node {
    /// Advertise a bounded incoming handshake reservation without activating it.
    /// Failed advertisements use the existing retry budget without renewing
    /// the candidate's original timeout; successful ones need only duplicate
    /// Msg1 handling, as before.
    pub(in crate::node) async fn send_retained_handshake_response(&mut self, link: LinkId) {
        let now = Self::now_ms();
        let Some(conn) = self.peers.get_connection(&link) else {
            return;
        };
        let scheduled = conn.next_resend_at_ms();
        if conn.is_outbound()
            || !conn.has_session()
            || conn.is_timed_out(
                now,
                self.config
                    .node
                    .rate_limit
                    .handshake_timeout_secs
                    .saturating_mul(1000),
            )
            || (scheduled > 0
                && (now < scheduled
                    || conn.resend_count() > self.config.node.rate_limit.handshake_max_resends))
            || !self.neighbor_rotation_response_ready(link, now)
        {
            return;
        }
        let Some((identity, transport_id, remote)) = conn
            .expected_identity()
            .copied()
            .zip(conn.transport_id())
            .zip(conn.source_addr().cloned())
            .map(|((identity, transport), remote)| (identity, transport, remote))
        else {
            return;
        };
        let Some(response) = self.find_stored_msg2(link) else {
            return;
        };
        if self
            .authorize_peer(
                &identity,
                PeerAclContext::InboundHandshake,
                transport_id,
                &remote,
            )
            .is_err()
        {
            self.cleanup_stale_connection(link, now).await;
            return;
        }
        let sent = if let Some(transport) = self.transports.get(&transport_id) {
            match transport.send(&remote, &response).await {
                Ok(_) => true,
                Err(error) => {
                    debug!(%link, %error, "Candidate Msg2 send failed; retaining for retry");
                    false
                }
            }
        } else {
            false
        };
        if scheduled > 0
            && let Some(conn) = self.peers.get_connection_mut(&link)
        {
            if sent {
                conn.schedule_handshake_resend(0);
            } else {
                let policy = &self.config.node.rate_limit;
                let delay = policy.handshake_resend_interval_ms as f64
                    * policy
                        .handshake_resend_backoff
                        .powi(conn.resend_count() as i32);
                conn.record_resend(Self::now_ms().saturating_add(delay as u64));
            }
        }
    }

    /// The crossed-dial allowance has room for only one inbound half.
    /// Requests from other source addresses cannot multiply that allowance.
    pub(super) fn has_unpaired_outbound_handshake(&self, peer: &NodeAddr) -> bool {
        let mut outbound = false;
        for conn in self.peers.connection_values().filter(|conn| {
            conn.expected_identity()
                .is_some_and(|identity| identity.node_addr() == peer)
        }) {
            if !conn.is_outbound() {
                return false;
            }
            outbound = true;
        }
        outbound
    }

    pub(in crate::node) fn active_link_for_carrier(
        &self,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) -> Option<LinkId> {
        self.peers
            .values()
            .find(|peer| {
                peer.transport_id() == Some(transport_id)
                    && peer.current_addr() == Some(remote_addr)
            })
            .map(|peer| peer.link_id())
    }

    pub(super) async fn close_unowned_handshake_carrier(
        &self,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) {
        if self.handshake_carrier_is_owned(transport_id, remote_addr) {
            return;
        }
        if let Some(transport) = self.transports.get(&transport_id) {
            transport.close_connection(remote_addr).await;
        }
    }

    pub(in crate::node) fn handshake_carrier_is_owned(
        &self,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) -> bool {
        self.links
            .values()
            .any(|link| link.transport_id() == transport_id && link.remote_addr() == remote_addr)
            || self
                .active_link_for_carrier(transport_id, remote_addr)
                .is_some()
            || self.peers.connection_values().any(|conn| {
                conn.transport_id() == Some(transport_id) && conn.source_addr() == Some(remote_addr)
            })
            || self.pending_connects.iter().any(|pending| {
                pending.transport_id == transport_id && &pending.remote_addr == remote_addr
            })
    }

    pub(super) async fn cleanup_failed_promotion(&mut self, link_id: LinkId) {
        if let Some(link) = self.remove_link(&link_id) {
            let transport_id = link.transport_id();
            if let Some(winner) = self.active_link_for_carrier(transport_id, link.remote_addr()) {
                self.restore_link_address(winner);
            }
            self.close_unowned_handshake_carrier(transport_id, link.remote_addr())
                .await;
            self.cleanup_bootstrap_transport_if_unused(transport_id);
        }
    }

    pub(in crate::node) fn unregister_handshake_candidate(&mut self, link_id: LinkId) {
        if let Some(conn) = self.peers.get_connection(&link_id)
            && let (Some(tid), Some(addr), Some(index)) =
                (conn.transport_id(), conn.source_addr(), conn.our_index())
        {
            self.dataplane
                .remove_fmp_handshake_candidate(tid, addr, index.as_u32());
            if let Some(reply) = conn.completed_handshake_response() {
                self.dataplane.remove_fmp_handshake_candidate(
                    reply.transport_id,
                    &reply.remote_addr,
                    index.as_u32(),
                );
            }
        }
    }

    pub(in crate::node) async fn confirm_pending_handshake(
        &mut self,
        packet: ReceivedPacket,
    ) -> bool {
        if self.packet_predates_carrier_rebind(packet.transport_id, packet.timestamp_ms) {
            return false;
        }
        let Ok(header) = FmpWireHeader::parse_encrypted(packet.data.as_slice()) else {
            return false;
        };
        // PacketRx snapshots candidates for a whole batch. Once its first
        // frame promotes the path, later diverted frames belong to the normal
        // owner and still need ordinary admission and delivery.
        if self.peers.values().any(|peer| {
            peer.transport_id() == Some(packet.transport_id)
                && peer.current_addr() == Some(&packet.remote_addr)
                && peer.our_index().map(|index| index.as_u32()) == Some(header.receiver_idx())
        }) {
            self.dataplane.defer_fmp_handshake_proof(packet);
            return true;
        }
        // A simultaneous outbound completion can own the carrier's reverse
        // address slot while this inbound receiver index still awaits proof.
        let Some((link_id, conn)) = self.peers.connection_iter().find(|(_, conn)| {
            conn.has_session()
                && (if conn.is_outbound() {
                    conn.completed_handshake_response()
                        .map(|reply| reply.transport_id)
                } else {
                    conn.transport_id()
                }) == Some(packet.transport_id)
                && conn.source_addr() == Some(&packet.remote_addr)
                && conn.our_index().map(|index| index.as_u32()) == Some(header.receiver_idx())
        }) else {
            return false;
        };
        let link_id = *link_id;
        if conn.is_timed_out(
            Self::now_ms(),
            self.config.node.rate_limit.handshake_timeout_secs * 1000,
        ) {
            return false;
        }
        let Some(identity) = conn.expected_identity().copied() else {
            return false;
        };
        let outbound = conn.is_outbound();
        if self
            .peers
            .get(identity.node_addr())
            .is_some_and(|peer| peer.remote_epoch() != conn.remote_epoch())
            || conn.handshake_confirmation().is_some_and(|first| {
                self.packet_predates_carrier_rebind(first.transport_id, first.timestamp_ms)
            })
        {
            self.cleanup_stale_connection(link_id, Self::now_ms()).await;
            return false;
        }
        let offset = usize::from(header.ciphertext_offset());
        let frame = packet.data.as_slice();
        if !conn.session().is_some_and(|session| {
            session
                .authenticate_with_counter_and_aad(
                    &frame[offset..],
                    header.counter(),
                    &frame[..offset],
                )
                .is_ok()
        }) {
            return false;
        }
        if self
            .authorize_peer(
                &identity,
                if outbound {
                    PeerAclContext::OutboundHandshake
                } else {
                    PeerAclContext::InboundHandshake
                },
                packet.transport_id,
                &packet.remote_addr,
            )
            .is_err()
        {
            self.cleanup_stale_connection(link_id, Self::now_ms()).await;
            return false;
        }
        if !outbound {
            self.confirm_neighbor_rotation_candidate(identity.node_addr(), link_id);
        }
        // Fresh demand can arrive after Msg2 was advertised. Keep the first
        // authenticated frame and original connection deadline until promotion
        // is safe; consuming the connection here would throw away valid proof.
        self.peers
            .get_connection_mut(&link_id)
            .unwrap()
            .retain_handshake_confirmation(&packet);
        if outbound {
            let first = self
                .peers
                .get_connection(&link_id)
                .unwrap()
                .handshake_confirmation()
                .unwrap();
            let duplicate = first.data.as_slice() == packet.data.as_slice();
            let reply = self
                .peers
                .get_connection(&link_id)
                .unwrap()
                .completed_handshake_response()
                .unwrap()
                .clone();
            self.finish_completed_outbound_handshake(link_id, reply)
                .await;
            if !duplicate
                && self.peers.get(identity.node_addr()).is_some_and(|peer| {
                    peer.link_id() == link_id
                        && peer.our_index().map(|index| index.as_u32())
                            == Some(header.receiver_idx())
                })
            {
                self.dataplane.defer_fmp_handshake_proof(packet);
            }
            return true;
        }
        if self.neighbor_rotation_awaits_confirmation(identity.node_addr())
            && self
                .choose_neighbor_rotation_promotion(link_id, &identity)
                .is_none()
        {
            return true;
        }
        let first = self
            .peers
            .get_connection(&link_id)
            .unwrap()
            .handshake_confirmation()
            .unwrap()
            .clone();
        let duplicate = first.data.as_slice() == packet.data.as_slice();
        if self
            .finish_inbound_handshake(link_id, identity, &first, true)
            .await
            .is_none()
        {
            return false;
        }
        if !duplicate {
            self.dataplane.defer_fmp_handshake_proof(packet);
        }
        true
    }
    pub(super) async fn finish_inbound_handshake(
        &mut self,
        link_id: LinkId,
        peer_identity: PeerIdentity,
        packet: &ReceivedPacket,
        confirmed: bool,
    ) -> Option<NodeAddr> {
        let connection = self.peers.get_connection(&link_id)?;
        let our_index = connection.our_index()?;
        let their_index = connection.their_index()?;
        let wire_msg2 = connection.handshake_msg2()?.to_vec();
        let confirmation = connection.handshake_confirmation().cloned();
        let admitted_at_ms = if connection.handshake_confirmation().is_some() {
            Self::now_ms()
        } else {
            packet.timestamp_ms
        };
        // Responder handshake is complete after receive_handshake_init (Noise IK
        // pattern: responder processes msg1 and generates msg2 in one step).
        // Promote first so a winning receiver index is owned and routed before
        // the peer can answer Msg2 with an Established frame. Losing inbound
        // candidates must never advertise their already-freed index.
        let rotation = self
            .prepare_neighbor_rotation_promotion(link_id, &peer_identity)
            .await;
        let (node_addr, loser_link_id) = match self.promote_connection_with_rotation(
            link_id,
            peer_identity,
            admitted_at_ms,
            rotation,
        ) {
            Ok(PromotionResult::Promoted(node_addr)) => (node_addr, None),
            Ok(PromotionResult::CrossConnectionWon {
                loser_link_id,
                node_addr,
            }) => (node_addr, Some(loser_link_id)),
            Ok(PromotionResult::CrossConnectionLost { winner_link_id }) => {
                self.close_cross_connection_loser_physical_path(link_id, Some(winner_link_id))
                    .await;
                self.cleanup_failed_promotion(link_id).await;
                self.links.insert_addr(
                    (packet.transport_id, packet.remote_addr.clone()),
                    winner_link_id,
                );
                debug!(
                    winner_link_id = %winner_link_id,
                    "Inbound cross-connection lost without advertising its receiver index"
                );
                return None;
            }
            Err(e) => {
                warn!(
                    link_id = %link_id,
                    error = %e,
                    "Failed to promote inbound connection"
                );
                // Clean up on promotion failure
                self.cleanup_failed_promotion(link_id).await;
                let _ = self.index_allocator.free(our_index);
                return None;
            }
        };

        // Retain Msg2 before sending so duplicate Msg1 can safely retry.
        // Timestamp generation, not queued arrival: an outbound dial may have
        // started while Msg1 waited for processing.
        if let Some(peer) = self.peers.get_mut(&node_addr) {
            peer.set_handshake_msg2(wire_msg2.clone(), Self::now_ms());
        }

        let receiver_route_owned = self.ensure_owned_msg2_receiver_route(&node_addr);
        if receiver_route_owned && let Some(proof) = confirmation {
            // Promotion consumed the pending owner. Transfer its first frame
            // before any cleanup/bootstrap await can cancel this operation.
            self.dataplane.defer_fmp_handshake_proof(proof);
        }
        let msg2_sent = if !receiver_route_owned {
            warn!(
                peer = %self.peer_display_name(&node_addr),
                our_index = %our_index,
                "Suppressing Msg2 because its receiver route is not owned"
            );
            false
        } else if confirmed {
            true
        } else {
            match self.transports.get(&packet.transport_id) {
                Some(transport) => match transport.send(&packet.remote_addr, &wire_msg2).await {
                    Ok(bytes) => {
                        debug!(
                            link_id = %link_id,
                            our_index = %our_index,
                            their_index = %their_index,
                            bytes,
                            "Sent msg2 response after installing receiver route"
                        );
                        true
                    }
                    Err(e) => {
                        warn!(
                            link_id = %link_id,
                            error = %e,
                            "Failed to send owned msg2; retaining it for duplicate-msg1 retry"
                        );
                        false
                    }
                },
                None => {
                    warn!(
                        link_id = %link_id,
                        "Msg2 transport disappeared; retaining owned response for retry"
                    );
                    false
                }
            }
        };

        if let Some(loser_link_id) = loser_link_id {
            self.close_cross_connection_loser_physical_path(loser_link_id, Some(link_id))
                .await;
            if let Some(loser_link) = self.remove_link(&loser_link_id) {
                self.cleanup_bootstrap_transport_if_unused(loser_link.transport_id());
            }
            debug!(
                peer = %self.peer_display_name(&node_addr),
                loser_link_id = %loser_link_id,
                "Inbound cross-connection won, loser link cleaned up"
            );
        } else {
            debug!(
                peer = %self.peer_display_name(&node_addr),
                link_id = %link_id,
                our_index = %our_index,
                "Inbound peer promoted before Msg2 advertisement"
            );
        }

        self.restore_link_address(link_id);
        if msg2_sent {
            Box::pin(self.complete_owned_msg2_bootstrap(&node_addr)).await;
        }

        self.retry_degraded_session_routes_after_peer_authenticated(node_addr, admitted_at_ms)
            .await;
        receiver_route_owned.then_some(node_addr)
    }
}
