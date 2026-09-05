use super::*;
use crate::dataplane::FmpWireHeader;
use crate::transport::{TransportAddr, TransportId};

impl Node {
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
        if self
            .active_link_for_carrier(transport_id, remote_addr)
            .is_none()
            && let Some(transport) = self.transports.get(&transport_id)
        {
            transport.close_connection(remote_addr).await;
        }
    }

    pub(in crate::node) fn unregister_handshake_candidate(&mut self, link_id: LinkId) {
        if let Some(conn) = self.peers.get_connection(&link_id)
            && let (Some(tid), Some(addr), Some(index)) =
                (conn.transport_id(), conn.source_addr(), conn.our_index())
        {
            self.dataplane
                .remove_fmp_handshake_candidate(tid, addr, index.as_u32());
        }
    }

    pub(in crate::node) async fn confirm_inbound_handshake(
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
            !conn.is_outbound()
                && conn.has_session()
                && conn.transport_id() == Some(packet.transport_id)
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
        if self
            .peers
            .get(identity.node_addr())
            .is_some_and(|peer| peer.remote_epoch() != conn.remote_epoch())
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
                PeerAclContext::InboundHandshake,
                packet.transport_id,
                &packet.remote_addr,
            )
            .is_err()
        {
            self.cleanup_stale_connection(link_id, Self::now_ms()).await;
            return false;
        }
        if self
            .finish_inbound_handshake(link_id, identity, &packet, true)
            .await
            .is_none()
        {
            return false;
        }
        self.dataplane.defer_fmp_handshake_proof(packet);
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
        self.unregister_handshake_candidate(link_id);
        // Responder handshake is complete after receive_handshake_init (Noise IK
        // pattern: responder processes msg1 and generates msg2 in one step).
        // Promote first so a winning receiver index is owned and routed before
        // the peer can answer Msg2 with an Established frame. Losing inbound
        // candidates must never advertise their already-freed index.
        let (node_addr, loser_link_id) =
            match self.promote_connection(link_id, peer_identity, packet.timestamp_ms) {
                Ok(PromotionResult::Promoted(node_addr)) => (node_addr, None),
                Ok(PromotionResult::CrossConnectionWon {
                    loser_link_id,
                    node_addr,
                }) => (node_addr, Some(loser_link_id)),
                Ok(PromotionResult::CrossConnectionLost { winner_link_id }) => {
                    self.close_cross_connection_loser_physical_path(link_id, Some(winner_link_id))
                        .await;
                    if let Some(link) = self.remove_link(&link_id) {
                        self.cleanup_bootstrap_transport_if_unused(link.transport_id());
                    }
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
                    if let Some(link) = self.remove_link(&link_id) {
                        self.cleanup_bootstrap_transport_if_unused(link.transport_id());
                    }
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

        self.retry_degraded_session_routes_after_peer_authenticated(node_addr, packet.timestamp_ms)
            .await;
        receiver_route_owned.then_some(node_addr)
    }
}
