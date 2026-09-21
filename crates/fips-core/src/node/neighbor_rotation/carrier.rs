use super::*;
use crate::PeerIdentity;

impl Node {
    pub(in crate::node) fn choose_neighbor_rotation_promotion(
        &self,
        link: LinkId,
        identity: &PeerIdentity,
    ) -> Option<PreparedNeighborRotation> {
        let candidate = self.peers.get_connection(&link)?;
        if !candidate.has_session()
            || candidate.expected_identity() != Some(identity)
            || self.peers.contains_key(identity.node_addr())
            || candidate.our_index().is_none()
            || candidate.their_index().is_none()
            || candidate.transport_id().is_none()
            || candidate.source_addr().is_none()
        {
            return None;
        }
        let decided_ms = Self::now_ms();
        let victim = self.rotation_promotion_victim(
            identity.node_addr(),
            link,
            candidate.is_outbound(),
            decided_ms,
        )?;
        let old = self.peers.get(&victim)?;
        Some(PreparedNeighborRotation {
            candidate: *identity.node_addr(),
            candidate_link: link,
            victim,
            victim_link: old.link_id(),
            victim_index: old.our_index(),
            victim_generation: old.session_generation(),
            decided_ms,
        })
    }

    /// Close an unshared incumbent carrier before releasing its native slot.
    ///
    /// The actor still owns the old peer/link/index while this awaits the
    /// transport pool. Cancellation therefore cannot orphan a physical carrier
    /// after its native accounting has disappeared. The returned admission
    /// decision must be consumed by synchronous promotion without another await.
    pub(in crate::node) async fn prepare_neighbor_rotation_promotion(
        &mut self,
        link: LinkId,
        identity: &PeerIdentity,
    ) -> Option<PreparedNeighborRotation> {
        let prepared = self.choose_neighbor_rotation_promotion(link, identity)?;
        let Some((transport_id, address)) = self
            .peers
            .get(&prepared.victim)
            .and_then(|peer| peer.transport_id().zip(peer.current_addr().cloned()))
        else {
            return Some(prepared);
        };
        if self.links.values().any(|owner| {
            owner.link_id() != prepared.victim_link
                && owner.transport_id() == transport_id
                && owner.remote_addr() == &address
        }) || self.peers.values().any(|peer| {
            peer.node_addr() != &prepared.victim
                && peer.transport_id() == Some(transport_id)
                && peer.current_addr() == Some(&address)
        }) || self.peers.connection_values().any(|pending| {
            pending.transport_id() == Some(transport_id) && pending.source_addr() == Some(&address)
        }) || self
            .pending_connects
            .iter()
            .any(|pending| pending.transport_id == transport_id && pending.remote_addr == address)
        {
            return Some(prepared);
        }
        if let Some(transport) = self.transports.get(&transport_id) {
            // These close methods await only the pool lock, then remove the
            // carrier without another yield. WebSocket/WebRTC use the existing
            // cleanup owned by remove_active_peer; their close can yield after
            // removal and must not interrupt this prepared promotion.
            match transport {
                crate::transport::TransportHandle::Tcp(t) => {
                    t.close_connection_async(&address).await
                }
                crate::transport::TransportHandle::Tor(t) => {
                    t.close_connection_async(&address).await
                }
                #[cfg(any(target_os = "linux", feature = "host-ble-transport", test))]
                crate::transport::TransportHandle::Ble(t) => {
                    t.close_connection_async(&address).await
                }
                _ => {}
            }
        }
        Some(prepared)
    }
}
