//! Local application demand used only by optional peer replacement.

use super::*;

impl Node {
    /// Traffic that already uses this adjacent peer protects it from optional
    /// replacement. Link maintenance and an idle end-to-end session do not.
    pub(in crate::node) fn peer_has_application_demand(
        &self,
        peer: &NodeAddr,
        now_ms: u64,
        idle_ms: u64,
    ) -> bool {
        let Some(active) = self.peers.get(peer) else {
            return false;
        };
        active.has_recent_transit_demand(now_ms, idle_ms)
            || self.deferred_session_forwards.has_demand_for(peer)
            || self
                .dataplane
                .min_fsp_data_rx_age_for_next_hop(peer, now_ms)
                .is_some_and(|age| age <= idle_ms)
            || self
                .dataplane
                .fsp_owner_destinations()
                .into_iter()
                .any(|dest| {
                    self.dataplane
                        .fsp_owner_activity(&dest)
                        .is_some_and(|activity| {
                            activity.last_outbound_next_hop() == Some(*peer)
                                && activity.has_recent_outbound_activity(now_ms, idle_ms)
                        })
                })
            || self.pending_session_traffic.destinations().any(|dest| {
                // Attribute queued application traffic to an existing explicit
                // or installed carrier. An unresolved lookup does not pin every
                // neighbor, which would prevent discovery of its missing route.
                self.source_routes
                    .get(&dest)
                    .copied()
                    .or_else(|| self.dataplane.fsp_owner_next_hop(&dest))
                    .or_else(|| self.peers.contains_key(&dest).then_some(dest))
                    == Some(*peer)
            })
    }

    pub(in crate::node) fn record_peer_transit_demand(&mut self, peer: &NodeAddr, now_ms: u64) {
        if let Some(active) = self.peers.get_mut(peer) {
            active.record_transit_demand(now_ms);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataplane::{
        ActivityTick, DataplaneAuthenticatedFspSession, DataplaneFspWrapRoute,
        DataplaneLiveOutboundFirsts, DataplaneLiveOwnerRoutes, FspReceiveSync, OutboundPacket,
        OwnerConfig, OwnerId, PacketClass,
    };
    use crate::peer::ActivePeer;
    use crate::protocol::SessionMessageType;
    use crate::transport::{LinkId, PacketBuffer};
    use std::time::Instant;

    fn add_peer(node: &mut Node, link: u64) -> NodeAddr {
        let identity = Identity::generate();
        let peer = PeerIdentity::from_pubkey_full(identity.pubkey_full());
        let addr = *peer.node_addr();
        node.peers
            .insert(addr, ActivePeer::new(peer, LinkId::new(link), 1));
        addr
    }

    fn receive(
        node: &mut Node,
        dest: NodeAddr,
        carrier: NodeAddr,
        ty: SessionMessageType,
        at: u64,
    ) {
        assert!(
            node.dataplane
                .record_authenticated_fsp_session(DataplaneAuthenticatedFspSession::new(
                    dest,
                    carrier,
                    ty.to_byte(),
                    8,
                    FspReceiveSync {
                        counter: at,
                        received_k_bit: false,
                        timestamp: 0,
                        plaintext_len: 32,
                        ce_flag: false,
                        path_mtu: u16::MAX,
                        spin_bit: false,
                    },
                    Some(ActivityTick::new(at)),
                    Instant::now(),
                ),)
                .is_some()
        );
    }

    async fn send(
        node: &mut Node,
        dest: NodeAddr,
        carrier: NodeAddr,
        ty: SessionMessageType,
        at: u64,
    ) {
        let owner = OwnerId::fsp_node(dest);
        node.dataplane
            .replace_owner_fsp_routes(
                owner,
                DataplaneLiveOwnerRoutes::default(),
                Some(DataplaneFspWrapRoute::new(
                    OwnerId::fmp_node(carrier),
                    1,
                    2,
                    *node.node_addr(),
                    dest,
                )),
                None,
            )
            .unwrap();
        let packet = OutboundPacket::fsp(
            owner,
            1,
            PacketClass::Bulk,
            0,
            PacketBuffer::new(vec![1; 8]),
        )
        .with_fsp_inner_header(ty.to_byte(), 0)
        .with_activity_tick(ActivityTick::new(at));
        // Exercise normal outbound admission/reservation. No transport or keys
        // are installed: a later local send failure must retain admitted demand.
        node.pump_dataplane_pending_outbound_firsts(
            DataplaneLiveOutboundFirsts {
                initial_outbound: Some(packet),
                ..Default::default()
            },
            0,
            0,
            8,
        )
        .await;
    }

    #[tokio::test]
    async fn local_data_protects_actual_rx_and_tx_carriers_without_control_refresh() {
        let mut node = Node::new(Config::new()).unwrap();
        let direct = add_peer(&mut node, 1);
        let routed = add_peer(&mut node, 2);
        node.dataplane
            .register_owner(OwnerId::fsp_node(direct), OwnerConfig::new(1, 8));
        node.peers.get_mut(&direct).unwrap().touch(100);
        node.peers
            .get_mut(&direct)
            .unwrap()
            .mark_heartbeat_sent(Instant::now());
        receive(
            &mut node,
            direct,
            direct,
            SessionMessageType::SenderReport,
            100,
        );
        assert!(!node.peer_has_application_demand(&direct, 100, 20));
        assert!(!node.peer_has_application_demand(&routed, 100, 20));

        send(
            &mut node,
            direct,
            routed,
            SessionMessageType::SenderReport,
            100,
        )
        .await;
        assert!(!node.peer_has_application_demand(&routed, 100, 20));
        send(
            &mut node,
            direct,
            routed,
            SessionMessageType::EndpointData,
            100,
        )
        .await;
        assert_eq!(
            node.dataplane
                .fsp_owner_activity(&direct)
                .unwrap()
                .traffic_counters()
                .0,
            1
        );
        assert!(node.peer_has_application_demand(&routed, 120, 20));
        assert!(!node.peer_has_application_demand(&direct, 120, 20));
        assert_eq!(
            node.dataplane
                .min_fsp_data_rx_age_for_next_hop(&routed, 120),
            None,
            "TX protection must not change the RX-only liveness query"
        );
        assert!(!node.peer_has_application_demand(&routed, 121, 20));

        receive(
            &mut node,
            direct,
            routed,
            SessionMessageType::EndpointData,
            130,
        );
        assert!(node.peer_has_application_demand(&routed, 150, 20));
        assert!(!node.peer_has_application_demand(&direct, 150, 20));
        receive(
            &mut node,
            direct,
            direct,
            SessionMessageType::ReceiverReport,
            151,
        );
        assert!(!node.peer_has_application_demand(&routed, 151, 20));
        assert!(!node.peer_has_application_demand(&direct, 151, 20));
        receive(
            &mut node,
            direct,
            direct,
            SessionMessageType::DataPacket,
            160,
        );
        assert!(node.peer_has_application_demand(&direct, 180, 20));
        assert!(!node.peer_has_application_demand(&routed, 180, 20));
    }

    #[test]
    fn queued_local_demand_follows_bound_carrier_and_expires_when_drained() {
        let mut node = Node::new(Config::new()).unwrap();
        let direct = add_peer(&mut node, 1);
        let routed = add_peer(&mut node, 2);
        node.pending_session_traffic
            .push_tun_packet(direct, vec![1], 8, 8, Some(1));
        assert!(node.peer_has_application_demand(&direct, 10_000, 1));
        assert!(!node.peer_has_application_demand(&routed, 10_000, 1));
        node.source_routes.insert(direct, routed);
        assert!(!node.peer_has_application_demand(&direct, 10_000, 1));
        assert!(node.peer_has_application_demand(&routed, 10_000, 1));
        node.pending_session_traffic.remove_destination(&direct);
        assert!(!node.peer_has_application_demand(&routed, 10_000, 1));

        let unknown = *Identity::generate().node_addr();
        node.pending_session_traffic
            .push_tun_packet(unknown, vec![1], 8, 8, Some(1));
        assert!(!node.peer_has_application_demand(&direct, 10_000, 1));
        assert!(!node.peer_has_application_demand(&routed, 10_000, 1));
    }

    #[test]
    fn admitted_transit_timestamp_is_monotonic_and_removed_with_the_peer() {
        let mut node = Node::new(Config::new()).unwrap();
        let peer = add_peer(&mut node, 1);
        node.record_peer_transit_demand(&peer, 100);
        node.record_peer_transit_demand(&peer, 90);
        assert!(node.peer_has_application_demand(&peer, 120, 20));
        assert!(!node.peer_has_application_demand(&peer, 121, 20));
        node.remove_active_peer(&peer);
        node.record_peer_transit_demand(&peer, 200);
        assert!(!node.peer_has_application_demand(&peer, 200, 20));
    }
}
