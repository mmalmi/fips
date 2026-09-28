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
            || self.peer_has_recent_local_application_data(peer, now_ms, idle_ms)
            || self.peer_has_queued_application_demand(peer)
    }

    /// Timed admitted local data only; queues and FSP reports do not qualify.
    pub(in crate::node) fn peer_has_recent_local_application_data(
        &self,
        peer: &NodeAddr,
        now_ms: u64,
        idle_ms: u64,
    ) -> bool {
        self.dataplane
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
    }

    /// Attribute local queues to their explicit or currently installed carrier.
    /// An unresolved destination asks for itself; no historical path is revived.
    pub(in crate::node) fn peer_has_queued_application_demand(&self, peer: &NodeAddr) -> bool {
        let carrier = |destination: &NodeAddr| {
            self.source_routes
                .get(destination)
                .copied()
                .or_else(|| self.dataplane.fsp_owner_next_hop(destination))
                .unwrap_or(*destination)
        };
        // Keep direct demand cheap without bypassing a selected other carrier.
        (self.pending_session_traffic.has_traffic_for(peer) && carrier(peer) == *peer)
            || self
                .pending_session_traffic
                .destinations()
                .any(|destination| destination != *peer && carrier(&destination) == *peer)
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
    use std::time::{Duration, Instant};

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

    fn local_history_node() -> Node {
        let mut config = Config::new();
        config.node.neighbor_rotation = Some(crate::config::NeighborRotationConfig {
            idle_secs: 1,
            interval_secs: 1,
        });
        config.node.rate_limit.handshake_timeout_secs = 6;
        let mut node = Node::new(config).unwrap();
        node.set_max_peers(2);
        node
    }

    fn history_prefers(node: &Node, peer: NodeAddr, now_ms: u64) -> bool {
        !node.neighbor_rotation_discovery_order(peer, now_ms).1
    }

    async fn application_activity(
        node: &mut Node,
        destination: NodeAddr,
        carrier: NodeAddr,
        at: u64,
        outbound: bool,
    ) {
        if outbound {
            send(
                node,
                destination,
                carrier,
                SessionMessageType::EndpointData,
                at,
            )
            .await;
        } else {
            receive(
                node,
                destination,
                carrier,
                SessionMessageType::EndpointData,
                at,
            );
        }
    }

    #[tokio::test]
    async fn local_data_history_follows_actual_carrier_without_control_refresh() {
        for outbound in [false, true] {
            for routed in [false, true] {
                for lost_at in [4_100, 4_101] {
                    let mut node = local_history_node();
                    let direct = add_peer(&mut node, 1);
                    let relay = add_peer(&mut node, 2);
                    let (carrier, other) = if routed {
                        (relay, direct)
                    } else {
                        (direct, relay)
                    };
                    node.dataplane
                        .register_owner(OwnerId::fsp_node(direct), OwnerConfig::new(1, 8));
                    application_activity(&mut node, direct, carrier, 100, outbound).await;
                    // Later control on another path must neither reattribute data
                    // nor extend its four-second admission lookback.
                    send(
                        &mut node,
                        direct,
                        other,
                        SessionMessageType::SenderReport,
                        4_000,
                    )
                    .await;
                    receive(
                        &mut node,
                        direct,
                        other,
                        SessionMessageType::ReceiverReport,
                        4_000,
                    );
                    node.remove_link_dead_discovered_peer(
                        &carrier,
                        lost_at,
                        Duration::from_secs(3),
                    );
                    let qualifies = lost_at == 4_100;
                    assert_eq!(
                        history_prefers(&node, carrier, lost_at),
                        qualifies,
                        "outbound={outbound}, routed={routed}, loss={lost_at}"
                    );
                    assert!(!history_prefers(&node, other, lost_at));
                    assert!(!node.retry_pending.contains_key(&carrier));
                    assert!(!node.source_routes.contains_key(&carrier));
                    assert!(node.get_peer(&carrier).is_none());
                    // Routed FSP ownership remains available after carrier removal.
                    // Repeating an old admitted observation is not a new history grant;
                    // this component helper does not claim to test wire replay rejection.
                    if routed {
                        assert!(node.dataplane.fsp_owner_activity(&direct).is_some());
                        application_activity(&mut node, direct, carrier, 100, outbound).await;
                        receive(
                            &mut node,
                            direct,
                            carrier,
                            SessionMessageType::SenderReport,
                            lost_at + 5_000,
                        );
                    }
                    node.config.node.rate_limit.handshake_timeout_secs = 60;
                    // An unused preference survives waiting for admission, but
                    // later control and old data cannot refresh its remembrance.
                    assert_eq!(history_prefers(&node, carrier, lost_at + 5_999), qualifies);
                    assert_eq!(history_prefers(&node, carrier, lost_at + 60_000), qualifies);
                    assert_eq!(
                        node.neighbor_rotation.lost_neighbors.get(&carrier).copied(),
                        qualifies.then_some(lost_at)
                    );
                    node.forget_neighbor_reconnection(&carrier);
                    assert!(!history_prefers(&node, carrier, lost_at + 60_000));
                    node.remove_link_dead_discovered_peer(&other, lost_at, Duration::from_secs(3));
                    assert!(!history_prefers(&node, other, lost_at));
                }
            }
        }
    }

    #[tokio::test]
    async fn retained_local_data_cannot_rearm_history_for_a_new_admitted_owner() {
        for outbound in [false, true] {
            for admitted_at in [100, 101] {
                let mut node = local_history_node();
                let carrier = add_peer(&mut node, 1);
                let identity = *node.get_peer(&carrier).unwrap().identity();
                let destination = *Identity::generate().node_addr();
                node.dataplane
                    .register_owner(OwnerId::fsp_node(destination), OwnerConfig::new(1, 8));
                application_activity(&mut node, destination, carrier, 100, outbound).await;
                node.remove_link_dead_discovered_peer(&carrier, 100, Duration::from_secs(3));
                assert!(history_prefers(&node, carrier, 100));
                let prior = node.dataplane.fsp_owner_activity(&destination).unwrap();
                if outbound {
                    assert_eq!(prior.last_outbound_next_hop(), Some(carrier));
                    assert!(prior.has_recent_outbound_activity(200, 100));
                } else {
                    assert_eq!(
                        node.dataplane
                            .min_fsp_data_rx_age_for_next_hop(&carrier, 200),
                        Some(100)
                    );
                }

                // Component-level owner replacement, with the original FSP activity
                // genuinely retained. Equal-millisecond data is excluded conservatively.
                node.peers.insert(
                    carrier,
                    ActivePeer::new(identity, LinkId::new(2), admitted_at),
                );
                send(
                    &mut node,
                    destination,
                    carrier,
                    SessionMessageType::SenderReport,
                    150,
                )
                .await;
                receive(
                    &mut node,
                    destination,
                    carrier,
                    SessionMessageType::ReceiverReport,
                    150,
                );
                assert_eq!(
                    node.dataplane
                        .fsp_owner_activity(&destination)
                        .unwrap()
                        .traffic_counters(),
                    prior.traffic_counters()
                );
                node.remove_link_dead_discovered_peer(&carrier, 200, Duration::from_secs(3));
                assert!(
                    !history_prefers(&node, carrier, 200),
                    "old FSP activity must not renew: outbound={outbound}, admission={admitted_at}"
                );

                node.peers
                    .insert(carrier, ActivePeer::new(identity, LinkId::new(3), 201));
                application_activity(&mut node, destination, carrier, 202, outbound).await;
                node.remove_link_dead_discovered_peer(&carrier, 203, Duration::from_secs(3));
                assert!(
                    history_prefers(&node, carrier, 203),
                    "new-owner application use can qualify again"
                );
            }
        }
    }

    #[tokio::test]
    async fn queues_and_control_only_traffic_cannot_create_local_use_history() {
        for queue in 0..=2 {
            let mut node = local_history_node();
            let peer = add_peer(&mut node, 1);
            node.dataplane
                .register_owner(OwnerId::fsp_node(peer), OwnerConfig::new(1, 8));
            match queue {
                1 => {
                    node.pending_session_traffic
                        .push_tun_packet(peer, vec![1], 8, 8, Some(100));
                }
                2 => {
                    node.pending_session_traffic
                        .push_endpoint_data_batch_with_enqueued_at_ms(
                            peer,
                            vec![EndpointDataPayload::from_packet_payload(vec![1]).unwrap()],
                            8,
                            8,
                            100,
                        );
                }
                _ => {}
            }
            node.peers.get_mut(&peer).unwrap().touch(100);
            node.peers
                .get_mut(&peer)
                .unwrap()
                .mark_heartbeat_sent(Instant::now());
            send(&mut node, peer, peer, SessionMessageType::SenderReport, 100).await;
            receive(
                &mut node,
                peer,
                peer,
                SessionMessageType::ReceiverReport,
                100,
            );
            assert_eq!(
                node.peer_has_application_demand(&peer, 200, 1_000),
                queue != 0,
                "queued traffic still protects an active peer"
            );
            assert_eq!(
                node.dataplane
                    .fsp_owner_activity(&peer)
                    .unwrap()
                    .traffic_counters(),
                (0, 0, 0, 0)
            );
            node.remove_link_dead_discovered_peer(&peer, 200, Duration::from_secs(3));
            assert!(!node.pending_session_traffic.has_traffic_for(&peer));
            assert!(!history_prefers(&node, peer, 200));
        }
    }
}
