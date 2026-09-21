use super::*;
use crate::node::wire::Msg1Header;

async fn dial(nodes: &mut [TestNode], source: usize, destination: usize) {
    let identity = PeerIdentity::from_pubkey_full(nodes[destination].node.identity.pubkey_full());
    let remote = nodes[destination].addr.clone();
    let node = &mut nodes[source];
    node.node
        .initiate_connection(node.transport_id, remote, identity)
        .await
        .unwrap();
}

async fn next_packet(node: &mut TestNode) -> ReceivedPacket {
    tokio::time::timeout(Duration::from_secs(1), node.packet_rx.recv())
        .await
        .expect("real UDP handshake packet must arrive")
        .unwrap()
}

async fn quiesce(nodes: &mut [TestNode]) {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut idle = 0;
        while idle < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if process_available_packets(nodes).await == 0 {
                idle += 1;
            } else {
                idle = 0;
            }
        }
    })
    .await
    .expect("handshake/bootstrap packets must settle");
}

#[test]
fn winning_outbound_rotation_retires_parked_crossed_inbound() {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-crossed-pending-inbound",
        || async {
            let mut nodes = [
                make_test_node().await,
                make_test_node().await,
                make_test_node().await,
            ];
            // The existing cross-dial rule keeps the smaller node's outbound.
            if nodes[0].node.node_addr() > nodes[1].node.node_addr() {
                nodes.swap(0, 1);
            }
            let local = *nodes[0].node.node_addr();
            let newcomer = *nodes[1].node.node_addr();
            let old = *nodes[2].node.node_addr();
            for node in &mut nodes {
                node.node.max_peers = 1;
                node.node.max_connections = 2;
                node.node.max_links = 3;
            }
            nodes[0].node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
                idle_secs: 1,
                interval_secs: 1,
            });

            // Fill the local roster through real UDP and Noise, then let the
            // incumbent genuinely age. No session or timestamp is synthesized.
            dial(&mut nodes, 0, 2).await;
            quiesce(&mut nodes).await;
            assert_eq!(resources(&nodes[0]), (1, 0, 1, 1));
            assert!(nodes[2].node.get_peer(&local).unwrap().can_send());
            let old_link = nodes[0].node.get_peer(&old).unwrap().link_id();
            tokio::time::sleep(Duration::from_millis(1_050)).await;
            assert!(
                nodes[0]
                    .node
                    .has_neighbor_rotation_opportunity(Node::now_ms())
            );

            // Both real Msg1 flights leave before either end handles the peer's
            // request. Two spare slots allow both halves to coexist.
            dial(&mut nodes, 0, 1).await;
            let outbound = nodes[0].node.peers.connection_values().next().unwrap();
            let winner_link = outbound.link_id();
            let winner_index = outbound.our_index().unwrap();
            let started_at = outbound.started_at();
            dial(&mut nodes, 1, 0).await;

            let incoming = next_packet(&mut nodes[0]).await;
            assert_eq!(incoming.remote_addr, nodes[1].addr);
            assert!(Msg1Header::parse(incoming.data.as_slice()).is_some());
            nodes[0].node.handle_msg1(incoming).await;
            assert_eq!(resources(&nodes[0]), (1, 2, 3, 3));
            assert_eq!(nodes[0].node.get_peer(&old).unwrap().link_id(), old_link);
            assert!(nodes[0].node.get_peer(&newcomer).is_none());
            let parked = nodes[0]
                .node
                .peers
                .connection_values()
                .find(|conn| conn.is_inbound())
                .unwrap();
            assert!(parked.is_complete());
            assert_eq!(parked.expected_identity().unwrap().node_addr(), &newcomer);
            assert_eq!(parked.transport_id(), Some(nodes[0].transport_id));
            assert_eq!(parked.source_addr(), Some(&nodes[1].addr));
            assert_eq!(parked.remote_epoch(), Some(nodes[1].node.startup_epoch));
            assert!(parked.started_at() >= started_at);
            let loser_link = parked.link_id();
            let loser_index = parked.our_index().unwrap();

            // The other end immediately promotes its inbound, since its roster
            // is empty. Local promotion then happens while its crossed inbound
            // is still waiting for the confirmation that the loser never sends.
            let request = next_packet(&mut nodes[1]).await;
            assert_eq!(request.remote_addr, nodes[0].addr);
            assert!(Msg1Header::parse(request.data.as_slice()).is_some());
            nodes[1].node.handle_msg1(request).await;
            assert!(nodes[1].node.get_peer(&local).unwrap().can_send());
            let response = next_packet(&mut nodes[0]).await;
            assert_eq!(response.remote_addr, nodes[1].addr);
            assert_eq!(
                Msg2Header::parse(response.data.as_slice())
                    .unwrap()
                    .receiver_idx,
                winner_index
            );
            nodes[0].node.handle_msg2(response).await;
            assert_eq!(
                nodes[0].node.get_peer(&newcomer).unwrap().link_id(),
                winner_link
            );
            assert!(nodes[0].node.get_peer(&old).is_none());

            // Deliver the remote's losing Msg2 and both real encrypted
            // bootstraps. The winning session must match at both ends.
            quiesce(&mut nodes).await;
            let local_peer = nodes[0].node.get_peer(&newcomer).unwrap();
            let remote_peer = nodes[1].node.get_peer(&local).unwrap();
            assert_eq!(local_peer.our_index(), remote_peer.their_index());
            assert_eq!(local_peer.their_index(), remote_peer.our_index());
            assert!(local_peer.can_send() && remote_peer.can_send());
            assert_eq!(nodes[1].node.connection_count(), 0);
            assert!(nodes[0].node.pending_outbound.is_empty());
            for (source, destination) in [(0, newcomer), (1, local)] {
                assert!(
                    nodes[source]
                        .node
                        .dataplane_fmp_link_metrics(&destination, Instant::now())
                        .unwrap()
                        .rx_packets
                        > 0,
                    "winning Noise session must receive authenticated traffic"
                );
            }

            // Normal rotation grace/cooldown elapses, but not the unchanged
            // 30-second handshake timeout. A dead crossed half must not pin the
            // now-idle active neighbor or retain its carrier/index resources.
            tokio::time::sleep(Duration::from_millis(1_050)).await;
            let remaining = resources(&nodes[0]);
            let parked_survives = nodes[0].node.get_connection(&loser_link).is_some();
            let loser_link_survives = nodes[0].node.links.get(&loser_link).is_some();
            let loser_index_survives = nodes[0].node.index_allocator.is_allocated(loser_index);
            let winner_address = nodes[0]
                .node
                .links
                .lookup_addr(nodes[0].transport_id, &nodes[1].addr);
            let can_explore = nodes[0]
                .node
                .has_neighbor_rotation_opportunity(Node::now_ms());
            cleanup_nodes(&mut nodes).await;

            assert!(
                !parked_survives,
                "winning outbound left its losing inbound parked: resources={remaining:?}, next_exploration={can_explore}"
            );
            assert!(!loser_link_survives && !loser_index_survives);
            assert_eq!(winner_address, Some(winner_link));
            assert_eq!(remaining, (1, 0, 1, 1));
            assert!(
                can_explore,
                "stale same-peer pending work must not pin the idle roster"
            );
        },
    );
}

#[test]
fn winning_outbound_preserves_parked_inbound_from_another_epoch() {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-crossed-different-epoch",
        || retained_inbound_guard(false),
    );
}

#[test]
fn winning_outbound_preserves_parked_inbound_on_another_carrier() {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-crossed-alternate-carrier",
        || retained_inbound_guard(true),
    );
}

async fn retained_inbound_guard(alternate_carrier: bool) {
    let mut nodes = [
        make_test_node().await,
        make_test_node().await,
        make_test_node().await,
    ];
    if nodes[0].node.node_addr() > nodes[1].node.node_addr() {
        nodes.swap(0, 1);
    }
    let local = *nodes[0].node.node_addr();
    let newcomer = *nodes[1].node.node_addr();
    let old = *nodes[2].node.node_addr();
    nodes[0].node.max_peers = 1;
    nodes[0].node.max_connections = 2;
    nodes[0].node.max_links = 3;
    nodes[0].node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: 1,
        interval_secs: 1,
    });
    dial(&mut nodes, 0, 2).await;
    quiesce(&mut nodes).await;
    assert_eq!(resources(&nodes[0]), (1, 0, 1, 1));
    tokio::time::sleep(Duration::from_millis(1_050)).await;
    dial(&mut nodes, 0, 1).await;
    let winner = nodes[0].node.peers.connection_values().next().unwrap();
    let winner_link = winner.link_id();
    let winner_index = winner.our_index().unwrap();

    // Authenticate the same signing identity, but vary exactly one cleanup
    // guard: either its Noise-bound startup epoch or its actual UDP socket.
    // Keep this raw initiator separate from the live remote Node so it cannot
    // accidentally confirm the parked handshake during bootstrap draining.
    let (alternate_socket, alternate_address) = local_path().await;
    let mut epoch = nodes[1].node.startup_epoch;
    let source = if alternate_carrier {
        alternate_address
    } else {
        epoch[0] ^= 1;
        nodes[1].addr.clone()
    };
    let mut handshake = HandshakeState::new_initiator(
        nodes[1].node.identity.keypair(),
        nodes[0].node.identity.pubkey_full(),
    );
    handshake.set_local_epoch(epoch);
    let wire = build_msg1(
        SessionIndex::new(32_767),
        &handshake.write_message_1().unwrap(),
    );
    if alternate_carrier {
        alternate_socket
            .send_to(&wire, nodes[0].addr.as_str().unwrap())
            .await
            .unwrap();
    } else {
        nodes[1]
            .node
            .transports
            .get(&nodes[1].transport_id)
            .unwrap()
            .send(&nodes[0].addr, &wire)
            .await
            .unwrap();
    }
    let incoming = next_packet(&mut nodes[0]).await;
    assert_eq!(incoming.remote_addr, source);
    assert!(Msg1Header::parse(incoming.data.as_slice()).is_some());
    nodes[0].node.handle_msg1(incoming).await;
    assert_eq!(resources(&nodes[0]), (1, 2, 3, 3));
    let parked = nodes[0]
        .node
        .peers
        .connection_values()
        .find(|conn| conn.is_inbound())
        .unwrap();
    assert!(parked.is_complete());
    assert_eq!(parked.expected_identity().unwrap().node_addr(), &newcomer);
    assert_eq!(parked.remote_epoch(), Some(epoch));
    assert_eq!(parked.transport_id(), Some(nodes[0].transport_id));
    assert_eq!(parked.source_addr(), Some(&source));
    let retained_link = parked.link_id();
    let retained_index = parked.our_index().unwrap();
    let retained_started = parked.started_at();
    let retained_activity = parked.last_activity();
    let msg2 = parked.handshake_msg2().unwrap().to_vec();
    let header = Msg2Header::parse(&msg2).unwrap();
    handshake.read_message_2(header.noise_msg2(&msg2)).unwrap();
    let _authenticated_session = handshake.into_session().unwrap();

    let request = next_packet(&mut nodes[1]).await;
    assert!(Msg1Header::parse(request.data.as_slice()).is_some());
    nodes[1].node.handle_msg1(request).await;
    let response = next_packet(&mut nodes[0]).await;
    assert_eq!(
        Msg2Header::parse(response.data.as_slice())
            .unwrap()
            .receiver_idx,
        winner_index
    );
    nodes[0].node.handle_msg2(response).await;
    quiesce(&mut nodes).await;

    let active = nodes[0].node.get_peer(&newcomer).unwrap();
    let remote = nodes[1].node.get_peer(&local).unwrap();
    assert_eq!(active.link_id(), winner_link);
    assert_eq!(active.remote_epoch(), Some(nodes[1].node.startup_epoch));
    assert_eq!(active.our_index(), remote.their_index());
    assert_eq!(active.their_index(), remote.our_index());
    assert!(active.can_send() && remote.can_send());
    assert!(nodes[0].node.get_peer(&old).is_none());
    assert!(nodes[0].node.pending_outbound.is_empty());
    for (source, destination) in [(0, newcomer), (1, local)] {
        assert!(
            nodes[source]
                .node
                .dataplane_fmp_link_metrics(&destination, Instant::now())
                .unwrap()
                .rx_packets
                > 0
        );
    }

    let unchanged = nodes[0]
        .node
        .get_connection(&retained_link)
        .is_some_and(|conn| {
            conn.is_inbound()
                && conn.is_complete()
                && conn.our_index() == Some(retained_index)
                && conn.remote_epoch() == Some(epoch)
                && conn.source_addr() == Some(&source)
                && conn.started_at() == retained_started
                && conn.last_activity() == retained_activity
                && conn.handshake_msg2() == Some(msg2.as_slice())
        });
    let remaining = resources(&nodes[0]);
    let link_retained = nodes[0].node.links.get(&retained_link).is_some();
    let index_retained = nodes[0].node.index_allocator.is_allocated(retained_index);
    cleanup_nodes(&mut nodes).await;
    assert!(
        unchanged,
        "a distinct epoch/carrier is not a proven crossed loser"
    );
    assert!(link_retained && index_retained);
    assert_eq!(remaining, (1, 1, 2, 2));
}
