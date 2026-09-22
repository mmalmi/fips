use super::*;
use crate::node::wire::build_msg1;
use crate::noise::HandshakeState;
use crate::utils::index::SessionIndex;

async fn start_unconfirmed(nodes: &mut [TestNode], source: usize, sender_index: u32) {
    let mut handshake = HandshakeState::new_initiator(
        nodes[source].node.identity.keypair(),
        nodes[0].node.identity.pubkey_full(),
    );
    handshake.set_local_epoch(nodes[source].node.startup_epoch);
    let msg1 = build_msg1(
        SessionIndex::new(sender_index),
        &handshake.write_message_1().unwrap(),
    );
    nodes[source].node.transports[&nodes[source].transport_id]
        .send(&nodes[0].addr, &msg1)
        .await
        .unwrap();
    // The initiator deliberately keeps no connection state and never confirms
    // Msg2. Dispatch the genuine transport datagram through the native handler.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    loop {
        let packet = tokio::time::timeout_at(deadline, nodes[0].packet_rx.recv())
            .await
            .expect("simulated Msg1 arrival")
            .unwrap();
        let is_request = packet.data.as_slice() == msg1;
        if is_request {
            assert_eq!(packet.remote_addr, nodes[source].addr);
        }
        spanning_tree::process_dataplane_packet(&mut nodes[0], packet).await;
        if is_request {
            break;
        }
    }
}

#[tokio::test]
async fn discovery_recovers_after_unconfirmed_restarts_without_a_forced_departure() {
    let name = format!("node-sim-rotation-unconfirmed-{}", std::process::id());
    let network = SimNetwork::new(41);
    network.set_default_link(SimLink {
        up: false,
        ..Default::default()
    });
    network.set_link("local", "incumbent", SimLink::default());
    register_sim_network(name.clone(), network.clone());
    let mut nodes = vec![
        discovering_node(&name, "local", true).await,
        discovering_node(&name, "incumbent", false).await,
        discovering_node(&name, "unconfirmed", false).await,
        discovering_node(&name, "newcomer", false).await,
    ];
    nodes[0].node.set_max_links(2);
    nodes[0].node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: 1,
        interval_secs: 1,
    });
    nodes[0].node.config.node.rate_limit.handshake_timeout_secs = 3;
    nodes[0].node.poll_transport_discovery().await;
    authenticate(&mut nodes, 1).await;
    tokio::time::sleep(Duration::from_millis(1_010)).await;
    process_available_packets(&mut nodes).await;
    let incumbent = *nodes[1].node.node_addr();
    let original_link = nodes[0].node.get_peer(&incumbent).unwrap().link_id();
    network.set_link("local", "unconfirmed", SimLink::default());
    network.set_link("local", "newcomer", SimLink::default());
    start_unconfirmed(&mut nodes, 2, 140).await;
    let started = tokio::time::Instant::now();
    assert_eq!(nodes[0].node.connection_count(), 1);
    assert_caps(&nodes);

    for round in 1..=2 {
        tokio::time::sleep_until(started + Duration::from_millis(1_050 * round)).await;
        start_unconfirmed(&mut nodes, 2, 140 + round as u32).await;
        nodes[0].node.check_timeouts().await;
        nodes[0].node.poll_transport_discovery().await;
        assert_eq!(
            nodes[0].node.get_peer(&incumbent).unwrap().link_id(),
            original_link
        );
        assert_eq!(nodes[0].node.connection_count(), 1);
        assert_caps(&nodes);
    }

    // Match the native fast maintenance order. No carrier is removed, no
    // handshake state is fabricated, and discovery chooses the next identity.
    tokio::time::sleep_until(started + Duration::from_millis(3_250)).await;
    nodes[0].node.check_timeouts().await;
    nodes[0].node.poll_transport_discovery().await;
    let candidate = nodes[0].node.peers.connection_values().next().unwrap();
    assert!(
        candidate.is_outbound(),
        "discovery must regain the exploration slot"
    );
    assert_eq!(
        candidate.expected_identity().unwrap().node_addr(),
        nodes[3].node.node_addr(),
    );
    authenticate(&mut nodes, 3).await;
    assert!(nodes[0].node.get_peer(&incumbent).is_none());
    assert!(nodes[0].node.get_peer(nodes[2].node.node_addr()).is_none());
    assert!(nodes.iter().all(|node| node.node.config.peers.is_empty()));
    assert!(nodes[0].node.pending_outbound.is_empty());
    assert_eq!(nodes[0].node.link_count(), 1);
    assert_caps(&nodes);
    cleanup_nodes(&mut nodes).await;
    unregister_sim_network(&name);
}

#[tokio::test]
async fn expired_incoming_attempt_does_not_rearm_initial_cursor_seeding() {
    use futures::FutureExt;
    use std::panic::AssertUnwindSafe;

    let name = format!("node-sim-rotation-expired-cursor-{}", std::process::id());
    let network = SimNetwork::new(59);
    network.set_default_link(SimLink {
        up: false,
        ..Default::default()
    });
    register_sim_network(name.clone(), network.clone());
    let mut nodes = vec![
        discovering_node(&name, "local", true).await,
        discovering_node(&name, "remote-a", false).await,
        discovering_node(&name, "remote-b", false).await,
        discovering_node(&name, "remote-c", false).await,
        discovering_node(&name, "remote-d", false).await,
    ];
    let result = AssertUnwindSafe(async {
        nodes[0].node.set_max_links(2);
        nodes[0].node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
            idle_secs: 1,
            interval_secs: 1,
        });
        nodes[0].node.config.node.rate_limit.handshake_timeout_secs = 3;
        let mut order = [1, 2, 3, 4];
        order.sort_unstable_by_key(|index| {
            nodes[0]
                .node
                .neighbor_rotation_order(*nodes[*index].node.node_addr())
        });
        let [first, healthy, second, initial] = order;
        network.set_link(
            "local",
            nodes[initial].addr.as_str().unwrap(),
            SimLink::default(),
        );
        nodes[0].node.poll_transport_discovery().await;
        authenticate(&mut nodes, initial).await;
        let initial_addr = *nodes[initial].node.node_addr();
        let peer = nodes[0].node.get_peer(&initial_addr).unwrap();
        let original = (peer.link_id(), peer.our_index(), peer.authenticated_at());
        tokio::time::sleep(Duration::from_millis(1_010)).await;
        process_available_packets(&mut nodes).await;
        for index in [first, healthy, second] {
            network.set_link(
                "local",
                nodes[index].addr.as_str().unwrap(),
                SimLink::default(),
            );
        }

        // A < N < B < S in the local edge order. A's accepted first incoming
        // turn seeds the cursor, but its expiry must not grant B another reset.
        // Do not poll discovery between attempts: no outgoing turn masks this.
        for (source, sender_index) in [(first, 210), (second, 211)] {
            start_unconfirmed(&mut nodes, source, sender_index).await;
            assert_eq!(nodes[0].node.connection_count(), 1);
            let candidate = nodes[0].node.peers.connection_values().next().unwrap();
            assert!(!candidate.is_outbound());
            assert_eq!(
                candidate.expected_identity().unwrap().node_addr(),
                nodes[source].node.node_addr()
            );
            let pending_index = candidate.our_index().unwrap();
            assert_caps(&nodes);
            tokio::time::sleep(Duration::from_millis(3_250)).await;
            nodes[0].node.check_timeouts().await;
            assert_eq!(nodes[0].node.connection_count(), 0);
            assert_eq!(nodes[0].node.link_count(), 1);
            assert!(!nodes[0].node.index_allocator.is_allocated(pending_index));
            assert!(nodes[0].node.pending_outbound.is_empty());
            let peer = nodes[0].node.get_peer(&initial_addr).unwrap();
            assert_eq!(
                (peer.link_id(), peer.our_index(), peer.authenticated_at()),
                original
            );
            assert_caps(&nodes);
        }

        nodes[0].node.poll_transport_discovery().await;
        let candidate = nodes[0].node.peers.connection_values().next().unwrap();
        assert!(candidate.is_outbound());
        assert_eq!(
            candidate.expected_identity().unwrap().node_addr(),
            nodes[healthy].node.node_addr(),
            "an expired second incoming attempt must not move the cursor beyond N"
        );
        authenticate(&mut nodes, healthy).await;
        assert!(nodes[0].node.get_peer(&initial_addr).is_none());
        for source in [first, second] {
            assert!(
                nodes[0]
                    .node
                    .get_peer(nodes[source].node.node_addr())
                    .is_none()
            );
        }
        assert_eq!(nodes[0].node.link_count(), 1);
        assert!(nodes.iter().all(|node| node.node.config.peers.is_empty()));
        assert_caps(&nodes);
    })
    .catch_unwind()
    .await;
    cleanup_nodes(&mut nodes).await;
    unregister_sim_network(&name);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
