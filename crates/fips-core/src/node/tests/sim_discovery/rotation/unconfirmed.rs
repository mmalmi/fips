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
