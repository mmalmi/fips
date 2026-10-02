use super::*;
use crate::node::tests::session::{
    build_ipv6_packet, recv_tun_packet_while_draining, send_tun_packet_via_dataplane,
};

fn check_caps(nodes: &[TestNode]) {
    for (index, node) in nodes.iter().enumerate() {
        let (peers, connections, links) = if index == 0 { (2, 2, 4) } else { (1, 1, 1) };
        assert!(node.node.peer_count() <= peers);
        assert!(node.node.connection_count() <= connections);
        assert!(node.node.link_count() <= links);
    }
}

fn outbound_targets(node: &TestNode) -> Vec<NodeAddr> {
    node.node
        .peers
        .connection_values()
        .map(|connection| {
            assert!(connection.is_outbound());
            *connection.expected_identity().unwrap().node_addr()
        })
        .collect()
}

async fn wait_for_peer(nodes: &mut [TestNode], remote: usize) {
    let local_addr = *nodes[0].node.node_addr();
    let remote_addr = *nodes[remote].node.node_addr();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        poll_available_packets(nodes).await;
        check_caps(nodes);
        if nodes[0].node.get_peer(&remote_addr).is_some()
            && nodes[remote].node.get_peer(&local_addr).is_some()
            && nodes.iter().all(|node| node.node.connection_count() == 0)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "discovered peer did not authenticate"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

async fn refresh_and_exploration(new_neighbor: bool) {
    let name = format!(
        "node-sim-rotation-refresh-{}-{new_neighbor}",
        std::process::id()
    );
    let network = SimNetwork::new(59);
    network.set_default_link(SimLink {
        up: false,
        ..Default::default()
    });
    network.set_link("local", "protected", SimLink::default());
    register_sim_network(name.clone(), network.clone());
    let mut nodes = vec![
        discovering_node(&name, "local", true).await,
        discovering_node(&name, "protected", false).await,
        discovering_node(&name, "idle", false).await,
        discovering_node(&name, "newcomer", false).await,
    ];
    nodes[0].node.set_max_peers(2);
    nodes[0].node.set_max_connections(2);
    nodes[0].node.set_max_links(4);
    nodes[0].node.config.node.heartbeat_interval_secs = 1;
    nodes[0].node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: 1,
        interval_secs: 1,
    });
    nodes[0].node.poll_transport_discovery().await;
    wait_for_peer(&mut nodes, 1).await;
    network.set_link("local", "idle", SimLink::default());
    nodes[0].node.poll_transport_discovery().await;
    wait_for_peer(&mut nodes, 2).await;

    // Drain bootstrap packets before the real idle interval. The test invokes
    // no maintenance tick that could refresh the idle peer during this wait.
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        process_available_packets(&mut nodes).await;
    }
    tokio::time::sleep(Duration::from_millis(1_050)).await;

    let protected = *nodes[1].node.node_addr();
    let idle = *nodes[2].node.node_addr();
    let newcomer = *nodes[3].node.node_addr();
    let original = {
        let peer = nodes[0].node.get_peer(&protected).unwrap();
        (peer.link_id(), peer.our_index(), peer.session_generation())
    };
    let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
    nodes[1].node.tun_tx = Some(tun_tx);
    let packet = build_ipv6_packet(
        &crate::FipsAddress::from_node_addr(nodes[0].node.node_addr()),
        &crate::FipsAddress::from_node_addr(&protected),
        b"protect this learned neighbor during discovery",
    );
    send_tun_packet_via_dataplane(&mut nodes, 0, packet.clone()).await;
    let delivered = recv_tun_packet_while_draining(
        &mut nodes,
        &tun_rx,
        Duration::from_secs(3),
        "rotation fixture application demand",
    )
    .await;
    assert_eq!(delivered, packet);
    // One-way delivery protects application demand but need not refresh the
    // sender's inbound data observations. Exercise a real reverse payload too.
    let (reverse_tx, reverse_rx) = crate::upper::tun::write_channel();
    nodes[0].node.tun_tx = Some(reverse_tx);
    let reverse = build_ipv6_packet(
        &crate::FipsAddress::from_node_addr(&protected),
        &crate::FipsAddress::from_node_addr(nodes[0].node.node_addr()),
        b"the protected neighbor also replies",
    );
    send_tun_packet_via_dataplane(&mut nodes, 1, reverse.clone()).await;
    let delivered = recv_tun_packet_while_draining(
        &mut nodes,
        &reverse_rx,
        Duration::from_secs(3),
        "rotation fixture reverse application demand",
    )
    .await;
    assert_eq!(delivered, reverse);
    assert!(
        nodes[0]
            .node
            .peer_has_application_demand(&protected, Node::now_ms(), 1_000)
    );
    assert!(
        !nodes[0]
            .node
            .peer_has_application_demand(&idle, Node::now_ms(), 1_000)
    );
    assert!(
        !nodes[0]
            .node
            .active_peer_needs_same_path_refresh(&protected)
    );
    assert!(nodes[0].node.active_peer_needs_same_path_refresh(&idle));
    assert!(
        nodes[0]
            .node
            .can_attempt_neighbor_rotation(&newcomer, true, Node::now_ms())
    );
    assert_eq!(nodes[0].node.connection_count(), 0);
    assert_eq!(nodes[0].node.peer_count(), 2);

    if new_neighbor {
        network.set_link("local", "newcomer", SimLink::default());
    }
    nodes[0].node.poll_transport_discovery().await;
    let mut selected = outbound_targets(&nodes[0]);
    if new_neighbor && selected == vec![newcomer] {
        // Its real Msg1 is queued remotely, not yet processed. The next
        // discovery turn must not undo exploration by refreshing its victim.
        nodes[0].node.poll_transport_discovery().await;
        selected = outbound_targets(&nodes[0]);
    }
    check_caps(&nodes);
    assert!(nodes[0].node.get_peer(&protected).is_some());
    assert!(nodes[0].node.get_peer(&idle).is_some());
    assert!(
        nodes[0].node.get_peer(&newcomer).is_none(),
        "discovery alone cannot evict"
    );
    let expected = if new_neighbor { newcomer } else { idle };
    let correct_selection = selected == vec![expected];

    if new_neighbor && correct_selection {
        wait_for_peer(&mut nodes, 3).await;
        assert!(nodes[0].node.get_peer(&idle).is_none());
        let retained = nodes[0].node.get_peer(&protected).unwrap();
        assert_eq!(
            (
                retained.link_id(),
                retained.our_index(),
                retained.session_generation()
            ),
            original
        );
        assert!(retained.has_session() && retained.can_send());
        assert!(nodes[0].node.get_peer(&newcomer).is_some());
    }
    assert!(nodes.iter().all(|node| node.node.config.peers.is_empty()));
    check_caps(&nodes);
    cleanup_nodes(&mut nodes).await;
    unregister_sim_network(&name);
    assert_eq!(
        selected,
        vec![expected],
        "new_neighbor={new_neighbor}: refreshing the idle victim must not cancel the same discovery turn's exploration; without a newcomer its refresh must still run"
    );
}

#[tokio::test]
async fn exploration_gets_a_turn_before_refreshing_its_idle_victim() {
    refresh_and_exploration(true).await;
}

#[tokio::test]
async fn idle_peer_refresh_runs_when_no_new_neighbor_is_discovered() {
    refresh_and_exploration(false).await;
}
