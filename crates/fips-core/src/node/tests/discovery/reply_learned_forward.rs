use super::*;

#[tokio::test]
async fn test_reply_learned_forward_fallback_uses_non_tree_peer_without_origin_echo() {
    // Topology: node0 -- node1 -- node2. Node1 has node2 as a live direct peer
    // but no tree edge to it. A lookup from node0 for an unknown target should
    // fan out to node2 in reply-learned fallback, without echoing back to the
    // originator and confusing request_id ownership.
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    nodes[1].node.config.node.routing.mode = RoutingMode::ReplyLearned;
    nodes[1].node.tree_state_mut().remove_peer(&node2_addr);
    nodes[1].node.tree_state_mut().become_root();
    assert!(
        nodes[1]
            .node
            .peers
            .get(&node2_addr)
            .is_some_and(|peer| peer.can_send()),
        "node2 should remain a direct sendable peer"
    );
    assert!(
        !nodes[1].node.is_tree_peer(&node2_addr),
        "node2 should not be a tree peer in this regression fixture"
    );

    let target = make_node_addr(0x66);
    let origin_coords = TreeCoordinate::from_addrs(vec![node0_addr, node1_addr]).unwrap();
    let request = LookupRequest::new(4343, target, node0_addr, origin_coords, 5, 0);
    let payload = &request.encode()[1..];

    nodes[1]
        .node
        .handle_lookup_request(&node0_addr, payload)
        .await;

    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    assert!(
        nodes[2].node.recent_requests.contains_key(&4343),
        "reply-learned fallback should fan out through the non-tree peer"
    );
    assert!(
        !nodes[0].node.recent_requests.contains_key(&4343),
        "transit fallback must not echo lookup requests to the originator"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_reply_learned_forward_fanout_skips_bootstrap_transit_peer() {
    // Topology: node0 asks node1 for node4. Node1 has a tree/bloom route via
    // node2 and a live non-tree neighbor node3 on a bootstrap transport. The
    // tree route should still be used, but the bootstrap peer should not be
    // pulled into private fallback transit.
    let edges = vec![(0, 1), (1, 2), (2, 4), (1, 3)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let node3_addr = *nodes[3].node.node_addr();
    let node4_addr = *nodes[4].node.node_addr();

    nodes[1].node.config.node.routing.mode = RoutingMode::ReplyLearned;
    assert!(
        nodes[1]
            .node
            .peers
            .get(&node2_addr)
            .is_some_and(|peer| peer.may_reach(&node4_addr)),
        "node2 should be the tree/bloom match for node4"
    );

    nodes[1].node.tree_state_mut().remove_peer(&node3_addr);
    nodes[1].node.tree_state_mut().become_root();
    let bootstrap_transport = crate::transport::TransportId::new(9_103);
    nodes[1]
        .node
        .peers
        .get_mut(&node3_addr)
        .expect("node3 should be an active peer")
        .set_current_addr(
            bootstrap_transport,
            &crate::transport::TransportAddr::from_string("bootstrap/node3"),
        );
    nodes[1].node.bootstrap_transports.mark(bootstrap_transport);
    assert!(
        nodes[1]
            .node
            .peers
            .get(&node3_addr)
            .is_some_and(|peer| peer.can_send()),
        "node3 should remain a direct sendable bootstrap peer"
    );
    assert!(
        !nodes[1].node.is_tree_peer(&node3_addr),
        "node3 should not be a tree peer in this regression fixture"
    );

    let origin_coords = TreeCoordinate::from_addrs(vec![node0_addr, node1_addr]).unwrap();
    let request = LookupRequest::new(4545, node4_addr, node0_addr, origin_coords, 5, 0);
    let payload = &request.encode()[1..];

    nodes[1]
        .node
        .handle_lookup_request(&node0_addr, payload)
        .await;

    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    assert!(
        nodes[2].node.recent_requests.contains_key(&4545),
        "tree/bloom match should receive the forwarded lookup"
    );
    assert!(
        !nodes[3].node.recent_requests.contains_key(&4545),
        "bootstrap transit peer should not receive private fallback lookup"
    );
    assert!(
        !nodes[0].node.recent_requests.contains_key(&4545),
        "transit fanout must not echo lookup requests to the originator"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_reply_learned_forward_fanout_skips_disabled_transit_peer() {
    // Forwarded lookups should also keep public/open or cached non-roster
    // peers out of the extra reply-learned fanout set.
    let edges = vec![(0, 1), (1, 2), (2, 4), (1, 3)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let node3_addr = *nodes[3].node.node_addr();
    let node4_addr = *nodes[4].node.node_addr();

    nodes[1].node.config.node.routing.mode = RoutingMode::ReplyLearned;
    assert!(
        nodes[1]
            .node
            .peers
            .get(&node2_addr)
            .is_some_and(|peer| peer.may_reach(&node4_addr)),
        "node2 should be the tree/bloom match for node4"
    );

    nodes[1].node.tree_state_mut().remove_peer(&node3_addr);
    nodes[1].node.tree_state_mut().become_root();
    nodes[1]
        .node
        .set_discovery_fallback_transit_allowed(node3_addr, false);
    assert!(
        nodes[1]
            .node
            .peers
            .get(&node3_addr)
            .is_some_and(|peer| peer.can_send()),
        "node3 should remain a direct sendable peer"
    );
    assert!(
        !nodes[1].node.is_tree_peer(&node3_addr),
        "node3 should not be a tree peer in this regression fixture"
    );

    let origin_coords = TreeCoordinate::from_addrs(vec![node0_addr, node1_addr]).unwrap();
    let request = LookupRequest::new(4646, node4_addr, node0_addr, origin_coords, 5, 0);
    let payload = &request.encode()[1..];

    nodes[1]
        .node
        .handle_lookup_request(&node0_addr, payload)
        .await;

    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    assert!(
        nodes[2].node.recent_requests.contains_key(&4646),
        "tree/bloom match should receive the forwarded lookup"
    );
    assert!(
        !nodes[3].node.recent_requests.contains_key(&4646),
        "fallback-disabled transit peer should not receive private fallback lookup"
    );
    assert!(
        !nodes[0].node.recent_requests.contains_key(&4646),
        "transit fanout must not echo lookup requests to the originator"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_reply_learned_open_policy_skips_unconfigured_lookup_fanout() {
    // In open Nostr discovery, ambient public peers can ask for arbitrary
    // targets. Those lookups must not be amplified into the configured mesh by
    // reply-learned fallback. Tree/bloom forwarding is still allowed; only the
    // extra fallback fanout is suppressed for unconfigured origin/target pairs.
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();

    nodes[1].node.config.node.routing.mode = RoutingMode::ReplyLearned;
    nodes[1].node.config.node.discovery.nostr.policy = crate::config::NostrDiscoveryPolicy::Open;
    nodes[1].node.tree_state_mut().remove_peer(&node2_addr);
    nodes[1].node.tree_state_mut().become_root();
    assert!(
        !nodes[1].node.is_tree_peer(&node2_addr),
        "node2 should not be a tree peer in this regression fixture"
    );

    let target = make_node_addr(0x77);
    let origin_coords = TreeCoordinate::from_addrs(vec![node0_addr, node1_addr]).unwrap();
    let request = LookupRequest::new(4747, target, node0_addr, origin_coords, 5, 0);
    let payload = &request.encode()[1..];

    nodes[1]
        .node
        .handle_lookup_request(&node0_addr, payload)
        .await;

    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    assert!(
        !nodes[2].node.recent_requests.contains_key(&4747),
        "open-discovery fallback must not amplify unconfigured public lookups"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_reply_learned_configured_policy_skips_unconfigured_lookup_fanout() {
    // Configured-only Nostr discovery is used by private apps such as nvpn.
    // It must not use reply-learned fallback to amplify lookups for public
    // targets that are not in the configured roster.
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();

    nodes[1].node.config.node.routing.mode = RoutingMode::ReplyLearned;
    nodes[1].node.config.node.discovery.nostr.enabled = true;
    nodes[1].node.config.node.discovery.nostr.policy =
        crate::config::NostrDiscoveryPolicy::ConfiguredOnly;
    nodes[1].node.tree_state_mut().remove_peer(&node2_addr);
    nodes[1].node.tree_state_mut().become_root();
    assert!(
        !nodes[1].node.is_tree_peer(&node2_addr),
        "node2 should not be a tree peer in this regression fixture"
    );

    let target = make_node_addr(0x78);
    let origin_coords = TreeCoordinate::from_addrs(vec![node0_addr, node1_addr]).unwrap();
    let request = LookupRequest::new(4788, target, node0_addr, origin_coords, 5, 0);
    let payload = &request.encode()[1..];

    nodes[1]
        .node
        .handle_lookup_request(&node0_addr, payload)
        .await;

    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    assert!(
        !nodes[2].node.recent_requests.contains_key(&4788),
        "configured-only fallback must not amplify unconfigured public lookups"
    );

    cleanup_nodes(&mut nodes).await;
}
