use super::*;

#[tokio::test]
async fn test_reply_learned_open_policy_allows_configured_lookup_fanout() {
    // The open-discovery guard above must not break private nvpn-style lookup:
    // when both origin and target are configured peers, reply-learned fallback
    // can still use a non-tree direct neighbor to repair stale tree state.
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();

    nodes[1].node.config.node.routing.mode = RoutingMode::ReplyLearned;
    nodes[1].node.config.node.discovery.nostr.policy = crate::config::NostrDiscoveryPolicy::Open;
    nodes[1].node.config.peers = vec![
        crate::config::PeerConfig {
            npub: nodes[0].node.npub(),
            ..Default::default()
        },
        crate::config::PeerConfig {
            npub: nodes[2].node.npub(),
            ..Default::default()
        },
    ];
    nodes[1].node.tree_state_mut().remove_peer(&node2_addr);
    nodes[1].node.tree_state_mut().become_root();
    assert!(
        !nodes[1].node.is_tree_peer(&node2_addr),
        "node2 should not be a tree peer in this regression fixture"
    );

    let origin_coords = TreeCoordinate::from_addrs(vec![node0_addr, node1_addr]).unwrap();
    let request = LookupRequest::new(4848, node2_addr, node0_addr, origin_coords, 5, 0);
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
        nodes[2].node.recent_requests.contains_key(&4848),
        "configured private lookup should still use reply-learned fallback"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_reply_learned_forwards_lookup_fanout_despite_tree_match() {
    // Topology: node0 asks node1 for node4. Node1 has a tree/bloom route via
    // node2 and a live non-tree neighbor node3. Reply-learned forwarding must
    // use both so one stale candidate cannot blackhole first-contact lookup.
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
    let request = LookupRequest::new(4444, node4_addr, node0_addr, origin_coords, 5, 0);
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
        nodes[2].node.recent_requests.contains_key(&4444),
        "tree/bloom match should receive the forwarded lookup"
    );
    assert!(
        nodes[3].node.recent_requests.contains_key(&4444),
        "non-tree peer should also receive reply-learned fanout"
    );
    assert!(
        !nodes[0].node.recent_requests.contains_key(&4444),
        "transit fanout must not echo lookup requests to the originator"
    );

    cleanup_nodes(&mut nodes).await;
}
