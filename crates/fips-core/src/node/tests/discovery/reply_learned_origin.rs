use super::*;

#[tokio::test]
async fn test_reply_learned_forwards_lookup_to_direct_non_tree_target() {
    // Topology: node0 -- node1 -- node2. Then make node2 a direct, sendable
    // peer of node1 that is no longer in node1's tree view. This models a
    // transit node that can reach the target directly even though the target
    // is not a tree neighbor for reply-learned flood forwarding.
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

    let origin_coords = TreeCoordinate::from_addrs(vec![node0_addr, node1_addr]).unwrap();
    let request = LookupRequest::new(4242, node2_addr, node0_addr, origin_coords, 5, 0);
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
        nodes[2].node.recent_requests.contains_key(&4242),
        "direct non-tree target should receive the forwarded lookup"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_reply_learned_lookup_does_not_stop_at_stale_direct_target() {
    // Topology: node0 -- node1, with node1 also linked to node2 (the target)
    // and node3 (a fallback neighbor). A stale direct target should remain
    // probeable, but it must not be the exclusive route for lookup.
    let edges = vec![(0, 1), (1, 2), (1, 3)];
    let mut nodes = run_tree_test(4, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let node3_addr = *nodes[3].node.node_addr();

    nodes[1].node.config.node.routing.mode = RoutingMode::ReplyLearned;
    nodes[1].node.tree_state_mut().remove_peer(&node2_addr);
    nodes[1].node.tree_state_mut().become_root();
    nodes[1]
        .node
        .get_peer_mut(&node2_addr)
        .expect("target direct peer")
        .mark_stale();
    assert!(
        nodes[1]
            .node
            .peers
            .get(&node2_addr)
            .is_some_and(|peer| peer.can_send() && !peer.is_healthy()),
        "target should remain probeable but not healthy"
    );
    assert!(
        nodes[1]
            .node
            .peers
            .get(&node3_addr)
            .is_some_and(|peer| peer.is_healthy()),
        "fallback neighbor should be healthy"
    );

    let origin_coords = TreeCoordinate::from_addrs(vec![node0_addr, node1_addr]).unwrap();
    let request = LookupRequest::new(4343, node2_addr, node0_addr, origin_coords, 5, 0);
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
        !nodes[2].node.recent_requests.contains_key(&4343),
        "stale direct target should not consume lookup as the only route"
    );
    assert!(
        nodes[3].node.recent_requests.contains_key(&4343),
        "healthy fallback neighbor should still receive the lookup"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_reply_learned_initiates_lookup_to_sendable_non_tree_peer() {
    // A reply-learned origin may have a valid direct peer that is not in its
    // current tree view. Discovery must still ask that peer when no bloom/tree
    // route is available, or stale sessions can remain pending forever.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    nodes[0].node.config.node.routing.mode = RoutingMode::ReplyLearned;
    nodes[0].node.tree_state_mut().remove_peer(&node1_addr);
    nodes[0].node.tree_state_mut().become_root();
    assert!(
        nodes[0]
            .node
            .peers
            .get(&node1_addr)
            .is_some_and(|peer| peer.can_send()),
        "node1 should remain a direct sendable peer"
    );
    assert!(
        !nodes[0].node.is_tree_peer(&node1_addr),
        "node1 should not be a tree peer in this regression fixture"
    );

    let target = make_node_addr(0x55);
    let sent = nodes[0].node.initiate_lookup(&target, 5).await;
    assert_eq!(
        sent, 1,
        "non-tree sendable peer should receive fallback lookup"
    );

    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    assert_eq!(
        nodes[1].node.recent_requests.len(),
        1,
        "fallback lookup should arrive at the non-tree peer"
    );
    let recent = nodes[1].node.recent_requests.values().next().unwrap();
    assert_eq!(recent.from_peer, node0_addr);

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_reply_learned_dns_target_uses_authenticated_physical_adjacency() {
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);

    let adjacent_addr = *nodes[1].node.node_addr();
    let adjacent_npub = nodes[1].node.identity().npub();
    nodes[0].node.config.node.routing.mode = RoutingMode::ReplyLearned;
    nodes[0].node.config.node.discovery.nostr.enabled = true;
    nodes[0].node.config.node.discovery.nostr.policy = crate::config::NostrDiscoveryPolicy::Open;
    nodes[0].node.tree_state_mut().remove_peer(&adjacent_addr);
    nodes[0].node.tree_state_mut().become_root();
    nodes[0]
        .node
        .update_peers(vec![crate::config::PeerConfig {
            npub: adjacent_npub,
            alias: None,
            addresses: Vec::new(),
            connect_policy: crate::config::ConnectPolicy::AutoConnect,
            auto_reconnect: true,
            discovery_fallback_transit: true,
        }])
        .await
        .expect("configure authenticated transit");
    assert!(
        nodes[0]
            .node
            .peers
            .get(&adjacent_addr)
            .is_some_and(|peer| peer.can_send()),
        "fixture requires one authenticated physical adjacency"
    );

    let ambient = Identity::generate();
    nodes[0]
        .node
        .register_identity(*ambient.node_addr(), ambient.pubkey_full());
    assert_eq!(
        nodes[0].node.initiate_lookup(ambient.node_addr(), 5).await,
        0,
        "an ambient learned identity must not broaden open-discovery fallback"
    );

    let resolved = Identity::generate();
    nodes[0]
        .node
        .register_dns_identity(*resolved.node_addr(), resolved.pubkey_full());
    assert_eq!(
        nodes[0].node.initiate_lookup(resolved.node_addr(), 5).await,
        1,
        "a user-resolved .fips target should use configured transit"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_reply_learned_endpoint_target_uses_configured_transit() {
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);

    let transit_addr = *nodes[1].node.node_addr();
    let transit_npub = nodes[1].node.identity().npub();
    nodes[0].node.config.node.routing.mode = RoutingMode::ReplyLearned;
    nodes[0].node.config.node.discovery.nostr.enabled = true;
    nodes[0].node.config.node.discovery.nostr.policy = crate::config::NostrDiscoveryPolicy::Open;
    nodes[0].node.tree_state_mut().remove_peer(&transit_addr);
    nodes[0].node.tree_state_mut().become_root();
    nodes[0]
        .node
        .update_peers(vec![crate::config::PeerConfig {
            npub: transit_npub,
            alias: None,
            addresses: Vec::new(),
            connect_policy: crate::config::ConnectPolicy::AutoConnect,
            auto_reconnect: true,
            discovery_fallback_transit: true,
        }])
        .await
        .expect("configure authenticated transit");

    let target = Identity::generate();
    nodes[0]
        .node
        .register_endpoint_identity(*target.node_addr(), target.pubkey_full());
    assert_eq!(
        nodes[0].node.initiate_lookup(target.node_addr(), 5).await,
        1,
        "a destination selected by the embedding application must route by identity through configured transit"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_reply_learned_initiates_lookup_fanout_despite_tree_match() {
    // Topology: node0 has a normal tree path toward node2 through node1, and
    // a live non-tree neighbor node3. Reply-learned discovery must ask node3
    // too, because real meshes can have stale tree/bloom candidates while a
    // non-tree neighbor has the working NAT path.
    let edges = vec![(0, 1), (1, 2), (0, 3)];
    let mut nodes = run_tree_test(4, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let node3_addr = *nodes[3].node.node_addr();

    nodes[0].node.config.node.routing.mode = RoutingMode::ReplyLearned;
    assert!(
        nodes[0]
            .node
            .peers
            .get(&node1_addr)
            .is_some_and(|peer| peer.may_reach(&node2_addr)),
        "node1 should be the tree/bloom match for node2"
    );

    nodes[0].node.tree_state_mut().remove_peer(&node3_addr);
    nodes[0].node.tree_state_mut().become_root();
    assert!(
        nodes[0]
            .node
            .peers
            .get(&node3_addr)
            .is_some_and(|peer| peer.can_send()),
        "node3 should remain a direct sendable peer"
    );
    assert!(
        !nodes[0].node.is_tree_peer(&node3_addr),
        "node3 should not be a tree peer in this regression fixture"
    );

    let sent = nodes[0].node.initiate_lookup(&node2_addr, 5).await;
    assert_eq!(
        sent, 2,
        "reply-learned lookup should include the tree match and live non-tree peer"
    );

    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    assert!(
        nodes[3]
            .node
            .recent_requests
            .values()
            .any(|request| request.from_peer == node0_addr),
        "non-tree peer should receive reply-learned fanout despite tree match"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_reply_learned_origin_fanout_uses_only_explicit_bootstrap_transit_peer() {
    // Topology: node0 has a normal tree path toward node2 through node1, and
    // a live non-tree neighbor node3 that was learned through a bootstrap
    // transport. Bootstrap/open-discovery peers are useful direct targets, but
    // they must not receive every private fallback lookup as ambient transit.
    let edges = vec![(0, 1), (1, 2), (0, 3)];
    let mut nodes = run_tree_test(4, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let node3_addr = *nodes[3].node.node_addr();

    nodes[0].node.config.node.routing.mode = RoutingMode::ReplyLearned;
    assert!(
        nodes[0]
            .node
            .peers
            .get(&node1_addr)
            .is_some_and(|peer| peer.may_reach(&node2_addr)),
        "node1 should be the tree/bloom match for node2"
    );

    nodes[0].node.tree_state_mut().remove_peer(&node3_addr);
    nodes[0].node.tree_state_mut().become_root();
    let bootstrap_transport = crate::transport::TransportId::new(9_003);
    nodes[0]
        .node
        .peers
        .get_mut(&node3_addr)
        .expect("node3 should be an active peer")
        .set_current_addr(
            bootstrap_transport,
            &crate::transport::TransportAddr::from_string("bootstrap/node3"),
        );
    nodes[0].node.bootstrap_transports.mark(bootstrap_transport);
    assert!(
        nodes[0]
            .node
            .peers
            .get(&node3_addr)
            .is_some_and(|peer| peer.can_send()),
        "node3 should remain a direct sendable bootstrap peer"
    );
    assert!(
        !nodes[0].node.is_tree_peer(&node3_addr),
        "node3 should not be a tree peer in this regression fixture"
    );

    let sent = nodes[0].node.initiate_lookup(&node2_addr, 5).await;
    assert_eq!(
        sent, 1,
        "reply-learned lookup should not spray bootstrap transit peers"
    );

    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    assert!(
        nodes[2].node.recent_requests.values().any(|request| {
            request.from_peer == node1_addr || request.from_peer == *nodes[0].node.node_addr()
        }),
        "tree path should still deliver the lookup"
    );
    assert!(
        nodes[3].node.recent_requests.is_empty(),
        "bootstrap transit peer should not receive private fallback lookup"
    );

    let mut configured_peers = nodes[0].node.config.peers.clone();
    configured_peers.push(crate::config::PeerConfig {
        npub: nodes[3].node.identity().npub(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    nodes[0]
        .node
        .update_peers(configured_peers)
        .await
        .expect("configured bootstrap transit peer update");

    let sent = nodes[0].node.initiate_lookup(&node2_addr, 5).await;
    assert_eq!(
        sent, 2,
        "an explicitly configured NAT-traversed peer must remain usable as fallback transit"
    );

    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    assert!(
        nodes[3]
            .node
            .recent_requests
            .values()
            .any(|request| request.from_peer == *nodes[0].node.node_addr()),
        "the configured bootstrap peer should receive fallback discovery"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_reply_learned_origin_fanout_skips_disabled_transit_peer() {
    // A live non-tree neighbor may be useful as a direct target while still
    // being unsuitable as ambient fallback transit. This is the case for peers
    // learned from public/open discovery or a recent-peer cache.
    let edges = vec![(0, 1), (1, 2), (0, 3)];
    let mut nodes = run_tree_test(4, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let node3_addr = *nodes[3].node.node_addr();

    nodes[0].node.config.node.routing.mode = RoutingMode::ReplyLearned;
    assert!(
        nodes[0]
            .node
            .peers
            .get(&node1_addr)
            .is_some_and(|peer| peer.may_reach(&node2_addr)),
        "node1 should be the tree/bloom match for node2"
    );

    nodes[0].node.tree_state_mut().remove_peer(&node3_addr);
    nodes[0].node.tree_state_mut().become_root();
    nodes[0]
        .node
        .set_discovery_fallback_transit_allowed(node3_addr, false);
    assert!(
        nodes[0]
            .node
            .peers
            .get(&node3_addr)
            .is_some_and(|peer| peer.can_send()),
        "node3 should remain a direct sendable peer"
    );
    assert!(
        !nodes[0].node.is_tree_peer(&node3_addr),
        "node3 should not be a tree peer in this regression fixture"
    );

    let sent = nodes[0].node.initiate_lookup(&node2_addr, 5).await;
    assert_eq!(
        sent, 1,
        "reply-learned lookup should not spray fallback-disabled transit peers"
    );

    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    assert!(
        nodes[2].node.recent_requests.values().any(|request| {
            request.from_peer == node1_addr || request.from_peer == *nodes[0].node.node_addr()
        }),
        "tree path should still deliver the lookup"
    );
    assert!(
        nodes[3].node.recent_requests.is_empty(),
        "fallback-disabled transit peer should not receive private fallback lookup"
    );

    cleanup_nodes(&mut nodes).await;
}
