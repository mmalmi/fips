use super::*;

// === Peer removal stops routing through removed peer ===

/// After removing a peer from a converged chain, routing to destinations
/// previously reachable through that peer should fail.
///
/// Chain: 0 -- 1 -- 2 -- 3. Remove node 2 from node 1's perspective.
/// Node 0 should no longer be able to route to node 3.
#[tokio::test]
async fn test_routing_stops_after_peer_removal() {
    use crate::protocol::{Disconnect, DisconnectReason};

    let edges = vec![(0, 1), (1, 2), (2, 3)];
    let mut nodes = run_tree_test(4, &edges, false).await;
    verify_tree_convergence(&nodes);

    let _node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let node3_addr = *nodes[3].node.node_addr();

    // Inject coordinates so routing works before removal
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let all_coords: Vec<(NodeAddr, crate::tree::TreeCoordinate)> = nodes
        .iter()
        .map(|tn| {
            (
                *tn.node.node_addr(),
                tn.node.tree_state().my_coords().clone(),
            )
        })
        .collect();

    for node in &mut nodes {
        for (addr, coords) in &all_coords {
            if addr != node.node.node_addr() {
                node.node
                    .coord_cache_mut()
                    .insert(*addr, coords.clone(), now_ms);
            }
        }
    }

    // Verify routing works before removal: node 0 → node 3
    let addr_index = build_addr_index(&nodes);
    match simulate_forwarding(&mut nodes, &addr_index, 0, 3) {
        ForwardResult::Delivered(_) => {}
        other => panic!("Expected delivery before removal, got {:?}", other),
    }

    // Node 2 sends Disconnect to node 1
    let disconnect = Disconnect::new(DisconnectReason::Shutdown);
    let plaintext = disconnect.encode();
    nodes[2]
        .node
        .send_dataplane_fmp_link_plaintext(&node1_addr, &plaintext, false)
        .await
        .expect("Failed to send disconnect");

    // Process disconnect and let bloom filters reconverge
    drain_all_packets(&mut nodes, false).await;

    // Verify node 1 removed node 2
    assert!(
        nodes[1].node.get_peer(&node2_addr).is_none(),
        "Node 1 should have removed node 2"
    );

    // Bloom filter check: node 0's peer (node 1) should no longer
    // advertise node 3 as reachable
    let node0_reaches_node3 = nodes[0]
        .node
        .peers()
        .any(|peer| peer.may_reach(&node3_addr));
    assert!(
        !node0_reaches_node3,
        "Node 0 should not see node 3 as reachable after partition"
    );

    // Routing from node 0 to node 3 should now fail: no bloom filter hit.
    // Greedy tree routing may still have stale coords cached, but without
    // bloom filter hits, routing should stop at node 1 (which lost its
    // peer to the other side). If stale coords exist, greedy routing could
    // still attempt forwarding — but the self-distance check prevents loops.
    // Either NoRoute or Loop-with-stale-coords is acceptable here; what
    // matters is that delivery does NOT succeed.
    match simulate_forwarding(&mut nodes, &addr_index, 0, 3) {
        ForwardResult::NoRoute { .. } => {} // Expected: can't reach node 3
        ForwardResult::Loop { .. } => {}    // Also acceptable: stale coords cause loop detection
        ForwardResult::Delivered(hops) => {
            panic!(
                "Should NOT deliver after partition, but got delivery in {} hops",
                hops
            );
        }
    }

    // But routing within the same component still works: node 2 → node 3
    match simulate_forwarding(&mut nodes, &addr_index, 2, 3) {
        ForwardResult::Delivered(_) => {}
        other => panic!("Expected delivery within component, got {:?}", other),
    }

    cleanup_nodes(&mut nodes).await;
}

// === Bloom-filter-only transit routing (no globally injected coords) ===

/// Nonroot transit routing needs destination coordinates, even with a Bloom hit.
/// Chain: 0 -- 1 -- 2 -- 3. Direct adjacency must still work without a cache entry.
#[tokio::test]
async fn test_routing_bloom_only_transit() {
    let edges = vec![(0, 1), (1, 2), (2, 3)];
    let mut nodes = run_tree_test(4, &edges, false).await;
    verify_tree_convergence(&nodes);

    // The current root has a valid local ancestry hint without cached coords.
    // Reverse this same chain if necessary to test a nonroot destination.
    let destination_was_root = nodes[3].node.node_addr() == nodes[3].node.tree_state().root();
    eprintln!("transit cache precondition: destination_was_root={destination_was_root}");
    if destination_was_root {
        nodes.reverse();
    }
    let node3_addr = *nodes[3].node.node_addr();
    let node3_coords = nodes[3].node.tree_state().my_coords().clone();
    assert_ne!(&node3_addr, nodes[1].node.tree_state().root());
    assert!(nodes[1].node.get_peer(&node3_addr).is_none());
    assert!(nodes[2].node.get_peer(&node3_addr).is_some());
    assert!(
        nodes[1]
            .node
            .peers
            .values()
            .any(|peer| peer.may_reach(&node3_addr))
    );

    // Convergence can legitimately cache ancestor coordinates. Establish only
    // the destination-cache precondition; keep the real links and filters.
    for transit in &mut nodes[1..=2] {
        transit.node.coord_cache_mut().remove(&node3_addr);
        assert!(
            !transit
                .node
                .coord_cache()
                .contains(&node3_addr, Node::now_ms())
        );
    }
    nodes[0]
        .node
        .coord_cache_mut()
        .insert(node3_addr, node3_coords.clone(), Node::now_ms());
    assert!(nodes[0].node.find_next_hop(&node3_addr).is_some());
    assert!(
        nodes[1].node.find_next_hop(&node3_addr).is_none(),
        "nonroot transit needs destination coords for loop prevention"
    );

    // Counterexample: the same transit becomes routable with genuine coords,
    // and loses that route again when only this cache entry is removed.
    nodes[1]
        .node
        .coord_cache_mut()
        .insert(node3_addr, node3_coords, Node::now_ms());
    assert!(nodes[1].node.find_next_hop(&node3_addr).is_some());
    nodes[1].node.coord_cache_mut().remove(&node3_addr);
    assert!(nodes[1].node.find_next_hop(&node3_addr).is_none());
    assert_eq!(
        nodes[2]
            .node
            .find_next_hop(&node3_addr)
            .map(|peer| *peer.node_addr()),
        Some(node3_addr),
        "direct peer routing does not require cached destination coords"
    );
    cleanup_nodes(&mut nodes).await;
}

/// 100-node routing: verify that with coords cached ONLY at the source,
/// multi-hop forwarding still works because each transit node either has
/// the destination as a direct peer OR needs coords to break bloom filter
/// ties.
///
/// This test reveals the boundary: in a converged network, bloom filter
/// routing needs dest_coords at each hop for loop-free forwarding through
/// non-adjacent nodes. Direct peer adjacency handles the last hop.
#[tokio::test]
async fn test_routing_source_only_coords_100_nodes() {
    let _guard = lock_large_network_test().await;

    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;

    let edges = generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, false).await;
    verify_tree_convergence(&nodes);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Collect all coords for injection
    let all_coords: Vec<(NodeAddr, crate::tree::TreeCoordinate)> = nodes
        .iter()
        .map(|tn| {
            (
                *tn.node.node_addr(),
                tn.node.tree_state().my_coords().clone(),
            )
        })
        .collect();

    let addr_index = build_addr_index(&nodes);

    // Test: for each pair, inject dest coords ONLY at the source.
    // Count how many pairs can be delivered vs fail.
    let mut source_only_delivered = 0usize;
    let mut source_only_failed = 0usize;
    let mut total_pairs = 0usize;

    // Test a sample of pairs (all pairs would be expensive)
    let sample_pairs: Vec<(usize, usize)> = (0..NUM_NODES)
        .step_by(10)
        .flat_map(|s| {
            (0..NUM_NODES)
                .step_by(10)
                .filter(move |&d| d != s)
                .map(move |d| (s, d))
        })
        .collect();

    for &(src, dst) in &sample_pairs {
        total_pairs += 1;

        // Clear ALL coord caches
        for node in &mut nodes {
            node.node.coord_cache_mut().clear();
        }

        // Inject dest coords ONLY at the source
        let (dest_addr, dest_coords) = &all_coords[dst];
        nodes[src]
            .node
            .coord_cache_mut()
            .insert(*dest_addr, dest_coords.clone(), now_ms);

        match simulate_forwarding(&mut nodes, &addr_index, src, dst) {
            ForwardResult::Delivered(_) => source_only_delivered += 1,
            ForwardResult::NoRoute { .. } => source_only_failed += 1,
            ForwardResult::Loop { .. } => {
                panic!(
                    "Routing loop detected with source-only coords: {} -> {}",
                    src, dst
                );
            }
        }
    }

    eprintln!(
        "\n  === Source-Only Coords Routing ({} nodes) ===",
        NUM_NODES
    );
    eprintln!(
        "  Pairs: {} | Delivered: {} | Failed: {} | Delivery rate: {:.1}%",
        total_pairs,
        source_only_delivered,
        source_only_failed,
        source_only_delivered as f64 / total_pairs as f64 * 100.0
    );

    // With source-only coords, only single-hop (direct peer) destinations
    // are guaranteed to be delivered. Multi-hop destinations fail at the
    // first transit node that doesn't have dest_coords cached. This
    // confirms the protocol's design: SessionSetup MUST carry coords
    // to warm transit router caches for multi-hop delivery.
    assert!(
        source_only_delivered > 0,
        "At least some direct-peer pairs should be delivered"
    );

    // Now compare: inject coords at ALL nodes (full cache) and verify 100%
    for node in &mut nodes {
        for (addr, coords) in &all_coords {
            if addr != node.node.node_addr() {
                node.node
                    .coord_cache_mut()
                    .insert(*addr, coords.clone(), now_ms);
            }
        }
    }

    let mut full_cache_failures = 0usize;
    for &(src, dst) in &sample_pairs {
        match simulate_forwarding(&mut nodes, &addr_index, src, dst) {
            ForwardResult::Delivered(_) => {}
            _ => full_cache_failures += 1,
        }
    }
    assert_eq!(
        full_cache_failures, 0,
        "With full coord caches, all pairs should be delivered"
    );

    cleanup_nodes(&mut nodes).await;
}
