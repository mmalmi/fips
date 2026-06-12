use super::*;

#[tokio::test]
async fn test_routing_chain_topology() {
    // Build a 4-node chain: 0 -- 1 -- 2 -- 3
    let mut nodes = vec![
        make_test_node().await,
        make_test_node().await,
        make_test_node().await,
        make_test_node().await,
    ];

    // Connect the chain
    initiate_handshake(&mut nodes, 0, 1).await;
    initiate_handshake(&mut nodes, 1, 2).await;
    initiate_handshake(&mut nodes, 2, 3).await;

    // Converge tree and bloom filters
    drain_all_packets(&mut nodes, false).await;

    // Verify tree convergence
    let root = nodes.iter().map(|n| *n.node.node_addr()).min().unwrap();
    for tn in &nodes {
        assert_eq!(*tn.node.tree_state().root(), root, "Tree not converged");
    }

    // Populate coord caches: each node caches the far-end node's coords
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let node3_addr = *nodes[3].node.node_addr();
    let node3_coords = nodes[3].node.tree_state().my_coords().clone();
    nodes[0]
        .node
        .coord_cache_mut()
        .insert(node3_addr, node3_coords, now_ms);

    let node0_addr = *nodes[0].node.node_addr();
    let node0_coords = nodes[0].node.tree_state().my_coords().clone();
    nodes[3]
        .node
        .coord_cache_mut()
        .insert(node0_addr, node0_coords, now_ms);

    // Node 0 should be able to route toward node 3.
    // The next hop should be node 1 (only peer of node 0).
    let node1_addr = *nodes[1].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let hop = nodes[0].node.find_next_hop(&node3_addr);
    assert!(hop.is_some(), "Node 0 should find route to node 3");
    assert_eq!(
        hop.unwrap().node_addr(),
        &node1_addr,
        "Node 0's next hop to node 3 should be node 1"
    );

    // Node 3 should route toward node 0 via node 2.
    let hop = nodes[3].node.find_next_hop(&node0_addr);
    assert!(hop.is_some(), "Node 3 should find route to node 0");
    assert_eq!(
        hop.unwrap().node_addr(),
        &node2_addr,
        "Node 3's next hop to node 0 should be node 2"
    );
}

#[tokio::test]
async fn test_routing_bloom_preferred_over_tree() {
    // Build a 3-node triangle: 0 -- 1, 0 -- 2, 1 -- 2
    let mut nodes = vec![
        make_test_node().await,
        make_test_node().await,
        make_test_node().await,
    ];

    initiate_handshake(&mut nodes, 0, 1).await;
    initiate_handshake(&mut nodes, 0, 2).await;
    initiate_handshake(&mut nodes, 1, 2).await;

    drain_all_packets(&mut nodes, false).await;

    // Create a destination beyond the network and cache its coords.
    // Place dest as a child of peer2 in the converged tree so bloom
    // filter routing selects peer2 (strictly closer to dest than us).
    let dest = make_node_addr(99);
    let peer2_addr = *nodes[2].node.node_addr();
    let mut dest_path: Vec<NodeAddr> = nodes[2]
        .node
        .tree_state()
        .my_coords()
        .node_addrs()
        .copied()
        .collect();
    dest_path.insert(0, dest);
    let dest_coords = TreeCoordinate::from_addrs(dest_path).unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    nodes[0]
        .node
        .coord_cache_mut()
        .insert(dest, dest_coords, now_ms);

    // Add dest to peer 2's bloom filter (from node 0's perspective)
    let peer2 = nodes[0].node.get_peer_mut(&peer2_addr).unwrap();
    let mut filter = BloomFilter::new();
    filter.insert(&dest);
    peer2.update_filter(filter, 100, 50000);

    // Bloom filter hit with cached coords should route via peer 2.
    let hop = nodes[0].node.find_next_hop(&dest);
    assert!(hop.is_some(), "Should route via bloom filter");
    assert_eq!(
        hop.unwrap().node_addr(),
        &peer2_addr,
        "Should pick peer with bloom filter hit"
    );
}
