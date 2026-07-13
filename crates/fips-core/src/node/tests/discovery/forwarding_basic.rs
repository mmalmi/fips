use super::*;

#[tokio::test]
async fn test_request_forwarding_two_node() {
    // Set up a two-node topology: node0 — node1
    // Send a LookupRequest from node0 targeting node1's address.
    // Node1 should receive the forwarded request.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;

    let node0_addr = *nodes[0].node.node_addr();
    let target = *nodes[1].node.node_addr(); // target node1 (in bloom filters)
    let root = make_node_addr(0);

    let coords = TreeCoordinate::from_addrs(vec![node0_addr, root]).unwrap();
    let request = LookupRequest::new(42, target, node0_addr, coords, 5, 0);
    let payload = &request.encode()[1..];

    // Handle on node0 as if we received it from outside
    nodes[0]
        .node
        .handle_lookup_request(&node0_addr, payload)
        .await;

    // Process packets — node1 should receive the forwarded request
    tokio::time::sleep(Duration::from_millis(50)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(
        count > 0,
        "Expected forwarded LookupRequest to arrive at node 1"
    );

    // Node1 should have recorded the request
    assert!(
        nodes[1].node.recent_requests.contains_key(&42),
        "Node 1 should have recorded the forwarded request"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_request_target_found_generates_response() {
    // Set up a two-node topology: node0 — node1
    // Node0 initiates a lookup targeting node1.
    // Node1 receives, detects it's the target, generates a LookupResponse.
    // Response routes back to node0 which caches the coordinates.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;

    let node1_addr = *nodes[1].node.node_addr();

    // Node0 initiates lookup (doesn't record in recent_requests)
    nodes[0].node.initiate_lookup(&node1_addr, 5).await;

    // Process packets in rounds to allow request + response
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    // Node0 should have cached node1's route (it originated the request)
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(
        nodes[0].node.coord_cache().contains(&node1_addr, now_ms),
        "Node 0 should have cached node 1's route from LookupResponse"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_request_three_node_chain() {
    // Topology: node0 — node1 — node2
    // Node0 initiates a lookup targeting node2.
    // Request should propagate: node0 → node1 → node2.
    // Node2 generates response, reverse-path: node2 → node1 → node0.
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;

    let node2_addr = *nodes[2].node.node_addr();
    let node2_pubkey = nodes[2].node.identity().pubkey_full();

    // Pre-populate node0's identity_cache with node2's identity
    // (in production, DNS resolution or prior handshake would do this)
    nodes[0].node.register_identity(node2_addr, node2_pubkey);

    // Node0 initiates lookup (doesn't record in recent_requests)
    nodes[0].node.initiate_lookup(&node2_addr, 8).await;

    // Wait for the observable end state rather than assuming a fixed number
    // of packet turns. Native crypto completions may be delayed by other
    // parallel full-suite tests.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while (nodes[1].node.recent_requests.is_empty()
        || nodes[2].node.recent_requests.is_empty()
        || !nodes[0]
            .node
            .coord_cache()
            .contains(&node2_addr, Node::now_ms()))
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
        process_available_packets(&mut nodes).await;
    }

    // Node1 should have been a transit node (has the request_id in recent_requests)
    assert!(
        !nodes[1].node.recent_requests.is_empty(),
        "Node 1 should have recorded the forwarded request"
    );

    // Node2 should have received the request (it's the target)
    assert!(
        !nodes[2].node.recent_requests.is_empty(),
        "Node 2 should have received the request"
    );

    // Node0 should have cached node2's route
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(
        nodes[0].node.coord_cache().contains(&node2_addr, now_ms),
        "Node 0 should have cached node 2's route through 3-node chain"
    );

    cleanup_nodes(&mut nodes).await;
}
