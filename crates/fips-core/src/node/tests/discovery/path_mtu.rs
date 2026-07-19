use super::*;

#[tokio::test]
async fn test_response_path_mtu_two_node() {
    // Two-node topology: node0 — node1
    // Node0 initiates lookup for node1. node1 is the target and generates
    // the response: send_lookup_response folds in node1's own outgoing-link
    // MTU before sending, so path_mtu reflects the target-edge link
    // constraint (the test transport MTU, 1280) even with no transit hops.
    // Without that target-edge fold, a 2-node lookup would leave path_mtu
    // at u16::MAX since no transit min-fold runs — that's the gap closed
    // alongside the configured-peer seed in the B3 follow-up.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;

    let node1_addr = *nodes[1].node.node_addr();

    nodes[0].node.initiate_lookup(&node1_addr, 5).await;

    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    assert!(
        nodes[0].node.coord_cache().contains(&node1_addr, now_ms),
        "Node 0 should have cached node 1's route"
    );

    let entry = nodes[0].node.coord_cache().get_entry(&node1_addr).unwrap();
    let path_mtu = entry
        .path_mtu()
        .expect("path_mtu should be set from discovery");
    assert_eq!(
        path_mtu, 1280,
        "Two-node path_mtu should be the target-edge link MTU (1280 in tests)"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_apply_outgoing_link_mtu_to_response_unknown_peer_noop() {
    // When next_hop is not a directly-connected peer (no entry in
    // self.peers), apply_outgoing_link_mtu_to_response is a no-op and the
    // response's path_mtu is left unchanged. Pins the early-return path.
    let node = make_node();
    let unknown = make_node_addr(0x99);

    let coords = TreeCoordinate::from_addrs(vec![unknown, make_node_addr(0)]).unwrap();
    let identity = Identity::generate();
    let proof_data = LookupResponse::proof_bytes(1, &unknown, &coords);
    let proof = identity.sign(&proof_data);
    let mut response = LookupResponse::new(1, unknown, coords, proof);
    response.path_mtu = 1500;

    node.apply_outgoing_link_mtu_to_response(&mut response, &unknown);
    assert_eq!(
        response.path_mtu, 1500,
        "Unknown next_hop must leave path_mtu untouched"
    );
}

#[tokio::test]
async fn test_response_path_mtu_three_node_chain() {
    // Topology: node0 — node1 — node2
    // Node0 initiates lookup for node2. The response travels node2→node1→node0.
    // Node1 is a transit node and applies path_mtu = min(u16::MAX, link_mtu).
    // With test transport MTU of 1280, the final path_mtu at node0 should be 1280.
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;

    let node2_addr = *nodes[2].node.node_addr();
    let node2_pubkey = nodes[2].node.identity().pubkey_full();

    nodes[0].node.register_identity(node2_addr, node2_pubkey);

    nodes[0].node.initiate_lookup(&node2_addr, 8).await;

    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        process_available_packets(&mut nodes).await;
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    assert!(
        nodes[0].node.coord_cache().contains(&node2_addr, now_ms),
        "Node 0 should have cached node 2's route"
    );

    // Node1 is transit and applies min(u16::MAX, 1280) = 1280
    let entry = nodes[0].node.coord_cache().get_entry(&node2_addr).unwrap();
    let path_mtu = entry
        .path_mtu()
        .expect("path_mtu should be set from discovery");
    assert_eq!(
        path_mtu, 1280,
        "Three-node chain path_mtu should reflect transit node's transport MTU (1280)"
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Unit Tests — Cache Entry path_mtu
// ============================================================================

#[tokio::test]
async fn test_cache_entry_path_mtu_stored() {
    // Verify that insert_with_path_mtu stores the path_mtu in the cache entry
    let mut node = make_node();
    let target = make_node_addr(0xBB);

    let coords = TreeCoordinate::from_addrs(vec![target, make_node_addr(0)]).unwrap();

    let now_ms = 1000u64;
    node.coord_cache_mut()
        .insert_with_path_mtu(target, coords, now_ms, 1280);

    let entry = node.coord_cache().get_entry(&target).unwrap();
    assert_eq!(entry.path_mtu(), Some(1280));
}

#[tokio::test]
async fn test_cache_entry_no_path_mtu_from_regular_insert() {
    // Verify that regular insert() does not set path_mtu
    let mut node = make_node();
    let target = make_node_addr(0xBB);

    let coords = TreeCoordinate::from_addrs(vec![target, make_node_addr(0)]).unwrap();

    let now_ms = 1000u64;
    node.coord_cache_mut().insert(target, coords, now_ms);

    let entry = node.coord_cache().get_entry(&target).unwrap();
    assert_eq!(entry.path_mtu(), None);
}

// ============================================================================
// Unit Tests — LookupRequest min_mtu field
// ============================================================================

#[tokio::test]
async fn test_request_min_mtu_preserved_through_encode_decode() {
    // Verify min_mtu survives encode/decode in the handler test context
    let target = make_node_addr(0xBB);
    let origin = make_node_addr(0xCC);
    let coords = TreeCoordinate::from_addrs(vec![origin, make_node_addr(0)]).unwrap();

    let request = LookupRequest::new(100, target, origin, coords, 5, 1386);
    let encoded = request.encode();
    let decoded = LookupRequest::decode(&encoded[1..]).unwrap();
    assert_eq!(decoded.min_mtu, 1386);
}

// ============================================================================
// Unit Tests — LookupResponse path_mtu in originator handling
// ============================================================================

#[tokio::test]
async fn test_originator_stores_path_mtu_in_cache() {
    // Verify that the originator stores path_mtu from the response in coord_cache
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();

    node.register_identity(target, target_identity.pubkey_full());

    let proof_data = LookupResponse::proof_bytes(800, &target, &coords);
    let proof = target_identity.sign(&proof_data);

    let mut response = LookupResponse::new(800, target, coords.clone(), proof);
    // Simulate transit having reduced path_mtu
    response.path_mtu = 1280;

    let payload = &response.encode()[1..];

    node.handle_lookup_response(&from, payload).await;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    assert!(node.coord_cache().contains(&target, now_ms));

    let entry = node.coord_cache().get_entry(&target).unwrap();
    assert_eq!(
        entry.path_mtu(),
        Some(1280),
        "Originator should store path_mtu from LookupResponse in cache"
    );
}

#[tokio::test]
async fn test_originator_lookup_response_keeps_tighter_path_mtu() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();
    let target_fips = crate::FipsAddress::from_node_addr(&target);

    node.register_identity(target, target_identity.pubkey_full());
    node.coord_cache_mut()
        .insert_with_path_mtu(target, coords.clone(), Node::now_ms(), 1280);
    node.path_mtu_lookup_insert(target_fips, 1280);

    let proof_data = LookupResponse::proof_bytes(801, &target, &coords);
    let proof = target_identity.sign(&proof_data);
    let mut response = LookupResponse::new(801, target, coords, proof);
    response.path_mtu = 1500;

    node.handle_lookup_response(&from, &response.encode()[1..])
        .await;

    assert_eq!(
        node.path_mtu_lookup_get(&target_fips),
        Some(1280),
        "LookupResponse must not loosen the TUN path-MTU clamp"
    );
    assert_eq!(
        node.coord_cache().get_entry(&target).unwrap().path_mtu(),
        Some(1280),
        "LookupResponse must not loosen the coordinate cache path MTU"
    );
}
