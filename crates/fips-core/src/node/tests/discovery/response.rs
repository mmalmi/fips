use super::*;

#[tokio::test]
async fn test_response_decode_error() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    node.handle_lookup_response(&from, &[0x00; 10]).await;
    // No panic, no route cached
    assert!(node.coord_cache().is_empty());
}

#[tokio::test]
async fn test_response_originator_caches_route() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    // Use the target identity's actual node_addr for consistency
    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();

    // Register target identity in cache so verification can find it
    node.register_identity(target, target_identity.pubkey_full());

    // Create a valid response with a real proof signature (includes coords)
    let proof_data = LookupResponse::proof_bytes(555, &target, &coords);
    let proof = target_identity.sign(&proof_data);

    let response = LookupResponse::new(555, target, coords.clone(), proof);
    let payload = &response.encode()[1..]; // skip msg_type

    // No entry in recent_requests for 555 → we're the originator
    assert!(!node.recent_requests.contains_key(&555));

    node.handle_lookup_response(&from, payload).await;

    // Route should be cached in coord_cache
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(node.coord_cache().contains(&target, now_ms));
    assert_eq!(node.coord_cache().get(&target, now_ms).unwrap(), &coords);
}

#[tokio::test]
async fn test_response_transit_learns_target_route() {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    let mut node = Node::new(config).unwrap();
    let from = make_node_addr(0xAA);
    let target = make_node_addr(0xBB);
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();

    // Transit nodes don't verify proofs, so any valid signature suffices
    let proof_data = LookupResponse::proof_bytes(444, &target, &coords);
    let target_identity = Identity::generate();
    let proof = target_identity.sign(&proof_data);

    let response = LookupResponse::new(444, target, coords.clone(), proof);
    let payload = &response.encode()[1..];

    // Simulate being a transit node: record a recent_request for this ID
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    node.recent_requests
        .insert(444, RecentRequest::new(make_node_addr(0xDD), now_ms));

    // Handle response — should try to reverse-path forward to 0xDD
    // (will fail silently since 0xDD is not an actual peer)
    node.handle_lookup_response(&from, payload).await;

    // A following SessionSetup uses this same transit. Retain the coordinates
    // and reverse next hop learned from the response so it does not immediately
    // report CoordsRequired for the route it just discovered.
    let now_ms2 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert_eq!(node.coord_cache().get(&target, now_ms2), Some(&coords));
    let learned = node.learned_route_table_snapshot(now_ms2);
    assert_eq!(learned.destination_count, 1);
    assert_eq!(learned.route_count, 1);
    assert_eq!(learned.destinations[0].destination, target.to_string());
    assert_eq!(learned.destinations[0].routes[0].next_hop, from.to_string());
}

// ============================================================================
// Unit Tests — LookupResponse Proof Verification
// ============================================================================

#[tokio::test]
async fn test_response_proof_verification_success() {
    // Verify that a properly signed response is accepted and cached
    // when the origin has the target's pubkey in identity_cache.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();

    // Register target in identity_cache
    node.register_identity(target, target_identity.pubkey_full());

    // Sign with correct proof_bytes (including coords)
    let proof_data = LookupResponse::proof_bytes(700, &target, &coords);
    let proof = target_identity.sign(&proof_data);

    let response = LookupResponse::new(700, target, coords.clone(), proof);
    let payload = &response.encode()[1..];

    node.handle_lookup_response(&from, payload).await;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(
        node.coord_cache().contains(&target, now_ms),
        "Valid proof should result in cached coords"
    );
    assert_eq!(node.coord_cache().get(&target, now_ms).unwrap(), &coords);
}

#[tokio::test]
async fn test_response_proof_verification_failure() {
    // Verify that a response with a bad signature is discarded.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();

    // Register target in identity_cache
    node.register_identity(target, target_identity.pubkey_full());

    // Sign with a DIFFERENT identity (wrong key)
    let wrong_identity = Identity::generate();
    let proof_data = LookupResponse::proof_bytes(701, &target, &coords);
    let proof = wrong_identity.sign(&proof_data);

    let response = LookupResponse::new(701, target, coords, proof);
    let payload = &response.encode()[1..];

    node.handle_lookup_response(&from, payload).await;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(
        !node.coord_cache().contains(&target, now_ms),
        "Bad signature should NOT result in cached coords"
    );
}

#[tokio::test]
async fn test_response_identity_cache_miss() {
    // Verify that a response is discarded when the origin lacks the
    // target's pubkey in identity_cache (e.g., XK responder before msg3).
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let root = make_node_addr(0xF0);
    let coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();

    // Do NOT register target in identity_cache

    let proof_data = LookupResponse::proof_bytes(702, &target, &coords);
    let proof = target_identity.sign(&proof_data);

    let response = LookupResponse::new(702, target, coords, proof);
    let payload = &response.encode()[1..];

    node.handle_lookup_response(&from, payload).await;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(
        !node.coord_cache().contains(&target, now_ms),
        "identity_cache miss should discard the response"
    );
}

#[tokio::test]
async fn test_response_coord_substitution_detected() {
    // Verify that if the proof was signed with correct coords but
    // different coords are placed in the response, verification fails.
    let mut node = make_node();
    let from = make_node_addr(0xAA);

    let target_identity = Identity::generate();
    let target = *target_identity.node_addr();
    let root = make_node_addr(0xF0);
    let real_coords = TreeCoordinate::from_addrs(vec![target, root]).unwrap();
    let fake_coords = TreeCoordinate::from_addrs(vec![target, make_node_addr(0xEE), root]).unwrap();

    // Register target in identity_cache
    node.register_identity(target, target_identity.pubkey_full());

    // Sign proof with real coords
    let proof_data = LookupResponse::proof_bytes(703, &target, &real_coords);
    let proof = target_identity.sign(&proof_data);

    // But construct the response with FAKE coords
    let response = LookupResponse::new(703, target, fake_coords, proof);
    let payload = &response.encode()[1..];

    node.handle_lookup_response(&from, payload).await;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(
        !node.coord_cache().contains(&target, now_ms),
        "Substituted coords should be detected and response discarded"
    );
}

// ============================================================================
// Unit Tests — RecentRequest Expiry
// ============================================================================
