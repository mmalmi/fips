use super::*;

#[test]
fn recent_discovery_requests_own_reverse_path_dedup_capacity_and_expiry() {
    let mut requests = crate::node::RecentDiscoveryRequests::default();
    let first_peer = make_node_addr(0xA1);
    let second_peer = make_node_addr(0xA2);

    assert!(requests.record_request(7, first_peer, 100, 1).accepted());
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests.get(&7).map(|entry| entry.from_peer),
        Some(first_peer)
    );

    assert!(
        requests
            .record_request(7, second_peer, 101, 1)
            .deduplicated()
    );
    assert_eq!(
        requests.get(&7).map(|entry| entry.from_peer),
        Some(first_peer)
    );

    assert!(requests.record_request(8, second_peer, 102, 1).cache_full());
    assert!(!requests.contains_key(&8));

    assert_eq!(
        requests.claim_response_forward(7),
        crate::node::RecentResponseForward::Forward {
            from_peer: first_peer
        }
    );
    assert_eq!(
        requests.claim_response_forward(7),
        crate::node::RecentResponseForward::AlreadyForwarded
    );
    assert_eq!(
        requests.claim_response_forward(99),
        crate::node::RecentResponseForward::Missing
    );

    requests.insert(9, RecentRequest::new(second_peer, 101));
    requests.purge_expired(10_101, 10_000);
    assert!(!requests.contains_key(&7));
    assert!(requests.contains_key(&9));
}

#[tokio::test]
async fn test_recent_request_expiry() {
    let mut node = make_node();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Insert an old request (11 seconds ago)
    node.recent_requests
        .insert(123, RecentRequest::new(make_node_addr(1), now_ms - 11_000));

    // Insert a recent request
    node.recent_requests
        .insert(456, RecentRequest::new(make_node_addr(2), now_ms));

    assert_eq!(node.recent_requests.len(), 2);

    // Trigger purge via a new lookup request
    let target = make_node_addr(0xBB);
    let origin = make_node_addr(0xCC);
    let coords = TreeCoordinate::from_addrs(vec![origin, make_node_addr(0)]).unwrap();
    let request = LookupRequest::new(789, target, origin, coords, 3, 0);
    let payload = &request.encode()[1..];
    node.handle_lookup_request(&make_node_addr(0xAA), payload)
        .await;

    // Old entry (123) should be purged, recent entry (456) and new entry (789) kept
    assert!(!node.recent_requests.contains_key(&123));
    assert!(node.recent_requests.contains_key(&456));
    assert!(node.recent_requests.contains_key(&789));
}

// ============================================================================
// Integration Tests — Multi-Node Forwarding
// ============================================================================
