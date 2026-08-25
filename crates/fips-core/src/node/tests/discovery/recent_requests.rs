use super::*;

#[test]
fn recent_discovery_requests_own_reverse_path_dedup_capacity_and_expiry() {
    let mut requests = crate::node::RecentDiscoveryRequests::default();
    let first_peer = make_node_addr(0xA1);
    let second_peer = make_node_addr(0xA2);

    let first_target = make_node_addr(0xB1);
    let second_target = make_node_addr(0xB2);
    assert!(
        requests
            .record_request(
                7,
                first_peer,
                first_target,
                100,
                RecentDiscoveryRequestLimits::new(1, 1, 1),
            )
            .accepted()
    );
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests.get(&7).map(|entry| entry.from_peer),
        Some(first_peer)
    );

    assert!(
        requests
            .record_request(
                7,
                second_peer,
                second_target,
                101,
                RecentDiscoveryRequestLimits::new(1, 1, 1),
            )
            .deduplicated()
    );
    assert_eq!(
        requests.get(&7).map(|entry| entry.from_peer),
        Some(first_peer)
    );

    let admission = requests.record_request(
        8,
        second_peer,
        second_target,
        102,
        RecentDiscoveryRequestLimits::new(1, 1, 1),
    );
    assert!(admission.accepted());
    assert!(admission.evicted());
    assert!(!requests.contains_key(&7));
    assert!(requests.contains_key(&8));
    assert_eq!(requests.indexed_len(), requests.len());

    assert_eq!(
        requests.claim_response_forward(8, first_target),
        crate::node::RecentResponseForward::Missing,
        "a response cannot reuse a transit request ID for another target"
    );

    assert_eq!(
        requests.claim_response_forward(8, second_target),
        crate::node::RecentResponseForward::Forward {
            from_peer: second_peer
        }
    );
    assert_eq!(
        requests.claim_response_forward(8, second_target),
        crate::node::RecentResponseForward::AlreadyForwarded
    );
    assert_eq!(
        requests.claim_response_forward(99, first_target),
        crate::node::RecentResponseForward::Missing
    );

    requests.insert(9, RecentRequest::new(second_peer, second_target, 200));
    requests.purge_expired(10_150, 10_000);
    assert!(!requests.contains_key(&8));
    assert!(requests.contains_key(&9));
    assert_eq!(requests.indexed_len(), requests.len());
}

#[test]
fn flooding_peer_pays_for_its_own_reverse_path_admission() {
    let mut requests = crate::node::RecentDiscoveryRequests::default();
    let heavy = make_node_addr(0xA1);
    let light = make_node_addr(0xA2);
    let target = make_node_addr(0xB1);

    assert!(
        requests
            .record_request(
                100,
                light,
                target,
                1,
                RecentDiscoveryRequestLimits::new(4, 2, 1),
            )
            .accepted()
    );
    assert!(
        requests
            .record_request(
                1,
                heavy,
                target,
                2,
                RecentDiscoveryRequestLimits::new(4, 2, 1),
            )
            .accepted()
    );
    assert!(
        requests
            .record_request(
                2,
                heavy,
                target,
                3,
                RecentDiscoveryRequestLimits::new(4, 2, 1),
            )
            .accepted()
    );
    let admission = requests.record_request(
        3,
        heavy,
        target,
        4,
        RecentDiscoveryRequestLimits::new(4, 2, 1),
    );

    assert!(admission.accepted() && admission.evicted());
    assert!(
        requests.contains_key(&100),
        "light peer must retain its response path"
    );
    assert!(!requests.contains_key(&1), "heavy peer's oldest entry pays");
    assert!(requests.contains_key(&3));
    assert_eq!(requests.indexed_len(), requests.len());
}

#[tokio::test]
async fn answering_self_lookups_is_bounded_per_ingress_peer() {
    let mut node = make_node();
    node.discovery_sign_limiter =
        crate::proto::lookup_limits::LookupSignRateLimiter::with_params(2.0, 0.0);
    let noisy = make_node_addr(0xA1);
    let quiet = make_node_addr(0xA2);
    let origin = make_node_addr(0xCC);
    let coords = TreeCoordinate::root(origin);
    let target = *node.node_addr();

    for request_id in 1..=3 {
        let request = LookupRequest::new(request_id, target, origin, coords.clone(), 3, 0);
        node.handle_lookup_request(&noisy, &request.encode()[1..])
            .await;
    }
    assert_eq!(node.stats().discovery.req_target_is_us, 2);
    assert_eq!(node.stats().discovery.req_sign_rate_limited, 1);

    let request = LookupRequest::new(10, target, origin, coords, 3, 0);
    node.handle_lookup_request(&quiet, &request.encode()[1..])
        .await;
    assert_eq!(node.stats().discovery.req_target_is_us, 3);
}

#[tokio::test]
async fn test_recent_request_expiry() {
    let mut node = make_node();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Insert an old request (11 seconds ago)
    node.recent_requests.insert(
        123,
        RecentRequest::new(make_node_addr(1), make_node_addr(11), now_ms - 11_000),
    );

    // Insert a recent request
    node.recent_requests.insert(
        456,
        RecentRequest::new(make_node_addr(2), make_node_addr(12), now_ms),
    );

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
