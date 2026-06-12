use super::*;

// ============================================================================
// Unit Tests — LookupRequest Handler
// ============================================================================

#[tokio::test]
async fn test_request_decode_error() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    // Too-short payload: should log error and return without panic
    node.handle_lookup_request(&from, &[0x00; 5]).await;
    assert!(node.recent_requests.is_empty());
}

#[tokio::test]
async fn test_request_dedup() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let target = make_node_addr(0xBB);
    let origin = make_node_addr(0xCC);
    let coords = TreeCoordinate::from_addrs(vec![origin, make_node_addr(0)]).unwrap();

    let request = LookupRequest::new(999, target, origin, coords, 5, 0);
    let payload = &request.encode()[1..]; // skip msg_type byte

    // First request: accepted
    node.handle_lookup_request(&from, payload).await;
    assert_eq!(node.recent_requests.len(), 1);

    // Duplicate request: dropped
    node.handle_lookup_request(&from, payload).await;
    assert_eq!(node.recent_requests.len(), 1);
}

#[tokio::test]
async fn test_request_target_is_self() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let origin = make_node_addr(0xCC);
    let my_addr = *node.node_addr();
    let coords = TreeCoordinate::from_addrs(vec![origin, make_node_addr(0)]).unwrap();

    // Request targeting us
    let request = LookupRequest::new(777, my_addr, origin, coords, 5, 0);
    let payload = &request.encode()[1..];

    // Should succeed without panic (response send will fail silently
    // since we have no peers to route toward origin)
    node.handle_lookup_request(&from, payload).await;
    assert!(node.recent_requests.contains_key(&777));
}

#[tokio::test]
async fn test_request_ttl_zero_not_forwarded() {
    let mut node = make_node();
    let from = make_node_addr(0xAA);
    let target = make_node_addr(0xBB);
    let origin = make_node_addr(0xCC);
    let coords = TreeCoordinate::from_addrs(vec![origin, make_node_addr(0)]).unwrap();

    let request = LookupRequest::new(666, target, origin, coords, 0, 0);
    let payload = &request.encode()[1..];

    node.handle_lookup_request(&from, payload).await;
    // Request recorded, but not forwarded (TTL=0, and no peers anyway)
    assert!(node.recent_requests.contains_key(&666));
}

// ============================================================================
// Unit Tests — LookupResponse Handler
// ============================================================================
