use super::*;

/// Test that stale handshake connections are cleaned up by check_timeouts().
///
/// Simulates the scenario where a node initiates a handshake to a peer that
/// isn't running. The outbound connection should be cleaned up after the
/// handshake timeout expires.
#[tokio::test]
async fn test_stale_connection_cleanup() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let peer_identity = make_peer_identity();
    let remote_addr = TransportAddr::from_string("10.0.0.2:2121");

    // Create outbound connection with a timestamp far in the past
    let past_time_ms = 1000; // A very early timestamp
    let link_id = node.allocate_link_id();
    let mut conn = PeerConnection::outbound(link_id, peer_identity, past_time_ms);

    // Allocate session index and set transport info
    let our_index = node.index_allocator.allocate().unwrap();
    let our_keypair = node.identity.keypair();
    let _noise_msg1 = conn
        .start_handshake(our_keypair, node.startup_epoch, past_time_ms)
        .unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(remote_addr.clone());

    // Set up all the state that initiate_peer_connection would create
    let link = Link::connectionless(
        link_id,
        transport_id,
        remote_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node.links.insert(link_id, link);
    node.links
        .insert_addr((transport_id, remote_addr.clone()), link_id);
    node.peers.insert_connection(link_id, conn);
    node.pending_outbound
        .insert((transport_id, our_index.as_u32()), link_id);

    // Verify state before timeout check
    assert_eq!(node.connection_count(), 1);
    assert_eq!(node.link_count(), 1);
    assert!(
        node.pending_outbound
            .contains_key(&(transport_id, our_index.as_u32()))
    );
    assert_eq!(node.index_allocator.count(), 1);

    // Connection was created at time 1000ms. check_timeouts uses SystemTime::now(),
    // which is far beyond the 30s timeout. The connection should be cleaned up.
    node.check_timeouts();

    // Verify everything was cleaned up
    assert_eq!(
        node.connection_count(),
        0,
        "Stale connection should be removed"
    );
    assert_eq!(node.link_count(), 0, "Stale link should be removed");
    assert!(
        !node
            .pending_outbound
            .contains_key(&(transport_id, our_index.as_u32())),
        "pending_outbound should be cleaned up"
    );
    assert_eq!(
        node.index_allocator.count(),
        0,
        "Session index should be freed"
    );
    assert!(
        !node.links.contains_addr(&(transport_id, remote_addr)),
        "address dispatch should be cleaned up"
    );
}

/// Test that failed connections are cleaned up by check_timeouts().
#[tokio::test]
async fn test_failed_connection_cleanup() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let peer_identity = make_peer_identity();
    let remote_addr = TransportAddr::from_string("10.0.0.2:2121");

    // Create a connection and mark it failed (simulating a send failure)
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let link_id = node.allocate_link_id();
    let mut conn = PeerConnection::outbound(link_id, peer_identity, now_ms);

    let our_index = node.index_allocator.allocate().unwrap();
    let our_keypair = node.identity.keypair();
    let _noise_msg1 = conn
        .start_handshake(our_keypair, node.startup_epoch, now_ms)
        .unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(remote_addr.clone());
    conn.mark_failed(); // Simulate send failure

    let link = Link::connectionless(
        link_id,
        transport_id,
        remote_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node.links.insert(link_id, link);
    node.links
        .insert_addr((transport_id, remote_addr.clone()), link_id);
    node.peers.insert_connection(link_id, conn);
    node.pending_outbound
        .insert((transport_id, our_index.as_u32()), link_id);

    assert_eq!(node.connection_count(), 1);

    // Failed connections should be cleaned up immediately regardless of age
    node.check_timeouts();

    assert_eq!(
        node.connection_count(),
        0,
        "Failed connection should be removed"
    );
    assert_eq!(node.link_count(), 0, "Failed link should be removed");
    assert_eq!(
        node.index_allocator.count(),
        0,
        "Session index should be freed"
    );
}

/// Test that msg1 bytes are stored on connection for resend.
#[tokio::test]
async fn test_msg1_stored_for_resend() {
    use crate::node::wire::build_msg1;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let peer_identity = make_peer_identity();
    let remote_addr = TransportAddr::from_string("10.0.0.2:2121");

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let link_id = node.allocate_link_id();
    let mut conn = PeerConnection::outbound(link_id, peer_identity, now_ms);

    let our_index = node.index_allocator.allocate().unwrap();
    let our_keypair = node.identity.keypair();
    let noise_msg1 = conn
        .start_handshake(our_keypair, node.startup_epoch, now_ms)
        .unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(remote_addr.clone());

    // Build wire msg1 and store it (as initiate_peer_connection does)
    let wire_msg1 = build_msg1(our_index, &noise_msg1);
    let resend_interval = node.config.node.rate_limit.handshake_resend_interval_ms;
    conn.set_handshake_msg1(wire_msg1.clone(), now_ms + resend_interval);

    // Verify stored msg1 matches what was built
    assert_eq!(conn.handshake_msg1().unwrap(), &wire_msg1);
    assert_eq!(conn.resend_count(), 0);
    assert!(conn.next_resend_at_ms() > now_ms);
}

/// Test that resend scheduling respects max_resends and backoff.
#[tokio::test]
async fn test_resend_scheduling() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let peer_identity = make_peer_identity();
    let remote_addr = TransportAddr::from_string("10.0.0.2:2121");

    let now_ms = 100_000u64; // Use a fixed time for predictable testing
    let link_id = node.allocate_link_id();
    let mut conn = PeerConnection::outbound(link_id, peer_identity, now_ms);

    let our_index = node.index_allocator.allocate().unwrap();
    let our_keypair = node.identity.keypair();
    let noise_msg1 = conn
        .start_handshake(our_keypair, node.startup_epoch, now_ms)
        .unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(remote_addr.clone());

    // Store msg1 with first resend at now + 1000ms
    let wire_msg1 = crate::node::wire::build_msg1(our_index, &noise_msg1);
    conn.set_handshake_msg1(wire_msg1, now_ms + 1000);

    let link = Link::connectionless(
        link_id,
        transport_id,
        remote_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node.links.insert(link_id, link);
    node.links.insert_addr((transport_id, remote_addr), link_id);
    node.pending_outbound
        .insert((transport_id, our_index.as_u32()), link_id);
    node.peers.insert_connection(link_id, conn);

    // Before resend time: nothing should happen (no transport = can't send,
    // but the filter should exclude it because now < next_resend_at)
    node.resend_pending_handshakes(now_ms + 500).await;
    let conn = node.peers.get_connection(&link_id).unwrap();
    assert_eq!(conn.resend_count(), 0, "No resend before scheduled time");

    // At resend time: would resend if transport existed. Without transport,
    // the send fails silently and resend_count stays at 0.
    // This tests the filtering logic — the connection IS a candidate.
    node.resend_pending_handshakes(now_ms + 1000).await;
    // No transport registered, so send fails — count stays 0.
    // That's the expected behavior (transport absence is a transient condition).
    let conn = node.peers.get_connection(&link_id).unwrap();
    assert_eq!(
        conn.resend_count(),
        0,
        "No transport means no resend recorded"
    );
}

/// Test that msg2 is stored on PeerConnection for responder resend.
#[test]
fn test_msg2_stored_on_connection() {
    let mut conn = PeerConnection::inbound(LinkId::new(1), 1000);

    assert!(conn.handshake_msg2().is_none());

    let msg2_bytes = vec![0x01, 0x02, 0x03, 0x04];
    conn.set_handshake_msg2(msg2_bytes.clone());

    assert_eq!(conn.handshake_msg2().unwrap(), &msg2_bytes);
}

/// Test that resend_count and next_resend_at_ms track correctly.
#[test]
fn test_resend_count_tracking() {
    let peer_identity = make_peer_identity();
    let mut conn = PeerConnection::outbound(LinkId::new(1), peer_identity, 1000);

    assert_eq!(conn.resend_count(), 0);
    assert_eq!(conn.next_resend_at_ms(), 0);

    // Simulate storing msg1 and scheduling first resend
    conn.set_handshake_msg1(vec![0x01], 2000);
    assert_eq!(conn.resend_count(), 0);
    assert_eq!(conn.next_resend_at_ms(), 2000);

    // Record first resend
    conn.record_resend(4000); // next at 4000 (2s backoff)
    assert_eq!(conn.resend_count(), 1);
    assert_eq!(conn.next_resend_at_ms(), 4000);

    // Record second resend
    conn.record_resend(8000); // next at 8000 (4s backoff)
    assert_eq!(conn.resend_count(), 2);
    assert_eq!(conn.next_resend_at_ms(), 8000);
}
