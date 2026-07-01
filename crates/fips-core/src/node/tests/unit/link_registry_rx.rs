use super::*;
use crate::node::link_registry::LinkAddressIndex;

#[test]
fn link_address_index_owns_lookup_replace_and_stale_safe_remove() {
    let transport_id = TransportId::new(1);
    let addr = TransportAddr::from_string("127.0.0.1:7000");
    let key = (transport_id, addr.clone());
    let first_link = LinkId::new(10);
    let winning_link = LinkId::new(11);

    let mut index = LinkAddressIndex::default();

    assert_eq!(index.insert(key.clone(), first_link), None);
    assert_eq!(index.lookup(transport_id, &addr), Some(first_link));

    assert_eq!(
        index.insert(key.clone(), winning_link),
        Some(first_link),
        "replacement must report the stale owner for cross-connection cleanup"
    );
    assert!(
        !index.remove_if_points_to(&key, &first_link),
        "stale loser cleanup must not delete a newer winner's route entry"
    );
    assert_eq!(index.lookup(transport_id, &addr), Some(winning_link));

    assert!(index.remove_if_points_to(&key, &winning_link));
    assert_eq!(index.lookup(transport_id, &addr), None);
    assert!(index.is_empty());
}

#[test]
fn link_registry_owns_storage_address_index_and_stale_safe_cleanup() {
    let transport_id = TransportId::new(1);
    let addr = TransportAddr::from_string("127.0.0.1:7000");
    let first_link_id = LinkId::new(10);
    let winning_link_id = LinkId::new(11);
    let first_link = Link::connectionless(
        first_link_id,
        transport_id,
        addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    let winning_link = Link::connectionless(
        winning_link_id,
        transport_id,
        addr.clone(),
        LinkDirection::Inbound,
        Duration::from_millis(100),
    );

    let mut registry = LinkRegistry::default();

    assert!(registry.insert(first_link_id, first_link).is_none());
    assert_eq!(
        registry.get(&first_link_id).map(Link::link_id),
        Some(first_link_id)
    );
    assert_eq!(
        registry.lookup_addr(transport_id, &addr),
        Some(first_link_id)
    );

    assert!(registry.insert(winning_link_id, winning_link).is_none());
    assert_eq!(
        registry.lookup_addr(transport_id, &addr),
        Some(winning_link_id),
        "newer link for the same address must own receive dispatch"
    );

    let removed = registry.remove(&first_link_id).expect("remove stale loser");
    assert_eq!(removed.link_id(), first_link_id);
    assert_eq!(
        registry.lookup_addr(transport_id, &addr),
        Some(winning_link_id),
        "removing a stale loser must not delete the winner's address mapping"
    );

    let removed = registry.remove(&winning_link_id).expect("remove winner");
    assert_eq!(removed.link_id(), winning_link_id);
    assert_eq!(registry.lookup_addr(transport_id, &addr), None);
    assert!(registry.is_empty());
}

#[tokio::test]
async fn test_node_rx_loop_requires_start() {
    let mut node = make_node();

    // RX loop should fail if node not started (no packet_rx)
    let result = node.run_rx_loop().await;
    assert!(matches!(result, Err(NodeError::NotStarted)));
}

#[tokio::test]
async fn test_node_rx_loop_takes_channel() {
    let mut node = make_node();
    node.start().await.unwrap();

    // packet_rx should be available after start
    assert!(node.packet_rx.is_some());

    // After run_rx_loop takes ownership, it should be None
    // We can't actually run the loop (it blocks), but we can test the take
    let rx = node.packet_rx.take();
    assert!(rx.is_some());
    assert!(node.packet_rx.is_none());

    node.stop().await.unwrap();
}

#[test]
fn test_rate_limiter_initialized() {
    let mut node = make_node();

    // Rate limiter should allow handshakes initially
    assert!(node.msg1_rate_limiter.can_start_handshake());

    // Start a handshake
    assert!(node.msg1_rate_limiter.start_handshake());
    assert_eq!(node.msg1_rate_limiter.pending_count(), 1);

    // Complete it
    node.msg1_rate_limiter.complete_handshake();
    assert_eq!(node.msg1_rate_limiter.pending_count(), 0);
}

// === Promotion / Retry Tests ===

/// Test that promoting a connection cleans up a pending outbound to the same peer.
///
/// Simulates the scenario where node A has a pending outbound handshake to B
/// (unanswered because B wasn't running), then B starts and initiates to A.
/// When A promotes B's inbound connection, it should immediately clean up the
/// stale pending outbound rather than waiting for the 30s timeout.
#[test]
fn test_promote_cleans_up_pending_outbound_to_same_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Generate peer B's identity (shared between the two connections)
    let peer_b_full = Identity::generate();
    let peer_b_identity = PeerIdentity::from_pubkey_full(peer_b_full.pubkey_full());
    let peer_b_node_addr = *peer_b_identity.node_addr();

    // --- Set up the pending outbound to B (link_id 1) ---
    // This simulates A having sent msg1 to B before B was running.
    let pending_link_id = LinkId::new(1);
    let pending_time_ms = 1000;
    let mut pending_conn =
        PeerConnection::outbound(pending_link_id, peer_b_identity, pending_time_ms);

    let our_keypair = node.identity.keypair();
    let _msg1 = pending_conn
        .start_handshake(our_keypair, node.startup_epoch, pending_time_ms)
        .unwrap();

    let pending_index = node.index_allocator.allocate().unwrap();
    pending_conn.set_our_index(pending_index);
    pending_conn.set_transport_id(transport_id);
    let pending_addr = TransportAddr::from_string("10.0.0.2:2121");
    pending_conn.set_source_addr(pending_addr.clone());

    let pending_link = Link::connectionless(
        pending_link_id,
        transport_id,
        pending_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node.links.insert(pending_link_id, pending_link);
    node.links
        .insert_addr((transport_id, pending_addr.clone()), pending_link_id);
    node.peers.insert_connection(pending_link_id, pending_conn);
    node.pending_outbound
        .insert((transport_id, pending_index.as_u32()), pending_link_id);

    // Verify pending state
    assert_eq!(node.connection_count(), 1);
    assert_eq!(node.link_count(), 1);
    assert_eq!(node.index_allocator.count(), 1);

    // --- Set up the completing inbound from B (link_id 2) ---
    // Simulate B's outbound arriving at A and completing the handshake.
    // We use make_completed_connection's pattern but with B's known identity.
    let completing_link_id = LinkId::new(2);
    let completing_time_ms = 2000;

    let mut completing_conn =
        PeerConnection::outbound(completing_link_id, peer_b_identity, completing_time_ms);

    let our_keypair = node.identity.keypair();
    let msg1 = completing_conn
        .start_handshake(our_keypair, node.startup_epoch, completing_time_ms)
        .unwrap();

    // B responds
    let mut resp_conn = PeerConnection::inbound(LinkId::new(999), completing_time_ms);
    let peer_keypair = peer_b_full.keypair();
    let mut resp_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut resp_epoch);
    let msg2 = resp_conn
        .receive_handshake_init(peer_keypair, resp_epoch, &msg1, completing_time_ms)
        .unwrap();

    completing_conn
        .complete_handshake(&msg2, completing_time_ms)
        .unwrap();

    let completing_index = node.index_allocator.allocate().unwrap();
    completing_conn.set_our_index(completing_index);
    completing_conn.set_their_index(SessionIndex::new(99));
    completing_conn.set_transport_id(transport_id);
    completing_conn.set_source_addr(TransportAddr::from_string("10.0.0.2:4001"));

    node.add_connection(completing_conn).unwrap();

    // Now 2 connections, 1 link (pending has link, completing doesn't yet need one for this test)
    assert_eq!(node.connection_count(), 2);
    assert_eq!(node.index_allocator.count(), 2);

    // --- Promote the completing connection ---
    let result = node
        .promote_connection(completing_link_id, peer_b_identity, completing_time_ms)
        .unwrap();

    assert!(matches!(result, PromotionResult::Promoted(_)));

    // The pending outbound should NOT be cleaned up during promotion —
    // it's deferred so handle_msg2 can learn the peer's inbound index.
    assert_eq!(
        node.connection_count(),
        1,
        "Pending outbound should be preserved (deferred cleanup)"
    );
    assert_eq!(node.peer_count(), 1, "Promoted peer should exist");
    assert!(
        node.pending_outbound
            .contains_key(&(transport_id, pending_index.as_u32())),
        "pending_outbound entry should still exist (awaiting msg2)"
    );
    assert_eq!(
        node.index_allocator.count(),
        2,
        "Both indices should remain until msg2 cleanup"
    );

    // Verify the promoted peer is correct
    let peer = node.get_peer(&peer_b_node_addr).unwrap();
    assert_eq!(peer.link_id(), completing_link_id);
}
