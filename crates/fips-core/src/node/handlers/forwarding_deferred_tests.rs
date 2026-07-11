fn pending_test_forward(owner: u8, source: u8, dest: u8) -> PreparedSessionForward {
    PreparedSessionForward {
        next_hop_addr: NodeAddr::from_bytes([owner; 16]),
        src_addr: NodeAddr::from_bytes([source; 16]),
        dest_addr: NodeAddr::from_bytes([dest; 16]),
        outgoing_ce: false,
        received_len: 100,
        encoded_len: 101,
        plaintext: PacketBuffer::default(),
    }
}

#[test]
fn forwarding_window_bounds_saturated_owner_and_source_but_admits_peer() {
    let mut deferred = DeferredSessionForwards::default();
    for token in 0..FORWARDING_BULK_OWNER_IN_FLIGHT as u64 {
        deferred.insert(token, pending_test_forward(1, 2, 3), ForwardingLane::Bulk);
    }
    let saturated = pending_test_forward(1, 2, 3);
    assert!(!deferred.has_capacity(&saturated, ForwardingLane::Bulk));
    assert!(!deferred.has_capacity(&pending_test_forward(1, 5, 6), ForwardingLane::Bulk));
    assert!(!deferred.has_capacity(&pending_test_forward(4, 2, 6), ForwardingLane::Bulk));
    assert!(deferred.has_capacity(&pending_test_forward(4, 5, 6), ForwardingLane::Bulk,));
    assert!(deferred.has_capacity(&saturated, ForwardingLane::Priority));
    for token in 1_000..1_000 + FORWARDING_PRIORITY_OWNER_IN_FLIGHT as u64 {
        deferred.insert(
            token,
            pending_test_forward(1, 2, 3),
            ForwardingLane::Priority,
        );
    }
    assert!(!deferred.has_capacity(&saturated, ForwardingLane::Priority));
}

#[test]
fn deferred_forward_receipts_complete_out_of_order_without_count_leaks() {
    let mut deferred = DeferredSessionForwards::default();
    for token in 1..=3 {
        deferred.insert(
            token,
            pending_test_forward(token as u8, token as u8, 9),
            ForwardingLane::Bulk,
        );
    }
    for token in [3, 1, 2] {
        let forward = deferred.take_pending(token).expect("pending forward");
        deferred.push_completed(forward, Ok(()));
    }
    assert!(deferred.take_pending(999).is_none());
    assert_eq!(deferred.pending_len(), 0);
    assert!(deferred.window.is_empty());
    let completed_owners: Vec<_> = std::iter::from_fn(|| deferred.pop_completed())
        .map(|(forward, _)| forward.next_hop_addr)
        .collect();
    assert_eq!(
        completed_owners,
        vec![
            NodeAddr::from_bytes([3; 16]),
            NodeAddr::from_bytes([1; 16]),
            NodeAddr::from_bytes([2; 16]),
        ]
    );
}

#[tokio::test]
async fn shutdown_abort_finishes_every_forward_and_matches_stats() {
    let mut node = Node::new(crate::Config::new()).expect("test node");
    node.deferred_session_forwards.insert(
        1,
        pending_test_forward(1, 2, 3),
        ForwardingLane::Bulk,
    );
    node.deferred_session_forwards.insert(
        2,
        pending_test_forward(4, 5, 6),
        ForwardingLane::Priority,
    );

    assert_eq!(
        node.abort_deferred_session_forwards("test shutdown").await,
        2
    );
    assert_eq!(node.deferred_session_forwards.pending_len(), 0);
    assert!(node.deferred_session_forwards.window.is_empty());
    assert!(node.deferred_session_forwards.completed.is_empty());
    assert_eq!(node.stats().forwarding.drop_send_error_packets, 2);
}
