fn pending_test_forward(owner: u8, source: u8, dest: u8) -> PreparedSessionForward {
    PreparedSessionForward {
        permit: None,
        ingress_peer: NodeAddr::from_bytes([source; 16]),
        next_hop_addr: NodeAddr::from_bytes([owner; 16]),
        src_addr: NodeAddr::from_bytes([source; 16]),
        dest_addr: NodeAddr::from_bytes([dest; 16]),
        outgoing_ce: false,
        received_len: 100,
        encoded_len: 101,
        plaintext: PacketBuffer::default(),
    }
}

#[derive(Debug, Default)]
struct CompletionAudit(std::sync::Mutex<Vec<crate::node::ForwardingOutcome>>);

impl crate::node::ForwardingPolicy for CompletionAudit {
    fn admit(&self, _: &crate::node::ForwardingRequest<'_>) -> Option<u64> {
        Some(7)
    }

    fn complete(&self, token: u64, outcome: crate::node::ForwardingOutcome) {
        assert_eq!(token, 7);
        self.0.lock().unwrap().push(outcome);
    }
}

fn admitted_test_forward(
    node: &Node,
    audit: &std::sync::Arc<CompletionAudit>,
) -> PreparedSessionForward {
    let mut forward = pending_test_forward(1, 2, 3);
    let policy: std::sync::Arc<dyn crate::node::ForwardingPolicy> = audit.clone();
    forward.permit = crate::node::forwarding_policy::ForwardingPermit::admit(
        &policy,
        &crate::node::ForwardingRequest {
            ingress: crate::PeerIdentity::from_pubkey_full(node.identity().pubkey_full()),
            next_hop: forward.next_hop_addr,
            source: forward.src_addr,
            destination: forward.dest_addr,
            session_payload: b"opaque-test-payload",
        },
    );
    forward
}

#[tokio::test]
async fn forwarding_policy_completes_success_error_abort_and_teardown_once() {
    use crate::node::ForwardingOutcome::{Submitted, Unconfirmed};
    let mut node = Node::new(crate::Config::new()).unwrap();
    let audit = std::sync::Arc::new(CompletionAudit::default());
    let replacement = std::sync::Arc::new(CompletionAudit::default());

    let success = admitted_test_forward(&node, &audit);
    node.set_forwarding_policy(Some(replacement.clone()));
    node.finish_prepared_session_forward(success, Ok(()), false).await;
    assert_eq!(*audit.0.lock().unwrap(), vec![Submitted]);
    assert!(replacement.0.lock().unwrap().is_empty(), "completion belongs to the admitting policy");

    let failure = admitted_test_forward(&node, &audit);
    let next_hop = failure.next_hop_addr;
    node.finish_prepared_session_forward(failure, Err(NodeError::SendFailed {
        node_addr: next_hop,
        reason: "test transport error".to_string(),
    }), false).await;

    let aborted = admitted_test_forward(&node, &audit);
    node.deferred_session_forwards.insert(1, aborted, ForwardingLane::Bulk);
    node.abort_deferred_session_forwards("test cancellation").await;

    let queued = admitted_test_forward(&node, &audit);
    node.deferred_session_forwards.insert(2, queued, ForwardingLane::Bulk);
    drop(node);
    assert_eq!(*audit.0.lock().unwrap(), vec![Submitted, Unconfirmed, Unconfirmed, Unconfirmed]);
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

#[tokio::test(start_paused = true)]
async fn orphan_forward_receipt_does_not_block_queued_endpoint_peer_snapshot() {
    let mut node = Node::new(crate::Config::new()).expect("test node");
    let endpoint_io = node
        .attach_endpoint_data_io(1)
        .expect("endpoint I/O should attach");
    let mut endpoint_control_rx = node
        .endpoint_control_rx
        .take()
        .expect("endpoint control receiver should attach");
    node.deferred_session_forwards.insert(
        1,
        pending_test_forward(1, 2, 3),
        ForwardingLane::Priority,
    );

    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    endpoint_io
        .control_tx
        .send(crate::node::NodeEndpointControlCommand::PeerSnapshot { response_tx })
        .await
        .expect("peer snapshot should queue behind forwarding drain");

    let queued_snapshot = async move {
        let drained = node.drain_deferred_session_forwards().await;
        let command = endpoint_control_rx
            .recv()
            .await
            .expect("queued endpoint control command");
        assert!(node.handle_endpoint_control(command).await.is_none());
        let peers = response_rx.await.expect("peer snapshot response");
        (node, drained, peers)
    };
    let (node, drained, peers) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        queued_snapshot,
    )
    .await
    .expect("orphan forwarding receipt must not starve endpoint control");

    assert_eq!(drained, 1);
    assert!(peers.is_empty());
    assert_eq!(node.deferred_session_forwards.pending_len(), 0);
    assert!(node.deferred_session_forwards.window.is_empty());
    assert!(node.deferred_session_forwards.completed.is_empty());
    assert_eq!(node.stats().forwarding.drop_send_error_packets, 1);
}
