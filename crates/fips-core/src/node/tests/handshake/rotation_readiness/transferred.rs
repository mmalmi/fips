//! A transferred retry needs time for the remote roster, not just the local one.
use super::*;

const AGE_MS: u64 = 2_000;
const BUDGET_MS: u64 = 8_000;

#[test]
fn transferred_retry_connects_when_remote_matures_before_original_expiry() {
    run(false);
}

#[test]
fn transferred_retry_connects_when_remote_matures_after_original_expiry() {
    run(true);
}

fn run(late_remote: bool) {
    run_large_stack_async_test("rotation-transferred-readiness", move || async move {
        let mut nodes = Vec::new();
        for _ in 0..5 {
            nodes.push(make_test_node().await);
        }
        let result = AssertUnwindSafe(exercise(&mut nodes, late_remote))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn sleep_until(at_ms: u64) {
    tokio::time::sleep(Duration::from_millis(at_ms.saturating_sub(Node::now_ms()))).await;
}

async fn exercise(nodes: &mut [TestNode], late_remote: bool) {
    for (i, node) in nodes.iter_mut().enumerate() {
        node.node.config.node.rekey.enabled = false;
        node.node.config.node.rate_limit = crate::config::Config::new().node.rate_limit;
        node.node.config.node.rate_limit.handshake_timeout_secs = BUDGET_MS / 1000;
        if i < 2 {
            node.node.max_peers = 1;
            node.node.max_connections = 1;
            node.node.max_links = 2;
            node.node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
                idle_secs: AGE_MS / 1000,
                interval_secs: 1,
            });
        }
    }
    let ids: Vec<_> = nodes.iter().map(|node| *node.node.node_addr()).collect();
    dial(nodes, 0, 2).await;
    quiesce(nodes).await;
    let old = Owner::capture(&nodes[0], &ids[2]);
    sleep_until(old.authenticated_at + AGE_MS + 100).await;
    dial(nodes, 0, 1).await;
    let original = Pending::capture(&nodes[0], &ids[1]);
    let original_deadline = original.attempt + BUDGET_MS;
    // The unanswered request really left A. Do not process it at B, fabricate
    // a timeout, or alter any native clock/candidate state.
    let unanswered = next_packet(&mut nodes[1]).await;
    assert_eq!(
        Msg1Header::parse(unanswered.data.as_slice())
            .unwrap()
            .sender_idx,
        original.index
    );

    sleep_until(original.attempt + 2_150).await;
    dial(nodes, 3, 0).await;
    quiesce(nodes).await;
    let replacement = Owner::capture(&nodes[0], &ids[3]);
    assert!(nodes[0].node.get_peer(&ids[2]).is_none());
    assert!(nodes[0].node.get_connection(&original.link).is_none());
    assert!(!nodes[0].node.index_allocator.is_allocated(original.index));

    sleep_until(original.attempt + 3_350).await;
    // Exercise the one-use retry via the real dial path. Discovery selection
    // has separate coverage; there is no explicit repair dial after this one.
    dial(nodes, 0, 1).await;
    let retry = Pending::capture(&nodes[0], &ids[1]);
    let request = next_packet(&mut nodes[1]).await;
    assert_ne!(retry.index, original.index);
    assert_ne!(retry.link, original.link);
    assert_eq!(Owner::capture(&nodes[0], &ids[3]), replacement);

    // B's real incumbent is admitted later. Both cases use the same exchange;
    // only this actual admission time changes its minimum-age boundary.
    let remote_admission_ms = if late_remote { 6_750 } else { 4_750 };
    sleep_until(original.attempt + remote_admission_ms).await;
    dial(nodes, 1, 4).await;
    quiesce(nodes).await;
    let remote_owner = Owner::capture(&nodes[1], &ids[4]);
    let remote_ready = remote_owner.authenticated_at + AGE_MS;
    if late_remote {
        assert!(remote_ready > original_deadline + 500);
    } else {
        assert!(remote_ready + 500 < original_deadline);
    }
    assert!(Node::now_ms() + 500 < original_deadline);
    nodes[1].node.handle_msg1(request).await;
    let remote_pending = Pending::capture(&nodes[1], &ids[0]);
    let response = next_packet(&mut nodes[0]).await;
    nodes[0].node.handle_msg2(response).await;
    let ready = next_packet(&mut nodes[1]).await;
    authenticate_proof(&nodes[1], &remote_pending, &ready);
    process_dataplane_packet(&mut nodes[1], ready).await;
    assert!(nodes[0].node.get_peer(&ids[1]).is_none());
    assert!(nodes[1].node.get_peer(&ids[0]).is_none());
    assert_eq!(Owner::capture(&nodes[1], &ids[4]), remote_owner);

    // Ordinary timeout/retransmission/proof handling must finish this attempt.
    // A valid response does not authorize replacing B's still-young incumbent.
    let deadline = remote_ready + 750;
    let mut connected = false;
    while Node::now_ms() < deadline {
        for node in nodes.iter_mut().take(2) {
            maintenance(node).await;
        }
        process_available_packets(nodes).await;
        if Node::now_ms() < remote_ready {
            assert_eq!(Owner::capture(&nodes[1], &ids[4]), remote_owner);
        }
        for node in nodes.iter().take(2) {
            assert!(node.node.peer_count() <= 1);
            assert!(node.node.connection_count() <= 1);
            assert!(node.node.link_count() <= 2);
            assert!(node.node.index_allocator.count() <= 2);
        }
        if let (Some(a), Some(b)) = (
            nodes[0].node.get_peer(&ids[1]),
            nodes[1].node.get_peer(&ids[0]),
        ) && a.our_index() == b.their_index()
            && a.their_index() == b.our_index()
        {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        connected,
        "transferred retry must become reciprocal after remote maturity: late={late_remote}, original_deadline={original_deadline}, remote_ready={remote_ready}"
    );

    let mut endpoints = [
        nodes[0].node.attach_endpoint_data_io(8).unwrap(),
        nodes[1].node.attach_endpoint_data_io(8).unwrap(),
    ];
    for (source, destination) in [(0, 1), (1, 0)] {
        let identity =
            PeerIdentity::from_pubkey_full(nodes[destination].node.identity.pubkey_full());
        let payload = vec![81 + source as u8; 64];
        send_endpoint_data_via_dataplane(&mut nodes[source].node, identity, payload.clone())
            .await
            .unwrap();
        let event = recv_endpoint_event_while_draining(
            nodes,
            &mut endpoints[destination].event_rx,
            Duration::from_secs(2),
            "bidirectional transferred-retry payload",
        )
        .await;
        endpoints[destination]
            .event_rx
            .release_messages(event.messages.len());
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            payload
        );
    }
}
