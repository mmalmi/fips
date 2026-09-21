//! A readiness frame can outlive its sender's candidate; a fresh dial must recover.
use super::*;

const MIN_AGE_MS: u64 = 1_000;
const ATTEMPT_MS: u64 = 3_000;

#[test]
fn expired_sender_readiness_recovers_without_rekey() {
    expired_readiness(false);
}

#[test]
fn expired_sender_readiness_recovers_with_default_rekey() {
    expired_readiness(true);
}

fn expired_readiness(rekey_enabled: bool) {
    run_large_stack_async_test("rotation-expired-readiness-recovery", move || async move {
        let mut nodes = [
            make_test_node().await,
            make_test_node().await,
            make_test_node().await,
            make_test_node().await,
        ];
        let result = AssertUnwindSafe(exercise_expired_readiness(&mut nodes, rekey_enabled))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise_expired_readiness(nodes: &mut [TestNode; 4], rekey_enabled: bool) {
    for (i, node) in nodes.iter_mut().enumerate() {
        // The supported full-handshake setting and default rekey setting share
        // the same real expiry. Liveness, admission and proof checks stay on.
        node.node.config.node.rekey.enabled = rekey_enabled;
        node.node.config.node.rate_limit = crate::config::Config::new().node.rate_limit;
        node.node.config.node.rate_limit.handshake_timeout_secs = ATTEMPT_MS / 1000;
        if i < 2 {
            node.node.max_peers = 1;
            node.node.max_connections = 1;
            node.node.max_links = 2;
            node.node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
                idle_secs: MIN_AGE_MS / 1000,
                interval_secs: 1,
            });
        }
    }
    let ids: Vec<_> = nodes.iter().map(|node| *node.node.node_addr()).collect();
    // A already has a mature incumbent when it starts its original attempt.
    dial(nodes, 0, 2).await;
    quiesce(nodes).await;
    let a_owner = Owner::capture(&nodes[0], &ids[2]);
    wait_until(a_owner.authenticated_at + MIN_AGE_MS + 50).await;
    dial(nodes, 0, 1).await;
    let a_pending = Pending::capture(&nodes[0], &ids[1]);
    let a_deadline = a_pending.attempt + ATTEMPT_MS;
    let request = next_packet(&mut nodes[1]).await;
    assert_eq!(request.remote_addr, nodes[0].addr);
    assert_eq!(
        Msg1Header::parse(request.data.as_slice())
            .unwrap()
            .sender_idx,
        a_pending.index
    );

    // Hold the actual received Msg1 without changing its wire or timestamp.
    // B's genuine incumbent admission gives B a later maturity window; its
    // local candidate deadline starts only when B handles the held request.
    wait_until(a_pending.attempt + 2_250).await;
    dial(nodes, 1, 3).await;
    quiesce(nodes).await;
    let b_owner = Owner::capture(&nodes[1], &ids[3]);
    let b_eligible = b_owner.authenticated_at + MIN_AGE_MS;
    assert!(b_eligible > a_deadline + 150);
    assert!(
        Node::now_ms() + 250 < a_deadline,
        "reply must precede A's expiry"
    );
    nodes[1].node.handle_msg1(request).await;
    let b_pending = Pending::capture(&nodes[1], &ids[0]);
    assert!(b_pending.attempt > a_pending.attempt);
    assert_eq!(resources(&nodes[0]), (1, 1, 2, 2));
    assert_eq!(resources(&nodes[1]), (1, 1, 2, 2));
    let response = next_packet(&mut nodes[0]).await;
    let header = Msg2Header::parse(response.data.as_slice()).unwrap();
    assert_eq!(header.receiver_idx, a_pending.index);
    assert_eq!(header.sender_idx, b_pending.index);
    nodes[0].node.handle_msg2(response).await;
    let ready = next_packet(&mut nodes[1]).await;
    authenticate_proof(&nodes[1], &b_pending, &ready);
    let ready_wire = ready.data.as_slice().to_vec();
    assert!(Node::now_ms() < a_deadline);
    assert!(Node::now_ms() < b_eligible);
    process_dataplane_packet(&mut nodes[1], ready).await;
    assert!(nodes[0].node.get_peer(&ids[1]).is_none());
    assert!(nodes[1].node.get_peer(&ids[0]).is_none());
    assert_eq!(Owner::capture(&nodes[0], &ids[2]), a_owner);
    assert_eq!(Owner::capture(&nodes[1], &ids[3]), b_owner);
    let retained = nodes[1].node.get_connection(&b_pending.link).unwrap();
    assert_eq!(
        retained.handshake_confirmation().unwrap().data.as_slice(),
        ready_wire
    );

    // A's ordinary timeout releases the real candidate/index before B matures.
    // No extra packet from A is needed for B's later local admission decision.
    wait_until(a_deadline + 50).await;
    assert!(Node::now_ms() < b_eligible);
    maintenance(&mut nodes[0]).await;
    assert!(nodes[0].node.get_connection(&a_pending.link).is_none());
    assert!(!nodes[0].node.index_allocator.is_allocated(a_pending.index));
    assert!(nodes[0].node.pending_outbound.is_empty());
    assert_eq!(Owner::capture(&nodes[0], &ids[2]), a_owner);
    assert_eq!(resources(&nodes[0]), (1, 0, 1, 1));

    wait_until(b_eligible + 50).await;
    assert!(Node::now_ms() < b_pending.attempt + ATTEMPT_MS);
    let retained = nodes[1].node.get_connection(&b_pending.link).unwrap();
    assert_eq!(retained.last_activity(), b_pending.activity);
    assert_eq!(
        retained.handshake_confirmation().unwrap().data.as_slice(),
        ready_wire
    );
    maintenance(&mut nodes[1]).await;
    let b_half = Owner::capture(&nodes[1], &ids[0]);
    assert_eq!(b_half.link, b_pending.link);
    assert_eq!(b_half.index, Some(b_pending.index));
    assert_eq!(
        nodes[1].node.get_peer(&ids[0]).unwrap().their_index(),
        Some(a_pending.index)
    );
    assert!(b_half.authenticated_at >= b_eligible);
    assert!(nodes[1].node.get_peer(&ids[3]).is_none());
    assert!(nodes[1].node.get_connection(&b_pending.link).is_none());
    assert_eq!(resources(&nodes[1]), (1, 0, 1, 1));
    assert!(nodes[0].node.get_peer(&ids[1]).is_none());
    // Let B consume its retained frame and deliver its ordinary confirmation
    // to A's now-unowned index. This cannot resurrect A's expired candidate.
    quiesce(nodes).await;
    assert!(nodes[0].node.get_peer(&ids[1]).is_none());
    assert!(!nodes[0].node.index_allocator.is_allocated(a_pending.index));
    assert_eq!(Owner::capture(&nodes[1], &ids[0]), b_half);
    assert_eq!(
        nodes[1]
            .node
            .dataplane_fmp_link_metrics(&ids[0], Instant::now())
            .unwrap()
            .rx_packets,
        1,
        "one saved readiness frame creates the half-owner, not a committed remote peer"
    );

    // This characterizes the finite protocol boundary; B cannot know A's
    // deadline. The required end state is recovery via a new ordinary dial.
    dial(nodes, 0, 1).await;
    let retry = Pending::capture(&nodes[0], &ids[1]);
    assert_ne!(retry.link, a_pending.link);
    assert_ne!(retry.index, a_pending.index);
    assert!(retry.attempt > a_pending.attempt);
    let recovered = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            for node in nodes.iter_mut().take(2) {
                maintenance(node).await;
                node.node.check_rekey().await;
                node.node.check_link_heartbeats().await;
            }
            process_available_packets(nodes).await;
            if let (Some(a), Some(b)) = (
                nodes[0].node.get_peer(&ids[1]),
                nodes[1].node.get_peer(&ids[0]),
            ) && a.our_index() == b.their_index()
                && a.their_index() == b.our_index()
                && (0..2).all(|i| {
                    nodes[i]
                        .node
                        .dataplane_fmp_link_metrics(&ids[1 - i], Instant::now())
                        .is_some_and(|metrics| metrics.current_epoch_authenticated)
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        recovered.is_ok(),
        "fresh retry must recover reciprocal current keys: rekey={rekey_enabled}, A={:?}, B={:?}, resources={:?}/{:?}",
        nodes[0].node.get_peer(&ids[1]).map(|peer| (
            peer.link_id(),
            peer.our_index(),
            peer.their_index()
        )),
        nodes[1].node.get_peer(&ids[0]).map(|peer| (
            peer.link_id(),
            peer.our_index(),
            peer.their_index()
        )),
        resources(&nodes[0]),
        resources(&nodes[1]),
    );
    let a = nodes[0]
        .node
        .get_peer(&ids[1])
        .expect("fresh retry must recover after the original sender expired");
    let b = nodes[1].node.get_peer(&ids[0]).unwrap();
    assert_eq!(a.link_id(), retry.link);
    assert_eq!(a.our_index(), b.their_index());
    assert_eq!(a.their_index(), b.our_index());
    assert_ne!(b.our_index(), b_half.index);
    assert!(b.session_generation() > b_half.generation);
    assert_eq!(b.authenticated_at(), b_half.authenticated_at);
    assert!(nodes[0].node.get_peer(&ids[2]).is_none());
    for (i, remote) in [(0, ids[1]), (1, ids[0])] {
        let node = &nodes[i];
        assert_eq!(node.node.peer_count(), 1);
        assert_eq!(node.node.connection_count(), 0);
        assert_eq!(node.node.link_count(), 1);
        // The replaced responder index may drain under the normal ten-second
        // policy; the test does not lengthen its runtime or erase that owner.
        assert!(node.node.index_allocator.count() <= 2);
        assert!(node.node.pending_outbound.is_empty());
        assert!(
            node.node
                .dataplane_fmp_link_metrics(&remote, Instant::now())
                .unwrap()
                .current_epoch_authenticated
        );
    }

    let mut endpoints = [
        nodes[0].node.attach_endpoint_data_io(8).unwrap(),
        nodes[1].node.attach_endpoint_data_io(8).unwrap(),
    ];
    for (source, destination) in [(0, 1), (1, 0)] {
        let identity =
            PeerIdentity::from_pubkey_full(nodes[destination].node.identity.pubkey_full());
        let payload = vec![71 + source as u8; 64];
        send_endpoint_data_via_dataplane(&mut nodes[source].node, identity, payload.clone())
            .await
            .unwrap();
        let event = recv_endpoint_event_while_draining(
            nodes,
            &mut endpoints[destination].event_rx,
            Duration::from_secs(2),
            "bidirectional payload after expired-readiness recovery",
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
    for node in nodes.iter_mut().take(2) {
        maintenance(node).await;
    }
    quiesce(nodes).await;
    for endpoint in &mut endpoints {
        assert!(matches!(
            endpoint.event_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }
}
