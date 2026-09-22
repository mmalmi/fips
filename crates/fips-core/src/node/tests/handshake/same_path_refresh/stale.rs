use super::*;
use crate::node::tests::spanning_tree::process_node_packets;

#[test]
fn delayed_same_epoch_refresh_proof_cannot_replace_completed_rekey() {
    run_large_stack_async_test("same-path-proof-after-real-rekey", || async {
        let mut nodes = [make_test_node().await, make_test_node().await];
        let result = AssertUnwindSafe(exercise_stale(&mut nodes))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

fn current_authenticated(node: &TestNode, peer: &NodeAddr) -> bool {
    node.node
        .dataplane_fmp_link_metrics(peer, Instant::now())
        .is_some_and(|metrics| metrics.current_epoch_authenticated)
}

// The first C proof is held outside this loop. Any other C ciphertext is
// deliberately lost at B, so it cannot promote C before the tested release.
// Every D rekey/control frame uses the normal receive/completion dispatcher.
async fn pump_without_c(nodes: &mut [TestNode; 2], c_index: SessionIndex) {
    for (index, node) in nodes.iter_mut().enumerate() {
        for _ in 0..64 {
            let Ok(packet) = node.packet_rx.try_recv() else {
                break;
            };
            if index == 1
                && FmpWireHeader::parse_encrypted(packet.data.as_slice())
                    .is_ok_and(|header| header.receiver_idx() == c_index.as_u32())
            {
                continue;
            }
            process_dataplane_packet(node, packet).await;
        }
        process_dataplane_completions(&mut node.node).await;
    }
}

async fn exercise_stale(nodes: &mut [TestNode; 2]) {
    for node in nodes.iter_mut() {
        assert!(node.node.config.node.rekey.enabled);
        node.node.config.node.heartbeat_interval_secs = 1;
    }
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    let a_epoch = nodes[0].node.startup_epoch;
    let b_epoch = nodes[1].node.startup_epoch;

    // Complete the first real Noise handshake, but initially lose A->B
    // encrypted bootstrap. B is healthy and owns keys; only A has observed
    // an authenticated current-epoch frame. No health/timestamp is seeded.
    dial(nodes).await;
    let initial_msg1 = next_matching(&mut nodes[1], |packet| {
        Msg1Header::parse(packet.data.as_slice()).is_some()
    })
    .await;
    nodes[1].node.handle_msg1(initial_msg1).await;
    let initial_msg2 = next_matching(&mut nodes[0], |packet| {
        Msg2Header::parse(packet.data.as_slice()).is_some()
    })
    .await;
    nodes[0].node.handle_msg2(initial_msg2).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while !current_authenticated(&nodes[0], &b) {
            let node = &mut nodes[0];
            process_node_packets(&mut node.node, &mut node.packet_rx).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("A receives B's genuine encrypted bootstrap");
    assert!(!current_authenticated(&nodes[1], &a));
    let original_b = owner(&nodes[1], &a);
    assert!(!nodes[1].node.get_peer(&a).unwrap().fmp_mmp_is_initiator());

    // Age only actual inbound observations. Late old bootstrap is discarded
    // by the matching receives below, not injected into current liveness.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert!(nodes[0].node.active_peer_needs_same_path_refresh(&b));
    assert!(!current_authenticated(&nodes[1], &a));
    assert!(
        nodes[1]
            .node
            .get_peer(&a)
            .unwrap()
            .session_established_at()
            .elapsed()
            < Duration::from_secs(30)
    );

    // D starts BEFORE C occupies this path. Starting it afterward would be
    // correctly refused by the production pending-path ownership guard.
    assert!(nodes[1].node.initiate_rekey(&a).await);
    let d_index_b = nodes[1]
        .node
        .get_peer(&a)
        .unwrap()
        .rekey_our_index()
        .unwrap();
    let d_msg1 = next_matching(&mut nodes[0], |packet| {
        Msg1Header::parse(packet.data.as_slice()).is_some()
    })
    .await;
    assert_eq!(
        Msg1Header::parse(d_msg1.data.as_slice())
            .unwrap()
            .sender_idx,
        d_index_b
    );

    // B's young, as-yet unconfirmed current owner does not classify C as
    // another ActivePeer rekey. C is a genuine full-handshake reservation.
    assert!(!nodes[1].node.same_path_msg1_is_established_rekey(
        &a,
        nodes[1].transport_id,
        &nodes[0].addr
    ));
    dial(nodes).await;
    let c_msg1 = next_matching(&mut nodes[1], |packet| {
        Msg1Header::parse(packet.data.as_slice()).is_some()
    })
    .await;
    nodes[1].node.handle_msg1(c_msg1).await;
    let c_msg2 = next_matching(&mut nodes[0], |packet| {
        Msg2Header::parse(packet.data.as_slice()).is_some()
    })
    .await;
    let c = nodes[1].node.peers.connection_values().next().unwrap();
    assert!(c.is_inbound() && c.is_complete());
    let c_link = c.link_id();
    let c_index = c.our_index().unwrap();
    let c_started = c.started_at();
    let c_activity = c.last_activity();
    assert_eq!(c.remote_epoch(), Some(a_epoch));
    assert_eq!(owner(&nodes[1], &a), original_b);
    assert!(nodes[1].node.get_peer(&a).unwrap().rekey_in_progress());

    nodes[0].node.handle_msg2(c_msg2).await;
    assert_eq!(
        nodes[0].node.get_peer(&b).unwrap().their_index(),
        Some(c_index)
    );
    assert!(nodes[0].node.get_peer(&b).unwrap().is_draining());
    let superseded_a = nodes[0]
        .node
        .get_peer(&b)
        .unwrap()
        .previous_our_index()
        .unwrap();
    let refreshed_a = owner(&nodes[0], &b).our;
    assert!(nodes[0].node.index_allocator.is_allocated(superseded_a));
    let c_proof = next_matching(&mut nodes[1], |packet| {
        FmpWireHeader::parse_encrypted(packet.data.as_slice())
            .is_ok_and(|header| header.receiver_idx() == c_index.as_u32())
    })
    .await;

    // A's actual C cutover now makes the already-sent D request a normal
    // rekey of its draining owner. D's response completes B's original
    // ActivePeer handshake, without consuming the separate parked C.
    assert!(nodes[0].node.same_path_msg1_is_established_rekey(
        &b,
        nodes[0].transport_id,
        &nodes[1].addr
    ));
    nodes[0].node.handle_msg1(d_msg1).await;
    let d_index_a = nodes[0]
        .node
        .get_peer(&b)
        .unwrap()
        .pending_our_index()
        .unwrap();
    let d_msg2 = next_matching(&mut nodes[1], |packet| {
        Msg2Header::parse(packet.data.as_slice())
            .is_some_and(|header| header.receiver_idx == d_index_b)
    })
    .await;
    nodes[1].node.handle_msg2(d_msg2).await;
    assert!(
        nodes[1]
            .node
            .get_peer(&a)
            .unwrap()
            .pending_new_session()
            .is_some()
    );
    assert_eq!(owner(&nodes[1], &a), original_b);

    // Use ordinary real-time maintenance and encrypted Heartbeats for D's
    // K-bit cutover. No direct owner installation or synthetic timer jump.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            for node in nodes.iter_mut() {
                node.node.check_rekey().await;
            }
            heartbeat(nodes, 1).await;
            heartbeat(nodes, 0).await;
            pump_without_c(nodes, c_index).await;
            assert!(nodes[1].node.get_connection(&c_link).is_some());
            if nodes[0].node.get_peer(&b).unwrap().our_index() == Some(d_index_a)
                && nodes[1].node.get_peer(&a).unwrap().our_index() == Some(d_index_b)
                && current_authenticated(&nodes[0], &b)
                && current_authenticated(&nodes[1], &a)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the already-started D rekey must authenticate both current owners");
    assert_pair(nodes);
    assert_retained_indices(&nodes[0], &b, superseded_a, refreshed_a);
    let current_a = owner(&nodes[0], &b);
    let current_b = owner(&nodes[1], &a);
    assert_eq!(current_b.link, original_b.link);
    assert!(current_b.generation > original_b.generation);
    assert_ne!(current_b.our, original_b.our);
    assert_eq!(current_b.epoch, original_b.epoch);
    assert!(!nodes[1].node.get_peer(&a).unwrap().fmp_mmp_is_initiator());
    for (index, remote) in [(0, b), (1, a)] {
        assert!(
            nodes[index].node.get_session(&remote).is_none(),
            "no FSP degradation may independently authorize the obsolete candidate"
        );
        assert!(
            !nodes[index]
                .node
                .same_epoch_msg1_is_direct_path_recovery(&remote, Node::now_ms())
        );
    }
    assert_eq!(nodes[0].node.startup_epoch, a_epoch);
    assert_eq!(nodes[1].node.startup_epoch, b_epoch);

    let c = nodes[1].node.get_connection(&c_link).unwrap();
    assert_eq!(c.started_at(), c_started);
    assert_eq!(c.last_activity(), c_activity);
    assert!(!c.is_timed_out(
        Node::now_ms(),
        nodes[1].node.config.node.rate_limit.handshake_timeout_secs * 1000
    ));
    assert!(c.handshake_confirmation().is_none());
    let header = FmpWireHeader::parse_encrypted(c_proof.data.as_slice()).unwrap();
    let offset = usize::from(header.ciphertext_offset());
    assert!(
        c.session()
            .unwrap()
            .authenticate_with_counter_and_aad(
                &c_proof.data.as_slice()[offset..],
                header.counter(),
                &c_proof.data.as_slice()[..offset]
            )
            .is_ok(),
        "C's delayed proof is still cryptographically valid and addressed to its live candidate"
    );
    let before = resources(&nodes[1]);
    let before_received = received(&nodes[1], &a);
    process_dataplane_packet(&mut nodes[1], c_proof).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while nodes[1].node.get_connection(&c_link).is_some() {
            process_dataplane_completions(&mut nodes[1].node).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("obsolete same-epoch candidate must be retired after proof");
    assert_eq!(
        owner(&nodes[1], &a),
        current_b,
        "delayed C proof cannot roll B back from its newer authenticated same-path rekey"
    );
    assert_eq!(owner(&nodes[0], &b), current_a);
    assert_eq!(received(&nodes[1], &a), before_received);
    assert!(!nodes[1].node.index_allocator.is_allocated(c_index));
    assert!(nodes[1].node.links.get(&c_link).is_none());
    assert_eq!(
        resources(&nodes[1]),
        (before.0, before.1 - 1, before.2 - 1, before.3 - 1)
    );
    assert_pair(nodes);

    // Another real rekey starts while both peers still retain a draining
    // epoch. Exercise retirement on the initiator as well as the responder.
    assert!(nodes[0].node.get_peer(&b).unwrap().is_draining());
    assert!(nodes[1].node.get_peer(&a).unwrap().is_draining());
    let previous_b = nodes[1]
        .node
        .get_peer(&a)
        .unwrap()
        .previous_our_index()
        .unwrap();
    assert!(nodes[0].node.initiate_rekey(&b).await);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            for node in nodes.iter_mut() {
                node.node.check_rekey().await;
            }
            heartbeat(nodes, 0).await;
            heartbeat(nodes, 1).await;
            process_available_packets(nodes).await;
            if owner(&nodes[0], &b).our != current_a.our
                && owner(&nodes[1], &a).our != current_b.our
                && current_authenticated(&nodes[0], &b)
                && current_authenticated(&nodes[1], &a)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a subsequent real rekey must retire both superseded drain epochs");
    assert_retained_indices(&nodes[0], &b, refreshed_a, current_a.our);
    assert_retained_indices(&nodes[1], &a, previous_b, current_b.our);
    let current_a = owner(&nodes[0], &b);
    let current_b = owner(&nodes[1], &a);

    // First application sessions are created only after the stale-proof
    // decision; actual bidirectional payload uses the latest rekey owners.
    deliver_both_directions(nodes).await;
    assert_eq!(owner(&nodes[0], &b), current_a);
    assert_eq!(owner(&nodes[1], &a), current_b);
}

fn assert_retained_indices(
    node: &TestNode,
    remote: &NodeAddr,
    retired: SessionIndex,
    previous: SessionIndex,
) {
    let peer = node.node.get_peer(remote).unwrap();
    assert_eq!(peer.previous_our_index(), Some(previous));
    assert!(
        !node.node.index_allocator.is_allocated(retired),
        "superseded drain index must be freed"
    );
    assert_eq!(
        node.node
            .peers
            .lookup_session_index((node.transport_id, retired.as_u32())),
        None
    );
    for index in [peer.our_index().unwrap(), previous] {
        assert!(node.node.index_allocator.is_allocated(index));
        assert_eq!(
            node.node
                .peers
                .lookup_session_index((node.transport_id, index.as_u32())),
            Some(*remote)
        );
    }
    assert_eq!(
        node.node.index_allocator.count(),
        2,
        "only current and draining FMP epochs remain"
    );
}
