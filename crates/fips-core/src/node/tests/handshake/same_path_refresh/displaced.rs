//! A displaced UDP peer can retain its active owner while refreshing that path.
//! Crossing with the returning peer must retire only the losing pending dial.
use super::*;
use crate::config::NeighborRotationConfig;

#[test]
fn displaced_peer_reclaims_losing_same_path_refresh_before_accepting_winner() {
    run_large_stack_async_test("displaced-same-path-crossed-refresh", || async {
        let mut nodes = [make_test_node().await, make_test_node().await];
        let mut replacement = make_test_node().await;
        // A's outbound wins the ordinary identity tie-break. B will keep the
        // old A adjacency after A genuinely replaces it with C.
        if nodes[0].node.node_addr() > nodes[1].node.node_addr() {
            nodes.swap(0, 1);
        }
        let result = AssertUnwindSafe(exercise(&mut nodes, &mut replacement))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        cleanup_nodes(std::slice::from_mut(&mut replacement)).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn dial_to(source: &mut TestNode, destination: &TestNode) {
    let identity = PeerIdentity::from_pubkey_full(destination.node.identity.pubkey_full());
    source
        .node
        .initiate_connection(source.transport_id, destination.addr.clone(), identity)
        .await
        .unwrap();
}

async fn drain_replacement(a: &mut TestNode, c: &mut TestNode) {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut empty = 0;
        while empty < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let count = process_available_packets(std::slice::from_mut(a)).await
                + process_available_packets(std::slice::from_mut(c)).await;
            empty = if count == 0 { empty + 1 } else { 0 };
        }
    })
    .await
    .expect("real elective replacement and bootstrap must settle");
}

fn assert_caps(node: &TestNode) {
    assert_eq!(
        (
            node.node.max_peers,
            node.node.max_connections,
            node.node.max_links
        ),
        (1, 1, 2)
    );
    assert!(node.node.peer_count() <= 1);
    assert!(node.node.connection_count() <= 1);
    assert!(node.node.link_count() <= 2);
    // One active epoch, its normal drain, and one pending handshake at most.
    assert!(node.node.index_allocator.count() <= 3);
}

async fn exercise(nodes: &mut [TestNode; 2], replacement: &mut TestNode) {
    for node in nodes.iter_mut().chain(std::iter::once(&mut *replacement)) {
        node.node.max_peers = 1;
        node.node.max_connections = 1;
        node.node.max_links = 2;
        node.node.config.node.heartbeat_interval_secs = 1;
        node.node.config.node.rate_limit.handshake_timeout_secs = 8;
        // Leave the supported default rekey policy enabled. This collision
        // concerns a real full refresh, not an ActivePeer rekey machine.
        assert!(node.node.config.node.rekey.enabled);
    }
    nodes[0].node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: 1,
        interval_secs: 1,
    });
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    let c = *replacement.node.node_addr();

    dial(nodes).await;
    quiesce(nodes).await;
    heartbeat(nodes, 0).await;
    heartbeat(nodes, 1).await;
    quiesce(nodes).await;
    assert_pair(nodes);
    let old_a = owner(&nodes[0], &b);
    let old_b = owner(&nodes[1], &a);
    let replay = observed_heartbeat(nodes, 0).await;
    // Generate, but do not deliver, one more genuine old-key frame. Delivering
    // it after admission below proves the original active keys remain usable.
    heartbeat(nodes, 0).await;
    let delayed_old_frame = next_matching(&mut nodes[1], |packet| {
        FmpWireHeader::parse_encrypted(packet.data.as_slice())
            .is_ok_and(|header| header.receiver_idx() == old_b.our.as_u32())
    })
    .await;

    // Real elapsed age and a real C handshake cause elective removal at A.
    // UDP removal sends no Disconnect, so B keeps its still-authenticated A.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    dial_to(&mut nodes[0], replacement).await;
    drain_replacement(&mut nodes[0], replacement).await;
    assert!(nodes[0].node.get_peer(&b).is_none());
    assert!(!nodes[0].node.index_allocator.is_allocated(old_a.our));
    assert_eq!(resources(&nodes[0]), (1, 0, 1, 1));
    let owner_c = owner(&nodes[0], &c);
    assert_eq!(owner_c.our, owner(replacement, &a).their);
    assert_eq!(owner_c.their, owner(replacement, &a).our);
    assert_eq!(owner(&nodes[1], &a), old_b);
    assert_eq!(resources(&nodes[1]), (1, 0, 1, 1));

    // C becomes eligible under the unchanged configured age; B's actual
    // inbound silence qualifies the production same-path refresh entry point.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert!(nodes[1].node.active_peer_needs_same_path_refresh(&a));
    let (left, right) = nodes.split_at_mut(1);
    dial_to(&mut right[0], &left[0]).await;
    let losing_request = next_matching(&mut nodes[0], |packet| {
        Msg1Header::parse(packet.data.as_slice()).is_some()
    })
    .await;
    let losing_header = Msg1Header::parse(losing_request.data.as_slice()).unwrap();
    let losing = nodes[1].node.peers.connection_values().next().unwrap();
    assert!(losing.is_outbound() && !losing.has_session());
    assert_eq!(
        losing.handshake_state(),
        crate::peer::HandshakeState::SentMsg1
    );
    assert_eq!(losing.expected_identity().unwrap().node_addr(), &a);
    assert_eq!(losing.transport_id(), Some(nodes[1].transport_id));
    assert_eq!(losing.source_addr(), Some(&nodes[0].addr));
    let losing_link = losing.link_id();
    let losing_index = losing.our_index().unwrap();
    let losing_start = losing.started_at();
    let losing_activity = losing.last_activity();
    assert_eq!(losing_header.sender_idx, losing_index);
    assert_eq!(resources(&nodes[1]), (1, 1, 2, 2));
    assert!(!nodes[1].node.get_peer(&a).unwrap().rekey_in_progress());
    assert!(
        nodes[1]
            .node
            .get_peer(&a)
            .unwrap()
            .pending_new_session()
            .is_none()
    );
    assert!(!nodes[1].node.same_path_msg1_is_established_rekey(
        &a,
        nodes[1].transport_id,
        &nodes[0].addr,
    ));
    assert!(!crate::peer::cross_connection_winner(&b, &a, true));

    // A now returns while B's real request remains unanswered. No maintenance
    // or old-link expiry is used to make room for this valid crossed request.
    dial(nodes).await;
    let winning = nodes[0].node.peers.connection_values().next().unwrap();
    let winning_link = winning.link_id();
    let winning_index = winning.our_index().unwrap();
    let winning_start = winning.started_at();
    let winning_deadline = nodes[0].node.neighbor_rotation_deadline(&b).unwrap();
    let request = next_matching(&mut nodes[1], |packet| {
        Msg1Header::parse(packet.data.as_slice()).is_some()
    })
    .await;
    assert_eq!(
        Msg1Header::parse(request.data.as_slice())
            .unwrap()
            .sender_idx,
        winning_index
    );

    // A corrupt Noise request must not reclaim capacity before authentication.
    let mut invalid = request.data.as_slice().to_vec();
    *invalid.last_mut().unwrap() ^= 1;
    send_wire(nodes, 0, &invalid).await;
    let invalid = next_matching(&mut nodes[1], |packet| {
        packet.data.as_slice() == invalid.as_slice()
    })
    .await;
    nodes[1].node.handle_msg1(invalid).await;
    assert_eq!(owner(&nodes[1], &a), old_b);
    let retained = nodes[1].node.get_connection(&losing_link).unwrap();
    assert_eq!(retained.our_index(), Some(losing_index));
    assert_eq!(
        (retained.started_at(), retained.last_activity()),
        (losing_start, losing_activity)
    );
    assert_eq!(resources(&nodes[1]), (1, 1, 2, 2));

    nodes[1].node.handle_msg1(request.clone()).await;
    assert!(
        nodes[1].node.get_connection(&losing_link).is_none(),
        "winning crossed request must promptly retire the losing same-path full refresh, not wait for the old active peer to expire"
    );
    assert!(!nodes[1].node.index_allocator.is_allocated(losing_index));
    assert!(
        !nodes[1]
            .node
            .pending_outbound
            .contains_key(&(nodes[1].transport_id, losing_index.as_u32()))
    );
    assert!(nodes[1].node.links.get(&losing_link).is_none());
    assert_eq!(
        owner(&nodes[1], &a),
        old_b,
        "Msg1 must preserve the old active keys"
    );
    let candidate = nodes[1].node.peers.connection_values().next().unwrap();
    assert!(candidate.is_inbound() && candidate.has_session());
    let candidate_link = candidate.link_id();
    let candidate_index = candidate.our_index().unwrap();
    let candidate_activity = candidate.last_activity();
    assert_eq!(candidate.their_index(), Some(winning_index));
    assert_eq!(resources(&nodes[1]), (1, 1, 2, 2));
    let response = next_matching(&mut nodes[0], |packet| {
        Msg2Header::parse(packet.data.as_slice()).is_some()
    })
    .await;
    assert_eq!(
        Msg2Header::parse(response.data.as_slice())
            .unwrap()
            .receiver_idx,
        winning_index
    );

    // Exact Msg1 replay and already-observed old-key traffic cannot promote
    // the pending receiver or replace its index/deadline.
    send_wire(nodes, 0, request.data.as_slice()).await;
    let duplicate = next_matching(&mut nodes[1], |packet| {
        Msg1Header::parse(packet.data.as_slice()).is_some()
    })
    .await;
    nodes[1].node.handle_msg1(duplicate).await;
    let repeated_response = next_matching(&mut nodes[0], |packet| {
        Msg2Header::parse(packet.data.as_slice()).is_some()
    })
    .await;
    assert_eq!(repeated_response.data.as_slice(), response.data.as_slice());
    let before_replay = received(&nodes[1], &a);
    send_wire(nodes, 0, replay.data.as_slice()).await;
    let replayed = next_matching(&mut nodes[1], |packet| {
        packet.data.as_slice() == replay.data.as_slice()
    })
    .await;
    process_dataplane_packet(&mut nodes[1], replayed).await;
    settle_completions(&mut nodes[1]).await;
    assert_eq!(received(&nodes[1], &a), before_replay);

    send_wire(nodes, 0, delayed_old_frame.data.as_slice()).await;
    let delayed = next_matching(&mut nodes[1], |packet| {
        packet.data.as_slice() == delayed_old_frame.data.as_slice()
    })
    .await;
    process_dataplane_packet(&mut nodes[1], delayed).await;
    settle_completions(&mut nodes[1]).await;
    assert_eq!(
        received(&nodes[1], &a),
        before_replay + 1,
        "the old active session must still decrypt a genuine frame before fresh proof"
    );
    assert_eq!(owner(&nodes[1], &a), old_b);
    let candidate = nodes[1].node.get_connection(&candidate_link).unwrap();
    assert_eq!(candidate.our_index(), Some(candidate_index));
    assert_eq!(candidate.last_activity(), candidate_activity);
    assert!(candidate.handshake_confirmation().is_none());

    nodes[0].node.handle_msg2(response).await;
    assert_eq!(owner(&nodes[0], &c), owner_c);
    assert_eq!(
        nodes[0]
            .node
            .get_connection(&winning_link)
            .unwrap()
            .started_at(),
        winning_start
    );
    assert_eq!(
        nodes[0].node.neighbor_rotation_deadline(&b),
        Some(winning_deadline)
    );
    assert!(Node::now_ms() < winning_deadline);
    let proof = next_matching(&mut nodes[1], |packet| {
        FmpWireHeader::parse_encrypted(packet.data.as_slice())
            .is_ok_and(|header| header.receiver_idx() == candidate_index.as_u32())
    })
    .await;
    process_dataplane_packet(&mut nodes[1], proof).await;
    settle_completions(&mut nodes[1]).await;
    assert_eq!(
        nodes[1].node.get_peer(&a).unwrap().our_index(),
        Some(candidate_index)
    );
    assert!(nodes[1].node.get_connection(&candidate_link).is_none());

    quiesce(nodes).await;
    heartbeat(nodes, 0).await;
    heartbeat(nodes, 1).await;
    quiesce(nodes).await;
    assert_pair(nodes);
    assert!(nodes[0].node.get_peer(&c).is_none());
    assert_eq!(owner(&nodes[0], &b).our, winning_index);
    assert_eq!(resources(&nodes[0]), (1, 0, 1, 1));
    // B's old authenticated receive epoch remains for the normal drain.
    assert_eq!(resources(&nodes[1]), (1, 0, 1, 2));
    assert_eq!(
        nodes[1].node.get_peer(&a).unwrap().previous_our_index(),
        Some(old_b.our)
    );
    assert!(nodes[0].node.pending_outbound.is_empty());
    assert!(nodes[1].node.pending_outbound.is_empty());
    for node in nodes.iter() {
        assert_caps(node);
    }
    deliver_both_directions(nodes).await;
    assert_pair(nodes);
}
