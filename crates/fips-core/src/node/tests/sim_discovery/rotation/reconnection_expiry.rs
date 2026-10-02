//! A real unanswered candidate must not extend an incumbent's native lifetime.
use super::*;

#[test]
fn held_replacement_candidate_does_not_exempt_native_link_expiry() {
    run_large_stack_async_test("held-replacement-link-expiry", || async {
        let _guard = spanning_tree::lock_large_network_test().await;
        let name = format!("held-replacement-link-expiry-{}", std::process::id());
        let (network, mut nodes) = topology(&name).await;
        let result = AssertUnwindSafe(exercise_expiry(&mut nodes, &network))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        unregister_sim_network(&name);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise_expiry(nodes: &mut [TestNode], network: &SimNetwork) {
    network.set_link(NAMES[A], NAMES[S], SimLink::default());
    nodes[A].node.poll_transport_discovery().await;
    authenticate(nodes, S).await;
    network.set_link(NAMES[A], NAMES[R], SimLink::default());
    nodes[A].node.poll_transport_discovery().await;
    authenticate(nodes, R).await;
    let returning = *nodes[R].node.node_addr();
    let candidate = *nodes[I].node.node_addr();
    let original = owner(nodes, A, R);
    let mut traffic = Traffic::new(nodes, None);
    wait_for(
        nodes,
        &mut traffic,
        3,
        "live incumbent becomes eligible",
        |nodes, traffic| {
            !traffic.received.is_empty()
                && nodes[A].node.peer_has_application_demand(
                    nodes[S].node.node_addr(),
                    Node::now_ms(),
                    1_000,
                )
                && nodes[A]
                    .node
                    .has_neighbor_rotation_opportunity(Node::now_ms())
        },
    )
    .await;
    assert_eq!(owner(nodes, A, R), original);

    // Hold the production-generated Msg1 at its actual destination. A dummy
    // receiver lets ordinary turns service every other node without confirming it.
    let (_dummy_tx, dummy_rx) = crate::transport::packet_channel(8);
    let mut held_rx = std::mem::replace(&mut nodes[I].packet_rx, dummy_rx);
    network.set_link(NAMES[A], NAMES[I], SimLink::default());
    nodes[A].node.poll_transport_discovery().await;
    let pending = nodes[A].node.peers.connection_values().next().unwrap();
    assert_eq!(pending.expected_identity().unwrap().node_addr(), &candidate);
    assert!(pending.is_outbound() && !pending.has_session());
    let pending_link = pending.link_id();
    let msg1 = pending.handshake_msg1().unwrap().to_vec();
    let deadline_ms = nodes[A]
        .node
        .neighbor_rotation_deadline(&candidate)
        .unwrap();
    let packet = tokio::time::timeout(Duration::from_secs(1), held_rx.recv())
        .await
        .expect("actual candidate Msg1 arrival")
        .unwrap();
    assert_eq!(packet.remote_addr, nodes[A].addr);
    assert_eq!(packet.data.as_slice(), msg1);
    let mut held = vec![packet];
    traffic.cut_returning_link(network);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while nodes[A].node.get_peer(&returning).is_some() {
        tokio::time::timeout_at(deadline, traffic.turn(nodes, true))
            .await
            .expect("native three-second link expiry while candidate is held");
        while let Ok(packet) = held_rx.try_recv() {
            assert_eq!(packet.remote_addr, nodes[A].addr);
            assert_eq!(packet.data.as_slice(), msg1);
            assert!(held.len() < 8, "bounded original candidate frames");
            held.push(packet);
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        Node::now_ms() < deadline_ms,
        "candidate handshake has not expired"
    );
    let pending = nodes[A].node.peers.get_connection(&pending_link).unwrap();
    assert!(!pending.has_session());
    assert!(nodes[A].node.get_peer(&candidate).is_none());
    assert!(nodes[I].node.get_peer(nodes[A].node.node_addr()).is_none());
    assert_eq!(nodes[A].node.peer_count(), 1);
    assert!(nodes[A].node.get_link(&original.0).is_none());
    assert!(
        !nodes[A]
            .node
            .index_allocator
            .is_allocated(original.1.unwrap())
    );
    caps(nodes);

    nodes[I].packet_rx = held_rx;
    for packet in held {
        spanning_tree::process_dataplane_packet(&mut nodes[I], packet).await;
    }
    authenticate(nodes, I).await;
    assert_eq!(owner(nodes, A, S), traffic.local_owner[1]);
    caps(nodes);
}
