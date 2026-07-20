use super::*;

#[test]
fn test_established_initiator_resends_final_msg3_until_responder_establishes() {
    run_large_stack_async_test("fips-established-msg3-resend", || async {
        established_initiator_resends_final_msg3_until_responder_establishes().await;
    });
}

#[test]
fn test_established_initiator_answers_late_ack_after_resend_budget() {
    run_large_stack_async_test("fips-established-msg3-late-ack", || async {
        established_initiator_answers_late_ack_after_resend_budget().await;
    });
}

async fn established_initiator_answers_late_ack_after_resend_budget() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    nodes[0].node.config.node.rate_limit.handshake_max_resends = 1;
    nodes[1].node.config.node.rate_limit.handshake_max_resends = 3;
    nodes[0]
        .node
        .config
        .node
        .rate_limit
        .handshake_resend_interval_ms = 5;
    nodes[1]
        .node
        .config
        .node
        .rate_limit
        .handshake_resend_interval_ms = 5;

    let initiator_addr = *nodes[0].node.node_addr();
    let responder_addr = *nodes[1].node.node_addr();
    let responder_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(responder_addr, responder_pubkey)
        .await
        .expect("session initiation should start");
    assert!(wait_process_packets_for_node(&mut nodes, 1).await > 0);
    assert!(wait_process_packets_for_node(&mut nodes, 0).await > 0);
    assert!(wait_drop_queued_packets_for_node(&mut nodes[1]).await > 0);
    assert!(
        nodes[1]
            .node
            .get_session(&initiator_addr)
            .is_some_and(|entry| entry.is_awaiting_msg3())
    );

    nodes[0]
        .node
        .sessions
        .get_mut(&responder_addr)
        .expect("established initiator session")
        .record_resend(0);
    nodes[0]
        .node
        .resend_pending_session_handshakes(Node::now_ms())
        .await;
    assert!(
        nodes[0]
            .node
            .get_session(&responder_addr)
            .and_then(|entry| entry.handshake_payload())
            .is_some(),
        "the final msg3 must remain available after proactive retries stop"
    );

    tokio::time::sleep(Duration::from_millis(10)).await;
    nodes[1]
        .node
        .resend_pending_session_handshakes(Node::now_ms())
        .await;
    assert!(
        wait_process_packets_for_node(&mut nodes, 0).await > 0,
        "the late responder Ack should reach the initiator"
    );
    assert!(
        wait_process_packets_for_node(&mut nodes, 1).await > 0,
        "the initiator should answer the late Ack with retained msg3"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&initiator_addr)
            .is_some_and(|entry| entry.is_established()),
        "the responder should establish after the solicited msg3 resend"
    );

    cleanup_nodes(&mut nodes).await;
}

async fn established_initiator_resends_final_msg3_until_responder_establishes() {
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    nodes[0]
        .node
        .config
        .node
        .rate_limit
        .handshake_resend_interval_ms = 5;
    nodes[0].node.config.node.rate_limit.handshake_max_resends = 3;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("session initiation should start");

    let count = wait_process_packets_for_node(&mut nodes, 1).await;
    assert!(count > 0, "SessionSetup should reach responder");
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .is_awaiting_msg3()
    );

    let count = wait_process_packets_for_node(&mut nodes, 0).await;
    assert!(count > 0, "SessionAck should reach initiator");
    let initiator_entry = nodes[0].node.get_session(&node1_addr).unwrap();
    assert!(initiator_entry.is_established());
    assert!(
        initiator_entry.handshake_payload().is_some(),
        "initiator should retain final msg3 for loss recovery"
    );

    tokio::time::sleep(Duration::from_millis(10)).await;
    let mut dropped = 0;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        dropped += drop_queued_packets_for_node(&mut nodes[1]);
        if dropped > 0 {
            break;
        }
    }
    assert!(dropped > 0, "fixture should drop the first SessionMsg3");
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .is_awaiting_msg3(),
        "responder should still be waiting after the dropped msg3"
    );

    tokio::time::sleep(Duration::from_millis(10)).await;
    let now_ms = Node::now_ms();
    nodes[0]
        .node
        .resend_pending_session_handshakes(now_ms)
        .await;

    let count = wait_process_packets_for_node(&mut nodes, 1).await;
    assert!(
        count > 0,
        "resender should deliver a replacement SessionMsg3"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .is_established(),
        "responder should establish from the resent SessionMsg3"
    );

    let mut node0_endpoint = nodes[0]
        .node
        .attach_endpoint_data_io(8)
        .expect("initiator endpoint data I/O should attach");
    let node0_identity = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
    send_endpoint_data_via_dataplane(
        &mut nodes[1].node,
        node0_identity,
        b"responder-proof".to_vec(),
    )
    .await
    .expect("responder should send endpoint data after establishment");
    let event = recv_endpoint_event_while_draining(
        &mut nodes,
        &mut node0_endpoint.event_rx,
        Duration::from_secs(10),
        "initiator responder-proof endpoint data",
    )
    .await;
    let message = expect_single_endpoint_data_event(event);
    assert_eq!(*message.source_peer.node_addr(), node1_addr);
    assert_eq!(message.payload.as_slice(), &b"responder-proof"[..]);
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .handshake_payload()
            .is_none(),
        "authentic responder traffic should clear the retained final msg3"
    );

    cleanup_nodes(&mut nodes).await;
}

#[test]
fn test_rekey_initiator_resends_final_msg3_until_responder_has_pending_session() {
    run_large_stack_async_test("fips-rekey-msg3-resend", || async {
        rekey_initiator_resends_final_msg3_until_responder_has_pending_session().await;
    });
}

async fn rekey_initiator_resends_final_msg3_until_responder_has_pending_session() {
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    nodes[0]
        .node
        .config
        .node
        .rate_limit
        .handshake_resend_interval_ms = 5;
    nodes[0].node.config.node.rate_limit.handshake_max_resends = 3;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initial session should start");
    wait_for_session_established(
        &mut nodes,
        0,
        &node1_addr,
        Duration::from_secs(10),
        "initial rekey msg3 fixture initiator",
    )
    .await;
    wait_for_session_established(
        &mut nodes,
        1,
        &node0_addr,
        Duration::from_secs(10),
        "initial rekey msg3 fixture responder",
    )
    .await;
    drain_to_quiescence(&mut nodes).await;
    settle_session_handshake_retransmits(&mut nodes, 0, &node1_addr, 1, &node0_addr);

    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_established()
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .is_established()
    );

    assert!(
        nodes[0].node.initiate_session_rekey(&node1_addr).await,
        "rekey should start"
    );

    wait_for_session_state_for_node(
        &mut nodes,
        1,
        &node0_addr,
        "rekey msg1 responder state",
        |entry| entry.has_rekey_in_progress() && !entry.is_rekey_initiator(),
    )
    .await;
    wait_for_session_state_for_node(
        &mut nodes,
        0,
        &node1_addr,
        "rekey msg2 initiator state",
        |entry| entry.pending_new_session().is_some(),
    )
    .await;
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "initiator should have a pending new session"
    );
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .rekey_msg3_payload()
            .is_some(),
        "initiator must retain rekey msg3 for resend"
    );

    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if drop_queued_packets_for_node(&mut nodes[1]) > 0 {
            break;
        }
    }
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .pending_new_session()
            .is_none(),
        "responder should not have the new session before msg3 is resent"
    );

    let mut node0_endpoint = nodes[0]
        .node
        .attach_endpoint_data_io(8)
        .expect("initiator endpoint data I/O should attach");
    let node0_identity = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
    send_endpoint_data_via_dataplane(
        &mut nodes[1].node,
        node0_identity,
        b"old-session-proof".to_vec(),
    )
    .await
    .expect("old session should carry endpoint data while rekey msg3 is pending");
    let event = recv_endpoint_event_while_draining(
        &mut nodes,
        &mut node0_endpoint.event_rx,
        Duration::from_secs(10),
        "initiator old-session-proof endpoint data",
    )
    .await;
    let message = expect_single_endpoint_data_event(event);
    assert_eq!(*message.source_peer.node_addr(), node1_addr);
    assert_eq!(message.payload.as_slice(), &b"old-session-proof"[..]);
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .rekey_msg3_payload()
            .is_some(),
        "old-session traffic must not clear retained rekey msg3"
    );
    let resend_count_before = nodes[0]
        .node
        .get_session(&node1_addr)
        .unwrap()
        .rekey_msg3_resend_count();

    tokio::time::sleep(Duration::from_millis(10)).await;
    let now_ms = Node::now_ms();
    nodes[0].node.resend_pending_session_msg3(now_ms).await;
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .rekey_msg3_resend_count()
            > resend_count_before,
        "rekey msg3 resend should be recorded"
    );

    wait_for_session_state_for_node(
        &mut nodes,
        1,
        &node0_addr,
        "replacement rekey msg3 responder state",
        |entry| entry.pending_new_session().is_some(),
    )
    .await;
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "responder should store the pending rekey session after resent msg3"
    );

    cleanup_nodes(&mut nodes).await;
}

#[test]
fn test_rekey_initiator_resends_msg1_when_first_setup_lost() {
    run_large_stack_async_test("fips-rekey-msg1-resend", || async {
        rekey_initiator_resends_msg1_when_first_setup_lost().await;
    });
}

async fn rekey_initiator_resends_msg1_when_first_setup_lost() {
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    nodes[0]
        .node
        .config
        .node
        .rate_limit
        .handshake_resend_interval_ms = 5;
    nodes[0].node.config.node.rate_limit.handshake_max_resends = 3;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initial session should start");
    wait_for_session_established(
        &mut nodes,
        0,
        &node1_addr,
        Duration::from_secs(10),
        "initial rekey exhaustion fixture initiator",
    )
    .await;
    wait_for_session_established(
        &mut nodes,
        1,
        &node0_addr,
        Duration::from_secs(10),
        "initial rekey exhaustion fixture responder",
    )
    .await;
    drain_to_quiescence(&mut nodes).await;
    settle_session_handshake_retransmits(&mut nodes, 0, &node1_addr, 1, &node0_addr);

    assert!(
        nodes[0].node.initiate_session_rekey(&node1_addr).await,
        "rekey should start"
    );
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .handshake_payload()
            .is_some(),
        "initiator must retain rekey msg1 for resend"
    );

    let dropped = wait_drop_queued_packets_for_node(&mut nodes[1]).await;
    assert!(dropped > 0, "fixture should drop the first rekey msg1");

    tokio::time::sleep(Duration::from_millis(10)).await;
    nodes[0]
        .node
        .resend_pending_session_handshakes(Node::now_ms())
        .await;

    wait_for_session_state_for_node(
        &mut nodes,
        1,
        &node0_addr,
        "replacement rekey msg1 responder state",
        |entry| entry.has_rekey_in_progress() && !entry.is_rekey_initiator(),
    )
    .await;
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .has_rekey_in_progress(),
        "responder should process the resent rekey msg1"
    );
    assert!(
        !nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .is_rekey_initiator(),
        "responder side should not become a competing initiator"
    );

    wait_for_session_state_for_node(
        &mut nodes,
        0,
        &node1_addr,
        "replacement rekey msg2 initiator state",
        |entry| entry.pending_new_session().is_some(),
    )
    .await;
    let entry = nodes[0].node.get_session(&node1_addr).unwrap();
    assert!(
        entry.pending_new_session().is_some(),
        "initiator should complete XK after resent msg1"
    );
    assert!(
        entry.handshake_payload().is_none(),
        "rekey msg1 resend payload should clear once msg2 arrives"
    );

    cleanup_nodes(&mut nodes).await;
}

#[test]
fn test_rekey_msg1_exhaustion_allows_peer_msg1_to_converge() {
    run_large_stack_async_test("fips-rekey-msg1-exhaustion", || async {
        rekey_msg1_exhaustion_allows_peer_msg1_to_converge().await;
    });
}

async fn rekey_msg1_exhaustion_allows_peer_msg1_to_converge() {
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initial session should start");
    wait_for_session_established(
        &mut nodes,
        0,
        &node1_addr,
        Duration::from_secs(10),
        "initial rekey exhaustion fixture initiator",
    )
    .await;
    wait_for_session_established(
        &mut nodes,
        1,
        &node0_addr,
        Duration::from_secs(10),
        "initial rekey exhaustion fixture responder",
    )
    .await;

    let smaller = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        0
    } else {
        1
    };
    let larger = 1 - smaller;
    let smaller_addr = *nodes[smaller].node.node_addr();
    let larger_addr = *nodes[larger].node.node_addr();

    nodes[smaller]
        .node
        .config
        .node
        .rate_limit
        .handshake_max_resends = 0;
    assert!(
        nodes[smaller]
            .node
            .initiate_session_rekey(&larger_addr)
            .await,
        "smaller side should start local rekey"
    );
    assert!(
        nodes[smaller]
            .node
            .get_session(&larger_addr)
            .unwrap()
            .handshake_payload()
            .is_some(),
        "local rekey msg1 should be retained before exhaustion"
    );

    let dropped = wait_drop_queued_packets_for_node(&mut nodes[larger]).await;
    assert!(dropped > 0, "fixture should drop smaller side's rekey msg1");

    nodes[smaller]
        .node
        .resend_pending_session_handshakes(Node::now_ms())
        .await;
    let entry = nodes[smaller].node.get_session(&larger_addr).unwrap();
    assert!(
        !entry.has_rekey_in_progress(),
        "exhausted local rekey should be abandoned"
    );
    assert!(
        entry.handshake_payload().is_none(),
        "abandoning local rekey must clear stale msg1 payload"
    );

    assert!(
        nodes[larger]
            .node
            .initiate_session_rekey(&smaller_addr)
            .await,
        "larger side should be able to start its own fresh rekey"
    );
    let count = wait_process_packets_for_node(&mut nodes, smaller).await;
    assert!(
        count > 0,
        "smaller side should process peer msg1 after abandoning stale local rekey"
    );
    let entry = nodes[smaller].node.get_session(&larger_addr).unwrap();
    assert!(
        entry.has_rekey_in_progress(),
        "smaller side should now be the rekey responder"
    );
    assert!(
        !entry.is_rekey_initiator(),
        "stale tiebreak winner must not keep dropping peer msg1"
    );

    cleanup_nodes(&mut nodes).await;
}

include!("resend_rekey_large_mesh.rs");
