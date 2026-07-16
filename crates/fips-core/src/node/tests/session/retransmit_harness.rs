use super::*;

#[test]
fn test_session_wait_drains_ack_before_due_setup_resend() {
    run_large_stack_async_test("fips-session-drain-before-retransmit", || async {
        session_wait_drains_ack_before_due_setup_resend().await;
    });
}

async fn session_wait_drains_ack_before_due_setup_resend() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    populate_all_coord_caches(&mut nodes);

    nodes[0]
        .node
        .config
        .node
        .rate_limit
        .handshake_resend_interval_ms = 1;

    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();
    let peer_packets_sent = |nodes: &[TestNode]| {
        nodes[0]
            .node
            .get_peer(&node1_addr)
            .expect("direct peer should exist")
            .link_stats()
            .packets_sent
    };

    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("session initiation should start");
    assert!(
        wait_process_packets_for_node(&mut nodes, 1).await > 0,
        "responder should queue SessionAck for the initiator"
    );
    let sent_before_wait = peer_packets_sent(&nodes);
    tokio::time::sleep(Duration::from_millis(2)).await;

    wait_for_session_established(
        &mut nodes,
        0,
        &node1_addr,
        Duration::from_millis(250),
        "initiator consumes queued Ack",
    )
    .await;

    assert_eq!(
        peer_packets_sent(&nodes) - sent_before_wait,
        1,
        "queued Ack should produce only msg3, not an unnecessary Setup resend"
    );

    cleanup_nodes(&mut nodes).await;
}

#[test]
fn test_session_wait_drives_all_nodes_retransmit_timers() {
    run_large_stack_async_test("fips-session-all-node-retransmit", || async {
        session_wait_drives_all_nodes_retransmit_timers().await;
    });
}

async fn session_wait_drives_all_nodes_retransmit_timers() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    populate_all_coord_caches(&mut nodes);

    nodes[1]
        .node
        .config
        .node
        .rate_limit
        .handshake_resend_interval_ms = 5;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("session initiation should start");
    assert!(
        wait_process_packets_for_node(&mut nodes, 1).await > 0,
        "responder should receive the initial SessionSetup"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .is_some_and(|entry| entry.is_awaiting_msg3()),
        "responder should retain SessionAck retransmit state"
    );

    assert!(
        wait_drop_queued_packets_for_node(&mut nodes[0]).await > 0,
        "fixture should drop the first SessionAck"
    );
    nodes[0]
        .node
        .sessions
        .get_mut(&node1_addr)
        .expect("initiator session should exist")
        .clear_handshake_payload();

    wait_for_session_established(
        &mut nodes,
        0,
        &node1_addr,
        Duration::from_millis(250),
        "initiator recovered by responder timer",
    )
    .await;

    cleanup_nodes(&mut nodes).await;
}
