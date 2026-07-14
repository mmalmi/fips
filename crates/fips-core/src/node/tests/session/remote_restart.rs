use super::*;

#[test]
fn test_recovery_rekey_replaces_session_after_remote_restart() {
    run_large_stack_async_test("fips-session-remote-restart", || async {
        recovery_rekey_replaces_session_after_remote_restart().await;
    });
}

#[test]
fn test_restarted_initiator_reestablishes_with_surviving_responder() {
    run_large_stack_async_test("fips-session-restarted-initiator", || async {
        restarted_initiator_reestablishes_with_surviving_responder().await;
    });
}

async fn recovery_rekey_replaces_session_after_remote_restart() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let survivor_addr = *nodes[0].node.node_addr();
    let restarted_addr = *nodes[1].node.node_addr();
    let restarted_identity = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());

    nodes[0]
        .node
        .initiate_session(restarted_addr, restarted_identity.pubkey_full())
        .await
        .expect("initial session should start");
    wait_for_session_established(
        &mut nodes,
        0,
        &restarted_addr,
        Duration::from_secs(10),
        "survivor initial session",
    )
    .await;
    wait_for_session_established(
        &mut nodes,
        1,
        &survivor_addr,
        Duration::from_secs(10),
        "restarted peer initial session",
    )
    .await;

    nodes[1].node.remove_dataplane_fsp_owner(&survivor_addr);
    assert!(nodes[1].node.remove_session(&survivor_addr).is_some());
    nodes[1].node.startup_epoch[0] ^= 0xff;

    assert!(
        nodes[0].node.initiate_session_rekey(&restarted_addr).await,
        "survivor should start recovery handshake"
    );
    assert!(wait_process_packets_for_node(&mut nodes, 1).await > 0);
    assert!(wait_process_packets_for_node(&mut nodes, 0).await > 0);

    let survivor_session = nodes[0].node.get_session(&restarted_addr).unwrap();
    assert!(survivor_session.is_established());
    assert!(!survivor_session.current_k_bit());
    assert!(survivor_session.pending_new_session().is_none());

    assert!(wait_process_packets_for_node(&mut nodes, 1).await > 0);
    let restarted_session = nodes[1].node.get_session(&survivor_addr).unwrap();
    assert!(restarted_session.is_established());
    assert!(!restarted_session.current_k_bit());

    let mut restarted_endpoint = nodes[1]
        .node
        .attach_endpoint_data_io(8)
        .expect("restarted endpoint data I/O should attach");
    send_endpoint_data_via_dataplane(
        &mut nodes[0].node,
        restarted_identity,
        b"restart-recovered".to_vec(),
    )
    .await
    .expect("recovered session should send endpoint data");
    let event = recv_endpoint_event_while_draining(
        &mut nodes,
        &mut restarted_endpoint.event_rx,
        Duration::from_secs(10),
        "restarted peer recovered endpoint data",
    )
    .await;
    assert_eq!(
        expect_single_endpoint_data_event(event).payload.as_slice(),
        &b"restart-recovered"[..]
    );

    cleanup_nodes(&mut nodes).await;
}

async fn restarted_initiator_reestablishes_with_surviving_responder() {
    let _guard = lock_large_network_test().await;
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let restarted_addr = *nodes[0].node.node_addr();
    let survivor_addr = *nodes[1].node.node_addr();
    let restarted_identity = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
    let survivor_identity = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());

    nodes[0]
        .node
        .initiate_session(survivor_addr, survivor_identity.pubkey_full())
        .await
        .expect("initial session should start");
    wait_for_session_established(
        &mut nodes,
        0,
        &survivor_addr,
        Duration::from_secs(10),
        "restarted peer initial session",
    )
    .await;
    wait_for_session_established(
        &mut nodes,
        1,
        &restarted_addr,
        Duration::from_secs(10),
        "survivor initial session",
    )
    .await;

    let survivor_session = nodes[1].node.get_session(&restarted_addr).unwrap();
    assert!(!survivor_session.is_initiator());
    assert!(
        survivor_session.handshake_payload().is_some(),
        "surviving responder should still retain its initial SessionAck"
    );

    nodes[0].node.remove_dataplane_fsp_owner(&survivor_addr);
    assert!(nodes[0].node.remove_session(&survivor_addr).is_some());
    nodes[0].node.startup_epoch[0] ^= 0xff;

    nodes[0]
        .node
        .initiate_session(survivor_addr, survivor_identity.pubkey_full())
        .await
        .expect("restarted peer should start a fresh session");
    assert!(wait_process_packets_for_node(&mut nodes, 1).await > 0);
    assert!(
        nodes[1]
            .node
            .get_session(&restarted_addr)
            .is_some_and(|entry| entry.has_rekey_in_progress()),
        "surviving responder must process the restarted peer's fresh setup"
    );
    assert!(wait_process_packets_for_node(&mut nodes, 0).await > 0);
    assert!(wait_process_packets_for_node(&mut nodes, 1).await > 0);

    let restarted_session = nodes[0].node.get_session(&survivor_addr).unwrap();
    assert!(restarted_session.is_established());
    assert!(!restarted_session.current_k_bit());

    let survivor_session = nodes[1].node.get_session(&restarted_addr).unwrap();
    assert!(survivor_session.is_established());
    assert!(!survivor_session.current_k_bit());
    assert!(survivor_session.pending_new_session().is_none());

    let mut restarted_endpoint = nodes[0]
        .node
        .attach_endpoint_data_io(8)
        .expect("restarted endpoint data I/O should attach");
    send_endpoint_data_via_dataplane(
        &mut nodes[1].node,
        restarted_identity,
        b"restarted-initiator-recovered".to_vec(),
    )
    .await
    .expect("recovered session should send endpoint data");
    let event = recv_endpoint_event_while_draining(
        &mut nodes,
        &mut restarted_endpoint.event_rx,
        Duration::from_secs(10),
        "restarted initiator recovered endpoint data",
    )
    .await;
    assert_eq!(
        expect_single_endpoint_data_event(event).payload.as_slice(),
        &b"restarted-initiator-recovered"[..]
    );

    cleanup_nodes(&mut nodes).await;
}
