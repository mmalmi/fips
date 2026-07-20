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
    let original_handshake_hash = *nodes[0]
        .node
        .get_session(&restarted_addr)
        .and_then(|session| session.handshake_hash())
        .expect("initial session should have a handshake hash");

    nodes[1].node.remove_dataplane_fsp_owner(&survivor_addr);
    assert!(nodes[1].node.remove_session(&survivor_addr).is_some());
    nodes[1].node.startup_epoch[0] ^= 0xff;

    assert!(
        nodes[0].node.initiate_session_rekey(&restarted_addr).await,
        "survivor should start recovery handshake"
    );
    wait_for_session_established(
        &mut nodes,
        1,
        &survivor_addr,
        Duration::from_secs(10),
        "restarted peer recovery session",
    )
    .await;

    let survivor_session = nodes[0].node.get_session(&restarted_addr).unwrap();
    assert!(survivor_session.is_established());
    assert!(!survivor_session.current_k_bit());
    assert!(survivor_session.pending_new_session().is_none());

    let restarted_session = nodes[1].node.get_session(&survivor_addr).unwrap();
    assert!(restarted_session.is_established());
    assert!(!restarted_session.current_k_bit());
    assert_ne!(
        survivor_session.handshake_hash(),
        Some(&original_handshake_hash),
        "the survivor must replace the stale session"
    );
    assert_eq!(
        survivor_session.handshake_hash(),
        restarted_session.handshake_hash(),
        "both peers must install the same recovery session"
    );

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
    wait_for_session_established(
        &mut nodes,
        0,
        &survivor_addr,
        Duration::from_secs(10),
        "restarted initiator fresh session",
    )
    .await;
    wait_for_session_rekey_complete(
        &mut nodes,
        1,
        &restarted_addr,
        Duration::from_secs(10),
        "surviving responder fresh session",
    )
    .await;

    let restarted_session = nodes[0].node.get_session(&survivor_addr).unwrap();
    assert!(restarted_session.is_established());
    assert!(!restarted_session.current_k_bit());

    let survivor_session = nodes[1].node.get_session(&restarted_addr).unwrap();
    assert!(survivor_session.is_established());
    assert!(!survivor_session.current_k_bit());
    assert!(survivor_session.pending_new_session().is_none());
    assert_eq!(
        restarted_session.handshake_hash(),
        survivor_session.handshake_hash(),
        "both peers must install the same restarted session"
    );
    let recovered_handshake_hash = survivor_session.handshake_hash().copied();
    let restarted_epoch = nodes[0].node.startup_epoch;
    assert!(
        !nodes[1]
            .node
            .clear_stale_fsp_unless_recovered_to_remote_epoch(
                &restarted_addr,
                Some(restarted_epoch),
                "test FMP recovery",
            ),
        "a later FMP recovery must preserve an FSP session that already authenticated the restarted peer epoch"
    );
    assert_eq!(
        nodes[1]
            .node
            .get_session(&restarted_addr)
            .expect("recovered FSP session must remain installed")
            .handshake_hash()
            .copied(),
        recovered_handshake_hash,
    );
    assert!(nodes[0].node.dataplane_has_fsp_owner(&survivor_addr));
    assert!(nodes[1].node.dataplane_has_fsp_owner(&restarted_addr));

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

    let mut survivor_endpoint = nodes[1]
        .node
        .attach_endpoint_data_io(8)
        .expect("survivor endpoint data I/O should attach");
    send_endpoint_data_via_dataplane(
        &mut nodes[0].node,
        survivor_identity,
        b"survivor-received-after-restart".to_vec(),
    )
    .await
    .expect("restarted initiator should send endpoint data");
    let event = recv_endpoint_event_while_draining(
        &mut nodes,
        &mut survivor_endpoint.event_rx,
        Duration::from_secs(10),
        "survivor endpoint data from restarted initiator",
    )
    .await;
    assert_eq!(
        expect_single_endpoint_data_event(event).payload.as_slice(),
        &b"survivor-received-after-restart"[..]
    );

    cleanup_nodes(&mut nodes).await;
}
