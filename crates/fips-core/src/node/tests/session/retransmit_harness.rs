use super::*;

const SESSION_FIXTURE_TIMEOUT: Duration = Duration::from_secs(2);

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
        SESSION_FIXTURE_TIMEOUT,
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
        SESSION_FIXTURE_TIMEOUT,
        "initiator recovered by responder timer",
    )
    .await;

    cleanup_nodes(&mut nodes).await;
}

#[test]
fn fair_poll_drains_real_endpoint_and_tun_inputs() {
    run_large_stack_async_test("fips-fair-poll-upper-inputs", || async {
        let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
        populate_all_coord_caches(&mut nodes);
        let result = std::panic::AssertUnwindSafe(fair_poll_upper_inputs(&mut nodes));
        let result = futures::FutureExt::catch_unwind(result).await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn fair_poll_upper_inputs(nodes: &mut [TestNode]) {
    let source = *nodes[0].node.node_addr();
    let remote = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let source_io = nodes[0].node.attach_endpoint_data_io(8).unwrap();
    let mut destination_io = nodes[1].node.attach_endpoint_data_io(8).unwrap();
    let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
    nodes[1].node.tun_tx = Some(tun_tx);
    nodes[0]
        .node
        .initiate_session(*remote.node_addr(), remote.pubkey_full())
        .await
        .unwrap();
    wait_for_session_established(
        nodes,
        0,
        remote.node_addr(),
        SESSION_FIXTURE_TIMEOUT,
        "real upper-input fixture",
    )
    .await;
    drain_to_quiescence(nodes).await;

    // Enqueue through the actual embedded APIs. Calling the handler directly,
    // or substituting empty input receivers in the pump, would miss this test.
    source_io
        .data_batch_tx
        .send_or_drop(
            crate::node::NodeEndpointDataBatch::from_payloads(
                remote,
                vec![
                    crate::node::EndpointDataPayload::from_packet_payload(
                        b"endpoint-input".to_vec(),
                    )
                    .unwrap(),
                ],
                None,
            )
            .unwrap(),
        )
        .unwrap();
    let ipv6 = build_ipv6_packet(
        &crate::FipsAddress::from_node_addr(&source),
        &crate::FipsAddress::from_node_addr(remote.node_addr()),
        b"tun-input",
    );
    enqueue_tun_packet_via_dataplane(nodes, 0, ipv6.clone());
    let until = tokio::time::Instant::now() + Duration::from_secs(1);
    let (mut endpoint, mut tun) = (None, None);
    loop {
        poll_available_packets(nodes).await;
        if let Ok(event) = destination_io.event_rx.try_recv() {
            destination_io
                .event_rx
                .release_messages(event.messages.len());
            assert!(endpoint.is_none(), "one queued endpoint input");
            endpoint = Some(expect_single_endpoint_data_event(event));
        }
        if let Ok(packet) = tun_rx.try_recv_packet() {
            assert!(tun.is_none(), "one queued TUN input");
            tun = Some(packet.as_slice().to_vec());
        }
        if endpoint.is_some() && tun.is_some() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "both real inputs arrive"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let endpoint = endpoint.unwrap();
    assert_eq!(endpoint.source_peer.node_addr(), &source);
    assert_eq!(endpoint.payload.as_slice(), b"endpoint-input");
    assert_eq!(tun.unwrap(), ipv6);
    assert!(nodes[0].node.endpoint_data_rx.is_some());
    assert!(nodes[0].node.tun_outbound_rx.is_some());
}
