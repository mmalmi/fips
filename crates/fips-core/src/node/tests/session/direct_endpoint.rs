use super::*;

#[tokio::test]
async fn test_session_direct_peer_handshake() {
    // Two directly connected nodes: A initiates a session with B
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    // Node 0 initiates session with Node 1
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initiate_session failed");

    // Node 0 should have a session in Initiating state
    assert_eq!(nodes[0].node.session_count(), 1);
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_initiating()
    );

    // Process packets: SessionSetup arrives at Node 1
    let count = wait_process_packets_for_node(&mut nodes, 1).await;
    assert!(count > 0, "Expected SessionSetup packet to arrive");

    // Node 1 should now have a session in AwaitingMsg3 state (XK: identity not yet known)
    assert_eq!(nodes[1].node.session_count(), 1);
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .is_awaiting_msg3()
    );

    // Process packets: SessionAck arrives at Node 0, Node 0 sends SessionMsg3
    let count = wait_process_packets_for_node(&mut nodes, 0).await;
    assert!(count > 0, "Expected SessionAck packet to arrive");

    // Node 0 should now be Established (transitions after sending msg3)
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_established()
    );

    // Process packets: SessionMsg3 arrives at Node 1
    let count = wait_process_packets_for_node(&mut nodes, 1).await;
    assert!(count > 0, "Expected SessionMsg3 packet to arrive");

    // Node 1 should now be Established (transitions after processing msg3)
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .is_established()
    );

    cleanup_nodes(&mut nodes).await;
}

#[test]
fn test_registered_service_datagram_request_reply_and_ipv6_port_compatibility() {
    run_large_stack_async_test("fips-service-datagram-request-reply", || async {
        const CLIENT_PORT: u16 = 41_000;
        const SERVICE_PORT: u16 = 7368;
        let edges = vec![(0, 1)];
        let mut nodes = run_tree_test(2, &edges, false).await;
        verify_tree_convergence(&nodes);
        populate_all_coord_caches(&mut nodes);

        let mut client_endpoint = nodes[0]
            .node
            .attach_endpoint_data_io(8)
            .expect("client endpoint I/O should attach");
        let mut server_endpoint = nodes[1]
            .node
            .attach_endpoint_data_io(8)
            .expect("server endpoint I/O should attach");
        assert!(
            nodes[0]
                .node
                .endpoint_services
                .register(CLIENT_PORT, client_endpoint.service_event_tx.clone())
        );
        assert!(
            nodes[1]
                .node
                .endpoint_services
                .register(SERVICE_PORT, server_endpoint.service_event_tx.clone())
        );

        let client_identity =
            PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
        let server_identity =
            PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
        send_service_datagram_via_dataplane(
            &mut nodes[0].node,
            server_identity,
            CLIENT_PORT,
            SERVICE_PORT,
            b"REQ".to_vec(),
        )
        .await;

        let request = recv_service_event_while_draining(
            &mut nodes,
            &mut server_endpoint.service_event_rx,
            Duration::from_secs(10),
            "service request",
        )
        .await;
        assert_eq!(request.messages.len(), 1);
        let request = &request.messages[0];
        assert_eq!(request.source_peer, client_identity);
        assert_eq!(request.source_port, CLIENT_PORT);
        assert_eq!(request.destination_port, SERVICE_PORT);
        assert_eq!(request.payload.as_slice(), b"REQ");

        send_service_datagram_via_dataplane(
            &mut nodes[1].node,
            request.source_peer,
            SERVICE_PORT,
            request.source_port,
            b"EVENT".to_vec(),
        )
        .await;
        let reply = recv_service_event_while_draining(
            &mut nodes,
            &mut client_endpoint.service_event_rx,
            Duration::from_secs(10),
            "service reply",
        )
        .await;
        assert_eq!(reply.messages.len(), 1);
        let reply = &reply.messages[0];
        assert_eq!(reply.source_peer, server_identity);
        assert_eq!(reply.source_port, SERVICE_PORT);
        assert_eq!(reply.destination_port, CLIENT_PORT);
        assert_eq!(reply.payload.as_slice(), b"EVENT");

        let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
        nodes[1].node.tun_tx = Some(tun_tx);
        let ipv6_packet = build_ipv6_packet(
            client_identity.address(),
            server_identity.address(),
            b"port-256-still-ipv6",
        );
        send_tun_packet_via_dataplane(&mut nodes, 0, ipv6_packet.clone()).await;
        let delivered = recv_tun_packet_while_draining(
            &mut nodes,
            &tun_rx,
            Duration::from_secs(10),
            "port 256 IPv6 packet",
        )
        .await;
        assert_eq!(delivered, ipv6_packet);

        assert!(client_endpoint.event_rx.try_recv().is_err());
        assert!(server_endpoint.event_rx.try_recv().is_err());
        cleanup_nodes(&mut nodes).await;
    });
}

#[test]
fn test_endpoint_data_flushes_after_session_establishment() {
    run_large_stack_async_test("fips-endpoint-data-flushes", || async {
        let edges = vec![(0, 1)];
        let mut nodes = run_tree_test(2, &edges, false).await;
        verify_tree_convergence(&nodes);
        populate_all_coord_caches(&mut nodes);

        let mut node0_endpoint = nodes[0]
            .node
            .attach_endpoint_data_io(8)
            .expect("node 0 endpoint data I/O should attach");
        let mut node1_endpoint = nodes[1]
            .node
            .attach_endpoint_data_io(8)
            .expect("node 1 endpoint data I/O should attach");

        let node0_addr = *nodes[0].node.node_addr();
        let node1_addr = *nodes[1].node.node_addr();
        let node0_identity = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
        let node1_identity = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());

        send_endpoint_data_via_dataplane(&mut nodes[0].node, node1_identity, b"ping".to_vec())
            .await
            .expect("endpoint data should queue behind session establishment");

        let event = recv_endpoint_event_while_draining(
            &mut nodes,
            &mut node1_endpoint.event_rx,
            Duration::from_secs(10),
            "node 1 endpoint data",
        )
        .await;
        let message = expect_single_endpoint_data_event(event);
        assert_eq!(*message.source_peer.node_addr(), node0_addr);
        assert_eq!(message.source_peer.npub(), nodes[0].node.npub());
        assert_eq!(message.payload.as_slice(), &b"ping"[..]);

        send_endpoint_data_via_dataplane(&mut nodes[1].node, node0_identity, b"pong".to_vec())
            .await
            .expect("reply data should send");

        let event = recv_endpoint_event_while_draining(
            &mut nodes,
            &mut node0_endpoint.event_rx,
            Duration::from_secs(10),
            "node 0 endpoint data",
        )
        .await;
        let message = expect_single_endpoint_data_event(event);
        assert_eq!(*message.source_peer.node_addr(), node1_addr);
        assert_eq!(message.source_peer.npub(), nodes[1].node.npub());
        assert_eq!(message.payload.as_slice(), &b"pong"[..]);

        cleanup_nodes(&mut nodes).await;
    });
}

#[test]
fn test_endpoint_data_batch_flushes_after_session_establishment() {
    run_large_stack_async_test("fips-endpoint-data-batch-flushes", || async {
        let edges = vec![(0, 1)];
        let mut nodes = run_tree_test(2, &edges, false).await;
        verify_tree_convergence(&nodes);
        populate_all_coord_caches(&mut nodes);

        let mut node1_endpoint = nodes[1]
            .node
            .attach_endpoint_data_io(8)
            .expect("node 1 endpoint data I/O should attach");

        let node0_addr = *nodes[0].node.node_addr();
        let node1_identity = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
        let payloads = vec![
            crate::node::EndpointDataPayload::from_packet_payload(b"ping-1".to_vec())
                .expect("test endpoint payload"),
            crate::node::EndpointDataPayload::from_packet_payload(b"ping-2".to_vec())
                .expect("test endpoint payload"),
        ];

        let batch = crate::node::NodeEndpointDataBatch::from_payloads_with_enqueued_at_ms(
            node1_identity,
            payloads,
            None,
            1_234,
        )
        .expect("endpoint data batch");
        nodes[0]
            .node
            .handle_endpoint_data_batch_no_established_flush(batch)
            .await;

        let mut observed = Vec::new();
        while observed.len() < 2 {
            let event = recv_endpoint_event_while_draining(
                &mut nodes,
                &mut node1_endpoint.event_rx,
                Duration::from_secs(10),
                "node 1 endpoint data batch",
            )
            .await;
            let NodeEndpointEvent { messages, .. } = event;
            for message in messages {
                assert_eq!(*message.source_peer.node_addr(), node0_addr);
                assert_eq!(message.source_peer.npub(), nodes[0].node.npub());
                observed.push(message.payload.as_slice().to_vec());
            }
        }
        assert_eq!(observed, vec![b"ping-1".to_vec(), b"ping-2".to_vec()]);

        cleanup_nodes(&mut nodes).await;
    });
}

#[test]
fn test_established_endpoint_data_recovery_stays_out_of_pending_queue() {
    run_large_stack_async_test("fips-established-endpoint-data-direct-recovery", || async {
        let edges = vec![(0, 1)];
        let mut nodes = run_tree_test(2, &edges, false).await;
        verify_tree_convergence(&nodes);
        populate_all_coord_caches(&mut nodes);

        let mut node1_endpoint = nodes[1]
            .node
            .attach_endpoint_data_io(8)
            .expect("node 1 endpoint data I/O should attach");

        let node0_addr = *nodes[0].node.node_addr();
        let node1_addr = *nodes[1].node.node_addr();
        let node1_identity = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());

        send_endpoint_data_via_dataplane(&mut nodes[0].node, node1_identity, b"warmup".to_vec())
            .await
            .expect("endpoint data should establish the session");
        let event = recv_endpoint_event_while_draining(
            &mut nodes,
            &mut node1_endpoint.event_rx,
            Duration::from_secs(10),
            "node 1 warmup endpoint data",
        )
        .await;
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            b"warmup"
        );

        let payloads = vec![
            crate::node::EndpointDataPayload::from_packet_payload(b"steady".to_vec())
                .expect("test endpoint payload"),
        ];
        let batch = crate::node::NodeEndpointDataBatch::from_payloads_with_enqueued_at_ms(
            node1_identity,
            payloads,
            None,
            crate::time::now_ms(),
        )
        .expect("endpoint data batch");
        nodes[0]
            .node
            .handle_endpoint_data_batch_no_established_flush(batch)
            .await;

        assert!(
            !nodes[0]
                .node
                .pending_session_traffic
                .has_traffic_for(&node1_addr),
            "established endpoint recovery must not re-enter pending session traffic"
        );

        let event = recv_endpoint_event_while_draining(
            &mut nodes,
            &mut node1_endpoint.event_rx,
            Duration::from_secs(10),
            "node 1 steady endpoint data",
        )
        .await;
        let message = expect_single_endpoint_data_event(event);
        assert_eq!(*message.source_peer.node_addr(), node0_addr);
        assert_eq!(message.payload.as_slice(), b"steady");

        cleanup_nodes(&mut nodes).await;
    });
}

#[test]
fn test_endpoint_data_routes_through_non_endpoint_transit_node() {
    run_large_stack_async_test("fips-endpoint-data-transit", || async {
        let _guard = lock_large_network_test().await;
        // Loaded full-suite runs can concurrently exercise several large
        // in-memory overlays; preserve the delivery assertions while allowing
        // the three-node route enough scheduler time.
        const LOADED_ROUTE_TIMEOUT: Duration = Duration::from_secs(30);

        // A-B-C: Alice and Bob are app endpoints. The middle node is only FIPS
        // overlay transport and must not receive app-owned endpoint payloads.
        let edges = vec![(0, 1), (1, 2)];
        let mut nodes = run_tree_test(3, &edges, false).await;
        verify_tree_convergence(&nodes);
        populate_all_coord_caches(&mut nodes);

        let mut alice_endpoint = nodes[0]
            .node
            .attach_endpoint_data_io(8)
            .expect("alice endpoint data I/O should attach");
        let mut transit_endpoint = nodes[1]
            .node
            .attach_endpoint_data_io(8)
            .expect("transit endpoint data I/O should attach");
        let mut bob_endpoint = nodes[2]
            .node
            .attach_endpoint_data_io(8)
            .expect("bob endpoint data I/O should attach");

        let alice_addr = *nodes[0].node.node_addr();
        let bob_addr = *nodes[2].node.node_addr();
        let alice_identity = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
        let bob_identity = PeerIdentity::from_pubkey_full(nodes[2].node.identity().pubkey_full());

        send_endpoint_data_via_dataplane(
            &mut nodes[0].node,
            bob_identity,
            b"alice-to-bob".to_vec(),
        )
        .await
        .expect("alice endpoint data should send");

        let event = recv_endpoint_event_while_draining(
            &mut nodes,
            &mut bob_endpoint.event_rx,
            LOADED_ROUTE_TIMEOUT,
            "alice to bob endpoint data",
        )
        .await;
        let message = expect_single_endpoint_data_event(event);
        assert_eq!(*message.source_peer.node_addr(), alice_addr);
        assert_eq!(message.source_peer.npub(), nodes[0].node.npub());
        assert_eq!(message.payload.as_slice(), &b"alice-to-bob"[..]);

        assert!(
            nodes[1].node.get_session(&alice_addr).is_none(),
            "transit node must not create an app endpoint session for Alice"
        );
        assert!(
            nodes[1].node.get_session(&bob_addr).is_none(),
            "transit node must not create an app endpoint session for Bob"
        );
        assert!(
            transit_endpoint.event_rx.try_recv().is_err(),
            "transit node must not receive app endpoint data"
        );

        send_endpoint_data_via_dataplane(
            &mut nodes[2].node,
            alice_identity,
            b"bob-to-alice".to_vec(),
        )
        .await
        .expect("bob endpoint data should send");

        let event = recv_endpoint_event_while_draining(
            &mut nodes,
            &mut alice_endpoint.event_rx,
            LOADED_ROUTE_TIMEOUT,
            "bob to alice endpoint data",
        )
        .await;
        let message = expect_single_endpoint_data_event(event);
        assert_eq!(*message.source_peer.node_addr(), bob_addr);
        assert_eq!(message.source_peer.npub(), nodes[2].node.npub());
        assert_eq!(message.payload.as_slice(), &b"bob-to-alice"[..]);
        assert!(
            transit_endpoint.event_rx.try_recv().is_err(),
            "transit node must stay outside the app endpoint flow"
        );

        cleanup_nodes(&mut nodes).await;
    });
}

#[test]
fn test_endpoint_data_reply_learned_first_contact_routes_via_intermediary() {
    run_large_stack_async_test("fips-endpoint-data-reply-learned", || async {
        // A-B-C with no preloaded coordinate cache. A must discover C through B,
        // establish the end-to-end endpoint-data session over that route, and keep
        // B as pure transit.
        let edges = vec![(0, 1), (1, 2)];
        let mut nodes = run_tree_test(3, &edges, false).await;
        verify_tree_convergence(&nodes);
        for node in &mut nodes {
            node.node.config.node.routing.mode = RoutingMode::ReplyLearned;
        }

        let mut transit_endpoint = nodes[1]
            .node
            .attach_endpoint_data_io(8)
            .expect("transit endpoint data I/O should attach");
        let mut bob_endpoint = nodes[2]
            .node
            .attach_endpoint_data_io(8)
            .expect("bob endpoint data I/O should attach");

        let alice_addr = *nodes[0].node.node_addr();
        let bob_addr = *nodes[2].node.node_addr();
        let bob_identity = PeerIdentity::from_pubkey_full(nodes[2].node.identity().pubkey_full());

        send_endpoint_data_via_dataplane(
            &mut nodes[0].node,
            bob_identity,
            b"first-contact".to_vec(),
        )
        .await
        .expect("alice endpoint data should queue and trigger discovery");

        for _ in 0..120 {
            drain_to_quiescence(&mut nodes).await;
            if let Ok(event) = bob_endpoint.event_rx.try_recv() {
                let message = expect_single_endpoint_data_event(event);
                assert_eq!(*message.source_peer.node_addr(), alice_addr);
                assert_eq!(message.source_peer.npub(), nodes[0].node.npub());
                assert_eq!(message.payload.as_slice(), &b"first-contact"[..]);
                assert!(
                    nodes[1].node.get_session(&alice_addr).is_none(),
                    "transit node must not create an app endpoint session for Alice"
                );
                assert!(
                    nodes[1].node.get_session(&bob_addr).is_none(),
                    "transit node must not create an app endpoint session for Bob"
                );
                assert!(
                    transit_endpoint.event_rx.try_recv().is_err(),
                    "transit node must not receive app endpoint data"
                );
                cleanup_nodes(&mut nodes).await;
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        cleanup_nodes(&mut nodes).await;
        panic!("reply-learned first-contact endpoint data did not reach Bob");
    });
}

// ============================================================================
// Integration tests: 3-node forwarded session
// ============================================================================
