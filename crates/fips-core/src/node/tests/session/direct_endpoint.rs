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
            .state()
            .is_initiating()
    );

    // Process packets: SessionSetup arrives at Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(count > 0, "Expected SessionSetup packet to arrive");

    // Node 1 should now have a session in AwaitingMsg3 state (XK: identity not yet known)
    assert_eq!(nodes[1].node.session_count(), 1);
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .state()
            .is_awaiting_msg3()
    );

    // Process packets: SessionAck arrives at Node 0, Node 0 sends SessionMsg3
    tokio::time::sleep(Duration::from_millis(20)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(count > 0, "Expected SessionAck packet to arrive");

    // Node 0 should now be Established (transitions after sending msg3)
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .state()
            .is_established()
    );

    // Process packets: SessionMsg3 arrives at Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(count > 0, "Expected SessionMsg3 packet to arrive");

    // Node 1 should now be Established (transitions after processing msg3)
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .state()
            .is_established()
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_session_direct_peer_data_transfer() {
    // Two nodes: establish session, then send data
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    // Establish session (XK: 3 messages — Setup, Ack, Msg3)
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await; // Setup → Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await; // Ack → Node 0, Node 0 sends Msg3
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await; // Msg3 → Node 1

    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .state()
            .is_established()
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .state()
            .is_established()
    );

    // Send data from Node 0 to Node 1
    let test_data = b"Hello, FIPS session!";
    nodes[0]
        .node
        .send_session_data(&node1_addr, 0, 0, test_data)
        .await
        .expect("send_session_data failed");

    // Process packets: encrypted data arrives at Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(count > 0, "Expected encrypted data to arrive");

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_endpoint_data_flushes_after_session_establishment() {
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

    nodes[0]
        .node
        .send_endpoint_data(node1_identity, b"ping".to_vec())
        .await
        .expect("endpoint data should queue behind session establishment");

    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }

    let event = tokio::time::timeout(Duration::from_secs(1), node1_endpoint.event_rx.recv())
        .await
        .expect("endpoint data event should not time out")
        .expect("endpoint data event should arrive");
    match event {
        NodeEndpointEvent::Data {
            source_peer,
            payload,
            ..
        } => {
            assert_eq!(*source_peer.node_addr(), node0_addr);
            assert_eq!(source_peer.npub(), nodes[0].node.npub());
            assert_eq!(payload, b"ping");
        }
        NodeEndpointEvent::DataBatch { .. } => panic!("expected single endpoint data event"),
    }

    nodes[1]
        .node
        .send_endpoint_data(node0_identity, b"pong".to_vec())
        .await
        .expect("reply data should send");

    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    let event = tokio::time::timeout(Duration::from_secs(1), node0_endpoint.event_rx.recv())
        .await
        .expect("endpoint data event should not time out")
        .expect("endpoint data event should arrive");
    match event {
        NodeEndpointEvent::Data {
            source_peer,
            payload,
            ..
        } => {
            assert_eq!(*source_peer.node_addr(), node1_addr);
            assert_eq!(source_peer.npub(), nodes[1].node.npub());
            assert_eq!(payload, b"pong");
        }
        NodeEndpointEvent::DataBatch { .. } => panic!("expected single endpoint data event"),
    }

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_endpoint_data_routes_through_non_endpoint_transit_node() {
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

    nodes[0]
        .node
        .send_endpoint_data(bob_identity, b"alice-to-bob".to_vec())
        .await
        .expect("alice endpoint data should send");
    drain_to_quiescence(&mut nodes).await;

    let event = tokio::time::timeout(Duration::from_secs(1), bob_endpoint.event_rx.recv())
        .await
        .expect("bob endpoint data should not time out")
        .expect("bob endpoint data should arrive");
    match event {
        NodeEndpointEvent::Data {
            source_peer,
            payload,
            ..
        } => {
            assert_eq!(*source_peer.node_addr(), alice_addr);
            assert_eq!(source_peer.npub(), nodes[0].node.npub());
            assert_eq!(payload, b"alice-to-bob");
        }
        NodeEndpointEvent::DataBatch { .. } => panic!("expected single endpoint data event"),
    }

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

    nodes[2]
        .node
        .send_endpoint_data(alice_identity, b"bob-to-alice".to_vec())
        .await
        .expect("bob endpoint data should send");
    drain_to_quiescence(&mut nodes).await;

    let event = tokio::time::timeout(Duration::from_secs(1), alice_endpoint.event_rx.recv())
        .await
        .expect("alice endpoint data should not time out")
        .expect("alice endpoint data should arrive");
    match event {
        NodeEndpointEvent::Data {
            source_peer,
            payload,
            ..
        } => {
            assert_eq!(*source_peer.node_addr(), bob_addr);
            assert_eq!(source_peer.npub(), nodes[2].node.npub());
            assert_eq!(payload, b"bob-to-alice");
        }
        NodeEndpointEvent::DataBatch { .. } => panic!("expected single endpoint data event"),
    }
    assert!(
        transit_endpoint.event_rx.try_recv().is_err(),
        "transit node must stay outside the app endpoint flow"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_endpoint_data_reply_learned_first_contact_routes_via_intermediary() {
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

    nodes[0]
        .node
        .send_endpoint_data(bob_identity, b"first-contact".to_vec())
        .await
        .expect("alice endpoint data should queue and trigger discovery");

    for _ in 0..120 {
        drain_to_quiescence(&mut nodes).await;
        if let Ok(event) = bob_endpoint.event_rx.try_recv() {
            match event {
                NodeEndpointEvent::Data {
                    source_peer,
                    payload,
                    ..
                } => {
                    assert_eq!(*source_peer.node_addr(), alice_addr);
                    assert_eq!(source_peer.npub(), nodes[0].node.npub());
                    assert_eq!(payload, b"first-contact");
                }
                NodeEndpointEvent::DataBatch { .. } => {
                    panic!("expected single endpoint data event")
                }
            }
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
}

// ============================================================================
// Integration tests: 3-node forwarded session
// ============================================================================
