use super::*;

#[test]
fn test_session_3node_forwarded_handshake() {
    run_large_stack_async_test("fips-forwarded-handshake", || async {
        session_3node_forwarded_handshake().await;
    });
}

async fn session_3node_forwarded_handshake() {
    // A—B—C: Node A initiates session with Node C through transit node B
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let node2_pubkey = nodes[2].node.identity().pubkey_full();

    // Node 0 initiates session with Node 2
    nodes[0]
        .node
        .initiate_session(node2_addr, node2_pubkey)
        .await
        .expect("initiate_session failed");

    // Process: SessionSetup: 0->1 (forwarded by transit B)
    assert!(wait_process_packets_for_node(&mut nodes, 1).await > 0);

    // Process: SessionSetup: 1->2 (arrives at destination C)
    assert!(wait_process_packets_for_node(&mut nodes, 2).await > 0);

    // Node 2 should have an AwaitingMsg3 session (XK: identity not yet known)
    assert!(
        nodes[2].node.get_session(&node0_addr).is_some(),
        "Node 2 should have a session entry for Node 0"
    );
    assert!(
        nodes[2]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .is_awaiting_msg3()
    );

    // Process: SessionAck: 2->1 (forwarded by transit B)
    assert!(wait_process_packets_for_node(&mut nodes, 1).await > 0);

    // Process: SessionAck: 1->0 (arrives at initiator A, sends SessionMsg3)
    assert!(wait_process_packets_for_node(&mut nodes, 0).await > 0);

    // Node 0 should now be Established (transitions after sending msg3)
    assert!(
        nodes[0]
            .node
            .get_session(&node2_addr)
            .unwrap()
            .is_established()
    );

    // Process: SessionMsg3: 0->1 (forwarded by transit B)
    assert!(wait_process_packets_for_node(&mut nodes, 1).await > 0);

    // Process: SessionMsg3: 1->2 (arrives at responder C)
    assert!(wait_process_packets_for_node(&mut nodes, 2).await > 0);

    // Node 2 should now be Established (transitions after processing msg3)
    assert!(
        nodes[2]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .is_established()
    );

    // Transit node B should NOT have a session
    assert_eq!(
        nodes[1].node.session_count(),
        0,
        "Transit node should have no sessions"
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Edge cases
// ============================================================================

#[tokio::test]
async fn test_session_initiate_idempotent() {
    // Calling initiate_session twice should be idempotent
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    // First call
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    assert_eq!(nodes[0].node.session_count(), 1);

    // Second call should be a no-op
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    assert_eq!(nodes[0].node.session_count(), 1);

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_session_ack_for_unknown_session() {
    // Receiving a SessionAck when we have no Initiating session should be dropped
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    // Fabricate a SessionAck and deliver directly
    let src_coords = nodes[1].node.tree_state().my_coords().clone();
    let dest_coords = nodes[0].node.tree_state().my_coords().clone();
    let ack = SessionAck::new(src_coords, dest_coords).with_handshake(vec![0u8; 57]);
    let datagram = SessionDatagram::new(node1_addr, node0_addr, ack.encode());

    // Send through link layer
    let encoded = datagram.encode();
    nodes[1]
        .node
        .send_dataplane_fmp_link_plaintext(&node0_addr, &encoded, false)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Node 0 should have no sessions (ack was for unknown session)
    assert_eq!(nodes[0].node.session_count(), 0);

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Large-scale test: 100-node session establishment + bidirectional data
// ============================================================================
