use super::*;
use crate::noise::HandshakeState;
use crate::protocol::SessionMsg3;

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

    wait_for_session_established(
        &mut nodes,
        0,
        &node2_addr,
        Duration::from_secs(10),
        "forwarded handshake initiator",
    )
    .await;
    wait_for_session_established(
        &mut nodes,
        2,
        &node0_addr,
        Duration::from_secs(10),
        "forwarded handshake responder",
    )
    .await;

    // Transit node B should NOT have a session
    assert_eq!(
        nodes[1].node.session_count(),
        0,
        "Transit node should have no sessions"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_routed_session_establishes_through_authenticated_previous_hop_without_reverse_route()
{
    // B--C is an established FMP edge. A's routed SessionSetup arrives at C
    // through B, while C deliberately has no route to A yet.
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);
    nodes[1].node.config.node.routing.mode = RoutingMode::ReplyLearned;

    let initiator = Node::new(Config::new()).expect("initiator node");
    let initiator_addr = *initiator.node_addr();
    let responder_addr = *nodes[1].node.node_addr();

    let mut handshake = HandshakeState::new_xk_initiator(
        initiator.identity().keypair(),
        nodes[1].node.identity().pubkey_full(),
    );
    handshake.set_local_epoch([0x01; 8]);
    let msg1 = handshake
        .write_xk_message_1()
        .expect("initiator should generate XK msg1");
    let setup = SessionSetup::new(
        initiator.tree_state().my_coords().clone(),
        nodes[1].node.tree_state().my_coords().clone(),
    )
    .with_handshake(msg1);
    let datagram = SessionDatagram::new(initiator_addr, responder_addr, setup.encode());
    let encoded = datagram.encode();

    assert!(
        nodes[1].node.find_next_hop(&initiator_addr).is_none(),
        "test requires the responder to have no ordinary route to the initiator"
    );

    nodes[0]
        .node
        .send_dataplane_fmp_link_plaintext(&responder_addr, &encoded, false)
        .await
        .expect("transit should send routed SessionSetup to responder");
    assert!(
        wait_process_packets_for_node(&mut nodes, 1).await > 0,
        "routed SessionSetup should reach the responder over FMP"
    );

    assert!(
        nodes[1]
            .node
            .get_session(&initiator_addr)
            .is_some_and(|session| session.is_awaiting_msg3()),
        "responder should return SessionAck through the authenticated previous hop"
    );
    assert!(
        wait_process_packets_for_node(&mut nodes, 0).await > 0,
        "SessionAck should reach the authenticated previous hop"
    );

    let ack_payload = nodes[1]
        .node
        .get_session(&initiator_addr)
        .and_then(|session| session.handshake_payload())
        .expect("responder should retain SessionAck for resend");
    let ack = SessionAck::decode(&ack_payload[FSP_COMMON_PREFIX_SIZE..])
        .expect("stored SessionAck should decode");
    handshake
        .read_xk_message_2(&ack.handshake_payload)
        .expect("initiator should process XK msg2");
    let msg3 = handshake
        .write_xk_message_3()
        .expect("initiator should generate XK msg3");
    let datagram = SessionDatagram::new(
        initiator_addr,
        responder_addr,
        SessionMsg3::new(msg3).encode(),
    );
    nodes[0]
        .node
        .send_dataplane_fmp_link_plaintext(&responder_addr, &datagram.encode(), false)
        .await
        .expect("transit should send routed SessionMsg3 to responder");
    assert!(
        wait_process_packets_for_node(&mut nodes, 1).await > 0,
        "routed SessionMsg3 should reach the responder over FMP"
    );

    let session = nodes[1]
        .node
        .get_session(&initiator_addr)
        .expect("responder should retain the authenticated session");
    assert!(
        session.is_established(),
        "responder session should establish"
    );
    assert_eq!(
        session
            .remote_identity()
            .map(|identity| *identity.node_addr()),
        Some(initiator_addr),
        "Noise msg3 must authenticate the claimed source NodeAddr"
    );
    let transit_addr = *nodes[0].node.node_addr();
    assert_eq!(
        nodes[1]
            .node
            .find_next_hop(&initiator_addr)
            .map(|peer| *peer.node_addr()),
        Some(transit_addr),
        "authenticated msg3 should install the reverse route"
    );
    assert_eq!(
        nodes[1].node.dataplane.fsp_owner_next_hop(&initiator_addr),
        Some(transit_addr),
        "responder dataplane owner should wrap replies through the authenticated previous hop"
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
