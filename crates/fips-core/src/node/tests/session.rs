//! End-to-end session establishment tests.

use super::*;
use crate::config::RoutingMode;
use crate::node::session::EndToEndState;
use crate::node::session_wire::FSP_COMMON_PREFIX_SIZE;
use crate::node::tests::spanning_tree::{
    TestNode, cleanup_nodes, generate_random_edges, lock_large_network_test,
    process_available_packets, run_tree_test, run_tree_test_with_mtus, verify_tree_convergence,
};
use crate::protocol::{SessionAck, SessionDatagram, SessionSetup};
use crate::tree::{ParentDeclaration, TreeCoordinate};

/// Populate all nodes' coordinate caches with each other's coords.
///
/// This enables routing between non-adjacent nodes (bloom filter + tree
/// routing both require cached destination coordinates).
fn populate_all_coord_caches(nodes: &mut [TestNode]) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let all_coords: Vec<(NodeAddr, crate::tree::TreeCoordinate)> = nodes
        .iter()
        .map(|tn| {
            (
                *tn.node.node_addr(),
                tn.node.tree_state().my_coords().clone(),
            )
        })
        .collect();

    for tn in nodes.iter_mut() {
        for (addr, coords) in &all_coords {
            if addr != tn.node.node_addr() {
                tn.node
                    .coord_cache_mut()
                    .insert(*addr, coords.clone(), now_ms);
            }
        }
    }
}

// ============================================================================
// Unit tests: SessionEntry data structure
// ============================================================================

#[test]
fn test_session_entry_new_initiating() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

    let entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    assert!(entry.state().is_initiating());
    assert!(!entry.state().is_established());
    assert!(!entry.state().is_awaiting_msg3());
    assert_eq!(entry.created_at(), 1000);
    assert_eq!(entry.last_activity(), 1000);
    assert_eq!(entry.last_inbound_frame_ms(), 1000);
}

#[test]
fn test_session_entry_rekey_jitter_in_range() {
    use crate::node::REKEY_JITTER_SECS;
    use crate::noise::HandshakeState;

    for _ in 0..100 {
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let handshake =
            HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

        let entry = crate::node::session::SessionEntry::new(
            *identity_b.node_addr(),
            identity_b.pubkey_full(),
            EndToEndState::Initiating(handshake),
            1000,
            true,
        );

        let jitter = entry.rekey_jitter_secs();
        assert!(
            (-REKEY_JITTER_SECS..=REKEY_JITTER_SECS).contains(&jitter),
            "jitter {} outside [-{}, +{}]",
            jitter,
            REKEY_JITTER_SECS,
            REKEY_JITTER_SECS
        );
    }
}

#[test]
fn test_session_entry_rekey_jitter_mean_near_zero() {
    use crate::noise::HandshakeState;

    let mut sum = 0i64;
    let n = 200i64;

    for _ in 0..n {
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let handshake =
            HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

        let entry = crate::node::session::SessionEntry::new(
            *identity_b.node_addr(),
            identity_b.pubkey_full(),
            EndToEndState::Initiating(handshake),
            1000,
            true,
        );

        sum += entry.rekey_jitter_secs();
    }

    let mean = sum / n;
    assert!(
        mean.abs() < 5,
        "empirical mean {} not within 5 of 0 over {} samples",
        mean,
        n
    );
}

#[test]
fn test_session_entry_touch() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    entry.touch(2000);
    assert_eq!(entry.last_activity(), 2000);
    assert_eq!(entry.created_at(), 1000);
}

#[test]
fn test_session_entry_decrypt_failure_counter() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    assert_eq!(entry.consecutive_decrypt_failures(), 0);

    for expected in 1..=5 {
        let count = entry.record_decrypt_failure();
        assert_eq!(count, expected);
        assert_eq!(entry.consecutive_decrypt_failures(), expected);
    }

    entry.reset_decrypt_failures();
    assert_eq!(entry.consecutive_decrypt_failures(), 0);

    // Idempotent reset on already-zero counter.
    entry.reset_decrypt_failures();
    assert_eq!(entry.consecutive_decrypt_failures(), 0);

    let count = entry.record_decrypt_failure();
    assert_eq!(count, 1);
}

#[test]
fn test_session_table_operations() {
    use crate::noise::HandshakeState;

    let mut node = make_node();
    let identity_b = Identity::generate();

    let handshake =
        HandshakeState::new_initiator(node.identity().keypair(), identity_b.pubkey_full());

    let dest_addr = *identity_b.node_addr();
    let entry = crate::node::session::SessionEntry::new(
        dest_addr,
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    node.sessions.insert(dest_addr, entry);
    assert_eq!(node.session_count(), 1);
    assert!(node.get_session(&dest_addr).is_some());
    assert!(node.get_session(&make_node_addr(0xFF)).is_none());

    let removed = node.remove_session(&dest_addr);
    assert!(removed.is_some());
    assert_eq!(node.session_count(), 0);
}

// ============================================================================
// Integration tests: 2-node direct session establishment
// ============================================================================

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
            source_node_addr,
            source_npub,
            payload,
            ..
        } => {
            assert_eq!(source_node_addr, node0_addr);
            assert_eq!(source_npub, Some(nodes[0].node.npub()));
            assert_eq!(payload, b"ping");
        }
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
            source_node_addr,
            source_npub,
            payload,
            ..
        } => {
            assert_eq!(source_node_addr, node1_addr);
            assert_eq!(source_npub, Some(nodes[1].node.npub()));
            assert_eq!(payload, b"pong");
        }
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
            source_node_addr,
            source_npub,
            payload,
            ..
        } => {
            assert_eq!(source_node_addr, alice_addr);
            assert_eq!(source_npub, Some(nodes[0].node.npub()));
            assert_eq!(payload, b"alice-to-bob");
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
            source_node_addr,
            source_npub,
            payload,
            ..
        } => {
            assert_eq!(source_node_addr, bob_addr);
            assert_eq!(source_npub, Some(nodes[2].node.npub()));
            assert_eq!(payload, b"bob-to-alice");
        }
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
                    source_node_addr,
                    source_npub,
                    payload,
                    ..
                } => {
                    assert_eq!(source_node_addr, alice_addr);
                    assert_eq!(source_npub, Some(nodes[0].node.npub()));
                    assert_eq!(payload, b"first-contact");
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

#[tokio::test]
async fn test_session_3node_forwarded_handshake() {
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

    // Process: SessionSetup: 0→1 (forwarded by transit B)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Process: SessionSetup: 1→2 (arrives at destination C)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

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
            .state()
            .is_awaiting_msg3()
    );

    // Process: SessionAck: 2→1 (forwarded by transit B)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Process: SessionAck: 1→0 (arrives at initiator A, sends SessionMsg3)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Node 0 should now be Established (transitions after sending msg3)
    assert!(
        nodes[0]
            .node
            .get_session(&node2_addr)
            .unwrap()
            .state()
            .is_established()
    );

    // Process: SessionMsg3: 0→1 (forwarded by transit B)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Process: SessionMsg3: 1→2 (arrives at responder C)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Node 2 should now be Established (transitions after processing msg3)
    assert!(
        nodes[2]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .state()
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

#[tokio::test]
async fn test_session_3node_forwarded_data() {
    // A—B—C: Establish session, send data end-to-end
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let node2_pubkey = nodes[2].node.identity().pubkey_full();

    // Establish session (needs more hops)
    nodes[0]
        .node
        .initiate_session(node2_addr, node2_pubkey)
        .await
        .unwrap();

    // Drain packets until handshake completes (multi-hop needs several rounds)
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }

    assert!(
        nodes[0]
            .node
            .get_session(&node2_addr)
            .map(|s| s.state().is_established())
            .unwrap_or(false),
        "Session should be established after handshake rounds"
    );

    // Send data
    let test_data = b"End-to-end through transit node B";
    nodes[0]
        .node
        .send_session_data(&node2_addr, 0, 0, test_data)
        .await
        .expect("send_session_data failed");

    // Drain data packet through transit node
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }

    // Node 2 should be Established (transitioned during XK handshake msg3)
    assert!(
        nodes[2]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .state()
            .is_established()
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
async fn test_session_send_data_no_session_fails() {
    let mut node = make_node();
    let fake_addr = make_node_addr(0xAA);

    let result = node.send_session_data(&fake_addr, 0, 0, b"test").await;
    assert!(result.is_err(), "Should fail with no session");
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
        .send_encrypted_link_message(&node0_addr, &encoded)
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

/// Drain packets until quiescent (2 consecutive idle rounds).
async fn drain_to_quiescence(nodes: &mut [TestNode]) {
    let mut idle_rounds = 0;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let count = process_available_packets(nodes).await;
        if count == 0 {
            idle_rounds += 1;
            if idle_rounds >= 2 {
                break;
            }
        } else {
            idle_rounds = 0;
        }
    }
}

async fn process_available_packets_for_node(node: &mut TestNode) -> usize {
    use crate::node::wire::{
        COMMON_PREFIX_SIZE, CommonPrefix, FMP_VERSION, PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2,
    };

    let mut count = 0;
    while let Ok(packet) = node.packet_rx.try_recv() {
        if packet.data.len() < COMMON_PREFIX_SIZE {
            continue;
        }
        if let Some(prefix) = CommonPrefix::parse(&packet.data) {
            if prefix.version != FMP_VERSION {
                continue;
            }
            match prefix.phase {
                PHASE_MSG1 => node.node.handle_msg1(packet).await,
                PHASE_MSG2 => node.node.handle_msg2(packet).await,
                PHASE_ESTABLISHED => node.node.handle_encrypted_frame(packet).await,
                _ => {}
            }
            count += 1;
        }
    }
    count
}

async fn wait_process_packets_for_node(nodes: &mut [TestNode], index: usize) -> usize {
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let count = process_available_packets_for_node(&mut nodes[index]).await;
        if count > 0 {
            return count;
        }
    }
    0
}

fn drop_queued_packets_for_node(node: &mut TestNode) -> usize {
    let mut dropped = 0;
    while node.packet_rx.try_recv().is_ok() {
        dropped += 1;
    }
    dropped
}

#[tokio::test]
async fn test_established_initiator_resends_final_msg3_until_responder_establishes() {
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
            .state()
            .is_awaiting_msg3()
    );

    let count = wait_process_packets_for_node(&mut nodes, 0).await;
    assert!(count > 0, "SessionAck should reach initiator");
    let initiator_entry = nodes[0].node.get_session(&node1_addr).unwrap();
    assert!(initiator_entry.state().is_established());
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
            .state()
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
            .state()
            .is_established(),
        "responder should establish from the resent SessionMsg3"
    );

    nodes[1]
        .node
        .send_session_data(&node0_addr, 0, 0, b"responder-proof")
        .await
        .expect("responder should send data after establishment");
    let count = wait_process_packets_for_node(&mut nodes, 0).await;
    assert!(count > 0, "initiator should receive responder proof data");
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

#[tokio::test]
async fn test_rekey_initiator_resends_final_msg3_until_responder_has_pending_session() {
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
    drain_to_quiescence(&mut nodes).await;

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

    assert!(
        nodes[0].node.initiate_session_rekey(&node1_addr).await,
        "rekey should start"
    );

    let count = wait_process_packets_for_node(&mut nodes, 1).await;
    assert!(count > 0, "rekey msg1 should reach responder");

    let count = wait_process_packets_for_node(&mut nodes, 0).await;
    assert!(count > 0, "rekey msg2 should reach initiator");
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

    nodes[1]
        .node
        .send_session_data(&node0_addr, 0, 0, b"old-session-proof")
        .await
        .expect("old session should remain usable while rekey msg3 is pending");
    let count = wait_process_packets_for_node(&mut nodes, 0).await;
    assert!(count > 0, "old-session proof should reach initiator");
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

    let count = wait_process_packets_for_node(&mut nodes, 1).await;
    assert!(
        count > 0,
        "resender should deliver a replacement rekey msg3"
    );
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

#[tokio::test]
async fn test_session_100_nodes() {
    let _guard = lock_large_network_test().await;

    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};
    use std::sync::mpsc;
    use std::time::Instant;

    // Same random topology as other 100-node tests
    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;

    let start = Instant::now();

    let edges = generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let setup_time = start.elapsed();

    // Collect identities: (node_addr, pubkey) for all nodes
    let all_info: Vec<(NodeAddr, secp256k1::PublicKey)> = nodes
        .iter()
        .map(|tn| (*tn.node.node_addr(), tn.node.identity().pubkey_full()))
        .collect();

    // Each node picks one random target for its outbound session.
    // Use deterministic RNG so failures are reproducible.
    let mut rng = StdRng::seed_from_u64(SEED + 1);
    let mut session_pairs: Vec<(usize, usize)> = Vec::with_capacity(NUM_NODES);
    for src in 0..NUM_NODES {
        let mut dst = rng.random_range(0..NUM_NODES);
        while dst == src {
            dst = rng.random_range(0..NUM_NODES);
        }
        session_pairs.push((src, dst));
    }

    // === Phase 1: Establish all sessions ===

    let session_start = Instant::now();

    for &(src, dst) in &session_pairs {
        let (dest_addr, dest_pubkey) = all_info[dst];

        nodes[src]
            .node
            .initiate_session(dest_addr, dest_pubkey)
            .await
            .expect("initiate_session failed");

        drain_to_quiescence(&mut nodes).await;
    }

    drain_to_quiescence(&mut nodes).await;
    let session_time = session_start.elapsed();

    // Verify all initiator sessions reached Established before data phase
    let mut handshake_failures: Vec<(usize, usize)> = Vec::new();
    for &(src, dst) in &session_pairs {
        let dest_addr = all_info[dst].0;
        let ok = nodes[src]
            .node
            .get_session(&dest_addr)
            .map(|e| e.state().is_established())
            .unwrap_or(false);
        if !ok {
            handshake_failures.push((src, dst));
        }
    }
    assert!(
        handshake_failures.is_empty(),
        "Handshake failed for {} pairs (first: {:?})",
        handshake_failures.len(),
        handshake_failures.first()
    );

    // === Phase 2: Inject TUN receivers and snapshot link stats ===

    // Install a tun_tx on every node so delivered datagrams can be counted.
    let mut tun_receivers: Vec<mpsc::Receiver<Vec<u8>>> = Vec::with_capacity(NUM_NODES);
    for tn in nodes.iter_mut() {
        let (tx, rx) = mpsc::channel();
        tn.node.tun_tx = Some(tx);
        tun_receivers.push(rx);
    }

    // Snapshot per-peer link stats before data phase
    let link_pkts_sent_before: Vec<Vec<(NodeAddr, u64)>> = nodes
        .iter()
        .map(|tn| {
            tn.node
                .peers()
                .map(|p| (*p.node_addr(), p.link_stats().packets_sent))
                .collect()
        })
        .collect();

    // === Phase 3: Bidirectional data transfer ===
    //
    // For each session pair:
    //   1. Initiator sends one datagram to responder
    //   2. Responder sends one datagram back to initiator
    //
    // Batched per pair with draining between each.

    let data_start = Instant::now();
    let mut send_forward_ok = 0usize;
    let mut send_forward_err = 0usize;
    let mut send_reverse_ok = 0usize;
    let mut send_reverse_err = 0usize;

    for (pair_idx, &(src, dst)) in session_pairs.iter().enumerate() {
        let dest_addr = all_info[dst].0;
        let src_addr = all_info[src].0;

        // Build IPv6 packets with pair index as payload
        let src_fips = crate::FipsAddress::from_node_addr(&src_addr);
        let dst_fips = crate::FipsAddress::from_node_addr(&dest_addr);

        // Forward: initiator → responder
        let fwd_payload = format!("fwd-{}", pair_idx).into_bytes();
        let fwd_ipv6 = build_ipv6_packet(&src_fips, &dst_fips, &fwd_payload);
        match nodes[src]
            .node
            .send_ipv6_packet(&dest_addr, &fwd_ipv6)
            .await
        {
            Ok(()) => send_forward_ok += 1,
            Err(_) => send_forward_err += 1,
        }

        drain_to_quiescence(&mut nodes).await;

        // Reverse: responder → initiator
        // (Responder should already be Established after XK msg3)
        let rev_payload = format!("rev-{}", pair_idx).into_bytes();
        let rev_ipv6 = build_ipv6_packet(&dst_fips, &src_fips, &rev_payload);
        match nodes[dst].node.send_ipv6_packet(&src_addr, &rev_ipv6).await {
            Ok(()) => send_reverse_ok += 1,
            Err(_) => send_reverse_err += 1,
        }

        drain_to_quiescence(&mut nodes).await;
    }

    let data_time = data_start.elapsed();

    // === Phase 4: Collect delivered datagrams from TUN receivers ===

    let mut delivered_per_node: Vec<Vec<Vec<u8>>> = Vec::with_capacity(NUM_NODES);
    for rx in tun_receivers.iter_mut() {
        let mut packets = Vec::new();
        while let Ok(pkt) = rx.try_recv() {
            packets.push(pkt);
        }
        delivered_per_node.push(packets);
    }

    let total_delivered: usize = delivered_per_node.iter().map(|v| v.len()).sum();

    // Verify each pair's forward and reverse datagrams arrived
    let mut fwd_delivered = 0usize;
    let mut rev_delivered = 0usize;
    let mut fwd_missing: Vec<(usize, usize)> = Vec::new();
    let mut rev_missing: Vec<(usize, usize)> = Vec::new();

    for (pair_idx, &(src, dst)) in session_pairs.iter().enumerate() {
        let fwd_payload = format!("fwd-{}", pair_idx).into_bytes();
        let rev_payload = format!("rev-{}", pair_idx).into_bytes();

        // After decompression, TUN receives full IPv6 packets.
        // Check that delivered packet's upper-layer payload matches.
        let fwd_found = delivered_per_node[dst]
            .iter()
            .any(|pkt| pkt.len() >= 40 && pkt[40..] == fwd_payload);
        if fwd_found {
            fwd_delivered += 1;
        } else if fwd_missing.len() < 20 {
            fwd_missing.push((src, dst));
        }

        let rev_found = delivered_per_node[src]
            .iter()
            .any(|pkt| pkt.len() >= 40 && pkt[40..] == rev_payload);
        if rev_found {
            rev_delivered += 1;
        } else if rev_missing.len() < 20 {
            rev_missing.push((src, dst));
        }
    }

    // === Phase 5: Final session state ===

    let mut total_established = 0usize;
    let mut total_responding = 0usize;
    let mut total_initiating = 0usize;
    let mut fully_established_nodes = 0usize;

    for tn in &nodes {
        let mut all_est = true;
        for (_, entry) in tn.node.sessions.iter() {
            if entry.state().is_established() {
                total_established += 1;
            } else if entry.state().is_awaiting_msg3() {
                total_responding += 1;
                all_est = false;
            } else {
                total_initiating += 1;
                all_est = false;
            }
        }
        if tn.node.session_count() > 0 && all_est {
            fully_established_nodes += 1;
        }
    }

    let session_counts: Vec<usize> = nodes.iter().map(|tn| tn.node.session_count()).collect();
    let total_sessions: usize = session_counts.iter().sum();
    let min_sessions = *session_counts.iter().min().unwrap();
    let max_sessions = *session_counts.iter().max().unwrap();

    // === Phase 6: Link and routing statistics ===

    // Link stats delta: packets sent during data phase
    let mut data_link_pkts_sent: u64 = 0;
    let mut total_link_pkts_sent: u64 = 0;
    let mut total_link_pkts_recv: u64 = 0;
    let mut total_link_bytes_sent: u64 = 0;
    let mut total_link_bytes_recv: u64 = 0;

    for (i, tn) in nodes.iter().enumerate() {
        for peer in tn.node.peers() {
            let stats = peer.link_stats();
            // Delta for this peer since before data phase
            let before = link_pkts_sent_before[i]
                .iter()
                .find(|(addr, _)| addr == peer.node_addr())
                .map(|(_, pkts)| *pkts)
                .unwrap_or(0);
            data_link_pkts_sent += stats.packets_sent.saturating_sub(before);

            // Totals (cumulative since node creation)
            total_link_pkts_sent += stats.packets_sent;
            total_link_pkts_recv += stats.packets_recv;
            total_link_bytes_sent += stats.bytes_sent;
            total_link_bytes_recv += stats.bytes_recv;
        }
    }

    // Estimate average hop count from link packet overhead.
    // Each data datagram traverses N link hops, each producing 1 link send.
    // We sent 200 datagrams total (100 forward + 100 reverse).
    let total_data_datagrams = (send_forward_ok + send_reverse_ok) as u64;
    let avg_hops = if total_data_datagrams > 0 {
        data_link_pkts_sent as f64 / total_data_datagrams as f64
    } else {
        0.0
    };

    // Coord cache stats
    let coord_cache_sizes: Vec<usize> =
        nodes.iter().map(|tn| tn.node.coord_cache().len()).collect();
    let total_coord_entries: usize = coord_cache_sizes.iter().sum();
    let min_coord = *coord_cache_sizes.iter().min().unwrap();
    let max_coord = *coord_cache_sizes.iter().max().unwrap();

    // === Report ===

    eprintln!("\n  === Session 100-Node Test ===");
    eprintln!(
        "  Topology: {} nodes, {} edges (seed {})",
        NUM_NODES,
        edges.len(),
        SEED
    );
    eprintln!(
        "  Session pairs: {} (1 outbound per node, random target)",
        session_pairs.len()
    );

    eprintln!("\n  --- Handshake ---");
    eprintln!(
        "  Initiator established: {}/{}",
        session_pairs.len(),
        session_pairs.len()
    );

    eprintln!("\n  --- Data Transfer ---");
    eprintln!(
        "  Forward (initiator->responder): {} sent, {} errors",
        send_forward_ok, send_forward_err
    );
    eprintln!(
        "  Reverse (responder->initiator): {} sent, {} errors",
        send_reverse_ok, send_reverse_err
    );
    eprintln!(
        "  TUN delivery: {} total ({} expected)",
        total_delivered,
        send_forward_ok + send_reverse_ok
    );
    eprintln!(
        "  Forward delivered: {}/{} | Reverse delivered: {}/{}",
        fwd_delivered, send_forward_ok, rev_delivered, send_reverse_ok
    );

    eprintln!("\n  --- Final Session State ---");
    eprintln!(
        "  Entries: {} total ({} established, {} responding, {} initiating)",
        total_sessions, total_established, total_responding, total_initiating
    );
    eprintln!(
        "  Per node: min={} max={} avg={:.1}",
        min_sessions,
        max_sessions,
        total_sessions as f64 / NUM_NODES as f64
    );
    eprintln!(
        "  All-established nodes: {}/{}",
        fully_established_nodes, NUM_NODES
    );

    eprintln!("\n  --- Routing ---");
    eprintln!(
        "  Data-phase link hops: {} ({:.1} avg hops/datagram over {} datagrams)",
        data_link_pkts_sent, avg_hops, total_data_datagrams
    );
    eprintln!(
        "  Lifetime link totals: {} pkts sent, {} pkts recv, {:.1} KB sent, {:.1} KB recv",
        total_link_pkts_sent,
        total_link_pkts_recv,
        total_link_bytes_sent as f64 / 1024.0,
        total_link_bytes_recv as f64 / 1024.0
    );
    eprintln!(
        "  Coord cache: total={} min={} max={} avg={:.1}",
        total_coord_entries,
        min_coord,
        max_coord,
        total_coord_entries as f64 / NUM_NODES as f64
    );

    eprintln!("\n  --- Timing ---");
    eprintln!(
        "  Setup: {:.1}s | Handshake: {:.1}s | Data: {:.1}s | Total: {:.1}s",
        setup_time.as_secs_f64(),
        session_time.as_secs_f64(),
        data_time.as_secs_f64(),
        start.elapsed().as_secs_f64()
    );

    if !fwd_missing.is_empty() {
        eprintln!(
            "\n  First {} undelivered forward datagrams:",
            fwd_missing.len()
        );
        for &(src, dst) in &fwd_missing {
            eprintln!("    node {} -> node {}", src, dst);
        }
    }
    if !rev_missing.is_empty() {
        eprintln!(
            "\n  First {} undelivered reverse datagrams:",
            rev_missing.len()
        );
        for &(src, dst) in &rev_missing {
            eprintln!("    node {} <- node {}", src, dst);
        }
    }

    // === Assertions ===

    assert_eq!(send_forward_err, 0, "All forward sends should succeed");
    assert_eq!(
        send_reverse_err, 0,
        "All reverse sends should succeed (responder Established after XK msg3)"
    );
    assert_eq!(
        fwd_delivered, send_forward_ok,
        "All forward datagrams should be delivered to responder TUN"
    );
    assert_eq!(
        rev_delivered, send_reverse_ok,
        "All reverse datagrams should be delivered to initiator TUN"
    );
    assert_eq!(
        total_established, total_sessions,
        "All {} session entries should be Established, \
         but {} responding, {} initiating",
        total_sessions, total_responding, total_initiating
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Data plane integration tests: TUN → session → link → TUN
// ============================================================================

/// Build a minimal valid IPv6 packet with given source and destination addresses.
fn build_ipv6_packet(
    src: &crate::FipsAddress,
    dst: &crate::FipsAddress,
    payload: &[u8],
) -> Vec<u8> {
    let payload_len = payload.len() as u16;
    let mut packet = vec![0u8; 40 + payload.len()];
    // Version (6) + traffic class high nibble
    packet[0] = 0x60;
    // Payload length (u16 BE)
    packet[4] = (payload_len >> 8) as u8;
    packet[5] = (payload_len & 0xff) as u8;
    // Next header: 59 = No Next Header
    packet[6] = 59;
    // Hop limit
    packet[7] = 64;
    // Source address (bytes 8-23)
    packet[8..24].copy_from_slice(src.as_bytes());
    // Destination address (bytes 24-39)
    packet[24..40].copy_from_slice(dst.as_bytes());
    // Payload
    packet[40..].copy_from_slice(payload);
    packet
}

fn make_reply_learned_node_with_tree_peer() -> Node {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    let mut node = Node::new(config).unwrap();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let (conn, peer_identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_addr = *peer_identity.node_addr();
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, peer_identity, 2000)
        .unwrap();

    let our_addr = *node.node_addr();
    let peer_coords = TreeCoordinate::from_addrs(vec![peer_addr, our_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(peer_addr, our_addr, 1, 2000),
        peer_coords,
    );
    assert!(
        node.is_tree_peer(&peer_addr),
        "fixture peer must be a tree peer"
    );
    node
}

fn insert_initiating_session(node: &mut Node, dest: &Identity) {
    insert_initiating_session_for(node, *dest.node_addr(), dest.pubkey_full());
}

fn insert_initiating_session_for(
    node: &mut Node,
    dest_addr: NodeAddr,
    dest_pubkey: secp256k1::PublicKey,
) {
    let handshake =
        crate::noise::HandshakeState::new_initiator(node.identity().keypair(), dest_pubkey);
    let entry = crate::node::session::SessionEntry::new(
        dest_addr,
        dest_pubkey,
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );
    node.sessions.insert(dest_addr, entry);
}

fn add_direct_peer_for_identity(node: &mut Node, identity: &Identity) {
    let peer_identity = crate::PeerIdentity::from_pubkey_full(identity.pubkey_full());
    node.peers.insert(
        *identity.node_addr(),
        crate::peer::ActivePeer::new(peer_identity, LinkId::new(99), 2000),
    );
}

fn has_outbound_handshake_to(node: &Node, dest_addr: &NodeAddr) -> bool {
    node.connections.values().any(|conn| {
        conn.is_outbound()
            && conn
                .expected_identity()
                .map(|identity| identity.node_addr() == dest_addr)
                .unwrap_or(false)
    })
}

#[test]
fn test_identity_cache_populated_on_promote() {
    use crate::peer::PromotionResult;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    let (conn, peer_identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);

    node.add_connection(conn).unwrap();

    // Promote
    let result = node
        .promote_connection(link_id, peer_identity, 2000)
        .unwrap();
    assert!(matches!(result, PromotionResult::Promoted(_)));

    // Identity cache should contain the peer
    let peer_addr = *peer_identity.node_addr();
    let mut prefix = [0u8; 15];
    prefix.copy_from_slice(&peer_addr.as_bytes()[0..15]);
    let cached = node.lookup_by_fips_prefix(&prefix);
    assert!(
        cached.is_some(),
        "Identity cache should contain promoted peer"
    );
    let (cached_addr, cached_pk) = cached.unwrap();
    assert_eq!(cached_addr, peer_addr);
    assert_eq!(cached_pk, peer_identity.pubkey_full());
}

#[tokio::test]
async fn test_tun_outbound_established_session() {
    // Two directly connected nodes, session established.
    // Inject IPv6 packet via handle_tun_outbound on Node 0,
    // verify plaintext arrives at Node 1's tun_tx.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node1_addr);

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

    // Install TUN receiver on Node 1
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[1].node.tun_tx = Some(tun_tx);

    // Build and inject an IPv6 packet
    let test_payload = b"data-plane-test-12345";
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, test_payload);

    nodes[0].node.handle_tun_outbound(ipv6_packet.clone()).await;

    // Process packets: encrypted data → Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Verify plaintext arrived at Node 1's TUN
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(delivered.len(), 1, "Exactly one packet should be delivered");
    assert_eq!(
        delivered[0], ipv6_packet,
        "Delivered packet should match original"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_tun_outbound_triggers_session_initiation() {
    // Two connected nodes, no session yet.
    // Inject a TUN packet — should trigger session initiation,
    // queue the packet, and deliver after handshake completes.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node1_addr);

    // No session yet
    assert_eq!(nodes[0].node.session_count(), 0);

    // Install TUN receiver on Node 1
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[1].node.tun_tx = Some(tun_tx);

    // Build and inject an IPv6 packet (identity cache populated at peer promotion)
    let test_payload = b"trigger-session-test";
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, test_payload);

    nodes[0].node.handle_tun_outbound(ipv6_packet.clone()).await;

    // Session should now be initiating
    assert_eq!(nodes[0].node.session_count(), 1);
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .state()
            .is_initiating()
    );

    // Drain packets until session established and queued packet delivered
    drain_to_quiescence(&mut nodes).await;

    // Session should be established on Node 0
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .state()
            .is_established()
    );

    // Verify the queued packet was delivered to Node 1
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(
        delivered.len(),
        1,
        "Queued packet should be delivered after handshake"
    );
    assert_eq!(delivered[0], ipv6_packet);

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_endpoint_data_for_pending_session_triggers_reply_learned_discovery() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let dest = Identity::generate();
    let dest_addr = *dest.node_addr();
    add_direct_peer_for_identity(&mut node, &dest);
    insert_initiating_session(&mut node, &dest);
    assert!(
        node.find_next_hop(&dest_addr).is_some(),
        "fixture should model a stale direct route that still looks sendable"
    );

    let baseline = node.stats().discovery.req_initiated;
    let remote = crate::PeerIdentity::from_pubkey_full(dest.pubkey_full());

    node.send_endpoint_data(remote, b"status-probe".to_vec())
        .await
        .unwrap();

    assert_eq!(
        node.pending_endpoint_data
            .get(&dest_addr)
            .map(std::collections::VecDeque::len),
        Some(1),
        "endpoint payload should stay queued until the pending session recovers"
    );
    assert!(
        node.pending_lookups.contains_key(&dest_addr),
        "a stale pending session must start mesh discovery in reply-learned mode"
    );
    assert_eq!(
        node.stats().discovery.req_initiated,
        baseline + 1,
        "discovery should be initiated exactly once"
    );
}

#[tokio::test]
async fn test_update_peers_warms_auto_connect_session_over_existing_graph() {
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let dest_addr = *nodes[2].node.node_addr();
    let peer = crate::config::PeerConfig {
        npub: nodes[2].node.npub(),
        alias: Some("graph-peer".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };

    let outcome = nodes[0].node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.added, 1);
    assert!(
        nodes[0]
            .node
            .get_session(&dest_addr)
            .is_some_and(|entry| entry.is_initiating()),
        "configured peer should start an FIPS graph session without waiting for data"
    );

    drain_to_quiescence(&mut nodes).await;

    assert!(
        nodes[0]
            .node
            .get_session(&dest_addr)
            .is_some_and(|entry| entry.is_established()),
        "proactive graph session should complete over the existing FIPS path"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_update_peers_prefers_existing_graph_over_direct_address() {
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let dest_addr = *nodes[2].node.node_addr();
    let peer = crate::config::PeerConfig {
        npub: nodes[2].node.npub(),
        alias: Some("graph-before-direct".to_string()),
        addresses: vec![crate::config::PeerAddress::new(
            "udp",
            nodes[2].addr.to_string(),
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };

    let outcome = nodes[0].node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.added, 1);
    assert!(
        nodes[0]
            .node
            .get_session(&dest_addr)
            .is_some_and(|entry| entry.is_initiating()),
        "configured peer should warm over the existing FIPS graph"
    );
    assert!(
        !has_outbound_handshake_to(&nodes[0].node, &dest_addr),
        "a usable graph route should suppress direct outgoing auto-connect"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_graph_auto_connect_timeout_falls_back_to_direct_address() {
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let dest_addr = *nodes[2].node.node_addr();
    let peer = crate::config::PeerConfig {
        npub: nodes[2].node.npub(),
        alias: Some("graph-timeout-direct".to_string()),
        addresses: vec![crate::config::PeerAddress::new(
            "udp",
            nodes[2].addr.to_string(),
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };

    nodes[0].node.update_peers(vec![peer]).await.unwrap();
    assert!(
        !has_outbound_handshake_to(&nodes[0].node, &dest_addr),
        "direct path should not be tried before graph session timeout"
    );

    let last_activity = nodes[0]
        .node
        .get_session(&dest_addr)
        .expect("graph session should be pending")
        .last_activity();
    let timeout_ms = nodes[0].node.config.node.rate_limit.handshake_timeout_secs * 1000;
    nodes[0]
        .node
        .resend_pending_session_handshakes(last_activity + timeout_ms + 1)
        .await;

    assert!(
        has_outbound_handshake_to(&nodes[0].node, &dest_addr),
        "a graph route that does not complete should fall back to direct auto-connect"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_update_peers_starts_lookup_for_auto_connect_peer_without_cached_route() {
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    nodes[0].node.config.node.routing.mode = RoutingMode::ReplyLearned;

    let dest_addr = *nodes[2].node.node_addr();
    nodes[0].node.coord_cache_mut().remove(&dest_addr);
    let peer = crate::config::PeerConfig {
        npub: nodes[2].node.npub(),
        alias: Some("lookup-peer".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };

    let outcome = nodes[0].node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.added, 1);
    assert!(
        nodes[0].node.pending_lookups.contains_key(&dest_addr),
        "configured peer should start FIPS discovery immediately when no route is cached"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_tun_packet_for_pending_session_triggers_reply_learned_discovery() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let dest = Identity::generate();
    let dest_addr = *dest.node_addr();
    add_direct_peer_for_identity(&mut node, &dest);
    node.register_identity(dest_addr, dest.pubkey_full());
    insert_initiating_session(&mut node, &dest);
    assert!(
        node.find_next_hop(&dest_addr).is_some(),
        "fixture should model a stale direct route that still looks sendable"
    );

    let src_fips = crate::FipsAddress::from_node_addr(node.node_addr());
    let dst_fips = crate::FipsAddress::from_node_addr(&dest_addr);
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, b"tun-probe");
    let baseline = node.stats().discovery.req_initiated;

    node.handle_tun_outbound(ipv6_packet).await;

    assert_eq!(
        node.pending_tun_packets
            .get(&dest_addr)
            .map(std::collections::VecDeque::len),
        Some(1),
        "TUN packet should stay queued until the pending session recovers"
    );
    assert!(
        node.pending_lookups.contains_key(&dest_addr),
        "a stale pending session must start mesh discovery in reply-learned mode"
    );
    assert_eq!(
        node.stats().discovery.req_initiated,
        baseline + 1,
        "discovery should be initiated exactly once"
    );
}

#[tokio::test]
async fn test_discovery_restarts_stale_pending_session_with_fresh_coords() {
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    for node in &mut nodes {
        node.node.config.node.routing.mode = RoutingMode::ReplyLearned;
    }

    let next_hop = *nodes[1].node.node_addr();
    let dest_addr = *nodes[2].node.node_addr();
    let dest_pubkey = nodes[2].node.identity().pubkey_full();
    nodes[0].node.register_identity(dest_addr, dest_pubkey);
    nodes[0].node.learn_reverse_route(dest_addr, next_hop);

    let now_ms = crate::time::now_ms();
    let stale_coords = nodes[0].node.tree_state().my_coords().clone();
    nodes[0]
        .node
        .coord_cache_mut()
        .insert(dest_addr, stale_coords.clone(), now_ms);
    insert_initiating_session_for(&mut nodes[0].node, dest_addr, dest_pubkey);
    nodes[0]
        .node
        .pending_endpoint_data
        .entry(dest_addr)
        .or_default()
        .push_back(b"queued".to_vec());

    let fresh_coords = nodes[2].node.tree_state().my_coords().clone();
    nodes[0]
        .node
        .coord_cache_mut()
        .insert(dest_addr, fresh_coords.clone(), now_ms + 1);

    nodes[0].node.retry_session_after_discovery(dest_addr).await;

    let entry = nodes[0]
        .node
        .get_session(&dest_addr)
        .expect("retry should install a fresh initiating session");
    assert!(entry.is_initiating());
    let setup_payload = entry
        .handshake_payload()
        .expect("fresh session should store SessionSetup for resend");
    let setup = SessionSetup::decode(&setup_payload[FSP_COMMON_PREFIX_SIZE..])
        .expect("stored setup should decode");
    let setup_dest_path: Vec<NodeAddr> = setup.dest_coords.node_addrs().copied().collect();
    let fresh_path: Vec<NodeAddr> = fresh_coords.node_addrs().copied().collect();
    let stale_path: Vec<NodeAddr> = stale_coords.node_addrs().copied().collect();
    assert_eq!(setup_dest_path, fresh_path);
    assert_ne!(
        setup_dest_path, stale_path,
        "discovery retry must not keep stale destination coordinates"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_tun_outbound_unknown_destination() {
    // Inject a packet for an unknown destination — should get ICMPv6 back
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);

    // Install TUN receiver on Node 0 (for ICMPv6 response)
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[0].node.tun_tx = Some(tun_tx);

    let src_fips = crate::FipsAddress::from_node_addr(nodes[0].node.node_addr());

    // Build a packet to an unknown FIPS address (not in identity cache)
    let unknown_addr = NodeAddr::from_bytes([0xAA; 16]);
    let unknown_fips = crate::FipsAddress::from_node_addr(&unknown_addr);
    let ipv6_packet = build_ipv6_packet(&src_fips, &unknown_fips, b"unknown");

    nodes[0].node.handle_tun_outbound(ipv6_packet).await;

    // Should receive ICMPv6 Destination Unreachable back on TUN
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(
        delivered.len(),
        1,
        "Should receive ICMPv6 Destination Unreachable"
    );
    // Verify it's an ICMPv6 Destination Unreachable (type 1, code 0)
    // ICMPv6 header starts at byte 40, type at byte 40, code at byte 41
    assert!(delivered[0].len() >= 48, "ICMPv6 response too short");
    assert_eq!(delivered[0][6], 58, "Next header should be ICMPv6 (58)");
    assert_eq!(
        delivered[0][40], 1,
        "ICMPv6 type should be Destination Unreachable (1)"
    );
    assert_eq!(delivered[0][41], 0, "ICMPv6 code should be No Route (0)");

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_tun_outbound_3node_forwarded() {
    // A—B—C: TUN packet from A destined for C, forwarded through B
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node2_addr);

    // Register Node 2's identity in Node 0's cache
    // (In production, this would come from the discovery protocol or DNS priming)
    let node2_pubkey = nodes[2].node.identity().pubkey_full();
    nodes[0].node.register_identity(node2_addr, node2_pubkey);

    // Install TUN receiver on Node 2
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[2].node.tun_tx = Some(tun_tx);

    // Build and inject an IPv6 packet (triggers session initiation to Node 2)
    let test_payload = b"forwarded-data-plane";
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, test_payload);

    nodes[0].node.handle_tun_outbound(ipv6_packet.clone()).await;

    // Drain packets: handshake + queued data delivery
    drain_to_quiescence(&mut nodes).await;

    // Session should be established
    assert!(
        nodes[0]
            .node
            .get_session(&node2_addr)
            .unwrap()
            .state()
            .is_established()
    );

    // Verify packet delivered to Node 2
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(delivered.len(), 1, "Packet should be delivered to Node 2");
    assert_eq!(delivered[0], ipv6_packet);

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_tun_outbound_pending_queue_flush() {
    // Send multiple packets before session exists — all should be delivered
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node1_addr);

    // Install TUN receiver on Node 1
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[1].node.tun_tx = Some(tun_tx);

    // Send 5 packets before any session exists
    let mut packets = Vec::new();
    for i in 0..5u8 {
        let payload = format!("queued-pkt-{}", i).into_bytes();
        let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, &payload);
        packets.push(ipv6_packet.clone());
        nodes[0].node.handle_tun_outbound(ipv6_packet).await;
    }

    // First packet triggers session initiation, rest are queued
    assert_eq!(nodes[0].node.session_count(), 1);
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .state()
            .is_initiating()
    );

    // Drain until session established and queued packets flushed
    drain_to_quiescence(&mut nodes).await;

    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .state()
            .is_established()
    );

    // All 5 packets should have been delivered
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(
        delivered.len(),
        5,
        "All 5 queued packets should be delivered"
    );
    for (i, pkt) in delivered.iter().enumerate() {
        assert_eq!(*pkt, packets[i], "Packet {} should match", i);
    }

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Unit tests: Session idle timeout
// ============================================================================

/// Helper: complete a Noise IK handshake and return the initiator's NoiseSession.
fn make_noise_session(
    our_identity: &Identity,
    remote_identity: &Identity,
) -> crate::noise::NoiseSession {
    use crate::noise::HandshakeState;

    let mut initiator =
        HandshakeState::new_initiator(our_identity.keypair(), remote_identity.pubkey_full());
    let mut responder = HandshakeState::new_responder(remote_identity.keypair());

    // Set epochs for both sides (required for handshake message encryption)
    let mut init_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut init_epoch);
    initiator.set_local_epoch(init_epoch);
    let mut resp_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut resp_epoch);
    responder.set_local_epoch(resp_epoch);

    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();

    initiator.into_session().unwrap()
}

#[test]
fn test_purge_idle_sessions_removes_expired() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000, // created at t=1000ms
        true,
    );

    node.sessions.insert(remote_addr, entry);
    assert_eq!(node.session_count(), 1);
    assert!(node.get_session(&remote_addr).unwrap().is_established());

    // Purge at t=92s — should exceed default 90s idle timeout
    let now_ms = 1000 + 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(node.session_count(), 0, "Idle session should be purged");
}

#[test]
fn test_purge_idle_sessions_keeps_active() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    // Touch at t=80s — recent activity
    entry.touch(81_000);

    node.sessions.insert(remote_addr, entry);

    // Purge at t=92s — only 11s since last activity, well within 90s timeout
    let now_ms = 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(
        node.session_count(),
        1,
        "Active session should survive purge"
    );
}

#[test]
fn test_purge_idle_sessions_ignores_initiating() {
    use crate::noise::HandshakeState;

    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let handshake = HandshakeState::new_initiator(node.identity().keypair(), remote.pubkey_full());
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    node.sessions.insert(remote_addr, entry);

    // Purge well past the idle timeout — Initiating sessions should not be touched
    let now_ms = 1000 + 200_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(
        node.session_count(),
        1,
        "Initiating session should not be purged by idle timeout"
    );
}

#[test]
fn test_purge_idle_sessions_cleans_pending_packets() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    node.sessions.insert(remote_addr, entry);

    // Insert some pending packets for this destination
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(vec![1, 2, 3]);
    node.pending_tun_packets.insert(remote_addr, queue);
    assert!(node.pending_tun_packets.contains_key(&remote_addr));

    // Purge after idle timeout
    let now_ms = 1000 + 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(node.session_count(), 0);
    assert!(
        !node.pending_tun_packets.contains_key(&remote_addr),
        "Pending packets should be cleaned up with idle session"
    );
}

#[test]
fn test_purge_idle_sessions_disabled_when_zero() {
    let mut node = make_node();
    node.config.node.session.idle_timeout_secs = 0;

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    node.sessions.insert(remote_addr, entry);

    // Even way past any timeout, sessions should survive when disabled
    let now_ms = 1000 + 1_000_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(
        node.session_count(),
        1,
        "Sessions should not be purged when idle timeout is disabled"
    );
}

#[test]
fn test_purge_idle_sessions_mmp_activity_does_not_prevent_purge() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000, // created at t=1s
        true,
    );

    // Do NOT call entry.touch() — simulates a session where only MMP
    // reports have flowed (MMP no longer calls touch). last_activity
    // remains at creation time (1000ms).
    node.sessions.insert(remote_addr, entry);

    // Purge at t=92s — 91s since creation, exceeds 90s idle timeout.
    // Even though MMP reports would have been flowing, they no longer
    // reset the idle timer.
    let now_ms = 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(
        node.session_count(),
        0,
        "Session with MMP-only activity should be purged"
    );
}

#[test]
fn test_purge_idle_sessions_removes_outbound_only_stale_session() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    // Simulate periodic outbound endpoint/application data keeping the old
    // idle timer fresh while no authenticated FSP frame comes back.
    entry.record_sent(128);
    entry.touch(91_000);

    node.sessions.insert(remote_addr, entry);

    let now_ms = 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(
        node.session_count(),
        0,
        "Outbound-only stale session should be purged so sends can re-handshake"
    );
}

#[test]
fn test_purge_idle_sessions_keeps_outbound_session_with_recent_inbound_frame() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    entry.record_sent(128);
    entry.touch(91_000);
    entry.touch_inbound_frame(91_500);

    node.sessions.insert(remote_addr, entry);

    let now_ms = 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(
        node.session_count(),
        1,
        "Recent authenticated inbound FSP traffic should keep the session alive"
    );
}

// ============================================================================
// Unit tests: COORDS_PRESENT warmup counter
// ============================================================================

#[test]
fn test_coords_warmup_counter_default_zero_on_new() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

    let entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    assert_eq!(
        entry.coords_warmup_remaining(),
        0,
        "Counter should be 0 for non-Established sessions"
    );
}

#[test]
fn test_coords_warmup_counter_set_and_get() {
    let node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    assert_eq!(entry.coords_warmup_remaining(), 0);

    entry.set_coords_warmup_remaining(5);
    assert_eq!(entry.coords_warmup_remaining(), 5);

    entry.set_coords_warmup_remaining(0);
    assert_eq!(entry.coords_warmup_remaining(), 0);
}

#[test]
fn test_coords_warmup_counter_decrement() {
    let node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    entry.set_coords_warmup_remaining(3);

    // Simulate the decrement pattern used in send_session_data
    for expected in (0..3).rev() {
        assert!(entry.coords_warmup_remaining() > 0);
        entry.set_coords_warmup_remaining(entry.coords_warmup_remaining() - 1);
        assert_eq!(entry.coords_warmup_remaining(), expected);
    }

    assert_eq!(
        entry.coords_warmup_remaining(),
        0,
        "Counter should reach 0 after N decrements"
    );
}

#[test]
fn test_coords_warmup_config_default() {
    let config = crate::config::Config::new();
    assert_eq!(
        config.node.session.coords_warmup_packets, 5,
        "Default coords_warmup_packets should be 5"
    );
}

// ============================================================================
// Unit tests: Identity cache
// ============================================================================

#[test]
fn test_identity_cache_lru_eviction() {
    let mut node = make_node();
    node.config.node.cache.identity_size = 2;

    let id1 = Identity::generate();
    let id2 = Identity::generate();
    let id3 = Identity::generate();

    // Insert first two with explicit timestamps to ensure deterministic ordering
    let mut prefix1 = [0u8; 15];
    prefix1.copy_from_slice(&id1.node_addr().as_bytes()[0..15]);
    let (xonly1, _) = id1.pubkey_full().x_only_public_key();
    node.identity_cache.insert(
        prefix1,
        IdentityCacheEntry::new(
            *id1.node_addr(),
            id1.pubkey_full(),
            encode_npub(&xonly1),
            1000,
        ),
    );

    let mut prefix2 = [0u8; 15];
    prefix2.copy_from_slice(&id2.node_addr().as_bytes()[0..15]);
    let (xonly2, _) = id2.pubkey_full().x_only_public_key();
    node.identity_cache.insert(
        prefix2,
        IdentityCacheEntry::new(
            *id2.node_addr(),
            id2.pubkey_full(),
            encode_npub(&xonly2),
            2000,
        ),
    );

    assert_eq!(node.identity_cache_len(), 2);

    // Adding a third should evict the oldest (id1, timestamp 1000)
    node.register_identity(*id3.node_addr(), id3.pubkey_full());
    assert_eq!(node.identity_cache_len(), 2);

    assert!(
        node.lookup_by_fips_prefix(&prefix1).is_none(),
        "Oldest entry should have been evicted"
    );

    let mut prefix3 = [0u8; 15];
    prefix3.copy_from_slice(&id3.node_addr().as_bytes()[0..15]);
    assert!(
        node.lookup_by_fips_prefix(&prefix3).is_some(),
        "Newest entry should be present"
    );
}

#[test]
fn test_identity_cache_lookup() {
    let mut node = make_node();

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    node.register_identity(remote_addr, remote.pubkey_full());

    let mut prefix = [0u8; 15];
    prefix.copy_from_slice(&remote_addr.as_bytes()[0..15]);

    let result = node.lookup_by_fips_prefix(&prefix);
    assert!(result.is_some(), "Registered identity should be available");

    let (addr, pk) = result.unwrap();
    assert_eq!(addr, remote_addr);
    assert_eq!(pk, remote.pubkey_full());
}

#[test]
fn test_identity_cache_rejects_mismatched_pubkey_claim() {
    let mut node = make_node();
    let claimed = Identity::generate();
    let actual = Identity::generate();

    assert!(
        !node.register_identity(*claimed.node_addr(), actual.pubkey_full()),
        "identity cache must reject node_addr/pubkey pairs that do not derive from each other"
    );

    let mut claimed_prefix = [0u8; 15];
    claimed_prefix.copy_from_slice(&claimed.node_addr().as_bytes()[0..15]);
    assert!(
        node.lookup_by_fips_prefix(&claimed_prefix).is_none(),
        "mismatched identity claim must not be cached under the claimed address"
    );
}

// ============================================================================
// Session-layer handshake resend tests
// ============================================================================

/// Test that SessionEntry handshake payload storage works correctly.
#[test]
fn test_session_entry_handshake_payload_storage() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    // Initially no handshake payload
    assert!(entry.handshake_payload().is_none());
    assert_eq!(entry.resend_count(), 0);
    assert_eq!(entry.next_resend_at_ms(), 0);

    // Store a handshake payload
    let payload = vec![0x01, 0x02, 0x03, 0x04];
    entry.set_handshake_payload(payload.clone(), 2000);

    assert_eq!(entry.handshake_payload().unwrap(), &payload);
    assert_eq!(entry.resend_count(), 0);
    assert_eq!(entry.next_resend_at_ms(), 2000);
}

/// Test that resend_count and next_resend_at_ms track correctly on SessionEntry.
#[test]
fn test_session_entry_resend_tracking() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    entry.set_handshake_payload(vec![0x01], 2000);

    // Record first resend
    entry.record_resend(4000);
    assert_eq!(entry.resend_count(), 1);
    assert_eq!(entry.next_resend_at_ms(), 4000);

    // Record second resend
    entry.record_resend(8000);
    assert_eq!(entry.resend_count(), 2);
    assert_eq!(entry.next_resend_at_ms(), 8000);
}

/// Test that clear_handshake_payload clears payload and resets timer.
#[test]
fn test_session_entry_clear_handshake_payload() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    entry.set_handshake_payload(vec![0x01, 0x02], 2000);
    entry.record_resend(4000);
    assert!(entry.handshake_payload().is_some());
    assert_eq!(entry.resend_count(), 1);

    // Clear on Established transition
    entry.clear_handshake_payload();
    assert!(entry.handshake_payload().is_none());
    assert_eq!(entry.next_resend_at_ms(), 0);
    // resend_count is NOT reset — it's a historical record
    assert_eq!(entry.resend_count(), 1);
}

/// Test that session handshake timeout removes stale Initiating sessions.
#[tokio::test]
async fn test_session_handshake_timeout() {
    use crate::noise::HandshakeState;

    let mut node = make_node();

    let identity_b = Identity::generate();
    let handshake =
        HandshakeState::new_initiator(node.identity.keypair(), identity_b.pubkey_full());

    let dest_addr = *identity_b.node_addr();

    // Create a session at time 1000
    let entry = crate::node::session::SessionEntry::new(
        dest_addr,
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );
    node.sessions.insert(dest_addr, entry);

    assert!(node.sessions.contains_key(&dest_addr));

    // Before timeout: session should remain
    let timeout_secs = node.config.node.rate_limit.handshake_timeout_secs;
    let before_timeout = 1000 + timeout_secs * 1000 - 1;
    node.resend_pending_session_handshakes(before_timeout).await;
    assert!(
        node.sessions.contains_key(&dest_addr),
        "Session should survive before timeout"
    );

    // After timeout: session should be removed
    let after_timeout = 1000 + timeout_secs * 1000 + 1;
    node.resend_pending_session_handshakes(after_timeout).await;
    assert!(
        !node.sessions.contains_key(&dest_addr),
        "Timed-out session should be removed"
    );
}

/// Test that session handshake timeout removes stale AwaitingMsg3 sessions.
#[tokio::test]
async fn test_session_awaiting_msg3_timeout() {
    use crate::noise::HandshakeState;

    let mut node = make_node();

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_xk_responder(identity_b.keypair());

    let src_addr = *identity_a.node_addr();

    // Create an AwaitingMsg3 session at time 1000
    let entry = crate::node::session::SessionEntry::new(
        src_addr,
        identity_a.pubkey_full(),
        EndToEndState::AwaitingMsg3(handshake),
        1000,
        false,
    );
    node.sessions.insert(src_addr, entry);

    assert!(node.sessions.contains_key(&src_addr));

    // After timeout: session should be removed
    let timeout_secs = node.config.node.rate_limit.handshake_timeout_secs;
    let after_timeout = 1000 + timeout_secs * 1000 + 1;
    node.resend_pending_session_handshakes(after_timeout).await;
    assert!(
        !node.sessions.contains_key(&src_addr),
        "Timed-out AwaitingMsg3 session should be removed"
    );
}

#[tokio::test]
async fn test_tun_outbound_path_mtu_generates_ptb() {
    // When a session's PathMtuState reports a lower MTU than the local
    // transport (simulating a bottleneck learned via MtuExceeded signals),
    // handle_tun_outbound should generate ICMPv6 Packet Too Big for
    // oversized packets instead of forwarding them.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node1_addr);

    // Establish session (XK: 3 messages — Setup, Ack, Msg3)
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .state()
            .is_established()
    );

    // Simulate receipt of MtuExceeded by reducing PathMtuState to a value
    // lower than the local transport MTU.
    let local_transport_mtu = nodes[0].node.transport_mtu();
    let reduced_mtu = local_transport_mtu - 200;
    {
        let entry = nodes[0].node.get_session_mut(&node1_addr).unwrap();
        let mmp = entry.mmp_mut().unwrap();
        mmp.path_mtu
            .apply_notification(reduced_mtu, std::time::Instant::now());
        assert_eq!(mmp.path_mtu.current_mtu(), reduced_mtu);
    }

    // Install TUN receiver on source node to capture ICMPv6 PTB
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[0].node.tun_tx = Some(tun_tx);

    // Build an IPv6 packet that fits local MTU but exceeds path MTU
    let reduced_ipv6_mtu = crate::upper::icmp::effective_ipv6_mtu(reduced_mtu) as usize;
    let local_ipv6_mtu = nodes[0].node.effective_ipv6_mtu() as usize;
    let oversized_payload = vec![0u8; reduced_ipv6_mtu - 39]; // 40-byte hdr + payload > reduced MTU
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, &oversized_payload);
    assert!(
        ipv6_packet.len() > reduced_ipv6_mtu,
        "packet must exceed path MTU"
    );
    assert!(
        ipv6_packet.len() <= local_ipv6_mtu,
        "packet must fit local MTU"
    );

    nodes[0].node.handle_tun_outbound(ipv6_packet).await;

    // Verify ICMPv6 Packet Too Big was generated
    let ptb_messages: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(
        ptb_messages.len(),
        1,
        "Should generate exactly one ICMPv6 PTB"
    );

    let ptb = &ptb_messages[0];
    assert_eq!(ptb[0] >> 4, 6, "Should be IPv6");
    assert_eq!(ptb[6], 58, "Next header should be ICMPv6 (58)");
    assert_eq!(ptb[40], 2, "ICMPv6 type should be Packet Too Big (2)");
    assert_eq!(ptb[41], 0, "ICMPv6 code should be 0");

    // Verify PTB source is the *remote peer* (original packet's destination),
    // NOT the local node. Linux ignores PTBs whose source matches a local
    // address, causing a PMTUD blackhole.
    let ptb_src = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ptb[8..24]).unwrap());
    let ptb_dst = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ptb[24..40]).unwrap());
    assert_eq!(
        ptb_src,
        dst_fips.to_ipv6(),
        "PTB source must be remote peer (original dst), not local node"
    );
    assert_eq!(
        ptb_dst,
        src_fips.to_ipv6(),
        "PTB destination must be local node (original src)"
    );

    // Verify reported MTU (32-bit field at ICMPv6 header bytes 4-7)
    let reported_mtu = u32::from_be_bytes([ptb[44], ptb[45], ptb[46], ptb[47]]);
    assert_eq!(
        reported_mtu, reduced_ipv6_mtu as u32,
        "Reported MTU should match path IPv6 MTU"
    );

    // Verify a packet that fits within path MTU passes through (no PTB)
    let (tun_tx2, tun_rx2) = std::sync::mpsc::channel();
    nodes[0].node.tun_tx = Some(tun_tx2);
    let fitting_payload = vec![0u8; reduced_ipv6_mtu - 41]; // fits within path MTU
    let fitting_packet = build_ipv6_packet(&src_fips, &dst_fips, &fitting_payload);
    assert!(fitting_packet.len() <= reduced_ipv6_mtu);

    nodes[0].node.handle_tun_outbound(fitting_packet).await;

    // No PTB should be generated for a fitting packet
    let ptb_messages2: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx2.try_recv().ok()).collect();
    assert_eq!(
        ptb_messages2.len(),
        0,
        "Should not generate PTB for fitting packet"
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration test: Multi-hop PMTUD with heterogeneous MTUs
// ============================================================================

#[tokio::test]
async fn test_multihop_pmtud_heterogeneous_mtu() {
    // Three-node chain: A(1400)—B(800)—C(800)
    //
    // Node B has a smaller transport MTU than A. When A sends an IPv6
    // packet that fits A's local MTU (1294) but whose wire size after
    // FIPS encapsulation exceeds B's transport MTU (800), B's forwarding
    // path fails with MtuExceeded and sends an MtuExceeded signal back
    // to A. A updates PathMtuState, and the next oversized packet
    // generates ICMPv6 Packet Too Big on TUN.
    //
    // This exercises the full PMTUD loop:
    //   1. Oversized packet forwarded A→B
    //   2. B→C forward fails (B's transport MTU 800 exceeded)
    //   3. B sends MtuExceeded signal back to A
    //   4. A receives signal, updates PathMtuState for C
    //   5. Next oversized packet → ICMPv6 PTB on TUN
    let mtus = [1400, 800, 800];
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test_with_mtus(&mtus, &edges).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node2_addr);

    // Register Node 2's identity in Node 0's cache
    let node2_pubkey = nodes[2].node.identity().pubkey_full();
    nodes[0].node.register_identity(node2_addr, node2_pubkey);

    // Establish session A→C via B (triggers routing through tree)
    nodes[0]
        .node
        .initiate_session(node2_addr, node2_pubkey)
        .await
        .unwrap();
    drain_to_quiescence(&mut nodes).await;
    assert!(
        nodes[0]
            .node
            .get_session(&node2_addr)
            .unwrap()
            .state()
            .is_established(),
        "Session A→C should be established"
    );

    // Exhaust coord warmup by sending small packets first.
    // Without piggybacked coords, the wire packet is ~106 + IPv6 bytes,
    // which fits B's receive buffer (mtu+100=900) for reasonable sizes.
    // With coords (~66 extra), the wire could exceed B's recv buffer.
    for _ in 0..5 {
        let small = build_ipv6_packet(&src_fips, &dst_fips, &[0u8; 10]);
        nodes[0]
            .node
            .send_ipv6_packet(&node2_addr, &small)
            .await
            .unwrap();
    }
    drain_to_quiescence(&mut nodes).await;

    // Build an IPv6 packet that fits A's local MTU (1294) but whose wire
    // size (~750 + 106 = ~856 bytes) exceeds B's transport MTU (800).
    // effective_ipv6_mtu(1400) = 1294, effective_ipv6_mtu(800) = 694
    let oversized_payload = vec![0xABu8; 750 - 40]; // 710 bytes payload → 750-byte IPv6 packet
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, &oversized_payload);
    assert_eq!(ipv6_packet.len(), 750);
    let local_effective_mtu = crate::upper::icmp::effective_ipv6_mtu(1400) as usize;
    assert!(
        ipv6_packet.len() <= local_effective_mtu,
        "packet ({}) must fit A's local MTU ({})",
        ipv6_packet.len(),
        local_effective_mtu
    );

    // Send the oversized packet — B should fail to forward and send
    // MtuExceeded signal back.
    nodes[0]
        .node
        .send_ipv6_packet(&node2_addr, &ipv6_packet)
        .await
        .unwrap();
    drain_to_quiescence(&mut nodes).await;

    // Verify PathMtuState was updated on A
    let path_mtu = {
        let entry = nodes[0].node.get_session(&node2_addr).unwrap();
        let mmp = entry.mmp().expect("session should have MMP state");
        mmp.path_mtu.current_mtu()
    };
    assert!(
        path_mtu < 1400,
        "PathMtuState should have decreased from MtuExceeded signal, got {}",
        path_mtu
    );

    // Verify path_mtu_lookup (consulted by the TUN reader/writer at TCP MSS
    // clamp time) also reflects the tightened bottleneck. The reactive
    // MtuExceeded handler writes here so subsequent SYN clamps see the
    // forward-path budget rather than the discovery reverse-path value.
    let lookup_mtu = nodes[0]
        .node
        .path_mtu_lookup_get(&dst_fips)
        .expect("path_mtu_lookup should have entry for C after MtuExceeded");
    assert!(
        lookup_mtu < 1400,
        "path_mtu_lookup should have tightened from MtuExceeded signal, got {}",
        lookup_mtu
    );

    // Now send ANOTHER oversized packet — this time handle_tun_outbound
    // should check PathMtuState and generate ICMPv6 PTB on TUN instead
    // of forwarding.
    let (tun_tx2, tun_rx2) = std::sync::mpsc::channel();
    nodes[0].node.tun_tx = Some(tun_tx2);

    nodes[0].node.handle_tun_outbound(ipv6_packet.clone()).await;

    let ptb_messages: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx2.try_recv().ok()).collect();
    assert_eq!(
        ptb_messages.len(),
        1,
        "Should generate ICMPv6 PTB for oversized packet after PathMtuState update"
    );

    let ptb = &ptb_messages[0];
    assert_eq!(ptb[0] >> 4, 6, "Should be IPv6");
    assert_eq!(ptb[6], 58, "Next header should be ICMPv6 (58)");
    assert_eq!(ptb[40], 2, "ICMPv6 type should be Packet Too Big (2)");
    assert_eq!(ptb[41], 0, "ICMPv6 code should be 0");

    // Verify PTB source is the *remote peer* (original packet's destination),
    // NOT the local node. Linux ignores PTBs whose source matches a local
    // address, causing a PMTUD blackhole.
    let ptb_src = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ptb[8..24]).unwrap());
    let ptb_dst = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ptb[24..40]).unwrap());
    assert_eq!(
        ptb_src,
        dst_fips.to_ipv6(),
        "PTB source must be remote peer (original dst), not local node"
    );
    assert_eq!(
        ptb_dst,
        src_fips.to_ipv6(),
        "PTB destination must be local node (original src)"
    );

    // Verify reported MTU is the path MTU (not local MTU)
    let reported_mtu = u32::from_be_bytes([ptb[44], ptb[45], ptb[46], ptb[47]]);
    let expected_ipv6_mtu = crate::upper::icmp::effective_ipv6_mtu(path_mtu) as u32;
    assert_eq!(
        reported_mtu, expected_ipv6_mtu,
        "ICMPv6 PTB MTU should match path IPv6 MTU (transport MTU {} - overhead)",
        path_mtu
    );

    // Verify a fitting packet still passes through without PTB
    let (tun_tx3, tun_rx3) = std::sync::mpsc::channel();
    nodes[0].node.tun_tx = Some(tun_tx3);

    let fitting_payload = vec![0xCDu8; 600 - 40]; // 600-byte IPv6 packet, well within 694
    let fitting_packet = build_ipv6_packet(&src_fips, &dst_fips, &fitting_payload);
    assert!(fitting_packet.len() <= expected_ipv6_mtu as usize);

    nodes[0].node.handle_tun_outbound(fitting_packet).await;

    let ptb_messages3: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx3.try_recv().ok()).collect();
    assert_eq!(
        ptb_messages3.len(),
        0,
        "Should not generate PTB for packet fitting within path MTU"
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Reactive MtuExceeded → path_mtu_lookup focused unit tests
//
// These exercise the receive-side write path that mirrors the bottleneck
// MTU into `path_mtu_lookup` (consulted by the TUN reader/writer at
// SYN-clamp time). Discovery's reverse-path response and the FMP-promotion
// seed populate the same lookup; the reactive channel keeps it
// authoritative under forward-path-asymmetry conditions.
// ============================================================================

/// Build an MtuExceeded inner payload (35 bytes: flags + dest + reporter + mtu LE).
///
/// `handle_mtu_exceeded` receives the payload after the dispatcher strips
/// the FSP prefix and msg_type byte, so the test wire is just the body.
fn build_mtu_exceeded_inner(dest: &NodeAddr, reporter: &NodeAddr, mtu: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(35);
    buf.push(0x00); // flags (reserved)
    buf.extend_from_slice(dest.as_bytes());
    buf.extend_from_slice(reporter.as_bytes());
    buf.extend_from_slice(&mtu.to_le_bytes());
    buf
}

#[tokio::test]
async fn test_handle_mtu_exceeded_writes_path_mtu_lookup_when_empty() {
    use crate::node::tests::spanning_tree::make_test_node;

    let mut tn = make_test_node().await;

    let dest = NodeAddr::from_bytes([0xCC; 16]);
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);

    assert!(
        tn.node.path_mtu_lookup_get(&dest_fips).is_none(),
        "lookup should start empty for this destination"
    );

    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1280);
    tn.node.handle_mtu_exceeded(&inner).await;

    assert_eq!(
        tn.node.path_mtu_lookup_get(&dest_fips),
        Some(1280),
        "MtuExceeded should populate path_mtu_lookup with the bottleneck MTU"
    );
}

#[tokio::test]
async fn test_handle_mtu_exceeded_tightens_existing_path_mtu_lookup() {
    use crate::node::tests::spanning_tree::make_test_node;

    let mut tn = make_test_node().await;

    let dest = NodeAddr::from_bytes([0xCC; 16]);
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);

    // Pre-seed with a generous value (e.g., from a discovery reverse-path
    // response that didn't reflect the forward-path bottleneck).
    tn.node.path_mtu_lookup_insert(dest_fips, 1500);

    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1280);
    tn.node.handle_mtu_exceeded(&inner).await;

    assert_eq!(
        tn.node.path_mtu_lookup_get(&dest_fips),
        Some(1280),
        "MtuExceeded with smaller bottleneck must tighten the lookup"
    );
}

#[tokio::test]
async fn test_handle_mtu_exceeded_keeps_tighter_existing_path_mtu_lookup() {
    use crate::node::tests::spanning_tree::make_test_node;

    let mut tn = make_test_node().await;

    let dest = NodeAddr::from_bytes([0xCC; 16]);
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);

    // Pre-seed with a tighter value than the incoming signal (e.g., from
    // a prior reactive event on a narrower hop). The clamp must never
    // loosen — keep the existing value.
    tn.node.path_mtu_lookup_insert(dest_fips, 1280);

    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1500);
    tn.node.handle_mtu_exceeded(&inner).await;

    assert_eq!(
        tn.node.path_mtu_lookup_get(&dest_fips),
        Some(1280),
        "MtuExceeded with looser bottleneck must not loosen a tighter existing value"
    );
}

// ============================================================================
// Proactive PathMtuNotification → path_mtu_lookup focused unit tests
//
// These exercise the receive-side write path that mirrors the proactive
// end-to-end echo into `path_mtu_lookup`. Without this mirror, new TCP
// flows opened on a path the proactive notification has tightened keep
// getting clamped by the staler discovery-time value until a reactive
// MtuExceeded fires for those flows — long-lived stable paths can sit
// in the gap indefinitely.
// ============================================================================

/// Build a PathMtuNotification body (2 bytes: path_mtu LE).
fn build_path_mtu_notification_body(mtu: u16) -> Vec<u8> {
    mtu.to_le_bytes().to_vec()
}

/// Insert an Established session with MMP initialized so the proactive
/// PathMtuNotification handler can apply notifications.
fn install_established_session_with_mmp(node: &mut Node, remote: &Identity) {
    let session = make_noise_session(node.identity(), remote);
    let remote_addr = *remote.node_addr();
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );
    entry.init_mmp(&node.config.node.session_mmp);
    node.sessions.insert(remote_addr, entry);
}

#[test]
fn test_handle_path_mtu_notification_writes_path_mtu_lookup_when_empty() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::FipsAddress::from_node_addr(&remote_addr);

    install_established_session_with_mmp(&mut node, &remote);

    assert!(
        node.path_mtu_lookup_get(&remote_fips).is_none(),
        "lookup should start empty for this destination"
    );

    let body = build_path_mtu_notification_body(1280);
    node.handle_session_path_mtu_notification(&remote_addr, &body);

    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1280),
        "PathMtuNotification should populate path_mtu_lookup with the reported MTU"
    );
}

#[test]
fn test_handle_path_mtu_notification_tightens_existing_path_mtu_lookup() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::FipsAddress::from_node_addr(&remote_addr);

    install_established_session_with_mmp(&mut node, &remote);

    // Pre-seed with a generous value (e.g., from the discovery seed at link
    // promotion time, before the destination's proactive echo arrived).
    node.path_mtu_lookup_insert(remote_fips, 1500);

    let body = build_path_mtu_notification_body(1280);
    node.handle_session_path_mtu_notification(&remote_addr, &body);

    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1280),
        "PathMtuNotification with smaller MTU must tighten the lookup"
    );
}

#[test]
fn test_handle_path_mtu_notification_keeps_tighter_existing_path_mtu_lookup() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::FipsAddress::from_node_addr(&remote_addr);

    install_established_session_with_mmp(&mut node, &remote);

    // Pre-seed with a tighter value than what the proactive notification
    // reports (e.g., from a prior reactive MtuExceeded on a narrower hop).
    // The mirror must never loosen the clamp.
    node.path_mtu_lookup_insert(remote_fips, 1200);

    let body = build_path_mtu_notification_body(1400);
    node.handle_session_path_mtu_notification(&remote_addr, &body);

    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1200),
        "PathMtuNotification with looser MTU must not loosen a tighter existing value"
    );
}

#[test]
fn test_handle_path_mtu_notification_no_session_no_op() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::FipsAddress::from_node_addr(&remote_addr);

    // No session installed. The handler should drop the notification entirely.
    let body = build_path_mtu_notification_body(1280);
    node.handle_session_path_mtu_notification(&remote_addr, &body);

    assert!(
        node.path_mtu_lookup_get(&remote_fips).is_none(),
        "PathMtuNotification with no session must not touch path_mtu_lookup"
    );
}
