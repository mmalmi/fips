//! Tests for the consecutive-decrypt-failure recovery path.
//!
//! Covers `Node::handle_decrypt_failure` (in `node/handlers/encrypted.rs`),
//! which increments `ActivePeer::increment_decrypt_failures` on each AEAD
//! verification failure and starts a link-session recovery rekey once
//! `DECRYPT_FAILURE_THRESHOLD` consecutive failures are observed. Peer
//! eviction is reserved for cases where recovery cannot be started.

use super::*;
use std::time::{Duration, Instant};

#[tokio::test]
async fn bad_udp_ciphertext_cannot_rekey_a_live_peer() {
    use spanning_tree::*;

    let mut nodes = vec![make_test_node().await, make_test_node().await];
    initiate_handshake(&mut nodes, 1, 0).await;
    assert!(drain_all_packets(&mut nodes, false).await > 0);
    let identity = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let peer = nodes[0].node.get_peer_mut(identity.node_addr()).unwrap();
    peer.set_session_established_at_for_test(Instant::now() - Duration::from_secs(31));
    let original = (peer.link_id(), peer.our_index(), peer.session_generation());
    let mut invalid = vec![0; 32];
    invalid[4..8].copy_from_slice(&peer.our_index().unwrap().as_u32().to_le_bytes());
    // The socket supplies the exact legitimate source address, modeling what
    // an address-spoofed datagram exposes to FIPS without requiring raw sockets.
    for counter in 1_000_000_u64..1_000_008 {
        invalid[8..16].copy_from_slice(&counter.to_le_bytes());
        nodes[1].node.transports[&nodes[1].transport_id]
            .send(&nodes[0].addr, &invalid)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let packet = nodes[0].packet_rx.recv().await.unwrap();
                let selected = packet.data.as_slice() == invalid;
                process_dataplane_packet(&mut nodes[0], packet).await;
                if selected {
                    break;
                }
            }
        })
        .await
        .unwrap();
    }
    let peer = nodes[0].node.get_peer(identity.node_addr()).unwrap();
    assert!(
        !peer.rekey_in_progress(),
        "bad ciphertext must not rekey a live UDP peer"
    );
    assert_eq!(peer.consecutive_decrypt_failures(), 0);
    assert_eq!(
        (peer.link_id(), peer.our_index(), peer.session_generation()),
        original
    );

    // Queue a valid heartbeat and bad ciphertext in one control turn. Even
    // previously expired liveness must be refreshed before recovery decisions.
    let mut turn = crate::dataplane::DataplaneLiveNodeTurn::default();
    for counter in 2_000_000_u64..2_000_008 {
        invalid[8..16].copy_from_slice(&counter.to_le_bytes());
        let packet = crate::transport::ReceivedPacket::with_timestamp(
            nodes[0].transport_id,
            nodes[1].addr.clone(),
            crate::transport::PacketBuffer::new(invalid.clone()),
            Node::now_ms(),
        );
        turn.absorb(collect_dataplane_ready_turn(&mut nodes[0].node, Some(packet)).await);
    }
    let receiver = *nodes[0].node.node_addr();
    nodes[1]
        .node
        .send_dataplane_fmp_link_plaintext(
            &receiver,
            &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
            false,
        )
        .await
        .unwrap();
    let heartbeat = tokio::time::timeout(Duration::from_secs(1), nodes[0].packet_rx.recv())
        .await
        .unwrap()
        .unwrap();
    turn.absorb(collect_dataplane_ready_turn(&mut nodes[0].node, Some(heartbeat)).await);
    tokio::time::timeout(Duration::from_secs(2), async {
        while turn.drops().len() < 8 || turn.fmp_link_ingress().is_empty() {
            let ready = nodes[0].node.dataplane.readiness_notify();
            turn.absorb(collect_dataplane_ready_turn(&mut nodes[0].node, None).await);
            if turn.drops().len() < 8 || turn.fmp_link_ingress().is_empty() {
                ready.notified().await;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(turn.drops().len(), 8);
    nodes[0]
        .node
        .get_peer_mut(identity.node_addr())
        .unwrap()
        .touch(Node::now_ms().saturating_sub(31_000));
    seed_dataplane_fmp_rx_for_test(
        &mut nodes[0].node,
        *identity.node_addr(),
        Duration::from_secs(31),
    );
    nodes[0]
        .node
        .process_dataplane_control_ingress(&mut turn)
        .await;
    let peer = nodes[0].node.get_peer(identity.node_addr()).unwrap();
    assert!(
        !peer.rekey_in_progress(),
        "authenticated work must precede same-turn failures"
    );
    assert_eq!(peer.consecutive_decrypt_failures(), 0);
    assert_eq!(
        (peer.link_id(), peer.our_index(), peer.session_generation()),
        original
    );

    populate_all_coord_caches(&mut nodes);
    let mut endpoint = nodes[1].node.attach_endpoint_data_io(8).unwrap();
    super::session::send_endpoint_data_via_dataplane(
        &mut nodes[0].node,
        identity,
        b"live UDP owner".to_vec(),
    )
    .await
    .unwrap();
    let event = super::session::recv_endpoint_event_while_draining(
        &mut nodes,
        &mut endpoint.event_rx,
        Duration::from_secs(2),
        "live UDP owner delivery",
    )
    .await;
    assert_eq!(
        super::session::expect_single_endpoint_data_event(event)
            .payload
            .as_slice(),
        b"live UDP owner"
    );
    cleanup_nodes(&mut nodes).await;
}

async fn make_started_udp_transport(id: u32) -> TransportHandle {
    let (packet_tx, _packet_rx) = packet_channel(64);
    let transport_id = TransportId::new(id);
    let mut udp = UdpTransport::new(
        transport_id,
        Some(format!("udp{}", id)),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    TransportHandle::Udp(udp)
}

/// Drive a fully-promoted peer to the decrypt-failure threshold with no usable
/// transport and verify forced removal still cleans up both active peer storage
/// and session-index dispatch.
///
/// Setup uses the `make_completed_connection` harness so the peer has a
/// real `our_index`/`transport_id`, ensuring `remove_active_peer` exercises
/// the full active peer registry cleanup path.
#[tokio::test]
async fn test_decrypt_failure_threshold_removes_peer_when_recovery_unavailable() {
    // Threshold constant in node/handlers/encrypted.rs (kept in sync with
    // production code; see DECRYPT_FAILURE_THRESHOLD).
    const THRESHOLD: u32 = 4;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    // Build a fully-promoted active peer with our_index/transport_id set
    // so session-index dispatch is populated by promote_connection.
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2_000).unwrap();

    // Sanity: peer is registered and indexed.
    assert_eq!(node.peer_count(), 1, "peer should be present after promote");
    let our_index = node
        .get_peer(&node_addr)
        .and_then(|p| p.our_index())
        .expect("promoted peer must have our_index");
    assert_eq!(
        node.peers
            .get_session_index(&(transport_id, our_index.as_u32())),
        Some(&node_addr),
        "active peer registry session-index dispatch must be populated after promote"
    );
    assert_eq!(
        node.get_peer(&node_addr)
            .unwrap()
            .consecutive_decrypt_failures(),
        0,
        "fresh peer's failure counter must start at zero"
    );

    // Drive failures up to (but not including) the threshold; peer must
    // remain present and the counter must increase monotonically.
    for expected in 1..THRESHOLD {
        node.handle_decrypt_failure(&node_addr).await;
        let count = node
            .get_peer(&node_addr)
            .expect("peer must still be present below threshold")
            .consecutive_decrypt_failures();
        assert_eq!(
            count, expected,
            "counter should track failures pre-threshold"
        );
    }
    assert_eq!(
        node.peer_count(),
        1,
        "peer must remain registered until threshold is reached"
    );

    // The Nth failure crosses the threshold. Recovery cannot start because
    // the peer's transport handle is absent, so we fall back to eviction.
    node.handle_decrypt_failure(&node_addr).await;

    assert!(
        node.get_peer(&node_addr).is_none(),
        "peer must be removed from peers table at threshold"
    );
    assert_eq!(
        node.peer_count(),
        0,
        "peer_count must be zero after eviction"
    );
    assert!(
        !node
            .peers
            .contains_session_index(&(transport_id, our_index.as_u32())),
        "active peer registry session-index entry must be cleaned up at threshold"
    );
}

/// With a usable transport, the threshold should start an in-place FMP rekey
/// and keep the existing peer/session alive instead of dropping the link.
#[tokio::test]
async fn test_decrypt_failure_threshold_starts_recovery_rekey_when_transport_available() {
    const THRESHOLD: u32 = 4;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    node.transports
        .insert(transport_id, make_started_udp_transport(1).await);

    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2_000).unwrap();

    for expected in 1..THRESHOLD {
        node.handle_decrypt_failure(&node_addr).await;
        let count = node
            .get_peer(&node_addr)
            .expect("peer must still be present below threshold")
            .consecutive_decrypt_failures();
        assert_eq!(count, expected);
    }

    node.handle_decrypt_failure(&node_addr).await;

    let peer = node
        .get_peer(&node_addr)
        .expect("recovery rekey should keep peer alive");
    assert!(
        peer.rekey_in_progress(),
        "threshold should start an in-place recovery rekey"
    );
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        0,
        "starting recovery should reset the local failure streak"
    );
    let rekey_index = peer
        .rekey_our_index()
        .expect("recovery rekey must allocate a new local index");
    assert!(
        node.pending_outbound
            .contains_key(&(transport_id, rekey_index.as_u32())),
        "rekey msg2 dispatch must be registered"
    );
    assert!(
        node.retry_pending.is_empty(),
        "recovery rekey should not schedule a reconnect retry"
    );

    let mut transport = node.transports.remove(&transport_id).unwrap();
    transport.stop().await.unwrap();
}

#[tokio::test]
async fn test_dataplane_decrypt_failures_suppressed_during_fresh_session_drain() {
    const THRESHOLD: u32 = 4;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    node.transports
        .insert(transport_id, make_started_udp_transport(1).await);

    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2_000).unwrap();

    for counter in 1..=THRESHOLD + 5 {
        node.handle_dataplane_fmp_decrypt_failure(&node_addr, counter as u64, 0)
            .await;
    }

    let peer = node
        .get_peer(&node_addr)
        .expect("fresh-session stale packet drain must not remove peer");
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        0,
        "fresh dataplane failures before any authenticated counter should be ignored"
    );
    assert!(
        !peer.rekey_in_progress(),
        "fresh stale packet drain must not start another recovery rekey"
    );

    let mut transport = node.transports.remove(&transport_id).unwrap();
    transport.stop().await.unwrap();
}

#[tokio::test]
async fn test_dataplane_decrypt_failures_suppressed_during_post_auth_fresh_session_drain() {
    const THRESHOLD: u32 = 4;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2_000).unwrap();

    for counter in 1..=THRESHOLD {
        node.handle_dataplane_fmp_decrypt_failure(&node_addr, counter as u64, 1)
            .await;
    }

    let peer = node
        .get_peer(&node_addr)
        .expect("post-auth stale packet drain must not remove peer");
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        0,
        "fresh dataplane failures after an authenticated counter should still be ignored briefly"
    );
}

#[tokio::test]
async fn dataplane_decrypt_failures_recover_after_configured_liveness_timeout() {
    for replay_highest in [0, 1] {
        let mut node = make_node();
        node.config.node.link_dead_timeout_secs = 5;
        let transport_id = TransportId::new(1);
        let link_id = LinkId::new(1);
        let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1_000);
        let node_addr = *identity.node_addr();
        node.add_connection(conn).unwrap();
        node.promote_connection(link_id, identity, 2_000).unwrap();
        seed_dataplane_fmp_rx_for_test(&mut node, node_addr, Duration::from_secs(6));
        for counter in 1..=4 {
            node.handle_dataplane_fmp_decrypt_failure(&node_addr, counter, replay_highest)
                .await;
        }
        assert!(
            node.get_peer(&node_addr).is_none(),
            "expired liveness must still permit recovery for an unauthenticating peer"
        );
    }
}
