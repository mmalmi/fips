use super::*;

#[tokio::test]
async fn test_two_node_handshake_udp() {
    use crate::config::UdpConfig;
    use crate::node::wire::build_msg1;
    use crate::transport::udp::UdpTransport;
    use tokio::time::{Duration, timeout};

    // === Setup: Two nodes with UDP transports on localhost ===

    let mut node_a = make_node();
    let mut node_b = make_node();

    let transport_id_a = TransportId::new(1);
    let transport_id_b = TransportId::new(1);

    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };

    let (packet_tx_a, mut packet_rx_a) = packet_channel(64);
    let (packet_tx_b, mut packet_rx_b) = packet_channel(64);

    let mut transport_a = UdpTransport::new(transport_id_a, None, udp_config.clone(), packet_tx_a);
    let mut transport_b = UdpTransport::new(transport_id_b, None, udp_config, packet_tx_b);

    transport_a.start_async().await.unwrap();
    transport_b.start_async().await.unwrap();

    let addr_b = transport_b.local_addr().unwrap();
    let remote_addr_b = TransportAddr::from_string(&addr_b.to_string());

    node_a
        .transports
        .insert(transport_id_a, TransportHandle::Udp(transport_a));
    node_b
        .transports
        .insert(transport_id_b, TransportHandle::Udp(transport_b));

    // === Phase 1: Node A initiates handshake to Node B ===

    // Create peer identity for B (must use full key for ECDH parity)
    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity.pubkey_full());
    let peer_b_node_addr = *peer_b_identity.node_addr();

    let link_id_a = node_a.allocate_link_id();
    let mut conn_a = PeerConnection::outbound(link_id_a, peer_b_identity, 1000);

    // Allocate session index for A's outbound
    let our_index_a = node_a.index_allocator.allocate().unwrap();

    // Start handshake (generates Noise IK msg1)
    let our_keypair_a = node_a.identity.keypair();
    let noise_msg1 = conn_a
        .start_handshake(our_keypair_a, node_a.startup_epoch, 1000)
        .unwrap();
    conn_a.set_our_index(our_index_a);
    conn_a.set_transport_id(transport_id_a);
    conn_a.set_source_addr(remote_addr_b.clone());

    // Build wire msg1 and track in node state
    let wire_msg1 = build_msg1(our_index_a, &noise_msg1);

    let link_a = Link::connectionless(
        link_id_a,
        transport_id_a,
        remote_addr_b.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node_a.links.insert(link_id_a, link_a);
    node_a.peers.insert_connection(link_id_a, conn_a);
    node_a
        .pending_outbound
        .insert((transport_id_a, our_index_a.as_u32()), link_id_a);

    // Send msg1 from A to B over UDP
    let transport = node_a.transports.get(&transport_id_a).unwrap();
    transport
        .send(&remote_addr_b, &wire_msg1)
        .await
        .expect("Failed to send msg1");

    // === Phase 2: Node B receives msg1, sends msg2, promotes ===

    let packet_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("Timeout waiting for msg1")
        .expect("Channel closed");

    node_b.handle_msg1(packet_b).await;

    // Verify B promoted the inbound connection
    let peer_a_node_addr =
        *PeerIdentity::from_pubkey_full(node_a.identity.pubkey_full()).node_addr();
    assert_eq!(
        node_b.peer_count(),
        1,
        "Node B should have 1 peer after msg1"
    );
    let peer_a_on_b = node_b
        .get_peer(&peer_a_node_addr)
        .expect("Node B should have peer A");
    assert!(
        peer_a_on_b.has_session(),
        "Peer A on B should have NoiseSession"
    );
    let our_index_b = peer_a_on_b.our_index().expect("B should have our_index");
    assert!(
        node_b
            .peers
            .contains_session_index(&(transport_id_b, our_index_b.as_u32())),
        "Node B active peer registry session-index dispatch should be populated"
    );

    // === Phase 3: Node A receives msg2, completes handshake, promotes ===

    let packet_a = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await
        .expect("Timeout waiting for msg2")
        .expect("Channel closed");

    node_a.handle_msg2(packet_a).await;

    // Verify A promoted the outbound connection
    assert_eq!(
        node_a.peer_count(),
        1,
        "Node A should have 1 peer after msg2"
    );
    let peer_b_on_a = node_a
        .get_peer(&peer_b_node_addr)
        .expect("Node A should have peer B");
    assert!(
        peer_b_on_a.has_session(),
        "Peer B on A should have NoiseSession"
    );
    assert_eq!(
        peer_b_on_a.our_index(),
        Some(our_index_a),
        "Peer B on A should have our_index matching what we allocated"
    );
    assert!(
        node_a
            .peers
            .contains_session_index(&(transport_id_a, our_index_a.as_u32())),
        "Node A active peer registry session-index dispatch should be populated"
    );

    // Clean up transports
    for (_, t) in node_a.transports.iter_mut() {
        t.stop().await.ok();
    }
    for (_, t) in node_b.transports.iter_mut() {
        t.stop().await.ok();
    }
}
