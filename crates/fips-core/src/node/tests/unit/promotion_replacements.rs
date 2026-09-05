use super::*;

pub(super) async fn confirm_inbound_candidate_for_test(
    node: &mut Node,
    transport_id: TransportId,
    source: &TransportAddr,
    mut remote_handshake: crate::noise::HandshakeState,
) {
    let link_id = node.find_link_by_addr(transport_id, source).unwrap();
    let pending = node.get_connection(&link_id).unwrap();
    let msg2 = pending.handshake_msg2().unwrap();
    let header = crate::node::wire::Msg2Header::parse(msg2).unwrap();
    assert_eq!(pending.our_index(), Some(header.sender_idx));
    assert!(node.index_allocator.is_allocated(header.sender_idx));
    remote_handshake
        .read_message_2(header.noise_msg2(msg2))
        .unwrap();
    let mut session = remote_handshake.into_session().unwrap();
    let mut heartbeat = 0u32.to_le_bytes().to_vec();
    heartbeat.push(crate::protocol::LinkMessageType::Heartbeat.to_byte());
    let aad = crate::dataplane::build_fmp_established_header(
        header.sender_idx.as_u32(),
        session.current_send_counter(),
        0,
        heartbeat.len() as u16,
    );
    let mut wire = aad.to_vec();
    wire.extend(session.encrypt_with_aad(&heartbeat, &aad).unwrap());
    assert!(
        node.confirm_inbound_handshake(ReceivedPacket::with_timestamp(
            transport_id,
            source.clone(),
            crate::transport::PacketBuffer::new(wire),
            Node::now_ms(),
        ))
        .await
    );
    assert!(node.get_connection(&link_id).is_none());
}

#[tokio::test]
async fn inbound_path_replacement_drops_superseded_bootstrap_transport() {
    use crate::config::WebSocketConfig;
    use crate::node::wire::build_msg1;
    use crate::transport::websocket::WebSocketTransport;

    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let bootstrap_transport_id = TransportId::new(1);
    let mut bootstrap = WebSocketTransport::new(
        bootstrap_transport_id,
        None,
        WebSocketConfig::default(),
        packet_tx.clone(),
        &node.identity,
    );
    bootstrap.start_async().await.unwrap();
    node.transports.insert(
        bootstrap_transport_id,
        TransportHandle::WebSocket(Box::new(bootstrap)),
    );

    let direct_transport_id = TransportId::new(2);
    let mut udp = UdpTransport::new(
        direct_transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(direct_transport_id, TransportHandle::Udp(udp));

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let bootstrap_addr = TransportAddr::from_string("wss://seed.example/fips");
    let old_link_id = LinkId::new(10);
    let old_our_index = SessionIndex::new(11);
    let old_their_index = SessionIndex::new(12);
    let old_session =
        make_test_fmp_session(&node.identity, &peer_full, node.startup_epoch, [0x11; 8]);
    let old_peer = ActivePeer::with_session(
        peer_identity,
        old_link_id,
        1_000,
        ActivePeerSession {
            session: old_session,
            our_index: old_our_index,
            their_index: old_their_index,
            transport_id: bootstrap_transport_id,
            current_addr: bootstrap_addr.clone(),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: false,
            remote_epoch: Some([0x11; 8]),
        },
    );
    node.peers.insert(peer_node_addr, old_peer);
    node.peers.insert_session_index(
        (bootstrap_transport_id, old_our_index.as_u32()),
        peer_node_addr,
    );
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            bootstrap_transport_id,
            bootstrap_addr,
            LinkDirection::Inbound,
            Duration::from_millis(100),
        ),
    );
    node.bootstrap_transports
        .register(bootstrap_transport_id, peer_identity.npub().to_string());

    let direct_addr = TransportAddr::from_string("127.0.0.1:9000");
    let sender_index = SessionIndex::new(78);
    let mut remote_handshake = crate::noise::HandshakeState::new_initiator(
        peer_full.keypair(),
        node.identity.pubkey_full(),
    );
    remote_handshake.set_local_epoch([0x11; 8]);
    let wire_msg1 = build_msg1(sender_index, &remote_handshake.write_message_1().unwrap());

    node.handle_msg1(ReceivedPacket::with_timestamp(
        direct_transport_id,
        direct_addr.clone(),
        crate::transport::PacketBuffer::new(wire_msg1),
        2_100,
    ))
    .await;

    let retained = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(retained.link_id(), old_link_id);
    assert_eq!(retained.transport_id(), Some(bootstrap_transport_id));
    assert!(node.transports.contains_key(&bootstrap_transport_id));
    assert!(node.bootstrap_transports.contains(&bootstrap_transport_id));
    confirm_inbound_candidate_for_test(
        &mut node,
        direct_transport_id,
        &direct_addr,
        remote_handshake,
    )
    .await;

    let active = node
        .get_peer(&peer_node_addr)
        .expect("authenticated direct path should remain active");
    assert_eq!(active.transport_id(), Some(direct_transport_id));
    assert_eq!(active.current_addr(), Some(&direct_addr));
    assert!(node.get_link(&old_link_id).is_none());
    assert!(
        !node.transports.contains_key(&bootstrap_transport_id),
        "the confirmed replacement must drop the superseded adopted carrier"
    );
    assert!(
        !node.bootstrap_transports.contains(&bootstrap_transport_id),
        "bootstrap bookkeeping must converge with the live transport registry"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn equal_priority_outbound_alternate_path_does_not_replace_healthy_peer() {
    let mut node = make_node();
    let peer_full = loop {
        let candidate = Identity::generate();
        if candidate.node_addr() < node.node_addr() {
            break candidate;
        }
    };
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    assert!(
        !crate::peer::cross_connection_winner(node.node_addr(), &peer_node_addr, true),
        "fixture should make our outbound lose the normal cross-connection tie-breaker"
    );

    let old_transport_id = TransportId::new(1);
    let old_link_id = LinkId::new(10);
    let old_addr = TransportAddr::from_string("127.0.0.1:8000");
    let old_our_index = SessionIndex::new(11);
    let old_their_index = SessionIndex::new(12);
    let old_session =
        make_test_fmp_session(&node.identity, &peer_full, node.startup_epoch, [0x11; 8]);
    let old_peer = ActivePeer::with_session(
        peer_identity,
        old_link_id,
        1_000,
        ActivePeerSession {
            session: old_session,
            our_index: old_our_index,
            their_index: old_their_index,
            transport_id: old_transport_id,
            current_addr: old_addr.clone(),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: Some([0x11; 8]),
        },
    );
    assert!(old_peer.can_send());
    node.peers.insert(peer_node_addr, old_peer);
    node.peers
        .insert_session_index((old_transport_id, old_our_index.as_u32()), peer_node_addr);

    let new_transport_id = TransportId::new(2);
    let new_link_id = LinkId::new(11);
    let new_addr = TransportAddr::from_string("127.0.0.1:9000");
    let mut new_conn = PeerConnection::outbound(new_link_id, peer_identity, 2_000);
    let msg1 = new_conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 2_000)
        .unwrap();
    let mut responder = PeerConnection::inbound(LinkId::new(99), 2_000);
    let msg2 = responder
        .receive_handshake_init(peer_full.keypair(), [0x11; 8], &msg1, 2_000)
        .unwrap();
    new_conn.complete_handshake(&msg2, 2_100).unwrap();
    let new_our_index = node.index_allocator.allocate().unwrap();
    let new_their_index = SessionIndex::new(77);
    new_conn.set_our_index(new_our_index);
    new_conn.set_their_index(new_their_index);
    new_conn.set_transport_id(new_transport_id);
    new_conn.set_source_addr(new_addr.clone());
    node.peers.insert_connection(new_link_id, new_conn);

    let result = node
        .promote_connection(new_link_id, peer_identity, 2_100)
        .unwrap();

    assert!(
        matches!(result, PromotionResult::CrossConnectionLost { .. }),
        "a same-priority alternate path should not churn a healthy active endpoint"
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&old_addr));
    assert!(active.can_send());
}

#[tokio::test]
async fn handle_msg2_keeps_healthy_peer_over_equal_priority_outbound_alternate_path() {
    let mut node = make_node();
    let peer_full = loop {
        let candidate = Identity::generate();
        if candidate.node_addr() < node.node_addr() {
            break candidate;
        }
    };
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    assert!(
        !crate::peer::cross_connection_winner(node.node_addr(), &peer_node_addr, true),
        "fixture should make our outbound lose the normal cross-connection tie-breaker"
    );

    let old_transport_id = TransportId::new(1);
    let old_link_id = LinkId::new(10);
    let old_addr = TransportAddr::from_string("127.0.0.1:8000");
    let old_our_index = SessionIndex::new(11);
    let old_their_index = SessionIndex::new(12);
    let old_session =
        make_test_fmp_session(&node.identity, &peer_full, node.startup_epoch, [0x11; 8]);
    let old_peer = ActivePeer::with_session(
        peer_identity,
        old_link_id,
        1_000,
        ActivePeerSession {
            session: old_session,
            our_index: old_our_index,
            their_index: old_their_index,
            transport_id: old_transport_id,
            current_addr: old_addr.clone(),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: Some([0x11; 8]),
        },
    );
    assert!(old_peer.can_send());
    node.peers.insert(peer_node_addr, old_peer);
    node.peers
        .insert_session_index((old_transport_id, old_our_index.as_u32()), peer_node_addr);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            old_transport_id,
            old_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((old_transport_id, old_addr.clone()), old_link_id);

    let new_transport_id = TransportId::new(2);
    let new_link_id = LinkId::new(11);
    let new_addr = TransportAddr::from_string("127.0.0.1:9000");
    let mut new_conn = PeerConnection::outbound(new_link_id, peer_identity, 2_000);
    let msg1 = new_conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 2_000)
        .unwrap();
    let our_index = node.index_allocator.allocate().unwrap();
    new_conn.set_our_index(our_index);
    new_conn.set_transport_id(new_transport_id);
    new_conn.set_source_addr(new_addr.clone());
    node.links.insert(
        new_link_id,
        Link::connectionless(
            new_link_id,
            new_transport_id,
            new_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((new_transport_id, new_addr.clone()), new_link_id);
    node.peers.insert_connection(new_link_id, new_conn);
    node.pending_outbound
        .insert((new_transport_id, our_index.as_u32()), new_link_id);

    let mut responder = PeerConnection::inbound(LinkId::new(99), 2_000);
    let noise_msg2 = responder
        .receive_handshake_init(peer_full.keypair(), [0x11; 8], &msg1, 2_000)
        .unwrap();
    let their_index = SessionIndex::new(77);
    let wire_msg2 = build_msg2(their_index, our_index, &noise_msg2);
    let packet = ReceivedPacket::with_timestamp(
        new_transport_id,
        new_addr.clone(),
        crate::transport::PacketBuffer::new(wire_msg2),
        2_100,
    );

    node.handle_msg2(packet).await;

    assert_eq!(node.connection_count(), 0);
    assert!(node.pending_outbound.is_empty());
    assert!(
        node.links.contains_key(&old_link_id),
        "healthy active link should remain active"
    );
    assert!(
        !node.links.contains_key(&new_link_id),
        "same-priority alternate link should be discarded"
    );
    assert_eq!(
        node.links
            .get_addr(&(old_transport_id, old_addr.clone()))
            .copied(),
        Some(old_link_id)
    );
    assert_eq!(
        node.links.get_addr(&(new_transport_id, new_addr.clone())),
        None
    );

    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.transport_id(), Some(old_transport_id));
    assert_eq!(active.current_addr(), Some(&old_addr));
    assert_eq!(active.our_index(), Some(old_our_index));
    assert_eq!(active.their_index(), Some(old_their_index));
    assert_eq!(
        node.peers
            .get_session_index(&(old_transport_id, old_our_index.as_u32()))
            .copied(),
        Some(peer_node_addr)
    );
}

#[tokio::test]
async fn handle_msg2_keeps_recently_authenticated_path_over_late_preferred_alternate() {
    run_recently_authenticated_alternate(false).await;
}

#[tokio::test]
async fn handle_msg2_upgrades_authenticated_websocket_to_preferred_direct_path() {
    run_recently_authenticated_alternate(true).await;
}

async fn run_recently_authenticated_alternate(websocket_bootstrap: bool) {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();

    let old_transport_id = if websocket_bootstrap {
        let id = TransportId::new(2);
        let bootstrap = crate::transport::websocket::WebSocketTransport::new(
            id,
            None,
            crate::config::WebSocketConfig::default(),
            node.packet_tx.clone().unwrap(),
            &node.identity,
        );
        node.transports
            .insert(id, TransportHandle::WebSocket(Box::new(bootstrap)));
        id
    } else {
        transport_id
    };
    let static_addr = TransportAddr::from_string(if websocket_bootstrap {
        "wss://seed.example/fips"
    } else {
        "127.0.0.1:8000"
    });
    let lower_priority_addr = TransportAddr::from_string("127.0.0.1:9000");
    node.config.peers = vec![crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority(
                if websocket_bootstrap {
                    "websocket"
                } else {
                    "udp"
                },
                static_addr.to_string(),
                100,
            ),
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:9000", 10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    }];
    refresh_configured_peer_cache_for_test(&mut node);

    let old_link_id = LinkId::new(10);
    let old_our_index = SessionIndex::new(11);
    let old_their_index = SessionIndex::new(12);
    let old_session =
        make_test_fmp_session(&node.identity, &peer_full, node.startup_epoch, [0x11; 8]);
    let mut old_peer = ActivePeer::with_session(
        peer_identity,
        old_link_id,
        1_000,
        ActivePeerSession {
            session: old_session,
            our_index: old_our_index,
            their_index: old_their_index,
            transport_id: old_transport_id,
            current_addr: static_addr.clone(),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: Some([0x11; 8]),
        },
    );
    assert!(old_peer.can_send());
    old_peer.touch(Node::now_ms());
    node.peers.insert(peer_node_addr, old_peer);
    node.peers
        .insert_session_index((old_transport_id, old_our_index.as_u32()), peer_node_addr);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            old_transport_id,
            static_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((old_transport_id, static_addr.clone()), old_link_id);
    seed_dataplane_fsp_data_rx_for_test(&mut node, peer_node_addr, peer_node_addr, Node::now_ms());
    assert!(node.active_peer_has_fresh_carrier_liveness(&peer_node_addr));

    let new_link_id = LinkId::new(11);
    let mut new_conn = PeerConnection::outbound(new_link_id, peer_identity, 2_000);
    let msg1 = new_conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 2_000)
        .unwrap();
    let our_index = node.index_allocator.allocate().unwrap();
    new_conn.set_our_index(our_index);
    new_conn.set_transport_id(transport_id);
    new_conn.set_source_addr(lower_priority_addr.clone());
    node.links.insert(
        new_link_id,
        Link::connectionless(
            new_link_id,
            transport_id,
            lower_priority_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((transport_id, lower_priority_addr.clone()), new_link_id);
    node.peers.insert_connection(new_link_id, new_conn);
    node.pending_outbound
        .insert((transport_id, our_index.as_u32()), new_link_id);

    let mut responder = PeerConnection::inbound(LinkId::new(99), 2_000);
    let noise_msg2 = responder
        .receive_handshake_init(peer_full.keypair(), [0x11; 8], &msg1, 2_000)
        .unwrap();
    let their_index = SessionIndex::new(77);
    let wire_msg2 = build_msg2(their_index, our_index, &noise_msg2);
    let packet = ReceivedPacket::with_timestamp(
        transport_id,
        lower_priority_addr.clone(),
        crate::transport::PacketBuffer::new(wire_msg2),
        2_100,
    );

    node.handle_msg2(packet).await;

    assert_eq!(node.connection_count(), 0);
    assert!(node.pending_outbound.is_empty());
    if websocket_bootstrap {
        let active = node.get_peer(&peer_node_addr).unwrap();
        assert_eq!(active.transport_id(), Some(transport_id));
        assert_eq!(active.link_id(), new_link_id);
        assert_eq!(active.current_addr(), Some(&lower_priority_addr));
        for transport in node.transports.values_mut() {
            transport.stop().await.ok();
        }
        return;
    }
    assert!(
        node.links.contains_key(&old_link_id),
        "healthy preferred static link should remain active"
    );
    assert!(
        !node.links.contains_key(&new_link_id),
        "a late alternate handshake must not replace a carrier that just authenticated traffic"
    );
    assert_eq!(
        node.links
            .get_addr(&(transport_id, static_addr.clone()))
            .copied(),
        Some(old_link_id)
    );
    assert_eq!(
        node.links
            .get_addr(&(transport_id, lower_priority_addr.clone())),
        None
    );

    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&static_addr));
    assert_eq!(active.our_index(), Some(old_our_index));
    assert_eq!(active.their_index(), Some(old_their_index));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

include!("promotion_paths_alternate.rs");
