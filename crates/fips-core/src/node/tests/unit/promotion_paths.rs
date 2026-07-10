use super::*;

#[tokio::test]
async fn promotion_keeps_authenticated_observed_path_over_configured_static_hint() {
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

    let link_id = LinkId::new(11);
    let (mut connection, peer_identity) =
        make_completed_connection(&mut node, link_id, transport_id, 1_000);
    let peer_node_addr = *peer_identity.node_addr();
    let observed_addr = TransportAddr::from_string("127.0.0.1:5000");
    let configured_addr = TransportAddr::from_string("127.0.0.1:5001");
    connection.set_source_addr(observed_addr.clone());
    node.config.peers = vec![auto_connect_peer(
        peer_identity.npub().to_string(),
        configured_addr.as_str().unwrap(),
    )];
    node.peers.insert_connection(link_id, connection);

    node.promote_connection(link_id, peer_identity, 1_100)
        .unwrap();

    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(
        active.current_addr(),
        Some(&observed_addr),
        "static endpoints should order dialing, while the authenticated observed source owns the live path"
    );
    assert_ne!(active.current_addr(), Some(&configured_addr));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn handle_msg2_preserves_static_send_addr_when_alternate_path_is_discarded() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();

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
            transport_id,
            current_addr: old_addr.clone(),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: Some([0x11; 8]),
        },
    );
    assert!(old_peer.can_send());
    node.peers.insert(peer_node_addr, old_peer);
    node.peers
        .insert_session_index((transport_id, old_our_index.as_u32()), peer_node_addr);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            old_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((transport_id, old_addr.clone()), old_link_id);

    let link_id = LinkId::new(11);
    let configured_addr = TransportAddr::from_string("127.0.0.1:52528");
    let observed_reply_addr = TransportAddr::from_string("127.0.0.1:51830");
    node.config.peers = vec![auto_connect_peer(
        peer_identity.npub().to_string(),
        configured_addr.as_str().unwrap(),
    )];

    let mut conn = PeerConnection::outbound(link_id, peer_identity, 2_000);
    let msg1 = conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 2_000)
        .unwrap();
    let our_index = node.index_allocator.allocate().unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(configured_addr.clone());
    node.links.insert(
        link_id,
        Link::connectionless(
            link_id,
            transport_id,
            configured_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((transport_id, configured_addr.clone()), link_id);
    node.peers.insert_connection(link_id, conn);
    node.pending_outbound
        .insert((transport_id, our_index.as_u32()), link_id);

    let mut responder = PeerConnection::inbound(LinkId::new(99), 2_000);
    let noise_msg2 = responder
        .receive_handshake_init(peer_full.keypair(), [0x11; 8], &msg1, 2_000)
        .unwrap();
    let their_index = SessionIndex::new(77);
    let wire_msg2 = build_msg2(their_index, our_index, &noise_msg2);
    let packet = ReceivedPacket::with_timestamp(
        transport_id,
        observed_reply_addr.clone(),
        crate::transport::PacketBuffer::new(wire_msg2),
        2_100,
    );

    node.handle_msg2(packet).await;

    assert_eq!(node.connection_count(), 0);
    assert!(node.pending_outbound.is_empty());
    assert!(
        node.links.contains_key(&old_link_id),
        "the existing healthy peer should remain active"
    );
    assert!(
        !node.links.contains_key(&link_id),
        "the completed alternate handshake should be discarded"
    );

    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.transport_id(), Some(transport_id));
    assert_eq!(
        active.current_addr(),
        Some(&old_addr),
        "receive/auth routing should stay on the established observed peer path"
    );
    assert_eq!(
        active.preferred_send_addr(),
        Some(&configured_addr),
        "the authenticated static dial target must survive even when its session is not promoted"
    );
    assert_eq!(active.send_addr(), Some(&configured_addr));
    assert_eq!(active.our_index(), Some(old_our_index));
    assert_eq!(active.their_index(), Some(old_their_index));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn fresh_handshake_replaces_reconnecting_peer_even_if_tie_breaker_would_lose() {
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
    let mut old_peer = ActivePeer::with_session(
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
    old_peer.mark_reconnecting();
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
    new_conn.set_source_addr(new_addr);
    node.peers.insert_connection(new_link_id, new_conn);

    let result = node
        .promote_connection(new_link_id, peer_identity, 2_100)
        .unwrap();

    assert!(
        matches!(result, PromotionResult::CrossConnectionWon { .. }),
        "fresh authenticated path should replace reconnecting peer"
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), new_link_id);
    assert!(active.can_send());
    assert_eq!(active.remote_epoch(), Some([0x11; 8]));
}

#[tokio::test]
async fn same_tuple_late_inbound_refresh_uses_cross_connection_tie_breaker() {
    let mut node = make_node();
    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    assert!(
        !crate::peer::cross_connection_winner(node.node_addr(), &peer_node_addr, false),
        "fixture should make our same-tuple inbound lose the normal cross-connection tie-breaker"
    );

    let transport_id = TransportId::new(1);
    let addr = TransportAddr::from_string("127.0.0.1:8000");
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
            transport_id,
            current_addr: addr.clone(),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: Some([0x11; 8]),
        },
    );
    assert!(old_peer.can_send());
    node.peers.insert(peer_node_addr, old_peer);
    node.peers
        .insert_session_index((transport_id, old_our_index.as_u32()), peer_node_addr);

    let new_link_id = LinkId::new(11);
    let mut inbound = PeerConnection::inbound(new_link_id, 2_000);
    let mut remote_outbound = PeerConnection::outbound(
        LinkId::new(99),
        PeerIdentity::from_pubkey_full(node.identity.pubkey_full()),
        2_000,
    );
    let msg1 = remote_outbound
        .start_handshake(peer_full.keypair(), [0x11; 8], 2_000)
        .unwrap();
    inbound
        .receive_handshake_init(node.identity.keypair(), node.startup_epoch, &msg1, 2_000)
        .unwrap();
    let new_our_index = SessionIndex::new(77);
    let new_their_index = SessionIndex::new(78);
    inbound.set_our_index(new_our_index);
    inbound.set_their_index(new_their_index);
    inbound.set_transport_id(transport_id);
    inbound.set_source_addr(addr.clone());
    node.peers.insert_connection(new_link_id, inbound);

    let result = node
        .promote_connection(new_link_id, peer_identity, 2_100)
        .unwrap();

    assert!(
        matches!(result, PromotionResult::CrossConnectionLost { .. }),
        "same-path inbound refresh should not bypass cross-connection tie-breaker"
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.our_index(), Some(old_our_index));
    assert_eq!(active.their_index(), Some(old_their_index));
    assert_eq!(active.current_addr(), Some(&addr));
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
async fn handle_msg2_does_not_demote_healthy_static_path_to_lower_priority_alternate() {
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

    let static_addr = TransportAddr::from_string("127.0.0.1:8000");
    let lower_priority_addr = TransportAddr::from_string("127.0.0.1:9000");
    node.config.peers = vec![crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:8000", 10),
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:9000", 100),
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
    let old_peer = ActivePeer::with_session(
        peer_identity,
        old_link_id,
        1_000,
        ActivePeerSession {
            session: old_session,
            our_index: old_our_index,
            their_index: old_their_index,
            transport_id,
            current_addr: static_addr.clone(),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: Some([0x11; 8]),
        },
    );
    assert!(old_peer.can_send());
    node.peers.insert(peer_node_addr, old_peer);
    node.peers
        .insert_session_index((transport_id, old_our_index.as_u32()), peer_node_addr);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            static_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((transport_id, static_addr.clone()), old_link_id);

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
    assert!(
        node.links.contains_key(&old_link_id),
        "healthy preferred static link should remain active"
    );
    assert!(
        !node.links.contains_key(&new_link_id),
        "lower-priority alternate link should be discarded"
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

#[tokio::test]
async fn handle_msg2_replaces_quiet_static_path_with_authenticated_alternate() {
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

    let static_addr = TransportAddr::from_string("127.0.0.1:8000");
    let lower_priority_addr = TransportAddr::from_string("127.0.0.1:9000");
    node.config.peers = vec![crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:8000", 10),
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:9000", 100),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    }];
    node.configured_peer_send_weights =
        crate::node::ConfiguredPeerSendWeights::from_config(&node.config);

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
            transport_id,
            current_addr: static_addr.clone(),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: Some([0x11; 8]),
        },
    );
    assert!(old_peer.can_send());
    node.peers.insert(peer_node_addr, old_peer);
    node.peers
        .insert_session_index((transport_id, old_our_index.as_u32()), peer_node_addr);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            static_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((transport_id, static_addr.clone()), old_link_id);

    let trust_timeout_ms = node.session_direct_path_exclusive_trust_timeout_ms();
    let now_ms = trust_timeout_ms + 10_000;
    let endpoint_entry = crate::node::session::SessionEntry::new(
        peer_node_addr,
        peer_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(make_test_fmp_session(
            &node.identity,
            &peer_full,
            [0x21; 8],
            [0x22; 8],
        )),
        now_ms - trust_timeout_ms - 1,
        true,
    );
    node.sessions.insert(peer_node_addr, endpoint_entry);
    seed_dataplane_fsp_data_sent_for_test(&mut node, peer_node_addr, peer_node_addr, now_ms);
    assert!(
        node.session_direct_path_exclusive_trust_expired(&peer_node_addr, now_ms),
        "active endpoint traffic without authenticated return should expire exclusive direct trust"
    );

    let new_link_id = LinkId::new(11);
    let mut new_conn = PeerConnection::outbound(new_link_id, peer_identity, now_ms - 100);
    let msg1 = new_conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, now_ms - 100)
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

    let mut responder = PeerConnection::inbound(LinkId::new(99), now_ms - 100);
    let noise_msg2 = responder
        .receive_handshake_init(peer_full.keypair(), [0x11; 8], &msg1, now_ms - 100)
        .unwrap();
    let their_index = SessionIndex::new(77);
    let wire_msg2 = build_msg2(their_index, our_index, &noise_msg2);
    let packet = ReceivedPacket::with_timestamp(
        transport_id,
        lower_priority_addr.clone(),
        crate::transport::PacketBuffer::new(wire_msg2),
        now_ms,
    );

    node.handle_msg2(packet).await;

    assert_eq!(node.connection_count(), 0);
    assert!(node.pending_outbound.is_empty());
    assert!(
        !node.links.contains_key(&old_link_id),
        "quiet static path should be retired after an authenticated alternate succeeds"
    );
    assert!(
        node.links.contains_key(&new_link_id),
        "authenticated alternate should remain active"
    );

    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), new_link_id);
    assert_eq!(active.current_addr(), Some(&lower_priority_addr));
    assert_eq!(active.our_index(), Some(our_index));
    assert_eq!(active.their_index(), Some(their_index));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn authenticated_packet_rotates_configured_static_path_to_observed_source() {
    let local_identity = Identity::generate();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let static_addr = TransportAddr::from_string("127.0.0.1:8000");
    let public_addr = TransportAddr::from_string("203.0.113.9:9000");

    let mut config = Config::new();
    config.peers = vec![crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:8000", 10),
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:9000", 200),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    }];
    let session = make_test_fmp_session(&local_identity, &peer_full, [1; 8], [2; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);
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
    let active = ActivePeer::with_session(
        peer_identity,
        LinkId::new(10),
        1_000,
        ActivePeerSession {
            session,
            our_index: crate::utils::index::SessionIndex::new(11),
            their_index: crate::utils::index::SessionIndex::new(12),
            transport_id,
            current_addr: static_addr.clone(),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: Some([2; 8]),
        },
    );
    assert!(active.can_send());
    node.peers.insert(peer_node_addr, active);
    let public_fmp_receive = |packet_timestamp_ms, fmp_counter| AuthenticatedFmpReceiveFacts {
        source_peer: peer_identity,
        transport_id,
        remote_addr: &public_addr,
        packet_timestamp_ms,
        packet_len: 64,
        fmp_counter,
        inner_timestamp_ms: 0,
        fmp_flags: 0,
    };

    node.record_authenticated_fmp_receive_facts(
        public_fmp_receive(2_000, 1),
        Some(&peer_node_addr),
    );

    let active = node.get_peer(&peer_node_addr).expect("peer");
    assert_eq!(
        active.current_addr(),
        Some(&static_addr),
        "a healthy configured static path should not be overwritten by a lower-priority observed source tuple"
    );
    assert_eq!(
        active.idle_time(2_500),
        500,
        "suppressed alternate-path rotation should still refresh authenticated same-peer liveness"
    );

    node.mark_session_direct_path_degraded(peer_node_addr, 3_000);
    node.record_authenticated_fmp_receive_facts(
        public_fmp_receive(3_100, 2),
        Some(&peer_node_addr),
    );

    let active = node.get_peer(&peer_node_addr).expect("peer");
    assert_eq!(
        active.current_addr(),
        Some(&public_addr),
        "degraded sessions should keep accepting authenticated traffic from the observed path"
    );
    assert_eq!(active.idle_time(3_100), 0);

    node.config.peers[0].addresses[0].seen_at_ms = Some(2_000);
    node.record_authenticated_fmp_receive_facts(
        public_fmp_receive(3_200, 3),
        Some(&peer_node_addr),
    );

    let active = node.get_peer(&peer_node_addr).expect("peer");
    assert_eq!(
        active.current_addr(),
        Some(&public_addr),
        "degraded discovered paths should still be allowed to roam to an authenticated alternate"
    );
    assert_eq!(active.idle_time(3_200), 0);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn handle_msg2_matches_pending_outbound_by_index_when_reply_transport_id_changes() {
    let mut node = make_node();
    let peer_full = loop {
        let candidate = Identity::generate();
        if candidate.node_addr() < node.node_addr() {
            break candidate;
        }
    };
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();

    let old_transport_id = TransportId::new(1);
    let old_link_id = LinkId::new(10);
    let old_addr = TransportAddr::from_string("203.0.113.24:51820");
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

    let dial_transport_id = TransportId::new(2);
    let recv_transport_id = TransportId::new(3);
    let new_link_id = LinkId::new(11);
    let gateway_addr = TransportAddr::from_string("198.51.100.91:51830");
    let mut new_conn = PeerConnection::outbound(new_link_id, peer_identity, 2_000);
    let msg1 = new_conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 2_000)
        .unwrap();
    let our_index = node.index_allocator.allocate().unwrap();
    new_conn.set_our_index(our_index);
    new_conn.set_transport_id(dial_transport_id);
    new_conn.set_source_addr(gateway_addr.clone());
    node.links.insert(
        new_link_id,
        Link::connectionless(
            new_link_id,
            dial_transport_id,
            gateway_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((dial_transport_id, gateway_addr.clone()), new_link_id);
    node.peers.insert_connection(new_link_id, new_conn);
    node.pending_outbound
        .insert((dial_transport_id, our_index.as_u32()), new_link_id);

    let mut responder = PeerConnection::inbound(LinkId::new(99), 2_000);
    let noise_msg2 = responder
        .receive_handshake_init(peer_full.keypair(), [0x11; 8], &msg1, 2_000)
        .unwrap();
    let their_index = SessionIndex::new(77);
    let wire_msg2 = build_msg2(their_index, our_index, &noise_msg2);
    let packet = ReceivedPacket::with_timestamp(
        recv_transport_id,
        gateway_addr.clone(),
        crate::transport::PacketBuffer::new(wire_msg2),
        2_100,
    );

    node.handle_msg2(packet).await;

    assert_eq!(node.connection_count(), 0);
    assert!(node.pending_outbound.is_empty());
    assert!(
        !node.links.contains_key(&old_link_id),
        "old public path should be retired after gateway reply completes"
    );

    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), new_link_id);
    assert_eq!(active.transport_id(), Some(dial_transport_id));
    assert_eq!(active.current_addr(), Some(&gateway_addr));
    assert_eq!(active.our_index(), Some(our_index));
    assert_eq!(active.their_index(), Some(their_index));
}

#[tokio::test]
async fn handle_msg2_uses_authenticated_reply_source_when_static_destination_differs() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();

    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(11);
    let configured_addr = TransportAddr::from_string("127.0.0.1:52528");
    let observed_reply_addr = TransportAddr::from_string("127.0.0.1:51830");
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
    node.config.peers = vec![auto_connect_peer(
        peer_identity.npub().to_string(),
        configured_addr.as_str().unwrap(),
    )];

    let mut conn = PeerConnection::outbound(link_id, peer_identity, 2_000);
    let msg1 = conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 2_000)
        .unwrap();
    let our_index = node.index_allocator.allocate().unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(configured_addr.clone());
    node.links.insert(
        link_id,
        Link::connectionless(
            link_id,
            transport_id,
            configured_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.peers.insert_connection(link_id, conn);
    node.pending_outbound
        .insert((transport_id, our_index.as_u32()), link_id);

    let mut responder = PeerConnection::inbound(LinkId::new(99), 2_000);
    let noise_msg2 = responder
        .receive_handshake_init(peer_full.keypair(), [0x11; 8], &msg1, 2_000)
        .unwrap();
    let their_index = SessionIndex::new(77);
    let wire_msg2 = build_msg2(their_index, our_index, &noise_msg2);
    let packet = ReceivedPacket::with_timestamp(
        transport_id,
        observed_reply_addr.clone(),
        crate::transport::PacketBuffer::new(wire_msg2),
        2_100,
    );

    node.handle_msg2(packet).await;

    assert_eq!(node.connection_count(), 0);
    assert!(node.pending_outbound.is_empty());

    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), link_id);
    assert_eq!(active.transport_id(), Some(transport_id));
    assert_eq!(
        active.current_addr(),
        Some(&observed_reply_addr),
        "the authenticated msg2 source remains the live receive path even when the dial target came from static config"
    );
    assert_ne!(active.current_addr(), Some(&configured_addr));
    assert_eq!(
        active.preferred_send_addr(),
        Some(&configured_addr),
        "the completed static dial remains the preferred outbound send path"
    );
    assert_eq!(active.send_addr(), Some(&configured_addr));
    assert_eq!(active.our_index(), Some(our_index));
    assert_eq!(active.their_index(), Some(their_index));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}
