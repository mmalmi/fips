#[tokio::test]
async fn fallback_becoming_live_after_network_rebind_replaces_unusable_direct_payload() {
    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    let mut node = Node::new(config).unwrap();
    let rebound_transport_id = TransportId::new(1);
    node.transports.insert(
        rebound_transport_id,
        make_udp_transport_with_mtu(1, 1280).await,
    );

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let direct_peer = make_active_test_peer(
        &node,
        &remote,
        rebound_transport_id,
        LinkId::new(1),
        TransportAddr::from_string("127.0.0.1:9"),
        SessionIndex::new(1),
        SessionIndex::new(2),
    );
    node.peers.insert(remote_addr, direct_peer);
    assert!(node.sync_dataplane_fmp_owner(&remote_addr));

    let fallback = Identity::generate();
    let fallback_addr = *fallback.node_addr();
    let fallback_peer = make_active_test_peer(
        &node,
        &fallback,
        TransportId::new(2),
        LinkId::new(2),
        TransportAddr::from_string("127.0.0.1:10"),
        SessionIndex::new(3),
        SessionIndex::new(4),
    );
    node.peers.insert(fallback_addr, fallback_peer);
    node.learn_reverse_route(remote_addr, fallback_addr);

    let mut session = SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        crate::node::session::EndToEndState::Established(make_test_fmp_session(
            node.identity(),
            &remote,
            [0x41; 8],
            [0x42; 8],
        )),
        1_000,
        true,
    );
    session.mark_established(1_000);
    node.sessions.insert(remote_addr, session);
    assert!(node.sync_dataplane_fsp_owner_from_current_session(&remote_addr, 0));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(remote_addr)
    );
    node.peers
        .get_mut(&remote_addr)
        .expect("direct peer exists")
        .mark_stale();

    assert_eq!(node.apply_prepared_network_rebind(None).await.unwrap(), 1);
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        None,
        "payload must not retain the withdrawn direct owner while no replacement carrier is usable"
    );

    assert!(node.sync_dataplane_fmp_owner(&fallback_addr));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(fallback_addr),
        "a fallback that recovers just after the carrier rebind must immediately take over the established payload"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn network_transport_rebind_discards_inflight_udp_handshakes() {
    let mut node = make_node();
    node.config.node.rate_limit.handshake_max_resends = 1;
    let transport_id = TransportId::new(1);
    node.transports
        .insert(transport_id, make_udp_transport_with_mtu(1, 1280).await);

    let remote = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(remote.pubkey_full());
    let remote_addr = TransportAddr::from_string("127.0.0.1:9");
    node.config.peers = vec![auto_connect_peer(
        remote.npub(),
        remote_addr.as_str().unwrap(),
    )];
    node.configured_peers = crate::node::ConfiguredPeerLookup::from_config(&node.config);
    node.initiate_connection(transport_id, remote_addr, peer_identity)
        .await
        .unwrap();

    let link_id = node
        .peers
        .connection_keys()
        .next()
        .copied()
        .expect("in-flight UDP handshake link");
    let connection = node
        .peers
        .get_connection_mut(&link_id)
        .expect("in-flight UDP handshake");
    connection.record_resend(u64::MAX);
    assert_eq!(connection.resend_count(), 1);
    assert_eq!(connection.next_resend_at_ms(), u64::MAX);

    assert_eq!(node.apply_prepared_network_rebind(None).await.unwrap(), 1);

    assert_eq!(
        node.connection_count(),
        0,
        "a handshake created on the old carrier must not survive the rebind and later promote a stale path"
    );
    assert!(
        node.retry_pending.contains_key(remote.node_addr()),
        "discarding the stale handshake must schedule a fresh bounded retry on the rebuilt carrier"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn network_transport_rebind_rejects_handshake_queued_by_old_carrier() {
    use crate::node::wire::build_msg1;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    node.transports
        .insert(transport_id, make_udp_transport_with_mtu(1, 1280).await);

    let remote = Identity::generate();
    let responder_identity = PeerIdentity::from_pubkey_full(node.identity.pubkey_full());
    let received_at_ms = Node::now_ms();
    let mut remote_connection =
        PeerConnection::outbound(LinkId::new(1), responder_identity, received_at_ms);
    let noise_msg1 = remote_connection
        .start_handshake(remote.keypair(), [0x11; 8], received_at_ms)
        .unwrap();
    let wire_msg1 = build_msg1(SessionIndex::new(7), &noise_msg1);

    assert_eq!(node.apply_prepared_network_rebind(None).await.unwrap(), 1);
    node.handle_msg1(ReceivedPacket::with_timestamp(
        transport_id,
        TransportAddr::from_string("127.0.0.1:5000"),
        crate::transport::PacketBuffer::new(wire_msg1),
        received_at_ms,
    ))
    .await;

    assert_eq!(
        node.peer_count() + node.connection_count(),
        0,
        "a handshake already queued by the old socket must not authenticate a stale path after carrier rebind"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn network_transport_rebind_ignores_queued_receive_without_discarding_live_session() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    node.transports
        .insert(transport_id, make_udp_transport_with_mtu(1, 1280).await);

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let transport_addr = TransportAddr::from_string("127.0.0.1:5000");
    let received_at_ms = Node::now_ms();
    let peer = make_active_test_peer(
        &node,
        &remote,
        transport_id,
        LinkId::new(1),
        transport_addr.clone(),
        SessionIndex::new(1),
        SessionIndex::new(2),
    );
    node.peers.insert(remote_addr, peer);
    assert!(node.sync_dataplane_fmp_owner(&remote_addr));

    assert_eq!(node.apply_prepared_network_rebind(None).await.unwrap(), 1);
    let last_seen_after_rebind = node.get_peer(&remote_addr).unwrap().last_seen();
    node.record_authenticated_fmp_receive_facts(
        AuthenticatedFmpReceiveFacts {
            source_peer: PeerIdentity::from_pubkey_full(remote.pubkey_full()),
            transport_id,
            remote_addr: &transport_addr,
            packet_timestamp_ms: received_at_ms,
            packet_len: 64,
            fmp_counter: 1,
            inner_timestamp_ms: 1,
            fmp_flags: 0,
        },
        None,
    );

    assert!(
        node.get_peer(&remote_addr).unwrap().is_healthy(),
        "the rebound socket must retain the authenticated peer session"
    );
    assert_eq!(
        node.get_peer(&remote_addr).unwrap().last_seen(),
        last_seen_after_rebind,
        "queued authenticated traffic from the old socket must not refresh path liveness"
    );
    assert!(
        node.dataplane_has_fmp_owner(&remote_addr),
        "the live session must keep its dataplane owner on the rebound socket"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn network_transport_rebind_schedules_fresh_handshake_for_active_udp_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    node.transports
        .insert(transport_id, make_udp_transport_with_mtu(1, 1280).await);

    let remote = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(remote.pubkey_full());
    let remote_addr = TransportAddr::from_string("127.0.0.1:9");
    let mut peer = ActivePeer::new(peer_identity, LinkId::new(1), 1_000);
    peer.set_current_addr(transport_id, &remote_addr);
    node.peers.insert(*remote.node_addr(), peer);
    node.config.peers = vec![auto_connect_peer(
        remote.npub(),
        remote_addr.as_str().unwrap(),
    )];
    refresh_configured_peer_cache_for_test(&mut node);

    assert_eq!(node.apply_prepared_network_rebind(None).await.unwrap(), 1);

    let retry = node
        .retry_pending
        .get(remote.node_addr())
        .expect("a carrier rebind must immediately queue a fresh authenticated path probe");
    assert!(retry.reconnect);
    assert_eq!(retry.retry_count, 0);
    assert!(
        retry.retry_after_ms <= Node::now_ms(),
        "the rebuilt carrier must not inherit link-dead jitter"
    );
    assert!(
        retry
            .peer_config
            .addresses
            .iter()
            .any(|candidate| candidate.transport == "udp"
                && candidate.addr == remote_addr.as_str().unwrap()),
        "the last authenticated UDP tuple must remain probeable on the rebound carrier"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn network_transport_rebind_preserves_pending_rekey_and_current_session() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    node.transports
        .insert(transport_id, make_udp_transport_with_mtu(1, 1280).await);

    let remote = Identity::generate();
    let remote_addr = TransportAddr::from_string("127.0.0.1:9");
    let mut peer = make_active_test_peer(
        &node,
        &remote,
        transport_id,
        LinkId::new(1),
        remote_addr.clone(),
        SessionIndex::new(10),
        SessionIndex::new(20),
    );
    peer.set_pending_session(
        make_test_fmp_session(&node.identity, &remote, [0x03; 8], [0x04; 8]),
        SessionIndex::new(11),
        SessionIndex::new(21),
        false,
    );
    node.peers.insert(*remote.node_addr(), peer);
    assert!(node.sync_dataplane_fmp_owner(remote.node_addr()));
    node.config.peers = vec![auto_connect_peer(
        remote.npub(),
        remote_addr.as_str().unwrap(),
    )];

    assert_eq!(node.apply_prepared_network_rebind(None).await.unwrap(), 1);
    let rebound_peer = node.get_peer(remote.node_addr()).unwrap();
    assert!(
        rebound_peer.pending_new_session().is_some(),
        "replacing only the local UDP socket must preserve a pending authenticated epoch that the remote peer may already have adopted"
    );
    assert!(
        rebound_peer.is_healthy() && rebound_peer.can_send(),
        "the current authenticated epoch must survive the local socket replacement"
    );
    assert!(node.dataplane_has_fmp_owner(remote.node_addr()));

    assert!(
        !rebound_peer.rekey_in_progress(),
        "the responder-side pending epoch must remain staged without becoming a local initiator rekey"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}
