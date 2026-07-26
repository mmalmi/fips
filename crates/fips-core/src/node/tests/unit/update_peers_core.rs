use super::*;

#[tokio::test]
async fn network_transport_rebind_preserves_peer_and_session_state() {
    use crate::noise::HandshakeState;

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

    let session_remote = Identity::generate();
    let session_addr = *session_remote.node_addr();
    let handshake =
        HandshakeState::new_initiator(node.identity.keypair(), session_remote.pubkey_full());
    node.sessions.insert(
        session_addr,
        SessionEntry::new(
            session_addr,
            session_remote.pubkey_full(),
            crate::node::session::EndToEndState::Initiating(handshake),
            1_000,
            true,
        ),
    );

    assert!(node.get_peer(remote.node_addr()).unwrap().is_healthy());
    assert_eq!(node.rebind_network_transports(None).await.unwrap(), 1);
    let preserved_peer = node.get_peer(remote.node_addr()).unwrap();
    assert!(
        !preserved_peer.is_healthy() && preserved_peer.can_send(),
        "a rebound carrier must preserve the peer but mark its old tuple stale so a freshly authenticated path can replace it"
    );
    assert!(node.sessions.get(&session_addr).is_some());

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn network_transport_rebind_preserves_session_but_uses_live_fallback_for_payload() {
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
    assert!(node.sync_dataplane_fmp_owner(&fallback_addr));
    node.learn_reverse_route(remote_addr, fallback_addr);

    let mut session = SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        crate::node::session::EndToEndState::Established(make_test_fmp_session(
            node.identity(),
            &remote,
            [0x31; 8],
            [0x32; 8],
        )),
        1_000,
        true,
    );
    session.mark_established(1_000);
    node.sessions.insert(remote_addr, session);
    assert!(node.sync_dataplane_fsp_owner_from_current_session(&remote_addr, 0));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(remote_addr),
        "fixture must start with established payload pinned to the direct carrier"
    );

    assert_eq!(node.rebind_network_transports(None).await.unwrap(), 1);

    assert!(
        node.dataplane_has_fmp_owner(&remote_addr),
        "an authenticated peer must install the rebound carrier's live socket without discarding its Noise session"
    );
    assert!(
        node.session_direct_path_degradation_active(&remote_addr, Node::now_ms()),
        "a network change invalidates the old NAT tuple until authenticated payload returns"
    );
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(fallback_addr),
        "established payload must immediately use the live mesh fallback instead of trusting the old direct tuple"
    );
    assert!(
        node.sessions.get(&remote_addr).is_some(),
        "carrier rebinding must preserve the end-to-end session"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn network_transport_rebind_discovers_fallback_when_transit_returns() {
    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    let remote = Identity::generate();
    config.peers = vec![auto_connect_peer(remote.npub(), "127.0.0.1:9")];
    let mut node = Node::new(config).unwrap();
    let rebound_transport_id = TransportId::new(1);
    node.transports.insert(
        rebound_transport_id,
        make_udp_transport_with_mtu(1, 1280).await,
    );

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

    let mut session = SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        crate::node::session::EndToEndState::Established(make_test_fmp_session(
            node.identity(),
            &remote,
            [0x51; 8],
            [0x52; 8],
        )),
        1_000,
        true,
    );
    session.mark_established(1_000);
    node.sessions.insert(remote_addr, session);
    assert!(node.sync_dataplane_fsp_owner_from_current_session(&remote_addr, 0));
    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(remote_addr),
        "fixture must begin on the direct path without a learned fallback route"
    );

    let fallback = Identity::generate();
    let fallback_addr = *fallback.node_addr();
    let mut stale_fallback_peer = make_active_test_peer(
        &node,
        &fallback,
        TransportId::new(2),
        LinkId::new(2),
        TransportAddr::from_string("127.0.0.1:10"),
        SessionIndex::new(3),
        SessionIndex::new(4),
    );
    stale_fallback_peer.mark_stale();
    node.peers.insert(fallback_addr, stale_fallback_peer);
    assert!(node.sync_dataplane_fmp_owner(&fallback_addr));
    node.pending_lookups.insert(
        remote_addr,
        crate::node::handlers::discovery::PendingLookup::new(900),
    );

    let baseline = node.stats().discovery.req_initiated;
    assert_eq!(node.rebind_network_transports(None).await.unwrap(), 1);
    assert!(
        node.retry_pending.contains_key(&remote_addr),
        "fresh direct candidates should still be reprobed after the underlay changes"
    );
    assert!(
        !node.pending_lookups.contains_key(&remote_addr),
        "recovery lookup must not be stranded on an unhealthy transit adjacency"
    );

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
    assert!(node.sync_dataplane_fmp_owner(&fallback_addr));
    node.process_pending_retries(Node::now_ms()).await;

    assert!(
        node.pending_lookups.contains_key(&remote_addr),
        "the returned transit neighbor must be asked for a replacement route before the direct retry is due"
    );
    assert_eq!(
        node.stats().discovery.req_initiated,
        baseline + 1,
        "a network rebind should start exactly one bounded recovery lookup"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

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

    assert_eq!(node.rebind_network_transports(None).await.unwrap(), 1);
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

    assert_eq!(node.rebind_network_transports(None).await.unwrap(), 1);

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

    assert_eq!(node.rebind_network_transports(None).await.unwrap(), 1);
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

    assert_eq!(node.rebind_network_transports(None).await.unwrap(), 1);
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

    let before_rebind_ms = Node::now_ms();
    assert_eq!(node.rebind_network_transports(None).await.unwrap(), 1);

    let retry = node
        .retry_pending
        .get(remote.node_addr())
        .expect("a carrier rebind must immediately queue a fresh authenticated path probe");
    assert!(retry.reconnect);
    assert_eq!(retry.retry_count, 0);
    assert!(
        retry.retry_after_ms <= before_rebind_ms + 1_500,
        "the active peer probe must use the bounded link-dead delay, not the generic liveness timeout"
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
async fn network_transport_rebind_discards_pending_rekey_but_keeps_current_session() {
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

    assert_eq!(node.rebind_network_transports(None).await.unwrap(), 1);
    let rebound_peer = node.get_peer(remote.node_addr()).unwrap();
    assert!(
        rebound_peer.pending_new_session().is_none(),
        "a carrier change must discard a pending key epoch tied to the old path"
    );
    assert!(
        rebound_peer.is_healthy() && rebound_peer.can_send(),
        "the current authenticated epoch must survive the local socket replacement"
    );
    assert!(node.dataplane_has_fmp_owner(remote.node_addr()));

    assert!(
        !rebound_peer.rekey_in_progress(),
        "discarding the pending epoch must not immediately rotate the preserved current epoch"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_preserves_input_priority_order() {
    let mut node = make_node();
    let first = Identity::generate();
    let second = Identity::generate();
    let third = Identity::generate();

    let first_original = auto_connect_peer(first.npub(), "127.0.0.1:9");
    let second_peer = auto_connect_peer(second.npub(), "127.0.0.1:10");
    let third_peer = auto_connect_peer(third.npub(), "127.0.0.1:11");
    let first_updated = auto_connect_peer(first.npub(), "127.0.0.1:12");

    let outcome = node
        .update_peers(vec![
            first_original,
            second_peer.clone(),
            third_peer.clone(),
            first_updated.clone(),
        ])
        .await
        .unwrap();

    assert_eq!(outcome.added, 3);
    assert_eq!(
        node.config
            .peers
            .iter()
            .map(|peer| peer.npub.as_str())
            .collect::<Vec<_>>(),
        vec![
            first_updated.npub.as_str(),
            second_peer.npub.as_str(),
            third_peer.npub.as_str(),
        ],
        "caller priority order should survive de-duplication"
    );
    assert_eq!(node.config.peers[0].addresses, first_updated.addresses);
}

#[tokio::test]
async fn update_peers_races_alternate_path_even_when_outbound_would_lose() {
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

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_loser(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let old_addr = TransportAddr::from_string("127.0.0.1:7");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &old_addr);
    node.peers.insert(peer_node_addr, active_peer);
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

    let peer = auto_connect_peer(peer_full.npub(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.unchanged, 1);
    assert_eq!(node.peer_count(), 1, "current active peer must remain live");
    assert_eq!(
        node.connection_count(),
        1,
        "alternate path should be attempted even when our outbound would lose cross-connection"
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&old_addr));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_returns_zero_on_empty_diff() {
    let mut node = make_node();

    let outcome = node.update_peers(Vec::new()).await.unwrap();
    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 0);
    assert_eq!(outcome.unchanged, 0);
}

#[tokio::test]
async fn update_peers_adds_new_peer_and_registers_alias() {
    let mut node = make_node();
    let npub = npub_for_test();
    let mut peer = auto_connect_peer(npub.clone(), "127.0.0.1:9");
    peer.alias = Some("alice".to_string());

    let outcome = node.update_peers(vec![peer.clone()]).await.unwrap();

    assert_eq!(outcome.added, 1);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 0);
    assert_eq!(outcome.unchanged, 0);
    assert_eq!(node.config.peers.len(), 1);
    let identity = PeerIdentity::from_npub(&peer.npub).unwrap();
    assert_eq!(
        node.peer_aliases.get(identity.node_addr()),
        Some(&"alice".to_string())
    );
    assert_eq!(
        node.configured_peer(identity.node_addr())
            .and_then(|cached| cached.alias.as_deref()),
        Some("alice"),
        "runtime configured-peer cache must refresh with update_peers"
    );
}

#[tokio::test]
async fn update_peers_removes_dropped_peer_and_clears_retry_state() {
    let mut node = make_node();
    let npub = npub_for_test();
    let peer = auto_connect_peer(npub.clone(), "127.0.0.1:9");

    let _ = node.update_peers(vec![peer.clone()]).await.unwrap();

    let identity = PeerIdentity::from_npub(&peer.npub).unwrap();
    let node_addr = *identity.node_addr();
    // Cold-add scheduled a retry because there's no transport.
    assert!(node.retry_pending.contains_key(&node_addr));

    let outcome = node.update_peers(Vec::new()).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 1);
    assert!(node.config.peers.is_empty());
    assert!(!node.retry_pending.contains_key(&node_addr));
    assert!(!node.peer_aliases.contains_key(&node_addr));
}

#[tokio::test]
async fn update_peers_reports_updated_when_addresses_change() {
    let mut node = make_node();
    let npub = npub_for_test();
    let original = auto_connect_peer(npub.clone(), "127.0.0.1:9");
    let _ = node.update_peers(vec![original]).await.unwrap();

    let new_version = auto_connect_peer(npub.clone(), "127.0.0.1:55180");
    let outcome = node.update_peers(vec![new_version.clone()]).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 1);
    assert_eq!(outcome.unchanged, 0);
    assert_eq!(node.config.peers.len(), 1);
    assert_eq!(node.config.peers[0].addresses[0].addr, "127.0.0.1:55180");
}

#[tokio::test]
async fn update_peers_reports_unchanged_for_identical_entry() {
    let mut node = make_node();
    let npub = npub_for_test();
    let peer = auto_connect_peer(npub, "127.0.0.1:9");
    let _ = node.update_peers(vec![peer.clone()]).await.unwrap();

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 0);
    assert_eq!(outcome.unchanged, 1);
}

#[tokio::test]
async fn update_peers_refreshes_stale_retry_config_even_when_peer_is_unchanged() {
    let mut node = make_node();
    let npub = npub_for_test();
    let peer = auto_connect_peer(npub, "127.0.0.1:9");
    let identity = PeerIdentity::from_npub(&peer.npub).unwrap();
    let node_addr = *identity.node_addr();
    node.config.peers = vec![peer.clone()];

    let mut stale_retry = super::super::retry::RetryState::new(auto_connect_peer(
        peer.npub.clone(),
        "203.0.113.99:51820",
    ));
    stale_retry.retry_after_ms = 123_456;
    stale_retry.reconnect = true;
    node.retry_pending.insert(node_addr, stale_retry);

    let outcome = node.update_peers(vec![peer.clone()]).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.updated, 0);
    assert_eq!(outcome.unchanged, 1);
    let retry = node.retry_pending.get(&node_addr).unwrap();
    assert_eq!(retry.peer_config.addresses, peer.addresses);
}

#[tokio::test]
async fn update_peers_redials_existing_auto_peer_with_direct_hint() {
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

    let npub = npub_for_test();
    let original = crate::config::PeerConfig {
        npub: npub.clone(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers = vec![original];

    let refreshed = auto_connect_peer(npub, "127.0.0.1:9");
    let outcome = node.update_peers(vec![refreshed]).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 1);
    assert_eq!(node.connection_count(), 1);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_redials_unchanged_auto_peer_without_link() {
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

    let peer = auto_connect_peer(npub_for_test(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 0);
    assert_eq!(outcome.unchanged, 1);
    assert_eq!(node.connection_count(), 1);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_races_alternate_path_for_active_peer_without_dropping_current_link() {
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

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let old_addr = TransportAddr::from_string("127.0.0.1:7");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &old_addr);
    node.peers.insert(peer_node_addr, active_peer);
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

    let peer = auto_connect_peer(peer_full.npub(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.unchanged, 1);
    assert_eq!(node.peer_count(), 1, "current active peer must remain live");
    assert_eq!(
        node.connection_count(),
        1,
        "alternate path should be a pending handshake, not a peer replacement"
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&old_addr));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_does_not_churn_active_peer_already_on_known_candidate() {
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

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);

    let peer = auto_connect_peer(peer_full.npub(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.unchanged, 1);
    assert_eq!(node.peer_count(), 1);
    assert_eq!(
        node.connection_count(),
        0,
        "known-good active concrete path should not be redialed every refresh"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn refresh_peer_paths_redials_active_peer_on_same_known_candidate() {
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

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let old_link_id = LinkId::new(7);
    let active_peer = make_active_test_peer(
        &node,
        &peer_full,
        transport_id,
        old_link_id,
        current_addr.clone(),
        SessionIndex::new(11),
        SessionIndex::new(12),
    );
    node.peers.insert(peer_node_addr, active_peer);
    assert!(node.sync_dataplane_fmp_owner(&peer_node_addr));

    let mut session = SessionEntry::new(
        peer_node_addr,
        peer_full.pubkey_full(),
        crate::node::session::EndToEndState::Established(make_test_fmp_session(
            node.identity(),
            &peer_full,
            [0x51; 8],
            [0x52; 8],
        )),
        1_000,
        true,
    );
    session.mark_established(1_000);
    node.sessions.insert(peer_node_addr, session);
    assert!(node.sync_dataplane_fsp_owner_from_current_session(&peer_node_addr, 0));

    let peer = auto_connect_peer(peer_full.npub(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];

    let refreshed = node.refresh_peer_paths(vec![peer.npub]).await.unwrap();

    assert_eq!(refreshed, 1);
    assert_eq!(node.peer_count(), 1, "current peer should stay live");
    assert_eq!(
        node.connection_count(),
        1,
        "forced refresh should race a same-path handshake for liveness recovery"
    );
    assert!(
        node.retry_pending.contains_key(&peer_node_addr),
        "forced refresh should keep quick direct re-probe state alive"
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&current_addr));
    let preserved_session = node
        .sessions
        .get(&peer_node_addr)
        .expect("refreshing a transport path must preserve the end-to-end session");
    assert!(
        !preserved_session.has_rekey_in_progress(),
        "refreshing a transport path must preserve the established end-to-end key epoch"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn refresh_peer_paths_continues_after_an_unreachable_peer() {
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

    let unreachable_full = Identity::generate();
    let mut unreachable = auto_connect_peer(unreachable_full.npub(), "127.0.0.1:8");
    unreachable.addresses.clear();

    let (reachable_full, reachable_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let reachable_node_addr = *reachable_identity.node_addr();
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(reachable_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(reachable_node_addr, active_peer);

    let reachable = auto_connect_peer(reachable_full.npub(), "127.0.0.1:9");
    node.config.peers = vec![unreachable.clone(), reachable.clone()];

    let refreshed = node
        .refresh_peer_paths(vec![unreachable.npub, reachable.npub])
        .await
        .unwrap();

    assert_eq!(refreshed, 1);
    assert_eq!(
        node.connection_count(),
        1,
        "an unreachable peer must not prevent later direct probes"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_marks_pruned_private_active_endpoint_stale() {
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

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let stale_private_addr = TransportAddr::from_string("192.168.50.57:51820");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &stale_private_addr);
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            stale_private_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );

    let original = auto_connect_peer(peer_full.npub(), "192.168.50.57:51820");
    node.config.peers = vec![original];
    let refreshed = auto_connect_peer(peer_full.npub(), "198.51.100.9:51820");

    let outcome = node.update_peers(vec![refreshed]).await.unwrap();

    assert_eq!(outcome.updated, 1);
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&stale_private_addr));
    assert!(
        active.can_send(),
        "stale direct path should preserve session continuity for probes/fallback"
    );
    assert!(
        !active.is_healthy(),
        "pruned private underlay endpoint must stop looking healthy immediately"
    );
    assert!(
        node.session_direct_path_blocks_direct_payload(&peer_node_addr, Node::now_ms()),
        "payload routing must not keep blackholing into the pruned private endpoint"
    );
    assert!(
        node.retry_pending.contains_key(&peer_node_addr),
        "existing quick direct re-probe path should be scheduled"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_keeps_public_active_endpoint_when_hint_changes() {
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

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let current_addr = TransportAddr::from_string("198.51.100.20:51820");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            current_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );

    let original = auto_connect_peer(peer_full.npub(), "198.51.100.20:51820");
    node.config.peers = vec![original];
    let refreshed = auto_connect_peer(peer_full.npub(), "198.51.100.21:51820");

    let outcome = node.update_peers(vec![refreshed]).await.unwrap();

    assert_eq!(outcome.updated, 1);
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&current_addr));
    assert!(
        active.is_healthy(),
        "public active endpoints may be learned paths and should not be pruned by config refresh alone"
    );
    assert!(!node.retry_pending.contains_key(&peer_node_addr));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[test]
fn active_peer_same_path_discovery_skips_fresh_peer() {
    let mut node = make_node();
    let (_peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), Node::now_ms());
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);
    let candidate = crate::config::PeerAddress::new("udp", "127.0.0.1:9");

    assert!(node.active_peer_candidate_is_fresh_enough_to_skip(
        &peer_node_addr,
        std::slice::from_ref(&candidate),
    ));
}

#[test]
fn active_peer_same_path_discovery_refreshes_stale_peer() {
    let mut node = make_node();
    let (_peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let stale_at = Node::now_ms().saturating_sub(
        node.config
            .node
            .heartbeat_interval_secs
            .saturating_add(1)
            .saturating_mul(1000),
    );
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), stale_at);
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);
    let candidate = crate::config::PeerAddress::new("udp", "127.0.0.1:9");

    assert!(!node.active_peer_candidate_is_fresh_enough_to_skip(
        &peer_node_addr,
        std::slice::from_ref(&candidate),
    ));
}

#[tokio::test]
async fn update_peers_races_new_alternative_even_when_current_path_is_still_known() {
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

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let new_addr = TransportAddr::from_string("127.0.0.1:10");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            current_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );

    let peer = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::new("udp", "127.0.0.1:9"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:10"),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers = vec![peer.clone()];

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.unchanged, 1);
    assert_eq!(node.peer_count(), 1, "existing link must stay live");
    assert_eq!(node.connection_count(), 1);
    assert_eq!(
        node.peers
            .connection_values()
            .next()
            .and_then(|conn| conn.source_addr()),
        Some(&new_addr)
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&current_addr));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_races_more_alternatives_while_peer_is_connecting_with_budget() {
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

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            current_addr,
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );

    let first = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::new("udp", "127.0.0.1:9"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:10"),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers = vec![first.clone()];
    let _ = node.update_peers(vec![first]).await.unwrap();
    assert_eq!(node.connection_count(), 1);

    let refreshed = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::new("udp", "127.0.0.1:9"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:10"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:11"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:12"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:13"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:14"),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };

    let outcome = node.update_peers(vec![refreshed]).await.unwrap();

    assert_eq!(outcome.updated, 1);
    assert_eq!(
        node.connection_count(),
        4,
        "one existing in-flight path plus three new paths should hit the per-peer race budget"
    );
    let attempted: std::collections::HashSet<_> = node
        .peers
        .connection_values()
        .filter_map(|conn| conn.source_addr().map(ToString::to_string))
        .collect();
    for addr in [
        "127.0.0.1:10",
        "127.0.0.1:11",
        "127.0.0.1:12",
        "127.0.0.1:13",
    ] {
        assert!(attempted.contains(addr), "missing attempted path {addr}");
    }
    assert!(
        !attempted.contains("127.0.0.1:14"),
        "candidate racing should be bounded per peer"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}
