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
    assert_eq!(node.apply_prepared_network_rebind(None).await.unwrap(), 1);
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
async fn network_transport_rebind_replaces_udp_upgrade_for_configured_websocket_peer() {
    let seed = Identity::generate();
    let mut config = Config::new();
    config.peers = vec![crate::config::PeerConfig::new(
        seed.npub(),
        "websocket",
        "wss://seed.example/fips",
    )];
    let mut node = Node::new(config).unwrap();
    let rebound_transport_id = TransportId::new(1);
    node.transports.insert(
        rebound_transport_id,
        make_udp_transport_with_mtu(1, 1280).await,
    );

    let seed_addr = *seed.node_addr();
    let upgraded_udp_peer = make_active_test_peer(
        &node,
        &seed,
        rebound_transport_id,
        LinkId::new(1),
        TransportAddr::from_string("127.0.0.1:9"),
        SessionIndex::new(1),
        SessionIndex::new(2),
    );
    node.peers.insert(seed_addr, upgraded_udp_peer);
    assert!(node.sync_dataplane_fmp_owner(&seed_addr));
    assert!(node.get_peer(&seed_addr).unwrap().is_healthy());

    assert_eq!(node.apply_prepared_network_rebind(None).await.unwrap(), 1);

    assert!(
        !node.get_peer(&seed_addr).unwrap().is_healthy(),
        "a peer reached through an opportunistic UDP upgrade must yield to its configured WebSocket path after the UDP underlay changes"
    );
    assert!(
        !node.dataplane_has_fmp_owner(&seed_addr),
        "the stale UDP seed tuple must not block the rebuilt WebSocket carrier from becoming active"
    );
    assert!(
        node.retry_pending.contains_key(&seed_addr),
        "the configured WebSocket seed must be redialed immediately"
    );

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
    let mut direct_peer = make_active_test_peer(
        &node,
        &remote,
        rebound_transport_id,
        LinkId::new(1),
        TransportAddr::from_string("127.0.0.1:9"),
        SessionIndex::new(1),
        SessionIndex::new(2),
    );
    let heartbeat_before_rebind = std::time::Instant::now() - Duration::from_secs(30);
    direct_peer.mark_heartbeat_sent(heartbeat_before_rebind);
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

    assert_eq!(node.apply_prepared_network_rebind(None).await.unwrap(), 1);

    assert!(
        node.dataplane_has_fmp_owner(&remote_addr),
        "an authenticated peer must install the rebound carrier's live socket without discarding its Noise session"
    );
    assert!(
        node.get_peer(&remote_addr)
            .and_then(ActivePeer::last_heartbeat_sent)
            .is_some_and(|sent| sent > heartbeat_before_rebind),
        "the rebound UDP carrier must immediately send authenticated traffic so the stationary peer can learn its new source tuple"
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
    assert_eq!(node.apply_prepared_network_rebind(None).await.unwrap(), 1);
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
async fn degraded_route_recovery_does_not_depend_on_direct_retry_state() {
    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    let remote = Identity::generate();
    config.peers = vec![auto_connect_peer(remote.npub(), "127.0.0.1:9")];
    let mut node = Node::new(config).unwrap();

    let remote_addr = *remote.node_addr();
    let direct_peer = make_active_test_peer(
        &node,
        &remote,
        TransportId::new(1),
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

    let now_ms = Node::now_ms();
    node.mark_session_direct_path_degraded(remote_addr, now_ms);
    node.retry_pending.remove(&remote_addr);
    let baseline = node.stats().discovery.req_initiated;

    node.maybe_recover_degraded_session_routes(now_ms).await;

    assert!(
        node.pending_lookups.contains_key(&remote_addr),
        "an authenticated transit return must recover a degraded route even if peer refresh removed the independent direct retry entry"
    );
    assert_eq!(node.stats().discovery.req_initiated, baseline + 1);
}

#[tokio::test]
async fn authenticated_transit_retries_a_rebind_lookup_without_waiting_for_backoff() {
    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    let remote = Identity::generate();
    config.peers = vec![auto_connect_peer(remote.npub(), "127.0.0.1:9")];
    let mut node = Node::new(config).unwrap();

    let remote_addr = *remote.node_addr();
    let direct_peer = make_active_test_peer(
        &node,
        &remote,
        TransportId::new(1),
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

    let now_ms = Node::now_ms();
    node.mark_session_direct_path_degraded(remote_addr, now_ms);
    node.pending_lookups.insert(
        remote_addr,
        crate::node::handlers::discovery::PendingLookup::new(now_ms.saturating_sub(500)),
    );
    let baseline = node.stats().discovery.req_initiated;

    node.retry_degraded_session_routes_after_peer_authenticated(fallback_addr, now_ms)
        .await;

    assert_eq!(
        node.stats().discovery.req_initiated,
        baseline + 1,
        "a transit adjacency that authenticates after the rebind must resend the stranded lookup immediately"
    );
    assert_eq!(
        node.pending_lookups
            .get(&remote_addr)
            .expect("recovery lookup remains bounded")
            .last_sent_ms,
        now_ms,
        "the ordinary lookup timeout must continue from the real post-reauthentication send"
    );
}

#[tokio::test]
async fn authenticated_transit_starts_rebind_lookup_when_initial_rebind_had_no_fallback() {
    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    let remote = Identity::generate();
    config.peers = vec![auto_connect_peer(remote.npub(), "127.0.0.1:9")];
    let mut node = Node::new(config).unwrap();

    let remote_addr = *remote.node_addr();
    let direct_peer = make_active_test_peer(
        &node,
        &remote,
        TransportId::new(1),
        LinkId::new(1),
        TransportAddr::from_string("127.0.0.1:9"),
        SessionIndex::new(1),
        SessionIndex::new(2),
    );
    node.peers.insert(remote_addr, direct_peer);
    assert!(node.sync_dataplane_fmp_owner(&remote_addr));

    let now_ms = Node::now_ms();
    node.mark_session_direct_path_degraded(remote_addr, now_ms);
    node.maybe_recover_degraded_session_routes(now_ms).await;
    assert!(
        !node.pending_lookups.contains_key(&remote_addr),
        "the carrier event cannot send a fallback lookup before transit authenticates"
    );
    let baseline = node.stats().discovery.req_initiated;

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

    node.retry_degraded_session_routes_after_peer_authenticated(fallback_addr, now_ms)
        .await;

    assert!(
        node.pending_lookups.contains_key(&remote_addr),
        "the first authenticated transit after a rebind must start the lookup that could not be sent at the carrier event"
    );
    assert_eq!(
        node.stats().discovery.req_initiated,
        baseline + 1,
        "transit authentication should start exactly one bounded recovery lookup"
    );
}

#[tokio::test]
async fn network_transport_rebind_updates_nostr_traversal_interface() {
    let mut node = make_node();
    let discovery =
        NostrDiscovery::new_for_test_with_bind_interface(Some("old-underlay".to_string()));
    node.nostr_discovery = Some(discovery.clone());
    let peer = Identity::generate();
    discovery
        .start_pending_initiator_for_test(&peer.npub())
        .await;
    assert_eq!(discovery.active_initiator_count_for_test().await, 1);

    assert_eq!(
        node.apply_prepared_network_rebind(Some("new-underlay".to_string()))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        discovery.bind_interface_for_test().await.as_deref(),
        Some("new-underlay"),
        "STUN and traversal sockets must bind to the new carrier instead of the disabled one"
    );
    assert_eq!(
        discovery.active_initiator_count_for_test().await,
        0,
        "the old-interface traversal must not suppress its replacement as already in progress"
    );
}

#[tokio::test]
async fn later_websocket_apply_failure_rolls_back_udp_and_network_config() {
    #[cfg(target_os = "macos")]
    const LOOPBACK_INTERFACE: &str = "lo0";
    #[cfg(all(not(target_os = "macos"), not(windows)))]
    const LOOPBACK_INTERFACE: &str = "lo";
    #[cfg(windows)]
    const LOOPBACK_INTERFACE: &str = "ignored-by-windows-udp";

    let mut node = make_node();
    let discovery = NostrDiscovery::new_for_test_with_bind_interface(None);
    node.nostr_discovery = Some(discovery.clone());

    let reserved_udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = reserved_udp.local_addr().unwrap();
    drop(reserved_udp);
    let udp_id = TransportId::new(1);
    let (udp_packet_tx, _udp_packet_rx) = packet_channel(64);
    let mut udp = UdpTransport::new(
        udp_id,
        Some("transactional-udp".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some(udp_addr.to_string()),
            ..Default::default()
        },
        udp_packet_tx,
    );
    udp.start_async().await.unwrap();
    assert_eq!(udp.local_addr(), Some(udp_addr));
    node.transports.insert(udp_id, TransportHandle::Udp(udp));

    let occupied_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let websocket_id = TransportId::new(2);
    let (websocket_packet_tx, _websocket_packet_rx) = packet_channel(64);
    let websocket = crate::transport::websocket::WebSocketTransport::new(
        websocket_id,
        Some("blocked-websocket".to_string()),
        crate::config::WebSocketConfig {
            bind_addr: Some(occupied_listener.local_addr().unwrap().to_string()),
            ..Default::default()
        },
        websocket_packet_tx,
        node.identity(),
    );
    node.transports.insert(
        websocket_id,
        TransportHandle::WebSocket(Box::new(websocket)),
    );

    let error = node
        .apply_prepared_network_rebind(Some(LOOPBACK_INTERFACE.to_string()))
        .await
        .expect_err("the occupied WebSocket listen port must fail carrier apply");
    assert!(error.to_string().contains("transport error"));
    assert_eq!(node.config.node.discovery.nostr.bind_interface, None);
    assert_eq!(discovery.bind_interface_for_test().await, None);
    match &node.config.transports.udp {
        crate::config::TransportInstances::Single(config) => {
            assert_eq!(config.bind_interface, None);
        }
        crate::config::TransportInstances::Named(configs) => {
            assert!(
                configs
                    .values()
                    .all(|config| config.bind_interface.is_none())
            );
        }
    }
    assert!(
        node.transport_rebind_packet_cutoffs_ms.is_empty(),
        "a rolled-back carrier must not invalidate packets or peer state"
    );

    let udp = match node.transports.get(&udp_id).unwrap() {
        TransportHandle::Udp(udp) => udp,
        _ => panic!("expected UDP carrier"),
    };
    assert_eq!(
        node.transports.get(&udp_id).unwrap().state(),
        crate::transport::TransportState::Up
    );
    assert_eq!(udp.local_addr(), Some(udp_addr));
    assert_eq!(udp.network_bind_interface(), None);

    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = TransportAddr::from_string(&receiver.local_addr().unwrap().to_string());
    node.transports
        .get(&udp_id)
        .unwrap()
        .send(&receiver_addr, b"rollback-live")
        .await
        .unwrap();
    let mut payload = [0u8; 32];
    let received = tokio::time::timeout(Duration::from_secs(1), receiver.recv(&mut payload))
        .await
        .expect("rolled-back UDP carrier delivery")
        .unwrap();
    assert_eq!(&payload[..received], b"rollback-live");
    assert_eq!(
        node.transports.get(&websocket_id).unwrap().state(),
        crate::transport::TransportState::Configured,
        "failed WebSocket start must restore its pre-apply lifecycle state"
    );

    node.transports
        .get_mut(&udp_id)
        .unwrap()
        .stop()
        .await
        .unwrap();
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

    let before_rebind_ms = Node::now_ms();
    assert_eq!(node.apply_prepared_network_rebind(None).await.unwrap(), 1);

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

    assert_eq!(node.apply_prepared_network_rebind(None).await.unwrap(), 1);
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
