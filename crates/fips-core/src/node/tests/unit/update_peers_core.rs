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

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn network_transport_rebind_defers_udp_reauthentication_until_tuple_is_quiet() {
    #[cfg(target_os = "macos")]
    const LOOPBACK_INTERFACE: &str = "lo0";
    #[cfg(target_os = "linux")]
    const LOOPBACK_INTERFACE: &str = "lo";

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    node.transports
        .insert(transport_id, make_udp_transport_with_mtu(1, 1280).await);

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let peer = make_active_test_peer(
        &node,
        &remote,
        transport_id,
        LinkId::new(1),
        current_addr.clone(),
        SessionIndex::new(1),
        SessionIndex::new(2),
    );
    node.peers.insert(remote_addr, peer);
    assert!(node.sync_dataplane_fmp_owner(&remote_addr));
    node.config.peers = vec![auto_connect_peer(
        remote.npub(),
        current_addr.as_str().expect("socket address"),
    )];
    refresh_configured_peer_cache_for_test(&mut node);

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

    let rebind_started_at_ms = Node::now_ms();
    assert_eq!(node.connection_count(), 0);
    assert_eq!(
        node.apply_prepared_network_rebind(Some(LOOPBACK_INTERFACE.to_string()))
            .await
            .unwrap(),
        1
    );
    assert!(
        !node.get_peer(&remote_addr).unwrap().is_healthy(),
        "a UDP link authenticated on another physical interface must be reauthenticated"
    );
    assert!(
        !node.dataplane_has_fmp_owner(&remote_addr),
        "the old-interface UDP tuple must not retain dataplane ownership"
    );
    let first_probe_at_ms = node
        .retry_pending
        .get(&remote_addr)
        .expect("the configured endpoint must remain scheduled on the new interface")
        .retry_after_ms;
    let quiet_interval_ms = node.config.node.rate_limit.handshake_resend_interval_ms;
    assert!(
        first_probe_at_ms >= rebind_started_at_ms.saturating_add(quiet_interval_ms),
        "the first fresh handshake must wait for the route and stationary peer's old tuple to settle"
    );
    assert_eq!(
        node.connection_count(),
        0,
        "the rebind must not waste a handshake inside the stationary peer's anti-thrash interval"
    );
    node.process_pending_retries(first_probe_at_ms).await;
    assert!(
        node.connection_count() > 0,
        "the fresh authenticated path probe must start as soon as the quiet interval ends"
    );
    assert!(
        node.sessions.get(&remote_addr).is_some(),
        "interface replacement must preserve the end-to-end session"
    );

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
async fn network_transport_rebind_preserves_live_rekey_drain() {
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let mut config = Config::new();
    config.peers = vec![auto_connect_peer(remote.npub(), "127.0.0.1:9")];
    let mut node = Node::new(config).unwrap();
    let transport_id = TransportId::new(1);
    node.transports
        .insert(transport_id, make_udp_transport_with_mtu(1, 1280).await);

    let mut peer = make_active_test_peer(
        &node,
        &remote,
        transport_id,
        LinkId::new(1),
        TransportAddr::from_string("127.0.0.1:9"),
        SessionIndex::new(1),
        SessionIndex::new(2),
    );
    peer.set_pending_session(
        make_test_fmp_session(node.identity(), &remote, [0x41; 8], [0x42; 8]),
        SessionIndex::new(3),
        SessionIndex::new(4),
        true,
    );
    assert!(peer.cutover_to_new_session().is_some());
    assert!(peer.is_draining(), "fixture requires an active FMP drain");
    node.peers.insert(remote_addr, peer);
    assert!(node.sync_dataplane_fmp_owner(&remote_addr));

    assert_eq!(node.apply_prepared_network_rebind(None).await.unwrap(), 1);
    assert!(
        node.get_peer(&remote_addr).unwrap().is_draining(),
        "replacing only the local UDP socket must preserve the previous authenticated epoch while the remote peer may still be sending it"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn network_transport_rebind_replaces_repeated_rebuilt_carrier_affinity() {
    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    let mut node = Node::new(config).unwrap();
    let rebound_transport_id = TransportId::new(1);
    node.transports.insert(
        rebound_transport_id,
        make_udp_transport_with_mtu(1, 1280).await,
    );
    let fallback_transport_id = TransportId::new(2);
    let (fallback_packet_tx, _fallback_packet_rx) = packet_channel(64);
    let mut fallback_transport = crate::transport::websocket::WebSocketTransport::new(
        fallback_transport_id,
        None,
        crate::config::WebSocketConfig::default(),
        fallback_packet_tx,
        node.identity(),
    );
    fallback_transport
        .start_async()
        .await
        .expect("start fallback WebSocket carrier");
    node.transports.insert(
        fallback_transport_id,
        TransportHandle::WebSocket(Box::new(fallback_transport)),
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
        fallback_transport_id,
        LinkId::new(2),
        TransportAddr::from_string("wss://seed.example/fips"),
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

    let mut scenario_now_ms = Node::now_ms();
    for cycle in 1..=2 {
        let now_ms = scenario_now_ms;
        node.restart_session_direct_path_validation(remote_addr, now_ms);
        assert_eq!(
            node.dataplane.fsp_owner_next_hop(&remote_addr),
            Some(fallback_addr),
            "cycle {cycle}: the proven fallback must carry payload while direct recovers"
        );
        seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, fallback_addr, now_ms);
        seed_dataplane_fsp_data_rx_for_test(&mut node, remote_addr, fallback_addr, now_ms);

        node.clear_session_direct_path_degraded_after_promotion(&remote_addr, now_ms);
        for offset_ms in [100, 350, 600, 850, 1_100] {
            seed_dataplane_fsp_data_sent_for_test(
                &mut node,
                remote_addr,
                remote_addr,
                now_ms + offset_ms,
            );
            seed_dataplane_fsp_data_rx_for_test(
                &mut node,
                remote_addr,
                remote_addr,
                now_ms + offset_ms,
            );
            assert_eq!(
                node.authenticated_direct_payload_validates_route(
                    &remote_addr,
                    now_ms + offset_ms,
                ),
                offset_ms == 1_100,
                "cycle {cycle}: direct recovery must require sustained authenticated payload"
            );
        }
        assert!(
            node.clear_session_direct_path_degraded(&remote_addr),
            "cycle {cycle}: authenticated direct payload should complete recovery"
        );
        scenario_now_ms += 2_000;
    }

    let now_ms = scenario_now_ms;
    let pending_epoch = make_test_fmp_session(node.identity(), &remote, [0x41; 8], [0x42; 8]);
    let session = node
        .sessions
        .get_mut(&remote_addr)
        .expect("established endpoint session");
    session.set_pending_session(pending_epoch);
    assert!(session.cutover_to_new_session(now_ms));
    assert!(session.is_draining(), "fixture must model rekey drain");
    assert!(node.sync_dataplane_fsp_owner_from_current_session_via(
        &remote_addr,
        Some(fallback_addr),
        0,
    ));
    seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, fallback_addr, now_ms);
    seed_dataplane_fsp_data_rx_for_test(&mut node, remote_addr, fallback_addr, now_ms);
    assert_eq!(
        node.dataplane
            .fsp_owner_activity(&remote_addr)
            .and_then(|activity| activity.last_outbound_next_hop()),
        Some(fallback_addr),
        "fixture must begin with proven fallback affinity from the old carrier incarnation"
    );

    for rebind in 1..=2 {
        if rebind == 2 {
            assert!(
                node.dataplane
                    .forget_fsp_data_route(remote_addr, fallback_addr),
                "fixture must retain authenticated return evidence after forgetting its outbound affinity"
            );
        }
        scenario_now_ms += 1;
        seed_dataplane_fsp_data_rx_for_test(&mut node, remote_addr, remote_addr, scenario_now_ms);
        assert!(
            node.dataplane
                .min_fsp_data_rx_age_for_next_hop(&remote_addr, scenario_now_ms)
                .is_some(),
            "rebind {rebind}: fixture must contain direct inbound evidence on the shared carrier"
        );
        assert_eq!(node.apply_prepared_network_rebind(None).await.unwrap(), 2);
        assert!(
            node.dataplane.fsp_owner_next_hop(&remote_addr).is_some(),
            "rebind {rebind}: the established owner should stay ready while rebuilt carriers reauthenticate"
        );
        assert_eq!(
            node.dataplane
                .fsp_owner_activity(&remote_addr)
                .and_then(|activity| activity.last_outbound_next_hop()),
            None,
            "rebind {rebind}: route affinity from the previous rebuilt-carrier incarnation must not suppress fresh route selection"
        );
        if rebind == 1 {
            assert!(
                !node
                    .dataplane
                    .fsp_owner_activity(&remote_addr)
                    .is_some_and(|activity| {
                        activity.has_recent_outbound_activity(Node::now_ms(), u64::MAX)
                    }),
                "rebind {rebind}: tagged outbound liveness from the previous carrier incarnation must not keep the rebuilt path trusted"
            );
        }
        assert_eq!(
            node.dataplane
                .min_fsp_data_rx_age_for_next_hop(&remote_addr, Node::now_ms()),
            None,
            "rebind {rebind}: inbound evidence from another peer on a rebuilt carrier must also be discarded"
        );
        assert!(
            node.sessions
                .get(&remote_addr)
                .is_some_and(SessionEntry::is_draining),
            "rebind {rebind}: carrier replacement must preserve the draining end-to-end session"
        );

        seed_dataplane_fsp_data_sent_for_test(
            &mut node,
            remote_addr,
            fallback_addr,
            Node::now_ms(),
        );
        assert!(
            !node
                .dataplane
                .fsp_owner_activity(&remote_addr)
                .is_some_and(|activity| {
                    activity.has_recent_data_return_from(&fallback_addr, Node::now_ms(), u64::MAX)
                }),
            "rebind {rebind}: a new send on the same next-hop identity must not inherit authenticated return evidence from the previous carrier incarnation"
        );
        seed_dataplane_fsp_data_rx_for_test(&mut node, remote_addr, fallback_addr, Node::now_ms());
    }

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

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn network_rebind_recovers_an_addressless_session_after_its_transit_returns() {
    #[cfg(target_os = "macos")]
    const LOOPBACK_INTERFACE: &str = "lo0";
    #[cfg(target_os = "linux")]
    const LOOPBACK_INTERFACE: &str = "lo";

    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    let mut node = Node::new(config).unwrap();
    let rebound_transport_id = TransportId::new(1);
    node.transports.insert(
        rebound_transport_id,
        make_udp_transport_with_mtu(1, 1280).await,
    );

    let transit = Identity::generate();
    let transit_addr = *transit.node_addr();
    let transit_peer = make_active_test_peer(
        &node,
        &transit,
        rebound_transport_id,
        LinkId::new(1),
        TransportAddr::from_string("127.0.0.1:9"),
        SessionIndex::new(1),
        SessionIndex::new(2),
    );
    node.peers.insert(transit_addr, transit_peer);
    assert!(node.sync_dataplane_fmp_owner(&transit_addr));

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    node.learn_reverse_route(remote_addr, transit_addr);
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
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(transit_addr),
        "fixture must route the addressless target through an authenticated graph peer"
    );
    assert!(
        node.get_peer(&remote_addr).is_none(),
        "the target must not have a direct transport connection"
    );

    assert_eq!(
        node.apply_prepared_network_rebind(Some(LOOPBACK_INTERFACE.to_string()))
            .await
            .unwrap(),
        1
    );
    assert!(
        node.sessions
            .get(&remote_addr)
            .is_some_and(SessionEntry::is_established),
        "carrier replacement must preserve the end-to-end session"
    );

    let returned_transit = make_active_test_peer(
        &node,
        &transit,
        rebound_transport_id,
        LinkId::new(2),
        TransportAddr::from_string("127.0.0.1:9"),
        SessionIndex::new(3),
        SessionIndex::new(4),
    );
    node.peers.insert(transit_addr, returned_transit);
    assert!(node.sync_dataplane_fmp_owner(&transit_addr));
    let now_ms = Node::now_ms();
    let baseline = node.stats().discovery.req_initiated;
    node.retry_degraded_session_routes_after_peer_authenticated(transit_addr, now_ms)
        .await;

    assert!(
        node.pending_lookups.contains_key(&remote_addr),
        "the returned graph peer must trigger npub route discovery for the stranded routed session"
    );
    assert_eq!(
        node.stats().discovery.req_initiated,
        baseline + 1,
        "recovery must issue exactly one bounded lookup without a direct endpoint"
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

include!("update_peers_core/rebind_sessions.rs");
