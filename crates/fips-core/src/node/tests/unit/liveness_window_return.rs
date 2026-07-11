#[tokio::test]
async fn endpoint_return_via_direct_next_hop_keeps_link_liveness_fresh() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let app_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();
    let app_peer = PeerIdentity::from_pubkey_full(app_identity.pubkey_full());
    let app_addr = *app_peer.node_addr();

    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.peers.push(peer_config.clone());
    let link_session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let endpoint_session = make_test_fmp_session(&local_identity, &app_identity, [3; 8], [4; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");
    node.config.node.heartbeat_interval_secs = 10;
    node.config.node.link_dead_timeout_secs = 30;
    node.config.node.fast_link_dead_timeout_secs = 5;

    let active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        ActivePeerSession {
            session: link_session,
            our_index: crate::utils::index::SessionIndex::new(11),
            their_index: crate::utils::index::SessionIndex::new(12),
            transport_id: TransportId::new(1),
            current_addr: crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: None,
        },
    );
    node.peers.insert(peer_addr, active);
    super::super::seed_dataplane_fmp_rx_for_test(
        &mut node,
        peer_addr,
        std::time::Duration::from_secs(11),
    );

    let now_ms = Node::now_ms();
    let session = crate::node::session::SessionEntry::new(
        app_addr,
        app_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(endpoint_session),
        1_000,
        true,
    );
    node.sessions.insert(app_addr, session);
    seed_dataplane_fsp_data_sent_for_test(&mut node, app_addr, peer_addr, now_ms);
    seed_dataplane_fsp_data_rx_for_test(&mut node, app_addr, peer_addr, now_ms);

    node.check_link_heartbeats().await;

    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "authenticated endpoint return through a direct first hop should keep that link out of direct-probe refresh"
    );
    let direct = node.find_next_hop(&peer_addr).expect("direct route");
    assert_eq!(
        direct.node_addr(),
        &peer_addr,
        "active endpoint traffic through this peer should keep the direct link eligible"
    );
}

#[tokio::test]
async fn authenticated_endpoint_return_clears_static_retry_on_fresh_discovered_udp() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let app_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();
    let app_peer = PeerIdentity::from_pubkey_full(app_identity.pubkey_full());
    let app_addr = *app_peer.node_addr();

    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.peers.push(peer_config.clone());
    let link_session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let endpoint_session = make_test_fmp_session(&local_identity, &app_identity, [3; 8], [4; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");
    node.config.node.heartbeat_interval_secs = 10;
    node.config.node.link_dead_timeout_secs = 30;
    node.config.node.fast_link_dead_timeout_secs = 5;

    let mut active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        ActivePeerSession {
            session: link_session,
            our_index: crate::utils::index::SessionIndex::new(11),
            their_index: crate::utils::index::SessionIndex::new(12),
            transport_id: TransportId::new(1),
            current_addr: crate::transport::TransportAddr::from_string("198.51.100.20:61062"),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: None,
        },
    );
    active.touch(Node::now_ms());
    node.peers.insert(peer_addr, active);
    super::super::seed_dataplane_fmp_rx_for_test(
        &mut node,
        peer_addr,
        std::time::Duration::from_secs(11),
    );

    assert!(
        !node.active_peer_should_keep_direct_retry(&peer_addr, &peer_config),
        "a healthy discovered UDP path should not keep retrying a mismatched static LAN hint"
    );

    let now_ms = Node::now_ms();
    let session = crate::node::session::SessionEntry::new(
        app_addr,
        app_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(endpoint_session),
        1_000,
        true,
    );
    node.sessions.insert(app_addr, session);
    seed_dataplane_fsp_data_sent_for_test(&mut node, app_addr, peer_addr, now_ms);
    seed_dataplane_fsp_data_rx_for_test(&mut node, app_addr, peer_addr, now_ms);

    let mut retry = super::super::retry::RetryState::new(peer_config);
    retry.reconnect = true;
    retry.retry_after_ms = now_ms;
    node.retry_pending.insert(peer_addr, retry);

    node.check_link_heartbeats().await;

    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "fresh authenticated endpoint return through a discovered UDP first hop should clear stale static-endpoint retry state"
    );
}

#[tokio::test]
async fn local_route_failure_for_one_peer_does_not_fast_dead_unrelated_direct_peer() {
    let local_identity = Identity::generate();
    let quiet_identity = Identity::generate();
    let failed_identity = Identity::generate();
    let quiet_config = crate::config::PeerConfig {
        npub: quiet_identity.npub(),
        alias: Some("quiet-lan-peer".to_string()),
        addresses: vec![crate::config::PeerAddress::with_priority(
            "udp",
            "198.51.100.57:51820",
            1,
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let quiet_peer = PeerIdentity::from_npub(&quiet_config.npub).expect("quiet peer identity");
    let quiet_addr = *quiet_peer.node_addr();
    let failed_peer =
        PeerIdentity::from_pubkey(failed_identity.pubkey_full().x_only_public_key().0);
    let failed_addr = *failed_peer.node_addr();

    let mut config = Config::new();
    config.peers.push(quiet_config);
    let session = make_test_fmp_session(&local_identity, &quiet_identity, [1; 8], [2; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");
    node.config.node.heartbeat_interval_secs = 2;
    node.config.node.link_dead_timeout_secs = 30;
    node.config.node.fast_link_dead_timeout_secs = 5;

    let quiet_active = ActivePeer::with_session(
        quiet_peer,
        LinkId::new(7),
        0,
        ActivePeerSession {
            session,
            our_index: crate::utils::index::SessionIndex::new(11),
            their_index: crate::utils::index::SessionIndex::new(12),
            transport_id: TransportId::new(1),
            current_addr: crate::transport::TransportAddr::from_string("198.51.100.57:51820"),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: None,
        },
    );
    node.peers.insert(quiet_addr, quiet_active);
    super::super::seed_dataplane_fmp_rx_for_test(
        &mut node,
        quiet_addr,
        std::time::Duration::from_secs(6),
    );

    // Simulate a route-unavailable send to some other peer. The quiet peer
    // has exceeded the fast timeout, but not the normal link-dead timeout.
    node.local_send_failures
        .record_failure(failed_addr, std::time::Instant::now());

    node.check_link_heartbeats().await;

    assert!(
        node.peers.contains_key(&quiet_addr),
        "a local route failure for {} must not demote unrelated healthy direct peer {}",
        failed_addr,
        quiet_addr
    );
    assert!(
        !node.retry_pending.contains_key(&quiet_addr),
        "unrelated local route failures must not schedule direct reconnect for the quiet peer"
    );
}

#[test]
fn stale_candidate_failure_does_not_fast_dead_active_current_path() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer = PeerIdentity::from_pubkey(peer_identity.pubkey_full().x_only_public_key().0);
    let peer_addr = *peer.node_addr();
    let mut node = Node::with_identity(local_identity, Config::new()).expect("node");
    let transport_id = TransportId::new(1);
    let current_addr = crate::transport::TransportAddr::from_string("198.51.100.57:51820");
    let stale_candidate = crate::transport::TransportAddr::from_string("192.168.178.55:51821");
    let route_error = Err(crate::transport::TransportError::SendFailed(
        "No route to host (os error 65)".to_string(),
    ));
    let now = std::time::Instant::now();
    let dead_timeout = std::time::Duration::from_secs(30);
    let fast_dead_timeout = std::time::Duration::from_secs(5);

    let mut active = ActivePeer::new(peer, LinkId::new(7), 0);
    active.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_addr, active);

    node.note_candidate_send_outcome(&peer_addr, &stale_candidate, &route_error);

    assert!(
        !node.local_send_failures.contains_key(&peer_addr),
        "a failed stale candidate probe must not poison liveness for the active current path"
    );
    assert_eq!(
        node.local_send_failure_dead_timeout_for_peer(
            &peer_addr,
            now,
            dead_timeout,
            fast_dead_timeout,
        ),
        dead_timeout
    );

    node.note_candidate_send_outcome(&peer_addr, &current_addr, &route_error);

    assert!(
        node.local_send_failures.contains_key(&peer_addr),
        "a failed send to the active current path should still enable fast-dead recovery"
    );
    assert_eq!(
        node.local_send_failure_dead_timeout_for_peer(
            &peer_addr,
            now,
            dead_timeout,
            fast_dead_timeout,
        ),
        fast_dead_timeout
    );
}

#[test]
fn fmp_bulk_classifier_detects_established_session_datagrams() {
    let src = make_node_addr(1);
    let dst = make_node_addr(2);
    let fsp_payload = crate::node::session_wire::build_fsp_header(7, 0, 0).to_vec();
    let datagram = crate::protocol::SessionDatagram::new(src, dst, fsp_payload);
    assert!(
        crate::node::endpoint_traffic::fmp_plaintext_is_bulk_session_datagram(&datagram.encode())
    );

    let coords_payload =
        crate::node::session_wire::build_fsp_header(8, crate::node::session_wire::FSP_FLAG_CP, 0)
            .to_vec();
    let coords_datagram = crate::protocol::SessionDatagram::new(src, dst, coords_payload);
    assert!(
        !crate::node::endpoint_traffic::fmp_plaintext_is_bulk_session_datagram(
            &coords_datagram.encode()
        ),
        "coordinate-carrying session packets warm fallback routes and must stay in the control lane"
    );

    let heartbeat = [crate::protocol::LinkMessageType::Heartbeat.to_byte()];
    assert!(!crate::node::endpoint_traffic::fmp_plaintext_is_bulk_session_datagram(&heartbeat));

    let setup_prefix = crate::node::session_wire::build_fsp_handshake_prefix(
        crate::node::session_wire::FSP_PHASE_MSG1,
        0,
    );
    let setup_datagram = crate::protocol::SessionDatagram::new(src, dst, setup_prefix.to_vec());
    assert!(
        !crate::node::endpoint_traffic::fmp_plaintext_is_bulk_session_datagram(
            &setup_datagram.encode()
        )
    );
}

#[tokio::test]
async fn link_dead_recent_endpoint_path_reprobes_without_traversal_cooldown() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).expect("node");
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

    let mut active = ActivePeer::new(peer, LinkId::new(7), 0);
    active.set_current_addr(
        transport_id,
        &crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
    );
    node.peers.insert(peer_addr, active);

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    node.nostr_discovery = Some(bootstrap.clone());
    node.config.node.heartbeat_interval_secs = 10;
    node.config.node.link_dead_timeout_secs = 30;
    node.config.node.fast_link_dead_timeout_secs = 5;

    let recent_path_timeout = node
        .traversal_path_link_dead_timeout(
            &peer_addr,
            std::time::Duration::from_secs(node.config.node.link_dead_timeout_secs),
            std::time::Duration::from_secs(node.config.node.fast_link_dead_timeout_secs),
        )
        .expect("recent endpoint path should get bounded liveness timeout");
    assert_eq!(recent_path_timeout, std::time::Duration::from_secs(30));

    node.record_link_dead_path_failure(&peer_addr, 1_000).await;

    assert!(
        bootstrap.cooldown_until(&peer_config.npub, 1_000).is_none(),
        "one transient link-dead event should not suppress direct traversal"
    );

    node.schedule_link_dead_reprobe(peer_addr, 1_000);
    let state = node
        .retry_pending
        .get(&peer_addr)
        .expect("link-dead reconnect should seed retry state");
    assert!(state.reconnect);
    assert_eq!(state.peer_config.npub, peer_config.npub);
    assert_eq!(state.retry_count, 0);
    assert!(
        (1_500..=2_500).contains(&state.retry_after_ms),
        "link-dead retry should stay quick but jittered, got {}",
        state.retry_after_ms
    );

    for now_ms in [2_000, 3_000, 4_000, 5_000] {
        node.record_link_dead_path_failure(&peer_addr, now_ms).await;
    }

    assert!(
        bootstrap.cooldown_until(&peer_config.npub, 5_000).is_none(),
        "repeated link-dead endpoint paths should not install peer traversal cooldown"
    );
    let state = node
        .retry_pending
        .get(&peer_addr)
        .expect("threshold link-dead penalty should preserve retry state");
    let first_retry_after_ms = state.retry_after_ms;
    assert!(
        (1_500..=2_500).contains(&first_retry_after_ms),
        "link-dead diagnostics must not push retry behind traversal cooldown"
    );

    node.schedule_link_dead_reprobe(peer_addr, 5_000);
    let state = node
        .retry_pending
        .get(&peer_addr)
        .expect("reconnect should preserve cooled-down retry state");
    assert!(
        (5_500..=6_500).contains(&state.retry_after_ms),
        "each link-dead removal should make direct probing eligible again quickly"
    );
    assert_eq!(state.retry_count, 0);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn quiet_recent_endpoint_path_stays_alive_within_mobile_window() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.peers.push(peer_config);
    let session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");
    node.config.node.heartbeat_interval_secs = 10;
    node.config.node.link_dead_timeout_secs = 30;
    node.config.node.fast_link_dead_timeout_secs = 5;
    let active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        ActivePeerSession {
            session,
            our_index: crate::utils::index::SessionIndex::new(11),
            their_index: crate::utils::index::SessionIndex::new(12),
            transport_id: TransportId::new(1),
            current_addr: crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: None,
        },
    );
    node.peers.insert(peer_addr, active);
    super::super::seed_dataplane_fmp_rx_for_test(
        &mut node,
        peer_addr,
        std::time::Duration::from_secs(29),
    );

    node.check_link_heartbeats().await;

    assert!(
        node.peers.contains_key(&peer_addr),
        "link-dead should keep the authenticated peer identity"
    );
    assert!(
        node.get_peer(&peer_addr).expect("peer").is_healthy(),
        "a proven traversal/recent path at 29s silence should refresh but not flap before the mobile-safe liveness window"
    );
    assert!(
        node.retry_pending.contains_key(&peer_addr),
        "quiet traversal liveness should schedule direct reprobe before link-dead"
    );
    assert!(
        node.get_peer(&peer_addr).expect("peer").can_send(),
        "quiet direct paths remain sendable while the reprobe runs"
    );
    let configured_peer = node.configured_peer(&peer_addr).expect("configured peer");
    assert!(
        node.active_peer_uses_recent_endpoint_path(&peer_addr, configured_peer),
        "test fixture should still classify the stale path as a recent endpoint path"
    );
    assert_eq!(
        node.find_next_hop(&peer_addr).map(|peer| *peer.node_addr()),
        Some(peer_addr),
        "without a fallback route, a soft-stale traversal path should remain the last-resort payload route while reprobe runs"
    );
}

#[test]
fn degraded_recent_endpoint_path_without_fallback_queues_payload() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.peers.push(peer_config);
    let session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");
    let mut active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        ActivePeerSession {
            session,
            our_index: crate::utils::index::SessionIndex::new(11),
            their_index: crate::utils::index::SessionIndex::new(12),
            transport_id: TransportId::new(1),
            current_addr: crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: None,
        },
    );
    active.mark_stale();
    node.peers.insert(peer_addr, active);
    node.mark_session_direct_path_degraded(peer_addr, Node::now_ms());

    let configured_peer = node.configured_peer(&peer_addr).expect("configured peer");
    assert!(
        node.active_peer_uses_recent_endpoint_path(&peer_addr, configured_peer),
        "test fixture should still classify the stale path as a recent endpoint path"
    );
    assert!(
        node.get_peer(&peer_addr).expect("peer").can_send(),
        "degraded direct paths stay sendable for reprobes"
    );
    assert!(
        node.find_next_hop(&peer_addr).is_none(),
        "a degraded stale traversal path must wait for fallback discovery instead of blackholing payload"
    );
}
