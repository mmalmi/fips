use super::*;

#[test]
fn local_send_failures_own_peer_scoped_fast_dead_clear_and_expiry() {
    let failed_peer = make_node_addr(0xA1);
    let quiet_peer = make_node_addr(0xA2);
    let now = std::time::Instant::now();
    let dead_timeout = std::time::Duration::from_secs(30);
    let fast_dead_timeout = std::time::Duration::from_secs(5);
    let route_error = Err(crate::transport::TransportError::SendFailed(
        "No route to host (os error 65)".to_string(),
    ));

    let mut failures = LocalSendFailures::default();
    failures.note_send_outcome(&failed_peer, &route_error, now);

    assert!(failures.contains_key(&failed_peer));
    assert!(!failures.contains_key(&quiet_peer));
    assert_eq!(
        failures.dead_timeout_for_peer(&failed_peer, now, dead_timeout, fast_dead_timeout),
        fast_dead_timeout
    );
    assert_eq!(
        failures.dead_timeout_for_peer(&quiet_peer, now, dead_timeout, fast_dead_timeout),
        dead_timeout,
        "local route failure must remain scoped to the peer whose send failed"
    );

    let non_local_error = Err(crate::transport::TransportError::SendFailed(
        "connection refused".to_string(),
    ));
    failures.note_send_outcome(&quiet_peer, &non_local_error, now);
    assert!(
        !failures.contains_key(&quiet_peer),
        "non-local send errors must not create a fast-dead route signal"
    );

    failures.note_send_outcome(&failed_peer, &Ok(1), now);
    assert!(
        !failures.contains_key(&failed_peer),
        "successful sends must clear that peer's local route failure signal"
    );

    failures.record_failure(failed_peer, now);
    let later = now + std::time::Duration::from_secs(4);
    failures.purge_expired(later);
    assert!(!failures.contains_key(&failed_peer));
}

#[test]
fn session_direct_degradation_owns_hold_extension_expiry_and_clear() {
    let dest = make_node_addr(0xB1);
    let other = make_node_addr(0xB2);
    let hold_ms = 20_000;
    let mut degradation = SessionDirectDegradation::default();

    assert!(degradation.mark_degraded(dest, 1_000, hold_ms));
    assert!(degradation.is_degraded(&dest, 20_999));
    assert!(
        !degradation.mark_degraded(dest, 2_000, hold_ms),
        "marking an already-degraded direct path should extend the hold without reporting a new transition"
    );
    assert!(degradation.is_degraded(&dest, 21_999));
    assert!(
        !degradation.is_degraded(&other, 21_999),
        "direct degradation must remain scoped to the destination that produced bad session evidence"
    );
    assert!(
        !degradation.is_degraded(&dest, 22_000),
        "the payload hold must expire so direct validation can be attempted"
    );
    assert!(
        degradation.has_pending_validation(&dest),
        "hold expiry must retain the need for an authenticated direct-path validation"
    );
    assert!(degradation.clear(&dest));

    assert!(degradation.mark_degraded(dest, 30_000, hold_ms));
    assert!(degradation.clear(&dest));
    assert!(!degradation.is_degraded(&dest, 30_000));
}

#[test]
fn traversal_path_liveness_keeps_mobile_safe_floor() {
    assert_eq!(
        crate::node::handlers::traversal_path_liveness_timeout(
            2,
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(5),
        ),
        std::time::Duration::from_secs(30),
        "short-heartbeat traversal paths should not collapse to the 5s local-failure floor"
    );
    assert_eq!(
        crate::node::handlers::traversal_path_liveness_timeout(
            10,
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(5),
        ),
        std::time::Duration::from_secs(30),
        "default FIPS heartbeat keeps a three-heartbeat traversal liveness window"
    );
    assert_eq!(
        crate::node::handlers::traversal_path_liveness_timeout(
            2,
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(40),
        ),
        std::time::Duration::from_secs(40),
        "an explicitly higher fast floor should still be honored"
    );
}

#[test]
fn traversal_path_quiet_refresh_uses_heartbeat_and_fast_dead_floor() {
    assert_eq!(
        crate::node::handlers::traversal_path_quiet_refresh_timeout(
            2,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(30),
        ),
        std::time::Duration::from_secs(5),
        "short-heartbeat products should refresh at the local-failure fast floor before the traversal liveness floor"
    );
    assert_eq!(
        crate::node::handlers::traversal_path_quiet_refresh_timeout(
            10,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(30),
        ),
        std::time::Duration::from_secs(10),
        "default FIPS heartbeat should refresh after one missed heartbeat, before full link-dead"
    );
    assert_eq!(
        crate::node::handlers::traversal_path_quiet_refresh_timeout(
            10,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(8),
        ),
        std::time::Duration::from_secs(7),
        "the proactive window must stay before the effective link-dead timeout"
    );
}

#[tokio::test]
async fn authenticated_fmp_heartbeat_on_observed_tuple_keeps_idle_direct_link_fresh() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let current_addr = crate::transport::TransportAddr::from_string("203.0.113.9:2121");
    let observed_addr = crate::transport::TransportAddr::from_string("198.51.100.20:61062");
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .learned()
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

    let mut active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        ActivePeerSession {
            session,
            our_index: crate::utils::index::SessionIndex::new(11),
            their_index: crate::utils::index::SessionIndex::new(12),
            transport_id: TransportId::new(1),
            current_addr: current_addr.clone(),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: None,
        },
    );
    active.touch(Node::now_ms().saturating_sub(31_000));
    node.peers.insert(peer_addr, active);
    super::super::seed_dataplane_fmp_rx_for_test(
        &mut node,
        peer_addr,
        std::time::Duration::from_secs(31),
    );

    node.record_authenticated_fmp_receive_facts(
        crate::node::AuthenticatedFmpReceiveFacts {
            source_peer: peer,
            transport_id: TransportId::new(1),
            remote_addr: &observed_addr,
            packet_timestamp_ms: Node::now_ms(),
            packet_len: 64,
            fmp_counter: 2,
            inner_timestamp_ms: 1_234,
            fmp_flags: 0,
        },
        Some(&peer_addr),
    );

    assert_eq!(
        node.get_peer(&peer_addr)
            .and_then(|peer| peer.current_addr()),
        Some(&current_addr),
        "liveness-only heartbeat should not bypass path-priority rotation rules"
    );
    assert!(
        node.dataplane_fmp_link_metrics(&peer_addr, std::time::Instant::now())
            .and_then(|metrics| metrics.last_recv_age_ms)
            .is_some_and(|age_ms| age_ms < 1_000),
        "authenticated same-peer heartbeat should refresh FMP receive liveness"
    );

    node.check_link_heartbeats().await;

    assert!(
        node.get_peer(&peer_addr).expect("direct peer").is_healthy(),
        "authenticated same-peer heartbeat should keep an idle direct peer out of link-dead"
    );
}

#[tokio::test]
async fn quiet_recent_endpoint_path_refresh_keeps_direct_payload_without_demoting_peer() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .learned()
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let transit_identity = Identity::generate();
    let transit_peer = PeerIdentity::from_pubkey(transit_identity.pubkey());
    let transit_addr = *transit_peer.node_addr();

    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.peers.push(peer_config.clone());
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
        std::time::Duration::from_secs(11),
    );
    node.peers.insert(
        transit_addr,
        ActivePeer::new(transit_peer, LinkId::new(9), 0),
    );
    node.learn_reverse_route(peer_addr, transit_addr);

    node.check_link_heartbeats().await;

    let direct = node.get_peer(&peer_addr).expect("direct peer retained");
    assert!(
        direct.is_healthy(),
        "quiet pre-dead refresh should not mark the direct peer stale yet"
    );
    assert!(
        node.retry_pending.contains_key(&peer_addr),
        "one missed traversal heartbeat should queue direct-path refresh before the full mobile-safe link-dead window"
    );
    assert!(
        !node.session_direct_path_is_degraded(&peer_addr, Node::now_ms()),
        "a quiet pre-dead refresh is only a probe signal, not a hard link-dead mark"
    );
    assert!(
        !node.pending_lookups.contains_key(&peer_addr),
        "quiet pre-dead refresh should not start fallback discovery until link-dead or loss evidence arrives"
    );
    let direct = node.find_next_hop(&peer_addr).expect("direct route");
    assert_eq!(
        direct.node_addr(),
        &peer_addr,
        "background direct-path refresh alone should not move payload off a healthy direct peer"
    );
}

#[tokio::test]
async fn active_endpoint_traffic_on_quiet_traversal_path_warms_fallback() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .learned()
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let transit_identity = Identity::generate();
    let transit_peer = PeerIdentity::from_pubkey(transit_identity.pubkey());
    let transit_addr = *transit_peer.node_addr();

    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.peers.push(peer_config.clone());
    let link_session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let endpoint_session = make_test_fmp_session(&local_identity, &peer_identity, [3; 8], [4; 8]);
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
    node.peers.insert(
        transit_addr,
        ActivePeer::new(transit_peer, LinkId::new(9), 0),
    );
    node.learn_reverse_route(peer_addr, transit_addr);

    let session = crate::node::session::SessionEntry::new(
        peer_addr,
        peer_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(endpoint_session),
        1_000,
        true,
    );
    node.sessions.insert(peer_addr, session);
    seed_dataplane_fsp_data_sent_for_test(&mut node, peer_addr, peer_addr, Node::now_ms());

    node.check_link_heartbeats().await;

    assert!(
        node.get_peer(&peer_addr).expect("direct peer").is_healthy(),
        "quiet-refresh evidence should not mark the direct peer link-dead"
    );
    assert!(
        node.retry_pending.contains_key(&peer_addr),
        "active blackhole evidence should still queue direct-path refresh"
    );
    assert!(
        node.pending_lookups.contains_key(&peer_addr),
        "active outbound traffic without authenticated return should warm fallback before full link-dead"
    );
    assert!(
        !node.session_direct_path_is_degraded(&peer_addr, Node::now_ms()),
        "quiet active-traffic evidence should de-prioritize exclusive direct trust without declaring the path dead"
    );
    let fallback = node.find_next_hop(&peer_addr).expect("fallback route");
    assert_eq!(
        fallback.node_addr(),
        &transit_addr,
        "known fallback should carry payload while quiet direct traversal refresh runs"
    );
}

#[tokio::test]
async fn endpoint_session_traffic_keeps_traversal_liveness_fresh() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .learned()
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.peers.push(peer_config.clone());
    let link_session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let endpoint_session = make_test_fmp_session(&local_identity, &peer_identity, [3; 8], [4; 8]);
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

    let session = crate::node::session::SessionEntry::new(
        peer_addr,
        peer_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(endpoint_session),
        1_000,
        true,
    );
    node.sessions.insert(peer_addr, session);
    seed_dataplane_fsp_data_rx_for_test(&mut node, peer_addr, peer_addr, Node::now_ms());

    node.check_link_heartbeats().await;

    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "authenticated endpoint traffic should suppress proactive direct refresh"
    );
    assert!(
        !node.session_direct_path_is_degraded(&peer_addr, Node::now_ms()),
        "fresh endpoint traffic should keep direct payload eligible"
    );
    assert!(
        !node.pending_lookups.contains_key(&peer_addr),
        "fresh endpoint traffic should not trigger fallback discovery"
    );
    let direct = node.find_next_hop(&peer_addr).expect("direct route");
    assert_eq!(
        direct.node_addr(),
        &peer_addr,
        "direct payload route should remain selected while endpoint traffic is fresh"
    );
}

#[tokio::test]
async fn endpoint_session_traffic_from_direct_peer_keeps_liveness_fresh_without_route_marker() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .learned()
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.peers.push(peer_config);
    let link_session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let endpoint_session = make_test_fmp_session(&local_identity, &peer_identity, [3; 8], [4; 8]);
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

    let session = crate::node::session::SessionEntry::new(
        peer_addr,
        peer_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(endpoint_session),
        1_000,
        true,
    );
    node.sessions.insert(peer_addr, session);
    seed_dataplane_fsp_data_rx_for_test(&mut node, peer_addr, peer_addr, Node::now_ms());

    node.check_link_heartbeats().await;

    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "authenticated direct endpoint data should keep the peer fresh even when next-hop bookkeeping is missing"
    );
    assert!(
        !node.pending_lookups.contains_key(&peer_addr),
        "fresh direct endpoint data should not start fallback discovery"
    );
    let direct = node.find_next_hop(&peer_addr).expect("direct route");
    assert_eq!(
        direct.node_addr(),
        &peer_addr,
        "direct payload route should stay eligible while authenticated direct endpoint data is fresh"
    );
}

#[tokio::test]
async fn direct_endpoint_data_refreshes_static_peer_after_fallback_send() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .learned()
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();
    let fallback_addr = *Identity::generate().node_addr();

    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.peers.push(peer_config);
    let link_session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let endpoint_session = make_test_fmp_session(&local_identity, &peer_identity, [3; 8], [4; 8]);
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
            current_addr: crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: None,
        },
    );
    active.touch(Node::now_ms().saturating_sub(31_000));
    node.peers.insert(peer_addr, active);
    super::super::seed_dataplane_fmp_rx_for_test(
        &mut node,
        peer_addr,
        std::time::Duration::from_secs(31),
    );

    let session = crate::node::session::SessionEntry::new(
        peer_addr,
        peer_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(endpoint_session),
        1_000,
        true,
    );
    node.sessions.insert(peer_addr, session);
    let now_ms = Node::now_ms();
    seed_dataplane_fsp_data_sent_for_test(&mut node, peer_addr, fallback_addr, now_ms);
    seed_dataplane_fsp_data_rx_for_test(&mut node, peer_addr, peer_addr, now_ms);

    node.check_link_heartbeats().await;

    assert!(
        node.get_peer(&peer_addr).expect("direct peer").is_healthy(),
        "fresh direct endpoint data should keep a static direct peer from being marked stale even after a fallback send"
    );
}

#[tokio::test]
async fn authenticated_control_return_does_not_keep_direct_payload_route_trusted() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .learned()
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let transit_identity = Identity::generate();
    let transit_peer = PeerIdentity::from_pubkey(transit_identity.pubkey());
    let transit_addr = *transit_peer.node_addr();

    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.peers.push(peer_config.clone());
    let link_session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let endpoint_session = make_test_fmp_session(&local_identity, &peer_identity, [3; 8], [4; 8]);
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
    node.peers.insert(
        transit_addr,
        ActivePeer::new(transit_peer, LinkId::new(9), 0),
    );
    node.learn_reverse_route(peer_addr, transit_addr);

    let now_ms = Node::now_ms();
    let session = crate::node::session::SessionEntry::new(
        peer_addr,
        peer_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(endpoint_session),
        1_000,
        true,
    );
    node.sessions.insert(peer_addr, session);
    seed_dataplane_fsp_data_sent_for_test(&mut node, peer_addr, peer_addr, now_ms);
    seed_dataplane_fsp_control_rx_for_test(&mut node, peer_addr, peer_addr, now_ms);

    node.check_link_heartbeats().await;

    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "fresh authenticated control/session return can stop direct-probe churn"
    );
    assert!(
        !node.pending_lookups.contains_key(&peer_addr),
        "a known learned fallback can carry payload without starting another lookup"
    );
    let fallback = node.find_next_hop(&peer_addr).expect("fallback route");
    assert_eq!(
        fallback.node_addr(),
        &transit_addr,
        "payload should use known fallback when recent direct endpoint sends lack authenticated data return"
    );
}

#[tokio::test]
async fn fresh_control_with_unreturned_endpoint_data_warms_fallback_lookup() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .learned()
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let transit_identity = Identity::generate();
    let transit_peer = PeerIdentity::from_pubkey(transit_identity.pubkey());
    let transit_addr = *transit_peer.node_addr();

    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.peers.push(peer_config.clone());
    let link_session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let endpoint_session = make_test_fmp_session(&local_identity, &peer_identity, [3; 8], [4; 8]);
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
            current_addr: crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: None,
        },
    );
    active.touch(Node::now_ms());
    node.peers.insert(peer_addr, active);
    super::super::seed_dataplane_fmp_rx_for_test(&mut node, peer_addr, std::time::Duration::ZERO);
    node.peers.insert(
        transit_addr,
        ActivePeer::new(transit_peer, LinkId::new(9), 0),
    );

    let now_ms = Node::now_ms();
    let session = crate::node::session::SessionEntry::new(
        peer_addr,
        peer_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(endpoint_session),
        1_000,
        true,
    );
    node.sessions.insert(peer_addr, session);
    seed_dataplane_fsp_data_sent_for_test(&mut node, peer_addr, peer_addr, now_ms);
    seed_dataplane_fsp_control_rx_for_test(&mut node, peer_addr, peer_addr, now_ms);

    let mut retry = super::super::retry::RetryState::new(peer_config);
    retry.reconnect = true;
    retry.retry_after_ms = now_ms;
    node.retry_pending.insert(peer_addr, retry);
    node.mark_session_direct_path_degraded(peer_addr, now_ms);

    node.check_link_heartbeats().await;

    assert!(
        node.get_peer(&peer_addr).expect("direct peer").is_healthy(),
        "fresh control traffic should not mark the direct peer link-dead"
    );
    assert!(
        node.session_direct_path_blocks_direct_payload(&peer_addr, Node::now_ms()),
        "fresh control traffic must not keep unreturned endpoint data pinned to the suspect direct path"
    );
    assert!(
        node.retry_pending.contains_key(&peer_addr),
        "fresh control traffic must keep direct-probe retry until direct payload return validates the path"
    );
    assert!(
        node.pending_lookups.contains_key(&peer_addr),
        "active endpoint sends without authenticated endpoint return should warm fallback even when control is fresh"
    );
    assert!(
        node.find_next_hop(&peer_addr).is_none(),
        "with a fallback peer available, payload should queue while fallback discovery warms a route"
    );
}

#[tokio::test]
async fn fresh_bootstrap_path_keeps_static_direct_refresh_pending() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .learned()
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.peers.push(peer_config.clone());
    let link_session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");
    node.config.node.heartbeat_interval_secs = 10;
    node.config.node.link_dead_timeout_secs = 30;
    node.config.node.fast_link_dead_timeout_secs = 5;

    let bootstrap_transport = TransportId::new(77);
    let mut active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        ActivePeerSession {
            session: link_session,
            our_index: crate::utils::index::SessionIndex::new(11),
            their_index: crate::utils::index::SessionIndex::new(12),
            transport_id: bootstrap_transport,
            current_addr: crate::transport::TransportAddr::from_string("198.51.100.9:44444"),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: None,
        },
    );
    let now_ms = Node::now_ms();
    active.touch(now_ms);
    node.peers.insert(peer_addr, active);
    super::super::seed_dataplane_fmp_rx_for_test(&mut node, peer_addr, std::time::Duration::ZERO);
    node.bootstrap_transports.mark(bootstrap_transport);

    let mut retry = super::super::retry::RetryState::new(peer_config);
    retry.reconnect = true;
    retry.retry_after_ms = now_ms;
    node.retry_pending.insert(peer_addr, retry);

    node.check_link_heartbeats().await;

    assert!(
        node.retry_pending.contains_key(&peer_addr),
        "a fresh adopted traversal path must not cancel refresh toward configured direct endpoints"
    );
}

#[tokio::test]
async fn fresh_bootstrap_endpoint_data_clears_static_direct_refresh_pending() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let app_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .learned()
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

    let bootstrap_transport = TransportId::new(77);
    let mut active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        ActivePeerSession {
            session: link_session,
            our_index: crate::utils::index::SessionIndex::new(11),
            their_index: crate::utils::index::SessionIndex::new(12),
            transport_id: bootstrap_transport,
            current_addr: crate::transport::TransportAddr::from_string("198.51.100.9:44444"),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: None,
        },
    );
    active.touch(Node::now_ms());
    node.peers.insert(peer_addr, active);
    super::super::seed_dataplane_fmp_rx_for_test(&mut node, peer_addr, std::time::Duration::ZERO);
    node.bootstrap_transports.mark(bootstrap_transport);

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

    assert!(
        !node.active_peer_should_keep_direct_retry(&peer_addr, &peer_config),
        "fresh endpoint data on an adopted path should quiet stale static-endpoint probing"
    );

    let mut retry = super::super::retry::RetryState::new(peer_config);
    retry.reconnect = true;
    retry.retry_after_ms = now_ms;
    node.retry_pending.insert(peer_addr, retry);

    node.check_link_heartbeats().await;

    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "fresh authenticated endpoint return on a bootstrap path should clear direct-probe retry"
    );
}

include!("liveness_window_control.rs");
include!("liveness_window_return.rs");
include!("liveness_window_failures.rs");
