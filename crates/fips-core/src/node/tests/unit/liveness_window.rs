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
        "the owner must expire and remove stale degradation holds"
    );
    assert!(
        !degradation.clear(&dest),
        "expired degradation state should already be removed"
    );

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
async fn quiet_recent_endpoint_path_refresh_keeps_direct_payload_without_demoting_peer() {
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

    let mut active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    active.mmp_mut().expect("mmp").receiver.record_recv(
        1,
        100,
        64,
        false,
        std::time::Instant::now() - std::time::Duration::from_secs(11),
    );
    node.peers.insert(peer_addr, active);
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
        link_session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    active.mmp_mut().expect("mmp").receiver.record_recv(
        1,
        100,
        64,
        false,
        std::time::Instant::now() - std::time::Duration::from_secs(11),
    );
    node.peers.insert(peer_addr, active);
    node.peers.insert(
        transit_addr,
        ActivePeer::new(transit_peer, LinkId::new(9), 0),
    );
    node.learn_reverse_route(peer_addr, transit_addr);

    let mut session = crate::node::session::SessionEntry::new(
        peer_addr,
        peer_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(endpoint_session),
        1_000,
        true,
    );
    session.record_sent(512);
    session.touch_outbound_frame(Node::now_ms());
    session.record_outbound_next_hop(peer_addr);
    node.sessions.insert(peer_addr, session);

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

    let mut active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        link_session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    active.mmp_mut().expect("mmp").receiver.record_recv(
        1,
        100,
        64,
        false,
        std::time::Instant::now() - std::time::Duration::from_secs(11),
    );
    node.peers.insert(peer_addr, active);

    let mut session = crate::node::session::SessionEntry::new(
        peer_addr,
        peer_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(endpoint_session),
        1_000,
        true,
    );
    session.record_outbound_next_hop(peer_addr);
    session.record_recv(512);
    session.touch_inbound_data_frame(Node::now_ms());
    node.sessions.insert(peer_addr, session);

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
async fn authenticated_control_return_does_not_keep_direct_payload_route_trusted() {
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
        link_session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    active.mmp_mut().expect("mmp").receiver.record_recv(
        1,
        100,
        64,
        false,
        std::time::Instant::now() - std::time::Duration::from_secs(11),
    );
    node.peers.insert(peer_addr, active);
    node.peers.insert(
        transit_addr,
        ActivePeer::new(transit_peer, LinkId::new(9), 0),
    );
    node.learn_reverse_route(peer_addr, transit_addr);

    let now_ms = Node::now_ms();
    let mut session = crate::node::session::SessionEntry::new(
        peer_addr,
        peer_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(endpoint_session),
        1_000,
        true,
    );
    session.record_sent(512);
    session.touch_outbound_frame(now_ms);
    session.touch_inbound_frame(now_ms);
    session.record_outbound_next_hop(peer_addr);
    node.sessions.insert(peer_addr, session);

    node.check_link_heartbeats().await;

    assert!(
        node.retry_pending.contains_key(&peer_addr),
        "authenticated control/session return alone should not suppress proactive direct refresh"
    );
    assert!(
        node.pending_lookups.contains_key(&peer_addr),
        "authenticated control/session return alone should warm fallback discovery when endpoint data is not returning"
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
        link_session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    active.mmp_mut().expect("mmp").receiver.record_recv(
        1,
        100,
        64,
        false,
        std::time::Instant::now(),
    );
    active.touch(Node::now_ms());
    node.peers.insert(peer_addr, active);
    node.peers.insert(
        transit_addr,
        ActivePeer::new(transit_peer, LinkId::new(9), 0),
    );

    let now_ms = Node::now_ms();
    let mut session = crate::node::session::SessionEntry::new(
        peer_addr,
        peer_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(endpoint_session),
        1_000,
        true,
    );
    session.record_sent(512);
    session.touch_outbound_frame(now_ms);
    session.touch_inbound_frame(now_ms);
    session.record_outbound_next_hop(peer_addr);
    node.sessions.insert(peer_addr, session);

    let mut retry = super::super::retry::RetryState::new(peer_config);
    retry.reconnect = true;
    retry.retry_after_ms = now_ms;
    node.retry_pending.insert(peer_addr, retry);

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
        node.pending_lookups.contains_key(&peer_addr),
        "active endpoint sends without authenticated endpoint return should warm fallback even when control is fresh"
    );
    let fallback = node.find_next_hop(&peer_addr).expect("fallback route");
    assert_eq!(
        fallback.node_addr(),
        &transit_addr,
        "direct-probe fallback warming should seed a learned fallback route before the next payload burst"
    );
}

#[tokio::test]
async fn fresh_control_with_unreturned_endpoint_data_blocks_direct_without_known_fallback() {
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
        link_session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    active.mmp_mut().expect("mmp").receiver.record_recv(
        1,
        100,
        64,
        false,
        std::time::Instant::now(),
    );
    active.touch(Node::now_ms());
    node.peers.insert(peer_addr, active);

    let now_ms = Node::now_ms();
    let mut session = crate::node::session::SessionEntry::new(
        peer_addr,
        peer_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(endpoint_session),
        1_000,
        true,
    );
    session.record_sent(512);
    session.touch_outbound_frame(now_ms);
    session.touch_inbound_frame(now_ms);
    session.record_outbound_next_hop(peer_addr);
    node.sessions.insert(peer_addr, session);

    node.check_link_heartbeats().await;

    let direct = node.get_peer(&peer_addr).expect("direct peer retained");
    assert!(
        direct.is_healthy() && direct.can_send(),
        "control-fresh peer should stay connected and probeable"
    );
    assert!(
        node.session_direct_path_blocks_direct_payload(&peer_addr, Node::now_ms()),
        "unreturned endpoint data should block payload routing over the suspect direct path"
    );
    assert!(
        node.pending_lookups.contains_key(&peer_addr),
        "fallback discovery should start immediately when direct payload is blocked"
    );
    assert!(
        node.find_next_hop(&peer_addr).is_none(),
        "without a known fallback, payload should queue instead of continuing into the blackholed direct tuple"
    );
}

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

    let mut active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        link_session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    active.mmp_mut().expect("mmp").receiver.record_recv(
        1,
        100,
        64,
        false,
        std::time::Instant::now() - std::time::Duration::from_secs(11),
    );
    node.peers.insert(peer_addr, active);

    let now_ms = Node::now_ms();
    let mut session = crate::node::session::SessionEntry::new(
        app_addr,
        app_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(endpoint_session),
        1_000,
        true,
    );
    session.record_sent(512);
    session.touch_outbound_frame(now_ms);
    session.record_recv(512);
    session.touch_inbound_data_frame(now_ms);
    session.record_outbound_next_hop(peer_addr);
    node.sessions.insert(app_addr, session);

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
        link_session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("198.51.100.20:61062"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    active.mmp_mut().expect("mmp").receiver.record_recv(
        1,
        100,
        64,
        false,
        std::time::Instant::now() - std::time::Duration::from_secs(11),
    );
    active.touch(Node::now_ms());
    node.peers.insert(peer_addr, active);

    assert!(
        !node.active_peer_should_keep_direct_retry(&peer_addr, &peer_config),
        "a healthy discovered UDP path should not keep retrying a mismatched static LAN hint"
    );

    let now_ms = Node::now_ms();
    let mut session = crate::node::session::SessionEntry::new(
        app_addr,
        app_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(endpoint_session),
        1_000,
        true,
    );
    session.record_sent(512);
    session.touch_outbound_frame(now_ms);
    session.record_recv(512);
    session.touch_inbound_data_frame(now_ms);
    session.record_outbound_next_hop(peer_addr);
    node.sessions.insert(app_addr, session);

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

    let mut quiet_active = ActivePeer::with_session(
        quiet_peer,
        LinkId::new(7),
        0,
        session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("198.51.100.57:51820"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    quiet_active.mmp_mut().expect("mmp").receiver.record_recv(
        1,
        100,
        64,
        false,
        std::time::Instant::now() - std::time::Duration::from_secs(6),
    );
    node.peers.insert(quiet_addr, quiet_active);

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
    assert!(fmp_plaintext_is_bulk_session_datagram(&datagram.encode()));
    let traffic = classify_fmp_plaintext_traffic(&datagram.encode());
    assert!(traffic.bulk_endpoint_data);
    assert!(
        !traffic.drop_on_backpressure,
        "encrypted FSP bulk may carry TCP endpoint data, so the generic FMP path must not drop it"
    );

    let coords_payload =
        crate::node::session_wire::build_fsp_header(8, crate::node::session_wire::FSP_FLAG_CP, 0)
            .to_vec();
    let coords_datagram = crate::protocol::SessionDatagram::new(src, dst, coords_payload);
    assert!(
        !fmp_plaintext_is_bulk_session_datagram(&coords_datagram.encode()),
        "coordinate-carrying session packets warm fallback routes and must stay in the control lane"
    );
    let traffic = classify_fmp_plaintext_traffic(&coords_datagram.encode());
    assert!(!traffic.bulk_endpoint_data);
    assert!(!traffic.drop_on_backpressure);

    let heartbeat = [crate::protocol::LinkMessageType::Heartbeat.to_byte()];
    assert!(!fmp_plaintext_is_bulk_session_datagram(&heartbeat));

    let setup_prefix = crate::node::session_wire::build_fsp_handshake_prefix(
        crate::node::session_wire::FSP_PHASE_MSG1,
        0,
    );
    let setup_datagram = crate::protocol::SessionDatagram::new(src, dst, setup_prefix.to_vec());
    assert!(!fmp_plaintext_is_bulk_session_datagram(
        &setup_datagram.encode()
    ));
}

#[test]
fn endpoint_payload_tcp_classifier_handles_common_ip_packets() {
    let mut ipv4_tcp = [0u8; 20];
    ipv4_tcp[0] = 0x45;
    ipv4_tcp[9] = 6;
    assert!(endpoint_payload_is_tcp(&ipv4_tcp));

    let mut ipv4_udp = ipv4_tcp;
    ipv4_udp[9] = 17;
    assert!(!endpoint_payload_is_tcp(&ipv4_udp));

    let mut ipv4_tcp_with_options = [0u8; 24];
    ipv4_tcp_with_options[0] = 0x46;
    ipv4_tcp_with_options[9] = 6;
    assert!(endpoint_payload_is_tcp(&ipv4_tcp_with_options));

    let mut ipv6_tcp = [0u8; 40];
    ipv6_tcp[0] = 0x60;
    ipv6_tcp[6] = 6;
    assert!(endpoint_payload_is_tcp(&ipv6_tcp));

    let mut ipv6_udp = ipv6_tcp;
    ipv6_udp[6] = 17;
    assert!(!endpoint_payload_is_tcp(&ipv6_udp));

    let mut ipv6_hop_tcp = vec![0u8; 48];
    ipv6_hop_tcp[0] = 0x60;
    ipv6_hop_tcp[6] = 0;
    ipv6_hop_tcp[40] = 6;
    ipv6_hop_tcp[41] = 0;
    assert!(endpoint_payload_is_tcp(&ipv6_hop_tcp));

    let mut ipv6_frag_tcp = vec![0u8; 48];
    ipv6_frag_tcp[0] = 0x60;
    ipv6_frag_tcp[6] = 44;
    ipv6_frag_tcp[40] = 6;
    assert!(endpoint_payload_is_tcp(&ipv6_frag_tcp));

    assert!(!endpoint_payload_is_tcp(&[]));
    assert!(!endpoint_payload_is_tcp(&[0x60; 8]));
}

#[test]
fn endpoint_payload_traffic_classifier_prioritizes_control_sized_packets() {
    fn ipv6_tcp_packet(flags: u8, tcp_payload_len: usize) -> Vec<u8> {
        let tcp_len = 20 + tcp_payload_len;
        let mut packet = vec![0u8; 40 + tcp_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
        packet[6] = 6;
        packet[40 + 12] = 5 << 4;
        packet[40 + 13] = flags;
        packet
    }

    let tcp_ack_packet = ipv6_tcp_packet(0x10, 0);
    let tcp_ack = classify_endpoint_payload(&tcp_ack_packet);
    assert_eq!(tcp_ack.lane(), EndpointPayloadLane::Priority);
    assert!(!tcp_ack.drop_on_backpressure());
    assert_eq!(
        endpoint_command_lane_for_payload(&tcp_ack_packet),
        EndpointCommandLane::Priority
    );

    let tcp_syn_packet = ipv6_tcp_packet(0x02, 0);
    let tcp_syn = classify_endpoint_payload(&tcp_syn_packet);
    assert_eq!(tcp_syn.lane(), EndpointPayloadLane::Priority);
    assert!(!tcp_syn.drop_on_backpressure());
    assert_eq!(
        endpoint_command_lane_for_payload(&tcp_syn_packet),
        EndpointCommandLane::Priority
    );

    let tiny_tcp_data_packet = ipv6_tcp_packet(0x18, 64);
    let tiny_tcp_data = classify_endpoint_payload(&tiny_tcp_data_packet);
    assert_eq!(tiny_tcp_data.lane(), EndpointPayloadLane::Priority);
    assert!(!tiny_tcp_data.drop_on_backpressure());
    assert_eq!(
        endpoint_command_lane_for_payload(&tiny_tcp_data_packet),
        EndpointCommandLane::Priority
    );

    let bulk_tcp_data_packet = ipv6_tcp_packet(0x18, 512);
    let bulk_tcp_data = classify_endpoint_payload(&bulk_tcp_data_packet);
    assert_eq!(bulk_tcp_data.lane(), EndpointPayloadLane::Bulk);
    assert!(!bulk_tcp_data.drop_on_backpressure());
    assert_eq!(
        endpoint_command_lane_for_payload(&bulk_tcp_data_packet),
        EndpointCommandLane::Bulk
    );

    let mut icmpv6_packet = vec![0u8; 48];
    icmpv6_packet[0] = 0x60;
    icmpv6_packet[4..6].copy_from_slice(&8u16.to_be_bytes());
    icmpv6_packet[6] = 58;
    let icmpv6 = classify_endpoint_payload(&icmpv6_packet);
    assert_eq!(icmpv6.lane(), EndpointPayloadLane::Priority);
    assert!(!icmpv6.drop_on_backpressure());
    assert_eq!(
        endpoint_command_lane_for_payload(&icmpv6_packet),
        EndpointCommandLane::Priority
    );

    let mut udp_packet = vec![0u8; 48];
    udp_packet[0] = 0x60;
    udp_packet[4..6].copy_from_slice(&8u16.to_be_bytes());
    udp_packet[6] = 17;
    let udp = classify_endpoint_payload(&udp_packet);
    assert_eq!(udp.lane(), EndpointPayloadLane::Bulk);
    assert!(udp.drop_on_backpressure());
    assert_eq!(
        endpoint_command_lane_for_payload(&udp_packet),
        EndpointCommandLane::Bulk
    );
}

#[test]
fn endpoint_payload_traffic_classifier_prioritizes_ipv4_icmp_ping() {
    let mut icmpv4_packet = vec![0u8; 28];
    icmpv4_packet[0] = 0x45;
    icmpv4_packet[2..4].copy_from_slice(&28u16.to_be_bytes());
    icmpv4_packet[9] = 1;
    icmpv4_packet[20] = 8;

    let icmpv4 = classify_endpoint_payload(&icmpv4_packet);
    assert!(
        icmpv4.lane() == EndpointPayloadLane::Priority,
        "IPv4 tunnel ping must use the reserved lane"
    );
    assert!(
        !icmpv4.drop_on_backpressure(),
        "IPv4 tunnel ping is the interactive canary and must not be bulk-dropped"
    );
    assert_eq!(
        endpoint_command_lane_for_payload(&icmpv4_packet),
        EndpointCommandLane::Priority
    );
}

#[test]
fn endpoint_flow_dispatch_key_tracks_inner_ip_transport_flow() {
    fn ipv6_tcp_flow(src_port: u16, dst_port: u16, tcp_payload_len: usize) -> Vec<u8> {
        let tcp_len = 20 + tcp_payload_len;
        let mut packet = vec![0u8; 40 + tcp_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
        packet[6] = 6;
        packet[8..24]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[40..42].copy_from_slice(&src_port.to_be_bytes());
        packet[42..44].copy_from_slice(&dst_port.to_be_bytes());
        packet[40 + 12] = 5 << 4;
        packet[40 + 13] = 0x18;
        packet
    }

    fn ipv4_tcp_flow(src_port: u16, dst_port: u16, tcp_payload_len: usize) -> Vec<u8> {
        let total_len = 20 + 20 + tcp_payload_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 2]);
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet[20 + 12] = 5 << 4;
        packet[20 + 13] = 0x18;
        packet
    }

    fn ipv4_tcp_fragment(fake_src_port: u16, fake_dst_port: u16, fragment_bits: u16) -> Vec<u8> {
        let mut packet = ipv4_tcp_flow(fake_src_port, fake_dst_port, 8);
        packet[6..8].copy_from_slice(&fragment_bits.to_be_bytes());
        packet
    }

    fn ipv6_tcp_fragment(fake_src_port: u16, fake_dst_port: u16) -> Vec<u8> {
        let tcp_len = 20;
        let mut packet = vec![0u8; 40 + 8 + tcp_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((8 + tcp_len) as u16).to_be_bytes());
        packet[6] = 44;
        packet[8..24]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[40] = 6;
        packet[42..44].copy_from_slice(&1u16.to_be_bytes());
        packet[48..50].copy_from_slice(&fake_src_port.to_be_bytes());
        packet[50..52].copy_from_slice(&fake_dst_port.to_be_bytes());
        packet[48 + 12] = 5 << 4;
        packet[48 + 13] = 0x18;
        packet
    }

    let flow_a = ipv6_tcp_flow(1000, 443, 512);
    let same_flow_larger_payload = ipv6_tcp_flow(1000, 443, 1024);
    let flow_b = ipv6_tcp_flow(1001, 443, 512);
    let ipv4_first_fragment = ipv4_tcp_fragment(1000, 443, 0x2000);
    let ipv4_later_fragment = ipv4_tcp_fragment(2000, 8443, 0x0001);
    let ipv6_first_fragment = ipv6_tcp_fragment(1000, 443);
    let ipv6_later_fragment = ipv6_tcp_fragment(2000, 8443);

    assert_eq!(
        endpoint_flow_dispatch_key(&flow_a).map(|key| key.get()),
        endpoint_flow_dispatch_key(&same_flow_larger_payload).map(|key| key.get()),
        "payload length must not split one TCP stream across workers"
    );
    assert_ne!(
        endpoint_flow_dispatch_key(&flow_a).map(|key| key.get()),
        endpoint_flow_dispatch_key(&flow_b).map(|key| key.get()),
        "different TCP streams may use different worker admission keys"
    );
    assert_eq!(
        endpoint_flow_dispatch_key(&ipv4_first_fragment).map(|key| key.get()),
        endpoint_flow_dispatch_key(&ipv4_later_fragment).map(|key| key.get()),
        "IPv4 fragments must not split one fragmented datagram by apparent port bytes"
    );
    assert_eq!(
        endpoint_flow_dispatch_key(&ipv6_first_fragment).map(|key| key.get()),
        endpoint_flow_dispatch_key(&ipv6_later_fragment).map(|key| key.get()),
        "IPv6 fragments must not split one fragmented datagram by apparent port bytes"
    );
    assert!(endpoint_flow_dispatch_key(&ipv4_tcp_flow(1000, 443, 512)).is_some());
    assert!(endpoint_flow_dispatch_key(&[0, 1, 2, 3]).is_none());
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
    let mut active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    active.mmp_mut().expect("mmp").receiver.record_recv(
        1,
        100,
        64,
        false,
        std::time::Instant::now() - std::time::Duration::from_secs(29),
    );
    node.peers.insert(peer_addr, active);

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

#[tokio::test]
async fn local_route_failure_does_not_collapse_recent_endpoint_liveness_window() {
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
    let mut active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    active.mmp_mut().expect("mmp").receiver.record_recv(
        1,
        100,
        64,
        false,
        std::time::Instant::now() - std::time::Duration::from_secs(6),
    );
    node.peers.insert(peer_addr, active);
    node.local_send_failures
        .record_failure(peer_addr, std::time::Instant::now());

    node.check_link_heartbeats().await;

    assert!(
        node.get_peer(&peer_addr).expect("peer").is_healthy(),
        "a transient local route error must not shrink a recent endpoint path from the traversal liveness window to fast-dead"
    );
    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "recent endpoint path should not be reprobed until its traversal liveness window expires"
    );
}

#[tokio::test]
async fn recent_authenticated_fmp_receive_prevents_traversal_link_dead() {
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
    let mut active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    active.mmp_mut().expect("mmp").receiver.record_recv(
        1,
        100,
        64,
        false,
        std::time::Instant::now() - std::time::Duration::from_secs(23),
    );
    active.touch(Node::now_ms());
    node.peers.insert(peer_addr, active);

    node.check_link_heartbeats().await;

    assert!(
        node.get_peer(&peer_addr).expect("peer").is_healthy(),
        "recent authenticated FMP traffic must keep traversal liveness warm even if MMP is stale"
    );
    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "a live authenticated path should not schedule link-dead direct reprobe"
    );
}

#[tokio::test]
async fn link_dead_after_rx_loop_timeout_does_not_cool_down_traversal_path() {
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
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).expect("node");
    node.config.node.link_dead_timeout_secs = 30;

    let mut active = ActivePeer::new(peer, LinkId::new(7), 0);
    active.set_current_addr(
        TransportId::new(1),
        &crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
    );
    node.peers.insert(peer_addr, active);

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    node.nostr_discovery = Some(bootstrap.clone());
    node.mark_rx_loop_maintenance_timeout();

    for now_ms in [1_000, 2_000, 3_000, 4_000, 5_000] {
        node.record_link_dead_path_failure(&peer_addr, now_ms).await;
    }

    assert!(
        bootstrap.cooldown_until(&peer_config.npub, 5_000).is_none(),
        "local rx-loop stalls must not be counted as repeated bad traversal paths"
    );
    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "skipping traversal penalty must not seed cooldown retry state"
    );
}

#[tokio::test]
async fn link_dead_marks_direct_path_stale_and_preserves_queued_packets() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority(
            "udp",
            "203.0.113.9:2121",
            1,
        )],
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
    node.config.node.heartbeat_interval_secs = 2;
    node.config.node.link_dead_timeout_secs = 30;
    node.config.node.fast_link_dead_timeout_secs = 5;

    let mut active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        link_session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    active.mmp_mut().expect("mmp").receiver.record_recv(
        1,
        100,
        64,
        false,
        std::time::Instant::now() - std::time::Duration::from_secs(31),
    );
    active.set_handshake_msg2(vec![0x02, 0x03, 0x04]);
    node.peers.insert(peer_addr, active);
    node.peers.insert(
        transit_addr,
        ActivePeer::new(transit_peer, LinkId::new(9), 0),
    );
    node.learn_reverse_route(peer_addr, transit_addr);

    node.sessions.insert(
        peer_addr,
        crate::node::session::SessionEntry::new(
            peer_addr,
            peer_identity.pubkey_full(),
            crate::node::session::EndToEndState::Established(endpoint_session),
            1_000,
            true,
        ),
    );
    node.pending_session_traffic
        .push_tun_packet(peer_addr, vec![1, 2, 3], usize::MAX, usize::MAX);
    node.pending_session_traffic.push_endpoint_data(
        peer_addr,
        crate::node::EndpointDataPayload::new(vec![4, 5, 6]),
        usize::MAX,
        usize::MAX,
    );

    node.check_link_heartbeats().await;

    assert!(
        node.peers.contains_key(&peer_addr),
        "link-dead should keep the authenticated peer identity"
    );
    assert!(
        node.get_peer(&peer_addr).expect("peer").can_send(),
        "link-dead should keep the stale direct path sendable for probes and late recovery"
    );
    assert!(
        !node.get_peer(&peer_addr).expect("peer").is_healthy(),
        "link-dead should remove the dead direct path from healthy-direct routing"
    );
    assert!(
        node.get_peer(&peer_addr)
            .expect("peer")
            .handshake_msg2()
            .is_none(),
        "link-dead recovery must not answer fresh retry msg1 with stale msg2"
    );
    assert!(
        node.sessions
            .get(&peer_addr)
            .is_some_and(|entry| entry.is_established()),
        "link-dead should preserve the established FSP session so fallback can carry traffic immediately"
    );
    assert_eq!(
        node.pending_session_traffic
            .tun_packets_for(&peer_addr)
            .map(|queue| queue.len()),
        Some(1),
        "queued TUN packets should survive direct link teardown"
    );
    assert_eq!(
        node.pending_session_traffic
            .endpoint_data_for(&peer_addr)
            .map(|queue| queue.len()),
        Some(1),
        "queued endpoint data should survive direct link teardown"
    );
    assert!(
        node.retry_pending.contains_key(&peer_addr),
        "direct reprobe should still be scheduled"
    );
    assert!(
        node.pending_lookups.contains_key(&peer_addr),
        "fallback lookup should start while queued packets are preserved"
    );
    assert!(
        node.session_direct_path_is_degraded(&peer_addr, Node::now_ms()),
        "link-dead should mark payload routing away from the suspect direct path"
    );
    let fallback = node.find_next_hop(&peer_addr).expect("fallback route");
    assert_eq!(
        fallback.node_addr(),
        &transit_addr,
        "fallback route should carry payload traffic while direct remains probeable"
    );

    let first_retry_after = node
        .retry_pending
        .get(&peer_addr)
        .expect("direct reprobe should stay scheduled")
        .retry_after_ms;

    node.check_link_heartbeats().await;

    assert!(
        node.get_peer(&peer_addr).expect("peer").can_send(),
        "a stale path should remain probeable instead of flapping to reconnecting"
    );
    assert_eq!(
        node.retry_pending
            .get(&peer_addr)
            .expect("direct reprobe should stay scheduled")
            .retry_after_ms,
        first_retry_after,
        "stale direct paths should not be repeatedly link-dead demoted every maintenance tick"
    );
}

#[test]
fn reconnecting_auto_connect_peer_is_eligible_for_graph_session_warmup() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config);
    let mut node = Node::new(config).expect("node");

    let mut active = ActivePeer::new(peer, LinkId::new(7), 0);
    active.mark_reconnecting();
    node.peers.insert(peer_addr, active);

    assert!(
        node.should_warm_auto_connect_session(&peer_addr),
        "a reconnecting direct peer should still warm an end-to-end fallback session"
    );
    assert!(
        node.find_next_hop(&peer_addr).is_none(),
        "a reconnecting direct peer must not be selected as a data next-hop"
    );
}
