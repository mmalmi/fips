use super::*;

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
    // Model the production race where route selection notices expired direct
    // trust and sends through a known relay just before the heartbeat pass.
    // The latest outbound hop is then indirect, so the direct-only predicate
    // must not lose the decision to keep probing the configured carrier.
    seed_dataplane_fsp_data_sent_for_test(&mut node, peer_addr, transit_addr, now_ms + 1);

    node.check_link_heartbeats().await;

    assert!(
        node.retry_pending.contains_key(&peer_addr),
        "automatic fallback must keep probing the direct path while payload return is missing"
    );
    assert!(
        node.session_direct_path_degradation_active(&peer_addr, Node::now_ms()),
        "automatic fallback must retain the degraded-direct decision until direct payload validates recovery"
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
