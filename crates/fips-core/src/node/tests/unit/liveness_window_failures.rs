#[tokio::test]
async fn local_route_payload_failure_degrades_direct_and_warms_retry() {
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

    assert_eq!(
        node.find_next_hop(&peer_addr).map(|peer| *peer.node_addr()),
        Some(peer_addr),
        "soft-stale traversal paths remain last-resort routes until a hard send failure arrives"
    );

    node.recover_direct_payload_send_failure(
        peer_addr,
        peer_addr,
        &crate::node::NodeError::LocalRouteUnavailable(
            "send failed: Network is unreachable (os error 51)".to_string(),
        ),
    );

    assert!(
        node.retry_pending.contains_key(&peer_addr),
        "local route failures should schedule a short direct-path retry"
    );
    assert!(
        node.find_next_hop(&peer_addr).is_none(),
        "after a local route payload failure, stale direct must stop blackholing payload while fallback warms"
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
        std::time::Duration::from_secs(6),
    );
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
    active.touch(Node::now_ms());
    node.peers.insert(peer_addr, active);
    super::super::seed_dataplane_fmp_rx_for_test(
        &mut node,
        peer_addr,
        std::time::Duration::from_secs(23),
    );

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
async fn outbound_fmp_send_does_not_refresh_direct_path_liveness() {
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
    assert!(node.sync_dataplane_fmp_owner(&peer_addr));
    assert!(
        node.dataplane
            .record_authenticated_fmp_mmp_receive(
                crate::dataplane::DataplaneAuthenticatedFmpMmpReceive::new(
                    peer_addr,
                    1,
                    100,
                    64,
                    false,
                    false,
                    std::time::Instant::now() - std::time::Duration::from_secs(23),
                ),
            )
            .is_ok(),
        "dataplane FMP MMP receive bookkeeping recorded"
    );
    assert!(
        node.peers.record_fmp_send_bookkeeping(&peer_addr, 64),
        "send bookkeeping recorded"
    );

    node.check_link_heartbeats().await;

    assert!(
        node.retry_pending.contains_key(&peer_addr),
        "outbound FMP send bookkeeping must not keep a quiet direct path trusted"
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
    active.set_handshake_msg2(vec![0x02, 0x03, 0x04]);
    node.peers.insert(peer_addr, active);
    super::super::seed_dataplane_fmp_rx_for_test(
        &mut node,
        peer_addr,
        std::time::Duration::from_secs(31),
    );
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
    node.pending_session_traffic
        .push_endpoint_data_batch_with_enqueued_at_ms(
            peer_addr,
            vec![
                crate::node::EndpointDataPayload::from_packet_payload(vec![4, 5, 6])
                    .expect("test endpoint payload"),
            ],
            usize::MAX,
            usize::MAX,
            crate::time::now_ms(),
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
