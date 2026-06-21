use super::*;

#[tokio::test]
async fn test_session_receiver_loss_degrades_direct_and_uses_fallback() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let fallback_next_hop = *node.peer_ids().next().expect("fallback peer");
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_npub = crate::encode_npub(&remote.pubkey());

    node.config.peers.push(crate::config::PeerConfig {
        npub: remote_npub,
        alias: Some("lossy-direct".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    add_direct_peer_for_identity(&mut node, &remote);
    install_established_session_with_mmp(&mut node, &remote);
    node.learn_reverse_route(remote_addr, fallback_next_hop);
    node.sessions
        .get_mut(&remote_addr)
        .expect("session")
        .record_outbound_next_hop(remote_addr);

    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(remote_addr),
        "healthy direct should initially hide fallback"
    );

    let baseline = SessionReceiverReport {
        highest_counter: 100,
        cumulative_packets_recv: 100,
        cumulative_bytes_recv: 10_000,
        timestamp_echo: 0,
        dwell_time: 0,
        max_burst_loss: 0,
        mean_burst_loss: 0,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
        interval_packets_recv: 0,
        interval_bytes_recv: 0,
    }
    .encode();
    node.handle_session_receiver_report(&remote_addr, &baseline)
        .await;

    let lossy_timestamp_echo = session_timestamp_echo_for(&node, &remote_addr, 50);
    let lossy = SessionReceiverReport {
        highest_counter: 120,
        cumulative_packets_recv: 118,
        cumulative_bytes_recv: 11_800,
        timestamp_echo: lossy_timestamp_echo,
        dwell_time: 0,
        max_burst_loss: 0,
        mean_burst_loss: 0,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
        interval_packets_recv: 12,
        interval_bytes_recv: 1_200,
    }
    .encode();
    node.handle_session_receiver_report(&remote_addr, &lossy)
        .await;

    assert!(
        node.session_direct_path_is_degraded(&remote_addr, Node::now_ms()),
        "session loss over direct should mark only the direct path suspect"
    );
    assert!(
        node.retry_pending.contains_key(&remote_addr),
        "direct reprobe should be scheduled without removing the session"
    );
    assert!(
        node.pending_lookups.contains_key(&remote_addr),
        "fallback discovery should be started while direct probes continue"
    );
    assert!(
        node.sessions
            .get(&remote_addr)
            .is_some_and(|entry| entry.is_established()),
        "session must remain installed while route preference changes"
    );
    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(fallback_next_hop),
        "degraded direct should not block learned fallback"
    );
    assert!(
        node.sessions
            .get(&remote_addr)
            .and_then(|entry| entry.mmp())
            .and_then(|mmp| mmp.metrics.srtt_ms())
            .is_some(),
        "loss-driven route changes in full session MMP must be backed by a valid RTT sample"
    );
}

#[test]
fn test_stale_direct_session_trust_prefers_fallback_before_loss_sample() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let fallback_next_hop = *node.peer_ids().next().expect("fallback peer");
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_npub = crate::encode_npub(&remote.pubkey());

    node.config.peers.push(crate::config::PeerConfig {
        npub: remote_npub,
        alias: Some("quiet-direct-session".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    add_direct_peer_for_identity(&mut node, &remote);
    install_established_session_with_mmp(&mut node, &remote);
    node.learn_reverse_route(remote_addr, fallback_next_hop);

    let session = node.sessions.get_mut(&remote_addr).expect("session");
    session.record_sent(128);
    session.touch_outbound_frame(Node::now_ms());
    session.record_outbound_next_hop(remote_addr);
    assert!(
        session
            .last_authenticated_inbound_data_age_ms(Node::now_ms())
            .is_none_or(|age| age > 10_000),
        "fixture should model a direct session that sent data but has no recent authenticated inbound data proof"
    );

    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(fallback_next_hop),
        "stale direct session trust should let known fallback carry the next burst before loss reports arrive"
    );
}

#[test]
fn test_stale_direct_session_trust_without_fallback_uses_direct_last_resort() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_npub = crate::encode_npub(&remote.pubkey());

    node.config.peers.push(crate::config::PeerConfig {
        npub: remote_npub,
        alias: Some("quiet-direct-no-fallback".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    add_direct_peer_for_identity(&mut node, &remote);
    install_established_session_with_mmp(&mut node, &remote);

    let session = node.sessions.get_mut(&remote_addr).expect("session");
    session.record_sent(128);
    session.touch_outbound_frame(Node::now_ms());
    session.record_outbound_next_hop(remote_addr);

    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(remote_addr),
        "an active one-way direct session with no known fallback must keep using the healthy direct route while recovery probes run"
    );
}

#[test]
fn test_stale_discovered_direct_session_trust_without_fallback_queues_payload() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_npub = crate::encode_npub(&remote.pubkey());
    let discovered_addr = crate::transport::TransportAddr::from_string("203.0.113.9:2121");

    node.config.peers.push(crate::config::PeerConfig {
        npub: remote_npub,
        alias: Some("quiet-discovered-no-fallback".to_string()),
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    node.configured_peer_send_weights =
        crate::node::ConfiguredPeerSendWeights::from_config(&node.config);
    add_direct_peer_for_identity(&mut node, &remote);
    node.peers
        .get_mut(&remote_addr)
        .expect("direct peer")
        .set_current_addr(TransportId::new(1), &discovered_addr);
    install_established_session_with_mmp(&mut node, &remote);

    let session = node.sessions.get_mut(&remote_addr).expect("session");
    session.record_sent(128);
    session.touch_outbound_frame(Node::now_ms());
    session.record_outbound_next_hop(remote_addr);
    assert!(
        node.session_direct_path_exclusive_trust_expired(&remote_addr, Node::now_ms()),
        "fixture should model active one-way endpoint data without authenticated return"
    );
    let configured_peer = node
        .configured_peer(&remote_addr)
        .expect("configured peer")
        .clone();
    assert!(
        node.active_peer_uses_traversal_path(&remote_addr, &configured_peer),
        "fixture should model a discovered endpoint hint, not an operator-pinned static path"
    );

    assert!(
        node.find_next_hop(&remote_addr).is_none(),
        "untrusted discovered endpoint hints should queue payload while discovery/probes recover"
    );
}

#[test]
fn test_pending_direct_probe_alone_keeps_healthy_direct_over_fallback() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let fallback_next_hop = *node.peer_ids().next().expect("fallback peer");
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_npub = crate::encode_npub(&remote.pubkey());

    let peer_config = crate::config::PeerConfig {
        npub: remote_npub,
        alias: Some("pending-direct-probe".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers.push(peer_config.clone());
    add_direct_peer_for_identity(&mut node, &remote);
    install_established_session_with_mmp(&mut node, &remote);
    node.learn_reverse_route(remote_addr, fallback_next_hop);
    node.sessions
        .get_mut(&remote_addr)
        .expect("session")
        .record_outbound_next_hop(remote_addr);
    let mut retry = super::super::retry::RetryState::new(peer_config);
    retry.reconnect = true;
    retry.retry_after_ms = Node::now_ms() + 500;
    node.retry_pending.insert(remote_addr, retry);

    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(remote_addr),
        "background direct-probe bookkeeping alone must not move payload off a healthy direct path"
    );
}

#[test]
fn test_unreturned_session_traffic_prefers_fallback_during_direct_probe() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let fallback_next_hop = *node.peer_ids().next().expect("fallback peer");
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_npub = crate::encode_npub(&remote.pubkey());

    let peer_config = crate::config::PeerConfig {
        npub: remote_npub,
        alias: Some("pending-direct-probe-unreturned".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers.push(peer_config.clone());
    add_direct_peer_for_identity(&mut node, &remote);
    install_established_session_with_mmp(&mut node, &remote);
    node.learn_reverse_route(remote_addr, fallback_next_hop);
    {
        let now_ms = Node::now_ms();
        let session = node.sessions.get_mut(&remote_addr).expect("session");
        session.record_sent(512);
        session.touch_outbound_frame(now_ms);
        session.record_outbound_next_hop(remote_addr);
    }
    let mut retry = super::super::retry::RetryState::new(peer_config);
    retry.reconnect = true;
    retry.retry_after_ms = Node::now_ms() + 500;
    node.retry_pending.insert(remote_addr, retry);

    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(fallback_next_hop),
        "fallback should carry payload when recent direct session sends have no authenticated return"
    );
}

#[test]
fn test_active_session_keeps_learned_fallback_next_hop_affinity() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let first_fallback = *node.peer_ids().next().expect("first fallback peer");
    let transport_id = TransportId::new(1);
    let second_link = LinkId::new(2);
    let (second_conn, second_identity) =
        make_completed_connection(&mut node, second_link, transport_id, 1000);
    let second_fallback = *second_identity.node_addr();
    node.add_connection(second_conn).unwrap();
    node.promote_connection(second_link, second_identity, 2000)
        .unwrap();

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    node.config.peers.push(crate::config::PeerConfig {
        npub: crate::encode_npub(&remote.pubkey()),
        alias: Some("active-fallback-affinity".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    add_direct_peer_for_identity(&mut node, &remote);
    install_established_session_with_mmp(&mut node, &remote);
    node.learn_reverse_route(remote_addr, first_fallback);
    node.learn_reverse_route(remote_addr, second_fallback);
    node.mark_session_direct_path_degraded(remote_addr, Node::now_ms());
    {
        let session = node.sessions.get_mut(&remote_addr).expect("session");
        session.record_sent(128);
        session.touch_outbound_frame(Node::now_ms());
        session.record_outbound_next_hop(first_fallback);
    }

    let selected = (0..8)
        .map(|_| {
            node.find_next_hop(&remote_addr)
                .map(|peer| *peer.node_addr())
                .expect("learned fallback route")
        })
        .collect::<Vec<_>>();

    assert!(
        selected.iter().all(|addr| *addr == first_fallback),
        "active fallback session should not spray one flow across learned routes: {selected:?}"
    );
}

#[test]
fn test_active_fallback_affinity_periodically_retries_direct_payload() {
    let mut node = make_reply_learned_node_with_tree_peer();
    node.config.node.routing.learned_fallback_explore_interval = 2;
    let fallback_next_hop = *node.peer_ids().next().expect("fallback peer");
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    node.config.peers.push(crate::config::PeerConfig {
        npub: crate::encode_npub(&remote.pubkey()),
        alias: Some("direct-retry-after-fallback-affinity".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    add_direct_peer_for_identity(&mut node, &remote);
    install_established_session_with_mmp(&mut node, &remote);
    node.learn_reverse_route(remote_addr, fallback_next_hop);
    {
        let now_ms = Node::now_ms();
        let session = node.sessions.get_mut(&remote_addr).expect("session");
        session.record_sent(128);
        session.touch_outbound_frame(now_ms);
        session.record_outbound_next_hop(fallback_next_hop);
    }

    let selected = (0..4)
        .map(|_| {
            node.find_next_hop(&remote_addr)
                .map(|peer| *peer.node_addr())
                .expect("route")
        })
        .collect::<Vec<_>>();

    assert_eq!(
        selected,
        vec![
            fallback_next_hop,
            fallback_next_hop,
            remote_addr,
            fallback_next_hop,
        ],
        "fallback affinity must not starve periodic direct payload probes"
    );
}

#[test]
fn test_cost_based_fallback_periodically_retries_healthy_direct_payload() {
    let mut node = make_reply_learned_node_with_tree_peer();
    node.config.node.routing.learned_fallback_explore_interval = 2;
    let fallback_next_hop = *node.peer_ids().next().expect("fallback peer");
    let transport_id = TransportId::new(1);
    let direct_link = LinkId::new(42);
    let (direct_conn, direct_identity) =
        make_completed_connection(&mut node, direct_link, transport_id, 1000);
    let remote_addr = *direct_identity.node_addr();
    node.add_connection(direct_conn).unwrap();
    node.promote_connection(direct_link, direct_identity, 2000)
        .unwrap();
    node.config.peers.push(crate::config::PeerConfig {
        npub: crate::encode_npub(&direct_identity.pubkey()),
        alias: Some("direct-retry-after-cost-fallback".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    let session = make_noise_session(node.identity(), &Identity::generate());
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        direct_identity.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );
    entry.init_mmp(&node.config.node.session_mmp);
    node.sessions.insert(remote_addr, entry);
    node.learn_reverse_route(remote_addr, fallback_next_hop);
    node.get_peer_mut(&remote_addr)
        .expect("direct peer")
        .mmp_mut()
        .expect("direct mmp")
        .metrics
        .srtt
        .update(90_000);
    node.get_peer_mut(&fallback_next_hop)
        .expect("fallback peer")
        .mmp_mut()
        .expect("fallback mmp")
        .metrics
        .srtt
        .update(5_000);
    {
        let now_ms = Node::now_ms();
        let session = node.sessions.get_mut(&remote_addr).expect("session");
        session.record_sent(128);
        session.record_recv(128);
        session.touch_inbound_data_frame(now_ms);
        session.touch_outbound_frame(now_ms);
        session.record_outbound_next_hop(fallback_next_hop);
    }
    assert!(
        !node.session_direct_path_exclusive_trust_expired(&remote_addr, Node::now_ms()),
        "fixture should make fallback win by stale path cost, not by missing direct data return"
    );
    assert!(
        node.route_candidate_beats_direct(Some(remote_addr), fallback_next_hop),
        "fixture should make the learned fallback look cheaper than direct"
    );

    let selected = (0..4)
        .map(|_| {
            node.find_next_hop(&remote_addr)
                .map(|peer| *peer.node_addr())
                .expect("route")
        })
        .collect::<Vec<_>>();

    assert_eq!(
        selected,
        vec![
            fallback_next_hop,
            fallback_next_hop,
            remote_addr,
            fallback_next_hop,
        ],
        "cost-based fallback must not starve periodic direct payload probes"
    );
}

#[test]
fn test_pending_direct_probe_does_not_block_fresh_healthy_direct_without_fallback() {
    let mut node = Node::new(Config::new()).unwrap();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let peer_config = crate::config::PeerConfig {
        npub: crate::encode_npub(&remote.pubkey()),
        alias: Some("fresh-direct-probe".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };

    add_direct_peer_for_identity(&mut node, &remote);
    node.get_peer_mut(&remote_addr)
        .expect("direct peer")
        .touch(Node::now_ms());
    let mut retry = super::super::retry::RetryState::new(peer_config);
    retry.reconnect = true;
    retry.retry_after_ms = Node::now_ms() + 500;
    node.retry_pending.insert(remote_addr, retry);

    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(remote_addr),
        "background direct-probe bookkeeping must not block a fresh healthy direct path when no fallback exists"
    );
}

#[test]
fn test_historical_outbound_session_counter_does_not_deprioritize_direct() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let fallback_next_hop = *node.peer_ids().next().expect("fallback peer");
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_npub = crate::encode_npub(&remote.pubkey());

    node.config.peers.push(crate::config::PeerConfig {
        npub: remote_npub,
        alias: Some("historical-direct-session".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    add_direct_peer_for_identity(&mut node, &remote);
    install_established_session_with_mmp(&mut node, &remote);
    node.learn_reverse_route(remote_addr, fallback_next_hop);

    let session = node.sessions.get_mut(&remote_addr).expect("session");
    session.record_sent(128);
    session.record_outbound_next_hop(remote_addr);

    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(remote_addr),
        "old send counters alone should not make a healthy quiet direct path lose payload routing"
    );
}

#[tokio::test]
async fn test_stale_direct_session_trust_does_not_reprobe_healthy_link() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let fallback_next_hop = *node.peer_ids().next().expect("fallback peer");
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_npub = crate::encode_npub(&remote.pubkey());

    node.config.peers.push(crate::config::PeerConfig {
        npub: remote_npub,
        alias: Some("quiet-direct-session-refresh".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    node.configured_peer_send_weights =
        crate::node::ConfiguredPeerSendWeights::from_config(&node.config);
    add_direct_peer_for_identity(&mut node, &remote);
    install_established_session_with_mmp(&mut node, &remote);
    node.learn_reverse_route(remote_addr, fallback_next_hop);

    let session = node.sessions.get_mut(&remote_addr).expect("session");
    session.record_sent(128);
    session.touch_outbound_frame(Node::now_ms());
    session.record_outbound_next_hop(remote_addr);

    node.check_link_heartbeats().await;

    assert!(
        !node.retry_pending.contains_key(&remote_addr),
        "session trust aging alone must not restart a healthy direct link"
    );
    assert!(
        !node.pending_lookups.contains_key(&remote_addr),
        "session trust aging alone must not start link-dead fallback discovery"
    );
    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(fallback_next_hop),
        "known fallback should carry payload while direct refresh runs"
    );
}

#[tokio::test]
async fn test_fresh_bogus_session_metrics_without_valid_rtt_do_not_change_route_choice() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let fallback_next_hop = *node.peer_ids().next().expect("fallback peer");
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_npub = crate::encode_npub(&remote.pubkey());

    node.config.peers.push(crate::config::PeerConfig {
        npub: remote_npub,
        alias: Some("bogus-session-metrics-direct".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    add_direct_peer_for_identity(&mut node, &remote);
    install_established_session_with_mmp(&mut node, &remote);
    node.learn_reverse_route(remote_addr, fallback_next_hop);
    node.sessions
        .get_mut(&remote_addr)
        .expect("session")
        .record_outbound_next_hop(remote_addr);

    let baseline = SessionReceiverReport {
        highest_counter: 100,
        cumulative_packets_recv: 100,
        cumulative_bytes_recv: 10_000,
        timestamp_echo: u32::MAX - 10,
        dwell_time: 20,
        max_burst_loss: u16::MAX,
        mean_burst_loss: u16::MAX,
        jitter: u32::MAX,
        ecn_ce_count: 0,
        owd_trend: i32::MAX,
        burst_loss_count: u32::MAX,
        cumulative_reorder_count: 0,
        interval_packets_recv: 0,
        interval_bytes_recv: 0,
    }
    .encode();
    node.handle_session_receiver_report(&remote_addr, &baseline)
        .await;

    tokio::time::sleep(Duration::from_millis(1)).await;

    let fresh_bogus_delta = SessionReceiverReport {
        highest_counter: 300,
        cumulative_packets_recv: 100,
        cumulative_bytes_recv: u64::MAX,
        timestamp_echo: u32::MAX - 10,
        dwell_time: 20,
        max_burst_loss: u16::MAX,
        mean_burst_loss: u16::MAX,
        jitter: u32::MAX,
        ecn_ce_count: u32::MAX,
        owd_trend: i32::MIN,
        burst_loss_count: u32::MAX,
        cumulative_reorder_count: u32::MAX,
        interval_packets_recv: 0,
        interval_bytes_recv: u32::MAX,
    }
    .encode();
    node.handle_session_receiver_report(&remote_addr, &fresh_bogus_delta)
        .await;

    {
        let mmp = node
            .sessions
            .get(&remote_addr)
            .expect("session")
            .mmp()
            .expect("session mmp");
        assert_eq!(
            mmp.metrics.srtt_ms(),
            None,
            "invalid RTT samples must not initialize full session MMP SRTT"
        );
        assert_eq!(
            mmp.metrics.last_forward_loss_sample(),
            Some((200, 1.0)),
            "fixture should exercise a fresh severe-loss sample rather than stale-report rejection"
        );
        assert!(
            mmp.metrics.goodput_bps() > 0.0,
            "fixture should exercise a fresh bogus goodput sample"
        );
    }

    assert!(
        !node.session_direct_path_is_degraded(&remote_addr, Node::now_ms()),
        "fresh bogus metrics without valid RTT must not mark direct degraded"
    );
    assert!(
        !node.retry_pending.contains_key(&remote_addr),
        "bogus route-quality samples must not schedule direct reprobe"
    );
    assert!(
        !node.pending_lookups.contains_key(&remote_addr),
        "bogus route-quality samples must not start fallback discovery"
    );
    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(remote_addr),
        "fresh bogus metrics without valid RTT must not move payload routing to fallback"
    );
}

#[tokio::test]
async fn test_stale_session_receiver_reports_do_not_change_route_choice() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let fallback_next_hop = *node.peer_ids().next().expect("fallback peer");
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_npub = crate::encode_npub(&remote.pubkey());

    node.config.peers.push(crate::config::PeerConfig {
        npub: remote_npub,
        alias: Some("stale-report-direct".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    add_direct_peer_for_identity(&mut node, &remote);
    install_established_session_with_mmp(&mut node, &remote);
    node.learn_reverse_route(remote_addr, fallback_next_hop);
    node.sessions
        .get_mut(&remote_addr)
        .expect("session")
        .record_outbound_next_hop(remote_addr);

    let baseline = SessionReceiverReport {
        highest_counter: 100,
        cumulative_packets_recv: 100,
        cumulative_bytes_recv: 10_000,
        timestamp_echo: 0,
        dwell_time: 0,
        max_burst_loss: 0,
        mean_burst_loss: 0,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
        interval_packets_recv: 0,
        interval_bytes_recv: 0,
    }
    .encode();
    node.handle_session_receiver_report(&remote_addr, &baseline)
        .await;

    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(remote_addr),
        "healthy direct should initially hide fallback"
    );

    let duplicate_with_bogus_rtt = SessionReceiverReport {
        highest_counter: 100,
        cumulative_packets_recv: 100,
        cumulative_bytes_recv: 10_000,
        timestamp_echo: 1,
        dwell_time: u16::MAX,
        max_burst_loss: u16::MAX,
        mean_burst_loss: u16::MAX,
        jitter: u32::MAX,
        ecn_ce_count: 0,
        owd_trend: i32::MAX,
        burst_loss_count: u32::MAX,
        cumulative_reorder_count: 0,
        interval_packets_recv: 0,
        interval_bytes_recv: 0,
    }
    .encode();
    node.handle_session_receiver_report(&remote_addr, &duplicate_with_bogus_rtt)
        .await;

    let regressed_with_bogus_goodput = SessionReceiverReport {
        highest_counter: 90,
        cumulative_packets_recv: 90,
        cumulative_bytes_recv: u64::MAX,
        timestamp_echo: 1,
        dwell_time: u16::MAX,
        max_burst_loss: u16::MAX,
        mean_burst_loss: u16::MAX,
        jitter: u32::MAX,
        ecn_ce_count: 0,
        owd_trend: i32::MIN,
        burst_loss_count: u32::MAX,
        cumulative_reorder_count: 0,
        interval_packets_recv: u32::MAX,
        interval_bytes_recv: u32::MAX,
    }
    .encode();
    node.handle_session_receiver_report(&remote_addr, &regressed_with_bogus_goodput)
        .await;

    assert!(
        !node.session_direct_path_is_degraded(&remote_addr, Node::now_ms()),
        "stale or regressed ReceiverReports must not mark direct degraded"
    );
    assert!(
        !node.retry_pending.contains_key(&remote_addr),
        "ignored ReceiverReports must not schedule direct reprobe"
    );
    assert!(
        !node.pending_lookups.contains_key(&remote_addr),
        "ignored ReceiverReports must not start fallback discovery"
    );
    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(remote_addr),
        "bogus stale metrics must not move payload routing to fallback"
    );

    let mmp = node
        .sessions
        .get(&remote_addr)
        .expect("session")
        .mmp()
        .expect("session mmp");
    assert_eq!(
        mmp.metrics.last_forward_loss_sample(),
        None,
        "ignored stale reports must not leave a loss sample behind"
    );
    assert_eq!(
        mmp.metrics.goodput_bps(),
        0.0,
        "ignored stale reports must not update goodput"
    );
}
