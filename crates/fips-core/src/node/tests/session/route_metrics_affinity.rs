#[test]
fn test_active_fallback_affinity_keeps_user_payload_on_fallback() {
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
        seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, fallback_next_hop, now_ms);
        seed_dataplane_fsp_data_rx_for_test(&mut node, remote_addr, fallback_next_hop, now_ms);
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
            fallback_next_hop,
            fallback_next_hop,
        ],
        "fallback affinity should not spend user payloads on direct probes"
    );
}

#[test]
fn test_active_fallback_exploration_skips_direct_while_refresh_pending() {
    let mut node = make_reply_learned_node_with_tree_peer();
    node.config.node.routing.learned_fallback_explore_interval = 2;
    let fallback_next_hop = *node.peer_ids().next().expect("fallback peer");
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let peer_config = crate::config::PeerConfig {
        npub: crate::encode_npub(&remote.pubkey()),
        alias: Some("direct-refresh-pending-fallback".to_string()),
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
        seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, fallback_next_hop, now_ms);
    }
    let mut retry = super::super::retry::RetryState::new(peer_config);
    retry.reconnect = true;
    retry.retry_after_ms = Node::now_ms() + 500;
    node.retry_pending.insert(remote_addr, retry);

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
            fallback_next_hop,
            fallback_next_hop,
        ],
        "direct refresh retry should not spend user payloads on direct probes"
    );
}

#[test]
fn test_stale_cost_fallback_keeps_user_payload_on_fallback() {
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
    entry.mark_established(1000);
    node.sessions.insert(remote_addr, entry);
    node.learn_reverse_route(remote_addr, fallback_next_hop);
    seed_dataplane_fmp_srtt_for_test(&mut node, remote_addr, 90);
    seed_dataplane_fmp_srtt_for_test(&mut node, fallback_next_hop, 5);
    {
        let now_ms = Node::now_ms();
        seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, fallback_next_hop, now_ms);
    }
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
            fallback_next_hop,
            fallback_next_hop,
        ],
        "cost-based fallback should not spend user payloads on direct probes"
    );
}

#[test]
fn test_recent_direct_payload_return_prefers_direct_over_cheaper_fallback() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let fallback_next_hop = *node.peer_ids().next().expect("fallback peer");
    let transport_id = TransportId::new(1);
    let direct_link = LinkId::new(43);
    let (direct_conn, direct_identity) =
        make_completed_connection(&mut node, direct_link, transport_id, 1000);
    let remote_addr = *direct_identity.node_addr();
    node.add_connection(direct_conn).unwrap();
    node.promote_connection(direct_link, direct_identity, 2000)
        .unwrap();
    node.config.peers.push(crate::config::PeerConfig {
        npub: crate::encode_npub(&direct_identity.pubkey()),
        alias: Some("fresh-direct-over-cost-fallback".to_string()),
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
    entry.mark_established(1000);
    node.sessions.insert(remote_addr, entry);
    node.learn_reverse_route(remote_addr, fallback_next_hop);
    seed_dataplane_fmp_srtt_for_test(&mut node, remote_addr, 90);
    seed_dataplane_fmp_srtt_for_test(&mut node, fallback_next_hop, 5);
    {
        let now_ms = Node::now_ms();
        seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, remote_addr, now_ms);
        seed_dataplane_fsp_data_rx_for_test(&mut node, remote_addr, remote_addr, now_ms);
    }
    assert!(
        node.route_candidate_beats_direct(Some(remote_addr), fallback_next_hop),
        "fixture should make stale link cost prefer fallback"
    );

    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(remote_addr),
        "fresh authenticated direct payload return should outrank stale fallback cost"
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
    node.configured_peers = crate::node::ConfiguredPeerLookup::from_config(&node.config);
    add_direct_peer_for_identity(&mut node, &remote);
    install_established_session_with_mmp(&mut node, &remote);
    node.learn_reverse_route(remote_addr, fallback_next_hop);

    let now_ms = Node::now_ms();
    seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, remote_addr, now_ms);

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
            .session_mmp_snapshot(&remote_addr)
            .expect("session dataplane MMP");
        assert_eq!(
            mmp.rtt_ms, None,
            "invalid RTT samples must not initialize full session MMP SRTT"
        );
        assert_eq!(
            mmp.last_forward_loss_sample,
            Some((200, 1.0)),
            "fixture should exercise a fresh severe-loss sample rather than stale-report rejection"
        );
        assert!(
            mmp.goodput_bps > 0.0,
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
        .session_mmp_snapshot(&remote_addr)
        .expect("session dataplane MMP");
    assert_eq!(
        mmp.last_forward_loss_sample, None,
        "ignored stale reports must not leave a loss sample behind"
    );
    assert_eq!(
        mmp.goodput_bps, 0.0,
        "ignored stale reports must not update goodput"
    );
}
