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
