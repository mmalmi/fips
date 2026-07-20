#[tokio::test]
async fn test_only_explicit_path_broken_replaces_healthy_learned_fallback() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let first_fallback = *node.peer_ids().next().expect("first fallback peer");
    assert!(node.sync_dataplane_fmp_owner(&first_fallback));
    let transport_id = TransportId::new(1);
    let second_link = LinkId::new(2);
    let (second_conn, second_identity) =
        make_completed_connection(&mut node, second_link, transport_id, 1_000);
    let second_fallback = *second_identity.node_addr();
    node.add_connection(second_conn).unwrap();
    node.promote_connection(second_link, second_identity, 2_000)
        .unwrap();
    assert!(node.sync_dataplane_fmp_owner(&second_fallback));

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    node.config.peers.push(crate::config::PeerConfig {
        npub: crate::encode_npub(&remote.pubkey()),
        alias: Some("unreturned-fallback-retransmits".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    add_direct_peer_for_identity(&mut node, &remote);
    install_established_session_with_mmp(&mut node, &remote);
    node.learn_reverse_route(remote_addr, first_fallback);
    node.learn_reverse_route(remote_addr, second_fallback);
    assert!(node.sync_dataplane_fsp_owner_from_current_session_via(
        &remote_addr,
        Some(first_fallback),
        0,
    ));
    node.mark_session_direct_path_degraded(remote_addr, Node::now_ms());

    let now_ms = Node::now_ms();
    let route_age_ms = node.session_direct_path_exclusive_trust_timeout_ms() + 1;
    seed_dataplane_fsp_data_sent_for_test(
        &mut node,
        remote_addr,
        first_fallback,
        now_ms.saturating_sub(route_age_ms),
    );
    seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, first_fallback, now_ms);

    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(first_fallback),
        "payload retransmits alone cannot prove a healthy learned fallback is broken"
    );
    assert!(node.refresh_dataplane_fsp_owner_routes(&remote_addr));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(first_fallback),
        "periodic liveness repair must preserve the protocol-selected fallback until explicit route feedback"
    );

    assert!(node.routing_error_matches_active_path(&remote_addr, &first_fallback));
    assert!(!node.routing_error_matches_active_path(&remote_addr, &second_fallback));

    let downstream_reporter = make_node_addr(180);
    let path_broken = PathBroken::new(remote_addr, downstream_reporter).encode();
    node.handle_session_payload(LocalSessionPayload::new(
        downstream_reporter,
        first_fallback,
        &path_broken,
    ))
    .await;

    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(second_fallback),
        "authenticated downstream PathBroken must demote the failed branch and move established traffic"
    );
    assert!(
        !node.routing_error_matches_active_path(&remote_addr, &first_fallback),
        "delayed errors from the failed branch must not poison its replacement"
    );
}

#[tokio::test]
async fn test_path_broken_matches_last_outbound_branch_after_wrap_route_moves() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let old_fallback = *node.peer_ids().next().expect("old fallback peer");
    assert!(node.sync_dataplane_fmp_owner(&old_fallback));

    let transport_id = TransportId::new(1);
    let replacement_link = LinkId::new(2);
    let (replacement_conn, replacement_identity) =
        make_completed_connection(&mut node, replacement_link, transport_id, 1_000);
    let replacement_fallback = *replacement_identity.node_addr();
    node.add_connection(replacement_conn).unwrap();
    node.promote_connection(replacement_link, replacement_identity, 2_000)
        .unwrap();
    assert!(node.sync_dataplane_fmp_owner(&replacement_fallback));

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    install_established_session_with_mmp(&mut node, &remote);
    node.learn_reverse_route(remote_addr, old_fallback);
    node.learn_reverse_route(remote_addr, replacement_fallback);
    assert!(node.sync_dataplane_fsp_owner_from_current_session_via(
        &remote_addr,
        Some(old_fallback),
        0,
    ));
    seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, old_fallback, Node::now_ms());

    // Model a reverse-path update moving the owner's wrap route while the
    // last transmitted payload and its explicit error are still on the old
    // branch. A newer authenticated handshake ingress may already pin the
    // replacement branch, but it did not carry that outbound payload.
    node.learned_routes
        .record_failure(&remote_addr, &old_fallback);
    node.learn_reverse_route(remote_addr, old_fallback);
    assert!(node.sync_dataplane_fsp_owner_from_current_session_via(
        &remote_addr,
        Some(replacement_fallback),
        0,
    ));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(replacement_fallback)
    );
    assert_eq!(
        node.dataplane
            .fsp_owner_activity(&remote_addr)
            .and_then(|activity| activity.last_outbound_next_hop()),
        Some(old_fallback)
    );
    node.pin_handshake_reverse_route(remote_addr, replacement_fallback);
    assert_eq!(
        node.learned_routes
            .active_handshake_route(&remote_addr, Node::now_ms()),
        Some(replacement_fallback)
    );

    assert!(
        node.routing_error_matches_active_path(&remote_addr, &old_fallback),
        "PathBroken must match the branch used by the last outbound payload even after the owner wrap route moves"
    );

    let downstream_reporter = make_node_addr(181);
    let path_broken = PathBroken::new(remote_addr, downstream_reporter).encode();
    node.handle_session_payload(LocalSessionPayload::new(
        downstream_reporter,
        old_fallback,
        &path_broken,
    ))
    .await;

    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(replacement_fallback),
        "failure of the old outbound branch must preserve the replacement wrap route"
    );
    assert!(
        !node.routing_error_matches_active_path(&remote_addr, &old_fallback),
        "the same old branch must become stale after its outbound affinity is cleared"
    );
}

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
fn test_authenticated_direct_handshake_gets_payload_validation_before_old_fallback_affinity() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let fallback_next_hop = *node.peer_ids().next().expect("fallback peer");
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    node.config.peers.push(crate::config::PeerConfig {
        npub: crate::encode_npub(&remote.pubkey()),
        alias: Some("direct-handshake-after-fallback".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    add_direct_peer_for_identity(&mut node, &remote);
    install_established_session_with_mmp(&mut node, &remote);
    node.learn_reverse_route(remote_addr, fallback_next_hop);
    seed_dataplane_fsp_data_sent_for_test(
        &mut node,
        remote_addr,
        fallback_next_hop,
        Node::now_ms(),
    );
    node.pin_handshake_reverse_route(remote_addr, remote_addr);

    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(remote_addr),
        "a fresh authenticated direct handshake must get one bounded payload-validation window before stale fallback affinity wins"
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
fn test_new_session_tries_healthy_direct_before_cheaper_fallback() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let fallback_next_hop = *node.peer_ids().next().expect("fallback peer");
    let transport_id = TransportId::new(1);
    let direct_link = LinkId::new(44);
    let (direct_conn, direct_identity) =
        make_completed_connection(&mut node, direct_link, transport_id, 1_000);
    let remote_addr = *direct_identity.node_addr();
    node.add_connection(direct_conn).unwrap();
    node.promote_connection(direct_link, direct_identity, 2_000)
        .unwrap();
    let session = make_noise_session(node.identity(), &Identity::generate());
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        direct_identity.pubkey_full(),
        EndToEndState::Established(session),
        1_000,
        true,
    );
    entry.mark_established(1_000);
    node.sessions.insert(remote_addr, entry);
    node.learn_reverse_route(remote_addr, fallback_next_hop);
    seed_dataplane_fmp_srtt_for_test(&mut node, remote_addr, 90);
    seed_dataplane_fmp_srtt_for_test(&mut node, fallback_next_hop, 5);
    assert!(
        node.route_candidate_beats_direct(Some(remote_addr), fallback_next_hop),
        "fixture should make the routed handshake ingress look cheaper than direct"
    );

    assert!(node.sync_dataplane_fsp_owner_from_current_session_via(
        &remote_addr,
        Some(fallback_next_hop),
        0,
    ));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(remote_addr),
        "a new session must validate its healthy authenticated direct carrier before inheriting a stale routed branch"
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
