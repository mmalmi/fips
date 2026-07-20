use super::*;
use crate::protocol::PathBroken;

#[test]
fn test_direct_fsp_requires_negotiated_capability() {
    let mut node = Node::new(Config::new()).unwrap();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(91);
    let (connection, remote_identity) =
        make_completed_connection(&mut node, link_id, transport_id, 1_000);
    let remote_addr = *remote_identity.node_addr();

    node.add_connection(connection).unwrap();
    node.promote_connection(link_id, remote_identity, 2_000)
        .unwrap();
    assert!(node.sync_dataplane_fmp_owner(&remote_addr));
    let remote = Identity::generate();
    let session = make_noise_session(node.identity(), &remote);
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote_identity.pubkey_full(),
        EndToEndState::Established(session),
        1_000,
        true,
    );
    entry.mark_established(1_000);
    node.sessions.insert(remote_addr, entry);

    assert!(node.sync_dataplane_fsp_owner_from_current_session(&remote_addr, 0));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(remote_addr),
        "a peer that did not negotiate direct FSP must use the 0.4.1-compatible FMP carrier"
    );
    assert_eq!(
        node.dataplane
            .owner_active_path(crate::dataplane::OwnerId::fsp_node(remote_addr)),
        Ok(None)
    );
}

#[test]
fn test_dataplane_fmp_owner_update_refreshes_fsp_owner_wrap_route() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let next_hop = *node.peer_ids().next().expect("fallback peer");
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    assert!(node.sync_dataplane_fmp_owner(&next_hop));
    node.learn_reverse_route(remote_addr, next_hop);
    install_established_session_with_mmp(&mut node, &remote);
    assert!(node.sync_dataplane_fsp_owner_from_current_session(&remote_addr, 0));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(next_hop)
    );

    node.remove_dataplane_fmp_owner(&next_hop);
    assert_eq!(
        node.refresh_dataplane_fsp_owner_routes_after_fmp_owner_update(&next_hop),
        1
    );
    assert_eq!(node.dataplane.fsp_owner_next_hop(&remote_addr), None);

    assert!(node.sync_dataplane_fmp_owner(&next_hop));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(next_hop)
    );
}

#[test]
fn test_handshake_proven_hop_overrides_initial_route_exploration() {
    let mut node = make_reply_learned_node_with_tree_peer();
    node.config.node.routing.learned_fallback_explore_interval = 1;
    let tree_peer = *node.peer_ids().next().expect("tree peer");
    let transport_id = TransportId::new(1);
    let proven_link = LinkId::new(2);
    let (proven_connection, proven_identity) =
        make_completed_connection(&mut node, proven_link, transport_id, 1_000);
    let proven_hop = *proven_identity.node_addr();
    node.add_connection(proven_connection).unwrap();
    node.promote_connection(proven_link, proven_identity, 2_000)
        .unwrap();

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    node.learn_reverse_route(remote_addr, proven_hop);
    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(proven_hop),
        "the discovery-proven route should carry the session handshake"
    );

    node.get_peer_mut(&proven_hop)
        .expect("proven hop should remain registered")
        .mark_stale();
    assert!(
        node.get_peer(&proven_hop)
            .is_some_and(|peer| peer.can_send() && !peer.is_healthy()),
        "fixture requires the authenticated handshake hop to remain sendable through transient liveness jitter"
    );

    install_established_session_with_mmp(&mut node, &remote);
    assert!(node.sync_dataplane_fsp_owner_from_current_session_via(
        &remote_addr,
        Some(proven_hop),
        0,
    ));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(proven_hop),
        "first established records must follow the authenticated sendable handshake ingress instead of the route-exploration slot"
    );
    assert_ne!(tree_peer, proven_hop);

    for _ in 0..4 {
        node.learn_reverse_route(remote_addr, tree_peer);
        assert_eq!(
            node.dataplane.fsp_owner_next_hop(&remote_addr),
            Some(proven_hop),
            "later discovery routes must not replace the handshake-proven next hop while it remains healthy"
        );
    }

    assert!(node.sync_dataplane_fmp_owner(&tree_peer));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(proven_hop),
        "refreshing an unrelated physical peer must not replace the established session's proven next hop"
    );
}

#[test]
fn test_active_peer_removal_invalidates_dependent_fsp_wrap_route() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let next_hop = *node.peer_ids().next().expect("fallback peer");
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    assert!(node.sync_dataplane_fmp_owner(&next_hop));
    node.learn_reverse_route(remote_addr, next_hop);
    install_established_session_with_mmp(&mut node, &remote);
    assert!(node.sync_dataplane_fsp_owner_from_current_session(&remote_addr, 0));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(next_hop)
    );

    node.remove_active_peer(&next_hop);
    assert_eq!(node.dataplane.fsp_owner_next_hop(&remote_addr), None);
}

#[test]
fn test_incomplete_fsp_route_refresh_preserves_existing_wrap_route() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let next_hop = *node.peer_ids().next().expect("fallback peer");
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    assert!(node.sync_dataplane_fmp_owner(&next_hop));
    node.learn_reverse_route(remote_addr, next_hop);
    install_established_session_with_mmp(&mut node, &remote);
    assert!(node.sync_dataplane_fsp_owner_from_current_session(&remote_addr, 0));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(next_hop)
    );

    node.peers
        .get_mut(&next_hop)
        .expect("fallback peer")
        .mark_reconnecting();

    assert!(!node.refresh_dataplane_fsp_owner_routes(&remote_addr));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(next_hop)
    );
}

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

    let lossy_timestamp_echo = session_timestamp_echo_for(50);
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
        node.session_mmp_snapshot(&remote_addr)
            .and_then(|mmp| mmp.rtt_ms)
            .is_some(),
        "loss-driven route changes in full session MMP must be backed by a valid RTT sample"
    );
}

#[tokio::test]
async fn test_session_receiver_loss_replaces_active_fallback_route() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let failed_fallback = *node.peer_ids().next().expect("failed fallback peer");
    assert!(node.sync_dataplane_fmp_owner(&failed_fallback));

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
    node.learn_reverse_route(remote_addr, failed_fallback);
    node.learn_reverse_route(remote_addr, replacement_fallback);
    assert!(node.sync_dataplane_fsp_owner_from_current_session_via(
        &remote_addr,
        Some(failed_fallback),
        0,
    ));
    seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, failed_fallback, Node::now_ms());

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

    let lossy = SessionReceiverReport {
        highest_counter: 120,
        cumulative_packets_recv: 118,
        cumulative_bytes_recv: 11_800,
        timestamp_echo: session_timestamp_echo_for(50),
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

    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(replacement_fallback),
        "valid end-to-end loss must demote the active learned branch and repin the established session"
    );
    assert!(
        node.pending_lookups.contains_key(&remote_addr),
        "route-quality failure should also refresh discovery while the replacement carries traffic"
    );
    assert!(
        !node.session_direct_path_is_degraded(&remote_addr, Node::now_ms()),
        "loss on a learned fallback must not poison the independent direct-path state"
    );
}

#[test]
fn test_authenticated_direct_promotion_releases_active_fallback_affinity() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let fallback_next_hop = *node.peer_ids().next().expect("fallback peer");
    assert!(node.sync_dataplane_fmp_owner(&fallback_next_hop));

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    add_direct_peer_for_identity(&mut node, &remote);
    install_established_session_with_mmp(&mut node, &remote);
    node.learn_reverse_route(remote_addr, fallback_next_hop);
    assert!(node.sync_dataplane_fsp_owner_from_current_session_via(
        &remote_addr,
        Some(fallback_next_hop),
        0,
    ));
    seed_dataplane_fsp_data_sent_for_test(
        &mut node,
        remote_addr,
        fallback_next_hop,
        Node::now_ms(),
    );
    let now_ms = Node::now_ms();

    node.clear_session_direct_path_degraded_after_promotion(&remote_addr, now_ms);

    assert!(
        !node.session_direct_path_degradation_active(&remote_addr, now_ms),
        "a newly authenticated direct carrier must remain eligible for a bounded payload retry"
    );
    assert_eq!(
        node.dataplane
            .fsp_owner_activity(&remote_addr)
            .and_then(|activity| activity.last_outbound_next_hop()),
        None,
        "fresh promotion must release the prior fallback flow affinity"
    );
    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(remote_addr),
        "freshly promoted direct peer should win route selection once fallback affinity is released"
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

    let now_ms = Node::now_ms();
    seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, remote_addr, now_ms);

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

    let now_ms = Node::now_ms();
    seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, remote_addr, now_ms);

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
                .learned()
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    node.configured_peers = crate::node::ConfiguredPeerLookup::from_config(&node.config);
    add_direct_peer_for_identity(&mut node, &remote);
    node.peers
        .get_mut(&remote_addr)
        .expect("direct peer")
        .set_current_addr(TransportId::new(1), &discovered_addr);
    install_established_session_with_mmp(&mut node, &remote);

    let now_ms = Node::now_ms();
    seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, remote_addr, now_ms);
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
        seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, remote_addr, now_ms);
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
        let now_ms = Node::now_ms();
        seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, first_fallback, now_ms);
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
