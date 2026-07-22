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
fn test_live_direct_peer_overrides_routed_handshake_ingress() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let routed_hop = *node.peer_ids().next().expect("routed handshake hop");
    assert!(node.sync_dataplane_fmp_owner(&routed_hop));

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let direct_link = LinkId::new(2);
    let (direct_connection, direct_identity) = make_completed_connection_for_identity(
        &mut node,
        direct_link,
        TransportId::new(1),
        2_000,
        &remote,
    );
    node.add_connection(direct_connection).unwrap();
    node.promote_connection(direct_link, direct_identity, 2_000)
        .unwrap();
    assert!(node.sync_dataplane_fmp_owner(&remote_addr));

    install_established_session_with_mmp(&mut node, &remote);
    assert!(node.sync_dataplane_fsp_owner_from_current_session_via(
        &remote_addr,
        Some(routed_hop),
        0,
    ));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(remote_addr),
        "a live direct peer must beat a transient routed SessionAck ingress"
    );
    assert!(
        node.dataplane
            .owner_active_path(crate::dataplane::OwnerId::fsp_node(remote_addr))
            .expect("direct FSP owner")
            .is_some(),
        "the FSP owner must use the direct transport path"
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
async fn test_session_receiver_loss_from_previous_route_does_not_degrade_promoted_direct() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let fallback_next_hop = *node.peer_ids().next().expect("fallback peer");
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    node.config.peers.push(crate::config::PeerConfig {
        npub: crate::encode_npub(&remote.pubkey()),
        alias: Some("promoted-direct-loss-baseline".to_string()),
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
    let fallback_baseline = SessionReceiverReport {
        highest_counter: 100,
        cumulative_packets_recv: 100,
        cumulative_bytes_recv: 10_000,
        timestamp_echo: session_timestamp_echo_for(50),
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
    node.handle_session_receiver_report(&remote_addr, &fallback_baseline)
        .await;

    node.clear_session_direct_path_degraded_after_promotion(&remote_addr, Node::now_ms());
    seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, remote_addr, Node::now_ms());
    let delayed_outage_report = SessionReceiverReport {
        highest_counter: 132,
        cumulative_packets_recv: 101,
        cumulative_bytes_recv: 10_100,
        timestamp_echo: session_timestamp_echo_for(50),
        dwell_time: 0,
        max_burst_loss: 31,
        mean_burst_loss: 31,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 1,
        cumulative_reorder_count: 0,
        interval_packets_recv: 1,
        interval_bytes_recv: 100,
    }
    .encode();
    node.handle_session_receiver_report(&remote_addr, &delayed_outage_report)
        .await;

    assert!(
        !node.session_direct_path_is_degraded(&remote_addr, Node::now_ms()),
        "the first report after a route transition spans the old carrier and must only establish the new route's loss baseline"
    );
    assert!(
        !node.retry_pending.contains_key(&remote_addr),
        "loss attributed to the previous carrier must not restart direct recovery"
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
fn test_fmp_rekey_releases_fallback_affinity_without_validating_fsp() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let fallback_next_hop = *node.peer_ids().next().expect("fallback peer");
    assert!(node.sync_dataplane_fmp_owner(&fallback_next_hop));

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let direct_transport = TransportId::new(91);
    let direct_link = LinkId::new(91);
    let (direct_conn, direct_identity) = make_completed_connection_for_identity(
        &mut node,
        direct_link,
        direct_transport,
        1_000,
        &remote,
    );
    node.config.peers.push(crate::config::PeerConfig::new(
        remote.npub(),
        "udp",
        "127.0.0.1:5000",
    ));
    node.add_connection(direct_conn).unwrap();
    node.promote_connection(direct_link, direct_identity, 2_000)
        .unwrap();
    assert!(node.sync_dataplane_fmp_owner(&remote_addr));

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
    node.mark_session_direct_path_degraded(remote_addr, now_ms);
    assert!(node.session_direct_path_degradation_active(&remote_addr, now_ms));

    node.make_direct_payload_eligible_for_validation_after_fmp_recovery(&remote_addr);

    assert!(
        node.session_direct_degradation
            .has_pending_validation(&remote_addr),
        "FMP control must not validate direct FSP payload"
    );
    assert!(
        !node.session_direct_path_degradation_active(&remote_addr, Node::now_ms()),
        "authenticated direct FMP recovery must end the hard payload hold so validation traffic can use the direct carrier"
    );
    assert_eq!(
        node.dataplane
            .fsp_owner_activity(&remote_addr)
            .and_then(|activity| activity.last_outbound_next_hop()),
        None,
        "authenticated direct FMP recovery must release stale fallback flow affinity"
    );
    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(remote_addr),
        "the next FSP payload should probe the recovered direct carrier"
    );

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
    let direct_transport_id = node
        .get_peer(&remote_addr)
        .and_then(|peer| peer.transport_id())
        .expect("direct transport");
    let direct_transport_addr = node
        .get_peer(&remote_addr)
        .and_then(|peer| peer.current_addr())
        .cloned()
        .expect("direct address");
    node.get_peer_mut(&remote_addr)
        .expect("direct peer")
        .mark_stale();
    node.mark_session_direct_path_degraded(remote_addr, Node::now_ms());

    node.make_direct_payload_eligible_for_validation_after_fmp_recovery(&remote_addr);

    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(fallback_next_hop),
        "a rekey cutover that races stale-link liveness cannot select direct until authenticated direct traffic revives the peer"
    );
    seed_dataplane_fsp_data_sent_for_test(
        &mut node,
        remote_addr,
        fallback_next_hop,
        Node::now_ms(),
    );

    node.record_authenticated_fmp_receive_facts(
        crate::node::AuthenticatedFmpReceiveFacts {
            source_peer: PeerIdentity::from_pubkey_full(remote.pubkey_full()),
            transport_id: direct_transport_id,
            remote_addr: &direct_transport_addr,
            packet_timestamp_ms: Node::now_ms(),
            packet_len: 128,
            fmp_counter: 1,
            inner_timestamp_ms: 1,
            fmp_flags: 0,
        },
        Some(&remote_addr),
    );

    assert!(
        node.get_peer(&remote_addr)
            .is_some_and(|peer| peer.is_healthy()),
        "authenticated direct FMP return must revive the stale carrier"
    );
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(remote_addr),
        "reviving a rekey-recovered carrier must immediately make the next FSP payload validate direct"
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

include!("route_metrics_affinity.rs");
