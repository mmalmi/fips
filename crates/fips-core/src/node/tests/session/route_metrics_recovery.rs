#[tokio::test]
async fn test_fmp_recovery_stages_prompt_direct_payload_validation_without_discarding_fallback() {
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
    node.configured_peers = crate::node::ConfiguredPeerLookup::from_config(&node.config);
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
        "authenticated direct FMP recovery must release the hard hold immediately so FSP can validate the recovered carrier"
    );
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(remote_addr),
        "the recovered direct carrier must be staged for a bounded FSP payload validation without waiting for the 20-second hold"
    );
    assert_eq!(
        node.dataplane
            .fsp_owner_activity(&remote_addr)
            .and_then(|activity| activity.last_outbound_next_hop()),
        Some(fallback_next_hop),
        "staging direct validation must retain the authenticated fallback affinity until a direct payload is actually sent"
    );
    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(fallback_next_hop),
        "the proven fallback must remain available while the one staged direct validation is awaiting authenticated payload"
    );
    seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, remote_addr, Node::now_ms());
    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(fallback_next_hop),
        "a direct validation without authenticated return must immediately leave the proven fallback eligible"
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
    let our_addr = *node.node_addr();
    node.coord_cache_mut().insert(
        remote_addr,
        TreeCoordinate::from_addrs(vec![remote_addr, fallback_next_hop, our_addr]).unwrap(),
        Node::now_ms(),
    );
    node.pin_handshake_reverse_route(remote_addr, remote_addr);
    for mode in [RoutingMode::Tree, RoutingMode::ReplyLearned] {
        node.config.node.routing.mode = mode;
        assert_eq!(
            node.find_next_hop(&remote_addr)
                .map(|peer| *peer.node_addr()),
            Some(fallback_next_hop),
            "{mode:?}: sending fallback data must not make the pending direct probe trusted"
        );
    }
    let mut report = SessionReceiverReport {
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
    };
    node.handle_session_receiver_report(&remote_addr, &report.encode())
        .await;
    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(fallback_next_hop),
        "a delayed report after fallback sends cannot prove the earlier direct probe arrived"
    );
    seed_dataplane_fsp_data_sent_for_test(&mut node, remote_addr, remote_addr, Node::now_ms());
    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(fallback_next_hop),
        "changing paths must not reuse fallback delivery feedback as direct proof"
    );
    report.highest_counter += 1;
    report.cumulative_packets_recv += 1;
    node.handle_session_receiver_report(&remote_addr, &report.encode())
        .await;
    assert!(!node.session_direct_path_has_recent_data_return(&remote_addr, Node::now_ms()));
    assert!(
        node.session_direct_degradation
            .has_pending_validation(&remote_addr)
    );
    assert_eq!(
        node.find_next_hop(&remote_addr)
            .map(|peer| *peer.node_addr()),
        Some(remote_addr),
        "advancing direct delivery reports must restore one-way traffic without requiring returned application data"
    );
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
        "authenticated direct control recovery must promptly stage an FSP validation instead of waiting for the hard hold"
    );
    assert_eq!(
        node.dataplane
            .fsp_owner_activity(&remote_addr)
            .and_then(|activity| activity.last_outbound_next_hop()),
        Some(fallback_next_hop),
        "the proven fallback remains recorded until staged direct FSP payload is actually sent"
    );
}
