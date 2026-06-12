use super::*;

#[tokio::test]
async fn test_graph_auto_connect_races_direct_address_before_timeout() {
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let dest_addr = *nodes[2].node.node_addr();
    let peer = crate::config::PeerConfig {
        npub: nodes[2].node.npub(),
        alias: Some("graph-timeout-direct".to_string()),
        addresses: vec![crate::config::PeerAddress::new(
            "udp",
            nodes[2].addr.to_string(),
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };

    nodes[0].node.update_peers(vec![peer]).await.unwrap();
    assert!(
        has_outbound_handshake_to(&nodes[0].node, &dest_addr),
        "direct path should be tried without waiting for graph session timeout"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_update_peers_starts_lookup_for_auto_connect_peer_without_cached_route() {
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    nodes[0].node.config.node.routing.mode = RoutingMode::ReplyLearned;

    let dest_addr = *nodes[2].node.node_addr();
    nodes[0].node.coord_cache_mut().remove(&dest_addr);
    let peer = crate::config::PeerConfig {
        npub: nodes[2].node.npub(),
        alias: Some("lookup-peer".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };

    let outcome = nodes[0].node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.added, 1);
    assert!(
        nodes[0].node.pending_lookups.contains_key(&dest_addr),
        "configured peer should start FIPS discovery immediately when no route is cached"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_tun_packet_for_pending_session_triggers_reply_learned_discovery() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let dest = Identity::generate();
    let dest_addr = *dest.node_addr();
    add_direct_peer_for_identity(&mut node, &dest);
    node.register_identity(dest_addr, dest.pubkey_full());
    insert_initiating_session(&mut node, &dest);
    assert!(
        node.find_next_hop(&dest_addr).is_some(),
        "fixture should model a stale direct route that still looks sendable"
    );

    let src_fips = crate::FipsAddress::from_node_addr(node.node_addr());
    let dst_fips = crate::FipsAddress::from_node_addr(&dest_addr);
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, b"tun-probe");
    let baseline = node.stats().discovery.req_initiated;

    node.handle_tun_outbound(ipv6_packet).await;

    assert_eq!(
        node.pending_session_traffic
            .tun_packets_for(&dest_addr)
            .map(|queue| queue.len()),
        Some(1),
        "TUN packet should stay queued until the pending session recovers"
    );
    assert!(
        node.pending_lookups.contains_key(&dest_addr),
        "a stale pending session must start mesh discovery in reply-learned mode"
    );
    assert_eq!(
        node.stats().discovery.req_initiated,
        baseline + 1,
        "discovery should be initiated exactly once"
    );
}

#[tokio::test]
async fn test_tun_packet_for_established_session_with_no_route_queues_and_discovers() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let dest = Identity::generate();
    let dest_addr = *dest.node_addr();
    node.register_identity(dest_addr, dest.pubkey_full());
    insert_established_session(&mut node, &dest);
    assert!(
        node.find_next_hop(&dest_addr).is_none(),
        "fixture should model an established end-to-end session whose direct path disappeared"
    );

    let src_fips = crate::FipsAddress::from_node_addr(node.node_addr());
    let dst_fips = crate::FipsAddress::from_node_addr(&dest_addr);
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, b"tun-probe");
    let baseline = node.stats().discovery.req_initiated;

    node.handle_tun_outbound(ipv6_packet).await;

    assert_eq!(
        node.pending_session_traffic
            .tun_packets_for(&dest_addr)
            .map(|queue| queue.len()),
        Some(1),
        "TUN packet should stay queued while fallback discovery repairs the route"
    );
    assert!(
        node.pending_lookups.contains_key(&dest_addr),
        "route loss under an established session must start mesh discovery"
    );
    assert_eq!(
        node.stats().discovery.req_initiated,
        baseline + 1,
        "discovery should be initiated exactly once"
    );
}

#[tokio::test]
async fn test_tun_packet_for_established_session_with_stale_direct_queues_and_discovers() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let dest = Identity::generate();
    let dest_addr = *dest.node_addr();
    node.register_identity(dest_addr, dest.pubkey_full());
    insert_established_session(&mut node, &dest);
    add_direct_peer_for_identity(&mut node, &dest);
    node.get_peer_mut(&dest_addr)
        .expect("direct peer")
        .mark_stale();

    assert!(
        node.get_peer(&dest_addr).expect("direct peer").can_send(),
        "stale direct peer should remain available for direct probing"
    );
    assert!(
        node.find_next_hop(&dest_addr).is_none(),
        "stale direct peer should not be selected for established-session payload"
    );

    let src_fips = crate::FipsAddress::from_node_addr(node.node_addr());
    let dst_fips = crate::FipsAddress::from_node_addr(&dest_addr);
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, b"tun-stale-direct-probe");
    let baseline = node.stats().discovery.req_initiated;

    node.handle_tun_outbound(ipv6_packet).await;

    assert_eq!(
        node.pending_session_traffic
            .tun_packets_for(&dest_addr)
            .map(|queue| queue.len()),
        Some(1),
        "TUN packet should stay queued while fallback discovery runs"
    );
    assert!(
        node.pending_lookups.contains_key(&dest_addr),
        "stale direct payload failure must start mesh discovery"
    );
    assert_eq!(
        node.stats().discovery.req_initiated,
        baseline + 1,
        "discovery should be initiated exactly once"
    );
}

#[tokio::test]
async fn test_discovery_restarts_stale_pending_session_with_fresh_coords() {
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    for node in &mut nodes {
        node.node.config.node.routing.mode = RoutingMode::ReplyLearned;
    }

    let next_hop = *nodes[1].node.node_addr();
    let dest_addr = *nodes[2].node.node_addr();
    let dest_pubkey = nodes[2].node.identity().pubkey_full();
    nodes[0].node.register_identity(dest_addr, dest_pubkey);
    nodes[0].node.learn_reverse_route(dest_addr, next_hop);

    let now_ms = crate::time::now_ms();
    let stale_coords = nodes[0].node.tree_state().my_coords().clone();
    nodes[0]
        .node
        .coord_cache_mut()
        .insert(dest_addr, stale_coords.clone(), now_ms);
    insert_initiating_session_for(&mut nodes[0].node, dest_addr, dest_pubkey);
    nodes[0].node.pending_session_traffic.push_endpoint_data(
        dest_addr,
        crate::node::EndpointDataPayload::new(b"queued".to_vec()),
        usize::MAX,
        usize::MAX,
    );

    let fresh_coords = nodes[2].node.tree_state().my_coords().clone();
    nodes[0]
        .node
        .coord_cache_mut()
        .insert(dest_addr, fresh_coords.clone(), now_ms + 1);

    nodes[0].node.retry_session_after_discovery(dest_addr).await;

    let entry = nodes[0]
        .node
        .get_session(&dest_addr)
        .expect("retry should install a fresh initiating session");
    assert!(entry.is_initiating());
    let setup_payload = entry
        .handshake_payload()
        .expect("fresh session should store SessionSetup for resend");
    let setup = SessionSetup::decode(&setup_payload[FSP_COMMON_PREFIX_SIZE..])
        .expect("stored setup should decode");
    let setup_dest_path: Vec<NodeAddr> = setup.dest_coords.node_addrs().copied().collect();
    let fresh_path: Vec<NodeAddr> = fresh_coords.node_addrs().copied().collect();
    let stale_path: Vec<NodeAddr> = stale_coords.node_addrs().copied().collect();
    assert_eq!(setup_dest_path, fresh_path);
    assert_ne!(
        setup_dest_path, stale_path,
        "discovery retry must not keep stale destination coordinates"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_discovery_warms_established_session_over_fresh_fallback_route() {
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    for node in &mut nodes {
        node.node.config.node.routing.mode = RoutingMode::ReplyLearned;
    }

    let fallback_next_hop = *nodes[1].node.node_addr();
    let dest_addr = *nodes[2].node.node_addr();
    let dest_pubkey = nodes[2].node.identity().pubkey_full();
    nodes[0].node.register_identity(dest_addr, dest_pubkey);
    populate_all_coord_caches(&mut nodes);
    nodes[0]
        .node
        .initiate_session(dest_addr, dest_pubkey)
        .await
        .expect("session should initiate over graph route");
    drain_to_quiescence(&mut nodes).await;
    assert!(
        nodes[0]
            .node
            .get_session(&dest_addr)
            .is_some_and(|entry| entry.is_established()),
        "fixture should start with an established end-to-end session"
    );
    nodes[0].node.coord_cache_mut().remove(&dest_addr);

    let request_id = 5150;
    let fresh_coords = nodes[2].node.tree_state().my_coords().clone();
    let proof_data =
        crate::protocol::LookupResponse::proof_bytes(request_id, &dest_addr, &fresh_coords);
    let proof = nodes[2].node.identity().sign(&proof_data);
    let response = crate::protocol::LookupResponse::new(request_id, dest_addr, fresh_coords, proof);
    let response_payload = &response.encode()[1..];
    let originated_before = nodes[0].node.stats().forwarding.originated_packets;

    nodes[0]
        .node
        .handle_lookup_response(&fallback_next_hop, response_payload)
        .await;

    assert_eq!(
        nodes[0]
            .node
            .pending_session_traffic
            .endpoint_data_for(&dest_addr)
            .map(|queue| queue.len()),
        None,
        "fixture should not rely on queued endpoint payloads for fallback warmup"
    );
    assert_eq!(
        nodes[0]
            .node
            .pending_session_traffic
            .tun_packets_for(&dest_addr)
            .map(|queue| queue.len()),
        None,
        "fixture should not rely on queued TUN packets for fallback warmup"
    );
    assert!(
        nodes[0].node.stats().forwarding.originated_packets > originated_before,
        "fresh discovery for an established session should immediately send a small fallback warmup"
    );
    assert_eq!(
        nodes[0]
            .node
            .get_session(&dest_addr)
            .expect("session")
            .coords_warmup_remaining(),
        nodes[0].node.config.node.session.coords_warmup_packets,
        "standalone warmup must not consume the data-plane coordinate warmup budget"
    );

    drain_to_quiescence(&mut nodes).await;
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_discovery_flushes_queued_tun_for_established_session_with_fresh_route() {
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    for node in &mut nodes {
        node.node.config.node.routing.mode = RoutingMode::ReplyLearned;
    }

    let src_addr = *nodes[0].node.node_addr();
    let fallback_next_hop = *nodes[1].node.node_addr();
    let dest_addr = *nodes[2].node.node_addr();
    let dest_pubkey = nodes[2].node.identity().pubkey_full();
    nodes[0].node.register_identity(dest_addr, dest_pubkey);
    populate_all_coord_caches(&mut nodes);
    nodes[0]
        .node
        .initiate_session(dest_addr, dest_pubkey)
        .await
        .expect("session should initiate over graph route");
    drain_to_quiescence(&mut nodes).await;
    assert!(
        nodes[0]
            .node
            .get_session(&dest_addr)
            .is_some_and(|entry| entry.is_established()),
        "fixture should start with an established end-to-end session"
    );
    nodes[0].node.coord_cache_mut().remove(&dest_addr);

    let src_fips = crate::FipsAddress::from_node_addr(&src_addr);
    let dest_fips = crate::FipsAddress::from_node_addr(&dest_addr);
    let ipv6_packet = build_ipv6_packet(&src_fips, &dest_fips, b"queued-fallback");
    nodes[0].node.pending_session_traffic.push_tun_packet(
        dest_addr,
        ipv6_packet.clone(),
        usize::MAX,
        usize::MAX,
    );

    let request_id = 4242;
    let fresh_coords = nodes[2].node.tree_state().my_coords().clone();
    let proof_data =
        crate::protocol::LookupResponse::proof_bytes(request_id, &dest_addr, &fresh_coords);
    let proof = nodes[2].node.identity().sign(&proof_data);
    let response = crate::protocol::LookupResponse::new(request_id, dest_addr, fresh_coords, proof);
    let response_payload = &response.encode()[1..];

    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[2].node.tun_tx = Some(tun_tx);
    nodes[0]
        .node
        .handle_lookup_response(&fallback_next_hop, response_payload)
        .await;
    drain_to_quiescence(&mut nodes).await;

    assert!(
        nodes[0]
            .node
            .pending_session_traffic
            .tun_packets_for(&dest_addr)
            .is_none(),
        "discovery should flush queued TUN traffic through the established session"
    );
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(
        delivered,
        vec![ipv6_packet],
        "fresh discovery route should carry queued session traffic over fallback"
    );

    cleanup_nodes(&mut nodes).await;
}
