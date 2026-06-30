use super::*;

#[test]
fn test_identity_cache_populated_on_promote() {
    use crate::peer::PromotionResult;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    let (conn, peer_identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);

    node.add_connection(conn).unwrap();

    // Promote
    let result = node
        .promote_connection(link_id, peer_identity, 2000)
        .unwrap();
    assert!(matches!(result, PromotionResult::Promoted(_)));

    // Identity cache should contain the peer
    let peer_addr = *peer_identity.node_addr();
    let mut prefix = [0u8; 15];
    prefix.copy_from_slice(&peer_addr.as_bytes()[0..15]);
    let cached = node.lookup_by_fips_prefix(&prefix);
    assert!(
        cached.is_some(),
        "Identity cache should contain promoted peer"
    );
    let (cached_addr, cached_pk) = cached.unwrap();
    assert_eq!(cached_addr, peer_addr);
    assert_eq!(cached_pk, peer_identity.pubkey_full());
}

#[test]
fn identity_cache_validates_claims_touches_lru_and_keeps_lookup_views() {
    let id1 = Identity::generate();
    let id2 = Identity::generate();
    let id3 = Identity::generate();
    let wrong = Identity::generate();
    let mut cache = crate::node::IdentityCache::default();

    assert!(cache.register(*id1.node_addr(), id1.pubkey_full(), 1_000, 2));
    assert!(cache.register(*id2.node_addr(), id2.pubkey_full(), 2_000, 2));
    assert_eq!(cache.len(), 2);

    assert!(!cache.register(*id1.node_addr(), wrong.pubkey_full(), 3_000, 2));
    assert_eq!(
        cache.pubkey_for_node_addr(id1.node_addr()),
        Some(id1.pubkey_full())
    );

    let id1_prefix = crate::node::IdentityCache::prefix_for(id1.node_addr());
    assert_eq!(
        cache.lookup_by_prefix(&id1_prefix, 4_000),
        Some((*id1.node_addr(), id1.pubkey_full()))
    );

    assert!(cache.register(*id3.node_addr(), id3.pubkey_full(), 5_000, 2));
    assert_eq!(cache.len(), 2);
    assert!(cache.has_prefix_for(id1.node_addr()));
    assert!(!cache.has_prefix_for(id2.node_addr()));
    assert_eq!(cache.npub_for_node_addr(id3.node_addr()), Some(id3.npub()));
}

#[tokio::test]
async fn test_tun_outbound_established_session() {
    // Two directly connected nodes, session established.
    // Inject IPv6 packet via PM2's TUN outbound queue on Node 0,
    // verify plaintext arrives at Node 1's tun_tx.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node1_addr);

    // Establish session (XK: 3 messages — Setup, Ack, Msg3)
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    wait_for_session_established(
        &mut nodes,
        0,
        &node1_addr,
        Duration::from_secs(10),
        "direct TUN fixture",
    )
    .await;

    // Install TUN receiver on Node 1
    let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
    nodes[1].node.tun_tx = Some(tun_tx);

    // Build and inject an IPv6 packet
    let test_payload = b"data-plane-test-12345";
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, test_payload);

    send_tun_packet_via_pm2(&mut nodes, 0, ipv6_packet.clone()).await;

    // Verify plaintext arrived at Node 1's TUN
    let delivered = recv_tun_packet_while_draining(
        &mut nodes,
        &tun_rx,
        Duration::from_secs(10),
        "direct established TUN packet",
    )
    .await;
    assert_eq!(
        delivered, ipv6_packet,
        "Delivered packet should match original"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_tun_outbound_triggers_session_initiation() {
    // Two connected nodes, no session yet.
    // Inject a TUN packet — should trigger session initiation,
    // queue the packet, and deliver after handshake completes.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node1_addr);

    // No session yet
    assert_eq!(nodes[0].node.session_count(), 0);

    // Install TUN receiver on Node 1
    let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
    nodes[1].node.tun_tx = Some(tun_tx);

    // Build and inject an IPv6 packet (identity cache populated at peer promotion)
    let test_payload = b"trigger-session-test";
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, test_payload);

    send_tun_packet_via_pm2(&mut nodes, 0, ipv6_packet.clone()).await;

    // Session should now be initiating
    assert_eq!(nodes[0].node.session_count(), 1);
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_initiating()
    );

    wait_for_session_established(
        &mut nodes,
        0,
        &node1_addr,
        Duration::from_secs(10),
        "TUN-triggered session",
    )
    .await;

    // Verify the queued packet was delivered to Node 1
    let delivered = recv_tun_packet_while_draining(
        &mut nodes,
        &tun_rx,
        Duration::from_secs(10),
        "queued TUN packet",
    )
    .await;
    assert_eq!(delivered, ipv6_packet);

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_endpoint_data_for_pending_session_triggers_reply_learned_discovery() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let dest = Identity::generate();
    let dest_addr = *dest.node_addr();
    add_direct_peer_for_identity(&mut node, &dest);
    insert_initiating_session(&mut node, &dest);
    assert!(
        node.find_next_hop(&dest_addr).is_some(),
        "fixture should model a stale direct route that still looks sendable"
    );

    let baseline = node.stats().discovery.req_initiated;
    let remote = crate::PeerIdentity::from_pubkey_full(dest.pubkey_full());

    send_endpoint_data_via_pm2(&mut node, remote, b"status-probe".to_vec())
        .await
        .unwrap();

    assert_eq!(
        node.pending_session_traffic
            .endpoint_data_for(&dest_addr)
            .map(|queue| queue.len()),
        Some(1),
        "endpoint payload should stay queued until the pending session recovers"
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
async fn test_endpoint_data_for_established_session_with_no_route_queues_and_discovers() {
    let mut node = make_reply_learned_node_with_tree_peer();
    let dest = Identity::generate();
    let dest_addr = *dest.node_addr();
    insert_established_session(&mut node, &dest);
    assert!(
        node.find_next_hop(&dest_addr).is_none(),
        "fixture should model an established end-to-end session whose direct path disappeared"
    );

    let baseline = node.stats().discovery.req_initiated;
    let remote = crate::PeerIdentity::from_pubkey_full(dest.pubkey_full());

    send_endpoint_data_via_pm2(&mut node, remote, b"status-probe".to_vec())
        .await
        .unwrap();

    assert_eq!(
        node.pending_session_traffic
            .endpoint_data_for(&dest_addr)
            .map(|queue| queue.len()),
        Some(1),
        "endpoint payload should stay queued while fallback discovery repairs the route"
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
async fn test_update_peers_warms_auto_connect_session_over_existing_graph() {
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let dest_addr = *nodes[2].node.node_addr();
    let peer = crate::config::PeerConfig {
        npub: nodes[2].node.npub(),
        alias: Some("graph-peer".to_string()),
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };

    let outcome = nodes[0].node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.added, 1);
    assert!(
        nodes[0]
            .node
            .get_session(&dest_addr)
            .is_some_and(|entry| entry.is_initiating()),
        "configured peer should start an FIPS graph session without waiting for data"
    );

    wait_for_session_established(
        &mut nodes,
        0,
        &dest_addr,
        Duration::from_secs(10),
        "proactive graph session",
    )
    .await;

    cleanup_nodes(&mut nodes).await;
}
