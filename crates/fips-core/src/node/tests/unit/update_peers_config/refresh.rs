use super::*;

#[tokio::test]
async fn refresh_peer_paths_redials_active_peer_on_same_known_candidate() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let old_link_id = LinkId::new(7);
    let active_peer = make_active_test_peer(
        &node,
        &peer_full,
        transport_id,
        old_link_id,
        current_addr.clone(),
        SessionIndex::new(11),
        SessionIndex::new(12),
    );
    node.peers.insert(peer_node_addr, active_peer);
    assert!(node.sync_dataplane_fmp_owner(&peer_node_addr));

    let mut session = SessionEntry::new(
        peer_node_addr,
        peer_full.pubkey_full(),
        crate::node::session::EndToEndState::Established(make_test_fmp_session(
            node.identity(),
            &peer_full,
            [0x51; 8],
            [0x52; 8],
        )),
        1_000,
        true,
    );
    session.mark_established(1_000);
    node.sessions.insert(peer_node_addr, session);
    assert!(node.sync_dataplane_fsp_owner_from_current_session(&peer_node_addr, 0));

    let peer = auto_connect_peer(peer_full.npub(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];
    refresh_configured_peer_cache_for_test(&mut node);

    let refreshed = node.refresh_peer_paths(vec![peer.npub]).await.unwrap();

    assert_eq!(refreshed, 1);
    assert_eq!(node.peer_count(), 1, "current peer should stay live");
    assert_eq!(
        node.connection_count(),
        1,
        "forced refresh should race a same-path handshake for liveness recovery"
    );
    assert!(
        node.retry_pending.contains_key(&peer_node_addr),
        "forced refresh should keep quick direct re-probe state alive"
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&current_addr));
    let preserved_session = node
        .sessions
        .get(&peer_node_addr)
        .expect("refreshing a transport path must preserve the end-to-end session");
    assert!(
        !preserved_session.has_rekey_in_progress(),
        "refreshing a transport path must preserve the established end-to-end key epoch"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn refresh_peer_paths_rediscovers_stale_established_fallback_session() {
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_config = auto_connect_peer(remote.npub(), "127.0.0.1:9");
    let transit = Identity::generate();
    let transit_addr = *transit.node_addr();
    let transit_config = auto_connect_peer(transit.npub(), "127.0.0.1:10");

    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.peers = vec![remote_config.clone(), transit_config];
    let mut node = Node::new(config).unwrap();

    let transport_id = TransportId::new(1);
    node.transports
        .insert(transport_id, make_udp_transport_with_mtu(1, 1280).await);
    let transit_peer = make_active_test_peer(
        &node,
        &transit,
        transport_id,
        LinkId::new(2),
        TransportAddr::from_string("127.0.0.1:10"),
        SessionIndex::new(3),
        SessionIndex::new(4),
    );
    node.peers.insert(transit_addr, transit_peer);
    assert!(node.sync_dataplane_fmp_owner(&transit_addr));
    node.learn_reverse_route(remote_addr, transit_addr);

    let mut session = SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        crate::node::session::EndToEndState::Established(make_test_fmp_session(
            node.identity(),
            &remote,
            [0x51; 8],
            [0x52; 8],
        )),
        1_000,
        true,
    );
    session.mark_established(1_000);
    node.sessions.insert(remote_addr, session);
    assert!(node.sync_dataplane_fsp_owner_from_current_session(&remote_addr, 0));
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(transit_addr),
        "fixture must begin with an established session over a live mesh neighbor"
    );
    assert!(
        !node.session_direct_path_degradation_active(&remote_addr, Node::now_ms()),
        "the app-level stale signal must not depend on a short-lived internal degradation marker"
    );

    let baseline = node.stats().discovery.req_initiated;
    let refreshed = node
        .refresh_peer_paths(vec![remote_config.npub])
        .await
        .unwrap();

    assert_eq!(refreshed, 1, "the direct path should still be raced");
    assert!(
        node.pending_lookups.contains_key(&remote_addr),
        "refreshing a stale participant must also seek a fresh route through the mesh"
    );
    assert_eq!(
        node.stats().discovery.req_initiated,
        baseline + 1,
        "one explicit refresh should start one bounded mesh lookup"
    );
    assert!(
        node.sessions
            .get(&remote_addr)
            .is_some_and(SessionEntry::is_established),
        "route rediscovery must preserve the end-to-end session"
    );
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&remote_addr),
        Some(transit_addr),
        "route rediscovery must preserve the current owner until a replacement is authenticated"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn refresh_peer_paths_continues_after_an_unreachable_peer() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let unreachable_full = Identity::generate();
    let mut unreachable = auto_connect_peer(unreachable_full.npub(), "127.0.0.1:8");
    unreachable.addresses.clear();

    let (reachable_full, reachable_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let reachable_node_addr = *reachable_identity.node_addr();
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(reachable_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(reachable_node_addr, active_peer);

    let reachable = auto_connect_peer(reachable_full.npub(), "127.0.0.1:9");
    node.config.peers = vec![unreachable.clone(), reachable.clone()];

    let refreshed = node
        .refresh_peer_paths(vec![unreachable.npub, reachable.npub])
        .await
        .unwrap();

    assert_eq!(refreshed, 1);
    assert_eq!(
        node.connection_count(),
        1,
        "an unreachable peer must not prevent later direct probes"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}
