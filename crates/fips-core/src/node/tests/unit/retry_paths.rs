use super::*;

#[tokio::test]
async fn active_direct_refresh_retries_process_oldest_due_peers_first() {
    let peers = (0..3)
        .map(|idx| {
            let identity = Identity::generate();
            let peer_config = crate::config::PeerConfig {
                npub: identity.npub(),
                alias: None,
                addresses: vec![crate::config::PeerAddress::with_priority(
                    "udp",
                    format!("127.0.0.1:{}", 31_000 + idx),
                    1,
                )],
                connect_policy: crate::config::ConnectPolicy::AutoConnect,
                auto_reconnect: true,
                discovery_fallback_transit: true,
            };
            (identity, peer_config)
        })
        .collect::<Vec<_>>();

    let mut config = Config::new();
    config.peers = peers.iter().map(|(_, peer)| peer.clone()).collect();
    let mut node = Node::new(config).unwrap();
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

    let retry_times = [100, 200, 300];
    let peer_addrs = peers
        .iter()
        .zip(retry_times)
        .map(|((identity, peer_config), retry_after_ms)| {
            let peer_identity = PeerIdentity::from_npub(&peer_config.npub).unwrap();
            let node_addr = *peer_identity.node_addr();
            let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), 1_000);
            active_peer.set_current_addr(
                transport_id,
                &TransportAddr::from_string(&format!("127.0.0.1:{}", 32_000 + retry_after_ms)),
            );
            active_peer.mark_stale();
            node.peers.insert(node_addr, active_peer);

            let mut retry = super::super::retry::RetryState::new(peer_config.clone());
            retry.retry_after_ms = retry_after_ms;
            retry.reconnect = true;
            node.retry_pending.insert(node_addr, retry);

            (node_addr, identity.npub(), retry_after_ms)
        })
        .collect::<Vec<_>>();

    node.process_pending_retries(1_000).await;

    for (node_addr, _npub, _retry_after_ms) in peer_addrs.iter().take(2) {
        let retry = node
            .retry_pending
            .get(node_addr)
            .expect("retry remains queued");
        assert!(
            retry.retry_after_ms > 1_000,
            "oldest active retry should be processed before newer due peers"
        );
    }
    let newest = node
        .retry_pending
        .get(&peer_addrs[2].0)
        .expect("newest retry remains queued");
    assert_eq!(
        newest.retry_after_ms, 300,
        "active retry cap should defer the newest due peer on the first tick"
    );

    node.process_pending_retries(2_000).await;

    let newest = node
        .retry_pending
        .get(&peer_addrs[2].0)
        .expect("newest retry remains queued after processing");
    assert!(
        newest.retry_after_ms > 2_000,
        "deferred active retry should become oldest and run on the next tick"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn link_dead_direct_path_initiates_fallback_lookup_without_peer_backoff() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority(
            "udp",
            "10.0.0.2:2121",
            1,
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let transit_identity = Identity::generate();
    let transit_peer = PeerIdentity::from_pubkey(transit_identity.pubkey());
    let transit_addr = *transit_peer.node_addr();

    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).unwrap();
    node.peers
        .insert(peer_addr, ActivePeer::new(peer, LinkId::new(8), 0));
    node.peers.insert(
        transit_addr,
        ActivePeer::new(transit_peer, LinkId::new(9), 0),
    );

    node.discovery_backoff.record_failure(&peer_addr);
    assert!(
        node.discovery_backoff.is_suppressed(&peer_addr),
        "fixture should start with stale discovery backoff"
    );

    let now_ms = Node::now_ms();
    node.schedule_link_dead_reprobe(peer_addr, now_ms);
    node.mark_session_direct_path_degraded(peer_addr, now_ms);
    assert!(
        node.find_next_hop(&peer_addr).is_none(),
        "degraded direct path should have no payload route before fallback is seeded"
    );

    node.maybe_initiate_direct_path_fallback_lookup(&peer_addr)
        .await;

    let retry = node
        .retry_pending
        .get(&peer_addr)
        .expect("direct retry should stay queued");
    let min_retry_after_ms = now_ms.saturating_add(500);
    let max_retry_after_ms = now_ms.saturating_add(1_500);
    assert!(
        (min_retry_after_ms..=max_retry_after_ms).contains(&retry.retry_after_ms),
        "link-dead fallback lookup should preserve the quick jittered direct retry, got {}",
        retry.retry_after_ms
    );
    assert!(
        node.pending_lookups.contains_key(&peer_addr),
        "link-dead should immediately ask fallback peers for a route"
    );
    assert!(
        node.find_next_hop(&peer_addr).is_none(),
        "direct-path recovery should wait for a verified fallback route instead of treating every lookup fanout peer as transit"
    );
    assert!(
        !node.discovery_backoff.is_suppressed(&peer_addr),
        "dead direct paths should not inherit stale peer discovery backoff"
    );
}

/// Test that a graceful Disconnect from an auto-connect peer schedules reconnect.
///
/// Regression test for issue #60: `handle_disconnect` previously called
/// `remove_active_peer` without `schedule_reconnect`, orphaning auto-connect
/// entries on a clean upstream shutdown. Other peer-removal paths (link-dead,
/// decrypt failure, peer restart) all schedule reconnect.
#[test]
fn test_disconnect_schedules_reconnect() {
    use crate::protocol::{Disconnect, DisconnectReason};

    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    let payload = Disconnect::new(DisconnectReason::Shutdown).encode();
    node.handle_disconnect(&peer_node_addr, &payload);

    let state = node
        .retry_pending
        .get(&peer_node_addr)
        .expect("handle_disconnect should schedule reconnect for auto-connect peer");
    assert!(state.reconnect, "Entry should be marked as reconnect");
    assert_eq!(
        state.retry_count, 0,
        "Fresh reconnect after disconnect should start at count=0"
    );
}

/// Test that promote_connection clears retry_pending.
#[test]
fn test_promote_clears_retry_pending() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();

    // Simulate a retry entry existing for this peer
    node.retry_pending.insert(
        node_addr,
        super::super::retry::RetryState::new(crate::config::PeerConfig::default()),
    );
    assert_eq!(node.retry_pending.len(), 1);

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();

    assert!(
        !node.retry_pending.contains_key(&node_addr),
        "retry_pending should be cleared on successful promotion"
    );
}

#[test]
fn test_promote_clears_direct_degradation_hold_for_authenticated_discovered_path() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();
    let now_ms = Node::now_ms();

    node.mark_session_direct_path_degraded(node_addr, now_ms);
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, now_ms).unwrap();

    assert!(
        !node.session_direct_path_blocks_direct_payload(&node_addr, Node::now_ms()),
        "an authenticated direct refresh should get a bounded payload retry after degradation"
    );
}

#[test]
fn healthy_control_path_with_degraded_payload_classifies_msg1_as_direct_recovery() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2_000).unwrap();
    node.get_peer_mut(&node_addr)
        .unwrap()
        .set_session_established_at_for_test(
            std::time::Instant::now() - std::time::Duration::from_secs(31),
        );
    assert!(node.get_peer(&node_addr).unwrap().is_healthy());

    let now_ms = Node::now_ms();
    node.mark_session_direct_path_degraded(node_addr, now_ms);
    assert!(
        node.same_epoch_msg1_is_direct_path_recovery(&node_addr, now_ms),
        "a healthy FMP control carrier must not turn a path-recovery msg1 into periodic rekey while FSP payload is still degraded"
    );

    node.clear_session_direct_path_degraded(&node_addr);
    assert!(
        !node.same_epoch_msg1_is_direct_path_recovery(&node_addr, Node::now_ms()),
        "an old healthy session without payload degradation remains eligible for ordinary periodic rekey"
    );
}

#[test]
fn stale_same_tuple_refresh_remains_an_established_rekey_candidate() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2_000).unwrap();
    let peer = node.get_peer_mut(&node_addr).unwrap();
    peer.set_session_established_at_for_test(
        std::time::Instant::now() - std::time::Duration::from_secs(31),
    );
    peer.mark_stale();

    let peer = node.get_peer(&node_addr).unwrap();
    assert!(peer.can_send());
    assert!(!peer.is_healthy());
    assert_eq!(peer.transport_id(), Some(transport_id));
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string("127.0.0.1:5000"))
    );
    assert!(
        node.same_epoch_msg1_is_direct_path_recovery(&node_addr, Node::now_ms()),
        "link-dead state still records that direct payload needs recovery"
    );
    assert!(
        node.same_path_msg1_is_established_rekey(
            &node_addr,
            transport_id,
            &TransportAddr::from_string("127.0.0.1:5000"),
        ),
        "a retained stale carrier must classify a same-tuple msg1 as rekey so both sides use the same cutover state machine"
    );
    assert!(
        !node.same_path_msg1_is_established_rekey(
            &node_addr,
            transport_id,
            &TransportAddr::from_string("127.0.0.1:5001"),
        ),
        "a different tuple remains an alternate-path recovery handshake"
    );
}

#[tokio::test]
async fn expired_direct_payload_hold_keeps_reconnect_until_validation() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();
    let peer_config = crate::config::PeerConfig::new(identity.npub(), "udp", "127.0.0.1:5000");

    node.config.peers = vec![peer_config.clone()];
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2_000).unwrap();

    let now_ms = Node::now_ms();
    node.get_peer_mut(&node_addr).unwrap().touch(now_ms);
    super::super::seed_dataplane_fmp_rx_for_test(&mut node, node_addr, std::time::Duration::ZERO);
    let expired_at = now_ms.saturating_sub(SESSION_DIRECT_DEGRADED_HOLD_MS + 1);
    node.mark_session_direct_path_degraded(node_addr, expired_at);
    node.retry_pending.insert(
        node_addr,
        super::super::retry::RetryState::new(peer_config.clone()),
    );
    assert!(
        !node.session_direct_path_degradation_active(&node_addr, now_ms),
        "fixture requires the temporary payload block to be expired"
    );
    assert!(
        node.active_peer_should_keep_direct_retry(&node_addr, &peer_config),
        "a resumed healthy FMP heartbeat must not cancel reconnect before direct FSP payload is validated"
    );
    node.clear_retry_unless_direct_refresh_needed(&node_addr);
    assert!(
        node.retry_pending.contains_key(&node_addr),
        "generic fresh-link cleanup must keep reconnect pending until direct FSP payload is validated"
    );
    assert!(
        !node.active_peer_needs_same_path_refresh(&node_addr),
        "fixture requires a fresh authenticated FMP control carrier"
    );

    let (packet_tx, _packet_rx) = packet_channel(8);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("direct-retry".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    assert!(
        node.initiate_active_peer_direct_refresh_connection(&peer_config)
            .await
            .unwrap(),
        "pending direct FSP validation must keep the authenticated same-path UDP candidate eligible even after FMP control traffic resumes"
    );
    assert!(
        node.get_peer(&node_addr).unwrap().rekey_in_progress(),
        "a healthy same-path carrier must refresh through the symmetric rekey state machine so the peer cannot classify the handshake differently"
    );
    assert_eq!(node.connection_count(), 0);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[test]
fn test_promote_clears_direct_degradation_hold_for_configured_static_path() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();
    let now_ms = Node::now_ms();

    node.config.peers = vec![crate::config::PeerConfig::new(
        identity.npub(),
        "udp",
        "127.0.0.1:5000",
    )];
    node.mark_session_direct_path_degraded(node_addr, now_ms);
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, now_ms).unwrap();

    assert!(
        !node.session_direct_path_blocks_direct_payload(&node_addr, Node::now_ms()),
        "configured direct refresh promotion should restore payload trust"
    );
}

#[test]
fn test_promote_keeps_retry_pending_for_bootstrap_path() {
    let mut node = make_node();
    let bootstrap_id = TransportId::new(1);
    node.bootstrap_transports.mark(bootstrap_id);

    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, bootstrap_id, 1000);
    let node_addr = *identity.node_addr();
    let peer_config = crate::config::PeerConfig::new(identity.npub(), "udp", "127.0.0.1:5000");

    node.retry_pending
        .insert(node_addr, super::super::retry::RetryState::new(peer_config));

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();

    assert!(
        node.retry_pending.contains_key(&node_addr),
        "promotion over bootstrap/fallback transport should keep direct refresh retry state"
    );
}

/// Initial peer-init failure at startup must enqueue a retry. Otherwise a peer
/// whose addresses cannot be dialed at boot (no operational transport for the
/// configured transport types, all addresses unreachable, NAT rebind, etc.)
/// stays dead forever — pings arrive but cannot be answered until the daemon
/// is manually restarted.
#[tokio::test]
async fn test_initiate_peer_connections_schedules_retry_on_no_transport() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    // udp address but no UDP transport registered on the node — every dial
    // attempt resolves to NodeError::NoTransportForType.
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();
    assert!(node.retry_pending.is_empty());

    node.initiate_peer_connections().await;

    assert!(
        node.retry_pending.contains_key(&peer_node_addr),
        "startup peer-init failure must enqueue a retry so the peer can recover \
         without a daemon restart"
    );
}

// ============================================================================
// transport_mtu() — ISSUE-2026-0011 regression coverage
// ============================================================================
