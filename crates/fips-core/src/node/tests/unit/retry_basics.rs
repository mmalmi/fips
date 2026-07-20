use super::*;

/// Test that schedule_retry creates a retry entry for auto-connect peers.
#[test]
fn test_schedule_retry_creates_entry() {
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

    assert!(node.retry_pending.is_empty());

    node.schedule_retry(peer_node_addr, 1000);

    assert_eq!(node.retry_pending.len(), 1);
    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert_eq!(state.retry_count, 1);
    assert!(
        state.reconnect,
        "auto-connect peers default to unlimited auto-reconnect"
    );
    // Default base = 5s, 2^1 = 10s, but first retry is 2^0... let me check:
    // retry_count is set to 1, backoff_ms(5000) = 5000 * 2^1 = 10000
    assert_eq!(state.retry_after_ms, 1000 + 10_000);
}

/// Test that schedule_retry increments on subsequent calls.
#[test]
fn test_schedule_retry_increments() {
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

    // First failure
    node.schedule_retry(peer_node_addr, 1000);
    assert_eq!(
        node.retry_pending.get(&peer_node_addr).unwrap().retry_count,
        1
    );

    // Second failure
    node.schedule_retry(peer_node_addr, 11_000);
    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert_eq!(state.retry_count, 2);
    // backoff_ms(5000) with retry_count=2 = 5000 * 4 = 20000
    assert_eq!(state.retry_after_ms, 11_000 + 20_000);
}

#[test]
fn test_local_route_transport_error_is_classified() {
    let error =
        crate::transport::TransportError::SendFailed("No route to host (os error 65)".to_string());

    let node_error = NodeError::from_transport_error(error);
    assert!(matches!(node_error, NodeError::LocalRouteUnavailable(_)));
}

#[test]
fn test_schedule_local_route_retry_does_not_increase_backoff() {
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

    node.schedule_retry(peer_node_addr, 1_000);
    {
        let state = node.retry_pending.get(&peer_node_addr).unwrap();
        assert_eq!(state.retry_count, 1);
        assert_eq!(state.retry_after_ms, 11_000);
    }

    node.schedule_local_route_retry(peer_node_addr, 2_000);

    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert_eq!(
        state.retry_count, 1,
        "local route outages must not count as peer failures"
    );
    assert_eq!(
        state.retry_after_ms, 4_000,
        "route recovery should be retried quickly instead of waiting on prior backoff"
    );
    assert!(state.reconnect);
}

/// Retry processing is paced so a large due set cannot start every
/// handshake candidate in one maintenance tick.
#[tokio::test]
async fn test_process_pending_retries_is_budgeted_per_tick() {
    let mut node = make_node();
    let mut addrs = Vec::new();

    for _ in 0..20 {
        let identity = Identity::generate();
        let npub = identity.npub();
        let peer_identity = PeerIdentity::from_npub(&npub).unwrap();
        let node_addr = *peer_identity.node_addr();
        node.retry_pending.insert(
            node_addr,
            crate::node::retry::RetryState {
                peer_config: crate::config::PeerConfig::new(npub, "udp", "10.0.0.2:2121"),
                retry_count: 0,
                retry_after_ms: 0,
                reconnect: true,
                expires_at_ms: None,
            },
        );
        addrs.push(node_addr);
    }

    node.process_pending_retries(1).await;

    let processed = addrs
        .iter()
        .filter(|addr| {
            node.retry_pending
                .get(addr)
                .is_some_and(|state| state.retry_count > 0)
        })
        .count();
    let deferred = addrs.len().saturating_sub(processed);

    assert_eq!(processed, 16);
    assert_eq!(deferred, 4);
    assert_eq!(node.retry_pending.len(), 20);
}

#[tokio::test]
async fn ambient_no_transport_retries_enter_traversal_cooldown() {
    let peer = Identity::generate();
    let peer_npub = peer.npub();
    let peer_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();
    let mut peer_config = crate::config::PeerConfig::new(
        peer_npub.clone(),
        "udp",
        "203.0.113.7:2121",
    );
    peer_config.auto_reconnect = false;

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.retry.max_retries = 10;
    let mut node = Node::new(config).unwrap();
    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    node.nostr_discovery = Some(bootstrap.clone());

    let mut retry = crate::node::retry::RetryState::new(peer_config);
    retry.retry_after_ms = 0;
    retry.expires_at_ms = Some(120_000);
    node.retry_pending.insert(peer_addr, retry);

    let mut now_ms = 1_000;
    for _ in 0..5 {
        node.retry_pending
            .get_mut(&peer_addr)
            .expect("ambient retry remains bounded")
            .retry_after_ms = now_ms;
        node.process_pending_retries(now_ms).await;
        now_ms += 1_000;
    }

    let cooldown_until = bootstrap
        .cooldown_until(&peer_npub, now_ms)
        .expect("repeated unusable ambient adverts should enter traversal cooldown");
    assert!(
        node.retry_pending
            .get(&peer_addr)
            .is_some_and(|state| state.retry_after_ms >= cooldown_until),
        "the bounded retry queue must not fire before the traversal cooldown expires"
    );
}

#[tokio::test]
async fn active_direct_refresh_retries_are_background_budgeted() {
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    let mut node = Node::new(config).unwrap();
    node.nostr_discovery = Some(Arc::new(NostrDiscovery::new_for_test()));
    let mut addrs = Vec::new();

    for _ in 0..6 {
        let identity = Identity::generate();
        let npub = identity.npub();
        let peer_identity = PeerIdentity::from_npub(&npub).unwrap();
        let node_addr = *peer_identity.node_addr();
        let peer_config = crate::config::PeerConfig {
            npub,
            alias: None,
            addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
            connect_policy: crate::config::ConnectPolicy::AutoConnect,
            auto_reconnect: true,
            discovery_fallback_transit: true,
        };
        node.config.peers.push(peer_config.clone());
        node.peers
            .insert(node_addr, ActivePeer::new(peer_identity, LinkId::new(7), 0));
        node.retry_pending.insert(
            node_addr,
            crate::node::retry::RetryState {
                peer_config,
                retry_count: 0,
                retry_after_ms: 0,
                reconnect: true,
                expires_at_ms: None,
            },
        );
        addrs.push(node_addr);
    }

    node.process_pending_retries(1_000).await;

    let processed = addrs
        .iter()
        .filter(|addr| {
            node.retry_pending
                .get(addr)
                .is_some_and(|state| state.retry_after_ms > 1_000)
        })
        .count();

    assert_eq!(
        processed, 2,
        "active direct refresh retries should be paced as background probes"
    );
    assert!(addrs.iter().all(|addr| {
        node.retry_pending
            .get(addr)
            .is_some_and(|state| state.retry_count == 0)
    }));
    assert_eq!(node.retry_pending.len(), 6);
}

#[tokio::test]
async fn active_direct_refresh_no_transport_is_cooled_down() {
    let peer_identity = Identity::generate();
    let npub = peer_identity.npub();
    let peer_config = crate::config::PeerConfig {
        npub,
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer_identity = PeerIdentity::from_npub(&peer_config.npub).unwrap();
    let node_addr = *peer_identity.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).unwrap();
    node.nostr_discovery = Some(Arc::new(NostrDiscovery::new_for_test()));
    node.peers
        .insert(node_addr, ActivePeer::new(peer_identity, LinkId::new(7), 0));
    node.retry_pending.insert(
        node_addr,
        crate::node::retry::RetryState {
            peer_config,
            retry_count: 0,
            retry_after_ms: 0,
            reconnect: true,
            expires_at_ms: None,
        },
    );

    node.process_pending_retries(1_000).await;

    let retry = node
        .retry_pending
        .get(&node_addr)
        .expect("active direct refresh retry should stay queued");
    assert_eq!(
        retry.retry_count, 0,
        "active fallback refresh failures should not enter peer backoff"
    );
    assert!(
        retry.retry_after_ms >= 31_000,
        "no-transport active refresh should cool down instead of refiring quickly, got {}",
        retry.retry_after_ms
    );

    node.process_pending_retries(2_000).await;

    let retry = node
        .retry_pending
        .get(&node_addr)
        .expect("active direct refresh retry should stay queued");
    assert!(
        retry.retry_after_ms >= 31_000,
        "cooled-down no-transport refresh should not fire again on the next tick"
    );
}

#[tokio::test]
async fn established_fallback_session_direct_refresh_stays_out_of_peer_backoff() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority(
            "udp",
            "127.0.0.1:9",
            1,
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer_addr = *PeerIdentity::from_npub(&peer_config.npub)
        .expect("peer identity")
        .node_addr();

    let fsp = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let mut config = Config::new();
    config.peers.push(peer_config.clone());
    let mut node = Node::with_identity(local_identity, config).expect("node");
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

    let session = crate::node::session::SessionEntry::new(
        peer_addr,
        peer_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(fsp),
        1_000,
        true,
    );
    node.sessions.insert(peer_addr, session);

    let mut retry = crate::node::retry::RetryState::new(peer_config);
    retry.reconnect = true;
    retry.retry_count = 12;
    retry.retry_after_ms = 0;
    node.retry_pending.insert(peer_addr, retry);

    node.process_pending_retries(1_000).await;

    let retry = node
        .retry_pending
        .get(&peer_addr)
        .expect("direct refresh should remain queued while fallback session is live");
    assert_eq!(
        retry.retry_count, 0,
        "a live fallback FIPS session should keep direct refresh out of peer-level exponential backoff"
    );
    assert!(
        (11_000..=21_000).contains(&retry.retry_after_ms),
        "fallback direct refresh should be paced after an attempt, got {}",
        retry.retry_after_ms
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

/// Test that auto-connect peers with auto-reconnect enabled retry indefinitely
/// (never exhaust).
#[test]
fn test_schedule_retry_auto_reconnect_never_exhausts() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.node.retry.max_retries = 2;
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    // All attempts should keep the entry alive despite max_retries=2.
    node.schedule_retry(peer_node_addr, 1000);
    assert!(node.retry_pending.contains_key(&peer_node_addr));

    node.schedule_retry(peer_node_addr, 2000);
    assert!(node.retry_pending.contains_key(&peer_node_addr));

    // Attempt 3 would have exhausted before, but now retries indefinitely
    node.schedule_retry(peer_node_addr, 3000);
    assert!(
        node.retry_pending.contains_key(&peer_node_addr),
        "Auto-connect peers should never exhaust retries"
    );
    assert_eq!(
        node.retry_pending.get(&peer_node_addr).unwrap().retry_count,
        3
    );
}

/// Test that auto-connect peers with auto-reconnect disabled remain bounded.
#[test]
fn test_schedule_retry_auto_connect_without_auto_reconnect_exhausts() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut peer_config = crate::config::PeerConfig::new(peer_npub, "udp", "10.0.0.2:2121");
    peer_config.auto_reconnect = false;

    let mut config = Config::new();
    config.node.retry.max_retries = 2;
    config.peers.push(peer_config);

    let mut node = Node::new(config).unwrap();

    node.schedule_retry(peer_node_addr, 1000);
    {
        let state = node.retry_pending.get(&peer_node_addr).unwrap();
        assert_eq!(state.retry_count, 1);
        assert!(
            !state.reconnect,
            "auto_reconnect=false should keep failed-handshake retries bounded"
        );
    }

    node.schedule_retry(peer_node_addr, 2000);
    assert!(node.retry_pending.contains_key(&peer_node_addr));

    node.schedule_retry(peer_node_addr, 3000);
    assert!(
        !node.retry_pending.contains_key(&peer_node_addr),
        "finite auto-connect retries should exhaust at max_retries"
    );
}

/// Test that schedule_retry does nothing when max_retries is 0.
#[test]
fn test_schedule_retry_disabled() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.node.retry.max_retries = 0;
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    node.schedule_retry(peer_node_addr, 1000);
    assert!(
        node.retry_pending.is_empty(),
        "No retry should be scheduled when max_retries=0"
    );
}

/// Test that schedule_retry does nothing for non-auto-connect peers.
#[test]
fn test_schedule_retry_ignores_non_autoconnect() {
    let peer_identity = Identity::generate();
    let peer_node_addr = *peer_identity.node_addr();

    // No peers configured at all
    let mut node = make_node();

    node.schedule_retry(peer_node_addr, 1000);
    assert!(
        node.retry_pending.is_empty(),
        "No retry for unconfigured peer"
    );
}

/// Test that schedule_retry does nothing if peer is already connected.
#[test]
fn test_schedule_retry_skips_connected_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Promote a peer so it's in the peers map
    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();
    assert_eq!(node.peer_count(), 1);

    // Scheduling a retry for an already-connected peer should be a no-op
    node.schedule_retry(node_addr, 3000);
    assert!(
        node.retry_pending.is_empty(),
        "No retry for already-connected peer"
    );
}

#[test]
fn test_schedule_retry_keeps_connected_bootstrap_peer_refreshable() {
    let peer_full = Identity::generate();
    let peer_npub = peer_full.npub();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "127.0.0.1:9",
    ));
    let mut node = Node::new(config).unwrap();

    let bootstrap_id = TransportId::new(99);
    node.bootstrap_transports.mark(bootstrap_id);
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), 1_000);
    active_peer.set_current_addr(bootstrap_id, &TransportAddr::from_string("127.0.0.1:9"));
    node.peers.insert(peer_node_addr, active_peer);

    node.schedule_retry(peer_node_addr, 3_000);

    assert!(
        node.retry_pending.contains_key(&peer_node_addr),
        "bootstrap/fallback paths should not permanently suppress direct refresh retries"
    );
}

#[test]
fn test_schedule_retry_active_fallback_paces_direct_reprobe() {
    let peer_full = Identity::generate();
    let peer_npub = peer_full.npub();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();

    let peer_config = crate::config::PeerConfig {
        npub: peer_npub,
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).unwrap();

    let bootstrap_id = TransportId::new(99);
    node.bootstrap_transports.mark(bootstrap_id);
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), 1_000);
    active_peer.set_current_addr(bootstrap_id, &TransportAddr::from_string("127.0.0.1:9"));
    node.peers.insert(peer_node_addr, active_peer);

    let mut state = super::super::retry::RetryState::new(peer_config);
    state.retry_count = 8;
    state.retry_after_ms = 120_000;
    state.reconnect = true;
    node.retry_pending.insert(peer_node_addr, state);

    node.schedule_retry(peer_node_addr, 3_000);

    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert_eq!(
        state.retry_count, 0,
        "active fallback direct refresh must not inherit peer-level exponential backoff"
    );
    assert!(
        (13_000..=23_000).contains(&state.retry_after_ms),
        "active fallback direct refresh should use a paced jittered reprobe, got {}",
        state.retry_after_ms
    );
}

#[tokio::test]
async fn test_try_peer_addresses_skips_connected_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let (conn, peer_identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_config = crate::config::PeerConfig::new(peer_identity.npub(), "udp", "127.0.0.1:9");

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, peer_identity, 2000)
        .unwrap();
    let link_count = node.link_count();
    let connection_count = node.connection_count();

    node.try_peer_addresses(&peer_config, peer_identity, true)
        .await
        .unwrap();

    assert_eq!(
        node.link_count(),
        link_count,
        "stale retry/traversal fallback must not create a duplicate link"
    );
    assert_eq!(
        node.connection_count(),
        connection_count,
        "stale retry/traversal fallback must not create a duplicate handshake"
    );
}

#[tokio::test]
async fn test_try_peer_addresses_skips_connecting_peer() {
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

    let peer_identity = make_peer_identity();
    let peer_config = crate::config::PeerConfig::new(peer_identity.npub(), "udp", "127.0.0.1:9");
    let mut pending = PeerConnection::outbound(LinkId::new(1), peer_identity, 1000);
    pending.set_transport_id(transport_id);
    pending.set_source_addr(TransportAddr::from_string("127.0.0.1:9"));
    node.add_connection(pending).unwrap();

    node.try_peer_addresses(&peer_config, peer_identity, true)
        .await
        .unwrap();

    assert_eq!(
        node.connection_count(),
        1,
        "stale retry/traversal fallback must not start a second handshake"
    );
    assert_eq!(
        node.link_count(),
        0,
        "stale retry/traversal fallback must not allocate a link for the duplicate path"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_nostr_traversal_failure_skips_connected_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let now_ms = Node::now_ms();
    let (conn, peer_identity) = make_completed_connection(&mut node, link_id, transport_id, now_ms);
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, peer_identity, now_ms)
        .unwrap();
    let peer_addr = *peer_identity.node_addr();
    let current_addr = node
        .peers
        .get(&peer_addr)
        .and_then(|peer| peer.current_addr().cloned())
        .expect("promoted test peer has a current address");
    node.peers
        .get_mut(&peer_addr)
        .expect("promoted test peer")
        .touch(Node::now_ms());

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    bootstrap.push_event_for_test(BootstrapEvent::Failed {
        peer_config: crate::config::PeerConfig::new(
            peer_identity.npub(),
            "udp",
            current_addr.to_string(),
        ),
        reason: "stale traversal failure".to_string(),
    });
    node.nostr_discovery = Some(bootstrap.clone());

    node.poll_nostr_discovery().await;

    assert!(
        bootstrap.failure_state_snapshot().is_empty(),
        "stale failures for connected peers must not affect traversal cooldown"
    );
    assert!(
        node.retry_pending.is_empty(),
        "stale failures for connected peers must not enqueue reconnect attempts"
    );
}

#[tokio::test]
async fn process_packet_ignores_punch_and_non_fmp_noise_for_bootstrap_cooldown() {
    let mut node = make_node();
    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let transport_id = TransportId::new(44);
    let peer = Identity::generate();
    let peer_npub = peer.npub();

    node.nostr_discovery = Some(bootstrap.clone());
    node.bootstrap_transports
        .register(transport_id, peer_npub.clone());

    let remote = crate::transport::TransportAddr::from_string("127.0.0.1:9");
    let mut punch = vec![0u8; 24];
    punch[..4].copy_from_slice(&crate::discovery::PUNCH_MAGIC.to_be_bytes());
    process_dataplane_control_packet_for_test(
        &mut node,
        ReceivedPacket::with_timestamp(
            transport_id,
            remote.clone(),
            crate::transport::PacketBuffer::new(punch),
            1,
        ),
    )
    .await;

    process_dataplane_control_packet_for_test(
        &mut node,
        ReceivedPacket::with_timestamp(
            transport_id,
            remote.clone(),
            crate::transport::PacketBuffer::new(vec![0x45, 0x00, 0x00, 0x00]),
            2,
        ),
    )
    .await;

    assert!(
        bootstrap.failure_state_snapshot().is_empty(),
        "stray punch/IPv4-looking datagrams must not poison bootstrap cooldown"
    );

    process_dataplane_control_packet_for_test(
        &mut node,
        ReceivedPacket::with_timestamp(
            transport_id,
            remote,
            crate::transport::PacketBuffer::new(vec![0x11, 0x00, 0x00, 0x00]),
            3,
        ),
    )
    .await;

    assert_eq!(
        bootstrap.failure_state_snapshot().len(),
        1,
        "a plausible FMP packet with a different version should still be treated as structural"
    );
}

async fn process_dataplane_control_packet_for_test(node: &mut Node, packet: ReceivedPacket) {
    let (packet_tx, mut packet_rx) = packet_channel(1);
    packet_tx.send(packet).expect("packet should enqueue");
    let (_endpoint_tx, mut endpoint_rx) = crate::node::endpoint_data_batch_channel(1);
    let (_tun_outbound_tx, mut tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
    let (_fast_tx, mut fast_ingress_rx) = tokio::sync::mpsc::channel(1);
    let (endpoint_tx, _endpoint_rx) = crate::node::EndpointEventSender::channel(1);

    let mut turn = {
        let mut dataplane_io = crate::node::handlers::rx_loop_dataplane_io(
            &mut packet_rx,
            &mut fast_ingress_rx,
            &mut endpoint_rx,
            &mut tun_outbound_rx,
            &endpoint_tx,
        );
        node.drain_dataplane_turn_with_firsts(
            &mut dataplane_io,
            crate::dataplane::DataplaneLiveTurnFirsts::default(),
            crate::node::handlers::RxLoopDataplaneTurnLimits::new(1, 0, 0, 1),
        )
        .await
    };
    node.process_dataplane_control_ingress(&mut turn).await;
}

#[tokio::test]
async fn test_process_pending_retries_drops_expired_entries() {
    let mut node = make_node();
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut state = super::super::retry::RetryState::new(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "127.0.0.1:9",
    ));
    state.retry_after_ms = 0;
    state.expires_at_ms = Some(1_000);
    state.reconnect = true;
    node.retry_pending.insert(peer_node_addr, state);

    node.process_pending_retries(1_000).await;

    assert!(
        !node.retry_pending.contains_key(&peer_node_addr),
        "expired retry entries should be dropped before retry processing"
    );
}

/// Test that schedule_reconnect preserves accumulated backoff across link-dead cycles.
///
/// Regression test for issue #5: previously `schedule_reconnect` always created a
/// fresh `RetryState` with `retry_count=0`, discarding any backoff accumulated by
/// prior failed handshake attempts. On repeated link-dead evictions the node would
/// restart exponential backoff from the base interval every time instead of
/// continuing to back off.
#[test]
fn test_schedule_reconnect_preserves_backoff() {
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

    // Simulate two stale handshake timeouts incrementing the retry count.
    node.schedule_retry(peer_node_addr, 1_000); // count=1, delay=10s
    node.schedule_retry(peer_node_addr, 11_000); // count=2, delay=20s
    {
        let state = node.retry_pending.get(&peer_node_addr).unwrap();
        assert_eq!(state.retry_count, 2, "Two failures should yield count=2");
    }

    // Now simulate a link-dead removal triggering schedule_reconnect.
    // The existing retry entry (count=2) should be preserved and bumped to 3,
    // NOT reset to 0 as it was before the fix.
    node.schedule_reconnect(peer_node_addr, 31_000);

    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert!(state.reconnect, "Entry should be marked as reconnect");
    assert_eq!(
        state.retry_count, 3,
        "schedule_reconnect should increment existing count (was 2), not reset to 0 (regression: issue #5)"
    );

    // With count=3, backoff should be 5s * 2^3 = 40s.
    let base_ms = node.config.node.retry.base_interval_secs * 1000;
    let max_ms = node.config.node.retry.max_backoff_secs * 1000;
    let expected_delay = state.backoff_ms(base_ms, max_ms);
    assert_eq!(
        state.retry_after_ms,
        31_000 + expected_delay,
        "retry_after_ms should reflect count=3 backoff"
    );
}

/// Test that schedule_reconnect on a fresh peer (no prior retry entry) starts at count=0.
#[test]
fn test_schedule_reconnect_fresh_state() {
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

    // No prior retry entry — first reconnect should use base delay.
    node.schedule_reconnect(peer_node_addr, 1_000);

    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert!(state.reconnect, "Entry should be marked as reconnect");
    assert_eq!(
        state.retry_count, 0,
        "Fresh reconnect should start at count=0"
    );
    // Base delay: 5s * 2^0 = 5s
    let base_ms = node.config.node.retry.base_interval_secs * 1000;
    let max_ms = node.config.node.retry.max_backoff_secs * 1000;
    let expected_delay = state.backoff_ms(base_ms, max_ms);
    assert_eq!(state.retry_after_ms, 1_000 + expected_delay);
}

#[test]
fn test_schedule_link_dead_reprobe_resets_backoff() {
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
    node.schedule_retry(peer_node_addr, 1_000);
    node.schedule_retry(peer_node_addr, 11_000);
    assert_eq!(
        node.retry_pending.get(&peer_node_addr).unwrap().retry_count,
        2
    );

    node.schedule_link_dead_reprobe(peer_node_addr, 31_000);

    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert!(state.reconnect);
    assert_eq!(
        state.retry_count, 0,
        "link-dead direct paths should not preserve peer-level exponential backoff"
    );
    assert!(
        (31_500..=32_500).contains(&state.retry_after_ms),
        "link-dead should schedule a quick jittered direct re-probe, got {}",
        state.retry_after_ms
    );
}
