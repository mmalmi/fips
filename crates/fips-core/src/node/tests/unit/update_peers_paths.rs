use super::*;

#[tokio::test]
async fn update_peers_races_primary_path_when_active_peer_uses_bootstrap_transport() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let bootstrap_id = TransportId::new(1);
    let primary_id = TransportId::new(2);
    for (transport_id, name) in [(bootstrap_id, "nostr-nat"), (primary_id, "main")] {
        let mut udp = UdpTransport::new(
            transport_id,
            Some(name.to_string()),
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx.clone(),
        );
        udp.start_async().await.unwrap();
        node.transports
            .insert(transport_id, TransportHandle::Udp(udp));
    }
    node.bootstrap_transports.mark(bootstrap_id);

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(bootstrap_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);

    let peer = auto_connect_peer(peer_full.npub(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.unchanged, 1);
    assert_eq!(node.peer_count(), 1);
    assert_eq!(
        node.connection_count(),
        1,
        "bootstrap NAT path should not suppress a primary-transport refresh"
    );
    let conn = node.peers.connection_values().next().unwrap();
    assert_eq!(conn.transport_id(), Some(primary_id));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn process_pending_retries_races_primary_path_for_active_bootstrap_peer() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let bootstrap_id = TransportId::new(1);
    let primary_id = TransportId::new(2);
    for (transport_id, name) in [(bootstrap_id, "nostr-nat"), (primary_id, "main")] {
        let mut udp = UdpTransport::new(
            transport_id,
            Some(name.to_string()),
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx.clone(),
        );
        udp.start_async().await.unwrap();
        node.transports
            .insert(transport_id, TransportHandle::Udp(udp));
    }
    node.bootstrap_transports.mark(bootstrap_id);

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), 1_000);
    active_peer.set_current_addr(bootstrap_id, &TransportAddr::from_string("127.0.0.1:8"));
    node.peers.insert(peer_node_addr, active_peer);

    let peer = auto_connect_peer(peer_full.npub(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];
    let mut state = super::super::retry::RetryState::new(peer);
    state.retry_after_ms = 0;
    state.reconnect = true;
    node.retry_pending.insert(peer_node_addr, state);

    node.process_pending_retries(1_000).await;

    assert_eq!(node.peer_count(), 1);
    assert_eq!(
        node.connection_count(),
        2,
        "retry maintenance should race the configured direct path and re-probe the old UDP path while fallback remains active"
    );
    let attempted: std::collections::HashSet<_> = node
        .peers
        .connection_values()
        .filter_map(|conn| {
            (conn.transport_id() == Some(primary_id))
                .then(|| conn.source_addr().map(ToString::to_string))
                .flatten()
        })
        .collect();
    assert!(attempted.contains("127.0.0.1:8"));
    assert!(attempted.contains("127.0.0.1:9"));
    assert!(
        node.retry_pending
            .get(&peer_node_addr)
            .is_some_and(|state| (1_500..=2_500).contains(&state.retry_after_ms)),
        "active fallback direct refresh should stay on quick reprobe cadence, got {:?}",
        node.retry_pending
            .get(&peer_node_addr)
            .map(|state| state.retry_after_ms)
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn active_direct_refresh_reclaims_inflight_slot_for_configured_static_path() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let primary_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        primary_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(primary_id, TransportHandle::Udp(udp));

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let current_addr = TransportAddr::from_string("127.0.0.1:20000");
    let active_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, active_link_id, 1_000);
    active_peer.set_current_addr(primary_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        active_link_id,
        Link::connectionless(
            active_link_id,
            primary_id,
            current_addr,
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );

    let static_addr = "127.0.0.1:9";
    let peer_config = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority(
            "udp",
            static_addr,
            10,
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers = vec![peer_config.clone()];
    refresh_configured_peer_cache_for_test(&mut node);

    for port in [10, 11, 12, 13] {
        node.initiate_connection(
            primary_id,
            TransportAddr::from_string(&format!("127.0.0.1:{port}")),
            peer_identity,
        )
        .await
        .unwrap();
    }
    assert_eq!(
        node.connection_count(),
        4,
        "test setup should fill the per-peer path-candidate budget"
    );

    let mut state = super::super::retry::RetryState::new(peer_config);
    state.retry_after_ms = 0;
    state.reconnect = true;
    node.retry_pending.insert(peer_node_addr, state);

    node.process_pending_retries(1_000).await;

    let static_transport_addr = TransportAddr::from_string(static_addr);
    assert!(
        node.find_link_by_addr(primary_id, &static_transport_addr)
            .is_some(),
        "a configured static path must be able to reclaim a lower-priority in-flight slot"
    );
    assert_eq!(
        node.connection_count(),
        4,
        "refresh should replace one lower-priority candidate instead of exceeding the cap"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn active_direct_refresh_prioritizes_configured_static_over_observed_udp_endpoint() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let primary_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        primary_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(primary_id, TransportHandle::Udp(udp));

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let observed_addr = TransportAddr::from_string("127.0.0.1:21000");
    let static_addr = TransportAddr::from_string("127.0.0.1:22000");
    let active_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, active_link_id, 1_000);
    active_peer.set_current_addr(primary_id, &observed_addr);
    node.peers.insert(peer_node_addr, active_peer);

    let peer_config = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority(
            "udp",
            static_addr.to_string(),
            1,
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers = vec![peer_config.clone()];
    refresh_configured_peer_cache_for_test(&mut node);

    let mut candidates = node.peer_address_candidates(&peer_config).await;
    if let Some(candidate) = node.active_peer_current_udp_candidate(&peer_node_addr)
        && !candidates.iter().any(|existing| {
            existing.transport == candidate.transport && existing.addr == candidate.addr
        })
    {
        candidates.push(candidate);
        candidates.sort_by(|a, b| {
            if a.priority != b.priority {
                return a.priority.cmp(&b.priority);
            }
            match (a.seen_at_ms, b.seen_at_ms) {
                (Some(a_ts), Some(b_ts)) => b_ts.cmp(&a_ts),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        });
    }

    assert_eq!(candidates[0].addr, static_addr.to_string());
    assert_eq!(candidates[1].addr, observed_addr.to_string());
    assert_eq!(
        candidates[1].priority,
        u8::MAX,
        "observed source tuples must not outrank configured static UDP addresses"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn active_fallback_static_hint_also_queues_nostr_traversal() {
    use crate::config::NostrDiscoveryPolicy;
    use crate::node::session::{EndToEndState, SessionEntry};
    use crate::noise::HandshakeState;

    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let peer_config = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::new("udp", "127.0.0.1:9")],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: false,
    };

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
    config.peers = vec![peer_config.clone()];
    let mut node = Node::new(config).expect("node");
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let bootstrap_id = TransportId::new(1);
    let primary_id = TransportId::new(2);
    for (transport_id, name) in [(bootstrap_id, "fips-mesh"), (primary_id, "main")] {
        let mut udp = UdpTransport::new(
            transport_id,
            Some(name.to_string()),
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx.clone(),
        );
        udp.start_async().await.unwrap();
        node.transports
            .insert(transport_id, TransportHandle::Udp(udp));
    }
    node.bootstrap_transports.mark(bootstrap_id);

    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), 1_000);
    active_peer.set_current_addr(bootstrap_id, &TransportAddr::from_string("127.0.0.1:8"));
    node.peers.insert(peer_node_addr, active_peer);

    let mut initiator =
        HandshakeState::new_initiator(node.identity.keypair(), peer_full.pubkey_full());
    let mut responder = HandshakeState::new_responder(peer_full.keypair());
    initiator.set_local_epoch([0x01; 8]);
    responder.set_local_epoch([0x02; 8]);
    let msg1 = initiator.write_message_1().expect("msg1");
    responder.read_message_1(&msg1).expect("read msg1");
    let msg2 = responder.write_message_2().expect("msg2");
    initiator.read_message_2(&msg2).expect("read msg2");
    node.sessions.insert(
        peer_node_addr,
        SessionEntry::new(
            peer_node_addr,
            peer_full.pubkey_full(),
            EndToEndState::Established(initiator.into_session().expect("session")),
            1_000,
            true,
        ),
    );

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    node.nostr_discovery = Some(bootstrap.clone());
    let mut state = super::super::retry::RetryState::new(peer_config);
    state.retry_after_ms = 0;
    state.reconnect = true;
    node.retry_pending.insert(peer_node_addr, state);

    node.process_pending_retries(1_000).await;

    assert_eq!(
        node.connection_count(),
        2,
        "static direct hint and old UDP path should be raced while fallback remains active"
    );
    assert_eq!(
        bootstrap.active_initiator_count_for_test().await,
        1,
        "stale static hints must not suppress Nostr/mesh traversal refresh"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn stale_active_direct_refresh_does_not_prioritize_old_current_path() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let primary_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        primary_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(primary_id, TransportHandle::Udp(udp));

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let old_current_addr = TransportAddr::from_string("127.0.0.1:21000");
    let active_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, active_link_id, 1_000);
    active_peer.set_current_addr(primary_id, &old_current_addr);
    active_peer.mark_stale();
    node.peers.insert(peer_node_addr, active_peer);

    let peer_config = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: (0..4)
            .map(|offset| {
                crate::config::PeerAddress::with_priority(
                    "udp",
                    format!("127.0.0.1:{}", 22000 + offset),
                    1,
                )
            })
            .collect(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers = vec![peer_config.clone()];
    refresh_configured_peer_cache_for_test(&mut node);

    let outcome = node.update_peers(vec![peer_config]).await.unwrap();
    assert_eq!(outcome.unchanged, 1);

    let attempted: std::collections::HashSet<_> = node
        .peers
        .connection_values()
        .filter_map(|conn| {
            (conn.transport_id() == Some(primary_id))
                .then(|| conn.source_addr().map(ToString::to_string))
                .flatten()
        })
        .collect();

    assert_eq!(
        attempted.len(),
        4,
        "fresh configured candidates should consume the race budget first"
    );
    assert!(
        !attempted.contains("127.0.0.1:21000"),
        "a stale old current path must not displace fresher candidates after roaming"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn active_nostr_peer_without_static_addresses_retests_observed_udp_path() {
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    let mut node = Node::new(config).expect("node");
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let primary_id = TransportId::new(2);
    let mut udp = UdpTransport::new(
        primary_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(primary_id, TransportHandle::Udp(udp));

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let peer_config = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers = vec![peer_config.clone()];

    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), 1_000);
    active_peer.set_current_addr(primary_id, &current_addr);
    active_peer.mark_reconnecting();
    node.peers.insert(peer_node_addr, active_peer);

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    node.nostr_discovery = Some(bootstrap.clone());
    node.config.node.discovery.nostr.enabled = true;
    node.config.node.discovery.nostr.policy = crate::config::NostrDiscoveryPolicy::ConfiguredOnly;
    refresh_configured_peer_cache_for_test(&mut node);
    let mut state = super::super::retry::RetryState::new(peer_config);
    state.retry_after_ms = 0;
    state.reconnect = true;
    node.retry_pending.insert(peer_node_addr, state);

    node.process_pending_retries(1_000).await;

    assert_eq!(
        node.connection_count(),
        1,
        "reconnecting active peers with no static hints should still probe the last observed UDP endpoint"
    );
    let conn = node.peers.connection_values().next().unwrap();
    assert_eq!(conn.transport_id(), Some(primary_id));
    assert_eq!(conn.source_addr(), Some(&current_addr));
    assert_eq!(
        bootstrap.active_initiator_count_for_test().await,
        1,
        "direct refresh should also send a Nostr/mesh call-me-maybe request"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn active_fallback_uses_cached_direct_advert_as_probe_hint() {
    use crate::discovery::nostr::{OverlayEndpointAdvert, OverlayTransportKind};

    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let primary_id = TransportId::new(2);
    let mut udp = UdpTransport::new(
        primary_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(primary_id, TransportHandle::Udp(udp));

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let peer_config = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: false,
    };
    node.config.node.discovery.nostr.enabled = true;
    node.config.node.discovery.nostr.policy = crate::config::NostrDiscoveryPolicy::ConfiguredOnly;
    node.config.peers = vec![peer_config.clone()];
    refresh_configured_peer_cache_for_test(&mut node);

    let bootstrap_id = TransportId::new(77);
    node.bootstrap_transports.mark(bootstrap_id);
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), 1_000);
    active_peer.set_current_addr(bootstrap_id, &TransportAddr::from_string("fips"));
    node.peers.insert(peer_node_addr, active_peer);

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let advert_addr = "127.0.0.1:9";
    let advert = NostrDiscovery::cached_advert_for_test(
        peer_config.npub.clone(),
        OverlayEndpointAdvert {
            transport: OverlayTransportKind::Udp,
            addr: advert_addr.to_string(),
        },
        1_700_000_000,
    );
    bootstrap
        .insert_advert_for_test(peer_config.npub.clone(), advert)
        .await;
    node.nostr_discovery = Some(bootstrap.clone());

    let mut state = super::super::retry::RetryState::new(peer_config);
    state.retry_after_ms = 0;
    state.reconnect = true;
    node.retry_pending.insert(peer_node_addr, state);

    node.process_pending_retries(1_000).await;

    assert!(
        node.find_link_by_addr(primary_id, &TransportAddr::from_string(advert_addr))
            .is_some(),
        "cached direct adverts are peer-location hints and should still be probed while fallback remains active"
    );
    assert_eq!(
        bootstrap.active_initiator_count_for_test().await,
        1,
        "probing a cached endpoint must not suppress the fresh Nostr/mesh traversal request"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn configured_direct_refresh_ignores_traversal_cooldown_for_mesh_signal() {
    use crate::config::NostrDiscoveryPolicy;

    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
    config.peers = vec![peer_config.clone()];
    let mut node = Node::new(config).expect("node");

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let now_ms = Node::now_ms();
    for i in 0..5 {
        bootstrap.record_traversal_failure(&peer_config.npub, now_ms + i * 1_000);
    }
    assert!(
        bootstrap
            .cooldown_until(&peer_config.npub, now_ms + 5_000)
            .is_some(),
        "fixture should put the peer in traversal cooldown"
    );
    node.nostr_discovery = Some(bootstrap.clone());

    assert!(
        node.request_nostr_bootstrap(&peer_config).await,
        "configured direct refresh should still send a call-me-maybe style mesh/Nostr request"
    );
    assert_eq!(
        bootstrap.active_initiator_count_for_test().await,
        1,
        "cooldown must not suppress immediate direct refresh probing for configured peers"
    );

    let mut mobile_peer = peer_config;
    mobile_peer.auto_reconnect = false;
    assert!(
        !node.request_nostr_bootstrap(&mobile_peer).await,
        "bounded mobile peers should stay quiet during traversal cooldown"
    );
}

#[tokio::test]
async fn mesh_signal_warms_session_instead_of_dropping_without_established_session() {
    use super::spanning_tree::{run_tree_test, verify_tree_convergence};
    use crate::discovery::nostr::{MeshTraversalSignal, TraversalOffer};

    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let peer_node_addr = *nodes[1].node.node_addr();
    let peer_npub = nodes[1].node.identity().npub();
    let peer_config = crate::config::PeerConfig {
        npub: peer_npub.clone(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: false,
    };

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    bootstrap.push_mesh_signal_for_test(MeshTraversalSignal::Offer {
        peer_npub: peer_npub.clone(),
        offer: TraversalOffer {
            message_type: "offer".to_string(),
            session_id: "session".to_string(),
            issued_at: 1,
            expires_at: 2,
            nonce: "nonce".to_string(),
            sender_npub: nodes[0].node.identity().npub(),
            recipient_npub: peer_npub,
            reflexive_address: None,
            local_addresses: Vec::new(),
            stun_server: None,
        },
    });
    nodes[0].node.config.node.discovery.nostr.enabled = true;
    nodes[0].node.config.peers = vec![peer_config];
    nodes[0].node.nostr_discovery = Some(bootstrap.clone());

    nodes[0].node.poll_nostr_discovery().await;

    assert!(
        nodes[0]
            .node
            .sessions
            .get(&peer_node_addr)
            .is_some_and(|entry| entry.is_initiating()),
        "mesh signal delivery should warm an end-to-end session over the existing mesh route"
    );
    assert!(
        bootstrap.drain_mesh_signals().await.is_empty(),
        "deferred mesh signals must not be requeued into the per-tick discovery channel"
    );
    assert_eq!(nodes[0].node.pending_mesh_signals.len(), 1);

    nodes[0].node.poll_nostr_discovery().await;
    assert_eq!(
        nodes[0].node.pending_mesh_signals.len(),
        1,
        "waiting for session readiness must retain one parsed signal without duplicating it"
    );
}

#[tokio::test]
async fn outbound_refresh_promotion_moves_active_peer_to_new_transport_tuple() {
    let mut node = make_node();
    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();

    let old_transport_id = TransportId::new(1);
    let old_link_id = LinkId::new(10);
    let old_addr = TransportAddr::from_string("127.0.0.1:7000");
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(old_transport_id, &old_addr);
    active_peer.mark_stale();
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            old_transport_id,
            old_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((old_transport_id, old_addr.clone()), old_link_id);

    let new_transport_id = TransportId::new(2);
    let new_link_id = LinkId::new(11);
    let new_addr = TransportAddr::from_string("127.0.0.1:9000");
    let mut conn = PeerConnection::outbound(new_link_id, peer_identity, 2_000);
    let our_index = node.index_allocator.allocate().unwrap();
    let noise_msg1 = conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 2_000)
        .unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(new_transport_id);
    conn.set_source_addr(new_addr.clone());
    node.links.insert(
        new_link_id,
        Link::connectionless(
            new_link_id,
            new_transport_id,
            new_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((new_transport_id, new_addr.clone()), new_link_id);
    node.peers.insert_connection(new_link_id, conn);
    node.pending_outbound
        .insert((new_transport_id, our_index.as_u32()), new_link_id);

    let mut responder = PeerConnection::inbound(LinkId::new(99), 2_000);
    let noise_msg2 = responder
        .receive_handshake_init(peer_full.keypair(), [0x42; 8], &noise_msg1, 2_000)
        .unwrap();
    let their_index = SessionIndex::new(77);
    let wire_msg2 = build_msg2(their_index, our_index, &noise_msg2);
    let packet = ReceivedPacket::with_timestamp(
        new_transport_id,
        new_addr.clone(),
        crate::transport::PacketBuffer::new(wire_msg2),
        2_100,
    );

    node.handle_msg2(packet).await;

    assert_eq!(node.connection_count(), 0);
    assert!(node.pending_outbound.is_empty());
    assert!(
        !node.links.contains_key(&old_link_id),
        "old active link should be retired after successful refresh"
    );
    assert!(
        node.links.contains_key(&new_link_id),
        "new outbound link should remain active"
    );
    assert_eq!(
        node.links.get_addr(&(old_transport_id, old_addr.clone())),
        None
    );
    assert_eq!(
        node.links
            .get_addr(&(new_transport_id, new_addr.clone()))
            .copied(),
        Some(new_link_id)
    );

    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), new_link_id);
    assert_eq!(active.transport_id(), Some(new_transport_id));
    assert_eq!(active.current_addr(), Some(&new_addr));
    assert_eq!(active.our_index(), Some(our_index));
    assert_eq!(active.their_index(), Some(their_index));
    assert_eq!(
        node.peers
            .get_session_index(&(new_transport_id, our_index.as_u32()))
            .copied(),
        Some(peer_node_addr)
    );
}

#[tokio::test]
async fn outbound_restart_promotion_clears_stale_fsp_session() {
    use crate::node::session::{EndToEndState, SessionEntry};
    use crate::noise::HandshakeState;

    let mut node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();

    let old_transport_id = TransportId::new(1);
    let old_link_id = LinkId::new(10);
    let old_addr = TransportAddr::from_string("127.0.0.1:7000");
    let mut old_conn = PeerConnection::outbound(old_link_id, peer_identity, 1_000);
    let old_msg1 = old_conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 1_000)
        .unwrap();
    let mut old_responder = PeerConnection::inbound(LinkId::new(98), 1_000);
    let old_msg2 = old_responder
        .receive_handshake_init(peer_full.keypair(), [0x11; 8], &old_msg1, 1_000)
        .unwrap();
    old_conn.complete_handshake(&old_msg2, 1_000).unwrap();
    let old_our_index = node.index_allocator.allocate().unwrap();
    old_conn.set_our_index(old_our_index);
    old_conn.set_their_index(SessionIndex::new(66));
    old_conn.set_transport_id(old_transport_id);
    old_conn.set_source_addr(old_addr.clone());
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            old_transport_id,
            old_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((old_transport_id, old_addr.clone()), old_link_id);
    node.peers.insert_connection(old_link_id, old_conn);
    node.promote_connection(old_link_id, peer_identity, 1_100)
        .unwrap();
    assert_eq!(
        node.get_peer(&peer_node_addr).unwrap().remote_epoch(),
        Some([0x11; 8])
    );

    let mut fsp_initiator =
        HandshakeState::new_initiator(node.identity.keypair(), peer_full.pubkey_full());
    let mut fsp_responder = HandshakeState::new_responder(peer_full.keypair());
    fsp_initiator.set_local_epoch([0x01; 8]);
    fsp_responder.set_local_epoch([0x02; 8]);
    let fsp_msg1 = fsp_initiator.write_message_1().unwrap();
    fsp_responder.read_message_1(&fsp_msg1).unwrap();
    let fsp_msg2 = fsp_responder.write_message_2().unwrap();
    fsp_initiator.read_message_2(&fsp_msg2).unwrap();
    let stale_session = fsp_initiator.into_session().unwrap();
    node.sessions.insert(
        peer_node_addr,
        SessionEntry::new(
            peer_node_addr,
            peer_full.pubkey_full(),
            EndToEndState::Established(stale_session),
            1_200,
            true,
        ),
    );
    assert!(node.sessions.get(&peer_node_addr).is_some());

    let new_transport_id = TransportId::new(2);
    let new_link_id = LinkId::new(11);
    let new_addr = TransportAddr::from_string("127.0.0.1:9000");
    let mut new_conn = PeerConnection::outbound(new_link_id, peer_identity, 2_000);
    let new_msg1 = new_conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 2_000)
        .unwrap();
    let mut new_responder = PeerConnection::inbound(LinkId::new(99), 2_000);
    let new_msg2 = new_responder
        .receive_handshake_init(peer_full.keypair(), [0x22; 8], &new_msg1, 2_000)
        .unwrap();
    new_conn.complete_handshake(&new_msg2, 2_100).unwrap();
    let new_our_index = node.index_allocator.allocate().unwrap();
    let their_index = SessionIndex::new(77);
    new_conn.set_our_index(new_our_index);
    new_conn.set_their_index(their_index);
    new_conn.set_transport_id(new_transport_id);
    new_conn.set_source_addr(new_addr.clone());
    node.links.insert(
        new_link_id,
        Link::connectionless(
            new_link_id,
            new_transport_id,
            new_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((new_transport_id, new_addr.clone()), new_link_id);
    node.peers.insert_connection(new_link_id, new_conn);

    let result = node
        .promote_connection(new_link_id, peer_identity, 2_100)
        .unwrap();
    assert!(matches!(result, PromotionResult::CrossConnectionWon { .. }));

    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), new_link_id);
    assert_eq!(active.remote_epoch(), Some([0x22; 8]));
    assert!(
        node.sessions.get(&peer_node_addr).is_none(),
        "old FSP session must be removed when the peer's startup epoch changes"
    );
}
