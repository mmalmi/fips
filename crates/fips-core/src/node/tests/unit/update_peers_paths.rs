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
    refresh_configured_peer_cache_for_test(&mut node);
    let mut state = super::super::retry::RetryState::new(peer);
    state.retry_after_ms = 0;
    state.reconnect = true;
    node.retry_pending.insert(peer_node_addr, state);

    node.process_pending_retries(1_000).await;

    assert_eq!(node.peer_count(), 1);
    assert_eq!(
        node.connection_count(),
        1,
        "retry maintenance should try only the configured direct path before its lower-priority old UDP fallback"
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
    assert!(attempted.contains("127.0.0.1:9"));
    assert!(
        node.retry_pending
            .get(&peer_node_addr)
            .is_some_and(|state| (3_000..=5_000).contains(&state.retry_after_ms)),
        "active fallback direct refresh should be paced after an attempt, got {:?}",
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
async fn active_bootstrap_refresh_renegotiates_without_discovery_hint() {
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
        1,
        "static direct hint should be tried before the lower-priority old UDP path while fallback remains active"
    );
    assert_eq!(
        bootstrap.active_initiator_count_for_test().await,
        1,
        "an authenticated bootstrap path must renegotiate direct connectivity without relying on an expiring discovery hint"
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
async fn active_nostr_peer_without_static_addresses_only_retests_observed_udp_path() {
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
        0,
        "an observed endpoint without udp:nat must not invent a NAT traversal attempt"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn active_fallback_concrete_hints_also_start_mesh_traversal() {
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
        addresses: vec![crate::config::PeerAddress::with_priority(
            "udp",
            "127.0.0.1:8",
            1,
        )],
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
        "an active mesh fallback must negotiate a fresh direct path even when concrete hints exist"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}
