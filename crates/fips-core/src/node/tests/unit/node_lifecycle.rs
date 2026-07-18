use super::*;
use crate::node::lifecycle::{
    LocalInterfaceNetwork, udp_remote_addr_locally_plausible_with_evidence,
};
use std::net::{IpAddr, SocketAddr};

#[test]
fn test_node_creation() {
    let node = make_node();

    assert_eq!(node.state(), NodeState::Created);
    assert_eq!(node.peer_count(), 0);
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.link_count(), 0);
    assert!(!node.is_leaf_only());
}

#[test]
fn test_node_with_identity() {
    let identity = Identity::generate();
    let expected_node_addr = *identity.node_addr();
    let config = Config::new();

    let node = Node::with_identity(identity, config).unwrap();

    assert_eq!(node.node_addr(), &expected_node_addr);
}

#[test]
fn test_node_with_identity_validates_config() {
    let identity = Identity::generate();
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = false;
    config.peers = vec![crate::config::PeerConfig {
        npub: "npub1peer".to_string(),
        ..Default::default()
    }];

    let err = Node::with_identity(identity, config).expect_err("expected config validation error");
    assert!(matches!(err, NodeError::Config(_)));
}

#[test]
fn test_node_leaf_only() {
    let config = Config::new();
    let node = Node::leaf_only(config).unwrap();

    assert!(node.is_leaf_only());
    assert!(node.bloom_state().is_leaf_only());
}

#[tokio::test]
async fn test_nat_bootstrap_failure_falls_back_to_direct_udp_address() {
    let peer_identity = Identity::generate();
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

    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "nat", 1),
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:9", 2),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer_identity = PeerIdentity::from_npub(&peer_config.npub).unwrap();

    node.try_peer_addresses(&peer_config, peer_identity, false)
        .await
        .unwrap();

    assert_eq!(node.connection_count(), 1);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_try_peer_addresses_races_all_concrete_udp_candidates() {
    let peer_identity = Identity::generate();
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

    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:9", 1),
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:10", 2),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer_identity = PeerIdentity::from_npub(&peer_config.npub).unwrap();

    node.try_peer_addresses(&peer_config, peer_identity, false)
        .await
        .unwrap();

    let mut addrs = node
        .peers
        .connection_values()
        .filter_map(|conn| conn.source_addr().and_then(|addr| addr.as_str()))
        .collect::<Vec<_>>();
    addrs.sort();
    assert_eq!(addrs, vec!["127.0.0.1:10", "127.0.0.1:9"]);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_try_peer_addresses_skips_incompatible_udp_address_family() {
    let peer_identity = Identity::generate();
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

    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "[fd00::1]:9", 1),
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:9", 2),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer_identity = PeerIdentity::from_npub(&peer_config.npub).unwrap();

    node.try_peer_addresses(&peer_config, peer_identity, false)
        .await
        .unwrap();

    assert_eq!(node.connection_count(), 1);
    assert_eq!(
        node.peers
            .connection_values()
            .next()
            .and_then(|conn| conn.source_addr())
            .and_then(|addr| addr.as_str()),
        Some("127.0.0.1:9")
    );
    assert!(
        node.find_link_by_addr(
            transport_id,
            &crate::transport::TransportAddr::from_string("[fd00::1]:9"),
        )
        .is_none(),
        "IPv6 candidate must not allocate a failed link on an IPv4-only socket"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_transport_discovery_skips_incompatible_udp_address_family() {
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

    let candidate = node.transport_discovery_candidate(
        transport_id,
        crate::transport::TransportAddr::from_string("[fd00::1]:9"),
    );

    assert!(
        candidate.is_none(),
        "transport discovery must not feed IPv6 candidates to an IPv4 UDP socket"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[test]
fn test_private_udp_hint_requires_matching_local_scope() {
    let hotspot_local: SocketAddr = "10.7.0.2:51820".parse().unwrap();
    let stale_lan_remote: SocketAddr = "192.168.44.57:51820".parse().unwrap();
    let hotspot_network = LocalInterfaceNetwork {
        ip: "10.7.0.2".parse::<IpAddr>().unwrap(),
        mask: "255.255.255.0".parse::<IpAddr>().unwrap(),
    };
    let hotspot_probe = Some("10.7.0.2".parse::<IpAddr>().unwrap());

    assert!(
        !udp_remote_addr_locally_plausible_with_evidence(
            hotspot_local,
            stale_lan_remote,
            &[hotspot_network],
            hotspot_probe,
        ),
        "a private LAN endpoint hint from another subnet must not be treated as reachable"
    );

    let same_lan_network = LocalInterfaceNetwork {
        ip: "192.168.44.55".parse::<IpAddr>().unwrap(),
        mask: "255.255.255.0".parse::<IpAddr>().unwrap(),
    };
    assert!(
        udp_remote_addr_locally_plausible_with_evidence(
            hotspot_local,
            stale_lan_remote,
            &[same_lan_network],
            None,
        ),
        "the same private endpoint remains usable when a local interface is on that subnet"
    );

    let public_remote: SocketAddr = "198.51.100.7:51820".parse().unwrap();
    assert!(
        udp_remote_addr_locally_plausible_with_evidence(hotspot_local, public_remote, &[], None),
        "public UDP endpoint candidates do not need local subnet evidence"
    );
}

#[tokio::test]
async fn test_active_peer_match_rejects_unresolvable_numeric_udp_candidate() {
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

    let link_id = LinkId::new(10);
    let (mut connection, peer_identity) =
        make_completed_connection(&mut node, link_id, transport_id, 1_000);
    let peer_node_addr = *peer_identity.node_addr();
    let unreachable_addr = TransportAddr::from_string("[fd00::1]:51820");
    connection.set_source_addr(unreachable_addr);
    node.peers.insert_connection(link_id, connection);
    node.promote_connection(link_id, peer_identity, 1_100)
        .unwrap();

    let candidate = crate::config::PeerAddress::with_priority("udp", "[fd00::1]:51820", 1);
    assert!(
        !node.active_peer_matches_candidate(&peer_node_addr, &candidate),
        "parsed UDP candidates that cannot resolve to a compatible transport must not fall back to string matching"
    );
    assert!(
        node.active_peer_current_udp_candidate(&peer_node_addr)
            .is_none(),
        "an unresolvable current UDP tuple must not be reinserted as a fresh retry candidate"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_transport_discovery_avoids_bootstrap_udp_transport() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let bootstrap_id = TransportId::new(1);
    let primary_id = TransportId::new(2);
    for (transport_id, name) in [(bootstrap_id, "bootstrap"), (primary_id, "main")] {
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

    let candidate = node
        .transport_discovery_candidate(
            bootstrap_id,
            crate::transport::TransportAddr::from_string("127.0.0.1:9"),
        )
        .expect("primary UDP transport should be eligible");

    assert_eq!(candidate.0, primary_id);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_udp_transport_picker_ignores_bootstrap_transports() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let bootstrap_id = TransportId::new(1);
    let primary_id = TransportId::new(2);
    let other_primary_id = TransportId::new(3);

    for (transport_id, name) in [
        (bootstrap_id, "bootstrap"),
        (other_primary_id, "other-primary"),
        (primary_id, "primary"),
    ] {
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

    assert_eq!(node.find_transport_for_type("udp"), Some(primary_id));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_node_state_transitions() {
    let mut node = make_node();

    assert!(!node.is_running());
    assert!(node.state().can_start());

    node.start().await.unwrap();
    assert!(node.is_running());
    assert!(!node.state().can_start());

    node.stop().await.unwrap();
    assert!(!node.is_running());
    assert_eq!(node.state(), NodeState::Stopped);
}

#[tokio::test]
async fn test_node_start_does_not_wait_for_nostr_discovery_startup() {
    let mut config = Config::new();
    config.node.control.enabled = false;
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.advertise = true;
    config.node.discovery.nostr.policy = crate::config::NostrDiscoveryPolicy::Open;
    config.node.discovery.nostr.advert_relays = vec!["wss://127.0.0.1:9".to_string()];
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        advertise_on_nostr: Some(true),
        public: Some(false),
        accept_connections: Some(true),
        ..Default::default()
    });

    let mut node = Node::new(config).unwrap();
    tokio::time::timeout(std::time::Duration::from_millis(500), node.start())
        .await
        .expect("node start should not wait for relay I/O")
        .unwrap();

    assert!(node.is_running());
    assert!(node.nostr_discovery_handle().is_some());

    node.stop().await.unwrap();
}

#[tokio::test]
async fn test_node_double_start() {
    let mut node = make_node();
    node.start().await.unwrap();

    let result = node.start().await;
    assert!(matches!(result, Err(NodeError::AlreadyStarted)));

    // Clean up
    node.stop().await.unwrap();
}

#[tokio::test]
async fn test_node_stop_not_started() {
    let mut node = make_node();

    let result = node.stop().await;
    assert!(matches!(result, Err(NodeError::NotStarted)));
}

#[test]
fn test_node_link_management() {
    let mut node = make_node();

    let link_id = node.allocate_link_id();
    let link = Link::connectionless(
        link_id,
        TransportId::new(1),
        TransportAddr::from_string("test"),
        LinkDirection::Outbound,
        Duration::from_millis(50),
    );

    node.add_link(link).unwrap();
    assert_eq!(node.link_count(), 1);

    assert!(node.get_link(&link_id).is_some());

    // Test reverse address dispatch lookup.
    assert_eq!(
        node.find_link_by_addr(TransportId::new(1), &TransportAddr::from_string("test")),
        Some(link_id)
    );

    node.remove_link(&link_id);
    assert_eq!(node.link_count(), 0);

    // Lookup should be gone
    assert!(
        node.find_link_by_addr(TransportId::new(1), &TransportAddr::from_string("test"))
            .is_none()
    );
}

#[test]
fn test_node_link_limit() {
    let mut node = make_node();
    node.set_max_links(2);

    for i in 0..2 {
        let link_id = node.allocate_link_id();
        let link = Link::connectionless(
            link_id,
            TransportId::new(1),
            TransportAddr::from_string(&format!("test{}", i)),
            LinkDirection::Outbound,
            Duration::from_millis(50),
        );
        node.add_link(link).unwrap();
    }

    let link_id = node.allocate_link_id();
    let link = Link::connectionless(
        link_id,
        TransportId::new(1),
        TransportAddr::from_string("test_extra"),
        LinkDirection::Outbound,
        Duration::from_millis(50),
    );

    let result = node.add_link(link);
    assert!(matches!(result, Err(NodeError::MaxLinksExceeded { .. })));
}

#[test]
fn test_node_connection_management() {
    let mut node = make_node();

    let identity = make_peer_identity();
    let link_id = LinkId::new(1);
    let conn = PeerConnection::outbound(link_id, identity, 1000);

    node.add_connection(conn).unwrap();
    assert_eq!(node.connection_count(), 1);

    assert!(node.get_connection(&link_id).is_some());

    node.remove_connection(&link_id);
    assert_eq!(node.connection_count(), 0);
}

#[test]
fn test_node_connection_duplicate() {
    let mut node = make_node();

    let identity = make_peer_identity();
    let link_id = LinkId::new(1);
    let conn1 = PeerConnection::outbound(link_id, identity, 1000);
    let conn2 = PeerConnection::outbound(link_id, identity, 2000);

    node.add_connection(conn1).unwrap();
    let result = node.add_connection(conn2);

    assert!(matches!(result, Err(NodeError::ConnectionAlreadyExists(_))));
}

#[test]
fn test_node_promote_connection() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    assert_eq!(node.connection_count(), 1);
    assert_eq!(node.peer_count(), 0);

    let result = node.promote_connection(link_id, identity, 2000).unwrap();

    assert!(matches!(result, PromotionResult::Promoted(_)));
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.peer_count(), 1);

    let peer = node.get_peer(&node_addr).unwrap();
    assert_eq!(peer.authenticated_at(), 2000);
    assert!(peer.has_session(), "Promoted peer should have NoiseSession");
    assert!(
        peer.our_index().is_some(),
        "Promoted peer should have our_index"
    );
    assert!(
        peer.their_index().is_some(),
        "Promoted peer should have their_index"
    );

    // Verify active peer registry session-index dispatch is populated
    let our_index = peer.our_index().unwrap();
    assert_eq!(
        node.peers
            .get_session_index(&(transport_id, our_index.as_u32())),
        Some(&node_addr)
    );
}

#[test]
fn test_promote_open_discovery_retry_blocks_fallback_transit() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();

    let retry = crate::node::retry::RetryState::new(crate::config::PeerConfig {
        npub: identity.npub(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: false,
    });
    node.retry_pending.insert(node_addr, retry);

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();

    assert!(
        node.discovery_fallback_transit.is_blocked(&node_addr),
        "open-discovery retry peers should not become ambient lookup transit"
    );
}

#[test]
fn test_promote_nonconfigured_open_discovery_peer_blocks_fallback_transit() {
    let mut node = make_node();
    node.config.node.discovery.nostr.policy = crate::config::NostrDiscoveryPolicy::Open;
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();

    assert!(
        node.discovery_fallback_transit.is_blocked(&node_addr),
        "nonconfigured peers accepted under open discovery should not be fallback transit"
    );
}

#[tokio::test]
async fn test_promote_explicit_websocket_seed_allows_open_discovery_fallback_transit() {
    use crate::config::WebSocketConfig;
    use crate::transport::websocket::WebSocketTransport;

    let mut node = make_node();
    node.config.node.discovery.nostr.policy = crate::config::NostrDiscoveryPolicy::Open;
    node.config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    let transport_id = TransportId::new(1);
    let seed_url = "wss://seed.example/fips";
    let (packet_tx, _packet_rx) = packet_channel(8);
    let websocket = WebSocketTransport::new(
        transport_id,
        None,
        WebSocketConfig {
            seed_urls: vec![seed_url.to_string()],
            ..WebSocketConfig::default()
        },
        packet_tx,
        &node.identity,
    );
    node.transports.insert(
        transport_id,
        TransportHandle::WebSocket(Box::new(websocket)),
    );

    let link_id = LinkId::new(1);
    let (mut conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();
    conn.set_source_addr(TransportAddr::from_string(seed_url));

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();

    assert!(
        !node.discovery_fallback_transit.is_blocked(&node_addr),
        "an explicitly configured WebSocket seed is intended first-contact transit"
    );

    let target = Identity::generate();
    let target_identity = PeerIdentity::from_pubkey_full(target.pubkey_full());
    node.config.peers.push(crate::config::PeerConfig {
        npub: target_identity.npub(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    refresh_configured_peer_cache_for_test(&mut node);

    assert_eq!(
        node.initiate_lookup(target_identity.node_addr(), 8).await,
        1,
        "the addressless roster target lookup must leave through the explicit seed"
    );
}

#[test]
fn discovery_fallback_transit_owns_target_exception_block_and_bootstrap_policy() {
    let peer = make_node_addr(0xD1);
    let target = make_node_addr(0xD2);
    let bootstrap_transport = TransportId::new(7);
    let normal_transport = TransportId::new(8);
    let mut transit = DiscoveryFallbackTransit::default();

    assert!(
        transit.allows_lookup_fallback_peer(&peer, &target, Some(normal_transport), |_| false),
        "ordinary sendable peers should be eligible fallback transit"
    );

    transit.set_allowed(peer, false);
    assert!(
        !transit.allows_lookup_fallback_peer(&peer, &target, Some(normal_transport), |_| false),
        "explicitly blocked peers must not become ambient lookup transit"
    );
    assert!(
        transit.allows_lookup_fallback_peer(&peer, &peer, Some(normal_transport), |_| false),
        "direct lookups to the target peer must remain allowed even when ambient transit is blocked"
    );

    transit.set_allowed(peer, true);
    assert!(
        !transit.allows_lookup_fallback_peer(&peer, &target, Some(bootstrap_transport), |id| {
            id == bootstrap_transport
        }),
        "bootstrap transports should not be used as ambient fallback transit"
    );
    assert!(
        transit.allows_lookup_fallback_peer(&peer, &target, Some(normal_transport), |id| {
            id == bootstrap_transport
        }),
        "unblocked non-bootstrap peers should be eligible again"
    );
    assert!(
        transit.allows_lookup_fallback_peer(&peer, &target, None, |_| false),
        "peers without a transport id should not be treated as bootstrap"
    );
}

#[test]
fn bootstrap_transports_own_membership_peer_npub_and_cleanup() {
    let transport = TransportId::new(7);
    let other_transport = TransportId::new(8);
    let mut bootstrap = BootstrapTransports::default();

    bootstrap.register(transport, "npub-one".to_string());
    assert!(bootstrap.contains(&transport));
    assert_eq!(bootstrap.peer_npub(&transport), Some("npub-one"));
    assert_eq!(bootstrap.peer_npub(&other_transport), None);

    bootstrap.register(transport, "npub-two".to_string());
    assert!(bootstrap.contains(&transport));
    assert_eq!(
        bootstrap.peer_npub(&transport),
        Some("npub-two"),
        "re-registering a transport must update the peer npub in the same owner"
    );

    bootstrap.remove(&transport);
    assert!(!bootstrap.contains(&transport));
    assert_eq!(
        bootstrap.peer_npub(&transport),
        None,
        "removing bootstrap membership must also drop the peer npub"
    );
}
