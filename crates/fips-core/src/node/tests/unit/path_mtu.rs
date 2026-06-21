use super::*;

#[tokio::test]
async fn test_transport_mtu_returns_min_across_operational() {
    // Multiple operational transports with varied MTUs. The picker must
    // return the smallest, deterministically, regardless of HashMap
    // iteration order. This is the core ISSUE-2026-0011 regression test.
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp1 = make_udp_transport_with_mtu(1, 1497).await;
    let udp2 = make_udp_transport_with_mtu(2, 1280).await;
    let udp3 = make_udp_transport_with_mtu(3, 1400).await;

    node.transports.insert(TransportId::new(1), udp1);
    node.transports.insert(TransportId::new(2), udp2);
    node.transports.insert(TransportId::new(3), udp3);

    // Expect the smallest (UDP-1280), not whichever HashMap iterates first.
    assert_eq!(node.transport_mtu(), 1280);

    // effective_ipv6_mtu = 1280 - 77 = 1203, max_mss = 1203 - 60 = 1143
    // (verifies the downstream clamp value).
    assert_eq!(node.effective_ipv6_mtu(), 1203);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_transport_mtu_fallback_when_no_operational_transports() {
    // No transports configured at all → falls back to 1280 (IPv6 minimum).
    let node = make_node();
    assert_eq!(node.transport_mtu(), 1280);
}

#[tokio::test]
async fn test_transport_mtu_min_with_single_operational() {
    // Single transport: trivially returns its MTU. Pins the picker doesn't
    // accidentally drop down to a smaller fallback when one transport is
    // operational.
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1452).await;
    node.transports.insert(TransportId::new(1), udp);

    assert_eq!(node.transport_mtu(), 1452);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

// path_mtu_lookup seeding for direct-link (configured) peers — closes the
// B3 coverage gap where configured/auto-connect peers never go through the
// discovery Lookup flow and so their FipsAddress was missing from
// path_mtu_lookup, causing the SYN-time TCP MSS clamp to fall back to the
// global ceiling.

#[tokio::test]
async fn test_seed_path_mtu_inserts_when_empty() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1452).await;
    node.transports.insert(TransportId::new(1), udp);

    let peer_addr = make_node_addr(0xAA);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.2:2121");

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);

    let stored = node
        .path_mtu_lookup
        .read()
        .unwrap()
        .get(&fips_addr)
        .copied();
    assert_eq!(
        stored,
        Some(1452),
        "Empty lookup should be seeded with the link MTU"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_seed_path_mtu_keeps_tighter_existing_value() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1452).await;
    node.transports.insert(TransportId::new(1), udp);

    let peer_addr = make_node_addr(0xBB);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.3:2121");

    // Pre-populate with a tighter value, e.g. learned from discovery's
    // reverse-path bottleneck.
    node.path_mtu_lookup
        .write()
        .unwrap()
        .insert(fips_addr, 1280);

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);

    let stored = node
        .path_mtu_lookup
        .read()
        .unwrap()
        .get(&fips_addr)
        .copied();
    assert_eq!(
        stored,
        Some(1280),
        "Existing tighter value (1280) must not be loosened by direct-link seed (1452)"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_seed_path_mtu_tightens_looser_existing_value() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1280).await;
    node.transports.insert(TransportId::new(1), udp);

    let peer_addr = make_node_addr(0xCC);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.4:2121");

    // Pre-populate with a looser stale value.
    node.path_mtu_lookup
        .write()
        .unwrap()
        .insert(fips_addr, 1452);

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);

    let stored = node
        .path_mtu_lookup
        .read()
        .unwrap()
        .get(&fips_addr)
        .copied();
    assert_eq!(
        stored,
        Some(1280),
        "Direct-link seed (1280) must overwrite looser existing value (1452)"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

/// On retry, ordinary configured direct addresses are hints: fresh overlay
/// fallbacks can sort ahead and still race inside the per-peer candidate
/// budget. A stale static LAN/nvpn hint must not pin the peer to a path that
/// cannot reply.
#[tokio::test]
async fn test_retry_races_overlay_advert_alongside_static_udp_hint() {
    use crate::config::NostrDiscoveryPolicy;
    use crate::discovery::nostr::{NostrDiscovery, OverlayEndpointAdvert, OverlayTransportKind};

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
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

    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();

    let static_sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind static sink");
    let stale_static_addr = static_sink
        .local_addr()
        .expect("static sink local addr")
        .to_string();
    let overlay_sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind overlay sink");
    let fresh_overlay_addr = overlay_sink
        .local_addr()
        .expect("overlay sink addr")
        .to_string();

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let endpoint = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: fresh_overlay_addr.to_string(),
    };
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let advert = NostrDiscovery::cached_advert_for_test(peer_npub.clone(), endpoint, now_secs);
    bootstrap
        .insert_advert_for_test(peer_npub.clone(), advert)
        .await;
    node.nostr_discovery = Some(bootstrap);

    let peer_config = crate::config::PeerConfig {
        npub: peer_npub.clone(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::new(
            "udp",
            stale_static_addr.clone(),
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers.push(peer_config.clone());
    refresh_configured_peer_cache_for_test(&mut node);

    let candidates = node.peer_address_candidates(&peer_config).await;
    assert_eq!(
        candidates.first().map(|addr| addr.addr.as_str()),
        Some(fresh_overlay_addr.as_str()),
        "fresh overlay candidate should sort ahead of the ordinary static hint"
    );

    node.initiate_peer_retry_connection(&peer_config)
        .await
        .unwrap();

    let fresh = TransportAddr::from_string(&fresh_overlay_addr);
    let stale = TransportAddr::from_string(&stale_static_addr);
    let fresh_link = node.find_link_by_addr(transport_id, &fresh);
    let stale_link = node.find_link_by_addr(transport_id, &stale);
    assert!(
        fresh_link.is_some(),
        "retry should race fresh overlay advert {fresh_overlay_addr} alongside the static candidate"
    );
    assert!(
        stale_link.is_some(),
        "retry should keep stale static {stale_static_addr} in the bounded path race"
    );
    assert_eq!(node.connection_count(), 2);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

/// Cold-start dial keeps explicitly configured direct hints first, but does
/// not let them suppress a fresh overlay advert. This avoids getting stuck on
/// stale private hints after a network move.
#[tokio::test]
async fn test_bootstrap_races_static_address_and_overlay_advert() {
    use crate::config::NostrDiscoveryPolicy;
    use crate::discovery::nostr::{NostrDiscovery, OverlayEndpointAdvert, OverlayTransportKind};

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
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

    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();

    let static_sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind static sink");
    let static_addr = static_sink
        .local_addr()
        .expect("static sink local addr")
        .to_string();
    let overlay_sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind overlay sink");
    let overlay_addr = overlay_sink
        .local_addr()
        .expect("overlay sink addr")
        .to_string();

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let endpoint = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: overlay_addr.clone(),
    };
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let advert = NostrDiscovery::cached_advert_for_test(peer_npub.clone(), endpoint, now_secs);
    bootstrap
        .insert_advert_for_test(peer_npub.clone(), advert)
        .await;
    node.nostr_discovery = Some(bootstrap);

    let peer_config = crate::config::PeerConfig {
        npub: peer_npub.clone(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::new("udp", static_addr.clone())],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers.push(peer_config.clone());
    refresh_configured_peer_cache_for_test(&mut node);

    node.initiate_peer_connection(&peer_config).await.unwrap();

    let stat = TransportAddr::from_string(&static_addr);
    let overlay = TransportAddr::from_string(&overlay_addr);
    let overlay_link = node.find_link_by_addr(transport_id, &overlay);
    let static_link = node.find_link_by_addr(transport_id, &stat);
    assert!(
        overlay_link.is_some(),
        "cold-start should race fresh overlay fallback alongside a static candidate"
    );
    assert!(
        static_link.is_some(),
        "cold-start should keep the unstamped static address in the bounded path race"
    );
    assert_eq!(node.connection_count(), 2);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_fresh_overlay_preempts_default_static_hint_when_budget_tight() {
    use crate::config::NostrDiscoveryPolicy;
    use crate::discovery::nostr::{NostrDiscovery, OverlayEndpointAdvert, OverlayTransportKind};

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
    config.node.limits.max_connections = 1;
    config.node.limits.max_links = 1;
    let mut node = Node::new(config).unwrap();
    node.set_max_connections(1);
    node.set_max_links(1);

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

    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();

    let static_sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind static sink");
    let stale_static_addr = static_sink
        .local_addr()
        .expect("static sink local addr")
        .to_string();
    let overlay_sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind overlay sink");
    let fresh_overlay_addr = overlay_sink
        .local_addr()
        .expect("overlay sink local addr")
        .to_string();

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let endpoint = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: fresh_overlay_addr.clone(),
    };
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let advert = NostrDiscovery::cached_advert_for_test(peer_npub.clone(), endpoint, now_secs);
    bootstrap
        .insert_advert_for_test(peer_npub.clone(), advert)
        .await;
    node.nostr_discovery = Some(bootstrap);

    let peer_config = crate::config::PeerConfig {
        npub: peer_npub.clone(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::new(
            "udp",
            stale_static_addr.clone(),
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers.push(peer_config.clone());
    refresh_configured_peer_cache_for_test(&mut node);

    node.initiate_peer_retry_connection(&peer_config)
        .await
        .unwrap();

    let overlay_link = node.find_link_by_addr(
        transport_id,
        &TransportAddr::from_string(&fresh_overlay_addr),
    );
    let static_link = node.find_link_by_addr(
        transport_id,
        &TransportAddr::from_string(&stale_static_addr),
    );
    assert!(
        overlay_link.is_some(),
        "fresh overlay hint should get the first candidate slot over an ordinary static hint; static_link={static_link:?}, connection_count={}",
        node.connection_count()
    );
    assert!(
        static_link.is_none(),
        "ordinary static IP hints should not crowd out a fresh overlay candidate"
    );
    assert_eq!(node.connection_count(), 1);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_retry_races_fresh_overlay_udp_candidates_without_static_direct() {
    use crate::config::NostrDiscoveryPolicy;
    use crate::discovery::nostr::{NostrDiscovery, OverlayEndpointAdvert, OverlayTransportKind};

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
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

    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();

    let first_sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind first sink");
    let second_sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind second sink");
    let first_addr = first_sink
        .local_addr()
        .expect("first sink addr")
        .to_string();
    let second_addr = second_sink
        .local_addr()
        .expect("second sink addr")
        .to_string();

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let first_endpoint = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: first_addr.clone(),
    };
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut advert =
        NostrDiscovery::cached_advert_for_test(peer_npub.clone(), first_endpoint, now_secs);
    advert.advert.endpoints.push(OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: second_addr.clone(),
    });
    bootstrap
        .insert_advert_for_test(peer_npub.clone(), advert)
        .await;
    node.nostr_discovery = Some(bootstrap);

    let peer_config = crate::config::PeerConfig {
        npub: peer_npub.clone(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers.push(peer_config.clone());
    refresh_configured_peer_cache_for_test(&mut node);

    node.initiate_peer_retry_connection(&peer_config)
        .await
        .unwrap();

    assert!(
        node.find_link_by_addr(transport_id, &TransportAddr::from_string(&first_addr))
            .is_some(),
        "first overlay UDP candidate should be raced"
    );
    assert!(
        node.find_link_by_addr(transport_id, &TransportAddr::from_string(&second_addr))
            .is_some(),
        "a fresh overlay attempt must not suppress a later direct UDP candidate"
    );
    assert_eq!(node.connection_count(), 2);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_seed_path_mtu_noop_for_unknown_transport() {
    let node = make_node();
    let peer_addr = make_node_addr(0xDD);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.5:2121");

    // No transport registered — call must be a no-op, not panic.
    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(99), &transport_addr);

    let map = node.path_mtu_lookup.read().unwrap();
    assert!(
        map.get(&fips_addr).is_none(),
        "Seed must be a no-op when transport_id is not registered"
    );
}

// === update_peers ============================================================
