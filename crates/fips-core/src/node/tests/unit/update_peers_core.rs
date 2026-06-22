use super::*;

#[tokio::test]
async fn update_peers_preserves_input_priority_order() {
    let mut node = make_node();
    let first = Identity::generate();
    let second = Identity::generate();
    let third = Identity::generate();

    let first_original = auto_connect_peer(first.npub(), "127.0.0.1:9");
    let second_peer = auto_connect_peer(second.npub(), "127.0.0.1:10");
    let third_peer = auto_connect_peer(third.npub(), "127.0.0.1:11");
    let first_updated = auto_connect_peer(first.npub(), "127.0.0.1:12");

    let outcome = node
        .update_peers(vec![
            first_original,
            second_peer.clone(),
            third_peer.clone(),
            first_updated.clone(),
        ])
        .await
        .unwrap();

    assert_eq!(outcome.added, 3);
    assert_eq!(
        node.config
            .peers
            .iter()
            .map(|peer| peer.npub.as_str())
            .collect::<Vec<_>>(),
        vec![
            first_updated.npub.as_str(),
            second_peer.npub.as_str(),
            third_peer.npub.as_str(),
        ],
        "caller priority order should survive de-duplication"
    );
    assert_eq!(node.config.peers[0].addresses, first_updated.addresses);
}

#[tokio::test]
async fn update_peers_races_alternate_path_even_when_outbound_would_lose() {
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

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_loser(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let old_addr = TransportAddr::from_string("127.0.0.1:7");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &old_addr);
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            old_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );

    let peer = auto_connect_peer(peer_full.npub(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.unchanged, 1);
    assert_eq!(node.peer_count(), 1, "current active peer must remain live");
    assert_eq!(
        node.connection_count(),
        1,
        "alternate path should be attempted even when our outbound would lose cross-connection"
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&old_addr));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_returns_zero_on_empty_diff() {
    let mut node = make_node();

    let outcome = node.update_peers(Vec::new()).await.unwrap();
    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 0);
    assert_eq!(outcome.unchanged, 0);
}

#[tokio::test]
async fn update_peers_adds_new_peer_and_registers_alias() {
    let mut node = make_node();
    let npub = npub_for_test();
    let mut peer = auto_connect_peer(npub.clone(), "127.0.0.1:9");
    peer.alias = Some("alice".to_string());

    let outcome = node.update_peers(vec![peer.clone()]).await.unwrap();

    assert_eq!(outcome.added, 1);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 0);
    assert_eq!(outcome.unchanged, 0);
    assert_eq!(node.config.peers.len(), 1);
    let identity = PeerIdentity::from_npub(&peer.npub).unwrap();
    assert_eq!(
        node.peer_aliases.get(identity.node_addr()),
        Some(&"alice".to_string())
    );
    assert_eq!(
        node.configured_peer(identity.node_addr())
            .and_then(|cached| cached.alias.as_deref()),
        Some("alice"),
        "runtime configured-peer cache must refresh with update_peers"
    );
}

#[tokio::test]
async fn update_peers_refreshes_configured_peer_binary_index() {
    let mut node = make_node();
    let first = Identity::generate();
    let second = Identity::generate();
    let first_peer = auto_connect_peer(first.npub(), "127.0.0.1:9");
    let second_peer = auto_connect_peer(second.npub(), "127.0.0.1:10");
    let first_identity = PeerIdentity::from_pubkey_full(first.pubkey_full());
    let second_identity = PeerIdentity::from_pubkey_full(second.pubkey_full());
    let first_addr = *first_identity.node_addr();
    let second_addr = *second_identity.node_addr();

    let _ = node.update_peers(vec![first_peer.clone()]).await.unwrap();
    let outcome = node.update_peers(vec![second_peer.clone()]).await.unwrap();

    assert_eq!(outcome.added, 1);
    assert_eq!(outcome.removed, 1);
    assert!(
        node.configured_peer(&first_addr).is_none(),
        "removed peer must leave the binary configured-peer index"
    );
    assert_eq!(
        node.configured_peer(&second_addr)
            .map(|peer| peer.npub.as_str()),
        Some(second_peer.npub.as_str()),
        "configured peer lookup should use the refreshed NodeAddr index"
    );
    assert_eq!(
        node.configured_peer_identity(&second_addr)
            .map(|identity| identity.node_addr()),
        Some(&second_addr),
        "configured identity should be cached beside the peer config"
    );
    assert_eq!(
        node.configured_peer_send_weights
            .identity_for_npub(&second_peer.npub)
            .map(|identity| identity.node_addr()),
        Some(&second_addr),
        "npub lookup should resolve through the refreshed side index"
    );
    assert!(
        node.configured_peer_send_weights
            .identity_for_npub(&first_peer.npub)
            .is_none(),
        "removed npub must leave the configured-peer side index"
    );
}

#[tokio::test]
async fn update_peers_removes_dropped_peer_and_clears_retry_state() {
    let mut node = make_node();
    let npub = npub_for_test();
    let peer = auto_connect_peer(npub.clone(), "127.0.0.1:9");

    let _ = node.update_peers(vec![peer.clone()]).await.unwrap();

    let identity = PeerIdentity::from_npub(&peer.npub).unwrap();
    let node_addr = *identity.node_addr();
    // Cold-add scheduled a retry because there's no transport.
    assert!(node.retry_pending.contains_key(&node_addr));

    let outcome = node.update_peers(Vec::new()).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 1);
    assert!(node.config.peers.is_empty());
    assert!(!node.retry_pending.contains_key(&node_addr));
    assert!(!node.peer_aliases.contains_key(&node_addr));
}

#[tokio::test]
async fn update_peers_reports_updated_when_addresses_change() {
    let mut node = make_node();
    let npub = npub_for_test();
    let original = auto_connect_peer(npub.clone(), "127.0.0.1:9");
    let _ = node.update_peers(vec![original]).await.unwrap();

    let new_version = auto_connect_peer(npub.clone(), "127.0.0.1:55180");
    let outcome = node.update_peers(vec![new_version.clone()]).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 1);
    assert_eq!(outcome.unchanged, 0);
    assert_eq!(node.config.peers.len(), 1);
    assert_eq!(node.config.peers[0].addresses[0].addr, "127.0.0.1:55180");
}

#[tokio::test]
async fn update_peers_reports_unchanged_for_identical_entry() {
    let mut node = make_node();
    let npub = npub_for_test();
    let peer = auto_connect_peer(npub, "127.0.0.1:9");
    let _ = node.update_peers(vec![peer.clone()]).await.unwrap();

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 0);
    assert_eq!(outcome.unchanged, 1);
}

#[tokio::test]
async fn update_peers_refreshes_stale_retry_config_even_when_peer_is_unchanged() {
    let mut node = make_node();
    let npub = npub_for_test();
    let peer = auto_connect_peer(npub, "127.0.0.1:9");
    let identity = PeerIdentity::from_npub(&peer.npub).unwrap();
    let node_addr = *identity.node_addr();
    node.config.peers = vec![peer.clone()];

    let mut stale_retry = super::super::retry::RetryState::new(auto_connect_peer(
        peer.npub.clone(),
        "203.0.113.99:51820",
    ));
    stale_retry.retry_after_ms = 123_456;
    stale_retry.reconnect = true;
    node.retry_pending.insert(node_addr, stale_retry);

    let outcome = node.update_peers(vec![peer.clone()]).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.updated, 0);
    assert_eq!(outcome.unchanged, 1);
    let retry = node.retry_pending.get(&node_addr).unwrap();
    assert_eq!(retry.peer_config.addresses, peer.addresses);
}

#[tokio::test]
async fn update_peers_redials_existing_auto_peer_with_direct_hint() {
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

    let npub = npub_for_test();
    let original = crate::config::PeerConfig {
        npub: npub.clone(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers = vec![original];

    let refreshed = auto_connect_peer(npub, "127.0.0.1:9");
    let outcome = node.update_peers(vec![refreshed]).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 1);
    assert_eq!(node.connection_count(), 1);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_redials_unchanged_auto_peer_without_link() {
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

    let peer = auto_connect_peer(npub_for_test(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 0);
    assert_eq!(outcome.unchanged, 1);
    assert_eq!(node.connection_count(), 1);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_races_alternate_path_for_active_peer_without_dropping_current_link() {
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
    let old_addr = TransportAddr::from_string("127.0.0.1:7");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &old_addr);
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            old_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );

    let peer = auto_connect_peer(peer_full.npub(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.unchanged, 1);
    assert_eq!(node.peer_count(), 1, "current active peer must remain live");
    assert_eq!(
        node.connection_count(),
        1,
        "alternate path should be a pending handshake, not a peer replacement"
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&old_addr));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_does_not_churn_active_peer_already_on_known_candidate() {
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
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);

    let peer = auto_connect_peer(peer_full.npub(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.unchanged, 1);
    assert_eq!(node.peer_count(), 1);
    assert_eq!(
        node.connection_count(),
        0,
        "known-good active concrete path should not be redialed every refresh"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

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
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);

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

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[test]
fn active_peer_same_path_discovery_skips_fresh_peer() {
    let mut node = make_node();
    let (_peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), Node::now_ms());
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);
    let candidate = crate::config::PeerAddress::new("udp", "127.0.0.1:9");

    assert!(node.active_peer_candidate_is_fresh_enough_to_skip(
        &peer_node_addr,
        std::slice::from_ref(&candidate),
    ));
}

#[test]
fn active_peer_same_path_discovery_refreshes_stale_peer() {
    let mut node = make_node();
    let (_peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let stale_at = Node::now_ms().saturating_sub(
        node.config
            .node
            .heartbeat_interval_secs
            .saturating_add(1)
            .saturating_mul(1000),
    );
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), stale_at);
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);
    let candidate = crate::config::PeerAddress::new("udp", "127.0.0.1:9");

    assert!(!node.active_peer_candidate_is_fresh_enough_to_skip(
        &peer_node_addr,
        std::slice::from_ref(&candidate),
    ));
}

#[tokio::test]
async fn update_peers_races_new_alternative_even_when_current_path_is_still_known() {
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
    let new_addr = TransportAddr::from_string("127.0.0.1:10");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            current_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );

    let peer = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::new("udp", "127.0.0.1:9"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:10"),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers = vec![peer.clone()];

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.unchanged, 1);
    assert_eq!(node.peer_count(), 1, "existing link must stay live");
    assert_eq!(node.connection_count(), 1);
    assert_eq!(
        node.peers
            .connection_values()
            .next()
            .and_then(|conn| conn.source_addr()),
        Some(&new_addr)
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&current_addr));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_races_more_alternatives_while_peer_is_connecting_with_budget() {
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
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            current_addr,
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );

    let first = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::new("udp", "127.0.0.1:9"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:10"),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers = vec![first.clone()];
    let _ = node.update_peers(vec![first]).await.unwrap();
    assert_eq!(node.connection_count(), 1);

    let refreshed = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::new("udp", "127.0.0.1:9"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:10"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:11"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:12"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:13"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:14"),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };

    let outcome = node.update_peers(vec![refreshed]).await.unwrap();

    assert_eq!(outcome.updated, 1);
    assert_eq!(
        node.connection_count(),
        4,
        "one existing in-flight path plus three new paths should hit the per-peer race budget"
    );
    let attempted: std::collections::HashSet<_> = node
        .peers
        .connection_values()
        .filter_map(|conn| conn.source_addr().map(ToString::to_string))
        .collect();
    for addr in [
        "127.0.0.1:10",
        "127.0.0.1:11",
        "127.0.0.1:12",
        "127.0.0.1:13",
    ] {
        assert!(attempted.contains(addr), "missing attempted path {addr}");
    }
    assert!(
        !attempted.contains("127.0.0.1:14"),
        "candidate racing should be bounded per peer"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}
