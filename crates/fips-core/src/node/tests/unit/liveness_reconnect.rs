use super::*;

#[test]
fn repeated_rx_loop_timeouts_do_not_extend_dead_peer_grace_forever() {
    let mut node = Node::new(Config::new()).expect("node");
    node.config.node.link_dead_timeout_secs = 30;

    node.mark_rx_loop_maintenance_timeout();
    let first = node.last_rx_loop_maintenance_timeout_at;
    node.mark_rx_loop_maintenance_timeout();
    assert_eq!(node.last_rx_loop_maintenance_timeout_at, first);

    node.last_rx_loop_maintenance_timeout_at =
        Some(std::time::Instant::now() - std::time::Duration::from_secs(31));
    let expired = node.last_rx_loop_maintenance_timeout_at;
    node.mark_rx_loop_maintenance_timeout();
    assert_ne!(node.last_rx_loop_maintenance_timeout_at, expired);
}

#[tokio::test]
async fn link_dead_after_recent_rx_loop_timeout_defers_peer_removal() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .learned()
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.peers.push(peer_config);
    let session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");
    node.config.node.heartbeat_interval_secs = 2;
    node.config.node.link_dead_timeout_secs = 30;
    node.config.node.fast_link_dead_timeout_secs = 5;
    let (packet_tx, _packet_rx) = packet_channel(8);
    node.transports.insert(
        TransportId::new(1),
        TransportHandle::Udp(UdpTransport::new(
            TransportId::new(1),
            None,
            crate::config::UdpConfig::default(),
            packet_tx,
        )),
    );

    let active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        ActivePeerSession {
            session,
            our_index: crate::utils::index::SessionIndex::new(11),
            their_index: crate::utils::index::SessionIndex::new(12),
            transport_id: TransportId::new(1),
            current_addr: crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: None,
        },
    );
    node.peers.insert(peer_addr, active);
    super::super::seed_dataplane_fmp_rx_for_test(
        &mut node,
        peer_addr,
        std::time::Duration::from_secs(31),
    );
    node.mark_rx_loop_maintenance_timeout();

    node.check_link_heartbeats().await;

    assert!(
        node.peers.contains_key(&peer_addr),
        "a local rx-loop stall is inconclusive and must not flap a direct peer to fallback"
    );
    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "deferring a locally suspect link-dead timeout should not schedule a direct reconnect"
    );
}

#[tokio::test]
async fn link_dead_unconfigured_browser_peer_is_fully_evicted() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer = PeerIdentity::from_pubkey_full(peer_identity.pubkey_full());
    let peer_addr = *peer.node_addr();
    let session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let mut node = Node::with_identity(local_identity, Config::new()).expect("node");
    node.config.node.link_dead_timeout_secs = 30;
    node.peers.insert(
        peer_addr,
        ActivePeer::with_session(
            peer,
            LinkId::new(7),
            0,
            ActivePeerSession {
                session,
                our_index: crate::utils::index::SessionIndex::new(11),
                their_index: crate::utils::index::SessionIndex::new(12),
                transport_id: TransportId::new(1),
                current_addr: crate::transport::TransportAddr::from_string(
                    "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
                link_stats: crate::transport::LinkStats::new(),
                is_initiator: false,
                remote_epoch: None,
            },
        ),
    );
    super::super::seed_dataplane_fmp_rx_for_test(
        &mut node,
        peer_addr,
        std::time::Duration::from_secs(31),
    );

    node.check_link_heartbeats().await;

    assert!(
        !node.peers.contains_key(&peer_addr),
        "an unconfigured ambient peer has no reconnect state to preserve"
    );
}

#[tokio::test]
async fn failed_heartbeat_send_does_not_suppress_next_probe() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority(
            "udp",
            "203.0.113.9:2121",
            1,
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.peers.push(peer_config);
    let session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");
    node.config.node.heartbeat_interval_secs = 2;
    node.config.node.link_dead_timeout_secs = 30;

    let active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        ActivePeerSession {
            session,
            our_index: crate::utils::index::SessionIndex::new(11),
            their_index: crate::utils::index::SessionIndex::new(12),
            transport_id: TransportId::new(1),
            current_addr: crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: None,
        },
    );
    node.peers.insert(peer_addr, active);

    node.check_link_heartbeats().await;

    assert!(
        node.peers
            .get(&peer_addr)
            .expect("peer should remain active")
            .last_heartbeat_sent()
            .is_none(),
        "a failed heartbeat send must stay eligible for the next heartbeat tick"
    );
}

#[test]
fn queue_active_fallback_direct_retries_seeds_configured_relayed_peer() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).expect("node");
    let mut active = ActivePeer::new(peer, LinkId::new(7), 0);
    active.mark_stale();
    node.peers.insert(peer_addr, active);

    node.queue_active_fallback_direct_retries();

    let state = node
        .retry_pending
        .get(&peer_addr)
        .expect("active fallback peer should get direct retry state");
    assert_eq!(state.peer_config.npub, peer_config.npub);
    assert_eq!(state.retry_count, 0);
    assert!(state.reconnect);
}

#[test]
fn healthy_configured_websocket_peer_keeps_direct_upgrade_retry() {
    use crate::config::WebSocketConfig;
    use crate::transport::websocket::WebSocketTransport;

    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer = PeerIdentity::from_pubkey_full(peer_identity.pubkey_full());
    let peer_addr = *peer.node_addr();
    let peer_npub = peer.npub().to_string();
    let peer_config = crate::config::PeerConfig {
        npub: peer_npub.clone(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority(
            "websocket",
            "wss://seed.example/fips",
            200,
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: false,
    };

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config.clone());
    let mut node = Node::with_identity(local_identity, config).expect("node");
    let bootstrap_transport_id = TransportId::new(1);
    let (packet_tx, _packet_rx) = packet_channel(8);
    let bootstrap = WebSocketTransport::new(
        bootstrap_transport_id,
        None,
        WebSocketConfig::default(),
        packet_tx,
        &node.identity,
    );
    node.transports.insert(
        bootstrap_transport_id,
        TransportHandle::WebSocket(Box::new(bootstrap)),
    );
    let active = make_active_test_peer(
        &node,
        &peer_identity,
        bootstrap_transport_id,
        LinkId::new(7),
        crate::transport::TransportAddr::from_string("wss://seed.example/fips"),
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
    );
    node.peers.insert(peer_addr, active);
    let now_ms = Node::now_ms();
    seed_dataplane_fsp_data_rx_for_test(&mut node, peer_addr, peer_addr, now_ms);
    assert!(node.active_peer_has_fresh_endpoint_data_liveness(&peer_addr));

    node.queue_active_fallback_direct_retries();

    let state = node
        .retry_pending
        .get(&peer_addr)
        .expect("a WebSocket bootstrap must not suppress better direct-path retries");
    assert_eq!(state.peer_config.npub, peer_config.npub);
    assert!(state.reconnect);

    node.clear_retry_unless_direct_refresh_needed(&peer_addr);
    assert!(
        node.retry_pending.contains_key(&peer_addr),
        "fresh application traffic over WebSocket must not cancel the direct-path upgrade"
    );
}

#[test]
fn queue_active_fallback_direct_retries_skips_non_reconnect_transit_peer() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: false,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config);
    let mut node = Node::new(config).expect("node");
    node.peers
        .insert(peer_addr, ActivePeer::new(peer, LinkId::new(7), 0));

    node.queue_active_fallback_direct_retries();

    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "transit peers with auto_reconnect=false must not enter the fast active fallback retry loop"
    );
}

#[tokio::test]
async fn process_pending_retries_drops_non_reconnect_active_direct_refresh_state() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: false,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).expect("node");
    node.peers
        .insert(peer_addr, ActivePeer::new(peer, LinkId::new(7), 0));

    let mut state = super::super::retry::RetryState::new(peer_config);
    state.retry_after_ms = 0;
    state.reconnect = true;
    node.retry_pending.insert(peer_addr, state);

    node.process_pending_retries(1_000).await;

    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "stale fast retry state for a non-reconnect active transit peer should be dropped instead of refiring every tick"
    );
}

#[test]
fn stale_udp_nostr_peer_without_static_addresses_keeps_direct_retry() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).expect("node");

    let transport_id = TransportId::new(1);
    let (packet_tx, _packet_rx) = packet_channel(64);
    let udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig::default(),
        packet_tx,
    );
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let mut active = ActivePeer::new(peer, LinkId::new(7), 0);
    active.set_current_addr(
        transport_id,
        &TransportAddr::from_string("203.0.113.24:51820"),
    );
    node.peers.insert(peer_addr, active);

    assert!(
        node.active_peer_should_keep_direct_retry(&peer_addr, &peer_config),
        "a stale UDP peer with only Nostr/NAT discovery must keep probing direct before link-dead"
    );
}

#[tokio::test]
async fn stale_udp_peer_reuses_current_addr_after_traversal_transport_removed() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config);
    let mut node = Node::new(config).expect("node");

    let live_udp_transport_id = TransportId::new(1);
    let old_traversal_transport_id = TransportId::new(99);
    let (packet_tx, _packet_rx) = packet_channel(64);
    let mut udp = UdpTransport::new(
        live_udp_transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(live_udp_transport_id, TransportHandle::Udp(udp));

    let now_ms = Node::now_ms();
    let mut active = ActivePeer::new(peer, LinkId::new(7), now_ms);
    active.set_current_addr(
        old_traversal_transport_id,
        &TransportAddr::from_string("10.254.253.252:51820"),
    );
    active.mark_stale();
    node.peers.insert(peer_addr, active);

    let candidate = node
        .active_peer_current_udp_candidate(&peer_addr)
        .expect("authenticated off-subnet UDP path should remain directly re-probeable");
    assert_eq!(candidate.transport, "udp");
    assert_eq!(candidate.addr, "10.254.253.252:51820");
    assert_eq!(
        candidate.provenance,
        crate::config::PeerAddressProvenance::Authenticated
    );
    assert_eq!(
        candidate.priority,
        u8::MAX,
        "stale current endpoints must not outrank newer advertised paths"
    );
    assert_eq!(
        candidate.seen_at_ms, None,
        "stale current endpoints must not be restamped as fresh"
    );

    node.schedule_reconnect(peer_addr, now_ms);
    node.remove_active_peer(&peer_addr);
    let remembered = node
        .retry_pending
        .get(&peer_addr)
        .and_then(|state| {
            state
                .peer_config
                .addresses
                .iter()
                .find(|address| address.addr == "10.254.253.252:51820")
        })
        .expect("peer removal must not discard its authenticated UDP route");
    assert_eq!(
        remembered.provenance,
        crate::config::PeerAddressProvenance::Authenticated
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[test]
fn fresh_udp_nostr_peer_without_static_addresses_skips_direct_retry() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).expect("node");

    let transport_id = TransportId::new(1);
    let (packet_tx, _packet_rx) = packet_channel(64);
    let udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig::default(),
        packet_tx,
    );
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let now_ms = Node::now_ms();
    let mut active = ActivePeer::new(peer, LinkId::new(7), now_ms);
    active.set_current_addr(
        transport_id,
        &TransportAddr::from_string("203.0.113.24:51820"),
    );
    node.peers.insert(peer_addr, active);

    assert!(
        !node.active_peer_should_keep_direct_retry(&peer_addr, &peer_config),
        "a fresh concrete UDP peer should not churn background traversal attempts"
    );
}

#[test]
fn fresh_static_udp_peer_data_liveness_skips_retry_without_resolving_hints() {
    use crate::node::session::{EndToEndState, SessionEntry};

    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority(
            "udp",
            "192.168.50.24:51820",
            100,
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config.clone());
    let session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");

    let transport_id = TransportId::new(1);
    let (packet_tx, _packet_rx) = packet_channel(64);
    let udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig::default(),
        packet_tx,
    );
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let now_ms = Node::now_ms();
    let mut active = ActivePeer::new(peer, LinkId::new(7), now_ms);
    active.set_current_addr(
        transport_id,
        &TransportAddr::from_string("198.51.100.24:51820"),
    );
    node.peers.insert(peer_addr, active);

    let entry = SessionEntry::new(
        peer_addr,
        peer_identity.pubkey_full(),
        EndToEndState::Established(session),
        1_000,
        true,
    );
    node.sessions.insert(peer_addr, entry);
    seed_dataplane_fsp_data_rx_for_test(&mut node, peer_addr, peer_addr, now_ms);

    assert!(
        !node.active_peer_should_keep_direct_retry(&peer_addr, &peer_config),
        "fresh authenticated endpoint data should treat static UDP addresses as hints, not mandatory retry targets"
    );
}

#[test]
fn degraded_static_udp_peer_keeps_direct_retry_even_when_sendable() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority(
            "udp",
            "192.0.2.24:51820",
            100,
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).expect("node");

    let transport_id = TransportId::new(1);
    let (packet_tx, _packet_rx) = packet_channel(64);
    let udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig::default(),
        packet_tx,
    );
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let now_ms = Node::now_ms();
    let mut active = ActivePeer::new(peer, LinkId::new(7), now_ms);
    active.set_current_addr(
        transport_id,
        &TransportAddr::from_string("192.0.2.24:51820"),
    );
    node.peers.insert(peer_addr, active);
    node.mark_session_direct_path_degraded(peer_addr, now_ms);

    assert!(
        node.active_peer_should_keep_direct_retry(&peer_addr, &peer_config),
        "a degraded direct payload path must keep probing even if the stale static UDP tuple remains sendable"
    );
}

#[test]
fn reconnecting_static_udp_peer_keeps_direct_retry() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority(
            "udp",
            "203.0.113.24:51820",
            1,
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).expect("node");

    let transport_id = TransportId::new(1);
    let (packet_tx, _packet_rx) = packet_channel(64);
    let udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig::default(),
        packet_tx,
    );
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let now_ms = Node::now_ms();
    let mut active = ActivePeer::new(peer, LinkId::new(7), now_ms);
    active.set_current_addr(
        transport_id,
        &TransportAddr::from_string("203.0.113.24:51820"),
    );
    active.mark_reconnecting();
    node.peers.insert(peer_addr, active);

    assert!(
        node.active_peer_should_keep_direct_retry(&peer_addr, &peer_config),
        "a link-dead static UDP path is not fresh enough to suppress direct probing"
    );
}

#[test]
fn show_peers_reports_fallback_active_with_direct_probe_pending() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).expect("node");

    let bootstrap_transport = TransportId::new(77);
    node.bootstrap_transports.mark(bootstrap_transport);
    let mut active = ActivePeer::new(peer, LinkId::new(7), 0);
    active.set_current_addr(
        bootstrap_transport,
        &crate::transport::TransportAddr::from_string("fips"),
    );
    node.peers.insert(peer_addr, active);

    let mut retry = super::super::retry::RetryState::new(peer_config);
    retry.reconnect = true;
    retry.retry_after_ms = 42_000;
    node.retry_pending.insert(peer_addr, retry);

    let peers = crate::control::queries::show_peers(&node);
    let peer_json = peers["peers"]
        .as_array()
        .and_then(|peers| peers.first())
        .expect("one peer");
    assert_eq!(peer_json["transport_addr"], "fips");
    assert_eq!(peer_json["nostr_traversal"]["direct_probe_pending"], true);
    assert_eq!(
        peer_json["nostr_traversal"]["direct_probe_after_ms"],
        42_000
    );
}

#[tokio::test]
async fn endpoint_peer_snapshot_does_not_treat_stale_historical_rx_as_connected() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer = PeerIdentity::from_pubkey_full(peer_identity.pubkey_full());
    let peer_addr = *peer.node_addr();
    let session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let mut node = Node::with_identity(local_identity, Config::new()).expect("node");
    node.config.node.heartbeat_interval_secs = 2;

    let mut stats = crate::transport::LinkStats::new();
    stats.record_recv(128, 1);
    let active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        1,
        ActivePeerSession {
            session,
            our_index: crate::utils::index::SessionIndex::new(11),
            their_index: crate::utils::index::SessionIndex::new(12),
            transport_id: TransportId::new(1),
            current_addr: crate::transport::TransportAddr::from_string("203.0.113.24:51820"),
            link_stats: stats,
            is_initiator: true,
            remote_epoch: Some([2; 8]),
        },
    );
    node.peers.insert(peer_addr, active);

    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    node.handle_endpoint_control(crate::node::NodeEndpointControlCommand::PeerSnapshot {
        response_tx,
    })
    .await;
    let peers = response_rx.await.expect("peer snapshot response");
    let peer = peers.first().expect("one peer");
    assert!(
        !peer.connected,
        "stale historical receive counters must not keep status/GUI online"
    );
}

#[tokio::test]
async fn endpoint_peer_snapshot_treats_fresh_rx_as_connected() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer = PeerIdentity::from_pubkey_full(peer_identity.pubkey_full());
    let peer_addr = *peer.node_addr();
    let session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let mut node = Node::with_identity(local_identity, Config::new()).expect("node");
    node.config.node.heartbeat_interval_secs = 2;

    let mut stats = crate::transport::LinkStats::new();
    stats.record_recv(128, Node::now_ms());
    let active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        Node::now_ms(),
        ActivePeerSession {
            session,
            our_index: crate::utils::index::SessionIndex::new(11),
            their_index: crate::utils::index::SessionIndex::new(12),
            transport_id: TransportId::new(1),
            current_addr: crate::transport::TransportAddr::from_string("203.0.113.24:51820"),
            link_stats: stats,
            is_initiator: true,
            remote_epoch: Some([2; 8]),
        },
    );
    node.peers.insert(peer_addr, active);

    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    node.handle_endpoint_control(crate::node::NodeEndpointControlCommand::PeerSnapshot {
        response_tx,
    })
    .await;
    let peers = response_rx.await.expect("peer snapshot response");
    let peer = peers.first().expect("one peer");
    assert!(
        peer.connected,
        "fresh receive evidence should keep status/GUI online"
    );
}

#[tokio::test]
async fn process_pending_retries_allows_active_direct_refresh_at_peer_capacity() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).expect("node");
    node.set_max_peers(1);
    node.peers
        .insert(peer_addr, ActivePeer::new(peer, LinkId::new(7), 0));

    let mut state = super::super::retry::RetryState::new(peer_config);
    state.reconnect = true;
    state.retry_after_ms = 0;
    node.retry_pending.insert(peer_addr, state);

    node.process_pending_retries(1_000).await;

    let state = node
        .retry_pending
        .get(&peer_addr)
        .expect("active peer retry should remain scheduled after failed initiation");
    assert_eq!(
        state.retry_count, 0,
        "active direct refresh should stay out of peer backoff"
    );
    assert!(
        state.retry_after_ms >= 31_000,
        "no-transport active direct refresh should be cooled down, got {}",
        state.retry_after_ms
    );
}

#[test]
fn nostr_discovery_outbound_admission_atomic_roundtrip() {
    let bootstrap = NostrDiscovery::new_for_test();
    assert!(bootstrap.outbound_admission_allowed());
    bootstrap.set_outbound_admission(false);
    assert!(!bootstrap.outbound_admission_allowed());
    bootstrap.set_outbound_admission(true);
    assert!(bootstrap.outbound_admission_allowed());

    assert!(bootstrap.direct_refresh_admission_allowed());
    bootstrap.set_direct_refresh_admission(false);
    assert!(!bootstrap.direct_refresh_admission_allowed());
    bootstrap.set_direct_refresh_admission(true);
    assert!(bootstrap.direct_refresh_admission_allowed());
}

include!("liveness_reconnect_nostr.rs");
