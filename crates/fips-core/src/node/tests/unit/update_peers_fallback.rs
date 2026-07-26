use super::*;

#[cfg(feature = "webrtc-transport")]
#[tokio::test]
async fn healthy_websocket_upgrade_skips_bootstrap_redial_and_unadvertised_udp_nat() {
    use crate::config::{
        NostrDiscoveryConfig, NostrDiscoveryPolicy, TransportInstances, WebRtcConfig,
        WebSocketConfig,
    };
    use crate::discovery::nostr::{OverlayEndpointAdvert, OverlayTransportKind};
    use crate::transport::webrtc::WebRtcTransport;
    use crate::transport::websocket::WebSocketTransport;

    let local_identity = Identity::generate();
    let mut peer_secret = [0u8; 32];
    peer_secret[31] = 6;
    let peer_full = Identity::from_secret_bytes(&peer_secret).expect("fixed odd-parity peer");
    assert_eq!(peer_full.pubkey_full().serialize()[0], 0x03);
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let peer_npub = peer_full.npub();
    let peer_config = crate::config::PeerConfig {
        npub: peer_npub.clone(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: false,
    };

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
    let webrtc_config = WebRtcConfig {
        auto_connect: Some(true),
        connect_timeout_ms: Some(5_000),
        ice_gather_timeout_ms: Some(2_000),
        stun_servers: Some(Vec::new()),
        resolve_mdns_candidates: Some(false),
        ..Default::default()
    };
    config.transports.websocket = TransportInstances::Single(WebSocketConfig::default());
    config.transports.webrtc = TransportInstances::Single(webrtc_config.clone());
    config.peers = vec![peer_config.clone()];
    let mut node = Node::with_identity(local_identity, config).expect("node");
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let bootstrap_transport_id = TransportId::new(1);
    let mut websocket = WebSocketTransport::new(
        bootstrap_transport_id,
        None,
        WebSocketConfig::default(),
        packet_tx.clone(),
        node.identity(),
    );
    websocket
        .start_async()
        .await
        .expect("start WebSocket transport");
    node.transports.insert(
        bootstrap_transport_id,
        TransportHandle::WebSocket(Box::new(websocket)),
    );
    let webrtc_transport_id = TransportId::new(2);
    let mut webrtc = WebRtcTransport::new(
        webrtc_transport_id,
        None,
        webrtc_config,
        packet_tx,
        node.identity(),
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    webrtc
        .use_canonical_loopback_candidate_profile()
        .expect("real UDP4 loopback candidate profile");
    webrtc.start_async().await.expect("start WebRTC transport");
    node.transports.insert(
        webrtc_transport_id,
        TransportHandle::WebRtc(Box::new(webrtc)),
    );

    let active_addr = TransportAddr::from_string("wss://seed.example/fips");
    let active = make_active_test_peer(
        &node,
        &peer_full,
        bootstrap_transport_id,
        LinkId::new(7),
        active_addr,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
    );
    node.peers.insert(peer_node_addr, active);
    seed_dataplane_fsp_data_rx_for_test(&mut node, peer_node_addr, peer_node_addr, Node::now_ms());

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let advertised_webrtc_addr =
        TransportAddr::from_string(&hex::encode(peer_full.pubkey_full().serialize()));
    let canonical_webrtc_addr = TransportAddr::from_string(&hex::encode(
        peer_full
            .pubkey()
            .public_key(secp256k1::Parity::Even)
            .serialize(),
    ));
    assert_ne!(advertised_webrtc_addr, canonical_webrtc_addr);
    let mut advert = NostrDiscovery::cached_advert_for_test(
        peer_npub.clone(),
        OverlayEndpointAdvert {
            transport: OverlayTransportKind::WebRtc,
            addr: advertised_webrtc_addr.to_string(),
        },
        1_700_000_000,
    );
    advert.advert.endpoints.push(OverlayEndpointAdvert {
        transport: OverlayTransportKind::WebSocket,
        addr: "wss://seed.example/fips".into(),
    });
    bootstrap
        .insert_advert_for_test(peer_npub.clone(), advert)
        .await;
    node.nostr_discovery = Some(bootstrap.clone());

    let mut retry = super::super::retry::RetryState::new(peer_config);
    retry.retry_after_ms = 0;
    retry.reconnect = true;
    node.retry_pending.insert(peer_node_addr, retry);
    node.process_pending_retries(Node::now_ms()).await;

    assert!(
        node.pending_connects.iter().any(|pending| {
            pending.transport_id == webrtc_transport_id
                && pending.remote_addr == canonical_webrtc_addr
        }),
        "an odd advertised WebRTC identity must be canonical before Node stores its pending path"
    );
    assert!(
        node.pending_connects
            .iter()
            .all(|pending| pending.remote_addr != advertised_webrtc_addr),
        "Node must not retain a parity-split alias for the advertised WebRTC identity"
    );

    assert!(
        node.pending_connects
            .iter()
            .all(|pending| pending.transport_id != bootstrap_transport_id),
        "a healthy WebSocket path must not redial itself during a direct-upgrade pass"
    );

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            node.poll_nostr_discovery().await;
            if bootstrap.active_initiator_count_for_test().await == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("unwanted traversal task should settle");
    node.poll_nostr_discovery().await;
    assert!(
        bootstrap.failure_state_snapshot().is_empty(),
        "a WebRTC+WebSocket advert without udp:nat must not record a NAT traversal failure"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn degraded_active_peer_refresh_starts_traversal_without_udp_nat_pseudocandidate() {
    use crate::config::NostrDiscoveryPolicy;

    let peer_full = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: Vec::new(),
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
    node.nostr_discovery = Some(bootstrap.clone());

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
    udp.start_async().await.expect("start UDP transport");
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let active = make_active_test_peer(
        &node,
        &peer_full,
        transport_id,
        LinkId::new(7),
        TransportAddr::from_string("127.0.0.1:9"),
        SessionIndex::new(11),
        SessionIndex::new(12),
    );
    node.peers.insert(peer_node_addr, active);
    assert!(node.sync_dataplane_fmp_owner(&peer_node_addr));
    node.mark_session_direct_path_degraded(peer_node_addr, Node::now_ms());

    assert!(
        node.initiate_active_peer_direct_refresh_connection(&peer_config)
            .await
            .expect("refresh degraded active peer"),
        "network-change refresh should start at least one recovery path"
    );
    assert_eq!(
        bootstrap.active_initiator_count_for_test().await,
        1,
        "a configured npub and authenticated mesh route should start NAT traversal without a synthetic udp:nat address"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn configured_direct_refresh_waits_for_mesh_route_then_ignores_traversal_cooldown() {
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
        !node.request_nostr_bootstrap(&peer_config).await,
        "configuration authorizes mesh signaling but must not start traversal before a route can carry it"
    );
    assert_eq!(
        bootstrap.active_initiator_count_for_test().await,
        0,
        "an unsendable offer must not spawn a traversal task that will time out and poison cooldown"
    );

    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();
    node.peers.insert(
        peer_addr,
        ActivePeer::new(peer, LinkId::new(7), Node::now_ms()),
    );

    assert!(
        node.request_nostr_bootstrap(&peer_config).await,
        "an authenticated mesh route should immediately carry direct negotiation"
    );
    assert_eq!(
        bootstrap.active_initiator_count_for_test().await,
        1,
        "cooldown must not suppress direct refresh once the mesh route is ready"
    );

    let mut mobile_peer = peer_config;
    mobile_peer.auto_reconnect = false;
    assert!(
        !node.request_nostr_bootstrap(&mobile_peer).await,
        "bounded mobile peers should stay quiet during traversal cooldown"
    );
}

#[tokio::test]
async fn unconfigured_nat_advert_without_fips_path_does_not_start_signaling() {
    use crate::config::NostrDiscoveryPolicy;

    let peer = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: false,
    };
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::Open;
    let mut node = Node::new(config).expect("node");
    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    node.nostr_discovery = Some(bootstrap.clone());

    assert!(
        !node.request_nostr_bootstrap(&peer_config).await,
        "Nostr announcements alone cannot carry WebRTC signaling"
    );
    assert_eq!(
        bootstrap.active_initiator_count_for_test().await,
        0,
        "no background traversal task should be spawned without an authenticated FIPS path"
    );
}

#[tokio::test]
async fn mesh_signal_warms_session_over_existing_multihop_route() {
    use super::spanning_tree::{run_tree_test, verify_tree_convergence};
    use crate::discovery::nostr::{MeshTraversalSignal, TraversalOffer};

    let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let peer_node_addr = *nodes[2].node.node_addr();
    let peer_npub = nodes[2].node.identity().npub();
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
