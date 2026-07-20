use super::*;
use crate::config::WebSocketConfig;
use crate::transport::websocket::WebSocketTransport;
use crate::transport::{TransportAddr, TransportHandle, TransportId, packet_channel};
use spanning_tree::{TestNode, cleanup_nodes, process_available_packets, run_synthetic_node_work};
use std::time::Duration;

async fn make_websocket_node(config: WebSocketConfig) -> TestNode {
    let mut node = make_node();
    node.config.node.rate_limit.handshake_resend_interval_ms = 50;
    node.config.node.rate_limit.handshake_max_resends = 20;
    let transport_id = TransportId::new(1);
    let (packet_tx, packet_rx) = packet_channel(256);
    let (tun_outbound_tx, tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(256);
    node.tun_outbound_rx = Some(tun_outbound_rx);
    let mut transport =
        WebSocketTransport::new(transport_id, None, config, packet_tx, node.identity());
    transport.start_async().await.unwrap();
    let addr = transport
        .local_addr()
        .map(|addr| TransportAddr::from_string(&format!("ws://{addr}/fips")))
        .unwrap_or_else(|| TransportAddr::from_string("websocket-client"));
    node.transports.insert(
        transport_id,
        TransportHandle::WebSocket(Box::new(transport)),
    );
    TestNode {
        node,
        transport_id,
        packet_rx,
        tun_outbound_tx,
        addr,
    }
}

#[tokio::test]
async fn url_only_seed_hint_completes_noise_ik_and_datagram_exchange() {
    let server = make_websocket_node(WebSocketConfig {
        bind_addr: Some("127.0.0.1:0".into()),
        ..Default::default()
    })
    .await;
    let seed_url = server.addr.to_string();
    let client = make_websocket_node(WebSocketConfig {
        seed_urls: vec![seed_url],
        reconnect_initial_ms: Some(10),
        reconnect_max_ms: Some(50),
        ..Default::default()
    })
    .await;
    let mut nodes = vec![server, client];
    for node in &mut nodes {
        node.node.config.node.discovery.nostr.enabled = true;
        node.node.config.node.discovery.nostr.policy =
            crate::config::NostrDiscoveryPolicy::ConfiguredOnly;
    }
    let server_addr = *nodes[0].node.node_addr();
    let client_addr = *nodes[1].node.node_addr();

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            for node in &mut nodes {
                node.node.poll_transport_discovery().await;
                node.node.poll_pending_connects().await;
            }
            run_synthetic_node_work(&mut nodes).await;
            process_available_packets(&mut nodes).await;
            if nodes[0].node.get_peer(&client_addr).is_some()
                && nodes[1].node.get_peer(&server_addr).is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("an operator-configured WebSocket adjacency must authenticate under configured-only discovery");

    assert_eq!(
        nodes[1]
            .node
            .get_peer(&server_addr)
            .and_then(|peer| peer.transport_id()),
        Some(nodes[1].transport_id)
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn open_discovery_listener_routes_first_contact_between_websocket_clients() {
    let seed = make_websocket_node(WebSocketConfig {
        bind_addr: Some("127.0.0.1:0".into()),
        ..Default::default()
    })
    .await;
    let seed_url = seed.addr.to_string();

    let router = make_websocket_node(WebSocketConfig {
        bind_addr: Some("127.0.0.1:0".into()),
        seed_urls: vec![seed_url.clone()],
        reconnect_initial_ms: Some(10),
        reconnect_max_ms: Some(50),
        ..Default::default()
    })
    .await;
    let router_url = router.addr.to_string();

    let guest = make_websocket_node(WebSocketConfig {
        seed_urls: vec![router_url],
        reconnect_initial_ms: Some(10),
        reconnect_max_ms: Some(50),
        ..Default::default()
    })
    .await;
    let admin = make_websocket_node(WebSocketConfig {
        seed_urls: vec![seed_url],
        reconnect_initial_ms: Some(10),
        reconnect_max_ms: Some(50),
        ..Default::default()
    })
    .await;

    let mut nodes = vec![seed, router, guest, admin];
    for node in &mut nodes {
        node.node.config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
        node.node.config.node.discovery.nostr.enabled = true;
        node.node.config.node.discovery.nostr.policy = crate::config::NostrDiscoveryPolicy::Open;
    }

    let seed_addr = *nodes[0].node.node_addr();
    let router_addr = *nodes[1].node.node_addr();
    let guest_addr = *nodes[2].node.node_addr();
    let admin_addr = *nodes[3].node.node_addr();
    let guest_npub = nodes[2].node.identity.npub();
    let guest_pubkey = nodes[2].node.identity.pubkey_full();
    nodes[3].node.config.peers.push(crate::config::PeerConfig {
        npub: guest_npub,
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    nodes[3].node.configured_peers = ConfiguredPeerLookup::from_config(&nodes[3].node.config);
    nodes[3].node.register_identity(guest_addr, guest_pubkey);

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            for node in &mut nodes {
                node.node.poll_transport_discovery().await;
                node.node.poll_pending_connects().await;
            }
            run_synthetic_node_work(&mut nodes).await;
            process_available_packets(&mut nodes).await;
            let seed_ready = nodes[0].node.get_peer(&router_addr).is_some()
                && nodes[0].node.get_peer(&admin_addr).is_some();
            let router_ready = nodes[1].node.get_peer(&seed_addr).is_some()
                && nodes[1].node.get_peer(&guest_addr).is_some();
            let edge_ready = nodes[2].node.get_peer(&router_addr).is_some()
                && nodes[3].node.get_peer(&seed_addr).is_some();
            if seed_ready && router_ready && edge_ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("WebSocket seed/router topology must authenticate");

    assert!(
        nodes[0]
            .node
            .peer_is_configured_websocket_adjacency(&admin_addr),
        "the seed must recognize an authenticated inbound admin as an operator-configured adjacency"
    );
    assert!(
        nodes[0]
            .node
            .peer_is_configured_websocket_adjacency(&router_addr),
        "the seed must recognize an authenticated inbound router as an operator-configured adjacency"
    );
    assert!(
        nodes[1]
            .node
            .peer_is_configured_websocket_adjacency(&seed_addr),
        "the router must recognize its explicitly configured outbound seed"
    );

    assert_eq!(
        nodes[3].node.initiate_lookup(&guest_addr, 8).await,
        1,
        "admin lookup should leave through its configured WebSocket seed"
    );
    for _ in 0..500 {
        run_synthetic_node_work(&mut nodes).await;
        process_available_packets(&mut nodes).await;
        if nodes[3].node.find_next_hop(&guest_addr).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        !nodes[0].node.recent_requests.is_empty(),
        "the WSS seed must receive the admin lookup"
    );
    assert!(
        !nodes[1].node.recent_requests.is_empty(),
        "the WSS seed must forward the lookup to the router client"
    );
    assert!(
        !nodes[2].node.recent_requests.is_empty(),
        "the router must forward the lookup to its direct guest"
    );
    assert!(
        nodes[3].node.find_next_hop(&guest_addr).is_some(),
        "lookup should traverse the WSS listener and return a guest route"
    );

    nodes[3]
        .node
        .initiate_session(guest_addr, guest_pubkey)
        .await
        .expect("admin should initiate an end-to-end session over the learned route");
    for _ in 0..500 {
        run_synthetic_node_work(&mut nodes).await;
        process_available_packets(&mut nodes).await;
        let admin_established = nodes[3]
            .node
            .get_session(&guest_addr)
            .is_some_and(|session| session.is_established());
        let guest_established = nodes[2]
            .node
            .get_session(&admin_addr)
            .is_some_and(|session| session.is_established());
        if admin_established && guest_established {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        nodes[3]
            .node
            .get_session(&guest_addr)
            .is_some_and(|session| session.is_established()),
        "the admin session should establish over WSS seed/router transit"
    );
    assert!(
        nodes[2]
            .node
            .get_session(&admin_addr)
            .is_some_and(|session| session.is_established()),
        "the guest session should establish over WSS seed/router transit"
    );

    cleanup_nodes(&mut nodes).await;
}
