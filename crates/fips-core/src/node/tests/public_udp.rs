use super::*;
use crate::config::UdpConfig;
use crate::transport::udp::UdpTransport;
use crate::transport::{TransportAddr, TransportHandle, TransportId, packet_channel};
use spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, initiate_handshake, process_available_packets,
    run_synthetic_node_work,
};
use std::time::Duration;

async fn make_udp_node(public: bool) -> TestNode {
    let mut node = make_node();
    node.config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    node.config.node.discovery.nostr.enabled = true;
    node.config.node.discovery.nostr.policy = crate::config::NostrDiscoveryPolicy::Open;
    node.config.node.rate_limit.handshake_resend_interval_ms = 50;
    node.config.node.rate_limit.handshake_max_resends = 20;

    let transport_id = TransportId::new(1);
    let (packet_tx, packet_rx) = packet_channel(256);
    let (tun_outbound_tx, tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(256);
    node.tun_outbound_rx = Some(tun_outbound_rx);
    let mut transport = UdpTransport::new(
        transport_id,
        None,
        UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            public: Some(public),
            accept_connections: Some(true),
            ..UdpConfig::default()
        },
        packet_tx,
    );
    transport.start_async().await.expect("start UDP transport");
    let addr = TransportAddr::from_string(
        &transport
            .local_addr()
            .expect("UDP listener address")
            .to_string(),
    );
    node.transports
        .insert(transport_id, TransportHandle::Udp(transport));
    TestNode {
        node,
        transport_id,
        packet_rx,
        tun_outbound_tx,
        addr,
    }
}

fn configure_transit(nodes: &mut [TestNode], client: usize, server: usize) {
    let server_npub = nodes[server].node.npub();
    let server_addr = nodes[server].addr.to_string();
    nodes[client]
        .node
        .config
        .peers
        .push(crate::config::PeerConfig::new(
            server_npub,
            "udp",
            server_addr,
        ));
    nodes[client].node.configured_peers =
        ConfiguredPeerLookup::from_config(&nodes[client].node.config);
}

#[tokio::test]
async fn public_udp_seed_router_routes_explicit_npub_without_advert_or_tree_match() {
    // admin -> seed -> router -> guest. Only the configured physical UDP
    // adjacencies exist; no Nostr advert or direct admin/guest connection does.
    let mut nodes = vec![
        make_udp_node(true).await,
        make_udp_node(true).await,
        make_udp_node(false).await,
        make_udp_node(false).await,
    ];
    configure_transit(&mut nodes, 1, 0);
    configure_transit(&mut nodes, 2, 1);
    configure_transit(&mut nodes, 3, 0);

    initiate_handshake(&mut nodes, 1, 0).await;
    initiate_handshake(&mut nodes, 2, 1).await;
    initiate_handshake(&mut nodes, 3, 0).await;
    assert!(drain_all_packets(&mut nodes, false).await > 0);

    let seed_addr = *nodes[0].node.node_addr();
    let router_addr = *nodes[1].node.node_addr();
    let guest_addr = *nodes[2].node.node_addr();
    let admin_addr = *nodes[3].node.node_addr();
    assert!(
        nodes[0]
            .node
            .peer_is_operator_routing_adjacency(&admin_addr),
        "public UDP seed must recognize its authenticated inbound client"
    );
    assert!(
        nodes[0]
            .node
            .peer_is_operator_routing_adjacency(&router_addr),
        "public UDP seed must recognize its authenticated inbound router"
    );
    assert!(
        nodes[1]
            .node
            .peer_is_operator_routing_adjacency(&guest_addr),
        "public UDP router must recognize its authenticated inbound guest"
    );

    // Deliberately remove the seed's tree match so the test proves the
    // operator-approved reply-learned fallback rather than tree convergence.
    nodes[0].node.tree_state_mut().remove_peer(&router_addr);
    nodes[0].node.tree_state_mut().become_root();
    let guest_pubkey = nodes[2].node.identity().pubkey_full();
    nodes[3]
        .node
        .register_endpoint_identity(guest_addr, guest_pubkey);
    assert_eq!(
        nodes[3].node.initiate_lookup(&guest_addr, 8).await,
        1,
        "application-selected npub lookup must leave through configured UDP transit"
    );

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            run_synthetic_node_work(&mut nodes).await;
            process_available_packets(&mut nodes).await;
            if nodes[3].node.find_next_hop(&guest_addr).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("routed npub lookup over public UDP transit");

    assert!(
        !nodes[0].node.recent_requests.is_empty(),
        "seed must receive the admin lookup"
    );
    assert!(
        !nodes[1].node.recent_requests.is_empty(),
        "seed must forward the lookup to its router client"
    );
    assert!(
        !nodes[2].node.recent_requests.is_empty(),
        "router must forward the lookup to its guest"
    );
    assert!(
        nodes[3].node.find_next_hop(&guest_addr).is_some(),
        "lookup response must install the reverse-learned route"
    );
    assert!(
        nodes[3].node.get_peer(&guest_addr).is_none(),
        "routed identity must not require a direct physical connection"
    );
    assert!(
        nodes[3].node.get_peer(&seed_addr).is_some(),
        "admin must retain only its configured transit adjacency"
    );

    cleanup_nodes(&mut nodes).await;
}
