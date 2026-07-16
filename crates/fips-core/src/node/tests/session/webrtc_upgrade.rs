use super::*;
use crate::config::{
    ConnectPolicy, NostrDiscoveryConfig, PeerAddress, PeerConfig, UdpConfig, WebRtcConfig,
};
use crate::node::tests::spanning_tree::{drain_all_packets, initiate_handshake};
use crate::transport::udp::UdpTransport;
use crate::transport::webrtc::WebRtcTransport;
use crate::transport::{ConnectionState, TransportHandle, packet_channel};

const UDP_TRANSPORT_NUMBER: u32 = 1;
const WEBRTC_TRANSPORT_NUMBER: u32 = 2;

#[test]
fn simultaneous_webrtc_upgrade_preserves_shared_physical_carrier() {
    run_large_stack_async_test("fips-native-webrtc-shared-carrier", || async {
        let mut nodes = vec![
            make_dual_transport_node(fixed_identity(6, 0x03)).await,
            make_dual_transport_node(fixed_identity(1, 0x02)).await,
        ];
        configure_fallback_and_direct_paths(&mut nodes).await;

        initiate_handshake(&mut nodes, 0, 1).await;
        drain_all_packets(&mut nodes, false).await;

        let identity_a = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
        let identity_b = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
        let node_a_addr = *identity_a.node_addr();
        let node_b_addr = *identity_b.node_addr();
        assert_eq!(
            nodes[0]
                .node
                .get_peer(&node_b_addr)
                .and_then(|peer| peer.transport_id()),
            Some(TransportId::new(UDP_TRANSPORT_NUMBER))
        );
        assert_eq!(
            nodes[1]
                .node
                .get_peer(&node_a_addr)
                .and_then(|peer| peer.transport_id()),
            Some(TransportId::new(UDP_TRANSPORT_NUMBER))
        );

        let webrtc_addr_a = identity_transport_addr(nodes[0].node.identity());
        let webrtc_addr_b = identity_transport_addr(nodes[1].node.identity());
        assert!(nodes[0].node.alternate_path_priority_allows_replace(
            &node_b_addr,
            TransportId::new(WEBRTC_TRANSPORT_NUMBER),
            &webrtc_addr_b,
        ));
        assert!(nodes[1].node.alternate_path_priority_allows_replace(
            &node_a_addr,
            TransportId::new(WEBRTC_TRANSPORT_NUMBER),
            &webrtc_addr_a,
        ));
        nodes[0]
            .node
            .initiate_connection(
                TransportId::new(WEBRTC_TRANSPORT_NUMBER),
                webrtc_addr_b.clone(),
                identity_b,
            )
            .await
            .expect("node A starts WebRTC upgrade");
        nodes[1]
            .node
            .initiate_connection(
                TransportId::new(WEBRTC_TRANSPORT_NUMBER),
                webrtc_addr_a.clone(),
                identity_a,
            )
            .await
            .expect("node B starts WebRTC upgrade");

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                drive_webrtc_negotiation(&mut nodes).await;
                if physical_path_is_connected(&nodes[0].node, &webrtc_addr_b)
                    && physical_path_is_connected(&nodes[1].node, &webrtc_addr_a)
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "simultaneous ordinary port-257 offers should establish one shared WebRTC carrier: A={}; B={}",
                upgrade_diagnostic(&nodes[0].node, &node_b_addr, &webrtc_addr_b),
                upgrade_diagnostic(&nodes[1].node, &node_a_addr, &webrtc_addr_a),
            )
        });

        // Hold logical FMP establishment until both physical data channels are
        // ready, then launch both directions in the same turn. This makes the
        // shared-carrier cross-connection teardown deterministic.
        for node in nodes.iter_mut() {
            node.node.poll_pending_connects().await;
            assert!(!node.node.pending_outbound.is_empty());
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                process_available_packets(&mut nodes).await;
                if active_path_is_webrtc(&nodes[0].node, &node_b_addr, &webrtc_addr_b)
                    && active_path_is_webrtc(&nodes[1].node, &node_a_addr, &webrtc_addr_a)
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "simultaneous logical FMP handshakes should preserve the winning shared carrier: A={}; B={}",
                upgrade_diagnostic(&nodes[0].node, &node_b_addr, &webrtc_addr_b),
                upgrade_diagnostic(&nodes[1].node, &node_a_addr, &webrtc_addr_a),
            )
        });

        let mut endpoint_b = nodes[1]
            .node
            .attach_endpoint_data_io(8)
            .expect("node B endpoint I/O");
        let endpoint_identity_b =
            PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
        send_endpoint_data_via_dataplane(
            &mut nodes[0].node,
            endpoint_identity_b,
            b"survives-cross-connection-resolution".to_vec(),
        )
        .await
        .expect("queue endpoint data after WebRTC promotion");
        let event = recv_endpoint_event_while_draining(
            &mut nodes,
            &mut endpoint_b.event_rx,
            Duration::from_secs(10),
            "endpoint data over promoted WebRTC carrier",
        )
        .await;
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            b"survives-cross-connection-resolution"
        );
        assert!(active_path_is_webrtc(
            &nodes[0].node,
            &node_b_addr,
            &webrtc_addr_b
        ));
        assert!(active_path_is_webrtc(
            &nodes[1].node,
            &node_a_addr,
            &webrtc_addr_a
        ));

        cleanup_nodes(&mut nodes).await;
    });
}

async fn configure_fallback_and_direct_paths(nodes: &mut [TestNode]) {
    let identity_a = nodes[0].node.identity();
    let identity_b = nodes[1].node.identity();
    let udp_addr_a = nodes[0].addr.to_string();
    let udp_addr_b = nodes[1].addr.to_string();
    let webrtc_addr_a = identity_transport_addr(identity_a).to_string();
    let webrtc_addr_b = identity_transport_addr(identity_b).to_string();

    let peer_b = test_peer_config(identity_b.npub(), udp_addr_b, webrtc_addr_b);
    let peer_a = test_peer_config(identity_a.npub(), udp_addr_a, webrtc_addr_a);
    nodes[0]
        .node
        .update_peers(vec![peer_b])
        .await
        .expect("configure node B fallback and direct paths");
    nodes[1]
        .node
        .update_peers(vec![peer_a])
        .await
        .expect("configure node A fallback and direct paths");
}

fn test_peer_config(npub: String, udp_addr: String, webrtc_addr: String) -> PeerConfig {
    PeerConfig {
        npub,
        alias: None,
        addresses: vec![
            PeerAddress::with_priority("udp", udp_addr, 250),
            PeerAddress::with_priority("webrtc", webrtc_addr, 100),
        ],
        connect_policy: ConnectPolicy::Manual,
        auto_reconnect: false,
        discovery_fallback_transit: true,
    }
}

fn fixed_identity(secret_scalar: u8, expected_parity: u8) -> Identity {
    let mut secret = [0u8; 32];
    secret[31] = secret_scalar;
    let identity = Identity::from_secret_bytes(&secret).expect("fixed test identity");
    assert_eq!(identity.pubkey_full().serialize()[0], expected_parity);
    identity
}

async fn make_dual_transport_node(identity: Identity) -> TestNode {
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.lan.enabled = false;
    config.node.rate_limit.handshake_burst = 1_000;
    config.node.rate_limit.handshake_rate = 1_000.0;
    config.node.bloom.update_debounce_ms = 50;
    let mut node = Node::with_identity(identity, config).expect("dual-transport test node");

    let (packet_tx, packet_rx) = packet_channel(256);
    let (tun_outbound_tx, tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(256);
    node.tun_outbound_rx = Some(tun_outbound_rx);

    let mut udp = UdpTransport::new(
        TransportId::new(UDP_TRANSPORT_NUMBER),
        None,
        UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(1_280),
            ..Default::default()
        },
        packet_tx.clone(),
    );
    udp.start_async().await.expect("loopback UDP transport");
    let udp_addr =
        TransportAddr::from_string(&udp.local_addr().expect("loopback UDP address").to_string());

    let mut webrtc = WebRtcTransport::new(
        TransportId::new(WEBRTC_TRANSPORT_NUMBER),
        None,
        WebRtcConfig {
            accept_connections: Some(true),
            max_connections: Some(1),
            connect_timeout_ms: Some(5_000),
            ice_gather_timeout_ms: Some(2_000),
            stun_servers: Some(Vec::new()),
            resolve_mdns_candidates: Some(false),
            ..Default::default()
        },
        packet_tx,
        node.identity(),
        &NostrDiscoveryConfig::default(),
    )
    .expect("loopback WebRTC transport");
    webrtc
        .use_canonical_loopback_candidate_profile()
        .expect("one real UDP4 loopback ICE candidate");
    webrtc.start_async().await.expect("start WebRTC transport");

    node.transports.insert(
        TransportId::new(UDP_TRANSPORT_NUMBER),
        TransportHandle::Udp(udp),
    );
    node.transports.insert(
        TransportId::new(WEBRTC_TRANSPORT_NUMBER),
        TransportHandle::WebRtc(Box::new(webrtc)),
    );

    TestNode {
        node,
        transport_id: TransportId::new(UDP_TRANSPORT_NUMBER),
        packet_rx,
        tun_outbound_tx,
        addr: udp_addr,
    }
}

async fn drive_webrtc_negotiation(nodes: &mut [TestNode]) {
    for node in nodes.iter_mut() {
        node.node.poll_nostr_discovery().await;
    }
    process_available_packets(nodes).await;
}

fn identity_transport_addr(identity: &Identity) -> TransportAddr {
    TransportAddr::from_string(&hex::encode(identity.pubkey_full().serialize()))
}

fn active_path_is_webrtc(
    node: &Node,
    peer_addr: &NodeAddr,
    transport_addr: &TransportAddr,
) -> bool {
    node.get_peer(peer_addr)
        .is_some_and(|peer| peer.transport_id() == Some(TransportId::new(WEBRTC_TRANSPORT_NUMBER)))
        && node
            .transports
            .get(&TransportId::new(WEBRTC_TRANSPORT_NUMBER))
            .is_some_and(|transport| {
                transport.connection_state(transport_addr) == ConnectionState::Connected
            })
}

fn physical_path_is_connected(node: &Node, transport_addr: &TransportAddr) -> bool {
    node.transports
        .get(&TransportId::new(WEBRTC_TRANSPORT_NUMBER))
        .is_some_and(|transport| {
            transport.connection_state(transport_addr) == ConnectionState::Connected
        })
}

fn upgrade_diagnostic(node: &Node, peer_addr: &NodeAddr, transport_addr: &TransportAddr) -> String {
    let peer_transport = node
        .get_peer(peer_addr)
        .and_then(|peer| peer.transport_id());
    let Some(TransportHandle::WebRtc(transport)) = node
        .transports
        .get(&TransportId::new(WEBRTC_TRANSPORT_NUMBER))
    else {
        return "missing WebRTC transport".to_string();
    };
    format!(
        "peerTransport={peer_transport:?} connection={:?} resources={:?} links={} pendingConnects={} pendingOutbound={} sessions={}",
        transport.connection_state_sync(transport_addr),
        transport.resource_snapshot(),
        node.links.len(),
        node.pending_connects.len(),
        !node.pending_outbound.is_empty(),
        node.sessions.len(),
    )
}
