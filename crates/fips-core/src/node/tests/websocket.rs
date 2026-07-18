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
    .expect("URL-only WebSocket seed must authenticate with Noise IK");

    assert_eq!(
        nodes[1]
            .node
            .get_peer(&server_addr)
            .and_then(|peer| peer.transport_id()),
        Some(nodes[1].transport_id)
    );
    cleanup_nodes(&mut nodes).await;
}
