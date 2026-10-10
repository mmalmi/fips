use super::*;
use crate::transport::ConnectionState;

#[tokio::test]
async fn closed_outbound_handshake_releases_candidate_before_noise_timeout() {
    let mut server = make_websocket_node(WebSocketConfig {
        bind_addr: Some("127.0.0.1:0".into()),
        ..Default::default()
    })
    .await;
    let mut client = make_websocket_node(WebSocketConfig::default()).await;
    let peer = PeerIdentity::from_pubkey_full(server.node.identity().pubkey_full());
    let destination = server.addr.clone();
    let config: crate::config::PeerConfig = serde_json::from_value(serde_json::json!({
        "npub": server.node.identity().npub(),
        "addresses": [{"transport": "websocket", "addr": destination.to_string()}],
        "auto_reconnect": true
    }))
    .unwrap();
    client.node.config.peers.push(config);
    client.node.configured_peers = ConfiguredPeerLookup::from_config(&client.node.config);
    client
        .node
        .initiate_connection(client.transport_id, destination.clone(), peer)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            client.node.poll_pending_connects().await;
            if client.node.connection_count() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("real carrier must enter Noise authentication");
    let first = tokio::time::timeout(Duration::from_secs(2), server.packet_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(crate::node::wire::Msg1Header::parse(first.data.as_slice()).is_some());
    let (link, index) = client
        .node
        .peers
        .connection_iter()
        .map(|(link, conn)| {
            assert!(conn.idle_time(Node::now_ms()) < 2_000);
            (*link, conn.our_index().unwrap())
        })
        .next()
        .unwrap();
    // A responsive but silent carrier is not failed: retain its normal deadline.
    client.node.check_timeouts().await;
    assert!(client.node.peers.get_connection(&link).is_some());
    // Close the real remote socket before replying to Noise, without marking
    // the local handshake failed or advancing its configured timeout.
    server
        .node
        .transports
        .get(&server.transport_id)
        .unwrap()
        .close_connection(&first.remote_addr)
        .await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while client
            .node
            .transports
            .get(&client.transport_id)
            .unwrap()
            .connection_state(&destination)
            != ConnectionState::None
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("client must observe physical closure");
    client.node.check_timeouts().await;
    assert_eq!(
        client.node.connection_count(),
        0,
        "a known-closed carrier must not occupy the full Noise timeout"
    );
    assert!(!client.node.index_allocator.is_allocated(index));
    assert!(client.node.pending_outbound.is_empty());
    assert!(!client.node.links.contains_key(&link));
    assert!(
        client.node.retry_pending.contains_key(peer.node_addr()),
        "configured peers must enter existing bounded retry policy"
    );
    cleanup_nodes(&mut [server, client]).await;
}
