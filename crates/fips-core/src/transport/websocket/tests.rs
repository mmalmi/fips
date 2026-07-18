use super::*;
use crate::node::wire::build_msg1;
use crate::transport::packet_channel;
use crate::utils::index::SessionIndex;

fn test_transport(queue: usize) -> WebSocketTransport {
    let identity = Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(8);
    WebSocketTransport::new(
        TransportId::new(7),
        None,
        WebSocketConfig {
            max_send_queue: Some(queue),
            ..Default::default()
        },
        packet_tx,
        &identity,
    )
}

async fn wait_for_connection(transport: &WebSocketTransport, addr: &TransportAddr) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if transport.connection_state_sync(addr) == ConnectionState::Connected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("WebSocket seed connection did not become ready");
}

#[test]
fn key_hint_round_trip_is_exact_and_nonce_bound() {
    let request = LocalKeyHint::Request { nonce: 42 };
    assert_eq!(LocalKeyHint::decode(&request.encode()), Some(request));
    let response = LocalKeyHint::Response {
        nonce: 42,
        pubkey: [9; 32],
    };
    assert_eq!(LocalKeyHint::decode(&response.encode()), Some(response));
    assert!(LocalKeyHint::decode(b"not-a-key-hint").is_none());
}

#[tokio::test]
async fn full_send_queue_returns_backpressure_without_growing() {
    let mut transport = test_transport(1);
    transport.state = TransportState::Up;
    let addr = TransportAddr::from_string("ws://127.0.0.1:1/fips");
    let (tx, _rx) = mpsc::channel(1);
    transport
        .runtime
        .pool
        .lock()
        .await
        .insert(addr.clone(), Connection { generation: 1, tx });
    let record = build_msg1(
        SessionIndex::new(1),
        &[0; crate::noise::HANDSHAKE_MSG1_SIZE],
    );
    transport.send_async(&addr, &record).await.unwrap();
    let error = transport.send_async(&addr, &record).await.unwrap_err();
    assert!(error.to_string().contains("send queue full"));
    assert_eq!(transport.stats().send_queue_full, 1);
}

#[tokio::test]
async fn configured_seed_reconnects_after_listener_restart() {
    let server_identity = Identity::generate();
    let (server_packet_tx, _server_packet_rx) = packet_channel(8);
    let mut first_server = WebSocketTransport::new(
        TransportId::new(1),
        None,
        WebSocketConfig {
            bind_addr: Some("127.0.0.1:0".into()),
            ..Default::default()
        },
        server_packet_tx,
        &server_identity,
    );
    first_server.start_async().await.unwrap();
    let server_addr = first_server.local_addr().unwrap();
    let seed_url = TransportAddr::from_string(&format!("ws://{server_addr}/fips"));

    let client_identity = Identity::generate();
    let (client_packet_tx, _client_packet_rx) = packet_channel(8);
    let mut client = WebSocketTransport::new(
        TransportId::new(2),
        None,
        WebSocketConfig {
            seed_urls: vec![seed_url.to_string()],
            reconnect_initial_ms: Some(10),
            reconnect_max_ms: Some(40),
            ..Default::default()
        },
        client_packet_tx,
        &client_identity,
    );
    client.start_async().await.unwrap();
    wait_for_connection(&client, &seed_url).await;

    first_server.stop_async().await.unwrap();
    let (replacement_packet_tx, _replacement_packet_rx) = packet_channel(8);
    let mut replacement_server = WebSocketTransport::new(
        TransportId::new(1),
        None,
        WebSocketConfig {
            bind_addr: Some(server_addr.to_string()),
            ..Default::default()
        },
        replacement_packet_tx,
        &server_identity,
    );
    replacement_server.start_async().await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if client.stats().connections_opened >= 2
                && client.connection_state_sync(&seed_url) == ConnectionState::Connected
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("configured WebSocket seed did not reconnect after restart");

    client.stop_async().await.unwrap();
    replacement_server.stop_async().await.unwrap();
}

#[test]
fn websocket_url_validation_rejects_remote_plaintext_and_bad_limits() {
    let remote_plaintext = WebSocketConfig {
        seed_urls: vec!["ws://example.com/fips".into()],
        ..Default::default()
    };
    assert!(remote_plaintext.validate().is_err());

    let loopback_plaintext = WebSocketConfig {
        seed_urls: vec!["ws://127.0.0.1:9000/fips".into()],
        ..Default::default()
    };
    loopback_plaintext.validate().unwrap();

    let unbounded = WebSocketConfig {
        max_send_queue: Some(4097),
        ..Default::default()
    };
    assert!(unbounded.validate().is_err());
}

#[test]
fn configured_seed_accepts_routed_fips_handshakes_by_default() {
    let client = WebSocketConfig {
        seed_urls: vec!["wss://seed.example/fips".into()],
        ..Default::default()
    };
    assert!(client.accept_connections());

    let explicitly_closed = WebSocketConfig {
        accept_connections: Some(false),
        ..client
    };
    assert!(!explicitly_closed.accept_connections());
}
