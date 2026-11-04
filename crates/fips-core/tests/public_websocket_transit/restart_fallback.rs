use super::*;
use fips_core::config::{PeerAddress, UdpConfig};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

fn with_udp(mut config: Config, addr: SocketAddr) -> Config {
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some(addr.to_string()),
        ..Default::default()
    });
    config
}

async fn exact_transport(seed: &FipsEndpoint, peer: &str, transport: &str) {
    loop {
        if seed.peers().await.unwrap().iter().any(|p| {
            p.npub == peer && p.connected && p.transport_type.as_deref() == Some(transport)
        }) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn send_to(
    receiver: &fips_core::FipsEndpointServiceReceiver,
    from: &FipsEndpoint,
    to: &FipsEndpoint,
    bytes: &[u8],
) {
    from.send_datagram(
        PeerIdentity::from_npub(to.npub()).unwrap(),
        SOURCE_PORT,
        SERVICE_PORT,
        bytes.to_vec(),
    )
    .await
    .unwrap();
    receive_payload(receiver, from.npub(), bytes).await;
}

#[derive(Clone, Copy, PartialEq)]
enum History {
    ForwardOnly,
    ColdReturn,
    RestartReturn,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restarted_client_recovers_both_routed_directions_in_ten_seconds() {
    qualify(History::ForwardOnly).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_websocket_returns_routed_payload_to_udp_in_ten_seconds() {
    qualify(History::ColdReturn).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restarted_websocket_returns_routed_payload_to_udp_in_ten_seconds() {
    qualify(History::RestartReturn).await;
}

async fn qualify(history: History) {
    let identity = Identity::generate();
    let ws = available_websocket_url();
    let seed_udp = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let seed = bind_endpoint(with_udp(websocket_config(Some(&ws), None), seed_udp)).await;
    let proxy = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let blocked = Arc::new(AtomicBool::new(history == History::ColdReturn));
    let bulk = Arc::new([AtomicU64::new(0), AtomicU64::new(0)]);
    let wire = bulk.clone();
    let gate = blocked.clone();
    let forwarding = tokio::spawn(async move {
        let mut client_addr = None;
        let mut buf = vec![0; 65535];
        loop {
            let (len, from) = proxy.recv_from(&mut buf).await.unwrap();
            if gate.load(Ordering::SeqCst) {
                continue;
            }
            let to = if from == seed_udp {
                let Some(client) = client_addr else { continue };
                client
            } else {
                client_addr = Some(from);
                seed_udp
            };
            if len >= 1000 {
                wire[usize::from(from == seed_udp)].fetch_add(1, Ordering::SeqCst);
            }
            proxy.send_to(&buf[..len], to).await.unwrap();
        }
    });
    let mut config = with_udp(websocket_config(None, None), "127.0.0.1:0".parse().unwrap());
    let mut peer = PeerConfig::new(seed.npub(), "udp", proxy_addr.to_string());
    peer.addresses = vec![
        PeerAddress::with_priority("udp", proxy_addr.to_string(), 10),
        PeerAddress::with_priority("websocket", ws.clone(), 200),
    ];
    config.peers.push(peer);
    let config = with_identity(config, &identity);
    let original = bind_endpoint(config.clone()).await;
    let recipient = bind_endpoint(websocket_config(None, Some((seed.npub(), &ws)))).await;
    let first_transport = if history == History::ColdReturn {
        "websocket"
    } else {
        "udp"
    };
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        exact_transport(&seed, original.npub(), first_transport),
    )
    .await
    .expect("initial carrier");
    wait_for_exact_seed(&recipient, seed.npub()).await;
    let receiver = recipient
        .register_service_receiver(SERVICE_PORT)
        .await
        .unwrap();
    let original_rx = original
        .register_service_receiver(SERVICE_PORT)
        .await
        .unwrap();
    send_to(&receiver, &original, &recipient, b"routed-before").await;
    send_to(&original_rx, &recipient, &original, b"reply-before").await;
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        exact_transport(&seed, original.npub(), first_transport),
    )
    .await
    .unwrap();

    let (client, client_rx) = if history == History::ColdReturn {
        (original, original_rx)
    } else {
        let started = Instant::now();
        tokio::time::timeout(Duration::from_secs(10), async {
            blocked.store(true, Ordering::SeqCst);
            original.shutdown().await.unwrap();
            let restarted = bind_endpoint(config).await;
            assert_eq!(restarted.npub(), identity.npub());
            exact_transport(&seed, restarted.npub(), "websocket").await;
            eprintln!(
                "authenticated_websocket_ms={}",
                started.elapsed().as_millis()
            );
            wait_for_exact_seed(&restarted, seed.npub()).await;
            let rx = restarted
                .register_service_receiver(SERVICE_PORT)
                .await
                .unwrap();
            send_to(&receiver, &restarted, &recipient, b"routed-after").await;
            send_to(&rx, &recipient, &restarted, b"reply-after").await;
            eprintln!("bidirectional_route_ms={}", started.elapsed().as_millis());
            (restarted, rx)
        })
        .await
        .expect("same-key restart and both routed deliveries must finish inside 10 seconds")
    };

    if history != History::ForwardOnly {
        // The WebSocket listener stays available. Exercise both directions while
        // observing large UDP frames on the only underlay path from this client.
        let restored = Instant::now();
        blocked.store(false, Ordering::SeqCst);
        let elapsed = tokio::time::timeout(Duration::from_secs(35), async {
            for sequence in 0u32.. {
                let first = marker(sequence, 1024);
                let second = marker(sequence, 1120);
                let before = bulk[0].load(Ordering::SeqCst);
                let outward = delivered(&receiver, &client, &recipient, &first).await
                    && bulk[0].load(Ordering::SeqCst) > before;
                let before = bulk[1].load(Ordering::SeqCst);
                let inward = delivered(&client_rx, &recipient, &client, &second).await
                    && bulk[1].load(Ordering::SeqCst) > before;
                if outward && inward {
                    return restored.elapsed();
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            unreachable!()
        })
        .await
        .expect("UDP never carried both routed payloads within the observation window");
        eprintln!("positive_bidirectional_udp_ms={}", elapsed.as_millis());
        assert!(
            elapsed < Duration::from_secs(10),
            "positive UDP return missed ten seconds: {elapsed:?}"
        );
    }
    client.shutdown().await.unwrap();
    forwarding.abort();
    let _ = forwarding.await;
    recipient.shutdown().await.unwrap();
    seed.shutdown().await.unwrap();
}

fn marker(sequence: u32, len: usize) -> Vec<u8> {
    let mut payload = vec![0xab; len];
    payload[..4].copy_from_slice(&sequence.to_be_bytes());
    payload
}

async fn delivered(
    receiver: &fips_core::FipsEndpointServiceReceiver,
    from: &FipsEndpoint,
    to: &FipsEndpoint,
    payload: &[u8],
) -> bool {
    let remote = PeerIdentity::from_npub(to.npub()).unwrap();
    tokio::time::timeout(Duration::from_millis(450), async {
        if from
            .send_datagram(remote, SOURCE_PORT, SERVICE_PORT, payload.to_vec())
            .await
            .is_err()
        {
            return false;
        }
        let mut batch = Vec::new();
        loop {
            batch.clear();
            receiver.recv_batch_into(&mut batch, 8).await.unwrap();
            if batch.iter().any(|d| {
                d.source_peer.npub() == from.npub()
                    && d.source_port == SOURCE_PORT
                    && d.destination_port == SERVICE_PORT
                    && d.data.as_slice() == payload
            }) {
                return true;
            }
        }
    })
    .await
    .unwrap_or(false)
}
