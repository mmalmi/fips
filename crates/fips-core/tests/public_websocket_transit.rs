use fips_core::config::{
    ConnectPolicy, NostrDiscoveryPolicy, PeerConfig, RoutingMode, TransportInstances,
    WebSocketConfig,
};
use fips_core::{Config, FipsEndpoint, Identity, PeerIdentity, encode_nsec};
use std::net::TcpListener;
use std::time::Duration;

const SERVICE_PORT: u16 = 44_000;
const SOURCE_PORT: u16 = 44_001;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(8);
const CHURN_ROUNDS: usize = 20;
const BUSY_SEED_CLIENTS: usize = 24;

fn available_websocket_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve WebSocket listener port");
    let port = listener
        .local_addr()
        .expect("read reserved WebSocket listener port")
        .port();
    drop(listener);
    format!("ws://127.0.0.1:{port}/fips")
}

fn websocket_config(bind_url: Option<&str>, seed: Option<(&str, &str)>) -> Config {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::Open;
    config.node.discovery.lan.enabled = false;
    config.node.discovery.local.enabled = false;
    config.node.rate_limit.handshake_resend_interval_ms = 50;
    config.node.rate_limit.handshake_max_resends = 20;

    let seed_urls = seed
        .map(|(_, url)| vec![url.to_string()])
        .unwrap_or_default();
    config.transports.websocket = TransportInstances::Single(WebSocketConfig {
        bind_addr: bind_url.map(|url| {
            url.strip_prefix("ws://")
                .and_then(|url| url.strip_suffix("/fips"))
                .expect("loopback WebSocket URL")
                .to_string()
        }),
        seed_urls,
        reconnect_initial_ms: Some(10),
        reconnect_max_ms: Some(50),
        ..WebSocketConfig::default()
    });
    if let Some((npub, url)) = seed {
        config.peers.push(PeerConfig::new(npub, "websocket", url));
    }
    config
}

fn with_identity(mut config: Config, identity: &Identity) -> Config {
    config.node.identity.nsec = Some(encode_nsec(&identity.keypair().secret_key()));
    config
}

fn configured_listener_peer(npub: &str, url: &str) -> PeerConfig {
    let mut peer = PeerConfig::new(npub, "websocket", url);
    peer.connect_policy = ConnectPolicy::Manual;
    peer
}

async fn bind_endpoint(config: Config) -> FipsEndpoint {
    FipsEndpoint::builder()
        .config(config)
        .without_system_tun()
        .bind()
        .await
        .expect("bind FIPS endpoint")
}

async fn wait_for_exact_seed(endpoint: &FipsEndpoint, seed_npub: &str) {
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        loop {
            let connected = endpoint
                .peers()
                .await
                .expect("peer snapshot")
                .into_iter()
                .filter(|peer| peer.connected)
                .collect::<Vec<_>>();
            if connected.iter().any(|peer| peer.npub == seed_npub) {
                assert!(
                    connected.iter().all(|peer| peer.npub == seed_npub),
                    "client authenticated an unexpected physical peer: {connected:?}"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("client did not authenticate expected seed {seed_npub}"));
}

async fn wait_for_adjacency(endpoint: &FipsEndpoint, peer_npub: &str) {
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        loop {
            if endpoint
                .peers()
                .await
                .expect("peer snapshot")
                .iter()
                .any(|peer| peer.connected && peer.npub == peer_npub)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("seed adjacency did not authenticate {peer_npub}"));
}

async fn receive_payload(
    receiver: &fips_core::FipsEndpointServiceReceiver,
    expected_source: &str,
    expected_payload: &[u8],
) {
    let mut datagrams = Vec::new();
    tokio::time::timeout(
        DELIVERY_TIMEOUT,
        receiver.recv_batch_into(&mut datagrams, 8),
    )
    .await
    .expect("route-by-npub delivery timed out")
    .expect("service receiver closed");
    assert_eq!(datagrams.len(), 1);
    assert_eq!(datagrams[0].source_peer.npub(), expected_source);
    assert_eq!(datagrams[0].source_port, SOURCE_PORT);
    assert_eq!(datagrams[0].destination_port, SERVICE_PORT);
    assert_eq!(datagrams[0].data.as_slice(), expected_payload);
}

#[tokio::test]
async fn persistent_two_seed_websocket_transit_survives_client_churn() {
    let seed_one_url = available_websocket_url();
    let seed_two_url = available_websocket_url();
    let seed_one_identity = Identity::generate();
    let seed_one_npub = seed_one_identity.npub();
    let seed_two_identity = Identity::generate();
    let seed_two_npub = seed_two_identity.npub();

    let mut seed_one_config = with_identity(
        websocket_config(Some(&seed_one_url), None),
        &seed_one_identity,
    );
    seed_one_config
        .peers
        .push(configured_listener_peer(&seed_two_npub, &seed_two_url));
    let seed_one = bind_endpoint(seed_one_config).await;
    let seed_two = bind_endpoint(with_identity(
        websocket_config(Some(&seed_two_url), Some((&seed_one_npub, &seed_one_url))),
        &seed_two_identity,
    ))
    .await;
    tokio::join!(
        wait_for_adjacency(&seed_one, &seed_two_npub),
        wait_for_adjacency(&seed_two, &seed_one_npub),
    );

    let mut busy_seed_clients = Vec::with_capacity(BUSY_SEED_CLIENTS);
    for _ in 0..BUSY_SEED_CLIENTS {
        busy_seed_clients.push(
            bind_endpoint(websocket_config(
                None,
                Some((&seed_one_npub, &seed_one_url)),
            ))
            .await,
        );
    }
    for client in &busy_seed_clients {
        wait_for_exact_seed(client, &seed_one_npub).await;
    }

    for round in 0..CHURN_ROUNDS {
        let (client_one, client_two) = tokio::join!(
            bind_endpoint(websocket_config(
                None,
                Some((&seed_one_npub, &seed_one_url))
            )),
            bind_endpoint(websocket_config(
                None,
                Some((&seed_two_npub, &seed_two_url))
            )),
        );
        let client_one_npub = client_one.npub().to_string();
        let client_two_npub = client_two.npub().to_string();

        tokio::join!(
            wait_for_exact_seed(&client_one, &seed_one_npub),
            wait_for_exact_seed(&client_two, &seed_two_npub),
        );

        let receiver_one = client_one
            .register_service_receiver(SERVICE_PORT)
            .await
            .expect("register first client service");
        let receiver_two = client_two
            .register_service_receiver(SERVICE_PORT)
            .await
            .expect("register second client service");
        let payload_one = format!("one-to-two-{round}").into_bytes();
        let payload_two = format!("two-to-one-{round}").into_bytes();

        client_one
            .send_datagram(
                PeerIdentity::from_npub(&client_two_npub).expect("second client identity"),
                SOURCE_PORT,
                SERVICE_PORT,
                payload_one.clone(),
            )
            .await
            .expect("send first-to-second datagram");
        client_two
            .send_datagram(
                PeerIdentity::from_npub(&client_one_npub).expect("first client identity"),
                SOURCE_PORT,
                SERVICE_PORT,
                payload_two.clone(),
            )
            .await
            .expect("send second-to-first datagram");

        tokio::join!(
            receive_payload(&receiver_two, &client_one_npub, &payload_one),
            receive_payload(&receiver_one, &client_two_npub, &payload_two),
        );

        let (first_shutdown, second_shutdown) =
            tokio::join!(client_one.shutdown(), client_two.shutdown());
        first_shutdown.expect("first client shutdown");
        second_shutdown.expect("second client shutdown");
    }

    for client in busy_seed_clients {
        client.shutdown().await.expect("busy-seed client shutdown");
    }
    let (first_shutdown, second_shutdown) = tokio::join!(seed_one.shutdown(), seed_two.shutdown());
    first_shutdown.expect("first seed shutdown");
    second_shutdown.expect("second seed shutdown");
}
