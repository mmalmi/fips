use fips_core::config::{
    ConnectPolicy, NostrDiscoveryPolicy, PeerConfig, RoutingMode, TransportInstances,
    WebSocketConfig,
};
use fips_core::{Config, FipsEndpoint, Identity, PeerIdentity, encode_nsec};
use socket2::SockRef;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const SERVICE_PORT: u16 = 44_000;
const SOURCE_PORT: u16 = 44_001;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(8);
const CHURN_ROUNDS: usize = 20;
const BUSY_SEED_CLIENTS: usize = 24;

fn available_websocket_address() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("reserve WebSocket listener port");
    let address = listener
        .local_addr()
        .expect("read reserved WebSocket listener address");
    drop(listener);
    address
}

async fn start_proxy(listen_address: SocketAddr, target_address: SocketAddr) -> JoinHandle<()> {
    let listener = tokio::net::TcpListener::bind(listen_address)
        .await
        .expect("bind WebSocket test proxy");
    tokio::spawn(async move {
        // Dropping the proxy task aborts every owned stream as well as its listener.
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut incoming, _) = accepted.expect("accept proxied connection");
                    connections.spawn(async move {
                        let mut outgoing = tokio::net::TcpStream::connect(target_address)
                            .await
                            .expect("connect proxy target");
                        let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
                    });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    result.expect("proxy connection task");
                }
            }
        }
    })
}

#[tokio::test]
async fn proxy_accepts_reconnections_and_aborts_open_streams() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (mut stream, _) = target.accept().await.unwrap();
            connections.spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    let proxy_address = available_websocket_address();
    let proxy = start_proxy(proxy_address, target_address).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        for _ in 0..2 {
            let mut stream = tokio::net::TcpStream::connect(proxy_address).await.unwrap();
            stream.write_all(b"a").await.unwrap();
            let mut reply = [0];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"a");
        }
        let mut streams = Vec::new();
        for _ in 0..2 {
            let mut stream = tokio::net::TcpStream::connect(proxy_address).await.unwrap();
            stream.write_all(b"b").await.unwrap();
            let mut reply = [0];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"b");
            streams.push(stream);
        }
        assert!(
            !proxy.is_finished(),
            "proxy must continue accepting connections"
        );
        proxy.abort();
        assert!(proxy.await.unwrap_err().is_cancelled());
        for mut stream in streams {
            match stream.read(&mut [0]).await {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                result => panic!("proxy abort must close every stream: {result:?}"),
            }
        }
    })
    .await
    .expect("proxy reconnect and stream cleanup deadline");
    echo.abort();
    assert!(echo.await.unwrap_err().is_cancelled());
}

fn websocket_url(address: SocketAddr) -> String {
    format!("ws://{address}/fips")
}

fn available_websocket_url() -> String {
    websocket_url(available_websocket_address())
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

async fn wait_for_either_rekey_drain(first: (&FipsEndpoint, &str), second: (&FipsEndpoint, &str)) {
    // Initial authentication applies the production 30-second anti-churn
    // dampening window. With the production +/-30-second timer jitter, 65
    // seconds deterministically covers the first scheduled rekey without a
    // test-only control path.
    tokio::time::timeout(Duration::from_secs(65), async {
        loop {
            let first_draining = first
                .0
                .peers()
                .await
                .expect("first peer snapshot")
                .iter()
                .any(|peer| peer.npub == first.1 && peer.rekey_draining);
            let second_draining = second
                .0
                .peers()
                .await
                .expect("second peer snapshot")
                .iter()
                .any(|peer| peer.npub == second.1 && peer.rekey_draining);
            if first_draining || second_draining {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("neither peer entered rekey drain");
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

async fn assert_bidirectional_routed_delivery(
    seed_one: (&str, &str),
    seed_two: (&str, &str),
    payload_one: Vec<u8>,
    payload_two: Vec<u8>,
) {
    let (client_one, client_two) = tokio::join!(
        bind_endpoint(websocket_config(None, Some(seed_one))),
        bind_endpoint(websocket_config(None, Some(seed_two))),
    );
    tokio::join!(
        wait_for_exact_seed(&client_one, seed_one.0),
        wait_for_exact_seed(&client_two, seed_two.0),
    );
    let client_one_npub = client_one.npub().to_string();
    let client_two_npub = client_two.npub().to_string();
    let receiver_one = client_one
        .register_service_receiver(SERVICE_PORT)
        .await
        .expect("register first routed service");
    let receiver_two = client_two
        .register_service_receiver(SERVICE_PORT)
        .await
        .expect("register second routed service");
    client_one
        .send_datagram(
            PeerIdentity::from_npub(&client_two_npub).expect("second client identity"),
            SOURCE_PORT,
            SERVICE_PORT,
            payload_one.clone(),
        )
        .await
        .expect("send first routed datagram");
    client_two
        .send_datagram(
            PeerIdentity::from_npub(&client_one_npub).expect("first client identity"),
            SOURCE_PORT,
            SERVICE_PORT,
            payload_two.clone(),
        )
        .await
        .expect("send second routed datagram");
    tokio::join!(
        receive_payload(&receiver_two, &client_one_npub, &payload_one),
        receive_payload(&receiver_one, &client_two_npub, &payload_two),
    );
    let (first_shutdown, second_shutdown) =
        tokio::join!(client_one.shutdown(), client_two.shutdown());
    first_shutdown.expect("first client shutdown");
    second_shutdown.expect("second client shutdown");
}

#[tokio::test]
async fn configured_websocket_seed_authenticates_after_tcp_reset() {
    let seed_address = available_websocket_address();
    let seed_url = websocket_url(seed_address);
    let seed_identity = Identity::generate();
    let seed_npub = seed_identity.npub();
    let reset_listener = tokio::net::TcpListener::bind(seed_address)
        .await
        .expect("bind resetting TCP listener");
    let (reset_sent_tx, reset_sent_rx) = oneshot::channel();
    let reset_task = tokio::spawn(async move {
        let (stream, _) = reset_listener
            .accept()
            .await
            .expect("accept configured WebSocket seed connection");
        let stream = stream.into_std().expect("convert reset stream");
        SockRef::from(&stream)
            .set_linger(Some(Duration::ZERO))
            .expect("configure TCP reset on close");
        drop(stream);
        reset_sent_tx.send(()).expect("report TCP reset");
    });

    let client = bind_endpoint(websocket_config(None, Some((&seed_npub, &seed_url)))).await;
    tokio::time::timeout(CONNECT_TIMEOUT, reset_sent_rx)
        .await
        .expect("client did not reach resetting TCP listener")
        .expect("reset listener stopped without reporting TCP reset");
    reset_task.await.expect("reset listener task");
    assert!(
        client
            .peers()
            .await
            .expect("client peer snapshot after TCP reset")
            .iter()
            .all(|peer| !peer.connected),
        "client unexpectedly authenticated through the resetting listener"
    );

    let seed = bind_endpoint(with_identity(
        websocket_config(Some(&seed_url), None),
        &seed_identity,
    ))
    .await;
    tokio::join!(
        wait_for_adjacency(&client, &seed_npub),
        wait_for_adjacency(&seed, client.npub()),
    );

    client.shutdown().await.expect("client shutdown");
    seed.shutdown().await.expect("seed shutdown");
}

#[tokio::test]
async fn configured_websocket_seed_reauthenticates_after_proxy_outage() {
    let seed_one_address = available_websocket_address();
    let seed_one_url = websocket_url(seed_one_address);
    let proxy_address = available_websocket_address();
    let proxy_url = websocket_url(proxy_address);
    let seed_two_url = available_websocket_url();
    let seed_one_identity = Identity::generate();
    let seed_one_npub = seed_one_identity.npub();
    let seed_two_identity = Identity::generate();
    let seed_two_npub = seed_two_identity.npub();

    let mut seed_one_config = with_identity(
        websocket_config(Some(&seed_one_url), None),
        &seed_one_identity,
    );
    seed_one_config.node.heartbeat_interval_secs = 1;
    seed_one_config.node.link_dead_timeout_secs = 3;
    seed_one_config.node.rekey.after_secs = 0;
    seed_one_config
        .peers
        .push(configured_listener_peer(&seed_two_npub, &seed_two_url));
    let seed_one = bind_endpoint(seed_one_config).await;
    let proxy = start_proxy(proxy_address, seed_one_address).await;

    let mut seed_two_config = with_identity(
        websocket_config(Some(&seed_two_url), Some((&seed_one_npub, &proxy_url))),
        &seed_two_identity,
    );
    seed_two_config.node.heartbeat_interval_secs = 1;
    seed_two_config.node.link_dead_timeout_secs = 3;
    seed_two_config.node.rekey.after_secs = 0;
    let seed_two = bind_endpoint(seed_two_config).await;
    tokio::join!(
        wait_for_adjacency(&seed_one, &seed_two_npub),
        wait_for_adjacency(&seed_two, &seed_one_npub),
    );
    wait_for_either_rekey_drain((&seed_one, &seed_two_npub), (&seed_two, &seed_one_npub)).await;

    assert!(!proxy.is_finished(), "proxy ended before the forced outage");
    proxy.abort();
    assert!(proxy.await.expect_err("proxy abort").is_cancelled());
    // Let multiple physical reconnect attempts fail, then restore the proxy
    // before logical FIPS liveness declares the old authenticated link dead.
    // This is the production ordering that previously left a fresh WSS stream
    // underneath a permanently stale FIPS adjacency.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let replacement_proxy = start_proxy(proxy_address, seed_one_address).await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(
        !replacement_proxy.is_finished(),
        "replacement proxy stopped accepting reconnects"
    );
    tokio::join!(
        wait_for_adjacency(&seed_one, &seed_two_npub),
        wait_for_adjacency(&seed_two, &seed_one_npub),
    );

    assert_bidirectional_routed_delivery(
        (&seed_one_npub, &seed_one_url),
        (&seed_two_npub, &seed_two_url),
        b"post-proxy-one-to-two".to_vec(),
        b"post-proxy-two-to-one".to_vec(),
    )
    .await;

    seed_two.shutdown().await.expect("second seed shutdown");
    seed_one.shutdown().await.expect("first seed shutdown");
    assert!(
        !replacement_proxy.is_finished(),
        "replacement proxy exited during recovery"
    );
    replacement_proxy.abort();
    assert!(
        replacement_proxy
            .await
            .expect_err("replacement proxy abort")
            .is_cancelled()
    );
}

#[tokio::test]
async fn closed_websocket_client_leaves_seed_roster_promptly() {
    let seed_url = available_websocket_url();
    let seed_identity = Identity::generate();
    let seed_npub = seed_identity.npub();
    let seed = bind_endpoint(with_identity(
        websocket_config(Some(&seed_url), None),
        &seed_identity,
    ))
    .await;
    let client = bind_endpoint(websocket_config(None, Some((&seed_npub, &seed_url)))).await;
    let client_npub = client.npub().to_string();

    tokio::join!(
        wait_for_exact_seed(&client, &seed_npub),
        wait_for_adjacency(&seed, &client_npub),
    );
    client.shutdown().await.expect("client shutdown");

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if seed
                .peers()
                .await
                .expect("seed peer snapshot")
                .iter()
                .all(|peer| peer.npub != client_npub)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("closed WebSocket client lingered in seed routing roster");

    seed.shutdown().await.expect("seed shutdown");
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
    let mut seed_two = bind_endpoint(with_identity(
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

    // Replace the dialing seed while the listener side is serving unrelated
    // clients. The replacement retains the same identity and configured
    // adjacency: it must reconnect through the one canonical physical dial
    // before fresh route-by-npub clients start churning.
    seed_two.shutdown().await.expect("second seed shutdown");
    seed_two = bind_endpoint(with_identity(
        websocket_config(Some(&seed_two_url), Some((&seed_one_npub, &seed_one_url))),
        &seed_two_identity,
    ))
    .await;
    tokio::join!(
        wait_for_adjacency(&seed_one, &seed_two_npub),
        wait_for_adjacency(&seed_two, &seed_one_npub),
    );

    for round in 0..CHURN_ROUNDS {
        let payload_one = format!("one-to-two-{round}").into_bytes();
        let payload_two = format!("two-to-one-{round}").into_bytes();
        assert_bidirectional_routed_delivery(
            (&seed_one_npub, &seed_one_url),
            (&seed_two_npub, &seed_two_url),
            payload_one,
            payload_two,
        )
        .await;
    }

    for client in busy_seed_clients {
        client.shutdown().await.expect("busy-seed client shutdown");
    }
    let (first_shutdown, second_shutdown) = tokio::join!(seed_one.shutdown(), seed_two.shutdown());
    first_shutdown.expect("first seed shutdown");
    second_shutdown.expect("second seed shutdown");
}
