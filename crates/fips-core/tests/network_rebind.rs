use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use fips_core::config::{NostrDiscoveryPolicy, PeerConfig, RoutingMode, TransportInstances};
use fips_core::{Config, FipsEndpoint, Identity, PeerIdentity, UdpConfig, encode_nsec};
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROL_PROGRESS_TIMEOUT: Duration = Duration::from_millis(250);
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(2);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_port_dual_family_udp_authenticates_and_delivers_over_both_families() {
    let port = available_udp_port();
    let server_identity = Identity::generate();
    let mut server_config = dual_family_config(port);
    server_config.node.identity.nsec = Some(encode_nsec(&server_identity.keypair().secret_key()));
    let server = bind_endpoint(server_config).await;

    for (target, ipv6) in [
        (format!("127.0.0.1:{port}"), false),
        (format!("[::1]:{port}"), true),
    ] {
        let mut client_config = dual_family_config(0);
        client_config
            .peers
            .push(PeerConfig::new(server.npub(), "udp", target));
        let client = bind_endpoint(client_config).await;

        wait_for_connected_peer(&client, server.npub()).await;
        wait_for_connected_peer(&server, client.npub()).await;
        assert_peer_family(&client, server.npub(), ipv6).await;
        assert_peer_family(&server, client.npub(), ipv6).await;
        assert_delivery(&client, &server, if ipv6 { b"IPv6" } else { b"IPv4" }).await;
        assert_delivery(
            &server,
            &client,
            if ipv6 { b"IPv6 reply" } else { b"IPv4 reply" },
        )
        .await;

        client.shutdown().await.expect("client endpoint shutdown");
    }

    server.shutdown().await.expect("server endpoint shutdown");
}

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos"
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_network_rebind_keeps_live_carrier_and_node_control_progress() {
    let rendezvous = rendezvous_addr();
    let first = endpoint(rendezvous, "transactional-network-rebind").await;
    let second = endpoint(rendezvous, "transactional-network-rebind").await;

    wait_for_connected_peer(&first, second.npub()).await;
    wait_for_connected_peer(&second, first.npub()).await;
    assert_delivery(&first, &second, b"before failed rebind").await;

    let rebind = {
        let first = Arc::clone(&first);
        tokio::spawn(async move {
            first
                .rebind_network_transports(Some("fips-no-such0".to_string()))
                .await
        })
    };

    tokio::time::sleep(Duration::from_millis(25)).await;
    let peers = timeout(CONTROL_PROGRESS_TIMEOUT, first.peers())
        .await
        .expect("network rebind preparation must not block the node RX loop")
        .expect("peer snapshot while rebind preparation is pending");
    assert!(
        peers
            .iter()
            .any(|peer| peer.npub == second.npub() && peer.connected),
        "the live peer/session must remain intact while replacement preparation runs"
    );

    let error = timeout(Duration::from_secs(4), rebind)
        .await
        .expect("failed rebind should finish within its bounded retry window")
        .expect("rebind task")
        .expect_err("a nonexistent interface must reject the rebind");
    assert!(
        error.to_string().contains("fips-no-such0"),
        "rebind failure should identify the rejected interface: {error}"
    );

    let peers = first
        .peers()
        .await
        .expect("peer snapshot after failed rebind");
    assert!(
        peers
            .iter()
            .any(|peer| peer.npub == second.npub() && peer.connected),
        "prepare failure must not leave a stale peer referencing a destroyed carrier"
    );
    assert_delivery(&first, &second, b"after failed rebind").await;

    let rebound = first
        .rebind_network_transports(None)
        .await
        .expect("a valid rebind must succeed after rejected preparation");
    assert!(rebound >= 1, "the live UDP carrier should be replaced");
    assert_delivery(&first, &second, b"after valid rebind").await;

    second.shutdown().await.expect("second endpoint shutdown");
    first.shutdown().await.expect("first endpoint shutdown");
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn windows_named_interface_rebinds_wildcard_udp_and_keeps_payload_flowing() {
    let rendezvous = rendezvous_addr();
    let first = endpoint(rendezvous, "windows-wildcard-network-rebind").await;
    let second = endpoint(rendezvous, "windows-wildcard-network-rebind").await;

    wait_for_connected_peer(&first, second.npub()).await;
    wait_for_connected_peer(&second, first.npub()).await;
    assert_delivery(&first, &second, b"before Windows rebind").await;

    let rebound = first
        .rebind_network_transports(Some("Ethernet".to_string()))
        .await
        .expect("Windows rebind should rebuild wildcard UDP without interface binding");
    assert!(rebound >= 1, "the live UDP carrier should be replaced");
    assert_delivery(&first, &second, b"after Windows rebind").await;

    second.shutdown().await.expect("second endpoint shutdown");
    first.shutdown().await.expect("first endpoint shutdown");
}

async fn endpoint(rendezvous_addr: SocketAddrV4, discovery_scope: &str) -> Arc<FipsEndpoint> {
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.lan.enabled = false;
    config.node.discovery.local.rendezvous_addr = rendezvous_addr;
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        advertise_on_nostr: Some(false),
        public: Some(false),
        ..UdpConfig::default()
    });
    Arc::new(
        FipsEndpoint::builder()
            .config(config)
            .discovery_scope(discovery_scope)
            .local_rendezvous()
            .without_system_tun()
            .bind()
            .await
            .expect("local endpoint"),
    )
}

fn dual_family_config(port: u16) -> Config {
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::Open;
    config.node.discovery.lan.enabled = false;
    config.node.routing.mode = RoutingMode::ReplyLearned;
    let udp = |bind_addr| UdpConfig {
        bind_addr: Some(bind_addr),
        advertise_on_nostr: Some(false),
        public: Some(false),
        ..UdpConfig::default()
    };
    config.transports.udp = TransportInstances::Named(HashMap::from([
        ("ipv4".to_string(), udp(format!("0.0.0.0:{port}"))),
        ("ipv6".to_string(), udp(format!("[::]:{port}"))),
    ]));
    config
}

async fn bind_endpoint(config: Config) -> Arc<FipsEndpoint> {
    Arc::new(
        FipsEndpoint::builder()
            .config(config)
            .without_system_tun()
            .bind()
            .await
            .expect("dual-family endpoint bind"),
    )
}

async fn assert_peer_family(endpoint: &FipsEndpoint, npub: &str, ipv6: bool) {
    let peer = endpoint
        .peers()
        .await
        .expect("peer snapshot")
        .into_iter()
        .find(|peer| peer.npub == npub && peer.connected)
        .expect("connected peer");
    let addr = peer
        .transport_addr
        .expect("authenticated UDP transport address")
        .parse::<SocketAddr>()
        .expect("socket transport address");
    assert_eq!(addr.is_ipv6(), ipv6, "peer used the wrong UDP family");
}

fn available_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("ephemeral UDP port");
    socket.local_addr().expect("ephemeral UDP address").port()
}

async fn wait_for_connected_peer(endpoint: &FipsEndpoint, npub: &str) {
    timeout(CONNECT_TIMEOUT, async {
        loop {
            if endpoint
                .peers()
                .await
                .expect("peer snapshot")
                .iter()
                .any(|peer| peer.npub == npub && peer.connected)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("authenticated local peer connection");
}

async fn assert_delivery(sender: &FipsEndpoint, receiver: &FipsEndpoint, payload: &[u8]) {
    let receiver_identity =
        PeerIdentity::from_npub(receiver.npub()).expect("receiver peer identity");
    sender
        .send_batch_to_peer(receiver_identity, vec![payload.to_vec()])
        .await
        .expect("enqueue endpoint payload");

    let mut received = Vec::new();
    timeout(DELIVERY_TIMEOUT, receiver.recv_batch_into(&mut received, 1))
        .await
        .expect("endpoint payload delivery")
        .expect("receiver remains open");
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].source_peer.npub(), sender.npub());
    assert_eq!(received[0].data.as_slice(), payload);
}

fn rendezvous_addr() -> SocketAddrV4 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("ephemeral rendezvous socket");
    match socket.local_addr().expect("rendezvous address") {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(_) => unreachable!("IPv4 bind returned an IPv6 address"),
    }
}
