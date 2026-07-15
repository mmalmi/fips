use super::*;
use crate::config::{PeerConfig, RoutingMode, TcpConfig, TransportInstances, UdpConfig};
use crate::discovery::local::{LocalInstanceAdvertisement, select_capability_provider};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;

const LOCAL_SCOPE: &str = "iris-local-egress-v1";
const EGRESS_CAPABILITY: &str = "fips.egress/1";
const REMOTE_SERVICE_PORT: u16 = 39_019;
const CONSUMER_REPLY_PORT: u16 = 49_019;
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(30);

fn reserve_loopback_tcp_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve TCP listener address");
    let addr = listener
        .local_addr()
        .expect("reserved TCP listener address");
    drop(listener);
    addr
}

fn local_udp_config(registry_dir: &Path) -> Config {
    let mut config = Config::new();
    // The consumer intentionally has no remote coordinates. Reply-learned
    // routing discovers the first end-to-end session through its local peer.
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.node.discovery.local.dir = Some(registry_dir.display().to_string());
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        advertise_on_nostr: Some(false),
        public: Some(false),
        ..UdpConfig::default()
    });
    config
}

async fn wait_for_connected_peer(endpoint: &FipsEndpoint, npub: &str) -> FipsEndpointPeer {
    tokio::time::timeout(CONVERGENCE_TIMEOUT, async {
        loop {
            if let Some(peer) = endpoint
                .peers()
                .await
                .expect("peer snapshot")
                .into_iter()
                .find(|peer| peer.npub == npub && peer.connected)
            {
                break peer;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("endpoint did not authenticate {npub}"))
}

async fn wait_for_capability(endpoint: &FipsEndpoint, name: &str) -> LocalInstanceAdvertisement {
    tokio::time::timeout(CONVERGENCE_TIMEOUT, async {
        loop {
            let adverts = endpoint
                .local_instance_advertisements()
                .expect("local capability snapshot");
            if let Some(selected) = select_capability_provider(&adverts, name) {
                break selected.clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("local capability {name} did not appear"))
}

async fn receive_one_service_datagram(
    receiver: &FipsEndpointServiceReceiver,
    expected: &str,
) -> FipsEndpointServiceDatagram {
    let mut datagrams = Vec::new();
    tokio::time::timeout(
        CONVERGENCE_TIMEOUT,
        receiver.recv_batch_into(&mut datagrams, 8),
    )
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {expected}"))
    .unwrap_or_else(|| panic!("service receiver closed before {expected}"));
    assert_eq!(datagrams.len(), 1, "expected exactly one {expected}");
    datagrams.pop().expect("one service datagram")
}

fn assert_loopback_transport(peer: &FipsEndpointPeer, expected_transport: &str) {
    assert_eq!(peer.transport_type.as_deref(), Some(expected_transport));
    let addr = peer
        .transport_addr
        .as_deref()
        .expect("authenticated peer transport address")
        .parse::<SocketAddr>()
        .expect("socket transport address");
    assert!(addr.ip().is_loopback());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn local_consumer_reaches_remote_service_only_through_selected_egress_provider() {
    // Provider ranking/withdrawal has its own focused registry test. One
    // provider here keeps the asserted transport topology unambiguous.
    let registry = tempfile::tempdir().expect("temporary local instance registry");
    let remote_tcp_addr = reserve_loopback_tcp_addr();

    let mut remote_config = Config::new();
    // First contact also needs the responder to return the Noise session
    // handshake through its authenticated previous hop.
    remote_config.node.routing.mode = RoutingMode::ReplyLearned;
    remote_config.transports.tcp = TransportInstances::Single(TcpConfig {
        bind_addr: Some(remote_tcp_addr.to_string()),
        ..TcpConfig::default()
    });
    let remote = FipsEndpoint::builder()
        .config(remote_config)
        .without_system_tun()
        .bind()
        .await
        .expect("bind remote service endpoint");
    let remote_identity = PeerIdentity::from_npub(remote.npub()).expect("remote identity");
    let remote_service = remote
        .register_service_receiver(REMOTE_SERVICE_PORT)
        .await
        .expect("register remote FSP service");

    let mut provider_config = local_udp_config(registry.path());
    provider_config.transports.tcp = TransportInstances::Single(TcpConfig {
        bind_addr: None,
        connect_timeout_ms: Some(2_000),
        ..TcpConfig::default()
    });
    provider_config.peers.push(PeerConfig::new(
        remote.npub(),
        "tcp",
        remote_tcp_addr.to_string(),
    ));
    let provider = FipsEndpoint::builder()
        .config(provider_config)
        .discovery_scope(LOCAL_SCOPE)
        .local_role(EGRESS_CAPABILITY, 100)
        .without_system_tun()
        .bind()
        .await
        .expect("bind egress provider");
    let provider_npub = provider.npub().to_string();
    let remote_peer = wait_for_connected_peer(&provider, remote.npub()).await;
    assert_loopback_transport(&remote_peer, "tcp");

    let consumer_config = local_udp_config(registry.path());
    assert!(
        consumer_config.transports.tcp.is_empty(),
        "consumer must not own an external TCP transport"
    );
    assert!(
        consumer_config.peers.is_empty(),
        "consumer must not have a configured path to the remote"
    );
    let consumer = FipsEndpoint::builder()
        .config(consumer_config)
        .discovery_scope(LOCAL_SCOPE)
        .without_system_tun()
        .bind()
        .await
        .expect("bind local consumer");
    let consumer_reply = consumer
        .register_service_receiver(CONSUMER_REPLY_PORT)
        .await
        .expect("register consumer reply port");

    let selected = wait_for_capability(&consumer, EGRESS_CAPABILITY).await;
    assert_eq!(selected.instance.npub, provider_npub);
    let capability = selected
        .capability(EGRESS_CAPABILITY)
        .expect("selected egress capability");
    assert_eq!(capability.priority, 100);
    assert_eq!(capability.fsp_port, None);

    let provider_peer = wait_for_connected_peer(&consumer, &provider_npub).await;
    assert_loopback_transport(&provider_peer, "udp");
    assert!(
        consumer
            .peers()
            .await
            .expect("consumer peer snapshot")
            .iter()
            .all(|peer| peer.npub != remote.npub()),
        "consumer must not establish a direct link to the remote"
    );

    consumer
        .send_datagram(
            remote_identity,
            CONSUMER_REPLY_PORT,
            REMOTE_SERVICE_PORT,
            b"through-egress".to_vec(),
        )
        .await
        .expect("queue routed service request");
    let request = receive_one_service_datagram(&remote_service, "routed request").await;
    assert_eq!(request.source_peer.npub(), consumer.npub());
    assert_eq!(request.source_port, CONSUMER_REPLY_PORT);
    assert_eq!(request.destination_port, REMOTE_SERVICE_PORT);
    assert_eq!(request.data.as_slice(), b"through-egress");

    remote
        .send_datagram(
            request.source_peer,
            REMOTE_SERVICE_PORT,
            request.source_port,
            b"through-egress-reply".to_vec(),
        )
        .await
        .expect("queue routed service response");
    let response = receive_one_service_datagram(&consumer_reply, "routed response").await;
    assert_eq!(response.source_peer.npub(), remote.npub());
    assert_eq!(response.source_port, REMOTE_SERVICE_PORT);
    assert_eq!(response.destination_port, CONSUMER_REPLY_PORT);
    assert_eq!(response.data.as_slice(), b"through-egress-reply");

    let consumer_peers = consumer.peers().await.expect("consumer peer snapshot");
    assert_eq!(
        consumer_peers
            .iter()
            .filter(|peer| peer.connected)
            .map(|peer| peer.npub.as_str())
            .collect::<Vec<_>>(),
        vec![provider_npub.as_str()],
        "consumer must retain only its authenticated local provider link"
    );
    assert_eq!(
        remote
            .peers()
            .await
            .expect("remote peer snapshot")
            .iter()
            .filter(|peer| peer.connected)
            .map(|peer| peer.npub.as_str())
            .collect::<Vec<_>>(),
        vec![provider_npub.as_str()],
        "provider must own the remote-facing link"
    );

    provider.shutdown().await.expect("provider shutdown");
    tokio::time::timeout(CONVERGENCE_TIMEOUT, async {
        loop {
            let adverts = consumer
                .local_instance_advertisements()
                .expect("local capability snapshot after provider shutdown");
            if select_capability_provider(&adverts, EGRESS_CAPABILITY).is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("provider shutdown must withdraw its egress advert");

    consumer.shutdown().await.expect("consumer shutdown");
    remote.shutdown().await.expect("remote shutdown");
}
