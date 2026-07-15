use super::*;
use crate::config::RoutingMode;
use crate::discovery::local::{
    LocalInstanceAdvertisement, LocalInstanceCapability, select_capability_provider,
};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

const SERVICE_CAPABILITY: &str = "hashtree.blob/1";
const SERVICE_PORT: u16 = 39_019;
const CONSUMER_PORT: u16 = 49_019;
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(20);

fn reserve_rendezvous_addr() -> SocketAddrV4 {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve loopback UDP port");
    let SocketAddr::V4(addr) = socket.local_addr().expect("reserved loopback UDP address") else {
        panic!("IPv4 loopback bind returned an IPv6 address");
    };
    drop(socket);
    addr
}

fn local_config(rendezvous_addr: SocketAddrV4) -> Config {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.node.discovery.local.enabled = true;
    config.node.discovery.local.rendezvous_addr = rendezvous_addr;
    config.node.discovery.local.retry_interval_ms = 20;
    config.node.discovery.lan.enabled = false;
    config.node.discovery.nostr.enabled = false;
    config
}

async fn bind_local(rendezvous_addr: SocketAddrV4) -> FipsEndpoint {
    FipsEndpoint::builder()
        .config(local_config(rendezvous_addr))
        .local_rendezvous()
        .without_system_tun()
        .bind()
        .await
        .expect("bind local FIPS endpoint")
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

async fn wait_for_capability(
    endpoint: &FipsEndpoint,
    name: &str,
    expected_npub: &str,
) -> LocalInstanceAdvertisement {
    tokio::time::timeout(CONVERGENCE_TIMEOUT, async {
        loop {
            let adverts = endpoint
                .local_instance_advertisements()
                .expect("local capability snapshot");
            if let Some(selected) = select_capability_provider(&adverts, name)
                && selected.npub == expected_npub
            {
                break selected.clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("local capability {name} did not appear"))
}

async fn wait_for_capability_removal(endpoint: &FipsEndpoint, name: &str) {
    tokio::time::timeout(CONVERGENCE_TIMEOUT, async {
        loop {
            let adverts = endpoint
                .local_instance_advertisements()
                .expect("local capability snapshot");
            if select_capability_provider(&adverts, name).is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("local capability {name} was not withdrawn"));
}

async fn receive_service_datagram(
    receiver: &FipsEndpointServiceReceiver,
    expected: &[u8],
) -> FipsEndpointServiceDatagram {
    tokio::time::timeout(CONVERGENCE_TIMEOUT, async {
        loop {
            let mut datagrams = Vec::new();
            receiver
                .recv_batch_into(&mut datagrams, 8)
                .await
                .unwrap_or_else(|| panic!("service receiver closed before {expected:?}"));
            if let Some(datagram) = datagrams
                .into_iter()
                .find(|datagram| datagram.data.as_slice() == expected)
            {
                break datagram;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {expected:?}"))
}

fn assert_loopback_udp(peer: &FipsEndpointPeer) {
    assert_eq!(peer.transport_type.as_deref(), Some("udp"));
    let addr = peer
        .transport_addr
        .as_deref()
        .expect("authenticated peer transport address")
        .parse::<SocketAddr>()
        .expect("UDP transport address");
    assert!(addr.ip().is_loopback());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_loopback_rendezvous_authenticates_capabilities_and_survives_anchor_exit() {
    let rendezvous_addr = reserve_rendezvous_addr();

    // The first exclusive binder is only a rendezvous anchor. Its lower
    // service priority must not affect ownership of the fixed socket.
    let anchor = bind_local(rendezvous_addr).await;
    let anchor_npub = anchor.npub().to_string();
    let _anchor_service = anchor
        .register_service_receiver_with_capability(
            LocalInstanceCapability::service(SERVICE_CAPABILITY, SERVICE_PORT).with_priority(1),
        )
        .await
        .expect("register anchor service capability");

    let provider = bind_local(rendezvous_addr).await;
    let provider_npub = provider.npub().to_string();
    let provider_service = provider
        .register_service_receiver_with_capability(
            LocalInstanceCapability::service(SERVICE_CAPABILITY, SERVICE_PORT).with_priority(10),
        )
        .await
        .expect("register preferred service capability");

    let consumer = bind_local(rendezvous_addr).await;
    let consumer_npub = consumer.npub().to_string();

    assert_loopback_udp(&wait_for_connected_peer(&provider, &anchor_npub).await);
    assert_loopback_udp(&wait_for_connected_peer(&consumer, &anchor_npub).await);
    assert_loopback_udp(&wait_for_connected_peer(&anchor, &provider_npub).await);
    assert_loopback_udp(&wait_for_connected_peer(&anchor, &consumer_npub).await);
    assert!(
        consumer
            .peers()
            .await
            .expect("consumer peer snapshot")
            .iter()
            .all(|peer| peer.npub != provider_npub || !peer.connected),
        "clients should initially use the authenticated rendezvous star"
    );

    let selected = wait_for_capability(&consumer, SERVICE_CAPABILITY, &provider_npub).await;
    assert_eq!(selected.npub, provider_npub);
    let capability = selected
        .capability(SERVICE_CAPABILITY)
        .expect("selected service capability");
    assert_eq!(capability.priority, 10);
    assert_eq!(capability.fsp_port, Some(SERVICE_PORT));

    consumer
        .send_datagram(
            PeerIdentity::from_npub(&provider_npub).expect("provider identity"),
            CONSUMER_PORT,
            SERVICE_PORT,
            b"through-anchor".to_vec(),
        )
        .await
        .expect("send through authenticated rendezvous star");
    let request = receive_service_datagram(&provider_service, b"through-anchor").await;
    assert_eq!(request.source_peer.npub(), consumer_npub);
    assert_eq!(request.data.as_slice(), b"through-anchor");

    // Releasing the exclusive bind lets either survivor become the next
    // anchor. They must authenticate again with ordinary Noise IK, then
    // rebuild the same FSP capability directory.
    anchor.shutdown().await.expect("anchor shutdown");
    assert_loopback_udp(&wait_for_connected_peer(&consumer, &provider_npub).await);
    assert_eq!(
        wait_for_capability(&consumer, SERVICE_CAPABILITY, &provider_npub)
            .await
            .npub,
        provider_npub
    );

    consumer
        .send_datagram(
            PeerIdentity::from_npub(&provider_npub).expect("provider identity"),
            CONSUMER_PORT,
            SERVICE_PORT,
            b"after-anchor-exit".to_vec(),
        )
        .await
        .expect("send after rendezvous failover");
    let request = receive_service_datagram(&provider_service, b"after-anchor-exit").await;
    assert_eq!(request.source_peer.npub(), consumer_npub);
    assert_eq!(request.data.as_slice(), b"after-anchor-exit");

    provider.shutdown().await.expect("provider shutdown");
    wait_for_capability_removal(&consumer, SERVICE_CAPABILITY).await;
    consumer.shutdown().await.expect("consumer shutdown");
}
