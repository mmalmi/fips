use super::*;
use crate::config::{PeerAddress, PeerConfig, RoutingMode};

async fn idle_endpoint(strict_client_only: bool) -> FipsEndpoint {
    let mut config = Config::new();
    config.node.strict_client_only = strict_client_only;
    config.node.control.enabled = false;
    config.node.discovery.local.enabled = false;
    config.node.discovery.lan.enabled = false;
    config.node.discovery.nostr.enabled = false;
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.node.heartbeat_interval_secs = 60;
    config.node.link_dead_timeout_secs = 180;
    config.node.tree.announce_refresh_interval_secs = 60;
    config.node.bloom.announce_refresh_interval_secs = 60;
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:0".into()),
        advertise_on_nostr: Some(false),
        accept_connections: Some(true),
        ..Default::default()
    });
    FipsEndpoint::builder()
        .config(config)
        .without_system_tun()
        .bind()
        .await
        .unwrap()
}

async fn peer(endpoint: &FipsEndpoint, npub: &str) -> FipsEndpointPeer {
    endpoint
        .peers()
        .await
        .unwrap()
        .into_iter()
        .find(|peer| peer.npub == npub && peer.connected)
        .expect("authenticated peer")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_link_reports_do_not_sustain_their_own_traffic() {
    idle_link(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_client_only_link_does_not_sustain_ancestry_repair() {
    idle_link(true).await;
}

async fn idle_link(strict_client_only: bool) {
    let first = idle_endpoint(strict_client_only).await;
    let second = idle_endpoint(false).await;
    first.register_service(44_010).await.unwrap();
    second.register_service(44_010).await.unwrap();
    let address = second.bound_udp_listen_addrs().await.unwrap()[0];
    first
        .update_peers(vec![PeerConfig {
            npub: second.npub().into(),
            addresses: vec![PeerAddress::new("udp", address.to_string())],
            ..Default::default()
        }])
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let routing = first.routing_status().await.unwrap();
            if first
                .peers()
                .await
                .unwrap()
                .iter()
                .any(|p| p.connected && p.npub == second.npub())
                && second
                    .peers()
                    .await
                    .unwrap()
                    .iter()
                    .any(|p| p.connected && p.npub == first.npub())
                && (!strict_client_only
                    || (routing.client_only && routing.peers_without_client_support == 0))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("link handshake");

    // Finish the initial handshake and measurement exchange, then observe an
    // otherwise idle authenticated link before its next liveness heartbeat.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let before = (
        peer(&first, second.npub()).await,
        peer(&second, first.npub()).await,
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    let after = (
        peer(&first, second.npub()).await,
        peer(&second, first.npub()).await,
    );
    let sent =
        after.0.packets_sent - before.0.packets_sent + after.1.packets_sent - before.1.packets_sent;
    first
        .send_datagram(
            PeerIdentity::from_npub(second.npub()).unwrap(),
            44_010,
            44_010,
            b"after idle".to_vec(),
        )
        .await
        .unwrap();
    let mut messages = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        second.recv_service_datagram_batch_into(&mut messages, 1),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(messages[0].data.as_slice(), b"after idle");
    second
        .send_datagram(
            PeerIdentity::from_npub(first.npub()).unwrap(),
            44_010,
            44_010,
            b"after idle reply".to_vec(),
        )
        .await
        .unwrap();
    messages.clear();
    tokio::time::timeout(
        Duration::from_secs(5),
        first.recv_service_datagram_batch_into(&mut messages, 1),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(messages[0].data.as_slice(), b"after idle reply");
    assert_eq!(before.0.link_id, after.0.link_id);
    assert_eq!(before.1.link_id, after.1.link_id);
    assert!(before.0.srtt_ms.is_some() && before.1.srtt_ms.is_some());
    first.shutdown().await.unwrap();
    second.shutdown().await.unwrap();
    assert_eq!(sent, 0, "idle reports must not trigger more reports");
}
