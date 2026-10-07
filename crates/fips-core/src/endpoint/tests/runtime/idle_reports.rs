use super::*;
use crate::config::{PeerAddress, PeerConfig, RoutingMode};

async fn idle_endpoint() -> FipsEndpoint {
    let mut config = Config::new();
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
    let first = idle_endpoint().await;
    let second = idle_endpoint().await;
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
    first.shutdown().await.unwrap();
    second.shutdown().await.unwrap();
    assert_eq!(sent, 0, "idle reports must not trigger more reports");
}
