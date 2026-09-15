use fips_core::{
    Config, FipsEndpoint, PeerIdentity,
    config::{PeerConfig, TransportInstances, UdpConfig},
};
use fips_relay::control_transport::ControlTransport;
use std::{sync::Arc, time::Duration};

fn config() -> Config {
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = false;
    config.node.discovery.lan.enabled = false;
    config.node.discovery.local.enabled = false;
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:0".into()),
        advertise_on_nostr: Some(false),
        ..UdpConfig::default()
    });
    config
}

async fn pair() -> (Arc<FipsEndpoint>, Arc<FipsEndpoint>) {
    let a = Arc::new(
        FipsEndpoint::builder()
            .config(config())
            .without_system_tun()
            .bind()
            .await
            .unwrap(),
    );
    let addr = a.bound_udp_listen_addrs().await.unwrap()[0];
    let mut b_config = config();
    b_config
        .peers
        .push(PeerConfig::new(a.npub(), "udp", addr.to_string()));
    let b = Arc::new(
        FipsEndpoint::builder()
            .config(b_config)
            .without_system_tun()
            .bind()
            .await
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if b.peers()
                .await
                .unwrap()
                .iter()
                .any(|p| p.connected && p.npub == a.npub())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (a, b)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_neighbor_control_carries_large_records_and_isolates_rejections() {
    tokio::time::timeout(Duration::from_secs(40), async {
        let (a, b) = pair().await;
        let alice = PeerIdentity::from_npub(a.npub()).unwrap();
        let bob = PeerIdentity::from_npub(b.npub()).unwrap();
        let (first, mut first_incoming) = ControlTransport::start(a.clone(), 44_710, vec![bob], 1)
            .await
            .unwrap();
        let (second, mut second_incoming) =
            ControlTransport::start(b.clone(), 44_710, vec![alice], 2)
                .await
                .unwrap();
        let responder = tokio::spawn(async move {
            let request = second_incoming.recv().await.unwrap();
            assert_eq!(request.peer, alice);
            assert_eq!(request.body, vec![42; 24_000]);
            request.respond.send(vec![51; 20_000]).unwrap();
            // Dropping the next responder must release only its own stream.
            drop(second_incoming.recv().await.unwrap());
            let next = second_incoming.recv().await.unwrap();
            next.respond.send(b"recovered".to_vec()).unwrap();
        });
        let reply = first.request(bob, vec![42; 24_000]).await.unwrap();
        assert_eq!(reply, vec![51; 20_000]);
        assert!(first.request(bob, vec![0; 65_537]).await.is_err());
        assert!(first.request(bob, b"cancel".to_vec()).await.is_err());
        assert_eq!(
            first.request(bob, b"retry".to_vec()).await.unwrap(),
            b"recovered"
        );
        responder.await.unwrap();
        let reverse = tokio::spawn(async move {
            let request = first_incoming.recv().await.unwrap();
            assert_eq!(request.peer, bob);
            request.respond.send(b"reverse".to_vec()).unwrap();
        });
        assert_eq!(
            second.request(alice, b"back".to_vec()).await.unwrap(),
            b"reverse"
        );
        reverse.await.unwrap();
        drop(first);
        drop(second);
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    })
    .await
    .expect("control record deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_service_rejects_an_identity_outside_its_configured_neighbors() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (a, b) = pair().await;
        let alice = PeerIdentity::from_npub(a.npub()).unwrap();
        let (first, mut incoming) = ControlTransport::start(a.clone(), 44_711, vec![], 3)
            .await
            .unwrap();
        let (second, _unused) = ControlTransport::start(b.clone(), 44_711, vec![alice], 4)
            .await
            .unwrap();
        assert!(second.request(alice, b"uninvited".to_vec()).await.is_err());
        assert!(incoming.try_recv().is_err());
        assert!(
            first
                .request(alice, b"not-neighbor".to_vec())
                .await
                .is_err()
        );
        drop(first);
        drop(second);
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    })
    .await
    .expect("rejection deadline");
}
