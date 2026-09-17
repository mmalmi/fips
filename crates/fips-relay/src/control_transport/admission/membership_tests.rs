use super::*;
use fips_core::{
    Config,
    config::{PeerConfig, TransportInstances, UdpConfig},
};

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

async fn attach(entry: &Arc<FipsEndpoint>) -> Arc<FipsEndpoint> {
    let mut config = config();
    let address = entry.bound_udp_listen_addrs().await.unwrap()[0];
    config
        .peers
        .push(PeerConfig::new(entry.npub(), "udp", address.to_string()));
    Arc::new(
        FipsEndpoint::builder()
            .config(config)
            .identity_nsec("42".repeat(32))
            .without_system_tun()
            .bind()
            .await
            .unwrap(),
    )
}

async fn connected(entry: &FipsEndpoint, peer: PeerIdentity, expected: bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let active = entry
                .peers()
                .await
                .unwrap()
                .iter()
                .any(|p| p.connected && p.node_addr == *peer.node_addr());
            if active == expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn existing_permits_recheck_adjacency_and_reconnect_keeps_identity_budgets() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let entry = Arc::new(
            FipsEndpoint::builder()
                .config(config())
                .without_system_tun()
                .bind()
                .await
                .unwrap(),
        );
        let remote = attach(&entry).await;
        let peer = PeerIdentity::from_npub(remote.npub()).unwrap();
        connected(&entry, peer, true).await;
        let admission = ControlAdmission::new(
            entry.clone(),
            vec![],
            None,
            NeighborAdmission::AuthenticatedAdjacent,
        )
        .unwrap();
        let incoming = admission.admit(peer, false).await.unwrap();
        let queued = admission.admit(peer, true).await.unwrap();
        incoming.recheck().await.unwrap();
        queued.recheck().await.unwrap();
        assert_eq!(admission.unconfigured.available_permits(), 6);
        remote.shutdown().await.unwrap();
        connected(&entry, peer, false).await;
        // These are the same guards invoked before an unsent connection and
        // before dispatching a fully received record to the financial handler.
        assert!(incoming.recheck().await.is_err());
        assert!(queued.recheck().await.is_err());
        let replacement = attach(&entry).await;
        assert_eq!(replacement.npub(), remote.npub());
        connected(&entry, peer, true).await;
        incoming.recheck().await.unwrap();
        queued.recheck().await.unwrap();
        {
            let state = admission.state.lock().unwrap();
            assert_eq!(state.peers.len(), 1);
            let saved = &state.peers[peer.node_addr()];
            assert_eq!(saved.incoming.tokens, ADMISSION_BURST - 1);
            assert_eq!(saved.outgoing.tokens, ADMISSION_BURST - 1);
            assert_eq!(saved.active, 2);
        }
        drop((incoming, queued));
        assert_eq!(admission.unconfigured.available_permits(), 8);
        assert_eq!(
            admission.state.lock().unwrap().peers[peer.node_addr()].active,
            0
        );
        replacement.shutdown().await.unwrap();
        entry.shutdown().await.unwrap();
    })
    .await
    .expect("admission reconnect deadline");
}
