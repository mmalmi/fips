use fips_core::config::{PeerConfig, TransportInstances};
use fips_core::{Config, FipsEndpoint, PeerIdentity, UdpConfig};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sparse_tree_mesh_keeps_idle_then_active_sessions_delivering() {
    let keys = [
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        "b102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fb0",
        "c102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fc0",
        "d102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fd0",
        "e102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fe0",
    ];
    let mut nodes = Vec::new();
    let mut receivers = Vec::new();
    let mut addresses = Vec::new();
    let edges = [(0, 3), (0, 4), (1, 2), (2, 3), (2, 4), (3, 4)];
    for key in keys {
        let mut config = Config::new();
        config.node.identity.nsec = Some(key.into());
        config.node.discovery.lan.enabled = false;
        config.node.discovery.local.enabled = false;
        config.node.discovery.nostr.enabled = false;
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some("127.0.0.1:0".into()),
            ..UdpConfig::default()
        });
        let endpoint = FipsEndpoint::builder()
            .config(config)
            .without_system_tun()
            .bind()
            .await
            .unwrap();
        addresses.push(endpoint.bound_udp_listen_addrs().await.unwrap()[0]);
        receivers.push(endpoint.register_service_receiver(44_000).await.unwrap());
        nodes.push(endpoint);
    }
    for (i, node) in nodes.iter().enumerate() {
        let peers = nodes
            .iter()
            .enumerate()
            .filter(|(j, _)| edges.contains(&(i, *j)) || edges.contains(&(*j, i)))
            .map(|(j, other)| PeerConfig::new(other.npub(), "udp", addresses[j].to_string()))
            .collect();
        node.update_peers(peers).await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut connected = 0;
            for node in &nodes {
                connected += node
                    .peers()
                    .await
                    .unwrap()
                    .iter()
                    .filter(|p| p.connected)
                    .count();
            }
            if connected == edges.len() * 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("mesh adjacencies");
    // Let the tree settle, then leave each data burst idle until the next report
    // period. Recovery must not mistake new sends for an already stalled path.
    let mut failed = Vec::new();
    for round in 0..3 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        for (i, source) in nodes.iter().enumerate() {
            for (j, destination) in nodes.iter().enumerate().filter(|(j, _)| *j != i) {
                let payload = vec![round, i as u8, j as u8];
                source
                    .send_datagram(
                        PeerIdentity::from_npub(destination.npub()).unwrap(),
                        44_001,
                        44_000,
                        payload.clone(),
                    )
                    .await
                    .unwrap();
                let result = tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        let mut batch = Vec::new();
                        receivers[j].recv_batch_into(&mut batch, 32).await.unwrap();
                        if batch.iter().any(|m| m.data.as_slice() == payload) {
                            break;
                        }
                    }
                })
                .await;
                if result.is_err() {
                    failed.push((round, i, j));
                }
            }
        }
    }
    for node in &nodes {
        node.shutdown().await.unwrap();
    }
    assert!(failed.is_empty(), "undelivered pairs: {failed:?}");
}
