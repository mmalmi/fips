//! Native path replacement, independent of payment control and application ACKs.
#![cfg(unix)]
use fips_core::config::{ConnectPolicy, PeerConfig, TransportInstances};
use fips_core::{Config, FipsEndpoint, Identity, PeerIdentity, UdpConfig};
use std::{net::SocketAddr, path::Path, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

async fn control(root: &Path, index: usize, request: serde_json::Value) -> serde_json::Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut socket = tokio::net::UnixStream::connect(root.join(format!("{index}.sock")))
            .await
            .unwrap();
        let mut bytes = serde_json::to_vec(&request).unwrap();
        bytes.push(b'\n');
        socket.write_all(&bytes).await.unwrap();
        let mut line = String::new();
        BufReader::new(socket).read_line(&mut line).await.unwrap();
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["status"], "ok", "{value}");
        value["data"].clone()
    })
    .await
    .unwrap()
}

async fn configure(nodes: &[FipsEndpoint], addresses: &[SocketAddr], edges: &[(usize, usize)]) {
    for (i, node) in nodes.iter().enumerate() {
        node.update_peers(
            nodes
                .iter()
                .enumerate()
                .filter(|(j, _)| edges.contains(&(i, *j)) || edges.contains(&(*j, i)))
                .map(|(j, n)| {
                    let mut p = PeerConfig::new(n.npub(), "udp", addresses[j].to_string());
                    if (i == 1 && j == 3) || (i == 3 && j == 1) {
                        p.connect_policy = ConnectPolicy::Manual;
                    }
                    p
                })
                .collect(),
        )
        .await
        .unwrap();
    }
}

async fn resolved(
    nodes: &[FipsEndpoint],
    identities: &[PeerIdentity],
    expected: [usize; 2],
) -> bool {
    // An authenticated peer may retain full-key parity while npub contains
    // only the x-coordinate. Compare the canonical public identity.
    for (source, destination, previous, next) in [(1, 4, 0, expected[0]), (3, 0, 4, expected[1])] {
        if nodes[source]
            .resolve_next_hop(
                identities[destination],
                Some(*identities[previous].node_addr()),
            )
            .await
            .unwrap()
            .map(|p| p.pubkey())
            != Some(identities[next].pubkey())
        {
            return false;
        }
    }
    true
}

async fn diagnostics(root: &Path, nodes: &[FipsEndpoint]) {
    let mut items = Vec::new();
    for (i, _) in nodes.iter().enumerate() {
        let mut item = serde_json::json!({"node":i});
        for query in [
            "show_peers",
            "show_tree",
            "show_cache",
            "show_routing",
            "show_bloom",
        ] {
            item[query] = control(root, i, serde_json::json!({"command":query})).await;
        }
        items.push(item);
    }
    eprintln!(
        "native route recovery: {}",
        serde_json::to_string(&items).unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_the_middle_root_recovers_transit_routes() {
    let root = tempfile::tempdir().unwrap();
    let mut keys: Vec<_> = (0..5).map(|_| Identity::generate()).collect();
    keys.sort_by_key(|i| *i.node_addr());
    keys.swap(0, 2); // Remove the smallest identity, which is the initial root.
    let mut nodes = Vec::new();
    let mut addresses = Vec::new();
    let mut identities = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        let mut config = Config::new();
        config.node.identity.nsec = Some(fips_core::encode_nsec(&key.keypair().secret_key()));
        config.node.control.socket_path = root
            .path()
            .join(format!("{i}.sock"))
            .to_str()
            .unwrap()
            .into();
        config.node.discovery.lan.enabled = false;
        config.node.discovery.local.enabled = false;
        config.node.discovery.nostr.enabled = false;
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some("127.0.0.1:0".into()),
            ..UdpConfig::default()
        });
        let node = FipsEndpoint::builder()
            .config(config)
            .without_system_tun()
            .bind()
            .await
            .unwrap();
        addresses.push(node.bound_udp_listen_addrs().await.unwrap()[0]);
        identities.push(PeerIdentity::from_npub(node.npub()).unwrap());
        nodes.push(node);
    }
    configure(&nodes, &addresses, &[(0, 1), (1, 2), (2, 3), (3, 4)]).await;
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
            if connected == 8 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("initial adjacencies");
    let initially_routed = tokio::time::timeout(Duration::from_secs(20), async {
        while !resolved(&nodes, &identities, [2, 2]).await {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .is_ok();
    if !initially_routed {
        diagnostics(root.path(), &nodes).await;
    }
    assert!(initially_routed, "initial transit routes");
    configure(&nodes, &addresses, &[(0, 1), (1, 3), (3, 4)]).await;
    for neighbor in [1, 3] {
        control(root.path(), 2, serde_json::json!({"command":"disconnect","params":{"npub":identities[neighbor].npub()}})).await;
    }
    control(
        root.path(),
        1,
        serde_json::json!({"command":"connect","params":{
            "npub":identities[3].npub(),"address":addresses[3].to_string(),"transport":"udp"
        }}),
    )
    .await;
    let recovered = tokio::time::timeout(Duration::from_secs(35), async {
        while !resolved(&nodes, &identities, [3, 1]).await {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .is_ok();
    if !recovered {
        diagnostics(root.path(), &nodes).await;
    }
    for node in &nodes {
        node.shutdown().await.unwrap();
    }
    assert!(
        recovered,
        "connected replacement path must rediscover transit routes"
    );
}
