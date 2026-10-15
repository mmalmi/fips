#[cfg(test)]
mod tests {
    use std::time::Duration;
    enum Peer {
        Current(current::FipsEndpoint),
        Legacy(legacy::FipsEndpoint),
    }
    impl Peer {
        fn npub(&self) -> &str {
            match self {
                Self::Current(n) => n.npub(),
                Self::Legacy(n) => n.npub(),
            }
        }
        async fn address(&self) -> String {
            match self {
                Self::Current(n) => n.bound_udp_listen_addrs().await.unwrap()[0].to_string(),
                Self::Legacy(n) => n.bound_udp_listen_addrs().await.unwrap()[0].to_string(),
            }
        }
        async fn connect(&self, peers: &[(String, String)]) {
            match self {
                Self::Current(n) => {
                    n.update_peers(
                        peers
                            .iter()
                            .map(|(npub, addr)| current::config::PeerConfig::new(npub, "udp", addr))
                            .collect(),
                    )
                    .await
                    .unwrap();
                }
                Self::Legacy(n) => {
                    n.update_peers(
                        peers
                            .iter()
                            .map(|(npub, addr)| legacy::config::PeerConfig::new(npub, "udp", addr))
                            .collect(),
                    )
                    .await
                    .unwrap();
                }
            };
        }
        async fn connected(&self) -> usize {
            match self {
                Self::Current(n) => n
                    .peers()
                    .await
                    .unwrap()
                    .iter()
                    .filter(|p| p.connected)
                    .count(),
                Self::Legacy(n) => n
                    .peers()
                    .await
                    .unwrap()
                    .iter()
                    .filter(|p| p.connected)
                    .count(),
            }
        }
        async fn send(&self, dest: &str, data: &[u8]) {
            match self {
                Self::Current(n) => n
                    .send_datagram(
                        current::PeerIdentity::from_npub(dest).unwrap(),
                        44001,
                        44000,
                        data.to_vec(),
                    )
                    .await
                    .unwrap(),
                Self::Legacy(n) => n
                    .send_datagram(
                        legacy::PeerIdentity::from_npub(dest).unwrap(),
                        44001,
                        44000,
                        data.to_vec(),
                    )
                    .await
                    .unwrap(),
            };
        }
        async fn recv(&self) -> Vec<Vec<u8>> {
            match self {
                Self::Current(n) => {
                    let mut b = Vec::new();
                    n.recv_service_datagram_batch_into(&mut b, 32)
                        .await
                        .unwrap();
                    b.iter().map(|d| d.data.as_slice().to_vec()).collect()
                }
                Self::Legacy(n) => {
                    let mut b = Vec::new();
                    n.recv_service_datagram_batch_into(&mut b, 32)
                        .await
                        .unwrap();
                    b.iter().map(|d| d.data.as_slice().to_vec()).collect()
                }
            }
        }
        async fn close(&self) {
            match self {
                Self::Current(n) => n.shutdown().await.unwrap(),
                Self::Legacy(n) => n.shutdown().await.unwrap(),
            };
        }
    }
    async fn delivery(nodes: &[Peer], from: usize, to: usize, data: &[u8]) -> bool {
        nodes[from].send(nodes[to].npub(), data).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if nodes[to].recv().await.iter().any(|p| p == data) {
                    break;
                }
            }
        })
        .await
        .is_ok()
    }
    async fn snapshot(paths: &[String], modern: bool, phase: &str) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        for (index,path) in paths.iter().enumerate() {
            for command in ["show_status", "show_tree", "show_cache", "show_sessions", "show_routing"] {
                let mut stream=tokio::net::UnixStream::connect(path).await.unwrap();
                stream.write_all(format!("{{\"command\":\"{command}\"}}\n").as_bytes()).await.unwrap();
                let mut response=String::new();
                BufReader::new(stream).read_line(&mut response).await.unwrap();
                eprintln!("LEGACY_PHASE modern={modern} phase={phase} node={index} command={command} {}",response.trim());
            }
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn old_routers_and_remote_can_reach_new_client_with_smallest_identity() {
        for modern_upstream in [false, true] {
            let mut identities: Vec<_> = (0..4).map(|_| current::Identity::generate()).collect();
            identities.sort_by_key(|i| *i.node_addr());
            let mut nodes = Vec::new();
            let nonce=std::time::UNIX_EPOCH.elapsed().unwrap().as_nanos();
            let paths: Vec<String>=(0..4).map(|i|std::env::temp_dir().join(format!("compat-{nonce}-{i}.sock")).to_string_lossy().into_owned()).collect();
            for (index, id) in identities.iter().enumerate() {
                let nsec = current::encode_nsec(&id.keypair().secret_key());
                if index == 0 || (modern_upstream && index == 1) {
                    let mut c = current::Config::new();
                    c.node.identity.nsec = Some(nsec);
                    c.node.leaf_only = index == 0;
                    if index == 0 {
                        c.node.routing.mode = current::config::RoutingMode::ReplyLearned;
                    }
                    c.node.control.enabled = true;
                    c.node.control.socket_path = paths[index].clone();
                    c.node.discovery.lan.enabled = false;
                    c.node.discovery.local.enabled = false;
                    c.node.discovery.nostr.enabled = false;
                    c.transports.udp =
                        current::config::TransportInstances::Single(current::UdpConfig {
                            bind_addr: Some("127.0.0.1:0".into()),
                            ..Default::default()
                        });
                    let n = current::FipsEndpoint::builder()
                        .config(c)
                        .without_system_tun()
                        .bind()
                        .await
                        .unwrap();
                    n.register_service(44000).await.unwrap();
                    nodes.push(Peer::Current(n));
                } else {
                    let mut c = legacy::Config::new();
                    c.node.identity.nsec = Some(nsec);
                    c.node.control.enabled = true;
                    c.node.control.socket_path = paths[index].clone();
                    c.node.discovery.lan.enabled = false;
                    c.node.discovery.local.enabled = false;
                    c.node.discovery.nostr.enabled = false;
                    c.transports.udp =
                        legacy::config::TransportInstances::Single(legacy::UdpConfig {
                            bind_addr: Some("127.0.0.1:0".into()),
                            ..Default::default()
                        });
                    let n = legacy::FipsEndpoint::builder()
                        .config(c)
                        .without_system_tun()
                        .bind()
                        .await
                        .unwrap();
                    n.register_service(44000).await.unwrap();
                    nodes.push(Peer::Legacy(n));
                }
            }
            let edges = if modern_upstream {
                vec![(0, 1), (1, 2), (2, 3)]
            } else {
                vec![(0, 1), (0, 2), (1, 2), (2, 3)]
            };
            let mut addresses = Vec::new();
            for n in &nodes {
                addresses.push(n.address().await);
            }
            for (i, n) in nodes.iter().enumerate() {
                let peers = nodes
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| edges.contains(&(i, *j)) || edges.contains(&(*j, i)))
                    .map(|(j, p)| (p.npub().into(), addresses[j].clone()))
                    .collect::<Vec<_>>();
                n.connect(&peers).await;
            }
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let mut count = 0;
                    for n in &nodes {
                        count += n.connected().await;
                    }
                    if count == edges.len() * 2 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
            let inbound = delivery(&nodes, 3, 0, b"legacy inbound").await;
            snapshot(&paths, modern_upstream, "inbound").await;
            let outbound = delivery(&nodes, 0, 3, b"client outbound").await;
            snapshot(&paths, modern_upstream, "outbound").await;
            if let Peer::Current(n) = &nodes[0] {
                n.rebind_network_transports(None).await.unwrap();
            }
            let rebind_out = delivery(&nodes, 0, 3, b"rebound client").await;
            let rebind_in = delivery(&nodes, 3, 0, b"rebound legacy").await;
            for n in &nodes {
                n.close().await;
            }
            for path in paths { let _=std::fs::remove_file(path); }
            assert!(
                inbound && outbound && rebind_out && rebind_in,
                "modern_upstream={modern_upstream}: in={inbound} out={outbound} rebind_out={rebind_out} rebind_in={rebind_in}"
            );
        }
    }
}
