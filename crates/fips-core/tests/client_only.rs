use fips_core::config::{PeerConfig, TransportInstances};
use fips_core::{Config, FipsEndpoint, Identity, PeerIdentity, UdpConfig, encode_nsec};
use std::time::Duration;

async fn endpoints(count: usize, client: bool, reply_learned: bool) -> Vec<FipsEndpoint> {
    // Force the client to have the smallest address: it must still follow a
    // router's coordinate root without ever becoming the mesh root itself.
    let mut identities: Vec<_> = (0..count).map(|_| Identity::generate()).collect();
    identities.sort_by_key(|identity| *identity.node_addr());
    let mut nodes = Vec::new();
    for (index, identity) in identities.into_iter().enumerate() {
        let mut config = Config::new();
        config.node.identity.nsec = Some(encode_nsec(&identity.keypair().secret_key()));
        config.node.leaf_only = client && index == 0;
        if reply_learned {
            config.node.routing.mode = fips_core::config::RoutingMode::ReplyLearned;
        }
        config.node.control.enabled = false;
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
        node.register_service(44_000).await.unwrap();
        nodes.push(node);
    }
    nodes
}

async fn connect(nodes: &[FipsEndpoint], edges: &[(usize, usize)]) {
    let mut addresses = Vec::new();
    for node in nodes {
        addresses.push(node.bound_udp_listen_addrs().await.unwrap()[0]);
    }
    for (index, node) in nodes.iter().enumerate() {
        let peers = nodes
            .iter()
            .enumerate()
            .filter(|(other, _)| {
                edges.contains(&(index, *other)) || edges.contains(&(*other, index))
            })
            .map(|(other, peer)| PeerConfig::new(peer.npub(), "udp", addresses[other].to_string()))
            .collect();
        node.update_peers(peers).await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut count = 0;
            for node in nodes {
                count += node
                    .peers()
                    .await
                    .unwrap()
                    .iter()
                    .filter(|peer| peer.connected)
                    .count();
            }
            if count == edges.len() * 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("authenticated adjacencies");
}

async fn delivered(source: &FipsEndpoint, dest: &FipsEndpoint, payload: &[u8]) -> bool {
    source
        .send_datagram(
            PeerIdentity::from_npub(dest.npub()).unwrap(),
            44_001,
            44_000,
            payload.to_vec(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let mut batch = Vec::new();
            dest.recv_service_datagram_batch_into(&mut batch, 32)
                .await
                .unwrap();
            if batch.iter().any(|packet| packet.data.as_slice() == payload) {
                break;
            }
        }
    })
    .await
    .is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_only_remains_reachable_through_each_upstream_and_after_rebind() {
    reachable(false).await;
    reachable(true).await;
}

async fn reachable(reply_learned: bool) {
    for upstreams in [vec![1], vec![2], vec![1, 2]] {
        let nodes = endpoints(4, true, reply_learned).await;
        let mut edges = vec![(1, 2), (2, 3)];
        edges.extend(upstreams.iter().map(|upstream| (0, *upstream)));
        connect(&nodes, &edges).await;
        // New sessions in both directions, with no supplied remote route.
        let inbound = delivered(&nodes[3], &nodes[0], b"first inbound").await;
        let outbound = delivered(&nodes[0], &nodes[3], b"first outbound").await;
        nodes[0].rebind_network_transports(None).await.unwrap();
        let rebound_out = delivered(&nodes[0], &nodes[3], b"rebound outbound").await;
        let rebound_in = delivered(&nodes[3], &nodes[0], b"rebound inbound").await;
        for node in &nodes {
            node.shutdown().await.unwrap();
        }
        assert!(
            inbound && outbound && rebound_out && rebound_in,
            "upstreams={upstreams:?}: inbound={inbound} outbound={outbound} rebound_out={rebound_out} rebound_in={rebound_in}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_only_cannot_bridge_unrelated_sessions_but_router_can() {
    for client in [false, true] {
        let nodes = endpoints(3, client, true).await;
        connect(&nodes, &[(1, 0), (0, 2)]).await;
        let own = delivered(&nodes[0], &nodes[1], b"client's own session").await;
        let transit = delivered(&nodes[1], &nodes[2], b"unrelated transit").await;
        for node in &nodes {
            node.shutdown().await.unwrap();
        }
        assert!(own, "own traffic must survive either role");
        assert_eq!(
            transit, !client,
            "only a router may join the two components"
        );
    }
}
