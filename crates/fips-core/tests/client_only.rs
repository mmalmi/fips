use fips_core::config::{PeerConfig, TransportInstances};
use fips_core::{Config, FipsEndpoint, Identity, PeerIdentity, UdpConfig, encode_nsec};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Default)]
struct InitialHandshakes(Mutex<Vec<(fips_core::NodeAddr, Vec<u8>)>>);

impl fips_core::node::OriginatedSessionObserver for InitialHandshakes {
    fn observe(&self, request: &fips_core::node::OriginatedSessionRequest<'_>) -> Option<u64> {
        // MSG1 has a four-byte common prefix. Observe the real wire payload
        // without supplying a route, handshake, or timing state to the node.
        if request.session_payload.first() == Some(&0x01) {
            let setup =
                fips_core::protocol::SessionSetup::decode(&request.session_payload[4..]).unwrap();
            let mut handshakes = self.0.lock().unwrap();
            assert!(handshakes.len() < 16, "bounded first-contact attempts");
            handshakes.push((request.destination, setup.handshake_payload));
        }
        None
    }

    fn complete(&self, _: u64, _: fips_core::node::ForwardingOutcome) {
        panic!("passive observation has no accounting reservation");
    }
}

struct TestEndpoint {
    endpoint: FipsEndpoint,
    control: String,
    handshakes: Arc<InitialHandshakes>,
    _directory: tempfile::TempDir,
}
impl std::ops::Deref for TestEndpoint {
    type Target = FipsEndpoint;
    fn deref(&self) -> &Self::Target {
        &self.endpoint
    }
}

async fn query(node: &TestEndpoint, command: &str) -> serde_json::Value {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    #[cfg(unix)]
    let mut stream = tokio::net::UnixStream::connect(&node.control)
        .await
        .unwrap();
    #[cfg(windows)]
    let mut stream =
        tokio::net::TcpStream::connect(("127.0.0.1", node.control.parse::<u16>().unwrap()))
            .await
            .unwrap();
    stream
        .write_all(format!("{{\"command\":\"{command}\"}}\n").as_bytes())
        .await
        .unwrap();
    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .await
        .unwrap();
    let response: serde_json::Value = serde_json::from_str(&response).unwrap();
    assert_eq!(response["status"], "ok");
    response["data"].clone()
}

async fn endpoints(count: usize, client: bool, reply_learned: bool) -> Vec<TestEndpoint> {
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
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let control = directory
            .path()
            .join("control.sock")
            .to_string_lossy()
            .into_owned();
        #[cfg(windows)]
        let control = std::net::TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
            .to_string();
        config.node.control.enabled = true;
        config.node.control.socket_path = control.clone();
        config.node.discovery.lan.enabled = false;
        config.node.discovery.local.enabled = false;
        config.node.discovery.nostr.enabled = false;
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some("127.0.0.1:0".into()),
            ..UdpConfig::default()
        });
        let handshakes = Arc::new(InitialHandshakes::default());
        let node = FipsEndpoint::builder()
            .config(config)
            .originated_session_observer(handshakes.clone())
            .without_system_tun()
            .bind()
            .await
            .unwrap();
        node.register_service(44_000).await.unwrap();
        nodes.push(TestEndpoint {
            endpoint: node,
            control,
            handshakes,
            _directory: directory,
        });
    }
    nodes
}

async fn connect(nodes: &[TestEndpoint], edges: &[(usize, usize)], client: bool) {
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
                if !client {
                    break;
                }
                // Authentication precedes capability and role negotiation. Do
                // not mistake the required legacy-compatible router phase for
                // an active client, or prewarm an FSP session before this gate.
                let status = query(&nodes[0], "show_status").await;
                let tree = query(&nodes[0], "show_tree").await;
                let identity = hex::encode(nodes[0].node_addr().as_bytes());
                let mut advertised = true;
                for &(left, right) in edges {
                    let upstream = if left == 0 {
                        right
                    } else if right == 0 {
                        left
                    } else {
                        continue;
                    };
                    let bloom = query(&nodes[upstream], "show_bloom").await;
                    advertised &= bloom["leaf_dependents"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|peer| peer.as_str() == Some(identity.as_str()));
                }
                if status["is_leaf_only"] == true && tree["is_root"] == false && advertised {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("authenticated adjacencies and negotiated client routing");
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
    reachable(false, false).await;
    reachable(true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn negotiated_client_remains_reachable_through_each_upstream_and_after_rebind() {
    reachable(false, true).await;
    reachable(true, true).await;
}

async fn reachable(reply_learned: bool, wait_for_client: bool) {
    for upstreams in [vec![1], vec![2], vec![1, 2]] {
        let nodes = endpoints(4, true, reply_learned).await;
        let mut edges = vec![(1, 2), (2, 3)];
        edges.extend(upstreams.iter().map(|upstream| (0, *upstream)));
        connect(&nodes, &edges, wait_for_client).await;
        // New sessions in both directions, with no supplied remote route.
        let inbound = delivered(&nodes[3], &nodes[0], b"first inbound").await;
        {
            let attempts = nodes[3].handshakes.0.lock().unwrap();
            let first = attempts.first().expect("a real initial Noise handshake");
            assert_eq!(first.0, *nodes[0].node_addr());
            assert!(
                attempts.iter().all(|attempt| attempt == first),
                "route recovery must retain the original Noise msg1"
            );
        }
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
        connect(&nodes, &[(1, 0), (0, 2)], client).await;
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
