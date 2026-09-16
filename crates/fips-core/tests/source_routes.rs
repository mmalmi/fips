//! Exercise source choices and native MMP over the production simulation carrier.
#![cfg(feature = "sim-transport")]
use fips_core::config::{PeerConfig, RoutingMode, SimTransportConfig, TransportInstances};
use fips_core::node::{ForwardingOutcome, ForwardingPolicy, ForwardingRequest};
use fips_core::{Config, FipsEndpoint, Identity, PeerIdentity, SimLink, SimNetwork};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Duration;

#[derive(Debug, Default)]
struct Relay {
    drop_transit: AtomicBool,
    admitted: AtomicU64,
    dropped: AtomicU64,
}

impl ForwardingPolicy for Relay {
    fn admit(&self, _: &ForwardingRequest<'_>) -> Option<u64> {
        if self.drop_transit.load(Ordering::Relaxed) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            None
        } else {
            Some(self.admitted.fetch_add(1, Ordering::Relaxed))
        }
    }
    fn complete(&self, _: u64, _: ForwardingOutcome) {}
}

struct Mesh {
    nodes: Vec<FipsEndpoint>,
    peers: Vec<PeerIdentity>,
    relays: Vec<Arc<Relay>>,
    network: String,
}

impl Mesh {
    async fn start(mode: RoutingMode) -> Self {
        let network = format!("source-routes-{}", Identity::generate().node_addr());
        let carrier = SimNetwork::new(42);
        carrier.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        let edges = [(0, 1), (0, 2), (1, 3), (2, 3)];
        for (a, b) in edges {
            carrier.set_link(
                a.to_string(),
                b.to_string(),
                SimLink {
                    latency_ms: 2,
                    ..Default::default()
                },
            );
        }
        fips_core::register_sim_network(network.clone(), carrier);
        let mut nodes = Vec::new();
        let mut relays = Vec::new();
        for i in 0..4 {
            let mut config = Config::new();
            config.node.identity.persistent = false;
            config.node.control.enabled = false;
            config.node.discovery.lan.enabled = false;
            config.node.discovery.local.enabled = false;
            config.node.discovery.nostr.enabled = false;
            config.node.routing.mode = mode;
            config.transports.sim = TransportInstances::Single(SimTransportConfig {
                network: Some(network.clone()),
                addr: Some(i.to_string()),
                mtu: Some(1280),
                auto_connect: Some(false),
                accept_connections: Some(true),
            });
            let relay = Arc::new(Relay::default());
            nodes.push(
                FipsEndpoint::builder()
                    .config(config)
                    .without_system_tun()
                    .forwarding_policy(relay.clone())
                    .bind()
                    .await
                    .unwrap(),
            );
            relays.push(relay);
        }
        let peers: Vec<_> = nodes
            .iter()
            .map(|n| PeerIdentity::from_npub(n.npub()).unwrap())
            .collect();
        for (i, node) in nodes.iter().enumerate() {
            node.update_peers(
                (0..4)
                    .filter(|&j| edges.contains(&(i, j)) || edges.contains(&(j, i)))
                    .map(|j| PeerConfig::new(peers[j].npub(), "sim", j.to_string()))
                    .collect(),
            )
            .await
            .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(15), async {
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
        .expect("diamond authenticated adjacencies");
        Self {
            nodes,
            peers,
            relays,
            network,
        }
    }

    async fn bind(&self, via: usize) {
        self.nodes[0]
            .set_source_route(self.peers[3], Some(self.peers[via]))
            .await
            .unwrap();
        self.nodes[3]
            .set_source_route(self.peers[0], Some(self.peers[via]))
            .await
            .unwrap();
    }

    async fn prove_delivery(&self, via: usize, label: u8) {
        let mut received = Vec::new();
        let mut delivered = false;
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                self.nodes[0]
                    .send_batch_to_peer(self.peers[3], vec![vec![label; 200]])
                    .await
                    .unwrap();
                if let Ok(Some(count)) = tokio::time::timeout(
                    Duration::from_millis(200),
                    self.nodes[3].recv_batch_into(&mut received, 32),
                )
                .await
                {
                    assert!(count > 0);
                    delivered |= received.iter().any(|m| {
                        m.source_peer.node_addr() == self.peers[0].node_addr()
                            && m.data.as_slice() == vec![label; 200]
                    });
                }
                let quality = self.nodes[0]
                    .source_route_quality(self.peers[3], Duration::from_secs(3))
                    .await
                    .unwrap();
                if delivered
                    && quality.next_hop == Some(*self.peers[via].node_addr())
                    && quality.has_recent_delivery_feedback
                    && quality.rtt_ms.is_some()
                    && quality.goodput_bps.is_some_and(|v| v > 0.0)
                {
                    assert!(!quality.delivery_feedback_timed_out);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .expect("delivered payload and native receiver-report quality through selected carrier");
    }

    async fn close(self) {
        for node in self.nodes {
            node.shutdown().await.unwrap();
        }
        fips_core::unregister_sim_network(&self.network);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_quality_distinguishes_a_live_blackhole_and_recovers_after_source_switch() {
    for mode in [RoutingMode::Tree, RoutingMode::ReplyLearned] {
        let mesh = Mesh::start(mode).await;
        mesh.bind(1).await;
        mesh.prove_delivery(1, 1).await;
        assert!(mesh.relays[1].admitted.load(Ordering::Relaxed) > 0);
        // Neighbor control remains healthy, but the relay stops all transit.
        mesh.relays[1].drop_transit.store(true, Ordering::Relaxed);
        // A same-neighbor rebind represents a changed downstream path. Old
        // delivery evidence must not validate this new trial.
        mesh.bind(1).await;
        let reset = mesh.nodes[0]
            .source_route_quality(mesh.peers[3], Duration::from_secs(3))
            .await
            .unwrap();
        assert!(!reset.has_recent_delivery_feedback);
        mesh.nodes[0]
            .send_batch_to_peer(mesh.peers[3], vec![vec![2; 200]])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
        let failed = mesh.nodes[0]
            .source_route_quality(mesh.peers[3], Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(failed.next_hop, Some(*mesh.peers[1].node_addr()));
        assert!(failed.delivery_feedback_timed_out, "{mode:?}: {failed:?}");
        assert!(!failed.has_recent_delivery_feedback);
        assert!(failed.rtt_ms.is_none() && failed.goodput_bps.is_none());
        assert!(mesh.relays[1].dropped.load(Ordering::Relaxed) > 0);
        assert_eq!(
            mesh.nodes[0]
                .peers()
                .await
                .unwrap()
                .iter()
                .filter(|p| p.connected)
                .count(),
            2
        );
        // Explicitly choose the alternative; this test does not implement a
        // second path-selection algorithm or claim monetary optimization.
        mesh.bind(2).await;
        mesh.prove_delivery(2, 3).await;
        assert!(mesh.relays[2].admitted.load(Ordering::Relaxed) > 0);
        mesh.nodes[0]
            .set_source_route(mesh.peers[3], None)
            .await
            .unwrap();
        mesh.close().await;
    }
}
