//! Unfunded neighbors fill admission slots without replacing paid authority.
use super::*;
use std::{future::Future, path::Path};

#[path = "full_roster.rs"]
mod automatic;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crowded_discovery_preserves_paid_progress_and_recovers_after_departure() {
    tokio::time::timeout(Duration::from_secs(480), exercise_crowded())
        .await
        .expect("crowded mesh encounter deadline");
}

struct Candidate {
    address: String,
    bridge: usize,
    peer: PeerIdentity,
    endpoint: FipsEndpoint,
}

async fn candidates(bench: &Bench) -> Vec<Candidate> {
    let mut result = Vec::new();
    for bridge in [2, 3] {
        for ordinal in 0..4 {
            let address = format!("candidate-{bridge}-{ordinal}");
            bench.network.set_link(
                &address,
                bridge.to_string(),
                SimLink {
                    latency_ms: 2,
                    ..Default::default()
                },
            );
            let key = Identity::from_secret_bytes(&[100 + bridge as u8 * 4 + ordinal; 32]).unwrap();
            let peer = PeerIdentity::from_pubkey_full(key.pubkey_full());
            let mut config = Config::new();
            config.node.identity.nsec = Some(fips_core::encode_nsec(&key.keypair().secret_key()));
            config.node.identity.persistent = false;
            config.node.control.enabled = false;
            config.node.discovery.nostr.enabled = false;
            config.node.discovery.lan.enabled = false;
            config.node.discovery.local.enabled = false;
            config.node.limits.max_peers = 1;
            config.node.limits.max_connections = 2;
            config.node.limits.max_links = 2;
            config.transports = Default::default();
            config.transports.sim = TransportInstances::Single(SimTransportConfig {
                network: Some(bench.network_name.clone()),
                addr: Some(address.clone()),
                mtu: Some(1280),
                auto_connect: Some(true),
                accept_connections: Some(true),
            });
            assert!(config.peers.is_empty());
            let endpoint = FipsEndpoint::builder()
                .config(config)
                .without_system_tun()
                .bind()
                .await
                .unwrap();
            result.push(Candidate {
                address,
                bridge,
                peer,
                endpoint,
            });
        }
    }
    result
}

async fn occupied(
    nodes: &[Arc<FipsEndpoint>],
    identities: &[PeerIdentity],
    candidates: &[Candidate],
) -> bool {
    for (bridge, internal) in [(2, 1), (3, 4)] {
        let peers = nodes[bridge].peers().await.unwrap();
        assert!(peers.len() <= 2);
        let healthy = peers
            .iter()
            .any(|p| p.node_addr == *identities[internal].node_addr() && p.connected);
        assert!(healthy, "crowding displaced the healthy internal neighbor");
        if peers.len() != 2 || peers.iter().any(|p| !p.connected) {
            return false;
        }
        let Some(candidate) = candidates.iter().find(|c| {
            c.bridge == bridge && peers.iter().any(|p| p.node_addr == *c.peer.node_addr())
        }) else {
            return false;
        };
        if !candidate.endpoint.peers().await.unwrap().iter().any(|p| {
            p.node_addr == *identities[bridge].node_addr()
                && p.connected
                && p.transport_type.as_deref() == Some("sim")
        }) {
            return false;
        }
    }
    true
}

impl Observer {
    async fn while_occupied<T>(
        &mut self,
        candidates: &[Candidate],
        operation: impl Future<Output = T>,
    ) -> T {
        let nodes = self.nodes.clone();
        let peers = self.peers.clone();
        self.during_checked(operation, || async {
            assert!(
                occupied(&nodes, &peers, candidates).await,
                "bridge slots must stay full during paid progress"
            );
        })
        .await
    }
}

async fn internal_links(
    root: &Path,
    nodes: &[Arc<FipsEndpoint>],
    identities: &[PeerIdentity],
) -> [(u64, u64); 2] {
    let mut result = [(0, 0); 2];
    for (index, (boundary, internal)) in [(2, 1), (3, 4)].into_iter().enumerate() {
        assert!(
            nodes[boundary].peers().await.unwrap().iter().any(|peer| {
                peer.connected && peer.node_addr == *identities[internal].node_addr()
            }),
            "the original local paid neighbor must remain connected"
        );
        let reply = native_query(root, boundary, "show_peers").await;
        let peer = reply["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|peer| peer["npub"] == identities[internal].npub())
            .expect("the original local native peer must remain present");
        assert_eq!(peer["transport_type"], "sim");
        result[index] = (
            peer["link_id"].as_u64().unwrap(),
            peer["authenticated_at_ms"].as_u64().unwrap(),
        );
    }
    result
}

async fn setup_crowded(
    seed: u64,
    rotation: Option<fips_core::config::NeighborRotationConfig>,
) -> (Bench, Observer, Vec<Account>, Vec<Candidate>) {
    let rotating = rotation.is_some();
    let mut bench = match rotation {
        Some(rotation) => Box::pin(bench::start_with_neighbor_rotation(0, seed, rotation)).await,
        None => Box::pin(bench::start(0, Scenario::MergeSplit, seed)).await,
    };
    let mut observer = Observer::new(&bench);
    if rotating {
        for (index, identity) in bench.peers.iter().enumerate() {
            eprintln!(
                "full-roster identity: node={index} address={} npub={}",
                identity.node_addr(),
                identity.npub()
            );
        }
    }
    converge(&bench, false, "crowded initial components").await;
    let original_links = if rotating {
        Some(internal_links(bench.root.path(), &bench.nodes, &bench.peers).await)
    } else {
        None
    };
    for (source, destination) in [(0, 2), (5, 3)] {
        watch(&bench, source, destination).await;
    }
    bench.network.set_link(
        "2",
        "3",
        SimLink {
            latency_ms: 2,
            ..Default::default()
        },
    );
    converge(&bench, true, "crowded initial merge").await;
    for (source, destination, tag) in [(0, 5, 100), (5, 0, 101)] {
        watch(&bench, source, destination).await;
        traffic(&mut bench, source, destination, tag).await;
    }
    let anchor = accounts(&bench).await;
    assert_watches(&bench).await;
    assert_eq!(anchor.iter().map(|a| a.funding.len()).sum::<usize>(), 8);
    assert_eq!(payments(&bench).await.len(), 8);
    bench.network.set_link_up("2", "3", false);
    converge(&bench, false, "before crowded encounter").await;

    if rotating {
        // Split convergence outlasts the idle threshold. Refresh real local
        // application demand before new discoveries compete for the last slots.
        for (source, destination, tag) in [(0, 2, 102), (5, 3, 103)] {
            traffic(&mut bench, source, destination, tag).await;
        }
    }

    let candidates = observer.during(candidates(&bench)).await;
    if rotating {
        for candidate in &candidates {
            eprintln!(
                "full-roster identity: node={} address={}",
                candidate.address,
                candidate.peer.node_addr()
            );
        }
    }
    let occupied_at = Instant::now();
    observer
        .during(async {
            tokio::time::timeout(Duration::from_secs(60), async {
                while !occupied(&bench.nodes, &bench.peers, &candidates).await {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            })
            .await
            .expect("both bridge peer slots fill with unfunded neighbors");
        })
        .await;
    eprintln!(
        "crowded mesh: eight candidates occupy two slots after {:.2}s",
        occupied_at.elapsed().as_secs_f64()
    );
    retain(&anchor, &accounts(&bench).await, true);
    assert_watches(&bench).await;
    if let Some(links) = original_links {
        assert_eq!(
            internal_links(bench.root.path(), &bench.nodes, &bench.peers).await,
            links,
            "crowding must retain the original refreshed internal link epochs"
        );
    }
    (bench, observer, anchor, candidates)
}

async fn exercise_crowded() {
    let (mut bench, mut observer, anchor, candidates) = Box::pin(setup_crowded(119, None)).await;
    // Full native rosters deliberately retain healthy peers. The bridge can
    // reconnect after departures; this fixture does not assume Sybil fairness.
    bench.network.set_link_up("2", "3", true);
    observer
        .while_occupied(&candidates, no_cross_delivery(&mut bench, 110))
        .await;
    let before_local = hop_usage(&bench).await;
    let paid_before: BTreeMap<_, _> = [(0, 1), (5, 4)]
        .into_iter()
        .map(|pair| {
            let channel = &before_local[&pair].channel;
            (
                channel.clone(),
                bench.sellers[pair.1]
                    .channel_usage(channel)
                    .unwrap()
                    .paid_msat,
            )
        })
        .collect();
    for (source, destination, tag) in [(0, 2, 120), (5, 3, 121)] {
        assert!(occupied(&bench.nodes, &bench.peers, &candidates).await);
        observer
            .while_occupied(&candidates, traffic(&mut bench, source, destination, tag))
            .await;
        assert!(occupied(&bench.nodes, &bench.peers, &candidates).await);
    }
    let after_local = hop_usage(&bench).await;
    let local_paid = observer.while_occupied(&candidates, payments(&bench)).await;
    for pair in [(0, 1), (5, 4)] {
        let before = &before_local[&pair];
        let after = &after_local[&pair];
        assert_eq!(after.channel, before.channel);
        assert!(after.evidence > before.evidence && after.submitted > before.submitted);
        assert!(local_paid[&after.channel] > paid_before[&after.channel]);
    }
    retain(&anchor, &accounts(&bench).await, true);
    assert_watches(&bench).await;
    for candidate in &candidates {
        bench
            .network
            .set_link_up(&candidate.address, candidate.bridge.to_string(), false);
    }
    observer
        .during(converge(&bench, true, "crowded candidates departed"))
        .await;
    let before_rejoin = hop_usage(&bench).await;
    for (source, destination, tag) in [(0, 5, 130), (5, 0, 131)] {
        observer
            .during(traffic(&mut bench, source, destination, tag))
            .await;
    }
    fresh_hops(&before_rejoin, &hop_usage(&bench).await);
    let paid = observer.during(payments(&bench)).await;
    assert_eq!(paid.len(), 8);
    for (channel, prior) in local_paid {
        assert!(paid[&channel] > prior);
    }
    retain(&anchor, &accounts(&bench).await, true);
    assert_watches(&bench).await;
    for candidate in candidates {
        candidate.endpoint.shutdown().await.unwrap();
    }
    observer.settled().await;
    eprintln!(
        "crowded mesh: {} native samples; maxima {:?}",
        observer.samples, observer.maxima
    );
    collect(bench, &anchor, &paid).await;
}
