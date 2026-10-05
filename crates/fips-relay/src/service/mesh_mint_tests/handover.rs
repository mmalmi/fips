//! Keep both former neighbors alive while mint forwarding changes direction.
use super::*;
use fips_core::{SimLink, SimNetwork, config::SimTransportConfig};
use std::{collections::BTreeSet, net::SocketAddr};

async fn info(address: SocketAddr) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut socket = TcpStream::connect(address)
            .await
            .map_err(|e| e.to_string())?;
        socket
            .write_all(b"GET /v1/info HTTP/1.1\r\nHost: mint\r\nConnection: close\r\n\r\n")
            .await
            .map_err(|e| e.to_string())?;
        let mut response = Vec::new();
        socket
            .take(128 * 1024)
            .read_to_end(&mut response)
            .await
            .map_err(|e| e.to_string())?;
        if response.starts_with(b"HTTP/1.1 200") && response.windows(6).any(|w| w == b"\"nuts\"") {
            Ok(())
        } else {
            Err(format!("incomplete mint info: {} bytes", response.len()))
        }
    })
    .await
    .map_err(|_| "mint info deadline".to_owned())?
}

async fn topology(nodes: &[RelayService], identities: &[PeerIdentity], changed: bool) {
    let wanted: [&[usize]; 4] = if changed {
        [&[1, 2], &[0], &[0, 3], &[2]]
    } else {
        [&[1], &[0, 2], &[1, 3], &[2]]
    };
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let mut ready = true;
            for (i, node) in nodes.iter().enumerate() {
                let connected: BTreeSet<_> = node
                    .endpoint
                    .peers()
                    .await
                    .unwrap()
                    .into_iter()
                    .filter(|p| p.connected)
                    .map(|p| p.node_addr)
                    .collect();
                ready &= connected
                    == wanted[i]
                        .iter()
                        .map(|j| *identities[*j].node_addr())
                        .collect();
            }
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("exact mesh edges must be observed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mint_client_requotes_after_its_former_customer_becomes_the_transit_peer() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    tokio::time::timeout(Duration::from_secs(180), async {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mint = LocalMint::start(
            root.path(),
            PaymentNetwork::new(318, 0, Arc::new(VirtualClock::new(now))),
            "handover-mint",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reserved.local_addr().unwrap();
        let url = format!("http://{address}");
        let name = format!("mint-handover-{}", Identity::generate().node_addr());
        let network = SimNetwork::new(318);
        network.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        for (a, b) in [(0, 1), (1, 2), (2, 3)] {
            network.set_link(a.to_string(), b.to_string(), SimLink::default());
        }
        fips_core::register_sim_network(name.clone(), network.clone());
        let mut configs = Vec::new();
        for i in 0..4 {
            let mut config: ServiceConfig =
                serde_json::from_str(include_str!("../../../service.example.json")).unwrap();
            config.state_directory = root.path().join(format!("node-{i}"));
            config.terms.billing = BillingBasis::ForwardingData;
            config.terms.controller.mint_url = url.clone();
            config.terms.quote_max_units = 2 * 1024 * 1024;
            config.neighbor_admission =
                crate::control_transport::NeighborAdmission::AuthenticatedAdjacent;
            config.return_allowance = true;
            config.free_bandwidth = Some(FreeBandwidthPolicy {
                global_bytes_per_second: 65_536,
                global_burst_bytes: 131_072,
                peer_bytes_per_second: 32_768,
                peer_burst_bytes: 65_536,
            });
            config.return_bandwidth = Some(FreeBandwidthPolicy {
                global_bytes_per_second: 32_768,
                global_burst_bytes: 65_536,
                peer_bytes_per_second: 8_192,
                peer_burst_bytes: 16_384,
            });
            config.transports = TransportsConfig {
                sim: TransportInstances::Single(SimTransportConfig {
                    network: Some(name.clone()),
                    addr: Some(i.to_string()),
                    auto_connect: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            };
            configs.push(config);
        }
        configs[3].mint_export = Some(crate::mint_mesh::MintExport {
            backend: mint.url().strip_prefix("http://").unwrap().parse().unwrap(),
            service_port: PORT,
        });
        let gateway = RelayService::initialize(configs[3].clone()).await.unwrap();
        configs[1].terms.mint_mesh = Some(crate::mint_mesh::MintMesh {
            npub: gateway.clone(),
            service_port: PORT,
        });
        let mut identities = Vec::new();
        for config in &mut configs[..3] {
            config.destination_fees = serde_json::from_value(json!({gateway.clone(): 0})).unwrap();
            let npub = RelayService::initialize(config.clone()).await.unwrap();
            identities.push(PeerIdentity::from_npub(&npub).unwrap());
        }
        identities.push(PeerIdentity::from_npub(&gateway).unwrap());
        drop(reserved);
        let mut nodes = Vec::new();
        for config in &configs {
            nodes.push(RelayService::load(config.clone()).await.unwrap());
        }
        topology(&nodes, &identities, false).await;
        // Warm the original customer's quoted path and native session. This
        // node stays alive when the provider later needs it in reverse.
        assert!(matches!(
            nodes[0].controller.open_route(identities[3]).await.unwrap(),
            RouteAccess::Free(_)
        ));
        let initial = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let initial_address = initial.local_addr().unwrap();
        let customer =
            MeshMintBridge::connect(nodes[0].endpoint.clone(), PORT, identities[3], initial)
                .await
                .unwrap();
        info(initial_address).await.unwrap();
        info(address).await.unwrap();
        let untouched: Vec<_> = configs
            .iter()
            .map(|c| {
                let path = c.state_directory.join("controller/controller.json");
                let data = std::fs::read(&path).unwrap();
                (path, data)
            })
            .collect();
        eprintln!("mint handover: both original paths work");
        network.set_link_up("1", "2", false);
        network.set_link("0", "2", SimLink::default());
        topology(&nodes, &identities, true).await;
        eprintln!("mint handover: replacement edges observed, old edge remains down");
        let mut last = None;
        for _ in 0..6 {
            match info(address).await {
                Ok(()) => {
                    last = None;
                    break;
                }
                Err(error) => last = Some(error),
            }
        }
        assert!(
            last.is_none(),
            "mint handover failed: {last:?}; transit {:?}",
            nodes[0].free.stats()
        );
        assert!(nodes[0].free.stats().admitted_session_bytes > 0);
        assert!(
            nodes[0]
                .forwarding
                .relay
                .return_stats()
                .unwrap()
                .traffic
                .admitted_packets
                > 0
        );
        for (path, data) in untouched {
            assert_eq!(std::fs::read(path).unwrap(), data);
        }
        customer.shutdown().await.unwrap();
        for node in nodes {
            node.shutdown().await.unwrap();
        }
        fips_core::unregister_sim_network(&name);
    })
    .await
    .expect("mint handover test deadline");
}
