use cashu_service::{create_topup_quote, load_wallet_overview, simulation::PaymentNetwork};
use fips_core::config::{PeerConfig, TcpConfig, TransportInstances, UdpConfig, WebSocketConfig};
use fips_relay::{
    control_transport::NeighborAdmission,
    controller::RenewalPolicy,
    ledger::BillingBasis,
    probe::{ReceiveProbe, SendProbe},
    service::{AdminRequest, ServiceConfig, native_request, request},
};
use serde_json::Value;
use std::{
    net::{SocketAddr, TcpListener, UdpSocket},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::process::Child;

use crate::process_support::{command, config, ready, start};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecondHop {
    Tcp,
    WebSocket,
    WebSocketSeed,
}

impl SecondHop {
    pub fn kind(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::WebSocket | Self::WebSocketSeed => "websocket",
        }
    }

    fn address(self, socket: SocketAddr) -> String {
        match self {
            Self::Tcp => socket.to_string(),
            Self::WebSocket | Self::WebSocketSeed => format!("ws://{socket}/fips"),
        }
    }
}

pub struct MixedBench {
    _root: tempfile::TempDir,
    pub configs: Vec<ServiceConfig>,
    pub paths: Vec<PathBuf>,
    pub npubs: Vec<String>,
    pub children: Vec<Child>,
    second_hop: SecondHop,
    next_probe: AtomicU64,
}

impl MixedBench {
    pub async fn start(mint: &str, network: &PaymentNetwork) -> Self {
        Self::start_with_second_hop(mint, network, SecondHop::Tcp).await
    }

    pub async fn start_with_second_hop(
        mint: &str,
        network: &PaymentNetwork,
        second_hop: SecondHop,
    ) -> Self {
        let root = tempfile::tempdir().unwrap();
        let udp: Vec<_> = (0..2)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        let tcp: Vec<_> = (0..2)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let (mut configs, mut paths, mut npubs) = (Vec::new(), Vec::new(), Vec::new());
        for node in 0..3 {
            let directory = root.path().join(format!("n{node}"));
            std::fs::create_dir(&directory).unwrap();
            let mut config = config(&directory, mint);
            config.transports = Default::default();
            if node < 2 {
                config.transports.udp = TransportInstances::Single(UdpConfig {
                    bind_addr: Some(udp[node].local_addr().unwrap().to_string()),
                    ..Default::default()
                });
            }
            if node > 0 {
                let bind_addr = Some(tcp[node - 1].local_addr().unwrap().to_string());
                match second_hop {
                    SecondHop::Tcp => {
                        config.transports.tcp = TransportInstances::Single(TcpConfig {
                            bind_addr,
                            ..Default::default()
                        });
                    }
                    SecondHop::WebSocket | SecondHop::WebSocketSeed => {
                        config.transports.websocket = TransportInstances::Single(WebSocketConfig {
                            bind_addr: if second_hop == SecondHop::WebSocketSeed && node == 2 {
                                None
                            } else {
                                bind_addr
                            },
                            seed_urls: if second_hop == SecondHop::WebSocketSeed && node == 2 {
                                vec![second_hop.address(tcp[0].local_addr().unwrap())]
                            } else {
                                Vec::new()
                            },
                            ..Default::default()
                        });
                    }
                }
                if second_hop == SecondHop::WebSocketSeed {
                    config.neighbor_admission = NeighborAdmission::AuthenticatedAdjacent;
                }
            }
            config.terms.billing = BillingBasis::ForwardingData;
            config.terms.controller.channel_capacity_sat = 8;
            config.terms.controller.max_locked_sat = 16;
            config.terms.controller.max_wallet_spend_sat = 64;
            config.terms.controller.renewal = Some(RenewalPolicy {
                at_capacity_percent: 75,
                before_expiry_secs: 30,
            });
            let path = directory.join("config.json");
            std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
            let initialized = command(&path, "init").await;
            assert!(
                initialized.status.success(),
                "{}",
                String::from_utf8_lossy(&initialized.stderr)
            );
            npubs.push(
                String::from_utf8(initialized.stdout)
                    .unwrap()
                    .trim()
                    .to_owned(),
            );
            let wallet = config.state_directory.join("wallet");
            let quote = create_topup_quote(&wallet, mint, 128).await.unwrap();
            network
                .orchestrator_funding()
                .settle_external(&quote.payment_request)
                .unwrap();
            assert!(
                load_wallet_overview(&wallet, true)
                    .await
                    .unwrap()
                    .warnings
                    .is_empty()
            );
            configs.push(config);
            paths.push(path);
        }
        configs[0].neighbors = vec![PeerConfig::new(
            &npubs[1],
            "udp",
            udp[1].local_addr().unwrap().to_string(),
        )];
        configs[1].neighbors = vec![PeerConfig::new(
            &npubs[0],
            "udp",
            udp[0].local_addr().unwrap().to_string(),
        )];
        if second_hop != SecondHop::WebSocketSeed {
            configs[1].neighbors.push(PeerConfig::new(
                &npubs[2],
                second_hop.kind(),
                second_hop.address(tcp[1].local_addr().unwrap()),
            ));
            configs[2].neighbors = vec![PeerConfig::new(
                &npubs[1],
                second_hop.kind(),
                second_hop.address(tcp[0].local_addr().unwrap()),
            )];
        } else {
            // The bootstrap URL carries no peer identity. The known npubs
            // remain test observations/destinations, not native peer rosters.
            assert!(configs[2].neighbors.is_empty());
            for config in &configs[1..] {
                assert_eq!(
                    config.neighbor_admission,
                    NeighborAdmission::AuthenticatedAdjacent
                );
                assert!(config.neighbors.iter().all(|peer| {
                    peer.addresses
                        .iter()
                        .all(|address| address.transport == "udp")
                }));
            }
            let client = configs[2].transports.websocket.iter().next().unwrap().1;
            assert!(client.bind_addr.is_none());
            assert!(client.public_url.is_none());
            assert_eq!(
                client.seed_urls,
                vec![second_hop.address(tcp[0].local_addr().unwrap())]
            );
        }
        assert!(
            configs[2].transports.udp.is_empty(),
            "stream endpoint has no UDP fallback"
        );
        assert_eq!(
            configs[2].transports.instance_counts().collect::<Vec<_>>(),
            vec![(second_hop.kind(), 1)],
            "final endpoint has only its selected stream adapter"
        );
        for (config, path) in configs.iter().zip(&paths) {
            std::fs::write(path, serde_json::to_vec(config).unwrap()).unwrap();
        }
        drop((udp, tcp));
        let mut children = Vec::new();
        for path in &paths {
            children.push(start(path).await);
        }
        ready(&configs, &paths, &npubs, &mut children).await;
        Self {
            _root: root,
            configs,
            paths,
            npubs,
            children,
            second_hop,
            next_probe: AtomicU64::new(1),
        }
    }

    pub fn second_hop_kind(&self) -> &'static str {
        self.second_hop.kind()
    }

    pub async fn states(&self) -> Vec<Value> {
        let mut states = Vec::new();
        for config in &self.configs {
            states.push(request(config, &AdminRequest::Status).await.unwrap());
        }
        states
    }

    pub async fn assert_carriers(&self) {
        if self.second_hop == SecondHop::WebSocketSeed {
            let report = native_request(
                &self.configs[2],
                &serde_json::json!({"command": "show_transports"}),
            )
            .await
            .unwrap();
            assert_eq!(report["status"], "ok");
            let transports = report["data"]["transports"].as_array().unwrap();
            assert_eq!(transports.len(), 1);
            assert_eq!(transports[0]["type"], "websocket");
            assert_eq!(transports[0]["state"], "up");
            assert!(
                transports[0].get("local_addr").is_none(),
                "seed client has no listener"
            );
        }
        for (node, status) in self.states().await.iter().enumerate() {
            let mut actual: Vec<_> = status["peers"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|peer| peer["connected"] == true)
                .map(|peer| peer["transport"].as_str().unwrap())
                .collect();
            actual.sort_unstable();
            let mut expected = match node {
                0 => vec!["udp"],
                1 => vec![self.second_hop_kind(), "udp"],
                _ => vec![self.second_hop_kind()],
            };
            expected.sort_unstable();
            assert_eq!(actual, expected, "native carrier topology at node {node}");
        }
    }

    pub async fn send_probe(
        &self,
        source: usize,
        destination: usize,
        count: u32,
        bytes: usize,
        rate: u32,
    ) -> Value {
        let stream_id = format!("{:032x}", self.next_probe.fetch_add(1, Ordering::Relaxed));
        request(
            &self.configs[destination],
            &AdminRequest::ReceiveProbe {
                probe: ReceiveProbe {
                    source: self.npubs[source].clone(),
                    stream_id: stream_id.clone(),
                    packet_count: count,
                    payload_bytes: bytes,
                    measure_one_way_latency: false,
                    reflect: false,
                },
            },
        )
        .await
        .unwrap();
        let submitted = request(
            &self.configs[source],
            &AdminRequest::SendProbe {
                probe: SendProbe {
                    destination: self.npubs[destination].clone(),
                    stream_id,
                    packet_count: count,
                    payload_bytes: bytes,
                    packets_per_second: rate,
                    measure_round_trip: false,
                },
            },
        )
        .await
        .unwrap();
        // Enqueue success is not a delivery receipt. A stopped sender cannot
        // stand in for the separate admission and receiver assertions below.
        let report = &submitted["probe"];
        assert_eq!(
            report["stopped_reason"],
            Value::Null,
            "probe sender stopped before admission could be tested: {submitted}"
        );
        assert_eq!(report["submitted_packets"], count);
        assert_eq!(report["submitted_bytes"], u64::from(count) * bytes as u64);
        submitted
    }

    pub async fn expect_denied(&self, source: usize, destination: usize) {
        self.assert_carriers().await;
        self.send_probe(source, destination, 2, 256, 4).await;
        let until = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let status = request(&self.configs[destination], &AdminRequest::Status)
                .await
                .unwrap();
            assert_eq!(
                status["probe"]["unique_packets"], 0,
                "unfunded/exhausted traffic delivered"
            );
            assert_eq!(status["probe"]["invalid_packets"], 0);
            if tokio::time::Instant::now() >= until {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        self.assert_carriers().await;
    }

    pub async fn deliver(&self, source: usize, destination: usize) {
        // Application retries stay separately billable, as in the existing
        // process restart fixture. No transport ACK is a payment receipt.
        for _ in 0..3 {
            self.send_probe(source, destination, 2, 128, 4).await;
            if tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let status = request(&self.configs[destination], &AdminRequest::Status)
                        .await
                        .unwrap();
                    if status["probe"]["unique_packets"] == 2 {
                        assert_eq!(status["probe"]["invalid_packets"], 0);
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .is_ok()
            {
                return;
            }
        }
        panic!("paid mixed-carrier delivery {source}->{destination} timed out");
    }

    pub async fn wait_paid(&self, channel: &str) {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let ledger: Value = serde_json::from_slice(
                    &std::fs::read(self.configs[1].state_directory.join("seller/ledger.json"))
                        .unwrap(),
                )
                .unwrap();
                let usage = &ledger["ledger"]["channels"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["terms"]["id"] == channel)
                    .unwrap()["usage"];
                let submitted = usage["submitted_msat"].as_u64().unwrap();
                if submitted > 0 && usage["paid_msat"].as_u64().unwrap() >= submitted {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("automatic payment reaches relay");
    }

    pub async fn wait_exhausted(&self, source: usize) {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let status = request(&self.configs[source], &AdminRequest::Status)
                    .await
                    .unwrap();
                let remaining = status["remaining_budget_sat"].as_u64().unwrap();
                assert!(
                    remaining >= 56,
                    "first channel exceeded its eight-sat capacity"
                );
                if remaining == 56 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("first channel authorizes its full eight-sat capacity with renewals paused");
    }

    pub async fn wait_replacements(&self, old_channels: &[String]) {
        tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                let statuses = self.states().await;
                if [0, 2].into_iter().zip(old_channels).all(|(source, old)| {
                    let purchases = statuses[source]["purchases"].as_array().unwrap();
                    purchases.len() == 1
                        && purchases[0]["channel"]["id"].as_str().unwrap() != old.as_str()
                }) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("explicitly resumed renewals replace both exhausted channels");
    }
}
