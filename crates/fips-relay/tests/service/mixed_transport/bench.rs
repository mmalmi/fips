use cashu_service::{create_topup_quote, load_wallet_overview, simulation::PaymentNetwork};
use fips_core::config::{PeerConfig, TcpConfig, TransportInstances, UdpConfig, WebSocketConfig};
use fips_relay::{
    control_transport::NeighborAdmission,
    controller::RenewalPolicy,
    ledger::BillingBasis,
    probe::{ReceiveProbe, SendProbe},
    service::{AdminRequest, ServiceConfig, native_request, request},
};
use serde_json::{Value, json};
use std::{
    io::{Read, Seek, SeekFrom},
    net::{SocketAddr, TcpListener, UdpSocket},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::process::Child;

use super::tls::TlsProxy;
use crate::process_support::{command, config, ready, start};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecondHop {
    Tcp,
    WebSocket,
    WebSocketSeed,
    WebSocketTls,
}

impl SecondHop {
    pub fn kind(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::WebSocket | Self::WebSocketSeed | Self::WebSocketTls => "websocket",
        }
    }

    fn address(self, socket: SocketAddr) -> String {
        match self {
            Self::Tcp => socket.to_string(),
            Self::WebSocket | Self::WebSocketSeed | Self::WebSocketTls => {
                format!("ws://{socket}/fips")
            }
        }
    }

    fn is_seed(self) -> bool {
        matches!(self, Self::WebSocketSeed | Self::WebSocketTls)
    }
}

pub struct MixedBench {
    _root: tempfile::TempDir,
    pub configs: Vec<ServiceConfig>,
    pub paths: Vec<PathBuf>,
    pub npubs: Vec<String>,
    pub children: Vec<Child>,
    pub tls: Option<TlsProxy>,
    second_hop: SecondHop,
    next_probe: AtomicU64,
    stage: &'static str,
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
        let tls = if second_hop == SecondHop::WebSocketTls {
            Some(TlsProxy::start(root.path(), tcp[0].local_addr().unwrap()).await)
        } else {
            None
        };
        let seed_url = tls.as_ref().map_or_else(
            || second_hop.address(tcp[0].local_addr().unwrap()),
            |proxy| proxy.url.clone(),
        );
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
                    SecondHop::WebSocket | SecondHop::WebSocketSeed | SecondHop::WebSocketTls => {
                        config.transports.websocket = TransportInstances::Single(WebSocketConfig {
                            bind_addr: if second_hop.is_seed() && node == 2 {
                                None
                            } else {
                                bind_addr
                            },
                            seed_urls: if second_hop.is_seed() && node == 2 {
                                vec![seed_url.clone()]
                            } else {
                                Vec::new()
                            },
                            ..Default::default()
                        });
                    }
                }
                if second_hop.is_seed() {
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
        if !second_hop.is_seed() {
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
            assert_eq!(client.seed_urls, vec![seed_url]);
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
        for (node, path) in paths.iter().enumerate() {
            children.push(
                if let Some(proxy) = &tls
                    && node == 2
                {
                    proxy.assert_rejections(&configs[node], path).await;
                    proxy.start_client(path).await
                } else {
                    start(path).await
                },
            );
        }
        ready(&configs, &paths, &npubs, &mut children).await;
        Self {
            _root: root,
            configs,
            paths,
            npubs,
            children,
            tls,
            second_hop,
            next_probe: AtomicU64::new(1),
            stage: "other-mixed-fixture",
        }
    }

    pub fn set_stage(&mut self, stage: &'static str) {
        self.stage = stage;
        eprintln!(
            "mixed-carrier stage={stage} second_hop={:?}",
            self.second_hop
        );
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
        if self.second_hop.is_seed() {
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
        // Failure is latched before these read-only observations. They cannot
        // retry or rescue this cohort, and sequential samples are not atomic.
        self.delivery_failure(source, destination).await;
        panic!(
            "paid mixed-carrier delivery {source}->{destination} timed out at stage={} second_hop={:?}",
            self.stage, self.second_hop
        );
    }

    async fn delivery_failure(&self, source: usize, destination: usize) {
        eprintln!(
            "mixed-carrier delivery-failure stage={} second_hop={:?} flow={source}->{destination} attempts=3",
            self.stage, self.second_hop
        );
        let captured = tokio::time::timeout(Duration::from_secs(4), async {
            for (node, config) in self.configs.iter().enumerate() {
                daemon_tail(node, &self.paths[node].with_extension("log"));
                match tokio::time::timeout(
                    Duration::from_millis(250),
                    request(config, &AdminRequest::Status),
                ).await {
                    Ok(Ok(status)) => {
                        let mut safe = selected(&status, &[
                            "peers", "funding_budget", "remaining_budget_sat", "locked_sat",
                            "probe", "data_carrier", "control_traffic", "payment_progress",
                        ]);
                        safe["last_error_present"] = json!(!status["last_error"].is_null());
                        safe["history_count"] = json!(status["history"].as_array().map(Vec::len));
                        safe["purchases"] = json!(status["purchases"].as_array().map(|rows| rows.iter().map(|row| json!({
                            "provider": row["provider"],
                            "channel": selected(&row["channel"], &["id", "capacity_sat", "expires_unix"]),
                            "contract": selected(&row["contract"], &["id", "destination", "next_hop", "expires_unix", "max_units", "billing"]),
                        })).collect::<Vec<_>>()));
                        diagnostic(node, "service-status", &safe);
                    }
                    _ => diagnostic(node, "service-status", &json!({"unavailable": true})),
                }
                // Never serialize the journal: it contains wallet material.
                // Project only the saved route phases and renewal switches.
                let journal = std::fs::File::open(config.state_directory.join("controller/controller.json"))
                    .ok().and_then(|file| {
                        let mut bytes = Vec::new();
                        file.take(1_048_577).read_to_end(&mut bytes).ok()?;
                        if bytes.len() > 1_048_576 { return None; }
                        serde_json::from_slice::<Value>(&bytes).ok()
                    });
                if let Some(journal) = journal {
                    let mut safe = selected(&journal, &["renewals_paused", "selling_stopped"]);
                    for (field, keys) in [
                        ("outgoing", &["accepted", "retired"][..]),
                        ("incoming", &["phase", "verified_paid_msat", "replacement_retired"][..]),
                        ("renewals", &["completed"][..]),
                        ("watched_routes", &["paused", "billing", "max_rate_msat_per_kib"][..]),
                    ] {
                        safe[field] = json!(journal[field].as_object().map(|rows| rows.iter().take(16)
                            .map(|(id, row)| json!({"id": id, "state": selected(row, keys)})).collect::<Vec<_>>()));
                    }
                    diagnostic(node, "controller-phases", &safe);
                } else {
                    diagnostic(node, "controller-phases", &json!({"unavailable": true}));
                }
                for command in ["show_connections", "show_tree", "show_routing", "show_sessions", "show_transports"] {
                    match tokio::time::timeout(Duration::from_millis(250), native_request(config, &json!({"command": command}))).await {
                        Ok(Ok(reply)) if reply["status"] == "ok" => diagnostic(node, command, &reply["data"]),
                        _ => diagnostic(node, command, &json!({"unavailable": true})),
                    }
                }
            }
        }).await;
        if captured.is_err() {
            eprintln!("mixed-carrier failure diagnostics reached their four-second budget");
        }
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

fn selected(value: &Value, fields: &[&str]) -> Value {
    Value::Object(
        fields
            .iter()
            .map(|field| ((*field).to_owned(), value[*field].clone()))
            .collect(),
    )
}

fn diagnostic(node: usize, label: &str, value: &Value) {
    let text = value.to_string();
    let bounded: String = text.chars().take(4096).collect();
    eprintln!(
        "mixed-carrier diagnostic node={node} query={label} truncated={} {bounded}",
        bounded.len() < text.len()
    );
}

fn daemon_tail(node: usize, path: &std::path::Path) {
    let tail = (|| -> std::io::Result<Vec<u8>> {
        let mut file = std::fs::File::open(path)?;
        let start = file.metadata()?.len().saturating_sub(8192);
        file.seek(SeekFrom::Start(start))?;
        let mut bytes = Vec::new();
        file.take(8192).read_to_end(&mut bytes)?;
        // Discard a possibly partial first line rather than print a suffix of
        // a sensitive record without the label used by the filter below.
        if start > 0 {
            let end = bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |i| i + 1);
            bytes.drain(..end);
        }
        Ok(bytes)
    })();
    let Ok(bytes) = tail else {
        diagnostic(node, "daemon-tail", &json!({"unavailable": true}));
        return;
    };
    let text = String::from_utf8_lossy(&bytes);
    let mut lines: Vec<_> = text.lines().rev().take(20).collect();
    lines.reverse();
    for line in lines {
        let lower = line.to_ascii_lowercase();
        let sensitive = [
            "cashua",
            "cashub",
            "nsec",
            "secret",
            "proof",
            "signature",
            "private_key",
            "seed_phrase",
            "seed_words",
            "access_token",
            "bearer",
        ]
        .iter()
        .any(|word| lower.contains(word))
            || line.split_whitespace().any(|word| word.len() > 256);
        eprintln!(
            "mixed-carrier daemon-tail node={node} {}",
            if sensitive {
                "[sensitive or oversized log line omitted]"
            } else {
                line
            }
        );
    }
}
