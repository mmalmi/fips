use cashu_service::{create_topup_quote, load_wallet_overview, simulation::PaymentNetwork};
use fips_core::config::{
    PeerConfig, TcpConfig, TransportInstances, UdpConfig, WebSocketConfig, WebSocketTlsVerification,
};
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
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::process::Child;

use super::{proxy::StreamProxy, tls::TlsProxy};
use crate::process_support::{command, config, ready, start};

#[path = "recovery.rs"]
mod recovery;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecondHop {
    Tcp,
    WebSocket,
    WebSocketSeed,
    WebSocketTls,
    WebSocketSelfSigned,
}

impl SecondHop {
    pub fn kind(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::WebSocket
            | Self::WebSocketSeed
            | Self::WebSocketTls
            | Self::WebSocketSelfSigned => "websocket",
        }
    }

    fn address(self, socket: SocketAddr) -> String {
        match self {
            Self::Tcp => socket.to_string(),
            Self::WebSocket
            | Self::WebSocketSeed
            | Self::WebSocketTls
            | Self::WebSocketSelfSigned => {
                format!("ws://{socket}/fips")
            }
        }
    }

    pub(super) fn is_seed(self) -> bool {
        matches!(
            self,
            Self::WebSocketSeed | Self::WebSocketTls | Self::WebSocketSelfSigned
        )
    }
}

pub struct MixedBench {
    _root: tempfile::TempDir,
    pub configs: Vec<ServiceConfig>,
    pub paths: Vec<PathBuf>,
    pub npubs: Vec<String>,
    pub children: Vec<Child>,
    pub tls: Option<TlsProxy>,
    proxy: Option<StreamProxy>,
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
        Self::start_configured(mint, network, second_hop, |_, _| {}).await
    }

    pub(super) async fn start_configured(
        mint: &str,
        network: &PaymentNetwork,
        second_hop: SecondHop,
        configure: impl Fn(usize, &mut ServiceConfig),
    ) -> Self {
        let root = tempfile::tempdir().unwrap();
        let udp: Vec<_> = (0..2)
            .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
            .collect();
        let tcp: Vec<_> = (0..2)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let tls = if matches!(
            second_hop,
            SecondHop::WebSocketTls | SecondHop::WebSocketSelfSigned
        ) {
            Some(
                TlsProxy::start(
                    root.path(),
                    tcp[0].local_addr().unwrap(),
                    second_hop == SecondHop::WebSocketSelfSigned,
                )
                .await,
            )
        } else {
            None
        };
        let proxy = if second_hop == SecondHop::WebSocketSeed {
            Some(StreamProxy::start(tcp[0].local_addr().unwrap(), None).await)
        } else {
            None
        };
        let seed_url = tls.as_ref().map_or_else(
            || {
                second_hop.address(
                    proxy
                        .as_ref()
                        .map_or_else(|| tcp[0].local_addr().unwrap(), |proxy| proxy.address),
                )
            },
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
                    SecondHop::WebSocket
                    | SecondHop::WebSocketSeed
                    | SecondHop::WebSocketTls
                    | SecondHop::WebSocketSelfSigned => {
                        config.transports.websocket = TransportInstances::Single(WebSocketConfig {
                            tls_verification: (second_hop == SecondHop::WebSocketSelfSigned
                                && node == 2)
                                .then_some(WebSocketTlsVerification::Fips),
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
            configure(node, &mut config);
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
            proxy,
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

    pub(super) fn seed_carrier(&self) -> Option<&StreamProxy> {
        self.proxy
            .as_ref()
            .or_else(|| self.tls.as_ref().map(TlsProxy::carrier))
    }

    pub async fn states(&self) -> Vec<Value> {
        let mut states = Vec::new();
        for config in &self.configs {
            states.push(request(config, &AdminRequest::Status).await.unwrap());
        }
        states
    }

    pub fn funding_intents(&self, renewals_paused: bool) -> Vec<serde_json::Map<String, Value>> {
        self.configs
            .iter()
            .map(|config| {
                let saved: Value = serde_json::from_slice(
                    &std::fs::read(config.state_directory.join("controller/controller.json"))
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(saved["renewals_paused"], renewals_paused);
                saved["funding"].as_object().unwrap().clone()
            })
            .collect()
    }

    pub async fn set_renewals_paused(&self, paused: bool) {
        let command = if paused {
            AdminRequest::PauseRenewals
        } else {
            AdminRequest::ResumeRenewals
        };
        for config in &self.configs {
            request(config, &command).await.unwrap();
        }
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
        let probe = self
            .prepare_probe(source, destination, count, bytes, rate)
            .await;
        self.submit_probe(source, probe).await
    }

    async fn prepare_probe(
        &self,
        source: usize,
        destination: usize,
        count: u32,
        bytes: usize,
        rate: u32,
    ) -> SendProbe {
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
                    lifetime_secs: None,
                    reflect: false,
                },
            },
        )
        .await
        .unwrap();
        SendProbe {
            destination: self.npubs[destination].clone(),
            stream_id,
            packet_count: count,
            payload_bytes: bytes,
            packets_per_second: rate,
            measure_round_trip: false,
            max_duration_secs: None,
        }
    }

    async fn submit_probe(&self, source: usize, probe: SendProbe) -> Value {
        let count = probe.packet_count;
        let bytes = probe.payload_bytes;
        let submitted = request(&self.configs[source], &AdminRequest::SendProbe { probe })
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

    pub(super) async fn send_bidirectional_probes(
        &self,
        endpoints: [usize; 2],
        count: u32,
        bytes: usize,
        rate: u32,
        pending: [bool; 2],
    ) {
        let mut probes = [None, None];
        // ReceiveProbe cannot replace receiver state while that endpoint sends.
        // Arm both directions before starting either concurrent sender.
        for direction in 0..2 {
            if pending[direction] {
                probes[direction] = Some(
                    self.prepare_probe(
                        endpoints[direction],
                        endpoints[1 - direction],
                        count,
                        bytes,
                        rate,
                    )
                    .await,
                );
            }
        }
        let send = |direction: usize, probe: Option<SendProbe>| async move {
            if let Some(probe) = probe {
                self.submit_probe(endpoints[direction], probe).await;
            }
        };
        let [first, second] = probes;
        tokio::join!(send(0, first), send(1, second));
    }

    pub(super) async fn deliver_bidirectional(&self, endpoints: [usize; 2]) {
        let mut pending = [true; 2];
        for _ in 0..3 {
            self.send_bidirectional_probes(endpoints, 2, 128, 4, pending)
                .await;
            let (first, second) = tokio::join!(
                async { !pending[0] || self.probe_delivered(endpoints[1]).await },
                async { !pending[1] || self.probe_delivered(endpoints[0]).await },
            );
            pending = [!first, !second];
            if pending == [false; 2] {
                return;
            }
        }
        let direction = if pending[0] { 0 } else { 1 };
        self.delivery_failure(endpoints[direction], endpoints[1 - direction])
            .await;
        panic!(
            "paid bidirectional delivery timed out at stage={}",
            self.stage
        );
    }

    async fn probe_delivered(&self, destination: usize) -> bool {
        tokio::time::timeout(Duration::from_secs(10), async {
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
        self.deliver_sized(source, destination, 128).await;
    }

    pub(super) async fn deliver_sized(&self, source: usize, destination: usize, bytes: usize) {
        self.deliver_cohorts(source, destination, bytes, 1).await;
    }

    pub(super) async fn deliver_cohorts(
        &self,
        source: usize,
        destination: usize,
        bytes: usize,
        cohorts: usize,
    ) {
        assert!((1..=3).contains(&cohorts));
        // Application retries stay separately billable, as in the existing
        // process restart fixture. No transport ACK is a payment receipt.
        for attempt in 0..3 {
            self.send_probe(source, destination, 2, bytes, 4).await;
            if self.probe_delivered(destination).await && attempt + 1 >= cohorts {
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

    pub(super) async fn delivery_failure(&self, source: usize, destination: usize) {
        eprintln!(
            "mixed-carrier delivery-failure stage={} second_hop={:?} flow={source}->{destination}",
            self.stage, self.second_hop
        );
        self.failure_snapshot().await;
    }

    pub(super) async fn failure_snapshot(&self) {
        let captured = tokio::time::timeout(Duration::from_secs(4), async {
            for (node, config) in self.configs.iter().enumerate() {
                daemon_tail(node, &self.paths[node].with_extension("log"));
                match tokio::time::timeout(
                    Duration::from_millis(250),
                    request(config, &AdminRequest::Status),
                ).await {
                    Ok(Ok(status)) => {
                        diagnostic(node, "admission-denials", &selected(
                            &status["measurements"], &["process_id", "admission_denials"],
                        ));
                        let mut safe = selected(&status, &[
                            "peers", "funding_budget", "remaining_budget_sat", "locked_sat",
                            "probe", "data_carrier", "control_traffic", "payment_progress", "bootstrap", "return_allowance",
                        ]);
                        safe["last_error_present"] = json!(!status["last_error"].is_null());
                        // Emit only known labels, never an arbitrary error that
                        // could contain wallet material or a remote response.
                        let error = status["last_error"].as_str();
                        let kind = error.map(|error| [
                            "control request timed out", "control transport stopped",
                            "control command queue is closed or full", "control stream closed",
                            "control request expired or canceled", "control stream ended before its record",
                            "control handler canceled request", "provider rejected usage",
                            "provider did not accept signed balance", "invalid usage response",
                            "invalid payment response", "payment signer failed:",
                            "channel capacity or lifetime spending budget exhausted",
                            "payment agreement expired", "accounting writer is suspended;",
                            "accounting journal I/O failed:",
                        ].into_iter().find(|label| error.starts_with(label)).unwrap_or("other"));
                        diagnostic(node, "controller-error", &json!({"kind": kind}));
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
                let journal = read_journal(&config.state_directory.join("controller/controller.json"));
                if let Some(journal) = journal {
                    diagnostic(node, "controller-phases", &controller_phases(&journal));
                } else {
                    diagnostic(node, "controller-phases", &json!({"unavailable": true}));
                }
                // This is the last durable snapshot, not live submission state.
                if let Some(journal) = read_journal(&config.state_directory.join("buyer/buyer.json")) {
                    let channels = json!(journal["channels"].as_object().map(|rows| rows.iter().take(16)
                        .map(|(id, row)| json!({
                            "id": id,
                            "state": selected(row, &["authorized_sat", "active", "retired"]),
                        })).collect::<Vec<_>>()));
                    diagnostic(node, "buyer-durable-channels", &channels);
                    let quotes = json!(journal["quotes"].as_object().map(|rows| rows.iter().take(16)
                        .map(|(id, row)| json!({
                            "id": id,
                            "contract": selected(&row["contract"], &["channel_id", "price", "billing"]),
                            "state": selected(row, &["active", "observed_units", "submitted_units", "completed"]),
                            "attempts": row["attempts"].as_array().map(|attempts| attempts.iter().take(16)
                                .map(|attempt| selected(attempt, &["units", "outcome"])).collect::<Vec<_>>()),
                        })).collect::<Vec<_>>()));
                    diagnostic(node, "buyer-durable-routes", &quotes);
                } else {
                    diagnostic(node, "buyer-durable-channels", &json!({"unavailable": true}));
                }
                if let Some(journal) = read_journal(&config.state_directory.join("seller/ledger.json")) {
                    let ledger = &journal["ledger"];
                    let mut safe = selected(&journal, &["window_msat", "ceilings"]);
                    safe["channels"] = json!(ledger["channels"].as_array().map(|rows| rows.iter().take(16)
                        .map(|row| json!({
                            "terms": selected(&row["terms"], &["id", "buyer", "capacity_sat", "grace_msat", "expires_unix"]),
                            "usage": row["usage"], "active": row["active"], "retired": row["retired"],
                        })).collect::<Vec<_>>()));
                    diagnostic(node, "seller-allowances", &safe);
                    let accounts = json!(ledger["accounts"].as_array().map(|rows| rows.iter().take(16)
                        .map(|row| json!({
                            "contract": selected(&row["contract"], &["id", "channel_id", "destination", "next_hop", "expires_unix", "max_units"]),
                            "usage": row["usage"], "active": row["active"], "completed": row["completed"],
                        })).collect::<Vec<_>>()));
                    diagnostic(node, "seller-routes", &accounts);
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
        self.wait_paid_beyond(channel, 0).await;
    }

    pub(super) fn relay_usage_msat(&self, channel: &str) -> (u64, u64) {
        let ledger: Value = serde_json::from_slice(
            &std::fs::read(self.configs[1].state_directory.join("seller/ledger.json")).unwrap(),
        )
        .unwrap();
        let usage = &ledger["ledger"]["channels"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["terms"]["id"] == channel)
            .unwrap()["usage"];
        (
            usage["submitted_msat"].as_u64().unwrap(),
            usage["paid_msat"].as_u64().unwrap(),
        )
    }

    pub(super) async fn wait_paid_beyond(&self, channel: &str, already_paid_msat: u64) {
        let result = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let (submitted, paid) = self.relay_usage_msat(channel);
                if submitted > already_paid_msat && paid >= submitted {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        if result.is_err() {
            let (submitted, paid) = self.relay_usage_msat(channel);
            eprintln!(
                "mixed-carrier payment-failure stage={} second_hop={:?} channel={channel} submitted_msat={submitted} paid_msat={paid} previous_paid_msat={already_paid_msat}",
                self.stage, self.second_hop
            );
            self.failure_snapshot().await;
            panic!("automatic payment reaches relay");
        }
    }

    pub async fn wait_exhausted(&self, source: usize, expected_remaining: u64) {
        let result = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let status = request(&self.configs[source], &AdminRequest::Status)
                    .await
                    .unwrap();
                let remaining = status["remaining_budget_sat"].as_u64().unwrap();
                assert!(
                    remaining >= expected_remaining,
                    "channel exceeded its authorized capacity"
                );
                if remaining == expected_remaining {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        if result.is_err() {
            self.failure_snapshot().await;
            panic!("channel authorizes its full capacity with renewals paused");
        }
    }

    pub async fn wait_replacements(&self, old_channels: &[String]) {
        let result = tokio::time::timeout(Duration::from_secs(40), async {
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
        .await;
        if result.is_err() {
            self.failure_snapshot().await;
            panic!("automatic renewals replace both channels");
        }
    }
}

pub(super) fn controller_phases(journal: &Value) -> Value {
    // Never serialize the journal: it contains wallet material. Settlement
    // observations expose only presence, not signed payments, reports or errors.
    let mut safe = selected(journal, &["renewals_paused", "selling_stopped"]);
    for (field, keys) in [
        ("outgoing", &["accepted", "retired"][..]),
        (
            "incoming",
            &["phase", "verified_paid_msat", "replacement_retired"][..],
        ),
        ("renewals", &["completed"][..]),
        (
            "watched_routes",
            &["paused", "billing", "max_rate_msat_per_kib"][..],
        ),
    ] {
        safe[field] = json!(journal[field].as_object().map(|rows| {
            rows.iter()
                .take(16)
                .map(|(id, row)| json!({"id": id, "state": selected(row, keys)}))
                .collect::<Vec<_>>()
        }));
    }
    safe["seller_settlements"] = json!(journal["seller_settlements"].as_object().map(|rows| {
        rows.iter()
            .take(16)
            .map(|(id, row)| {
                json!({
                    "id": id,
                    "has_payment": row["payment"].is_object(),
                    "has_report": row["report"].is_object(),
                })
            })
            .collect::<Vec<_>>()
    }));
    safe
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

fn read_journal(path: &Path) -> Option<Value> {
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(1_048_577).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= 1_048_576)
        .then(|| serde_json::from_slice(&bytes).ok())
        .flatten()
}
