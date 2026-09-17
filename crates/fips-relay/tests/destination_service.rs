#![cfg(unix)]
use cashu_service::{
    create_topup_quote, load_mint_balance, load_wallet_overview,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use fips_core::config::PeerConfig;
use fips_relay::{
    ledger::BillingBasis,
    route_quotes::PriceSelectionPolicy,
    service::{AdminRequest, ServiceConfig, native_request, request},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Child,
};
mod process_support;
#[path = "process_support/quality.rs"]
mod quality;
#[path = "destination_service/upkeep.rs"]
mod upkeep;
use process_support::*;

#[derive(Clone, Copy)]
enum Pricing {
    OwnDestination,
    MixedDestinations,
    Defaults { fees: [u64; 5], ceilings: [u64; 5] },
}

struct OfflineMint {
    url: String,
    contacts: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl OfflineMint {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let contacts = Arc::new(AtomicUsize::new(0));
        let counter = contacts.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0; 4096];
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
            }
        });
        Self {
            url,
            contacts,
            task,
        }
    }

    fn assert_unused(&self) {
        assert_eq!(
            self.contacts.load(Ordering::SeqCst),
            0,
            "free routing must not contact a mint"
        );
    }
}

impl Drop for OfflineMint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Bench {
    _root: tempfile::TempDir,
    configs: Vec<ServiceConfig>,
    paths: Vec<PathBuf>,
    npubs: Vec<String>,
    children: Vec<Child>,
}

impl Bench {
    async fn start(mint: &str, pricing: Pricing) -> Self {
        Self::start_with_mints(std::array::from_fn(|_| mint.to_owned()), pricing, None).await
    }

    async fn start_with_mints(
        mints: [String; 5],
        pricing: Pricing,
        selection: Option<PriceSelectionPolicy>,
    ) -> Self {
        Self::start_configured(mints, pricing, selection, |_, _| {}).await
    }

    async fn start_configured(
        mints: [String; 5],
        pricing: Pricing,
        selection: Option<PriceSelectionPolicy>,
        mut configure: impl FnMut(usize, &mut ServiceConfig),
    ) -> Self {
        let root = tempfile::tempdir().unwrap();
        let (mut configs, mut paths, mut npubs, mut sockets) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for i in 0..5 {
            let directory = root.path().join(format!("n{i}"));
            std::fs::create_dir(&directory).unwrap();
            let mut cfg = config(&directory, &mints[i]);
            cfg.terms.billing = BillingBasis::ForwardingData;
            cfg.return_allowance = matches!(pricing, Pricing::OwnDestination);
            if i == 0 {
                cfg.price_selection = selection.clone();
            }
            if let Pricing::Defaults { fees, ceilings } = pricing {
                // These are immutable saved terms, so choose them before init.
                cfg.terms.fee_msat_per_kib = fees[i];
                cfg.terms.max_rate_msat_per_kib = ceilings[i];
            }
            configure(i, &mut cfg);
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            cfg.transports = udp_transports(socket.local_addr().unwrap());
            sockets.push(socket);
            let path = directory.join("config.json");
            std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
            let output = command(&path, "init").await;
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            npubs.push(String::from_utf8(output.stdout).unwrap().trim().to_owned());
            configs.push(cfg);
            paths.push(path);
        }
        let addresses: Vec<_> = configs.iter().map(udp_bind).collect();
        for (i, cfg) in configs.iter_mut().enumerate() {
            // Rules live outside immutable financial terms: new offers can
            // change without editing or discarding old account records.
            if !matches!(pricing, Pricing::Defaults { .. }) {
                let mut fees = json!({npubs[4].clone(): 0});
                if matches!(pricing, Pricing::MixedDestinations) && i == 1 {
                    fees[npubs[3].clone()] = 0.into();
                }
                if matches!(pricing, Pricing::MixedDestinations) && i == 2 {
                    fees[npubs[3].clone()] = 2_048.into();
                }
                cfg.destination_fees = serde_json::from_value(fees).unwrap();
            }
            cfg.neighbors = npubs
                .iter()
                .enumerate()
                .filter(|(j, _)| i.abs_diff(*j) == 1)
                .map(|(j, p)| PeerConfig::new(p, "udp", addresses[j].to_string()))
                .collect();
            std::fs::write(&paths[i], serde_json::to_vec(cfg).unwrap()).unwrap();
        }
        drop(sockets);
        let mut bench = Self {
            _root: root,
            configs,
            paths,
            npubs,
            children: Vec::new(),
        };
        for path in &bench.paths {
            bench.children.push(start(path).await);
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        ready(
            &bench.configs,
            &bench.paths,
            &bench.npubs,
            &mut bench.children,
        )
        .await;
        bench.wait_selection_topology("startup", deadline).await;
        bench
    }

    async fn native_topology(&self) -> Vec<Value> {
        let mut nodes = Vec::new();
        for config in &self.configs {
            let mut node = json!({});
            for (field, command) in [("tree", "show_tree"), ("bloom", "show_bloom")] {
                node[field] = match native_request(config, &json!({"command": command})).await {
                    Ok(response) => response["data"].clone(),
                    Err(error) => json!({"error": error}),
                };
            }
            nodes.push(node);
        }
        nodes
    }

    async fn wait_selection_topology(&self, phase: &str, deadline: tokio::time::Instant) {
        if self.configs[0].price_selection.is_none() {
            return;
        }
        // Selection has a bounded quote fanout. Connected links alone do not
        // establish that transit discovery has a mutually consistent tree.
        let mut observed = Vec::new();
        tokio::time::timeout_at(deadline, async {
            loop {
                observed = self.native_topology().await;
                if line_topology_ready(&observed) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{phase}: native line topology did not converge: {observed:?}"));
    }

    async fn states(&self) -> Vec<Value> {
        let mut states = Vec::new();
        for cfg in &self.configs {
            states.push(request(cfg, &AdminRequest::Status).await.unwrap());
        }
        states
    }

    async fn open(&self, destination: usize) -> Value {
        self.open_at(destination, "explicit open").await
    }

    async fn open_at(&self, destination: usize, phase: &str) -> Value {
        match request(
            &self.configs[0],
            &AdminRequest::Buy {
                destination: self.npubs[destination].clone(),
            },
        )
        .await
        {
            Ok(offer) => offer,
            Err(error) => panic!(
                "{phase}: destination {destination} open failed: {error}; topology: {:?}",
                self.native_topology().await
            ),
        }
    }

    async fn send(&self, destination: usize, payload: &str) {
        request(
            &self.configs[0],
            &AdminRequest::Send {
                destination: self.npubs[destination].clone(),
                payload: payload.into(),
            },
        )
        .await
        .unwrap();
    }

    async fn deliver(&self, destination: usize, label: &str) {
        let payload = format!("{label}{}", "x".repeat(900));
        let digest = format!("{:x}", Sha256::digest(payload.as_bytes()));
        for _ in 0..6 {
            self.send(destination, &payload).await;
            if tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let s = request(&self.configs[destination], &AdminRequest::Status)
                        .await
                        .unwrap();
                    if s["received"]["last_sha256"] == digest {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
            })
            .await
            .is_ok()
            {
                return;
            }
        }
        panic!(
            "destination {destination} did not receive {label}: {:?}",
            self.states().await
        );
    }

    async fn restart(&mut self) {
        for child in &mut self.children {
            stop(child).await;
        }
        for (i, child) in self.children.iter_mut().enumerate() {
            *child = start(&self.paths[i]).await;
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        ready(&self.configs, &self.paths, &self.npubs, &mut self.children).await;
        self.wait_selection_topology("restart", deadline).await;
    }

    async fn stop(&mut self) {
        for child in &mut self.children {
            stop(child).await;
        }
    }
}

fn line_topology_ready(nodes: &[Value]) -> bool {
    let Some(root) = nodes.first().and_then(|n| n["tree"]["root"].as_str()) else {
        return false;
    };
    nodes.iter().enumerate().all(|(i, node)| {
        let tree = &node["tree"];
        let (Some(peers), Some(filters)) = (
            tree["peers"].as_array(),
            node["bloom"]["peer_filters"].as_array(),
        ) else {
            return false;
        };
        let neighbors: Vec<_> = nodes
            .iter()
            .enumerate()
            .filter(|(j, _)| i.abs_diff(*j) == 1)
            .collect();
        tree["root"] == root
            && peers.len() == neighbors.len()
            && filters.len() == neighbors.len()
            && neighbors.into_iter().all(|(_, neighbor)| {
                let remote = &neighbor["tree"];
                peers.iter().any(|peer| {
                    peer["node_addr"] == remote["my_node_addr"]
                        && peer["root"] == root
                        && peer["coords"].is_array()
                        && peer["coords"] == remote["my_coords"]
                }) && filters.iter().any(|filter| {
                    filter["peer"] == remote["my_node_addr"]
                        && filter["has_filter"] == true
                        && filter["set_bits"].as_u64().is_some_and(|bits| bits > 0)
                })
            })
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn own_destination_crosses_three_relays_without_funding_or_contacting_a_mint() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let mint = OfflineMint::start().await;
        let mut bench = Bench::start(&mint.url, Pricing::OwnDestination).await;
        for epoch in ["first", "after restart"] {
            let offer = bench.open(4).await;
            assert!(offer["purchase"].is_null());
            assert_eq!(offer["free_route"]["price"]["msat"], 0);
            bench.deliver(4, epoch).await;
            quality::assert_quality(&bench.configs[0], &bench.npubs[4]).await;
            bench.send(3, "unpaid neighboring destination").await;
            tokio::time::sleep(Duration::from_millis(500)).await;
            let states = bench.states().await;
            assert_eq!(states[3]["received"]["packets"], 0);
            for state in &states {
                assert!(state["history"].as_array().unwrap().is_empty());
                assert_eq!(state["locked_sat"], 0);
                assert_eq!(state["remaining_budget_sat"], 64);
            }
            for state in &states[1..4] {
                assert!(state["free_routes"]["admitted_packets"].as_u64().unwrap() > 0);
            }
            if epoch == "first" {
                bench.restart().await;
            }
        }
        mint.assert_unused();
        for cfg in &bench.configs {
            assert!(
                request(cfg, &AdminRequest::Settle).await.unwrap()["settlements"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
        }
        bench.stop().await;
        mint.assert_unused();
    })
    .await
    .expect("offline free destination deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn free_destinations_zero_margin_resale_and_a_paid_prefix_coexist() {
    tokio::time::timeout(Duration::from_secs(240), async {
        let mint_root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(99, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            mint_root.path(),
            network.clone(),
            "destination-test",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let mut bench = Bench::start(mint.url(), Pricing::MixedDestinations).await;
        bench.open(4).await;
        bench.deliver(4, "unfunded free path").await;
        for cfg in &bench.configs[..2] {
            let wallet = cfg.state_directory.join("wallet");
            let quote = create_topup_quote(&wallet, mint.url(), 256).await.unwrap();
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
        }
        let purchase = bench.open(3).await;
        assert_eq!(
            purchase["purchase"]["contract"]["price"]["msat"], 2_048,
            "first relay's zero markup must not waive downstream price"
        );
        bench.deliver(3, "custom paid destination").await;
        let default = bench.open(2).await;
        assert_eq!(default["purchase"]["contract"]["price"]["msat"], 1_024);
        bench.deliver(2, "default destination fee").await;
        bench.deliver(4, "free while paid routes exist").await;
        let old = bench.states().await;
        bench.configs[1].destination_fees = serde_json::from_value(
            json!({bench.npubs[4].clone(): 1_024, bench.npubs[3].clone(): 0}),
        )
        .unwrap();
        std::fs::write(
            &bench.paths[1],
            serde_json::to_vec(&bench.configs[1]).unwrap(),
        )
        .unwrap();
        bench.restart().await;
        let new = bench.states().await;
        for (a, b) in old.iter().zip(&new) {
            assert_eq!(a["history"], b["history"]);
            assert_eq!(a["locked_sat"], b["locked_sat"]);
            assert!(
                b["remaining_budget_sat"].as_u64().unwrap()
                    <= a["remaining_budget_sat"].as_u64().unwrap()
            );
        }
        bench
            .send(4, "changed free route must not purchase automatically")
            .await;
        tokio::time::sleep(Duration::from_millis(600)).await;
        let unchanged = bench.states().await;
        assert_eq!(unchanged[4]["received"]["packets"], 0);
        assert_eq!(unchanged[0]["history"], new[0]["history"]);
        let prefix = bench.open(4).await;
        assert_eq!(prefix["purchase"]["contract"]["price"]["msat"], 1_024);
        bench.deliver(4, "paid prefix free tail").await;
        bench.open(3).await;
        bench.deliver(3, "preserved prior paid agreement").await;
        let states = bench.states().await;
        assert!(
            states[2]["purchases"].as_array().unwrap().is_empty(),
            "free continuation must never open a downstream channel"
        );
        let mut channels = 0;
        for cfg in &bench.configs {
            channels += request(cfg, &AdminRequest::Settle).await.unwrap()["settlements"]
                .as_array()
                .unwrap()
                .len();
        }
        assert_eq!(
            channels, 2,
            "destination quotes share the same two funded neighbor channels"
        );
        bench.stop().await;
        let mut total = 0;
        for (i, cfg) in bench.configs.iter().enumerate() {
            let balance = load_mint_balance(&cfg.state_directory.join("wallet"), mint.url())
                .await
                .unwrap()
                .balance_sat;
            if i == 1 {
                assert!(balance > 256);
            }
            if i == 2 {
                assert!(balance > 0);
            }
            if i >= 3 {
                assert_eq!(balance, 0);
            }
            total += balance;
        }
        assert_eq!(total, 512);
        assert!(network.accounting().unwrap().is_conserved());
    })
    .await
    .expect("mixed destination pricing deadline");
}

fn monetary_journals(config: &ServiceConfig) -> Value {
    let read = |relative: &str| -> Value {
        serde_json::from_slice(&std::fs::read(config.state_directory.join(relative)).unwrap())
            .unwrap()
    };
    let mut controller = read("controller/controller.json");
    // Lifecycle switches are asserted separately from financial operations.
    controller
        .as_object_mut()
        .unwrap()
        .remove("selling_stopped");
    controller
        .as_object_mut()
        .unwrap()
        .remove("renewals_paused");
    // Free source authorizations are checked separately, including on restart.
    controller.as_object_mut().unwrap().remove("watched_routes");
    json!({
        "buyer": read("buyer/buyer.json"),
        "seller": read("seller/ledger.json"),
        "controller": controller,
    })
}

fn assert_free_lifecycle(bench: &Bench, destinations: &[usize], renewals_paused: bool) {
    for (i, config) in bench.configs.iter().enumerate() {
        let mut expected = json!({});
        if i == 0 && config.price_selection.is_some() {
            for &destination in destinations {
                let npub = &bench.npubs[destination];
                expected[npub] = json!({
                    "billing": BillingBasis::ForwardingData,
                    "destination": npub,
                    "max_rate_msat_per_kib": 0,
                    "paused": true,
                    "pending": null,
                });
            }
        }
        let saved: Value = serde_json::from_slice(
            &std::fs::read(config.state_directory.join("controller/controller.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(saved["renewals_paused"], renewals_paused);
        assert_eq!(saved["selling_stopped"], false);
        assert_eq!(
            saved["watched_routes"], expected,
            "node {i}'s source authorization changed"
        );
    }
}

async fn assert_unfunded(bench: &Bench, original: &[Value]) {
    for (i, (config, state)) in bench.configs.iter().zip(bench.states().await).enumerate() {
        assert!(state["purchases"].as_array().unwrap().is_empty());
        assert!(state["history"].as_array().unwrap().is_empty());
        assert_eq!(state["remaining_budget_sat"], 64);
        assert_eq!(state["locked_sat"], 0);
        for amount in state["funding_budget"].as_object().unwrap().values() {
            assert_eq!(amount, 0);
        }
        let saved = monetary_journals(config);
        assert!(saved["buyer"]["channels"].as_object().unwrap().is_empty());
        assert!(saved["buyer"]["quotes"].as_object().unwrap().is_empty());
        assert!(
            saved["seller"]["ledger"]["channels"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            saved["seller"]["ledger"]["accounts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            saved, original[i],
            "free access changed node {i}'s financial journal"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zero_default_forwards_arbitrary_destinations_without_payment_or_shared_mint() {
    assert_default_free(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zero_default_with_price_selection_recovers_without_mint_contact() {
    assert_default_free(Some(PriceSelectionPolicy::default())).await;
}

async fn assert_default_free(selection: Option<PriceSelectionPolicy>) {
    tokio::time::timeout(Duration::from_secs(180), async {
        let mint = OfflineMint::start().await;
        let mut bench = Bench::start_with_mints(
            std::array::from_fn(|i| format!("{}/mint-{i}", mint.url)),
            Pricing::Defaults {
                fees: [0; 5],
                ceilings: [0; 5],
            },
            selection,
        )
        .await;
        let original: Vec<_> = bench.configs.iter().map(monetary_journals).collect();
        for config in &bench.configs {
            assert!(config.destination_fees.is_empty());
            assert!(!config.return_allowance);
        }
        assert_free_lifecycle(&bench, &[], false);
        for epoch in ["first", "after restart"] {
            for state in bench.states().await {
                assert_eq!(state["free_routes"]["incoming_leases"], 0);
                assert_eq!(state["free_routes"]["outgoing_leases"], 0);
            }
            for destination in [3, 4] {
                let offer = bench.open_at(destination, epoch).await;
                assert!(offer["purchase"].is_null());
                assert_eq!(offer["free_route"]["price"]["msat"], 0);
                bench
                    .deliver(destination, &format!("{epoch} destination {destination}"))
                    .await;
            }
            for state in &bench.states().await[1..4] {
                assert!(state["free_routes"]["admitted_packets"].as_u64().unwrap() > 0);
            }
            assert_free_lifecycle(&bench, &[3, 4], false);
            assert_unfunded(&bench, &original).await;
            mint.assert_unused();
            if epoch == "first" {
                bench.restart().await;
                assert_free_lifecycle(&bench, &[3, 4], false);
            }
        }
        for config in &bench.configs {
            assert!(
                request(config, &AdminRequest::Settle).await.unwrap()["settlements"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
        }
        // Even an empty Settle pauses renewals; it must not create any money state.
        assert_free_lifecycle(&bench, &[3, 4], true);
        assert_unfunded(&bench, &original).await;
        bench.stop().await;
        for config in &bench.configs {
            let balance = load_mint_balance(
                &config.state_directory.join("wallet"),
                &config.terms.controller.mint_url,
            )
            .await
            .unwrap();
            assert_eq!(balance.balance_sat, 0);
        }
        mint.assert_unused();
    })
    .await
    .expect("default-free multi-hop deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zero_price_ceiling_rejects_paid_prefix_without_funding() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let mint = OfflineMint::start().await;
        let mut bench = Bench::start(
            &mint.url,
            Pricing::Defaults {
                fees: [0, 1_024, 0, 0, 0],
                ceilings: [0, 1_024, 0, 0, 0],
            },
        )
        .await;
        let original: Vec<_> = bench.configs.iter().map(monetary_journals).collect();
        let result = request(
            &bench.configs[0],
            &AdminRequest::Buy {
                destination: bench.npubs[4].clone(),
            },
        )
        .await;
        assert!(
            result.is_err(),
            "zero ceiling must reject a positive aggregate quote"
        );
        bench
            .send(4, "rejected price must not create free access")
            .await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(bench.states().await[4]["received"]["packets"], 0);
        assert_free_lifecycle(&bench, &[], false);
        assert_unfunded(&bench, &original).await;
        bench.stop().await;
        mint.assert_unused();
    })
    .await
    .expect("zero ceiling rejection deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn default_priced_prefix_funds_one_channel_and_keeps_free_suffix_unfunded() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let mint_root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(100, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            mint_root.path(),
            network.clone(),
            "default-pricing-test",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let mut bench = Bench::start(
            mint.url(),
            Pricing::Defaults {
                fees: [0, 1_024, 0, 0, 0],
                ceilings: [1_024, 1_024, 0, 0, 0],
            },
        )
        .await;
        let tail: Vec<_> = bench.configs[2..].iter().map(monetary_journals).collect();
        let wallet = bench.configs[0].state_directory.join("wallet");
        let quote = create_topup_quote(&wallet, mint.url(), 256).await.unwrap();
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
        let purchase = bench.open(4).await;
        assert_eq!(purchase["purchase"]["contract"]["price"]["msat"], 1_024);
        bench
            .deliver(4, "one paid prefix followed by two free relays")
            .await;
        let states = bench.states().await;
        assert_eq!(states[0]["purchases"].as_array().unwrap().len(), 1);
        assert_eq!(states[0]["funding_budget"]["wallet_debited_sat"], 32);
        for state in &states[1..] {
            assert!(state["purchases"].as_array().unwrap().is_empty());
            assert!(state["history"].as_array().unwrap().is_empty());
            assert_eq!(state["locked_sat"], 0);
            assert_eq!(state["remaining_budget_sat"], 64);
            assert_eq!(state["funding_budget"]["wallet_debited_sat"], 0);
        }
        for state in &states[2..4] {
            assert!(state["free_routes"]["admitted_packets"].as_u64().unwrap() > 0);
        }
        for (config, original) in bench.configs[2..].iter().zip(&tail) {
            assert_eq!(&monetary_journals(config), original);
        }
        let mut channels = 0;
        for config in &bench.configs {
            channels += request(config, &AdminRequest::Settle).await.unwrap()["settlements"]
                .as_array()
                .unwrap()
                .len();
        }
        assert_eq!(
            channels, 1,
            "the free suffix must not create payment channels"
        );
        bench.stop().await;
        let mut total = 0;
        for (i, config) in bench.configs.iter().enumerate() {
            let balance = load_mint_balance(&config.state_directory.join("wallet"), mint.url())
                .await
                .unwrap()
                .balance_sat;
            if i == 1 {
                assert!(balance > 0, "paid relay must collect its fee");
            }
            if i >= 2 {
                assert_eq!(balance, 0);
            }
            total += balance;
        }
        assert_eq!(total, 256);
        assert!(network.accounting().unwrap().is_conserved());
    })
    .await
    .expect("default mixed pricing deadline");
}
