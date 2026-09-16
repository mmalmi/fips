#![cfg(unix)]
use cashu_service::{
    create_topup_quote, load_mint_balance, load_wallet_overview,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use fips_core::config::PeerConfig;
use fips_relay::{
    ledger::BillingBasis,
    service::{AdminRequest, ServiceConfig, request},
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
use process_support::*;

struct Bench {
    _root: tempfile::TempDir,
    configs: Vec<ServiceConfig>,
    paths: Vec<PathBuf>,
    npubs: Vec<String>,
    children: Vec<Child>,
}

impl Bench {
    async fn start(mint: &str, paid: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let (mut configs, mut paths, mut npubs, mut sockets) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for i in 0..5 {
            let directory = root.path().join(format!("n{i}"));
            std::fs::create_dir(&directory).unwrap();
            let mut cfg = config(&directory, mint);
            cfg.terms.billing = BillingBasis::ForwardingData;
            cfg.return_allowance = !paid;
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            cfg.udp_bind = Some(socket.local_addr().unwrap());
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
        let addresses: Vec<_> = configs.iter().map(|c| c.udp_bind.unwrap()).collect();
        for (i, cfg) in configs.iter_mut().enumerate() {
            // Rules live outside immutable financial terms: new offers can
            // change without editing or discarding old account records.
            let mut fees = json!({npubs[4].clone(): 0});
            if paid && i == 1 {
                fees[npubs[3].clone()] = 0.into();
            }
            if paid && i == 2 {
                fees[npubs[3].clone()] = 2_048.into();
            }
            cfg.destination_fees = serde_json::from_value(fees).unwrap();
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
        ready(
            &bench.configs,
            &bench.paths,
            &bench.npubs,
            &mut bench.children,
        )
        .await;
        bench
    }

    async fn states(&self) -> Vec<Value> {
        let mut states = Vec::new();
        for cfg in &self.configs {
            states.push(request(cfg, &AdminRequest::Status).await.unwrap());
        }
        states
    }

    async fn open(&self, destination: usize) -> Value {
        request(
            &self.configs[0],
            &AdminRequest::Buy {
                destination: self.npubs[destination].clone(),
            },
        )
        .await
        .unwrap()
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
        ready(&self.configs, &self.paths, &self.npubs, &mut self.children).await;
    }

    async fn stop(&mut self) {
        for child in &mut self.children {
            stop(child).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn own_destination_crosses_three_relays_without_funding_or_contacting_a_mint() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mint = format!("http://{}", listener.local_addr().unwrap());
        let contacts = Arc::new(AtomicUsize::new(0));
        let counter = contacts.clone();
        let mock = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0; 4096];
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
            }
        });
        let mut bench = Bench::start(&mint, false).await;
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
            for state in &states[1..4] { assert!(state["free_routes"]["admitted_packets"].as_u64().unwrap() > 0); }
            if epoch == "first" { bench.restart().await; }
        }
        assert_eq!(contacts.load(Ordering::SeqCst), 0, "free setup, traffic and restart must not need a mint");
        for cfg in &bench.configs {
            assert!(request(cfg, &AdminRequest::Settle).await.unwrap()["settlements"].as_array().unwrap().is_empty());
        }
        bench.stop().await;
        mock.abort();
    }).await.expect("offline free destination deadline");
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
        let mut bench = Bench::start(mint.url(), true).await;
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
