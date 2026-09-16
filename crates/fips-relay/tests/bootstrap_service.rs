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
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
mod process_support;
use process_support::*;

async fn statuses(configs: &[ServiceConfig]) -> Vec<Value> {
    let mut result = Vec::new();
    for cfg in configs {
        result.push(request(cfg, &AdminRequest::Status).await.unwrap());
    }
    result
}

async fn send(
    configs: &[ServiceConfig],
    npubs: &[String],
    source: usize,
    destination: usize,
    payload: &str,
) {
    request(
        &configs[source],
        &AdminRequest::Send {
            destination: npubs[destination].clone(),
            payload: payload.into(),
        },
    )
    .await
    .unwrap();
}

async fn deliver(configs: &[ServiceConfig], npubs: &[String], epoch: u8) {
    let payload = format!("{epoch}:{}", "x".repeat(900));
    let digest = format!("{:x}", Sha256::digest(payload.as_bytes()));
    // Match the existing service test's native discovery/restart retry budget.
    // These are application retries; every submitted data attempt is billable.
    for _ in 0..6 {
        send(configs, npubs, 0, 4, &payload).await;
        if tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let status = request(&configs[4], &AdminRequest::Status).await.unwrap();
                if status["received"]["last_sha256"] == digest {
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
        "one-way paid delivery failed: {:?}",
        statuses(configs).await
    );
}

fn payment_counts(states: &[Value]) -> Vec<(u64, u64)> {
    states
        .iter()
        .map(|status| {
            let row = status["control_traffic"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["service_port"] == 44_743)
                .unwrap();
            (
                row["counters"]["requests_started"].as_u64().unwrap(),
                row["counters"]["requests_received"].as_u64().unwrap(),
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_way_purchase_delivers_to_an_empty_wallet_across_a_full_restart() {
    tokio::time::timeout(Duration::from_secs(240), async {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(97, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "bootstrap-test",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let (mut configs, mut paths, mut npubs, mut reservations) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for i in 0..5 {
            let directory = root.path().join(format!("n{i}"));
            std::fs::create_dir(&directory).unwrap();
            let mut cfg = config(&directory, mint.url());
            cfg.terms.billing = BillingBasis::ForwardingData;
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            cfg.udp_bind = Some(socket.local_addr().unwrap());
            reservations.push(socket);
            let path = directory.join("config.json");
            std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
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
            // Source and relays have test capital; the final recipient has none.
            if i < 4 {
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
            configs.push(cfg);
            paths.push(path);
        }
        let addresses: Vec<_> = configs.iter().map(|c| c.udp_bind.unwrap()).collect();
        for (i, cfg) in configs.iter_mut().enumerate() {
            cfg.neighbors = npubs
                .iter()
                .enumerate()
                .filter(|(j, _)| i.abs_diff(*j) == 1)
                .map(|(j, p)| PeerConfig::new(p, "udp", addresses[j].to_string()))
                .collect();
            std::fs::write(&paths[i], serde_json::to_vec(cfg).unwrap()).unwrap();
        }
        drop(reservations);
        let mut children = Vec::new();
        for path in &paths {
            children.push(start(path).await);
        }
        ready(&configs, &paths, &npubs, &mut children).await;
        send(&configs, &npubs, 0, 4, "unpaid data must not pass").await;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let states = statuses(&configs).await;
                if states[1..4]
                    .iter()
                    .all(|s| s["bootstrap"]["admitted_packets"].as_u64().unwrap() >= 3)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("unpaid handshake should cross all three relays");
        for status in statuses(&configs).await {
            assert_eq!(status["locked_sat"], 0);
            assert_eq!(status["remaining_budget_sat"], 64);
            assert!(status["purchases"].as_array().unwrap().is_empty());
            assert_eq!(status["received"]["packets"], 0);
        }
        let purchased = request(
            &configs[0],
            &AdminRequest::Buy {
                destination: npubs[4].clone(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            purchased["purchase"]["contract"]["billing"],
            "forwarding_data"
        );
        deliver(&configs, &npubs, 1).await;
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        let before = statuses(&configs).await;
        let counts = payment_counts(&before);
        assert!(counts.iter().any(|(sent, received)| sent + received > 0));
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        assert_eq!(
            payment_counts(&statuses(&configs).await),
            counts,
            "free handshake must not leave unclaimable paid evidence or endless idle polls"
        );
        for child in &mut children {
            stop(child).await;
        }
        for (i, child) in children.iter_mut().enumerate() {
            *child = start(&paths[i]).await;
        }
        ready(&configs, &paths, &npubs, &mut children).await;
        let recovered = statuses(&configs).await;
        for (old, new) in before.iter().zip(&recovered) {
            assert_eq!(new["npub"], old["npub"]);
            assert_eq!(new["history"], old["history"]);
            assert_eq!(new["locked_sat"], old["locked_sat"]);
            assert!(
                new["remaining_budget_sat"].as_u64().unwrap()
                    <= old["remaining_budget_sat"].as_u64().unwrap()
            );
        }
        deliver(&configs, &npubs, 2).await;
        send(&configs, &npubs, 4, 0, "receiver has no reverse purchase").await;
        tokio::time::sleep(Duration::from_millis(1_000)).await;
        let final_states = statuses(&configs).await;
        assert_eq!(final_states[0]["received"]["packets"], 0);
        for i in [3, 4] {
            assert!(final_states[i]["purchases"].as_array().unwrap().is_empty());
            assert_eq!(final_states[i]["locked_sat"], 0);
            assert_eq!(final_states[i]["remaining_budget_sat"], 64);
        }
        let mut settled = 0;
        for cfg in &configs {
            settled += request(cfg, &AdminRequest::Settle).await.unwrap()["settlements"]
                .as_array()
                .unwrap()
                .len();
        }
        assert_eq!(settled, 3, "only the forward direction was funded");
        for child in &mut children {
            stop(child).await;
        }
        let mut total = 0;
        for (i, cfg) in configs.iter().enumerate() {
            let balance = load_mint_balance(&cfg.state_directory.join("wallet"), mint.url())
                .await
                .unwrap()
                .balance_sat;
            total += balance;
            if (1..=3).contains(&i) {
                assert!(balance > 256, "relay {i} must earn a net fee");
            }
            if i == 4 {
                assert_eq!(balance, 0, "recipient needs no wallet funding");
            }
        }
        assert_eq!(total, 1_024);
        assert!(network.accounting().unwrap().is_conserved());
    })
    .await
    .expect("one-way bootstrap test deadline");
}
