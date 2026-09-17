//! Explicit watch authority maintains free permission without creating money state.
use super::*;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn watch(bench: &Bench, ceiling: u64) -> Value {
    request(
        &bench.configs[0],
        &AdminRequest::Watch {
            destination: bench.npubs[4].clone(),
            max_rate_msat_per_kib: ceiling,
        },
    )
    .await
    .unwrap_or_else(|error| panic!("initial watch ceiling {ceiling}: {error}"))
}

fn assert_watch(bench: &Bench, ceiling: u64, paused: bool) {
    for (i, config) in bench.configs.iter().enumerate() {
        let saved: Value = serde_json::from_slice(
            &std::fs::read(config.state_directory.join("controller/controller.json")).unwrap(),
        )
        .unwrap();
        let expected = if i == 0 {
            json!({bench.npubs[4].clone(): {
                "billing": BillingBasis::ForwardingData,
                "destination": bench.npubs[4],
                "max_rate_msat_per_kib": ceiling,
                "paused": paused,
                "pending": null,
            }})
        } else {
            json!({})
        };
        assert_eq!(
            saved["watched_routes"], expected,
            "node {i} watch authority"
        );
    }
}

async fn wait_status(bench: &Bench, phase: &str, ready: impl Fn(&[Value]) -> bool) -> Vec<Value> {
    let mut last = Vec::new();
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            last = bench.states().await;
            if ready(&last) {
                return last.clone();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{phase}: {last:?}"))
}

async fn idle(bench: &Bench) {
    let before = bench.states().await;
    let saved: Vec<_> = bench.configs.iter().map(monetary_journals).collect();
    // More than two five-second watch checks, within a fresh long-lived grant.
    tokio::time::sleep(Duration::from_secs(12)).await;
    let after = bench.states().await;
    for (i, (a, b)) in before.iter().zip(&after).enumerate() {
        assert_eq!(
            a["control_traffic"], b["control_traffic"],
            "idle node {i} made control requests"
        );
        assert_eq!(monetary_journals(&bench.configs[i]), saved[i]);
        #[cfg(feature = "measurements")]
        for (operation, old) in a["measurements"]["operations"].as_object().unwrap() {
            for field in [
                "journal_bytes_written",
                "journal_writes",
                "journal_syncs",
                "journal_commits",
            ] {
                assert_eq!(
                    old[field], b["measurements"]["operations"][operation][field],
                    "idle node {i} wrote {operation}/{field}"
                );
            }
        }
    }
}

async fn empty_settlement(bench: &Bench) {
    for config in &bench.configs {
        assert!(
            request(config, &AdminRequest::Settle).await.unwrap()["settlements"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}

async fn after_expiry(expires: u64) {
    let seconds = expires.saturating_sub(now()).saturating_add(1);
    assert!(seconds <= 61, "fixture must use a bounded quote lifetime");
    tokio::time::sleep(Duration::from_secs(seconds)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn free_watch_upkeeps_quota_expiry_restart_and_respects_pause_without_money() {
    tokio::time::timeout(Duration::from_secs(200), async {
        let mint = OfflineMint::start().await;
        let mut bench = Bench::start_configured(
            std::array::from_fn(|i| format!("{}/mint-{i}", mint.url)),
            Pricing::Defaults {
                fees: [0; 5],
                ceilings: [0; 5],
            },
            None,
            |_, config| {
                config.terms.quote_lifetime_secs = 60;
                config.terms.quote_max_units = 4_096;
            },
        )
        .await;
        let original: Vec<_> = bench.configs.iter().map(monetary_journals).collect();
        let opened = watch(&bench, 0).await;
        assert!(opened["purchase"].is_null());
        let offer = &opened["free_route"];
        assert_eq!(offer["price"]["msat"], 0);
        assert_eq!(offer["max_units"], 4_096);
        let expires = offer["expires_unix"].as_u64().unwrap();
        assert_watch(&bench, 0, false);
        idle(&bench).await;
        // Each successful label contains 900 payload bytes. Six distinct
        // deliveries cannot fit in one 4096-byte grant, even ignoring headers.
        for sequence in 0..6 {
            bench
                .deliver(4, &format!("automatic quota {sequence}"))
                .await;
        }
        assert!(
            now() < expires,
            "quota recovery must precede the original expiry"
        );
        assert_unfunded(&bench, &original).await;
        after_expiry(expires).await;
        bench.deliver(4, "automatic expiry").await;
        bench.restart().await;
        bench
            .deliver(4, "automatic restart without another Watch")
            .await;
        assert_watch(&bench, 0, false);
        assert_unfunded(&bench, &original).await;
        mint.assert_unused();

        request(&bench.configs[0], &AdminRequest::PauseRouteRefresh)
            .await
            .unwrap();
        // Restart removes ephemeral grants; paused authority must not recreate them.
        bench.restart().await;
        assert_watch(&bench, 0, true);
        idle(&bench).await;
        bench.send(4, "paused watch cannot regain access").await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let states = bench.states().await;
        assert_eq!(states[4]["received"]["packets"], 0);
        for state in states {
            assert_eq!(state["free_routes"]["outgoing_leases"], 0);
        }
        empty_settlement(&bench).await;
        assert_unfunded(&bench, &original).await;
        bench.stop().await;
        mint.assert_unused();
    })
    .await
    .expect("automatic free lifecycle deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn free_only_watch_refuses_paid_repricing_and_recovers_when_free_returns() {
    tokio::time::timeout(Duration::from_secs(150), async {
        let mint = OfflineMint::start().await;
        let mut bench = Bench::start_configured(
            std::array::from_fn(|_| mint.url.clone()),
            Pricing::Defaults {
                fees: [0; 5],
                ceilings: [1_024, 1_024, 0, 0, 0],
            },
            None,
            |_, config| {
                config.terms.quote_lifetime_secs = 60;
            },
        )
        .await;
        let original: Vec<_> = bench.configs.iter().map(monetary_journals).collect();
        assert_eq!(watch(&bench, 0).await["free_route"]["price"]["msat"], 0);
        bench.deliver(4, "free before repricing").await;
        bench.configs[1].destination_fees =
            serde_json::from_value(json!({bench.npubs[4].clone(): 1_024})).unwrap();
        std::fs::write(
            &bench.paths[1],
            serde_json::to_vec(&bench.configs[1]).unwrap(),
        )
        .unwrap();
        bench.restart().await;
        wait_status(&bench, "automatic paid quote refusal", |states| {
            states[0]["last_error"] == "route exceeds source authorization"
                && states[0]["control_traffic"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|entry| {
                        entry["service_port"] == 44_741
                            && entry["counters"]["requests_started"].as_u64().unwrap() > 0
                    })
        })
        .await;
        bench
            .send(4, "zero ceiling cannot buy the paid offer")
            .await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(bench.states().await[4]["received"]["packets"], 0);
        assert_watch(&bench, 0, false);
        assert_unfunded(&bench, &original).await;
        mint.assert_unused();

        bench.configs[1].destination_fees = Default::default();
        std::fs::write(
            &bench.paths[1],
            serde_json::to_vec(&bench.configs[1]).unwrap(),
        )
        .unwrap();
        bench.restart().await;
        bench
            .deliver(4, "automatic recovery when free returns")
            .await;
        assert_watch(&bench, 0, false);
        assert_unfunded(&bench, &original).await;
        empty_settlement(&bench).await;
        bench.stop().await;
        mint.assert_unused();
    })
    .await
    .expect("free repricing recovery deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paid_watch_refreshes_expired_free_suffix_without_refunding_its_channel() {
    tokio::time::timeout(Duration::from_secs(150), async {
        let root = tempfile::tempdir().unwrap();
        let network = PaymentNetwork::new(101, 0, Arc::new(VirtualClock::new(now())));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "watched-free-tail",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let mut bench = Bench::start_configured(
            std::array::from_fn(|_| mint.url().to_owned()),
            Pricing::Defaults {
                fees: [0, 1_024, 0, 0, 0],
                ceilings: [1_024, 1_024, 0, 0, 0],
            },
            None,
            |_, config| {
                config.terms.quote_lifetime_secs = 15;
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
        let opened = watch(&bench, 1_024).await;
        let purchase = &opened["purchase"];
        assert_eq!(purchase["contract"]["price"]["msat"], 1_024);
        let channel = purchase["channel"]["id"].clone();
        let funding = monetary_journals(&bench.configs[0])["controller"]["funding"].clone();
        bench.deliver(4, "initial watched paid prefix").await;
        after_expiry(purchase["contract"]["expires_unix"].as_u64().unwrap()).await;
        bench.deliver(4, "automatically renewed free suffix").await;
        let states = bench.states().await;
        let purchases = states[0]["purchases"].as_array().unwrap();
        assert_eq!(purchases.len(), 1);
        assert_eq!(purchases[0]["channel"]["id"], channel);
        assert_ne!(purchases[0]["contract"]["id"], purchase["contract"]["id"]);
        assert_eq!(
            monetary_journals(&bench.configs[0])["controller"]["funding"],
            funding
        );
        assert_eq!(states[0]["funding_budget"]["wallet_debited_sat"], 32);
        for (i, original) in tail.iter().enumerate() {
            assert_eq!(&monetary_journals(&bench.configs[i + 2]), original);
        }
        for state in &states[1..] {
            assert!(state["purchases"].as_array().unwrap().is_empty());
            assert_eq!(state["remaining_budget_sat"], 64);
            assert_eq!(state["funding_budget"]["wallet_debited_sat"], 0);
        }
        let mut count = 0;
        for config in &bench.configs {
            count += request(config, &AdminRequest::Settle).await.unwrap()["settlements"]
                .as_array()
                .unwrap()
                .len();
        }
        assert_eq!(count, 1);
        bench.stop().await;
        let mut total = 0;
        for (i, config) in bench.configs.iter().enumerate() {
            let balance = load_mint_balance(&config.state_directory.join("wallet"), mint.url())
                .await
                .unwrap()
                .balance_sat;
            if i == 1 {
                assert!(balance > 0);
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
    .expect("watched mixed route deadline");
}
