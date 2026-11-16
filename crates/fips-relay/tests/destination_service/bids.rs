use super::*;

fn public_seed(cfg: &mut ServiceConfig) {
    cfg.public_free_transit = true;
    cfg.terms.buyer_budget_sat = 0;
    let policy = &mut cfg.terms.controller;
    policy.max_locked_sat = 0;
    policy.max_wallet_spend_sat = 0;
    policy.max_funding_overhead_sat = 0;
    policy.renewal = None;
    cfg.free_bandwidth = Some(fips_relay::free_routes::FreeBandwidthPolicy {
        global_bytes_per_second: 65536,
        global_burst_bytes: 65536,
        peer_bytes_per_second: 16384,
        peer_burst_bytes: 16384,
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn voluntary_bid_funds_only_accepted_hops_on_a_free_route() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(100, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "voluntary-bid",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let mut bench = Bench::start(
            mint.url(),
            Pricing::Defaults {
                fees: [0; 5],
                ceilings: [32; 5],
            },
        )
        .await;
        let bid = |destination: usize, cap| AdminRequest::Bid {
            destination: bench.npubs[destination].clone(),
            bid_msat_per_kib: 4,
            max_rate_msat_per_kib: cap,
        };
        // Two forwarding hops cost eight, including when a wallet is empty.
        let error = request(&bench.configs[4], &bid(1, 7)).await.unwrap_err();
        assert!(error.contains("source authorization"), "{error}");
        for state in bench.states().await {
            assert_eq!(state["funding_budget"]["wallet_debited_sat"], 0);
        }
        assert!(bench.open(3).await.get("free_route").is_some());
        bench.deliver(3, "unfunded before opting in").await;
        for config in &bench.configs[..2] {
            let wallet = config.state_directory.join("wallet");
            let quote = create_topup_quote(&wallet, mint.url(), 128).await.unwrap();
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
        let purchase = request(&bench.configs[0], &bid(3, 8)).await.unwrap();
        let contract = &purchase["purchase"]["contract"];
        assert_eq!(contract["price"]["msat"], 8);
        assert_eq!(contract["bid_msat_per_kib"], 4);
        bench
            .deliver(3, "forwarded under the funded priority bid")
            .await;
        let states = bench.states().await;
        assert_eq!(states[1]["purchases"][0]["contract"]["bid_msat_per_kib"], 4);
        assert_eq!(states[1]["purchases"][0]["contract"]["price"]["msat"], 4);
        assert_eq!(states[2]["funding_budget"]["wallet_debited_sat"], 0);
        bench.stop().await;
    })
    .await
    .expect("voluntary bid process deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn receive_only_public_seeds_forward_without_wallet_or_quote_after_restart() {
    tokio::time::timeout(Duration::from_secs(100), async {
        let mint = OfflineMint::start().await;
        let mut bench = Bench::start_configured(
            std::array::from_fn(|_| mint.url.clone()),
            Pricing::Defaults {
                fees: [0; 5],
                ceilings: [32; 5],
            },
            None,
            |i, cfg| {
                if (1..4).contains(&i) {
                    public_seed(cfg);
                }
            },
        )
        .await;
        bench
            .deliver(4, "ordinary FIPS transit without quotes")
            .await;
        bench.restart().await;
        bench.deliver(4, "ordinary transit after restart").await;
        for state in &bench.states().await[1..4] {
            assert_eq!(state["remaining_budget_sat"], 0);
            assert_eq!(state["funding_budget"]["wallet_debited_sat"], 0);
            assert_eq!(state["free_routes"]["incoming_leases"], 0);
            assert!(state["free_routes"]["admitted_packets"].as_u64().unwrap() > 0);
        }
        mint.assert_unused();
        bench.stop().await;
    })
    .await
    .expect("unfunded seed transit deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_seed_accepts_two_issuers_and_keeps_earnings_separate() {
    use fips_relay::wallet_tools::{WalletRequest, offline_wallet_at_mint};
    tokio::time::timeout(Duration::from_secs(180), async {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(100, 0, Arc::new(VirtualClock::new(now)));
        let a = LocalMint::start(
            &root.path().join("a"),
            network.clone(),
            "primary",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let b = LocalMint::start(
            &root.path().join("b"),
            network.clone(),
            "secondary",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let mints = std::array::from_fn(|i| {
            if i == 1 {
                b.url().to_string()
            } else {
                a.url().to_string()
            }
        });
        let mut bench = Bench::start_configured(
            mints,
            Pricing::Defaults {
                fees: [0; 5],
                ceilings: [2048; 5],
            },
            None,
            |i, cfg| {
                if i == 2 {
                    cfg.terms.controller.additional_receive_mints = vec![b.url().to_string()];
                    public_seed(cfg);
                }
            },
        )
        .await;
        for (source, target, mint) in [(1, 3, b.url()), (3, 1, a.url())] {
            let wallet = bench.configs[source].state_directory.join("wallet");
            let topup = create_topup_quote(&wallet, mint, 128).await.unwrap();
            network
                .orchestrator_funding()
                .settle_external(&topup.payment_request)
                .unwrap();
            assert!(
                load_wallet_overview(&wallet, true)
                    .await
                    .unwrap()
                    .warnings
                    .is_empty()
            );
            let paid = request(
                &bench.configs[source],
                &AdminRequest::Bid {
                    destination: bench.npubs[target].clone(),
                    bid_msat_per_kib: 1024,
                    max_rate_msat_per_kib: 1024,
                },
            )
            .await
            .unwrap();
            assert_eq!(paid["purchase"]["channel"]["mint_url"], mint);
            bench
                .deliver_from(source, target, "paid transit, buyer-selected mint")
                .await;
        }
        bench.restart().await;
        for source in [1, 3] {
            let settled = request(&bench.configs[source], &AdminRequest::Settle)
                .await
                .unwrap();
            assert_eq!(settled["settlements"].as_array().unwrap().len(), 1);
        }
        bench.stop().await;
        for mint in [a.url(), b.url()] {
            let seller = &bench.configs[2];
            let balance = offline_wallet_at_mint(seller, WalletRequest::Balance, mint)
                .await
                .unwrap();
            assert!(balance["balance_sat"].as_u64().unwrap() > 0);
            let export = WalletRequest::Export {
                id: 1,
                amount_sat: 1,
            };
            let sent = offline_wallet_at_mint(seller, export.clone(), mint)
                .await
                .unwrap();
            assert_eq!(
                offline_wallet_at_mint(seller, export, mint).await.unwrap(),
                sent
            );
            offline_wallet_at_mint(
                seller,
                WalletRequest::AcknowledgeExports { through: 1 },
                mint,
            )
            .await
            .unwrap();
        }
        assert!(
            offline_wallet_at_mint(
                &bench.configs[2],
                WalletRequest::Balance,
                "https://unknown.invalid"
            )
            .await
            .is_err()
        );
    })
    .await
    .expect("two-issuer seed settlement deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn receive_only_seed_sells_its_link_over_an_unpriced_native_tail() {
    tokio::time::timeout(Duration::from_secs(150), async {
        let root = tempfile::tempdir().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(100, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "native-tail",
            IssuerMode::ClosedLoop,
        )
        .await
        .unwrap();
        let mut bench = Bench::start_configured(
            std::array::from_fn(|_| mint.url().to_string()),
            Pricing::Defaults {
                fees: [0; 5],
                ceilings: [1024; 5],
            },
            None,
            |i, cfg| {
                if (1..4).contains(&i) {
                    public_seed(cfg);
                }
            },
        )
        .await;
        let wallet = bench.configs[0].state_directory.join("wallet");
        let topup = create_topup_quote(&wallet, mint.url(), 128).await.unwrap();
        network
            .orchestrator_funding()
            .settle_external(&topup.payment_request)
            .unwrap();
        assert!(
            load_wallet_overview(&wallet, true)
                .await
                .unwrap()
                .warnings
                .is_empty()
        );
        let paid = request(
            &bench.configs[0],
            &AdminRequest::Bid {
                destination: bench.npubs[4].clone(),
                bid_msat_per_kib: 1024,
                max_rate_msat_per_kib: 1024,
            },
        )
        .await
        .unwrap();
        assert_eq!(paid["purchase"]["contract"]["price"]["msat"], 1024);
        bench
            .deliver(4, "only the first forwarding link is paid")
            .await;
        bench.restart().await;
        bench.deliver(4, "native tail after restart").await;
        let states = bench.states().await;
        for state in &states[1..4] {
            assert_eq!(state["funding_budget"]["wallet_debited_sat"], 0);
        }
        for state in &states[2..4] {
            assert!(state["free_routes"]["admitted_packets"].as_u64().unwrap() > 0);
        }
        let settled = request(&bench.configs[0], &AdminRequest::Settle)
            .await
            .unwrap();
        assert_eq!(settled["settlements"].as_array().unwrap().len(), 1);
        bench.stop().await;
    })
    .await
    .expect("receive-only paid first hop deadline");
}
