//! Opt-in turnover acceptance using real UDP/TLS processes and the existing gates.
use super::bench::controller_phases;
use super::*;
use cashu_service::simulation::MintProxy;
use fips_relay::controller::FundingRequestBudget;
use std::num::NonZeroU32;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "repeated renewal acceptance; run explicitly"]
async fn concurrent_bidirectional_renewals_preserve_payment_progress() {
    tokio::time::timeout(Duration::from_secs(240), scenario())
        .await
        .expect("bounded repeated renewal acceptance");
}

async fn scenario() {
    let root = tempfile::tempdir().unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let network = PaymentNetwork::new(112, 0, Arc::new(VirtualClock::new(now)));
    let mint = LocalMint::start(
        root.path(),
        network.clone(),
        "renewal-load",
        IssuerMode::ClosedLoop,
    )
    .await
    .unwrap();
    let proxy = MintProxy::start(mint.url()).await;
    let mut bench =
        MixedBench::start_configured(&proxy.url, &network, SecondHop::WebSocketTls, |_, cfg| {
            cfg.funding_request_budget = Some(FundingRequestBudget {
                burst: NonZeroU32::new(128).unwrap(),
                requests_per_minute: NonZeroU32::new(60_000).unwrap(),
            });
        })
        .await;
    bench.assert_carriers().await;
    bench.set_stage("turnover-initial-purchase");
    for (source, destination) in [(0, 2), (2, 0)] {
        request(
            &bench.configs[source],
            &AdminRequest::Buy {
                destination: bench.npubs[destination].clone(),
            },
        )
        .await
        .unwrap();
    }
    let original = bench.states().await;
    let funding = bench.funding_intents(false);
    let budget = bench.configs[0].terms.buyer_budget_sat;
    let capacity = bench.configs[0].terms.controller.channel_capacity_sat;
    for round in 0..=4 {
        eprintln!("mixed-carrier turnover round={round}");
        let prior = bench.funding_intents(false);
        // Pause only to observe a fixed channel generation. Fresh delivery and
        // automatic credit must succeed before any settlement can collect it.
        bench.set_renewals_paused(true).await;
        bench.set_stage("turnover-payment");
        let states = bench.states().await;
        let channels: Vec<_> = [0, 2]
            .into_iter()
            .map(|source| {
                assert_eq!(states[source]["purchases"].as_array().unwrap().len(), 1);
                states[source]["purchases"][0]["channel"]["id"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        bench.deliver_bidirectional([0, 2]).await;
        tokio::join!(bench.wait_paid(&channels[0]), bench.wait_paid(&channels[1]));
        if round == 4 {
            bench.set_renewals_paused(false).await;
            break;
        }
        let remaining = budget - (round + 1) * capacity;
        let before = bench.states().await;
        if round == 1 {
            bench.set_stage("turnover-shared-provider");
            held_close_with_other_payment(&bench, &proxy, &channels, remaining).await;
        } else {
            bench.set_stage("turnover-fill");
            bench
                .send_bidirectional_probes([0, 2], 40, 256, 8, [true; 2])
                .await;
            tokio::join!(
                bench.wait_exhausted(0, remaining),
                bench.wait_exhausted(2, remaining)
            );
            tokio::join!(bench.wait_paid(&channels[0]), bench.wait_paid(&channels[1]));
            bench.set_stage("turnover-renewal");
            bench.set_renewals_paused(false).await;
        }
        bench.wait_replacements(&channels).await;
        assert_replacement_accounts(&bench, &before, &bench.states().await, &prior, [1, 0, 1])
            .await;
    }
    assert_replacement_accounts(
        &bench,
        &original,
        &bench.states().await,
        &funding,
        [4, 0, 4],
    )
    .await;
    bench.set_renewals_paused(true).await;
    bench.set_stage("turnover-settlement");
    for config in &bench.configs {
        request(config, &AdminRequest::Settle).await.unwrap();
    }
    let settled = bench.states().await;
    for child in &mut bench.children {
        process_support::stop(child).await;
    }
    let mut total = 0;
    for (node, config) in bench.configs.iter().enumerate() {
        let amount = load_mint_balance(&config.state_directory.join("wallet"), &proxy.url)
            .await
            .unwrap()
            .balance_sat;
        if node == 1 {
            assert!(amount > 128, "provider redeems its earned payments");
        } else {
            let budget: FundingBudget =
                serde_json::from_value(settled[node]["funding_budget"].clone()).unwrap();
            assert_eq!(budget.pending_reserved_sat, 0);
            assert_eq!(budget.locked_sat, 0);
            assert_eq!(amount + budget.exposure_sat, 128);
            assert_eq!(settled[node]["history"].as_array().unwrap().len(), 5);
        }
        total += amount;
    }
    assert_eq!(total, 384);
    assert!(network.accounting().unwrap().is_conserved());
}

async fn held_close_with_other_payment(
    bench: &MixedBench,
    proxy: &MintProxy,
    channels: &[String],
    remaining: u64,
) {
    bench.send_probe(0, 2, 40, 256, 8).await;
    bench.wait_exhausted(0, remaining).await;
    bench.wait_paid(&channels[0]).await;
    // Funding is complete and both renewals are paused. The next mint swap is
    // the first provider close, which retains the shared provider's wallet lock.
    let (committed, release) = proxy.state.pause_matching_swap_reply(|_| true);
    request(&bench.configs[0], &AdminRequest::ResumeRenewals)
        .await
        .unwrap();
    if !matches!(
        tokio::time::timeout(Duration::from_secs(30), committed).await,
        Ok(Ok(_))
    ) {
        bench.failure_snapshot().await;
        panic!("provider close must commit before the held reply");
    }
    let (_, paid_before) = bench.relay_usage_msat(&channels[1]);
    bench.deliver_sized(2, 0, 512).await;
    bench.wait_paid_beyond(&channels[1], paid_before).await;
    eprintln!("mixed-carrier other-neighbor credit advanced while provider close held");

    bench.send_probe(2, 0, 40, 256, 8).await;
    bench.wait_exhausted(2, remaining).await;
    bench.wait_paid(&channels[1]).await;
    request(&bench.configs[2], &AdminRequest::ResumeRenewals)
        .await
        .unwrap();
    let journal = bench.configs[1]
        .state_directory
        .join("controller/controller.json");
    let overlapping = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let state: Value = serde_json::from_slice(&std::fs::read(&journal).unwrap()).unwrap();
            if channels.iter().all(|id| {
                state["seller_settlements"][id]["payment"].is_object()
                    && state["seller_settlements"][id]["report"].is_null()
            }) {
                let safe = controller_phases(&state);
                let settlements = safe["seller_settlements"].as_array().unwrap();
                assert!(settlements.len() <= 16);
                for id in channels {
                    let row = settlements.iter().find(|row| row["id"] == *id).unwrap();
                    assert_eq!(
                        row,
                        &serde_json::json!({
                            "id": id,
                            "has_payment": true,
                            "has_report": false,
                        }),
                        "held settlements expose only their identifiers and presence flags"
                    );
                }
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if overlapping.is_err() {
        bench.failure_snapshot().await;
        panic!("both provider settlements overlap before the held close returns");
    }
    release
        .send(())
        .expect("the mint reply remained held through both observations");
    bench.set_renewals_paused(false).await;
}
