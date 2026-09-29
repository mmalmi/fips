//! Automatic renewal across a committed refund, offline provider and two crashes.
use super::restore::{read, wait_journal};
use super::wallet_crash::{arm, kill, kill_at};
use super::*;
use fips_relay::{controller::RenewalPolicy, service::ServiceConfig};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::atomic::Ordering};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn renewal_recovers_refund_and_replaces_once_after_repeated_restart() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().to_owned();
    let result = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(240), scenario(&path))
            .await
            .expect("bounded automatic renewal recovery");
    })
    .await;
    if let Err(error) = result {
        panic!(
            "{error}; retained failed fixture at {}",
            root.keep().display()
        );
    }
}

async fn scenario(root: &Path) {
    let (mint, network) = setup::start_mint(root, 9627).await;
    let proxy = MintProxy::start(mint.url()).await;
    let setup::Bench {
        mint: _mint,
        configs,
        paths,
        npubs,
        mut children,
    } = setup::start_configured_line(
        root,
        mint,
        network,
        &proxy.url,
        setup::LineConfig {
            lifetime: 600,
            quote_lifetime: 300,
            funding_limits: &[80, 40, 40],
        },
        |index, config| {
            if index == 0 {
                config.terms.controller.max_locked_sat = 40;
                config.terms.controller.max_funding_overhead_sat = 8;
                config.terms.controller.renewal = Some(RenewalPolicy {
                    at_capacity_percent: 25,
                    before_expiry_secs: 30,
                });
            }
        },
    )
    .await;
    request(&configs[0], &AdminRequest::PauseRenewals)
        .await
        .unwrap();
    for (source, destination) in [(0, 2), (2, 0)] {
        request(
            &configs[source],
            &AdminRequest::Buy {
                destination: npubs[destination].clone(),
            },
        )
        .await
        .unwrap();
    }
    for round in 0..10 {
        deliver(&configs, &npubs[2], round).await;
    }
    let journals: Vec<_> = configs
        .iter()
        .map(|cfg| cfg.state_directory.join("controller/controller.json"))
        .collect();
    let before = read(&journals[0]);
    let funding = before["funding"].as_object().unwrap();
    assert_eq!(funding.len(), 1);
    let (funding_id, original) = funding.iter().next().unwrap();
    let id = original["funded"]["terms"]["id"].as_str().unwrap();
    let wallet = configs[0].state_directory.join("wallet");
    let balance_before = load_mint_balance(&wallet, &proxy.url)
        .await
        .unwrap()
        .balance_sat;
    let budget_before = request(&configs[0], &AdminRequest::Status).await.unwrap();
    let marker = arm(&wallet, id, "refund");
    request(&configs[0], &AdminRequest::ResumeRenewals)
        .await
        .unwrap();
    kill_at(&mut children[0], &marker, id).await;
    let interrupted = read(&journals[0]);
    assert_eq!(interrupted["renewals"][id]["completed"], false);
    assert!(interrupted["renewals"][id]["replacements"].is_null());
    assert_eq!(interrupted["funding"], before["funding"]);
    let pending = &interrupted["buyer_settlements"][id];
    let report = &pending["report"];
    let refund = report["refunded_sat"].as_u64().unwrap();
    assert!(refund > 0 && report["paid_sat"].as_u64().unwrap() > 0);
    assert_eq!(pending["refunded"], false);
    assert_eq!(pending["released"], false);
    assert!(pending["wallet_refund_sat"].is_null());
    assert_eq!(pending["payment"]["balance"], report["paid_sat"]);
    let recovered_balance = balance_before + refund;
    assert_eq!(
        load_mint_balance(&wallet, &proxy.url)
            .await
            .unwrap()
            .balance_sat,
        recovered_balance
    );

    // The original refund must become durable locally while its provider is
    // absent. Recovery cannot depend on a new Buy or Settle administrative call.
    stop(&mut children[1]).await;
    children[0] = start(&paths[0]).await;
    let recovered = wait_journal(&journals[0], 30, |j| {
        j["buyer_settlements"][id]["refunded"] == true
    })
    .await;
    let mut expected = pending.clone();
    expected["refunded"] = true.into();
    expected["wallet_refund_sat"] = refund.into();
    assert_eq!(recovered["buyer_settlements"][id], expected);
    for field in ["funding", "next_funding", "policy"] {
        assert_eq!(recovered[field], before[field]);
    }
    assert_eq!(recovered["renewals"], interrupted["renewals"]);
    let status = request(&configs[0], &AdminRequest::Status).await.unwrap();
    assert!(status["purchases"].as_array().unwrap().is_empty());
    let mut expected_budget = budget_before["funding_budget"].clone();
    expected_budget["wallet_refunded_sat"] = refund.into();
    expected_budget["locked_sat"] = 0.into();
    expected_budget["exposure_sat"] =
        (expected_budget["wallet_debited_sat"].as_u64().unwrap() - refund).into();
    assert_eq!(status["funding_budget"], expected_budget);
    assert!(
        status["remaining_budget_sat"].as_u64().unwrap()
            <= budget_before["remaining_budget_sat"].as_u64().unwrap()
    );
    assert_eq!(
        load_mint_balance(&wallet, &proxy.url)
            .await
            .unwrap()
            .balance_sat,
        recovered_balance
    );
    kill(&mut children[0]).await;
    assert_eq!(read(&journals[0]), recovered);

    children[1] = start(&paths[1]).await;
    children[0] = start(&paths[0]).await;
    ready(&configs, &paths, &npubs, &mut children).await;
    let renewed = wait_journal(&journals[0], 40, |j| j["renewals"][id]["completed"] == true).await;
    request(&configs[0], &AdminRequest::PauseRenewals)
        .await
        .unwrap();
    assert_eq!(renewed["policy"], before["policy"]);
    assert_eq!(renewed["funding"].as_object().unwrap().len(), 2);
    assert_eq!(renewed["funding"][funding_id], *original);
    assert_eq!(
        renewed["next_funding"].as_u64().unwrap(),
        before["next_funding"].as_u64().unwrap() + 1
    );
    expected["released"] = true.into();
    assert_eq!(renewed["buyer_settlements"][id], expected);
    let seller = read(&journals[1]);
    assert_eq!(seller["seller_settlements"][id]["report"], *report);
    assert_eq!(seller["seller_settlements"][id]["released"], true);
    let status = request(&configs[0], &AdminRequest::Status).await.unwrap();
    let purchases = status["purchases"].as_array().unwrap();
    assert_eq!(purchases.len(), 1);
    let replacement = purchases[0]["channel"]["id"].as_str().unwrap().to_owned();
    assert_ne!(replacement, id);
    assert_eq!(status["funding_budget"]["wallet_refunded_sat"], refund);
    assert!(status["funding_budget"]["locked_sat"].as_u64().unwrap() <= 40);
    assert!(
        status["funding_budget"]["wallet_debited_sat"]
            .as_u64()
            .unwrap()
            <= 80
    );
    assert!(
        status["remaining_budget_sat"].as_u64().unwrap()
            <= budget_before["remaining_budget_sat"].as_u64().unwrap()
    );
    deliver(&configs, &npubs[2], 100).await;
    // Observe automatic payment before final settlement can collect it.
    wait_journal(
        &configs[1].state_directory.join("seller/ledger.json"),
        10,
        |j| {
            j["ledger"]["channels"].as_array().unwrap().iter().any(|c| {
                let usage = &c["usage"];
                c["terms"]["id"] == replacement
                    && usage["submitted_msat"].as_u64().unwrap() > 0
                    && usage["paid_msat"].as_u64().unwrap()
                        >= usage["submitted_msat"].as_u64().unwrap()
            })
        },
    )
    .await;

    let settled = request(&configs[0], &AdminRequest::Settle).await.unwrap();
    let reports = settled["settlements"].as_array().unwrap();
    assert_eq!(reports.len(), 2);
    assert!(reports.contains(report));
    assert!(
        reports
            .iter()
            .any(|r| { r["channel_id"] == replacement && r["paid_sat"].as_u64().unwrap() > 0 })
    );
    for config in &configs[1..] {
        request(config, &AdminRequest::Settle).await.unwrap();
    }
    for (index, config) in configs.iter().enumerate() {
        let status = request(config, &AdminRequest::Status).await.unwrap();
        assert_eq!(status["funding_budget"]["locked_sat"], 0);
        assert_eq!(status["funding_budget"]["pending_reserved_sat"], 0);
        assert!(
            status["funding_budget"]["exposure_sat"].as_u64().unwrap()
                <= config.terms.controller.max_wallet_spend_sat
        );
        if index == 0 {
            let paid: u64 = reports
                .iter()
                .map(|r| r["paid_sat"].as_u64().unwrap())
                .sum();
            assert_eq!(
                status["remaining_budget_sat"],
                config.terms.buyer_budget_sat - paid
            );
        }
        stop(&mut children[index]).await;
    }
    let final_state = read(&journals[0]);
    assert_eq!(final_state["funding"], renewed["funding"]);
    assert_eq!(final_state["next_funding"], renewed["next_funding"]);
    assert_eq!(final_state["policy"], before["policy"]);
    let mut available = 0;
    for config in &configs {
        available += load_mint_balance(&config.state_directory.join("wallet"), &proxy.url)
            .await
            .unwrap()
            .balance_sat;
    }
    assert_eq!(
        available + proxy.state.fees_collected.load(Ordering::SeqCst),
        384
    );
}

async fn deliver(configs: &[ServiceConfig], destination: &str, round: u8) {
    let payload = format!("renewal-restart-{round}:{}", "x".repeat(700));
    let digest = format!("{:x}", Sha256::digest(payload.as_bytes()));
    request(
        &configs[0],
        &AdminRequest::Send {
            destination: destination.into(),
            payload,
        },
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status = request(&configs[2], &AdminRequest::Status).await.unwrap();
            if status["received"]["last_sha256"] == digest {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("fresh paid payload must reach its destination");
}
