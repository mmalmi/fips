//! Renewal keeps its original intent across a delayed, lost committed mint reply.
use super::restore::{read, wait_journal};
use super::*;
use fips_relay::{controller::RenewalPolicy, service::ServiceConfig};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{path::Path, sync::atomic::Ordering};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delayed_lost_mint_close_reply_renews_once_and_keeps_other_buyers_paid() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().to_owned();
    let result = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(240), scenario(&path))
            .await
            .expect("bounded delayed-mint renewal recovery");
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
    let (mint, network) = setup::start_mint(root, 9631).await;
    let proxy = MintProxy::start(mint.url()).await;
    let setup::Bench {
        mint: _mint,
        configs,
        npubs,
        mut children,
        ..
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
        send(&configs, &npubs, 0, round).await;
    }
    let journal = configs[0]
        .state_directory
        .join("controller/controller.json");
    let seller_journal = configs[1]
        .state_directory
        .join("controller/controller.json");
    let before = read(&journal);
    let funding = before["funding"].as_object().unwrap();
    assert_eq!(funding.len(), 1);
    let (funding_id, original) = funding.iter().next().unwrap();
    let id = original["funded"]["terms"]["id"].as_str().unwrap();
    let status = request(&configs[0], &AdminRequest::Status).await.unwrap();
    let reverse = request(&configs[2], &AdminRequest::Status).await.unwrap();
    let reverse_id = reverse["purchases"][0]["channel"]["id"].as_str().unwrap();
    let reverse_before = usage(&configs[1], reverse_id);
    let swaps_before = proxy.state.swaps.load(Ordering::SeqCst);
    let (committed, release) =
        setup::pause_channel_close(&proxy, &configs[0].state_directory.join("wallet"), id);
    request(&configs[0], &AdminRequest::ResumeRenewals)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), committed)
        .await
        .expect("original mint close must commit")
        .unwrap();
    let held_at = tokio::time::Instant::now();
    // A different buyer needs no new mint funds to keep forwarding and paying.
    send(&configs, &npubs, 2, 100).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !new_usage_paid(&configs[1], reverse_id, reverse_before) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("held mint close cannot stall another buyer's payment");
    tokio::time::sleep_until(held_at + Duration::from_secs(7)).await;
    assert!(
        !release.is_closed(),
        "the committed response must remain held"
    );
    assert_eq!(
        proxy.state.swaps.load(Ordering::SeqCst),
        swaps_before + 1,
        "only the original close reaches the mint while held"
    );
    let pending = read(&journal);
    assert_eq!(pending["renewals"][id]["completed"], false);
    assert!(read(&seller_journal)["seller_settlements"][id]["report"].is_null());
    assert_eq!(pending["funding"], before["funding"]);
    assert_eq!(pending["next_funding"], before["next_funding"]);
    // Only the held original swap is outstanding; lose its reply after commit.
    proxy.state.lose_swap_reply.store(true, Ordering::SeqCst);
    release.send(()).unwrap();
    let renewed = wait_journal(&journal, 60, |j| j["renewals"][id]["completed"] == true).await;
    request(&configs[0], &AdminRequest::PauseRenewals)
        .await
        .unwrap();
    assert!(!proxy.state.lose_swap_reply.load(Ordering::SeqCst));
    assert_eq!(renewed["policy"], before["policy"]);
    assert_eq!(renewed["funding"][funding_id], *original);
    assert_eq!(renewed["funding"].as_object().unwrap().len(), 2);
    assert_eq!(
        renewed["next_funding"].as_u64().unwrap(),
        before["next_funding"].as_u64().unwrap() + 1
    );
    let refund = &renewed["buyer_settlements"][id];
    assert_eq!(refund["refunded"], true);
    assert_eq!(refund["released"], true);
    let closed = read(&seller_journal);
    assert_eq!(closed["seller_settlements"][id]["report"], refund["report"]);
    assert_eq!(closed["seller_settlements"][id]["released"], true);
    let after = request(&configs[0], &AdminRequest::Status).await.unwrap();
    assert_eq!(after["purchases"].as_array().unwrap().len(), 1);
    let replacement = after["purchases"][0]["channel"]["id"].as_str().unwrap();
    assert_ne!(replacement, id);
    assert_eq!(after["funding_budget"]["pending_reserved_sat"], 0);
    assert!(after["funding_budget"]["locked_sat"].as_u64().unwrap() <= 40);
    assert!(
        after["funding_budget"]["wallet_debited_sat"]
            .as_u64()
            .unwrap()
            <= 80
    );
    assert!(
        after["remaining_budget_sat"].as_u64().unwrap()
            <= status["remaining_budget_sat"].as_u64().unwrap()
    );
    let before_usage = usage(&configs[1], replacement);
    send(&configs, &npubs, 0, 101).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !new_usage_paid(&configs[1], replacement, before_usage) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("replacement must resume automatic payment");
    for config in &configs {
        request(config, &AdminRequest::Settle).await.unwrap();
        let status = request(config, &AdminRequest::Status).await.unwrap();
        assert_eq!(status["funding_budget"]["locked_sat"], 0);
        assert_eq!(status["funding_budget"]["pending_reserved_sat"], 0);
    }
    for child in &mut children {
        stop(child).await;
    }
    let final_state = read(&journal);
    assert_eq!(final_state["funding"], renewed["funding"]);
    assert_eq!(final_state["next_funding"], renewed["next_funding"]);
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
    eprintln!(
        "Delayed/lost committed mint reply: one replacement, other buyer paid, all 384 test sats accounted for"
    );
}

fn usage(config: &ServiceConfig, channel: &str) -> (u64, u64) {
    let ledger = read(&config.state_directory.join("seller/ledger.json"));
    let usage = &ledger["ledger"]["channels"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["terms"]["id"] == channel)
        .unwrap()["usage"];
    (
        usage["submitted_msat"].as_u64().unwrap(),
        usage["paid_msat"].as_u64().unwrap(),
    )
}

fn new_usage_paid(config: &ServiceConfig, channel: &str, before: (u64, u64)) -> bool {
    let (submitted, paid) = usage(config, channel);
    submitted > before.0 && paid > before.1 && paid >= submitted
}

async fn send(configs: &[ServiceConfig], npubs: &[String], source: usize, round: u8) {
    let destination = 2 - source;
    let payload = format!("renewal-mint-loss-{source}-{round}:{}", "x".repeat(700));
    let digest = format!("{:x}", Sha256::digest(payload.as_bytes()));
    request(
        &configs[source],
        &AdminRequest::Send {
            destination: npubs[destination].clone(),
            payload,
        },
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status: Value = request(&configs[destination], &AdminRequest::Status)
                .await
                .unwrap();
            if status["received"]["last_sha256"] == digest {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("fresh paid payload must arrive without retries");
}
