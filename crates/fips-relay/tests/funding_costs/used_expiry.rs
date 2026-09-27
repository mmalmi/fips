//! Shared paid channels recover independently when their two owners depart.
use super::*;
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_paid_channel_expires_with_each_counterparty_offline() {
    recover(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seller_recovers_after_missing_the_shared_channel_collection_deadline() {
    recover(true).await;
}

async fn recover(seller_misses_deadline: bool) {
    tokio::time::timeout(Duration::from_secs(240), async {
        let root = tempfile::tempdir().unwrap();
        let (mint, network) = setup::start_mint(root.path(), 9631).await;
        let proxy = MintProxy::start(mint.url()).await;
        let setup::Bench {
            mint: _mint,
            configs,
            paths,
            npubs,
            mut children,
        } = setup::start_line(
            root.path(),
            mint,
            network,
            &proxy.url,
            60,
            30,
            &[40, 40, 40, 40],
        )
        .await;
        for (source, destination) in [(0, 2), (0, 3), (2, 0), (3, 0)] {
            request(
                &configs[source],
                &AdminRequest::Buy {
                    destination: npubs[destination].clone(),
                },
            )
            .await
            .unwrap();
        }
        for destination in [2, 3] {
            let payload = format!("shared-expiry-{destination}:{}", "x".repeat(700));
            let digest = format!("{:x}", Sha256::digest(payload.as_bytes()));
            request(
                &configs[0],
                &AdminRequest::Send {
                    destination: npubs[destination].clone(),
                    payload,
                },
            )
            .await
            .unwrap();
            tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if request(&configs[destination], &AdminRequest::Status)
                        .await
                        .unwrap()["received"]["last_sha256"]
                        == digest
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .expect("both destinations must receive paid traffic on the shared channel");
        }
        let journals: Vec<_> = configs
            .iter()
            .map(|c| c.state_directory.join("controller/controller.json"))
            .collect();
        let buyer_path = configs[0].state_directory.join("buyer/buyer.json");
        let opened = restore::read(&journals[0]);
        let funding = opened["funding"].as_object().unwrap();
        assert_eq!(
            funding.len(),
            1,
            "the two routes must share original funding"
        );
        let original = funding.values().next().unwrap();
        let channel = original["funded"]["terms"]["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let expiry = original["expires_unix"].as_u64().unwrap();
        assert_eq!(opened["outgoing"].as_object().unwrap().len(), 2);
        assert!(
            opened["outgoing"]
                .as_object()
                .unwrap()
                .values()
                .all(|o| { o["purchase"]["channel"]["id"] == channel && o["accepted"] == true })
        );
        restore::wait_journal(&buyer_path, 10, |j| {
            j["channels"][&channel]["authorized_sat"]
                .as_u64()
                .unwrap_or(0)
                > 0
        })
        .await;
        let seller_path = configs[1].state_directory.join("seller/ledger.json");
        restore::wait_journal(&seller_path, 10, |j| {
            j["ledger"]["channels"].as_array().unwrap().iter().any(|c| {
                c["terms"]["id"] == channel && c["usage"]["paid_msat"].as_u64().unwrap_or(0) > 0
            })
        })
        .await;
        if seller_misses_deadline {
            children[1].kill().await.unwrap();
            assert!(!children[1].wait().await.unwrap().success());
        }
        children[0].kill().await.unwrap();
        assert!(!children[0].wait().await.unwrap().success());
        assert!(
            restore::read(&journals[0])["buyer_settlements"]
                .get(&channel)
                .is_none(),
            "the buyer must depart before cooperative settlement starts"
        );
        let seller_accepted = restore::read(&seller_path)["ledger"]["channels"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["terms"]["id"] == channel)
            .unwrap()["usage"]["paid_msat"]
            .as_u64()
            .unwrap()
            / 1_000;
        assert!(seller_accepted > 0);
        let stopped = restore::read(&buyer_path);
        let signed = stopped["channels"][&channel]["authorized_sat"]
            .as_u64()
            .unwrap();
        let budget = stopped["total_budget_sat"].as_u64().unwrap();

        let refunded = if seller_misses_deadline {
            while restore::now() <= expiry + 60 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            // All buyers recover while this provider is still stopped. Its
            // accepted signatures can no longer be redeemed for these channels.
            for journal in &journals[2..] {
                restore::wait_journal(journal, 40, |j| {
                    j["funding"].as_object().unwrap().is_empty()
                })
                .await;
            }
            children[0] = start(&paths[0]).await;
            let buyer = restore::wait_journal(&journals[0], 30, |j| {
                j["funding"].as_object().unwrap().is_empty()
            })
            .await;
            let refunded = buyer["history"]["channels"]["totals"]["refund_sat"].clone();
            assert!(refunded.as_u64().unwrap() > 0);
            stop(&mut children[0]).await;
            children[1] = start(&paths[1]).await;
            let recovered = restore::wait_journal(&journals[1], 40, |j| {
                j["funding"].as_object().unwrap().is_empty()
                    && j["seller_settlements"].as_object().unwrap().is_empty()
                    && j["history"]["seller"]["totals"]["accounting"]["channels"]
                        .as_u64()
                        .unwrap_or(0)
                        > 0
            })
            .await;
            let seller = &recovered["history"]["seller"]["totals"];
            assert_eq!(
                seller["paid_sat"], 0,
                "expired signatures are not collected money"
            );
            assert!(seller["signed_sat"].as_u64().unwrap() >= seller_accepted);
            assert_eq!(
                seller["accounting"]["usage"]["paid_msat"].as_u64().unwrap(),
                seller["signed_sat"].as_u64().unwrap() * 1_000
            );
            assert_eq!(
                seller["receiver"]["totals"][0]["signed_amount"],
                seller["signed_sat"]
            );
            assert_eq!(seller["receiver"]["totals"][0]["closed_amount"], 0);
            assert_eq!(seller["receiver"]["totals"][0]["receiver_sum"], 0);
            stop(&mut children[1]).await;
            refunded
        } else {
            // Collect during the grace period without a final buyer RPC.
            while restore::now() <= expiry {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let report = tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    let j = restore::read(&journals[1]);
                    if !j["seller_settlements"][&channel]["report"].is_null() {
                        break j["seller_settlements"][&channel]["report"].clone();
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .expect("expired seller must settle its retained payment without the buyer");
            assert!(report["paid_sat"].as_u64().unwrap() > 0);
            assert!(report["paid_sat"].as_u64().unwrap() <= signed);
            for journal in &journals[1..] {
                restore::wait_journal(journal, 150, |j| {
                    j["funding"].as_object().unwrap().is_empty()
                        && j["seller_settlements"].as_object().unwrap().is_empty()
                })
                .await;
            }
            assert!(restore::now() > expiry + 60);
            stop(&mut children[1]).await;
            report["refunded_sat"].clone()
        };
        children[0] = start(&paths[0]).await;
        // The saved journal is already retired on replay; wait for this process.
        ready(&configs[..1], &paths[..1], &npubs[..1], &mut children[..1]).await;
        let retired = restore::wait_journal(&journals[0], 30, |j| {
            j["funding"].as_object().unwrap().is_empty()
        })
        .await;
        assert!(retired["outgoing"].as_object().unwrap().is_empty());
        assert_eq!(retired["next_funding"], opened["next_funding"]);
        let totals = &retired["history"]["channels"]["totals"];
        assert_eq!(totals["channels"], 1);
        assert_eq!(totals["signed_sat"], signed);
        assert_eq!(totals["refund_sat"], refunded);
        let status = request(&configs[0], &AdminRequest::Status).await.unwrap();
        assert_eq!(status["remaining_budget_sat"], budget - signed);
        assert_eq!(status["funding_budget"]["locked_sat"], 0);
        assert_eq!(status["funding_budget"]["wallet_refunded_sat"], refunded);
        stop(&mut children[0]).await;
        for child in &mut children[2..] {
            stop(child).await;
        }
        let mut available = 0;
        for config in &configs {
            available += load_mint_balance(&config.state_directory.join("wallet"), &proxy.url)
                .await
                .unwrap()
                .balance_sat;
        }
        assert_eq!(
            available + proxy.state.fees_collected.load(Ordering::SeqCst),
            512
        );
    })
    .await
    .expect("bounded shared-channel expiry and offline recovery");
}
