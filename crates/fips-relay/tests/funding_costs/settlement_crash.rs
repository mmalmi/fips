//! SIGKILL at both wallet/controller handoffs, followed by ordinary recovery.
use super::wallet_crash::{arm, kill, kill_at};
use super::*;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use tokio::process::Child;

pub(super) async fn settle(
    configs: &[fips_relay::service::ServiceConfig],
    paths: &[PathBuf],
    npubs: &[String],
    children: &mut [Child],
    mint_url: &str,
) -> (Value, BTreeMap<String, cashu::nuts::Proof>) {
    let read = |index: usize| -> Value {
        serde_json::from_slice(
            &std::fs::read(
                configs[index]
                    .state_directory
                    .join("controller/controller.json"),
            )
            .unwrap(),
        )
        .unwrap()
    };
    let before = read(0);
    let funding = before["funding"].as_object().unwrap();
    assert_eq!(funding.len(), 1);
    let funded = &funding.values().next().unwrap()["funded"];
    let id = funded["terms"]["id"].as_str().unwrap();
    assert!(!funded["wallet_operation_id"].as_str().unwrap().is_empty());
    let wallet = configs[0].state_directory.join("wallet");
    let balance_before = load_mint_balance(&wallet, mint_url)
        .await
        .unwrap()
        .balance_sat;
    let budget_before =
        request(&configs[0], &AdminRequest::Status).await.unwrap()["funding_budget"].clone();
    assert_eq!(budget_before["wallet_refunded_sat"], 0);
    let seller_wallet = configs[1].state_directory.join("wallet");
    let seller_before = proofs(&seller_wallet, mint_url).await;
    assert!(
        read(1)["seller_settlements"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    let payout_marker = arm(&seller_wallet, id, "payout");
    let refund_marker = arm(&wallet, id, "refund");
    let cfg = configs[0].clone();
    let mut settling = tokio::spawn(async move { request(&cfg, &AdminRequest::Settle).await });
    tokio::select! {
        result = &mut settling => panic!("settlement completed before the payout boundary: {result:?}"),
        () = kill_at(&mut children[1], &payout_marker, id) => {}
    }
    // Keep the buyer absent during seller recovery: no peer retry may drive the
    // missing report write. Its original administrative request must be lost.
    kill(&mut children[0]).await;
    assert!(settling.await.unwrap().is_err());
    let seller = read(1);
    assert_eq!(seller["seller_settlements"].as_object().unwrap().len(), 1);
    let interrupted_sale = seller["seller_settlements"][id].clone();
    assert!(interrupted_sale["report"].is_null());
    assert_eq!(interrupted_sale["released"], false);
    assert_eq!(interrupted_sale["channel"], funded["terms"]);
    let signed = interrupted_sale["payment"]["balance"].as_u64().unwrap();
    assert!(signed > 0);
    assert!(read(0)["buyer_settlements"][id]["report"].is_null());
    let seller_paid = proofs(&seller_wallet, mint_url).await;
    assert!(
        seller_before
            .iter()
            .all(|(y, proof)| seller_paid.get(y) == Some(proof))
    );
    let payout_proofs: BTreeMap<_, _> = seller_paid
        .iter()
        .filter(|(y, _)| !seller_before.contains_key(*y))
        .map(|(y, proof)| (y.clone(), proof.proof.clone()))
        .collect();
    let payout: u64 = payout_proofs
        .values()
        .map(|proof| proof.amount.to_u64())
        .sum();
    assert!(
        payout > signed,
        "exercise an imported payout with a fee reserve"
    );

    children[1] = start(&paths[1]).await;
    let recovered_sale = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let sale = read(1)["seller_settlements"][id].clone();
            if !sale["report"].is_null() {
                break sale;
            }
            assert!(children[1].try_wait().unwrap().is_none());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("seller upkeep must save the original payout without its buyer");
    let original_report = recovered_sale["report"].clone();
    let mut expected_sale = interrupted_sale;
    expected_sale["report"] = original_report.clone();
    assert_eq!(recovered_sale, expected_sale);
    assert_eq!(read(1)["seller_settlements"].as_object().unwrap().len(), 1);
    assert_eq!(original_report["channel_id"], id);
    assert_eq!(original_report["paid_sat"], signed);
    assert_eq!(
        payout,
        signed
            + original_report["receiver_fee_reserve_sat"]
                .as_u64()
                .unwrap()
    );
    assert_eq!(proofs(&seller_wallet, mint_url).await, seller_paid);
    assert_eq!(
        load_mint_balance(&wallet, mint_url)
            .await
            .unwrap()
            .balance_sat,
        balance_before
    );

    // Buyer upkeep must recover the saved report and original refund without a
    // new Settle request, then reach the second actual wallet handoff.
    children[0] = start(&paths[0]).await;
    kill_at(&mut children[0], &refund_marker, id).await;

    // Read-only observations: neither reopening a wallet nor invoking recovery
    // is allowed to repair the state before the original service restarts.
    let interrupted = read(0);
    let pending = &interrupted["buyer_settlements"][id];
    let report = pending["report"].clone();
    assert_eq!(report, original_report);
    let refund = report["refunded_sat"].as_u64().unwrap();
    assert!(refund > 0);
    assert_eq!(pending["refunded"], false);
    assert_eq!(pending["released"], false);
    assert!(pending["wallet_refund_sat"].is_null());
    assert_eq!(pending["channel"], funded["terms"]);
    assert_eq!(pending["payment"]["balance"], report["paid_sat"]);
    assert_eq!(read(1)["seller_settlements"][id]["report"], report);
    assert_eq!(read(1)["seller_settlements"][id]["released"], false);
    assert_eq!(interrupted["funding"], before["funding"]);
    let recovered_balance = load_mint_balance(&wallet, mint_url)
        .await
        .unwrap()
        .balance_sat;
    assert_eq!(recovered_balance, balance_before + refund);

    children[0] = start(&paths[0]).await;
    // Status and journal reads only. In particular, do not retry Settle until
    // the normal worker has completed both refund accounting and release.
    let budget = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let buyer = read(0);
            if buyer["buyer_settlements"][id]["refunded"] == true
                && buyer["buyer_settlements"][id]["released"] == true
                && read(1)["seller_settlements"][id]["released"] == true
                && let Ok(status) = request(&configs[0], &AdminRequest::Status).await
            {
                break status["funding_budget"].clone();
            }
            assert!(children[0].try_wait().unwrap().is_none());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("ordinary restart must finish the original settlement automatically");
    let recovered = read(0);
    assert_eq!(recovered["funding"], before["funding"]);
    assert_eq!(recovered["next_funding"], before["next_funding"]);
    assert_eq!(recovered["policy"], before["policy"]);
    let mut expected = pending.clone();
    expected["refunded"] = true.into();
    expected["released"] = true.into();
    expected["wallet_refund_sat"] = refund.into();
    assert_eq!(recovered["buyer_settlements"][id], expected);
    let mut expected_budget = budget_before;
    expected_budget["wallet_refunded_sat"] = refund.into();
    expected_budget["locked_sat"] = 0.into();
    expected_budget["exposure_sat"] =
        (expected_budget["wallet_debited_sat"].as_u64().unwrap() - refund).into();
    assert_eq!(budget, expected_budget);
    assert_eq!(
        load_mint_balance(&wallet, mint_url)
            .await
            .unwrap()
            .balance_sat,
        recovered_balance
    );
    assert_eq!(read(1)["seller_settlements"][id]["report"], report);
    assert_eq!(proofs(&seller_wallet, mint_url).await, seller_paid);
    ready(configs, paths, npubs, children).await;
    let replay = request(&configs[0], &AdminRequest::Settle).await.unwrap();
    assert_eq!(replay["settlements"], serde_json::json!([report]));
    (replay, payout_proofs)
}

async fn proofs(wallet: &Path, mint: &str) -> BTreeMap<String, cdk_common::wallet::ProofInfo> {
    setup::load_mint_proofs(wallet, mint)
        .await
        .unwrap()
        .into_iter()
        .map(|proof| (proof.y.to_string(), proof))
        .collect()
}
