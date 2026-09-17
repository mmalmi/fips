#![cfg(unix)]
//! Real service processes account for mint fees and replayed refunds.
#[allow(dead_code)]
mod process_support;
#[path = "funding_costs/retirement.rs"]
mod retirement;
#[path = "funding_costs/setup.rs"]
mod setup;
use cashu_service::{
    create_topup_quote, load_mint_balance, load_wallet_overview,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use fips_core::config::PeerConfig;
use fips_relay::service::{AdminRequest, RelayService, request};
use process_support::*;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_costs_and_refunds_survive_restart_without_resetting_the_lifetime_limit() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let root = tempfile::tempdir().unwrap();
        let setup::Bench {
            mint,
            configs,
            paths,
            npubs,
            mut children,
        } = setup::start_bench(root.path(), 9616, 600).await;
        let buy = AdminRequest::Buy {
            destination: npubs[2].clone(),
        };
        request(&configs[0], &buy).await.unwrap();
        let status = request(&configs[0], &AdminRequest::Status).await.unwrap();
        let budget = status["funding_budget"].clone();
        let debit = budget["wallet_debited_sat"].as_u64().unwrap();
        assert!(debit > 32 && debit <= 40);
        assert_eq!(budget["locked_sat"], debit);
        assert_eq!(status["locked_sat"], budget["locked_sat"]);
        let wallet = configs[0].state_directory.join("wallet");
        assert_eq!(
            128 - load_mint_balance(&wallet, mint.url())
                .await
                .unwrap()
                .balance_sat,
            debit
        );
        for child in &mut children {
            stop(child).await;
        }
        children.clear();
        for path in &paths {
            children.push(start(path).await);
        }
        ready(&configs, &paths, &npubs, &mut children).await;
        assert_eq!(
            request(&configs[0], &AdminRequest::Status).await.unwrap()["funding_budget"],
            budget
        );
        if let Err(error) = request(&configs[0], &AdminRequest::Settle).await {
            let provider = request(&configs[1], &AdminRequest::Status).await.unwrap();
            panic!("settlement: {error}; provider: {}", provider["last_error"]);
        }
        let settled =
            request(&configs[0], &AdminRequest::Status).await.unwrap()["funding_budget"].clone();
        assert_eq!(settled["locked_sat"], 0);
        assert_eq!(settled["wallet_debited_sat"], debit);
        let refund = settled["wallet_refunded_sat"].as_u64().unwrap();
        assert!(refund > 0 && refund < debit);
        assert_eq!(settled["exposure_sat"], debit - refund);
        assert_eq!(
            128 - load_mint_balance(&wallet, mint.url())
                .await
                .unwrap()
                .balance_sat,
            debit - refund
        );
        // Simulate loss of the controller's completion flag after the SDK has
        // imported and saved the refund. Recovery must reuse its exact total.
        for child in &mut children {
            stop(child).await;
        }
        let journal_path = configs[0]
            .state_directory
            .join("controller/controller.json");
        let mut journal: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&journal_path).unwrap()).unwrap();
        for entry in journal["buyer_settlements"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            entry["refunded"] = false.into();
            entry["released"] = false.into();
            entry["wallet_refund_sat"] = serde_json::Value::Null;
        }
        // Retired offers were removed; recover only the already-recorded close.
        journal["outgoing"] = serde_json::json!({});
        std::fs::write(journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
        children.clear();
        for path in &paths {
            children.push(start(path).await);
        }
        ready(&configs, &paths, &npubs, &mut children).await;
        request(&configs[0], &AdminRequest::Settle).await.unwrap();
        assert_eq!(
            request(&configs[0], &AdminRequest::Status).await.unwrap()["funding_budget"],
            settled
        );
        let before = load_mint_balance(&wallet, mint.url())
            .await
            .unwrap()
            .balance_sat;
        let error = request(&configs[0], &buy).await.unwrap_err();
        assert!(
            error.contains("lifetime wallet spending budget exhausted"),
            "{error}"
        );
        assert_eq!(
            load_mint_balance(&wallet, mint.url())
                .await
                .unwrap()
                .balance_sat,
            before
        );
        for child in &mut children {
            stop(child).await;
        }
    })
    .await
    .expect("bounded funding-cost service scenario");
}
