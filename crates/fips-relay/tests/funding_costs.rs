#![cfg(unix)]
//! Real service processes account for mint fees and replayed refunds.
#[path = "funding_costs/cancelled_preopening.rs"]
mod cancelled_preopening;
#[path = "funding_costs/connected_preopening.rs"]
mod connected_preopening;
#[path = "funding_costs/filesystem_exhaustion.rs"]
mod filesystem_exhaustion;
#[path = "funding_costs/paid_fees.rs"]
mod paid_fees;
#[path = "funding_costs/preopening.rs"]
mod preopening;
#[path = "funding_costs/preopening_support.rs"]
mod preopening_support;
#[allow(dead_code)]
mod process_support;
#[path = "funding_costs/restore.rs"]
mod restore;
#[path = "funding_costs/retirement.rs"]
mod retirement;
#[cfg(feature = "testbench")]
#[path = "funding_costs/settlement_crash.rs"]
mod settlement_crash;
#[path = "funding_costs/setup.rs"]
mod setup;
#[path = "funding_costs/terminal_history.rs"]
mod terminal_history;
#[path = "funding_costs/transit_preopening.rs"]
mod transit_preopening;
#[cfg(feature = "testbench")]
#[path = "funding_costs/wallet_crash.rs"]
mod wallet_crash;
use cashu_service::{
    create_topup_quote, load_wallet_overview,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use fips_core::config::PeerConfig;
use fips_relay::service::{AdminRequest, RelayService, request};
use process_support::*;
use setup::load_mint_balance;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_costs_and_refunds_survive_restart_without_resetting_the_lifetime_limit() {
    shared_wallet_recovery(None).await;
}

async fn shared_wallet_recovery(volume: Option<&filesystem_exhaustion::Volume>) {
    tokio::time::timeout(Duration::from_secs(180), async {
        let root = tempfile::tempdir().unwrap();
        let (mint, network) = setup::start_mint(root.path(), 9616).await;
        let url = mint.url().to_owned();
        let setup::Bench {
            mint,
            configs,
            paths,
            npubs,
            mut children,
        } = setup::start_configured_line(
            root.path(),
            mint,
            network,
            &url,
            setup::LineConfig {
                lifetime: 600,
                quote_lifetime: 300,
                funding_limits: &[40, 40, 40, 40],
            },
            |index, config| {
                config.terms.wallet_capacity_bytes = Some(16 * 1024 * 1024);
                if index == 1
                    && let Some(volume) = volume
                {
                    config.state_directory = volume.path.join("state");
                }
            },
        )
        .await;
        let buy = AdminRequest::Buy {
            destination: npubs[3].clone(),
        };
        request(&configs[0], &buy).await.unwrap();
        // This tariff bills session setup in both directions, including replies.
        request(
            &configs[3],
            &AdminRequest::Buy {
                destination: npubs[0].clone(),
            },
        )
        .await
        .unwrap();
        let middle_budget =
            request(&configs[1], &AdminRequest::Status).await.unwrap()["funding_budget"].clone();
        let middle_debit = middle_budget["wallet_debited_sat"].as_u64().unwrap();
        assert!(
            middle_debit > 32 && middle_debit <= 40,
            "transit relay funds its own next hop"
        );
        let middle_db = if volume.is_some() {
            cdk_sqlite::WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(
                &configs[1].state_directory.join("wallet"),
            ))
            .await
            .unwrap()
        } else {
            setup::fill_wallet_capacity(&configs[1]).await
        };
        send_shared_wallet_payload(&configs, &npubs).await;
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
        if let Some(volume) = volume {
            volume
                .interrupt(
                    &configs[1],
                    &paths[1],
                    &mut children[1],
                    &middle_db,
                    mint.url(),
                )
                .await;
        }
        for (index, child) in children.iter_mut().enumerate() {
            if volume.is_none() || index != 1 {
                stop(child).await;
            }
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
        assert_eq!(
            request(&configs[1], &AdminRequest::Status).await.unwrap()["funding_budget"],
            middle_budget
        );
        send_shared_wallet_payload(&configs, &npubs).await;
        let mut settlements = Vec::new();
        for config in &configs {
            let result = request(config, &AdminRequest::Settle).await.unwrap();
            assert_eq!(result["settlements"].as_array().unwrap().len(), 1);
            settlements.push(result["settlements"][0].clone());
        }
        let outgoing = &settlements[1];
        assert!(settlements[0]["paid_sat"].as_u64().unwrap() > 0);
        assert!(outgoing["paid_sat"].as_u64().unwrap() > 0);
        let earned: u64 = [0, 2]
            .iter()
            .map(|&index| {
                settlements[index]["paid_sat"].as_u64().unwrap()
                    + settlements[index]["receiver_fee_reserve_sat"]
                        .as_u64()
                        .unwrap()
            })
            .sum();
        let mut available = 0;
        for config in &configs {
            available += load_mint_balance(&config.state_directory.join("wallet"), mint.url())
                .await
                .unwrap()
                .balance_sat;
        }
        let mut spent = 0;
        let mut returned = 0;
        for config in &configs {
            let budget =
                request(config, &AdminRequest::Status).await.unwrap()["funding_budget"].clone();
            assert_eq!(budget["locked_sat"], 0);
            spent += budget["wallet_debited_sat"].as_u64().unwrap();
            returned += budget["wallet_refunded_sat"].as_u64().unwrap();
        }
        let paid: u64 = settlements
            .iter()
            .map(|report| {
                report["paid_sat"].as_u64().unwrap()
                    + report["receiver_fee_reserve_sat"].as_u64().unwrap()
            })
            .sum();
        assert_eq!(available, 512 + returned + paid - spent);
        let middle_after =
            request(&configs[1], &AdminRequest::Status).await.unwrap()["funding_budget"].clone();
        let middle_refund = middle_after["wallet_refunded_sat"].as_u64().unwrap();
        assert_eq!(middle_after["wallet_debited_sat"], middle_debit);
        assert_eq!(middle_after["locked_sat"], 0);
        assert_eq!(middle_refund, outgoing["refunded_sat"].as_u64().unwrap());
        assert!(middle_refund > 0);
        assert_eq!(
            load_mint_balance(&configs[1].state_directory.join("wallet"), mint.url())
                .await
                .unwrap()
                .balance_sat,
            128 + earned + middle_refund - middle_debit
        );
        let capacity = middle_db.storage_capacity().await.unwrap().unwrap();
        assert_eq!(
            Some(capacity.maximum_bytes),
            configs[1].terms.wallet_capacity_bytes
        );
        assert!(capacity.charged_bytes <= capacity.maximum_bytes);
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

async fn send_shared_wallet_payload(
    configs: &[fips_relay::service::ServiceConfig],
    npubs: &[String],
) {
    let payload = "shared-wallet:".to_owned() + &"x".repeat(700);
    request(
        &configs[0],
        &AdminRequest::Send {
            destination: npubs[3].clone(),
            payload: payload.clone(),
        },
    )
    .await
    .unwrap();
    let delivered = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status = request(&configs[3], &AdminRequest::Status).await.unwrap();
            if status["received"]["bytes"].as_u64().unwrap() == payload.len() as u64 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if delivered.is_err() {
        for (index, config) in configs.iter().enumerate() {
            let status = request(config, &AdminRequest::Status).await.unwrap();
            eprintln!(
                "node {index}: {}",
                serde_json::json!({
                    "received": status["received"], "last_error": status["last_error"],
                    "data_carrier": status["data_carrier"], "funding_budget": status["funding_budget"],
                })
            );
        }
        panic!("paid traffic must cross both relays at wallet capacity");
    }
}
