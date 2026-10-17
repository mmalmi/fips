//! Real export custody and bounded retained-cache pressure.
use super::*;
use std::{os::unix::fs::OpenOptionsExt, time::Instant};

async fn export_custody(cfg: &ServiceConfig) -> (usize, Vec<cdk_common::wallet::Transaction>) {
    use cdk_common::database::WalletDatabase;
    // Only the fixed test wallet is inspected; never log its original proofs.
    let database = cdk_sqlite::WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(
        &cfg.state_directory.join("wallet"),
    ))
    .await
    .unwrap();
    let coins = database
        .get_proofs(None, None, None, None)
        .await
        .unwrap()
        .len();
    let receipts = database
        .list_transactions(
            None,
            Some(cdk_common::wallet::TransactionDirection::Incoming),
            None,
        )
        .await
        .unwrap();
    (coins, receipts)
}

async fn unspent_export_survives_recovery(cfg: &ServiceConfig, payment: &Value) {
    use cdk_common::database::WalletDatabase;
    let database = cdk_sqlite::WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(
        &cfg.state_directory.join("wallet"),
    ))
    .await
    .unwrap();
    let operation = payment["operation_id"].as_str().unwrap().parse().unwrap();
    let original = database.get_saga(&operation).await.unwrap().unwrap();
    assert_eq!(
        original.state,
        cdk_common::wallet::WalletSagaState::Send(cdk_common::wallet::SendSagaState::TokenCreated)
    );
    let proofs = database.get_proofs(None, None, None, None).await.unwrap();
    let recovered = offline_wallet(cfg, WalletRequest::Recover).await.unwrap();
    assert_eq!(recovered["recovery_pass_complete"], true);
    assert_eq!(recovered["minted_amount"], 0);
    assert_eq!(recovered["finalized_melts"], 0);
    assert!(
        database.get_saga(&operation).await.unwrap().as_ref() == Some(&original),
        "a successful recovery pass retains the unclaimed original send"
    );
    assert!(
        database.get_proofs(None, None, None, None).await.unwrap() == proofs,
        "recovery must not reclaim or discard a still-unspent export"
    );
}

pub(super) async fn check_export_retirement(exports: u64) {
    let root = tempfile::tempdir().unwrap().keep();
    eprintln!("export retirement fixture: {}", root.display());
    let retained_batch = exports == 131;
    // Fixed disposable seed; recovery must preserve the original URL and SQLite.
    let mut mint = BenchMint::start_seeded(
        BenchConfig {
            state_directory: root.join("mint"),
            bind: "127.0.0.1:0".parse().unwrap(),
            max_issued_sat: 256,
            fragmented_channel_keyset: false,
        },
        614,
    )
    .await
    .unwrap();
    let mut cfg = config(&root, mint.url());
    cfg.terms.wallet_capacity_bytes = Some(16 * 1024 * 1024);
    let saved = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("relay.json"))
        .unwrap();
    serde_json::to_writer(&saved, &cfg).unwrap();
    saved.sync_all().unwrap();
    RelayService::initialize(cfg.clone()).await.unwrap();
    let buyer = std::fs::read(cfg.state_directory.join("buyer/buyer.json")).unwrap();
    let export = WalletRequest::Export {
        id: 1,
        amount_sat: 1,
    };
    let ack = WalletRequest::AcknowledgeExports { through: 1 };
    assert!(offline_wallet(&cfg, export.clone()).await.is_err());
    assert!(
        offline_wallet(&cfg, ack.clone())
            .await
            .unwrap_err()
            .contains("unfinished wallet request"),
        "unfinished sends cannot be retired"
    );
    let grant = mint
        .handle(BenchRequest::Issue {
            id: "retirement".into(),
            amount_sat: 256,
        })
        .await
        .unwrap();
    let payment: Value =
        serde_json::from_slice(&std::fs::read(grant["path"].as_str().unwrap()).unwrap()).unwrap();
    offline_wallet(
        &cfg,
        WalletRequest::Import {
            token: payment["token"].as_str().unwrap().into(),
        },
    )
    .await
    .unwrap();
    let directory = cfg.state_directory.join("exports");
    // Unknown evidence consumes capacity and is never silently deleted.
    for n in 0..128 {
        std::fs::write(directory.join(format!("retained-{n}")), b"retained").unwrap();
    }
    let full = offline_wallet(
        &cfg,
        WalletRequest::Export {
            id: 2,
            amount_sat: 1,
        },
    )
    .await
    .unwrap_err();
    assert!(full.contains("export file limit"));
    let wallet =
        cashu_service::CashuWalletService::open_file_backed(&cfg.state_directory.join("wallet"))
            .await
            .unwrap();
    assert!(
        wallet
            .wallet_send_request("cashu-seq-v1:fips-exports:2")
            .await
            .unwrap()
            .is_none()
    );
    drop(wallet);
    assert_eq!(
        offline_wallet(&cfg, WalletRequest::Balance).await.unwrap()["balance_sat"],
        256
    );
    for n in 1..128 {
        std::fs::remove_file(directory.join(format!("retained-{n}"))).unwrap();
    }
    let (initial_coins, incoming_receipts) = export_custody(&cfg).await;
    assert_eq!(incoming_receipts.len(), 1);
    let mut last_history = Value::Null;
    for id in 1..=exports {
        let amount_sat = if id == exports { 257 - exports } else { 1 };
        let summary = offline_wallet(&cfg, WalletRequest::Export { id, amount_sat })
            .await
            .unwrap();
        if id == 3 {
            assert!(
                !directory.join("2.json").exists(),
                "new exports finish previously acknowledged cleanup"
            );
        }
        let path = Path::new(summary["path"].as_str().unwrap());
        let original = std::fs::read(path).unwrap();
        if id == 1 {
            let mut changed: Value = serde_json::from_slice(&original).unwrap();
            changed["operation_id"] = json!("conflicting");
            let bytes = serde_json::to_vec(&changed).unwrap();
            std::fs::write(path, &bytes).unwrap();
            assert!(offline_wallet(&cfg, ack.clone()).await.is_err());
            assert!(
                std::fs::read(path).unwrap() == bytes,
                "retain refused evidence"
            );
            let wallet = cashu_service::CashuWalletService::open_file_backed(
                &cfg.state_directory.join("wallet"),
            )
            .await
            .unwrap();
            assert_eq!(
                wallet.wallet_send_history().await.unwrap().sequences["fips-exports"].through,
                0
            );
            drop(wallet);
            std::fs::write(path, &original).unwrap();
        }
        let payment: Value = serde_json::from_slice(&original).unwrap();
        let collect = BenchRequest::Collect {
            token: payment["token"].as_str().unwrap().into(),
        };
        if id != 2 {
            mint.handle(collect.clone()).await.unwrap();
        }
        if id == 1 {
            // Fail cache deletion after the SDK has durably retired the request.
            let permissions = std::fs::metadata(&directory).unwrap().permissions();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500)).unwrap();
            let interrupted = offline_wallet(&cfg, ack.clone()).await;
            std::fs::set_permissions(&directory, permissions).unwrap();
            assert!(interrupted.is_err());
            assert!(std::fs::read(path).unwrap() == original);
            let wallet = cashu_service::CashuWalletService::open_file_backed(
                &cfg.state_directory.join("wallet"),
            )
            .await
            .unwrap();
            let retired = wallet.wallet_send_history().await.unwrap();
            assert_eq!(retired.sequences["fips-exports"].through, 1);
            assert_eq!(retired.sequences["fips-exports"].cost.wallet_debit_sat, 1);
            drop(wallet);
            assert!(offline_wallet(&cfg, export.clone()).await.is_err());
        }
        // The opt-in case fills the real cache after the two interruption checks.
        if retained_batch && (3..130).contains(&id) {
            continue;
        }
        let cached_bytes = if retained_batch && id == 130 {
            full_cache_refuses_new_spending(&cfg).await
        } else {
            0
        };
        let command = WalletRequest::AcknowledgeExports { through: id };
        // Observe the whole offline call, including reopen, validation and cleanup.
        let started = Instant::now();
        last_history = offline_wallet(&cfg, command.clone()).await.unwrap();
        let elapsed = started.elapsed();
        if retained_batch && id == 130 {
            eprintln!(
                "EXPORT_PRESSURE {}",
                json!({
                    "retained_exports": 128, "cached_bytes": cached_bytes,
                    "wallet_capacity_bytes": cfg.terms.wallet_capacity_bytes,
                    "whole_offline_reopen_ack_us": elapsed.as_micros(),
                    "through": last_history["through"],
                    "requested_sat": last_history["requested_sat"],
                })
            );
        }
        assert_eq!(last_history["through"], id);
        assert_eq!(last_history["requests"], id);
        assert_eq!(
            last_history["requested_sat"],
            if id == exports { 256 } else { id }
        );
        assert_eq!(
            last_history["cost"]["wallet_debit_sat"],
            last_history["requested_sat"]
        );
        let marker_retained = !retained_batch || id <= 2;
        assert_eq!(
            std::fs::read_dir(&directory).unwrap().count(),
            usize::from(marker_retained)
        );
        if marker_retained {
            assert_eq!(
                std::fs::read(directory.join("retained-0")).unwrap(),
                b"retained"
            );
        }
        if id == 2 {
            // An acknowledgement may hand off a still-unclaimed token. Keep it
            // outside the cache and prove it remains redeemable after cleanup.
            unspent_export_survives_recovery(&cfg, &payment).await;
            mint.handle(collect).await.unwrap();
        }
        if id == 2 {
            // Model an acknowledged cache file still present after interruption.
            std::fs::write(path, &original).unwrap();
            if retained_batch {
                // Remove only our synthetic marker after proving it was preserved.
                std::fs::remove_file(directory.join("retained-0")).unwrap();
            }
        }
        if id == 1 {
            assert_eq!(
                last_history,
                offline_wallet(&cfg, command).await.unwrap(),
                "acknowledgement retries do not reset or add costs"
            );
        }
    }
    let wallet =
        cashu_service::CashuWalletService::open_file_backed(&cfg.state_directory.join("wallet"))
            .await
            .unwrap();
    assert_eq!(
        wallet
            .wallet_send_history()
            .await
            .unwrap()
            .retained_requests,
        0
    );
    let proof_history = wallet.payment_proof_history().await.unwrap();
    assert!(
        proof_history.retired_proofs > 0,
        "acknowledged exports must release their native coin history"
    );
    drop(wallet);
    // Close an absent number too: it must never become fresh spending authority.
    let closed = offline_wallet(
        &cfg,
        WalletRequest::AcknowledgeExports {
            through: exports + 1,
        },
    )
    .await
    .unwrap();
    assert_eq!(closed["requests"], last_history["requests"]);
    for id in [1, exports, exports + 1] {
        assert!(
            offline_wallet(&cfg, WalletRequest::Export { id, amount_sat: 2 })
                .await
                .is_err()
        );
    }
    assert_eq!(
        offline_wallet(&cfg, WalletRequest::Balance).await.unwrap()["balance_sat"],
        0
    );
    assert_eq!(
        buyer,
        std::fs::read(cfg.state_directory.join("buyer/buyer.json")).unwrap()
    );
    let collected = mint.handle(BenchRequest::Report).await.unwrap();
    assert_eq!(collected["issued_sat"], 256);
    assert_eq!(collected["collected_sat"], 256);
    assert_eq!(collected["conserved"], true);
    let recovered = offline_wallet(
        &cfg,
        serde_json::from_value(json!({"type":"recover"})).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(recovered["recovery_pass_complete"], true);
    assert_eq!(recovered["warning_count"], 0);
    assert_eq!(recovered["minted_amount"], 0);
    assert_eq!(recovered["finalized_melts"], 0);
    let acknowledged = offline_wallet(
        &cfg,
        WalletRequest::AcknowledgeExports {
            through: exports + 1,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        acknowledged, closed,
        "recovery does not change retired send costs"
    );
    let wallet =
        cashu_service::CashuWalletService::open_file_backed(&cfg.state_directory.join("wallet"))
            .await
            .unwrap();
    // Fixed cleanup work for this fixture, independent of the export count.
    // Original incoming receipt owners remain; their coin rows are not garbage.
    for _ in 0..64 {
        wallet.collect_released_proof_history().await.unwrap();
    }
    let proof_history = wallet.payment_proof_history().await.unwrap();
    let capacity = wallet.storage_capacity().await.unwrap().unwrap();
    assert_eq!(
        Some(capacity.maximum_bytes),
        cfg.terms.wallet_capacity_bytes
    );
    assert!(capacity.charged_bytes <= capacity.maximum_bytes);
    drop(wallet);
    let (native_coins, retained_receipts) = export_custody(&cfg).await;
    assert_eq!(
        retained_receipts, incoming_receipts,
        "recovery preserves original incoming receipts"
    );
    eprintln!(
        "exports={exports} initial_coins={initial_coins} native_coins={native_coins} retired_coins={} archived_refs={}",
        proof_history.retired_proofs, proof_history.archived_proofs
    );
    assert!(
        native_coins <= initial_coins,
        "export coin history exceeds original receipt custody: {native_coins} > {initial_coins}"
    );
    let report = mint.handle(BenchRequest::Report).await.unwrap();
    assert_eq!(
        report, collected,
        "recovery creates no new funding or spending"
    );
    mint.shutdown().await;
}

async fn full_cache_refuses_new_spending(cfg: &ServiceConfig) -> u64 {
    let directory = cfg.state_directory.join("exports");
    let originals: Vec<_> = (3..=130)
        .map(|id| {
            let path = directory.join(format!("{id}.json"));
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 128);
    let wallet =
        cashu_service::CashuWalletService::open_file_backed(&cfg.state_directory.join("wallet"))
            .await
            .unwrap();
    let before = wallet.wallet_send_history().await.unwrap();
    assert_eq!(before.retained_requests, 128);
    assert_eq!(before.sequences["fips-exports"].through, 2);
    drop(wallet);
    let request = WalletRequest::Export {
        id: 131,
        amount_sat: 126,
    };
    assert!(
        offline_wallet(cfg, request)
            .await
            .unwrap_err()
            .contains("export file limit")
    );
    let wallet =
        cashu_service::CashuWalletService::open_file_backed(&cfg.state_directory.join("wallet"))
            .await
            .unwrap();
    assert_eq!(wallet.wallet_send_history().await.unwrap(), before);
    assert!(
        wallet
            .wallet_send_request("cashu-seq-v1:fips-exports:131")
            .await
            .unwrap()
            .is_none()
    );
    drop(wallet);
    assert_eq!(
        offline_wallet(cfg, WalletRequest::Balance).await.unwrap()["balance_sat"],
        126
    );
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 128);
    assert!(
        originals
            .iter()
            .all(|(path, bytes)| std::fs::read(path).unwrap() == *bytes)
    );
    originals.iter().map(|(_, bytes)| bytes.len() as u64).sum()
}
