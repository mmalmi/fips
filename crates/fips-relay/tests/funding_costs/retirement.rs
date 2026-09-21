use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn service_retires_real_wallet_channels_after_expiry_without_resetting_spending() {
    tokio::time::timeout(Duration::from_secs(200), async {
        let root = tempfile::tempdir().unwrap();
        let setup::Bench {
            mint,
            configs,
            paths,
            npubs,
            mut children,
        } = setup::start_bench(root.path(), 9617, 60).await;
        let cfg = &configs[0];
        let buy = AdminRequest::Buy {
            destination: npubs[2].clone(),
        };
        request(cfg, &buy).await.unwrap();
        request(cfg, &AdminRequest::Settle).await.unwrap();
        let before = request(cfg, &AdminRequest::Status).await.unwrap()["funding_budget"].clone();
        let controller_path = cfg.state_directory.join("controller/controller.json");
        let seller_controller = configs[1]
            .state_directory
            .join("controller/controller.json");
        let seller_ledger = configs[1].state_directory.join("seller/ledger.json");
        let buyer_path = cfg.state_directory.join("buyer/buyer.json");
        let wallet = cfg.state_directory.join("wallet");
        let wallet_balance = load_mint_balance(&wallet, mint.url())
            .await
            .unwrap()
            .balance_sat;
        let read = |path: &std::path::Path| -> serde_json::Value {
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
        };
        let journal = read(&controller_path);
        let sender_before = read(&cashu_service::spilman_client_store_path(&wallet));
        let refunds = sender_before["settled_refunds"].as_object().unwrap();
        assert_eq!(refunds.len(), 1);
        let refund_originals: Vec<cashu::nuts::Proof> = serde_json::from_str(
            refunds.values().next().unwrap()["proofs_json"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert!(!refund_originals.is_empty());
        assert!(
            journal["buyer_settlements"]
                .as_object()
                .unwrap()
                .values()
                .all(|s| s["released"] == true)
        );
        assert!(
            read(&seller_controller)["seller_settlements"]
                .as_object()
                .unwrap()
                .values()
                .all(|s| s["released"] == true)
        );
        assert_eq!(journal["funding"].as_object().unwrap().len(), 1);
        assert!(
            journal["funding"]
                .as_object()
                .unwrap()
                .keys()
                .all(|id| id.starts_with("cashu-seq-v1:"))
        );
        let expires = journal["funding"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap()["expires_unix"]
            .as_u64()
            .unwrap();
        let buyer_before = read(&buyer_path);
        let signed: u64 = buyer_before["channels"]
            .as_object()
            .unwrap()
            .values()
            .map(|c| c["authorized_sat"].as_u64().unwrap())
            .sum();
        // Lose the release reply after the seller durably received it. Keep the
        // buyer offline until the seller has removed its released report, then
        // require a no-op acknowledgment to finish the buyer's original intent.
        stop(&mut children[0]).await;
        let mut interrupted = read(&controller_path);
        for entry in interrupted["buyer_settlements"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            entry["released"] = false.into();
        }
        std::fs::write(&controller_path, serde_json::to_vec(&interrupted).unwrap()).unwrap();
        let mut restarted = false;
        // Exercise the real recovery worker and wall-clock gate, without editing
        // immutable funding or expiry evidence in any application journal.
        tokio::time::timeout(Duration::from_secs(150), async {
            loop {
                let retired_seller = read(&seller_controller)["seller_settlements"]
                    .as_object()
                    .unwrap()
                    .is_empty();
                if retired_seller && !restarted {
                    children[0] = start(&paths[0]).await;
                    ready(&configs, &paths, &npubs, &mut children).await;
                    restarted = true;
                }
                let j = read(&controller_path);
                if restarted && j["funding"].as_object().unwrap().is_empty() && retired_seller {
                    break;
                }
                let status = request(
                    if restarted { cfg } else { &configs[1] },
                    &AdminRequest::Status,
                )
                .await
                .unwrap();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if now > expires + 90 {
                    panic!("retirement did not finish: {}", status["last_error"]);
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
        .await
        .unwrap();
        let seller_after = read(&seller_ledger);
        assert!(
            seller_after["ledger"]["channels"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(seller_after["ledger"]["history"]["channels"], 1);
        assert_eq!(
            read(&seller_controller)["history"]["seller"]["totals"]["accounting"]["channels"],
            1
        );
        let receiver = cashu_service::FileSpilmanPaymentReceiver::load(
            &configs[1].state_directory.join("receiver"),
            cashu_service::FileSpilmanPaymentReceiverConfig::new([mint.url().to_string()]),
        )
        .unwrap();
        let receiver_history = receiver.retirement_history().unwrap();
        assert_eq!(
            receiver_history
                .totals
                .iter()
                .map(|t| t.channels)
                .sum::<u64>(),
            1,
            "FIPS must finish the original receiver financial handoff"
        );
        assert_eq!(
            read(&seller_controller)["history"]["seller"]["totals"]["receiver"],
            serde_json::to_value(&receiver_history).unwrap()
        );
        let channel_id = journal["buyer_settlements"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap();
        assert!(
            receiver
                .close_cashu_spilman_channel(channel_id)
                .await
                .is_err(),
            "the receiver API must no longer retain the released close report"
        );
        let after = request(cfg, &AdminRequest::Status).await.unwrap();
        assert_eq!(after["funding_budget"], before);
        let buyer_after = read(&buyer_path);
        assert!(buyer_after["channels"].as_object().unwrap().is_empty());
        assert!(buyer_after["quotes"].as_object().unwrap().is_empty());
        assert_eq!(buyer_after["history"]["authorized_sat"], signed);
        assert_eq!(
            read(&controller_path)["history"]["channels"]["totals"]["channels"],
            1
        );
        assert_eq!(
            load_mint_balance(&wallet, mint.url())
                .await
                .unwrap()
                .balance_sat,
            wallet_balance
        );
        for child in &mut children {
            stop(child).await;
        }
        children.clear();
        for path in &paths {
            children.push(start(path).await);
        }
        ready(&configs, &paths, &npubs, &mut children).await;
        let db =
            cdk_sqlite::WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(&wallet))
                .await
                .unwrap();
        let heads = archive_heads(&db).await;
        assert!(!heads.is_empty());
        let financial = read(&controller_path)["history"]["channels"].clone();
        let sender_history = read(&cashu_service::spilman_client_store_path(&wallet))["retirement"]
            ["scopes"].clone();
        // A previous upkeep could have collected only alongside retirement.
        // Require later progress after restart without any new financial owner.
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let current = archive_heads(&db).await;
                let controller = read(&controller_path);
                assert!(controller["funding"].as_object().unwrap().is_empty());
                assert_eq!(controller["history"]["channels"], financial);
                assert_eq!(
                    read(&cashu_service::spilman_client_store_path(&wallet))["retirement"]["scopes"],
                    sender_history
                );
                if heads.iter().any(|(scope, head)| current.get(scope).is_some_and(|next| next > head)) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await.expect("upkeep must revisit custody without another retired channel");
        assert_eq!(
            request(cfg, &AdminRequest::Status).await.unwrap()["funding_budget"],
            before
        );
        let error = request(cfg, &buy).await.unwrap_err();
        assert!(
            error.contains("lifetime wallet spending budget exhausted"),
            "{error}"
        );
        assert_eq!(
            load_mint_balance(&wallet, mint.url())
                .await
                .unwrap()
                .balance_sat,
            wallet_balance
        );
        for child in &mut children {
            stop(child).await;
        }
        // The real service must hand off sender refunds before deleting their
        // original channel owner, including after the source process restarts.
        use cdk_common::database::WalletDatabase;
        let sender = read(&cashu_service::spilman_client_store_path(&wallet));
        assert_eq!(sender["version"], 11);
        assert!(sender["settled_refunds"].is_null());
        let service = cashu_service::CashuWalletService::open_file_backed(&wallet)
            .await
            .unwrap();
        let custody = service.payment_proof_history().await.unwrap();
        assert!(custody.archived_proofs >= refund_originals.len() as u64);
        let registry: serde_json::Value = serde_json::from_slice(
            &db.kv_read("cashu_service", "proof_archive", "registry")
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(
            registry["value"]["scopes"]
                .as_object()
                .unwrap()
                .values()
                .any(|scope| { scope["pending"].is_null() && scope["head"].as_u64().unwrap() > 0 }),
            "service upkeep must visit acknowledged custody after financial retirement"
        );
        let mut archived = std::collections::BTreeMap::new();
        for key in db.kv_list("cashu_service", "proof_archive").await.unwrap() {
            if !key.starts_with("page_") {
                continue;
            }
            let page: serde_json::Value = serde_json::from_slice(
                &db.kv_read("cashu_service", "proof_archive", &key)
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            let proofs: Vec<cashu::nuts::Proof> =
                serde_json::from_value(page["value"]["proofs"].clone()).unwrap();
            for proof in proofs {
                archived.insert(proof.y().unwrap().to_string(), proof);
            }
        }
        for original in &refund_originals {
            let y = original.y().unwrap();
            let saved = db.get_proofs_by_ys(vec![y]).await.unwrap();
            assert_eq!(saved.len(), 1);
            assert!(
                saved[0].proof == *original,
                "original sender refund changed"
            );
            assert_eq!(saved[0].state, cashu::nuts::State::Unspent);
            assert!(
                archived.get(&y.to_string()) == Some(original),
                "sender refund was not handed to paged custody unchanged"
            );
        }
    })
    .await
    .expect("bounded real channel retirement scenario");
}

async fn archive_heads(
    db: &cdk_sqlite::WalletSqliteDatabase,
) -> std::collections::BTreeMap<String, u64> {
    use cdk_common::database::WalletDatabase;
    let registry: serde_json::Value = serde_json::from_slice(
        &db.kv_read("cashu_service", "proof_archive", "registry")
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    registry["value"]["scopes"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(scope, saved)| {
            assert!(saved["pending"].is_null());
            (scope.clone(), saved["head"].as_u64().unwrap())
        })
        .collect()
}
