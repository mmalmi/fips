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
        // Exercise the real recovery worker and wall-clock gate, without editing
        // immutable funding or expiry evidence in any application journal.
        tokio::time::timeout(Duration::from_secs(150), async {
            loop {
                let j = read(&controller_path);
                if j["funding"].as_object().unwrap().is_empty() {
                    break;
                }
                let status = request(cfg, &AdminRequest::Status).await.unwrap();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if now > expires + 70 {
                    panic!("retirement did not finish: {}", status["last_error"]);
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
        .await
        .unwrap();
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
    })
    .await
    .expect("bounded real channel retirement scenario");
}
