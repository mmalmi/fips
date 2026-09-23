use super::*;
use cdk_common::database::WalletDatabase;
use sha2::{Digest, Sha256};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paid_service_settlement_preserves_redemption_reserves_and_signed_charges() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let root = tempfile::tempdir().unwrap();
        let setup::Bench {
            mint,
            configs,
            paths,
            npubs,
            mut children,
        } = setup::start_bench(root.path(), 9618, 60).await;
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
        for round in 0..3 {
            let payload = format!("fee-{round}:{}", "x".repeat(700));
            let digest = format!("{:x}", Sha256::digest(payload.as_bytes()));
            request(
                &configs[0],
                &AdminRequest::Send {
                    destination: npubs[2].clone(),
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
            .expect("paid datagram must reach the destination");
        }
        #[cfg(feature = "testbench")]
        let settled =
            refund_crash::settle(&configs, &paths, &npubs, &mut children, mint.url()).await;
        #[cfg(not(feature = "testbench"))]
        let settled = request(&configs[0], &AdminRequest::Settle)
            .await
            .unwrap_or_else(|e| panic!("valid fee-bearing traffic must settle: {e}"));
        let reports = settled["settlements"].as_array().unwrap();
        assert_eq!(reports.len(), 1);
        let report = &reports[0];
        let signed = report["paid_sat"].as_u64().unwrap();
        let reserve = report["receiver_fee_reserve_sat"].as_u64().unwrap();
        assert!(signed > 0 && reserve > 0, "exercise a paid fee reserve");
        assert_eq!(
            report["value_after_stage1_sat"].as_u64().unwrap(),
            signed
                + reserve
                + report["refunded_sat"].as_u64().unwrap()
                + report["fee_sat"].as_u64().unwrap()
        );
        let read = |index: usize| -> serde_json::Value {
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
        let buyer = read(0);
        let id = report["channel_id"].as_str().unwrap();
        assert_eq!(buyer["buyer_settlements"][id]["payment"]["balance"], signed);
        assert_eq!(read(1)["seller_settlements"][id]["report"], *report);
        assert_eq!(
            load_mint_balance(&configs[1].state_directory.join("wallet"), mint.url())
                .await
                .unwrap()
                .balance_sat,
            128 + signed + reserve
        );
        let budget =
            request(&configs[0], &AdminRequest::Status).await.unwrap()["funding_budget"].clone();
        let balance = load_mint_balance(&configs[0].state_directory.join("wallet"), mint.url())
            .await
            .unwrap()
            .balance_sat;
        assert_eq!(
            128 - balance,
            budget["wallet_debited_sat"].as_u64().unwrap()
                - budget["wallet_refunded_sat"].as_u64().unwrap()
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
            request(&configs[0], &AdminRequest::Settle).await.unwrap(),
            settled
        );
        assert_eq!(
            request(&configs[0], &AdminRequest::Status).await.unwrap()["funding_budget"],
            budget
        );
        assert_eq!(
            load_mint_balance(&configs[0].state_directory.join("wallet"), mint.url())
                .await
                .unwrap()
                .balance_sat,
            balance
        );
        let reverse = request(&configs[2], &AdminRequest::Settle).await.unwrap();
        let receiver = cashu_service::FileSpilmanPaymentReceiver::load(
            &configs[1].state_directory.join("receiver"),
            cashu_service::FileSpilmanPaymentReceiverConfig::new([mint.url().to_string()]),
        )
        .unwrap();
        let directory = configs[1].state_directory.join("wallet");
        let db =
            cdk_sqlite::WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(&directory))
                .await
                .unwrap();
        // Capture the actual settled payouts before their receiver records retire.
        // Later queue references must retain these exact original wallet rows.
        let mut original = std::collections::BTreeMap::new();
        for report in reports
            .iter()
            .chain(reverse["settlements"].as_array().unwrap())
        {
            let closed = receiver
                .close_cashu_spilman_channel(report["channel_id"].as_str().unwrap())
                .await
                .unwrap();
            assert!(closed.already_closed, "the service must have settled first");
            let proofs: Vec<cashu::nuts::Proof> =
                serde_json::from_str(&closed.receiver_proofs_json).unwrap();
            for proof in proofs {
                let y = proof.y().unwrap();
                let rows = db.get_proofs_by_ys(vec![y]).await.unwrap();
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].proof, proof);
                assert!(original.insert(y.to_string(), rows[0].clone()).is_none());
            }
        }
        let history = tokio::time::timeout(Duration::from_secs(150), async {
            loop {
                let history = receiver.retirement_history().unwrap();
                if history.totals.iter().map(|t| t.channels).sum::<u64>() == 2
                    && read(1)["seller_settlements"]
                        .as_object()
                        .unwrap()
                        .is_empty()
                {
                    break history;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .expect("both paid/zero payout receiver handoffs must finish after actual expiry");
        let all = reports
            .iter()
            .chain(reverse["settlements"].as_array().unwrap());
        let mut expected = [0u64; 4];
        for r in all {
            expected[0] += r["paid_sat"].as_u64().unwrap();
            expected[1] +=
                r["paid_sat"].as_u64().unwrap() + r["receiver_fee_reserve_sat"].as_u64().unwrap();
            expected[2] += r["refunded_sat"].as_u64().unwrap();
            expected[3] += r["value_after_stage1_sat"].as_u64().unwrap();
        }
        let t = &history.totals[0];
        assert_eq!(
            [
                t.closed_amount,
                t.receiver_sum,
                t.sender_sum,
                t.value_after_stage1
            ],
            expected
        );
        assert_eq!(
            read(1)["history"]["seller"]["totals"]["receiver"],
            serde_json::to_value(&history).unwrap()
        );
        assert_eq!(
            request(&configs[0], &AdminRequest::Status).await.unwrap()["funding_budget"],
            budget
        );
        assert_eq!(
            load_mint_balance(&configs[1].state_directory.join("wallet"), mint.url())
                .await
                .unwrap()
                .balance_sat,
            128 + expected[1]
        );
        for child in &mut children {
            stop(child).await;
        }
        // The real service worker must finish the payout ownership handoff,
        // including a nonzero payout with a redemption reserve. All processes
        // are stopped before opening their exclusively owned wallet.
        let wallet = cashu_service::CashuWalletService::open_file_backed(&directory)
            .await
            .unwrap();
        let released = wallet.payment_proof_history().await.unwrap();
        assert!(released.retained_proofs > 0);
        assert_eq!(released.retired_proofs, 0);
        let queue: serde_json::Value = serde_json::from_slice(
            &db.kv_read("cashu_service", "proof_history", "journal")
                .await
                .unwrap()
                .expect("completed seller handoff must release original payouts"),
        )
        .unwrap();
        let candidates = queue["candidates"].as_object().unwrap();
        assert_eq!(candidates.len(), released.retained_proofs);
        assert_eq!(
            candidates.keys().collect::<Vec<_>>(),
            original.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            original
                .values()
                .map(|p| p.proof.amount.to_u64())
                .sum::<u64>(),
            expected[1]
        );
        for (key, proof) in original {
            assert_eq!(
                candidates[&key]["y"],
                serde_json::to_value(proof.y).unwrap()
            );
            let saved = db.get_proofs_by_ys(vec![proof.y]).await.unwrap();
            assert_eq!(saved, vec![proof]);
            assert_eq!(saved[0].state, cashu::nuts::State::Unspent);
            assert_eq!(saved[0].mint_url.to_string(), mint.url());
        }
        assert!(queue["pending"].is_null());
        assert_ne!(read(1)["version"].as_u64().unwrap() & 0x4000, 0);
    })
    .await
    .expect("bounded paid settlement fee scenario");
}
