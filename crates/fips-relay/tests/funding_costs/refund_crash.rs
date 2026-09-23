//! SIGKILL at the real wallet/controller handoff, followed by ordinary recovery.
use super::*;
use serde_json::Value;

pub(super) async fn settle(
    configs: &[fips_relay::service::ServiceConfig],
    paths: &[std::path::PathBuf],
    npubs: &[String],
    children: &mut [tokio::process::Child],
    mint_url: &str,
) -> Value {
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
    let marker = wallet.join("test-refund-handoff.reached");
    std::fs::write(wallet.join("test-refund-handoff.arm"), id).unwrap();
    let cfg = configs[0].clone();
    let mut settling = tokio::spawn(async move { request(&cfg, &AdminRequest::Settle).await });
    let expected_marker = format!("{}\n{id}", children[0].id().unwrap());
    tokio::time::timeout(Duration::from_secs(30), async {
        tokio::select! {
            result = &mut settling => panic!("settlement completed before the crash boundary: {result:?}"),
            () = async {
                loop {
                    if std::fs::read_to_string(&marker).is_ok_and(|v| v == expected_marker) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            } => {}
        }
    })
    .await
    .expect("real wallet completion must reach the armed controller handoff");
    children[0].kill().await.unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(children[0].wait().await.unwrap().signal(), Some(9));
    assert!(settling.await.unwrap().is_err());

    // Read-only observations: neither reopening a wallet nor invoking recovery
    // is allowed to repair the state before the original service restarts.
    let interrupted = read(0);
    let pending = &interrupted["buyer_settlements"][id];
    let report = pending["report"].clone();
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
    ready(configs, paths, npubs, children).await;
    let replay = request(&configs[0], &AdminRequest::Settle).await.unwrap();
    assert_eq!(replay["settlements"], serde_json::json!([report]));
    replay
}
