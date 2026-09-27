//! A held payout must allow other settlement intents to queue for the same wallet.
use super::*;
use cashu_service::spilman_client_store_path;
use fips_relay::service::ServiceConfig;
use serde_json::Value;
use std::collections::BTreeSet;
use tokio::task::JoinSet;

pub(super) async fn settle(
    configs: &[ServiceConfig],
    proxy: &MintProxy,
    middle_db: &cdk_sqlite::WalletSqliteDatabase,
) -> Vec<Value> {
    let before = middle_db.storage_capacity().await.unwrap().unwrap();
    let source = request(&configs[0], &AdminRequest::Status).await.unwrap();
    let middle = request(&configs[1], &AdminRequest::Status).await.unwrap();
    let incoming = source["purchases"][0]["channel"]["id"].as_str().unwrap();
    let outgoing = middle["purchases"][0]["channel"]["id"].as_str().unwrap();
    let store = restore::read(&spilman_client_store_path(
        &configs[0].state_directory.join("wallet"),
    ));
    let funding: Vec<cashu::nuts::Proof> = serde_json::from_str(
        store["funding"][incoming]["funding_proofs_json"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let originals: BTreeSet<_> = funding
        .iter()
        .map(|proof| proof.y().unwrap().to_string())
        .collect();
    assert!(!originals.is_empty());
    let (committed, release) = proxy.state.pause_matching_swap_reply(move |swap| {
        swap.inputs().len() == originals.len()
            && swap
                .inputs()
                .iter()
                .all(|proof| proof.y().is_ok_and(|y| originals.contains(&y.to_string())))
    });
    let mut requests = JoinSet::new();
    spawn_settlement(&mut requests, 0, configs[0].clone());
    tokio::time::timeout(Duration::from_secs(30), committed)
        .await
        .expect("the middle relay must hold the original incoming mint-close reply")
        .unwrap();
    for (index, config) in configs.iter().enumerate().skip(1) {
        spawn_settlement(&mut requests, index, config.clone());
    }
    // The incoming close holds the wallet owner. The outgoing settlement must
    // still persist its intent and sealed usage before waiting to sign locally.
    restore::wait_journal(
        &configs[1]
            .state_directory
            .join("controller/controller.json"),
        15,
        |state| {
            let sale = &state["seller_settlements"][incoming];
            let purchase = &state["buyer_settlements"][outgoing];
            sale["payment"].is_object()
                && sale["report"].is_null()
                && purchase["usage"].is_object()
                && purchase["payment"].is_null()
        },
    )
    .await;
    let capacity = middle_db.storage_capacity().await.unwrap().unwrap();
    assert_eq!(
        capacity, before,
        "queued settlement cannot resize or consume the held wallet"
    );
    assert_eq!(
        Some(capacity.maximum_bytes),
        configs[1].terms.wallet_capacity_bytes
    );
    assert!(capacity.charged_bytes <= capacity.maximum_bytes);
    release.send(()).unwrap();
    let mut settlements = vec![Value::Null; configs.len()];
    while let Some(result) = requests.join_next().await {
        let (index, result) = result.unwrap();
        let result = result.unwrap();
        assert_eq!(result["settlements"].as_array().unwrap().len(), 1);
        settlements[index] = result["settlements"][0].clone();
    }
    settlements
}

fn spawn_settlement(
    requests: &mut JoinSet<(usize, Result<Value, String>)>,
    index: usize,
    config: ServiceConfig,
) {
    requests.spawn(async move { (index, request(&config, &AdminRequest::Settle).await) });
}
