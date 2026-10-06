//! A held payout must not block signing and collection by another provider.
use super::*;
use fips_relay::service::ServiceConfig;
use serde_json::Value;
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
    let (committed, release) =
        setup::pause_channel_close(proxy, &configs[0].state_directory.join("wallet"), incoming);
    let mut requests = JoinSet::new();
    spawn_settlement(&mut requests, 0, configs[0].clone());
    tokio::time::timeout(Duration::from_secs(30), committed)
        .await
        .expect("the middle relay must hold the original incoming mint-close reply")
        .unwrap();
    for (index, config) in configs.iter().enumerate().skip(1) {
        spawn_settlement(&mut requests, index, config.clone());
    }
    // The incoming close owns this wallet. Signing and remote collection need
    // no local wallet proofs; only the outgoing refund must wait for ownership.
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
                && purchase["payment"].is_object()
                && purchase["report"].is_object()
                && purchase["refunded"] == false
        },
    )
    .await;
    assert!(
        !release.is_closed(),
        "the other provider must collect before the held mint reply is released"
    );
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
