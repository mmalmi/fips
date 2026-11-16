//! A held mint close must not occupy the wallet needed by another refund.
use super::*;
use fips_relay::service::ServiceConfig;
use serde_json::Value;
use tokio::task::JoinSet;

pub(super) async fn settle(
    configs: &[ServiceConfig],
    proxy: &MintProxy,
    middle_db: &cdk_sqlite::WalletSqliteDatabase,
) -> (Vec<Value>, bool) {
    let before = middle_db.storage_capacity().await.unwrap().unwrap();
    let wallet = configs[1].state_directory.join("wallet");
    let balance_before = load_mint_balance(&wallet, &proxy.url)
        .await
        .unwrap()
        .balance_sat;
    let source = request(&configs[0], &AdminRequest::Status).await.unwrap();
    let middle = request(&configs[1], &AdminRequest::Status).await.unwrap();
    let incoming = source["purchases"][0]["channel"]["id"].as_str().unwrap();
    assert_eq!(middle["purchases"].as_array().unwrap().len(), 1);
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
    let mut settlements = vec![Value::Null; configs.len()];
    let independent_refund = tokio::time::timeout(Duration::from_secs(15), async {
        while settlements[1].is_null() {
            record(&mut settlements, requests.join_next().await.unwrap());
        }
    })
    .await
    .is_ok();
    let held = restore::read(
        &configs[1]
            .state_directory
            .join("controller/controller.json"),
    );
    let sale = &held["seller_settlements"][incoming];
    assert!(sale["payment"].is_object() && sale["report"].is_null());
    assert!(
        !release.is_closed(),
        "the original incoming mint reply must remain held"
    );
    if independent_refund {
        let refunded = settlements[1]["refunded_sat"].as_u64().unwrap();
        assert!(refunded > 0);
        assert!(
            load_mint_balance(&wallet, &proxy.url)
                .await
                .unwrap()
                .balance_sat
                >= balance_before + refunded
        );
    }
    let capacity = middle_db.storage_capacity().await.unwrap().unwrap();
    assert_eq!(
        capacity.maximum_bytes, before.maximum_bytes,
        "independent settlement cannot resize the wallet"
    );
    assert_eq!(
        Some(capacity.maximum_bytes),
        configs[1].terms.wallet_capacity_bytes
    );
    assert!(capacity.charged_bytes <= capacity.maximum_bytes);
    release.send(()).unwrap();
    while let Some(result) = requests.join_next().await {
        record(&mut settlements, result);
    }
    (settlements, independent_refund)
}

fn record(
    settlements: &mut [Value],
    result: Result<(usize, Result<Value, String>), tokio::task::JoinError>,
) {
    let (index, result) = result.unwrap();
    let result = result.unwrap();
    assert_eq!(result["settlements"].as_array().unwrap().len(), 1);
    settlements[index] = result["settlements"][0].clone();
}

fn spawn_settlement(
    requests: &mut JoinSet<(usize, Result<Value, String>)>,
    index: usize,
    config: ServiceConfig,
) {
    requests.spawn(async move { (index, request(&config, &AdminRequest::Settle).await) });
}
