//! Offline money operations retain their configured pacing across wallet reopen.
use super::*;
use cdk_common::{
    database::WalletDatabase,
    rate_limit::{RateLimitConfig, RateLimiterManager, origin_key},
};
use cdk_sqlite::WalletSqliteDatabase;
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

async fn debt(database: &WalletSqliteDatabase, origin: &str) -> u64 {
    let stored = database
        .kv_read("rate_limiter", "", origin)
        .await
        .unwrap()
        .unwrap();
    let arrival = u64::from_be_bytes(stored.try_into().unwrap());
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    arrival.saturating_sub(now)
}

async fn consume_default_burst(database: Arc<WalletSqliteDatabase>, url: &url::Url) {
    // Persist a real exhausted HTTP burst, without inventing monetary records
    // or spending time waiting for dozens of ordinary mint operations.
    let limits = RateLimitConfig::default();
    let limiter = RateLimiterManager::new(limits, Some(database));
    for _ in 0..limits.capacity.get() {
        limiter.bucket_for(url).acquire(async {}).await;
    }
    limiter.flush().await;
}

async fn configured_debt(database: &WalletSqliteDatabase, origin: &str) -> u64 {
    // CDK persists pacing through a background writer. Allow that write to
    // finish without converting this into a test of filesystem scheduling.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let remaining = debt(database, origin).await;
        if remaining < 1_000 || Instant::now() >= deadline {
            return remaining;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn token(summary: &Value) -> String {
    let payment: Value =
        serde_json::from_slice(&std::fs::read(summary["path"].as_str().unwrap()).unwrap()).unwrap();
    payment["token"].as_str().unwrap().into()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_import_and_export_apply_configured_persisted_request_budget() {
    let root = tempfile::tempdir().unwrap();
    let mut mint = BenchMint::start(
        serde_json::from_value(json!({
            "state_directory": root.path().join("mint"),
            "bind": "127.0.0.1:0",
            "max_issued_sat": 2,
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let mut cfg = config(root.path(), mint.url());
    RelayService::initialize(cfg.clone()).await.unwrap();
    let database = Arc::new(
        WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(
            &cfg.state_directory.join("wallet"),
        ))
        .await
        .unwrap(),
    );
    let url = url::Url::parse(mint.url()).unwrap();
    let origin = origin_key(&url).unwrap();
    let grant = mint
        .handle(BenchRequest::Issue {
            id: "pacing".into(),
            amount_sat: 2,
        })
        .await
        .unwrap();
    consume_default_burst(database.clone(), &url).await;
    assert!(cfg.funding_request_budget.is_none());
    offline_wallet(
        &cfg,
        WalletRequest::Import {
            token: token(&grant),
        },
    )
    .await
    .unwrap();
    let default_debt = debt(&database, &origin).await;

    cfg.funding_request_budget = Some(
        serde_json::from_value(json!({
            "burst": 128, "requests_per_minute": 60_000,
        }))
        .unwrap(),
    );
    let export = offline_wallet(
        &cfg,
        WalletRequest::Export {
            id: 1,
            amount_sat: 1,
        },
    )
    .await
    .unwrap();
    let export_debt = configured_debt(&database, &origin).await;
    if export_debt < 1_000 {
        consume_default_burst(database.clone(), &url).await;
    }
    offline_wallet(
        &cfg,
        WalletRequest::Import {
            token: token(&export),
        },
    )
    .await
    .unwrap();
    let import_debt = configured_debt(&database, &origin).await;

    // Close the original two-sat fixture before asserting pacing behavior.
    // These are stored limiter bounds, not host execution-time thresholds.
    let rest = offline_wallet(
        &cfg,
        WalletRequest::Export {
            id: 2,
            amount_sat: 2,
        },
    )
    .await
    .unwrap();
    mint.handle(BenchRequest::Collect {
        token: token(&rest),
    })
    .await
    .unwrap();
    let history = offline_wallet(&cfg, WalletRequest::AcknowledgeExports { through: 2 })
        .await
        .unwrap();
    assert_eq!(history["requested_sat"], 3);
    assert_eq!(
        offline_wallet(&cfg, WalletRequest::Balance).await.unwrap()["balance_sat"],
        0
    );
    let report = mint.handle(BenchRequest::Report).await.unwrap();
    assert_eq!(report["collected_sat"], 2);
    assert_eq!(report["conserved"], true);
    mint.shutdown().await;
    assert!(
        default_debt > 1_000,
        "omission must preserve CDK's default pacing"
    );
    assert!(
        export_debt < 1_000,
        "configured export retained default debt: {export_debt}ms"
    );
    assert!(
        import_debt < 1_000,
        "configured import retained default debt: {import_debt}ms"
    );
}
