use fips_relay::service::ServiceConfig;

// Admit sending and receiving, including the shared 4 MiB receiver history reserve.
// Pressure tests still fill every unreserved byte after channel admission.
pub const MIXED_ROLE_CAPACITY: u64 = 20 * 1024 * 1024;

/// Occupy only unreserved space; admitted refunds and payouts retain their allowance.
pub async fn fill_wallet_capacity(config: &ServiceConfig) -> cdk_sqlite::WalletSqliteDatabase {
    use cdk_common::database::WalletDatabase;
    let db = cdk_sqlite::WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(
        &config.state_directory.join("wallet"),
    ))
    .await
    .unwrap();
    db.kv_write("capacity-test", "", "ballast", &[])
        .await
        .unwrap();
    let capacity = db.storage_capacity().await.unwrap().unwrap();
    assert_eq!(
        Some(capacity.maximum_bytes),
        config.terms.wallet_capacity_bytes
    );
    db.kv_write(
        "capacity-test",
        "",
        "ballast",
        &vec![0; (capacity.maximum_bytes - capacity.charged_bytes) as usize],
    )
    .await
    .unwrap();
    assert_eq!(
        db.storage_capacity().await.unwrap().unwrap().charged_bytes,
        capacity.maximum_bytes
    );
    db
}
