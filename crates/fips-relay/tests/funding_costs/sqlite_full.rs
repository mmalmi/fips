//! The same real SQLite transaction must fail when full and succeed after recovery.
use cdk_common::database::WalletDatabase;
use cdk_sqlite::WalletSqliteDatabase;
use serde_json::{Value, json};

pub(super) struct Probe<'a> {
    db: &'a WalletSqliteDatabase,
    saved: Value,
    value: Vec<u8>,
}

async fn snapshot(db: &WalletSqliteDatabase) -> Value {
    let mut proofs = db.get_proofs(None, None, None, None).await.unwrap();
    proofs.sort_by_key(|row| row.y.to_string());
    let capacity = db
        .storage_capacity()
        .await
        .unwrap()
        .map(|value| (value.maximum_bytes, value.charged_bytes));
    json!({"proofs": proofs, "capacity": capacity})
}

impl<'a> Probe<'a> {
    pub async fn new(db: &'a WalletSqliteDatabase, bytes: usize) -> Self {
        let capacity = db.storage_capacity().await.unwrap().unwrap();
        assert!(capacity.maximum_bytes - capacity.charged_bytes > bytes as u64 + 256);
        assert_eq!(
            db.kv_read("filesystem-test", "", "probe").await.unwrap(),
            None
        );
        Self {
            db,
            saved: snapshot(db).await,
            value: vec![0x5a; bytes],
        }
    }

    pub async fn refused(&self) {
        let error = self
            .db
            .kv_write("filesystem-test", "", "probe", &self.value)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("database or disk is full"),
            "{error}"
        );
        assert_eq!(
            self.db
                .kv_read("filesystem-test", "", "probe")
                .await
                .unwrap(),
            None
        );
        assert!(
            snapshot(self.db).await == self.saved,
            "failed transaction changed proofs or capacity"
        );
        eprintln!(
            "SQLite FULL: {}-byte write rolled back; proofs and capacity unchanged",
            self.value.len()
        );
    }

    pub async fn recovered(&self) {
        self.db
            .kv_write("filesystem-test", "", "probe", &self.value)
            .await
            .unwrap();
        assert!(
            self.db
                .kv_read("filesystem-test", "", "probe")
                .await
                .unwrap()
                .as_ref()
                == Some(&self.value)
        );
        self.db
            .kv_remove("filesystem-test", "", "probe")
            .await
            .unwrap();
        assert!(
            snapshot(self.db).await == self.saved,
            "recovery changed proofs or capacity"
        );
        eprintln!(
            "same {}-byte write succeeded after freeing space; probe removed; proofs and capacity restored",
            self.value.len()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a marked disposable wallet filesystem and a stopped funded test account"]
async fn funded_wallet_write_recovers_after_filesystem_full() {
    // An 8 MiB ext4 image has roughly 3.5 MiB of usable data blocks.
    let volume = super::Volume::from_environment(2 * 1024 * 1024);
    let wallet = std::path::PathBuf::from(std::env::var_os("FIPS_TEST_STORAGE_WALLET").unwrap())
        .canonicalize()
        .unwrap();
    // The harness supplies its stopped funded account on the marked test mount.
    assert_eq!(wallet, volume.path.parent().unwrap());
    let database = cashu_service::cashu_wallet_db_path(&wallet);
    assert!(database.is_file());
    let db = WalletSqliteDatabase::new(database).await.unwrap();
    assert!(
        !db.get_proofs(None, None, None, None)
            .await
            .unwrap()
            .is_empty()
    );
    let probe = Probe::new(&db, 256 * 1024).await;
    let ballast = volume.fill();
    probe.refused().await;
    drop(ballast);
    probe.recovered().await;
    std::fs::remove_dir(&volume.path).unwrap();
}
