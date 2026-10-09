//! Opt-in real ENOSPC on a small, explicitly marked disposable filesystem.
use super::*;
use fips_relay::service::ServiceConfig;
use std::{
    collections::BTreeMap,
    io::{ErrorKind, Write},
    os::unix::{fs::MetadataExt, process::ExitStatusExt},
    path::{Path, PathBuf},
};
use tokio::process::Child;
#[path = "sqlite_full.rs"]
mod sqlite_full;

pub(super) struct Volume {
    pub path: PathBuf,
    device: u64,
    capacity: u64,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a marked disposable 32–128 MiB filesystem; see SERVICE.md"]
async fn full_filesystem_preserves_wallet_and_channels() {
    let volume = Volume::from_environment(32 * 1024 * 1024);
    shared_wallet_recovery(Some(&volume)).await;
}

impl Volume {
    fn from_environment(minimum_bytes: u64) -> Self {
        let root = PathBuf::from(std::env::var_os("FIPS_TEST_STORAGE_VOLUME").unwrap())
            .canonicalize()
            .unwrap();
        let token = std::env::var("FIPS_TEST_STORAGE_TOKEN").unwrap();
        assert!(!token.is_empty());
        let marker: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join(".fips-storage-test.json")).unwrap())
                .unwrap();
        let device = root.metadata().unwrap().dev();
        let capacity = fs2::total_space(&root).unwrap();
        assert_ne!(device, root.parent().unwrap().metadata().unwrap().dev());
        assert!((minimum_bytes..=128 * 1024 * 1024).contains(&capacity));
        assert_eq!(marker["schema"], 1);
        assert_eq!(marker["device"], device);
        assert_eq!(marker["capacity_bytes"], capacity);
        assert_eq!(marker["token"], token);
        let path = tempfile::Builder::new()
            .prefix("relay-case-")
            .tempdir_in(root)
            .unwrap()
            .keep();
        Self {
            path,
            device,
            capacity,
        }
    }

    fn fill(&self) -> tempfile::NamedTempFile {
        assert_eq!(self.path.metadata().unwrap().dev(), self.device);
        assert_eq!(fs2::total_space(&self.path).unwrap(), self.capacity);
        let mut ballast = tempfile::NamedTempFile::new_in(&self.path).unwrap();
        let mut written = 0;
        // Real writes, including the last allocation block; a sparse file or a
        // failure of a large write alone does not establish filesystem exhaustion.
        for block in [64 * 1024, 4096, 1] {
            let bytes = vec![0x5a; block];
            loop {
                match ballast.write(&bytes) {
                    Ok(0) => panic!("ballast write made no progress"),
                    Ok(n) => {
                        written += n as u64;
                        assert!(written <= self.capacity);
                    }
                    Err(error) if error.kind() == ErrorKind::StorageFull => break,
                    Err(error) => panic!("expected ENOSPC, got {error}"),
                }
            }
        }
        ballast.as_file().sync_all().unwrap();
        assert_eq!(fs2::available_space(&self.path).unwrap(), 0);
        eprintln!("isolated filesystem exhausted after {written} ballast bytes");
        ballast
    }

    pub(super) async fn interrupt(
        &self,
        config: &ServiceConfig,
        config_path: &Path,
        child: &mut Child,
        db: &cdk_sqlite::WalletSqliteDatabase,
        mint: &str,
    ) {
        let wallet = config.state_directory.join("wallet");
        let original_proofs = proofs(&wallet, mint).await;
        let probe = sqlite_full::Probe::new(db, 4 * 1024 * 1024).await;
        let ballast = self.fill();
        let journal = config.state_directory.join("controller/controller.json");
        let saved = std::fs::read(&journal).unwrap();
        let error = request(config, &AdminRequest::Settle).await.unwrap_err();
        assert!(error.contains("os error 28"), "expected ENOSPC: {error}");
        assert!(
            std::fs::read(&journal).unwrap() == saved,
            "saved journal changed"
        );

        probe.refused().await;

        child.kill().await.unwrap();
        assert_eq!(child.wait().await.unwrap().signal(), Some(9));
        *child = start(config_path).await;
        let failed = tokio::time::timeout(Duration::from_secs(15), child.wait())
            .await
            .expect("full filesystem must not resume paid routing")
            .unwrap();
        assert!(!failed.success());
        let log = std::fs::read_to_string(config_path.with_extension("log")).unwrap();
        assert!(
            log.contains("os error 28")
                || log.contains("fips-relay: failed to open Cashu wallet database"),
            "full-storage restart must fail while opening wallet state"
        );
        assert!(
            std::fs::read(&journal).unwrap() == saved,
            "saved journal changed"
        );

        drop(ballast);
        assert!(fs2::available_space(&self.path).unwrap() > 4 * 1024 * 1024);
        assert!(
            proofs(&wallet, mint).await == original_proofs,
            "original wallet proofs changed"
        );
        probe.recovered().await;
        // The shared scenario now restarts normally, settles every original
        // channel, reconciles all funds and rechecks lifetime spending limits.
    }
}

async fn proofs(wallet: &Path, mint: &str) -> BTreeMap<String, cashu::nuts::Proof> {
    setup::load_mint_proofs(wallet, mint)
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.y.to_string(), row.proof))
        .collect()
}
