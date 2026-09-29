//! Opt-in filesystem fault in the existing paid process lifecycle. Run unprivileged.
use super::{AdminRequest, MixedBench, Value, request};
use std::{
    fs::{self, Permissions},
    io::ErrorKind,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

struct BlockWalletWrites {
    directory: PathBuf,
    original: Permissions,
}

impl BlockWalletWrites {
    fn new(directory: &Path) -> Self {
        let guard = Self {
            directory: directory.into(),
            original: fs::metadata(directory).unwrap().permissions(),
        };
        // Keep existing files readable and lockable; only atomic replacement fails.
        fs::set_permissions(directory, Permissions::from_mode(0o500)).unwrap();
        assert_eq!(
            tempfile::NamedTempFile::new_in(directory)
                .expect_err("run signer write-failure acceptance as an unprivileged user")
                .kind(),
            ErrorKind::PermissionDenied
        );
        guard
    }
}

impl Drop for BlockWalletWrites {
    fn drop(&mut self) {
        fs::set_permissions(&self.directory, self.original.clone()).unwrap();
    }
}

fn buyer(bench: &MixedBench) -> Value {
    serde_json::from_slice(
        &fs::read(bench.configs[0].state_directory.join("buyer/buyer.json")).unwrap(),
    )
    .unwrap()
}

pub(super) async fn assert_automatic_recovery(bench: &mut MixedBench, channels: &[String]) {
    bench.set_stage("signer-storage-failure");
    let before = bench.states().await;
    let funding = bench.funding_intents(true);
    let pids: Vec<_> = bench.children.iter().map(|child| child.id()).collect();
    let wallet = bench.configs[0].state_directory.join("wallet");
    let client = cashu_service::spilman_client_store_path(&wallet);
    let original_client = fs::read(&client).unwrap();
    let original_mode = fs::metadata(&wallet).unwrap().permissions().mode();
    let original_buyer = buyer(bench);
    let paid = channels
        .iter()
        .map(|channel| bench.relay_usage_msat(channel).1)
        .collect::<Vec<_>>();

    let blocked = BlockWalletWrites::new(&wallet);
    bench.deliver_cohorts(0, 2, 512, 2).await;
    let failed = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let state = request(&bench.configs[0], &AdminRequest::Status)
                .await
                .unwrap();
            if state["last_error"].as_str().is_some_and(|error| {
                error.starts_with("payment signer failed: failed to write Spilman client store:")
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if failed.is_err() {
        bench.delivery_failure(0, 2).await;
        panic!("automatic payment must reach the failed native signer commit");
    }
    let authorized = buyer(bench)["channels"][&channels[0]]["authorized_sat"]
        .as_u64()
        .unwrap();
    assert!(authorized * 1_000 > paid[0]);
    assert_eq!(bench.relay_usage_msat(&channels[0]).1, paid[0]);
    assert!(fs::read(&client).unwrap() == original_client);

    bench.deliver_cohorts(2, 0, 512, 2).await;
    bench.wait_paid_beyond(&channels[1], paid[1]).await;
    assert_eq!(bench.relay_usage_msat(&channels[0]).1, paid[0]);
    assert!(fs::read(&client).unwrap() == original_client);
    eprintln!("automatic signer storage: other buyer paid while signer writes failed");

    // No restart, manual payment flush or new purchase: the scheduler retries.
    drop(blocked);
    assert_eq!(
        fs::metadata(&wallet).unwrap().permissions().mode(),
        original_mode
    );
    bench.wait_paid_beyond(&channels[0], paid[0]).await;
    let recovered = buyer(bench);
    let recovered_authorized = recovered["channels"][&channels[0]]["authorized_sat"]
        .as_u64()
        .unwrap();
    assert!(recovered_authorized >= authorized);
    assert!(bench.relay_usage_msat(&channels[0]).1 >= authorized * 1_000);
    assert_eq!(
        recovered["total_budget_sat"],
        original_buyer["total_budget_sat"]
    );
    let after = bench.states().await;
    for source in [0, 2] {
        assert!(after[source]["purchases"] == before[source]["purchases"]);
        assert_eq!(
            after[source]["funding_budget"],
            before[source]["funding_budget"]
        );
        assert!(
            after[source]["remaining_budget_sat"].as_u64().unwrap()
                <= before[source]["remaining_budget_sat"].as_u64().unwrap()
        );
    }
    assert!(bench.funding_intents(true) == funding);
    for (child, pid) in bench.children.iter_mut().zip(pids) {
        assert_eq!(child.id(), pid);
        assert!(child.try_wait().unwrap().is_none());
    }
    eprintln!("automatic signer storage: original channel recovered without restart");
    bench.set_stage("initial-paid");
}
