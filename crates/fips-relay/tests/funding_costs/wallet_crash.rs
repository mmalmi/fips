//! Exact process identity and one-shot wallet completion barriers.
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Child;

pub(super) fn arm(wallet: &Path, id: &str, stage: &str) -> PathBuf {
    let path = wallet.join(format!("test-wallet-{stage}"));
    std::fs::write(path.with_extension("arm"), id).unwrap();
    path.with_extension("reached")
}

pub(super) async fn kill_at(child: &mut Child, marker: &Path, id: &str) {
    wait_at(child, marker, id).await;
    kill(child).await;
}

pub(super) async fn wait_at(child: &mut Child, marker: &Path, id: &str) {
    let expected = format!("{}\n{id}", child.id().unwrap());
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if std::fs::read_to_string(marker).is_ok_and(|v| v == expected) {
                break;
            }
            assert!(child.try_wait().unwrap().is_none());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("real wallet completion must reach the armed controller handoff");
}

pub(super) async fn kill(child: &mut Child) {
    use std::os::unix::process::ExitStatusExt;
    child.kill().await.unwrap();
    assert_eq!(child.wait().await.unwrap().signal(), Some(9));
}
