use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

#[test]
fn private_new_preserves_existing_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profile.json");
    private_new(&path, b"original").unwrap();
    assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    assert!(private_new(&path, b"replacement").is_err());
    let alias = directory.path().join("alias.json");
    symlink(&path, &alias).unwrap();
    assert!(private_new(&alias, b"replacement").is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"original");
    assert!(alias.is_symlink());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
}

#[test]
fn private_new_failed_write_is_retryable() {
    const CHILD: &str = "FIPS_TEST_PRIVATE_NEW_WRITE_LIMIT";
    if std::env::var_os(CHILD).is_none() {
        // Limit only this child. Ignoring SIGXFSZ makes the real write fail
        // partway through instead of terminating the process.
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", "ulimit -f 1; trap '' XFSZ; exec \"$@\"", "sh"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "wallet_tools::tests::private_new_failed_write_is_retryable",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "limited child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profile.json");
    assert!(private_new(&path, &[b'x'; 4096]).is_err());
    assert!(
        !path.exists(),
        "failed write published a partial configuration"
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    private_new(&path, b"complete").unwrap();
    assert_eq!(std::fs::read(path).unwrap(), b"complete");
}
