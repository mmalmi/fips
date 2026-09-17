#![cfg(all(unix, feature = "testbench"))]

use fips_relay::{
    service::{RelayService, ServiceConfig},
    testbench::{BenchConfig, BenchMint, BenchRequest},
    wallet_tools::{WalletRequest, offline_wallet},
};
use serde_json::{Value, json};
use std::{os::unix::fs::PermissionsExt, path::Path};

fn config(root: &Path, mint: &str) -> ServiceConfig {
    let mut value: Value = serde_json::from_str(include_str!("../service.example.json")).unwrap();
    value["state_directory"] = json!(root.join("relay"));
    value["transports"] = json!({"udp": {"bind_addr": "127.0.0.1:0", "advertise_on_nostr": false}});
    value["terms"]["controller"]["mint_url"] = json!(mint);
    serde_json::from_value(value).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_mint_funds_a_saved_relay_and_redeems_its_private_export() {
    let root = tempfile::tempdir().unwrap();
    let mint_config = BenchConfig {
        state_directory: root.path().join("mint"),
        bind: "127.0.0.1:0".parse().unwrap(),
        max_issued_sat: 256,
    };
    let mut mint = BenchMint::start(mint_config.clone()).await.unwrap();
    assert!(BenchMint::start(mint_config).await.is_err());
    let cfg = config(root.path(), mint.url());
    RelayService::initialize(cfg.clone()).await.unwrap();
    let buyer_before = std::fs::read(cfg.state_directory.join("buyer/buyer.json")).unwrap();
    let grant = BenchRequest::Issue {
        id: "router-1".into(),
        amount_sat: 256,
    };
    let first = mint.handle(grant.clone()).await.unwrap();
    assert_eq!(
        first,
        mint.handle(grant).await.unwrap(),
        "same grant is reused"
    );
    assert!(
        mint.handle(BenchRequest::Issue {
            id: "router-2".into(),
            amount_sat: 1,
        })
        .await
        .is_err()
    );
    assert!(
        mint.handle(BenchRequest::Issue {
            id: "router-1".into(),
            amount_sat: 255,
        })
        .await
        .is_err()
    );
    let token_path = first["path"].as_str().unwrap();
    assert_eq!(
        std::fs::metadata(token_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let payment: Value = serde_json::from_slice(&std::fs::read(token_path).unwrap()).unwrap();
    let token = payment["token"].as_str().unwrap().to_owned();
    let live = RelayService::load(cfg.clone()).await.unwrap();
    assert!(
        offline_wallet(
            &cfg,
            WalletRequest::Import {
                token: token.clone()
            }
        )
        .await
        .is_err()
    );
    live.shutdown().await.unwrap();
    let received = offline_wallet(
        &cfg,
        WalletRequest::Import {
            token: token.clone(),
        },
    )
    .await
    .unwrap();
    assert_eq!(received["amount_sat"], 256);
    assert!(!received.to_string().contains("cashuB"));
    assert!(
        offline_wallet(&cfg, WalletRequest::Import { token })
            .await
            .is_err()
    );
    assert_eq!(
        offline_wallet(&cfg, WalletRequest::Balance).await.unwrap()["balance_sat"],
        256
    );
    assert_eq!(
        buyer_before,
        std::fs::read(cfg.state_directory.join("buyer/buyer.json")).unwrap(),
        "funding cannot reset spending authorization or create relay credit"
    );
    let export = WalletRequest::Export {
        id: "return-1".into(),
        amount_sat: 256,
    };
    let sent = offline_wallet(&cfg, export.clone()).await.unwrap();
    assert_eq!(sent, offline_wallet(&cfg, export).await.unwrap());
    assert!(!sent.to_string().contains("cashuB"));
    assert!(
        offline_wallet(
            &cfg,
            WalletRequest::Export {
                id: "../escape".into(),
                amount_sat: 1
            }
        )
        .await
        .is_err()
    );
    let returned: Value =
        serde_json::from_slice(&std::fs::read(sent["path"].as_str().unwrap()).unwrap()).unwrap();
    mint.handle(BenchRequest::Collect {
        token: returned["token"].as_str().unwrap().into(),
    })
    .await
    .unwrap();
    assert_eq!(
        offline_wallet(&cfg, WalletRequest::Balance).await.unwrap()["balance_sat"],
        0
    );
    let report = mint.handle(BenchRequest::Report).await.unwrap();
    assert_eq!(report["issued_sat"], 256);
    assert_eq!(report["collected_sat"], 256);
    assert_eq!(report["conserved"], true);
    // A pending export is not silently retried as a fresh spend.
    std::fs::write(cfg.state_directory.join("exports/interrupted.intent"), b"1").unwrap();
    assert!(
        offline_wallet(
            &cfg,
            WalletRequest::Export {
                id: "interrupted".into(),
                amount_sat: 1
            }
        )
        .await
        .is_err()
    );
    mint.shutdown().await;
}

#[tokio::test]
async fn test_mint_refuses_public_or_wildcard_binding() {
    let root = tempfile::tempdir().unwrap();
    for address in [
        "0.0.0.0:30338",
        "8.8.8.8:30338",
        "[::]:30338",
        "224.0.0.1:30338",
    ] {
        let cfg = BenchConfig {
            state_directory: root.path().join("mint"),
            bind: address.parse().unwrap(),
            max_issued_sat: 10,
        };
        assert!(BenchMint::start(cfg).await.is_err());
        assert!(!root.path().join("mint").exists());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn command_line_tools_fund_over_the_private_control_socket() {
    use std::{process::Stdio, time::Duration};
    use tokio::{io::AsyncWriteExt, process::Command};

    async fn cli(binary: &str, action: &str, config: &Path, input: Value) -> std::process::Output {
        let mut child = Command::new(binary)
            .args([action, config.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin
            .write_all(&serde_json::to_vec(&input).unwrap())
            .await
            .unwrap();
        stdin.shutdown().await.unwrap();
        drop(stdin);
        child.wait_with_output().await.unwrap()
    }

    tokio::time::timeout(Duration::from_secs(60), async {
        let root = tempfile::tempdir().unwrap();
        let cfg = BenchConfig {
            state_directory: root.path().join("mint"),
            bind: "127.0.0.1:0".parse().unwrap(),
            max_issued_sat: 16,
        };
        let path = root.path().join("mint.json");
        std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_fips-relay-test-mint"))
            .args(["run", path.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let ready = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "test mint stays running"
                );
                if let Ok(report) =
                    fips_relay::testbench::request(&cfg, &BenchRequest::Report).await
                {
                    break report;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        let relay = config(root.path(), ready["url"].as_str().unwrap());
        let relay_path = root.path().join("relay.json");
        std::fs::write(&relay_path, serde_json::to_vec(&relay).unwrap()).unwrap();
        let initialized = cli(
            env!("CARGO_BIN_EXE_fips-relay"),
            "init",
            &relay_path,
            Value::Null,
        )
        .await;
        assert!(
            initialized.status.success(),
            "{}",
            String::from_utf8_lossy(&initialized.stderr)
        );
        let grant = cli(
            env!("CARGO_BIN_EXE_fips-relay-test-mint"),
            "ctl",
            &path,
            json!({"type":"issue","id":"phone","amount_sat":16}),
        )
        .await;
        assert!(
            grant.status.success(),
            "{}",
            String::from_utf8_lossy(&grant.stderr)
        );
        let grant: Value = serde_json::from_slice(&grant.stdout).unwrap();
        let payment: Value =
            serde_json::from_slice(&std::fs::read(grant["path"].as_str().unwrap()).unwrap())
                .unwrap();
        let imported = cli(
            env!("CARGO_BIN_EXE_fips-relay"),
            "wallet",
            &relay_path,
            json!({"type":"import","token":payment["token"]}),
        )
        .await;
        assert!(
            imported.status.success(),
            "{}",
            String::from_utf8_lossy(&imported.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&imported.stdout).unwrap()["amount_sat"],
            16
        );
        assert_eq!(
            std::fs::metadata(cfg.state_directory.join("control.sock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(
            Command::new("kill")
                .args(["-TERM", &child.id().unwrap().to_string()])
                .status()
                .await
                .unwrap()
                .success()
        );
        assert!(child.wait().await.unwrap().success());
    })
    .await
    .expect("CLI test deadline");
}
