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
    let mut cfg = config(root.path(), mint.url());
    cfg.terms.wallet_capacity_bytes = Some(16 * 1024 * 1024);
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
    let unfunded = WalletRequest::Export {
        id: 1,
        amount_sat: 10,
    };
    assert!(offline_wallet(&cfg, unfunded.clone()).await.is_err());
    let wallet =
        cashu_service::CashuWalletService::open_file_backed(&cfg.state_directory.join("wallet"))
            .await
            .unwrap();
    assert!(
        wallet
            .wallet_send_request("cashu-seq-v1:fips-exports:1")
            .await
            .unwrap()
            .is_some(),
        "the unfunded export retains its original request"
    );
    drop(wallet);
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
        id: 2,
        amount_sat: 10,
    };
    let sent = offline_wallet(&cfg, export.clone()).await.unwrap();
    let exported = Path::new(sent["path"].as_str().unwrap());
    let original = std::fs::read(exported).unwrap();
    for (field, value) in [
        ("operation_id", json!("different-operation")),
        ("token", json!("different-token")),
        ("unit", json!("usd")),
        ("send_fee_sat", json!(1)),
    ] {
        let mut conflicting: Value = serde_json::from_slice(&original).unwrap();
        conflicting[field] = value;
        let conflicting = serde_json::to_vec(&conflicting).unwrap();
        std::fs::write(exported, &conflicting).unwrap();
        assert!(
            offline_wallet(&cfg, export.clone()).await.is_err(),
            "cached export {field} must match the original wallet result"
        );
        assert!(
            std::fs::read(exported).unwrap() == conflicting,
            "conflicting export evidence must remain untouched"
        );
    }
    std::fs::write(exported, &original).unwrap();
    let unfinished = cfg.state_directory.join("exports/1.json");
    std::fs::write(&unfinished, &original).unwrap();
    assert!(offline_wallet(&cfg, unfunded).await.is_err());
    assert!(std::fs::read(&unfinished).unwrap() == original);
    assert_eq!(
        offline_wallet(&cfg, WalletRequest::Balance).await.unwrap()["balance_sat"],
        246,
        "checking a cached export cannot fund an unfinished wallet request"
    );
    let orphan = cfg.state_directory.join("exports/3.json");
    std::fs::write(&orphan, &original).unwrap();
    assert!(
        offline_wallet(
            &cfg,
            WalletRequest::Export {
                id: 3,
                amount_sat: 10,
            },
        )
        .await
        .is_err(),
        "a cached export cannot authorize a new wallet request"
    );
    assert!(std::fs::read(&orphan).unwrap() == original);
    let wallet =
        cashu_service::CashuWalletService::open_file_backed(&cfg.state_directory.join("wallet"))
            .await
            .unwrap();
    assert!(
        wallet
            .wallet_send_request("cashu-seq-v1:fips-exports:3")
            .await
            .unwrap()
            .is_none(),
        "refusing an export must not reserve another send"
    );
    drop(wallet);
    // The wallet completed its send, but the caller lost the published file.
    // Retrying must recover that operation even though enough funds remain to
    // accidentally create another token. Keep the original private for comparison.
    std::fs::rename(exported, root.path().join("retained-export.json")).unwrap();
    assert!(
        offline_wallet(
            &cfg,
            WalletRequest::Export {
                id: 2,
                amount_sat: 11,
            },
        )
        .await
        .is_err(),
        "an unfinished export cannot change its original amount"
    );
    assert_eq!(
        offline_wallet(&cfg, WalletRequest::Balance).await.unwrap()["balance_sat"],
        246
    );
    let recovered = offline_wallet(&cfg, export.clone()).await.unwrap();
    assert_eq!(sent, recovered, "the original operation must be recovered");
    assert!(
        std::fs::read(exported).unwrap() == original,
        "recovery must return the original token without printing bearer funds"
    );
    assert_eq!(sent, offline_wallet(&cfg, export).await.unwrap());
    assert!(!sent.to_string().contains("cashuB"));
    assert!(
        offline_wallet(
            &cfg,
            WalletRequest::Export {
                id: 0,
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
    let remaining = offline_wallet(&cfg, WalletRequest::Balance).await.unwrap()["balance_sat"]
        .as_u64()
        .unwrap();
    assert_eq!(remaining, 246, "recovering the export cannot spend again");
    let remainder = offline_wallet(
        &cfg,
        WalletRequest::Export {
            id: 4,
            amount_sat: remaining,
        },
    )
    .await
    .unwrap();
    let payment: Value =
        serde_json::from_slice(&std::fs::read(remainder["path"].as_str().unwrap()).unwrap())
            .unwrap();
    mint.handle(BenchRequest::Collect {
        token: payment["token"].as_str().unwrap().into(),
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
    std::fs::write(cfg.state_directory.join("exports/5.intent"), b"1").unwrap();
    assert!(
        offline_wallet(
            &cfg,
            WalletRequest::Export {
                id: 5,
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
async fn acknowledged_exports_preserve_custody_and_costs() {
    check_export_retirement(3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "131 real exports beyond the retained-request limit; run explicitly"]
async fn acknowledged_exports_outlive_the_request_limit_without_reusing_spends() {
    check_export_retirement(131).await;
}

async fn check_export_retirement(exports: u64) {
    let root = tempfile::tempdir().unwrap();
    let mut mint = BenchMint::start(BenchConfig {
        state_directory: root.path().join("mint"),
        bind: "127.0.0.1:0".parse().unwrap(),
        max_issued_sat: 256,
    })
    .await
    .unwrap();
    let mut cfg = config(root.path(), mint.url());
    cfg.terms.wallet_capacity_bytes = Some(16 * 1024 * 1024);
    RelayService::initialize(cfg.clone()).await.unwrap();
    let buyer = std::fs::read(cfg.state_directory.join("buyer/buyer.json")).unwrap();
    let export = WalletRequest::Export {
        id: 1,
        amount_sat: 1,
    };
    let ack = WalletRequest::AcknowledgeExports { through: 1 };
    assert!(offline_wallet(&cfg, export.clone()).await.is_err());
    assert!(
        offline_wallet(&cfg, ack.clone())
            .await
            .unwrap_err()
            .contains("unfinished wallet request"),
        "unfinished sends cannot be retired"
    );
    let grant = mint
        .handle(BenchRequest::Issue {
            id: "retirement".into(),
            amount_sat: 256,
        })
        .await
        .unwrap();
    let payment: Value =
        serde_json::from_slice(&std::fs::read(grant["path"].as_str().unwrap()).unwrap()).unwrap();
    offline_wallet(
        &cfg,
        WalletRequest::Import {
            token: payment["token"].as_str().unwrap().into(),
        },
    )
    .await
    .unwrap();
    let directory = cfg.state_directory.join("exports");
    // Unknown evidence consumes capacity and is never silently deleted.
    for n in 0..128 {
        std::fs::write(directory.join(format!("retained-{n}")), b"retained").unwrap();
    }
    let full = offline_wallet(
        &cfg,
        WalletRequest::Export {
            id: 2,
            amount_sat: 1,
        },
    )
    .await
    .unwrap_err();
    assert!(full.contains("export file limit"));
    let wallet =
        cashu_service::CashuWalletService::open_file_backed(&cfg.state_directory.join("wallet"))
            .await
            .unwrap();
    assert!(
        wallet
            .wallet_send_request("cashu-seq-v1:fips-exports:2")
            .await
            .unwrap()
            .is_none()
    );
    drop(wallet);
    assert_eq!(
        offline_wallet(&cfg, WalletRequest::Balance).await.unwrap()["balance_sat"],
        256
    );
    for n in 1..128 {
        std::fs::remove_file(directory.join(format!("retained-{n}"))).unwrap();
    }
    let mut last_history = Value::Null;
    for id in 1..=exports {
        let amount_sat = if id == exports { 257 - exports } else { 1 };
        let summary = offline_wallet(&cfg, WalletRequest::Export { id, amount_sat })
            .await
            .unwrap();
        if id == 3 {
            assert!(
                !directory.join("2.json").exists(),
                "new exports finish previously acknowledged cleanup"
            );
        }
        let path = Path::new(summary["path"].as_str().unwrap());
        let original = std::fs::read(path).unwrap();
        if id == 1 {
            let mut changed: Value = serde_json::from_slice(&original).unwrap();
            changed["operation_id"] = json!("conflicting");
            let bytes = serde_json::to_vec(&changed).unwrap();
            std::fs::write(path, &bytes).unwrap();
            assert!(offline_wallet(&cfg, ack.clone()).await.is_err());
            assert!(
                std::fs::read(path).unwrap() == bytes,
                "retain refused evidence"
            );
            let wallet = cashu_service::CashuWalletService::open_file_backed(
                &cfg.state_directory.join("wallet"),
            )
            .await
            .unwrap();
            assert_eq!(
                wallet.wallet_send_history().await.unwrap().sequences["fips-exports"].through,
                0
            );
            drop(wallet);
            std::fs::write(path, &original).unwrap();
        }
        let payment: Value = serde_json::from_slice(&original).unwrap();
        mint.handle(BenchRequest::Collect {
            token: payment["token"].as_str().unwrap().into(),
        })
        .await
        .unwrap();
        if id == 1 {
            // Fail cache deletion after the SDK has durably retired the request.
            let permissions = std::fs::metadata(&directory).unwrap().permissions();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500)).unwrap();
            let interrupted = offline_wallet(&cfg, ack.clone()).await;
            std::fs::set_permissions(&directory, permissions).unwrap();
            assert!(interrupted.is_err());
            assert!(std::fs::read(path).unwrap() == original);
            let wallet = cashu_service::CashuWalletService::open_file_backed(
                &cfg.state_directory.join("wallet"),
            )
            .await
            .unwrap();
            let retired = wallet.wallet_send_history().await.unwrap();
            assert_eq!(retired.sequences["fips-exports"].through, 1);
            assert_eq!(retired.sequences["fips-exports"].cost.wallet_debit_sat, 1);
            drop(wallet);
            assert!(offline_wallet(&cfg, export.clone()).await.is_err());
        }
        let command = WalletRequest::AcknowledgeExports { through: id };
        last_history = offline_wallet(&cfg, command.clone()).await.unwrap();
        assert_eq!(last_history["through"], id);
        assert_eq!(last_history["requests"], id);
        assert_eq!(
            last_history["requested_sat"],
            if id == exports { 256 } else { id }
        );
        assert_eq!(
            last_history["cost"]["wallet_debit_sat"],
            last_history["requested_sat"]
        );
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        assert_eq!(
            std::fs::read(directory.join("retained-0")).unwrap(),
            b"retained"
        );
        if id == 2 {
            // Model an acknowledged cache file still present after interruption.
            std::fs::write(path, &original).unwrap();
        }
        if id == 1 {
            assert_eq!(
                last_history,
                offline_wallet(&cfg, command).await.unwrap(),
                "acknowledgement retries do not reset or add costs"
            );
        }
    }
    let wallet =
        cashu_service::CashuWalletService::open_file_backed(&cfg.state_directory.join("wallet"))
            .await
            .unwrap();
    assert_eq!(
        wallet
            .wallet_send_history()
            .await
            .unwrap()
            .retained_requests,
        0
    );
    drop(wallet);
    // Close an absent number too: it must never become fresh spending authority.
    let closed = offline_wallet(
        &cfg,
        WalletRequest::AcknowledgeExports {
            through: exports + 1,
        },
    )
    .await
    .unwrap();
    assert_eq!(closed["requests"], last_history["requests"]);
    for id in [1, exports, exports + 1] {
        assert!(
            offline_wallet(&cfg, WalletRequest::Export { id, amount_sat: 2 })
                .await
                .is_err()
        );
    }
    assert_eq!(
        offline_wallet(&cfg, WalletRequest::Balance).await.unwrap()["balance_sat"],
        0
    );
    assert_eq!(
        buyer,
        std::fs::read(cfg.state_directory.join("buyer/buyer.json")).unwrap()
    );
    let report = mint.handle(BenchRequest::Report).await.unwrap();
    assert_eq!(report["collected_sat"], 256);
    assert_eq!(report["conserved"], true);
    mint.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn command_line_tools_fund_and_recover_export_over_the_private_control_socket() {
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
        let pending = json!({"type":"export","id":1,"amount_sat":5});
        assert!(
            !cli(
                env!("CARGO_BIN_EXE_fips-relay"),
                "wallet",
                &relay_path,
                pending.clone(),
            )
            .await
            .status
            .success()
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
        let mut original: Option<(Value, Vec<u8>)> = None;
        for _ in 0..2 {
            let output = cli(
                env!("CARGO_BIN_EXE_fips-relay"),
                "wallet",
                &relay_path,
                json!({"type":"export","id":2,"amount_sat":5}),
            )
            .await;
            assert!(
                output.status.success(),
                "wallet export process must succeed"
            );
            let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert!(summary.get("token").is_none());
            let exported = Path::new(summary["path"].as_str().unwrap());
            let bytes = std::fs::read(exported).unwrap();
            if let Some((prior, token)) = &original {
                assert_eq!(&summary, prior);
                assert!(
                    bytes == *token,
                    "retry must recover the original bearer token"
                );
            } else {
                // The next invocation is a separate process with no published token.
                std::fs::rename(exported, root.path().join("retained-export.json")).unwrap();
                original = Some((summary, bytes));
            }
        }
        let cached = relay.state_directory.join("exports/1.json");
        let (_, token) = original.unwrap();
        std::fs::write(&cached, &token).unwrap();
        assert!(
            !cli(
                env!("CARGO_BIN_EXE_fips-relay"),
                "wallet",
                &relay_path,
                pending,
            )
            .await
            .status
            .success()
        );
        assert!(std::fs::read(&cached).unwrap() == token);
        let balance = cli(
            env!("CARGO_BIN_EXE_fips-relay"),
            "wallet",
            &relay_path,
            json!({"type":"balance"}),
        )
        .await;
        assert!(balance.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&balance.stdout).unwrap()["balance_sat"],
            11,
            "separate export processes must not debit the wallet twice"
        );
        eprintln!("wallet CLI recovered the original export without another debit");
        eprintln!("wallet CLI rejected an unfinished cached export without spending");
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
