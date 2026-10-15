#![cfg(all(unix, feature = "testbench"))]

#[path = "bench/export_retirement.rs"]
mod export_retirement;
#[path = "bench/fragmented_channel_keyset.rs"]
mod fragmented_channel_keyset;
#[path = "bench/selected_mint_reply.rs"]
mod selected_mint_reply;

use fips_relay::{
    service::{RelayService, ServiceConfig},
    testbench::{BenchConfig, BenchMint, BenchRequest, FaultAction},
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
        fragmented_channel_keyset: false,
    };
    let mut mint = BenchMint::start(mint_config).await.unwrap();
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
    let armed = mint
        .handle(BenchRequest::Fault {
            command: FaultAction::ArmSwapReply { input_hashes: None },
        })
        .await
        .unwrap();
    assert_eq!(armed["phase"], "armed");
    assert!(
        mint.handle(BenchRequest::Fault {
            command: FaultAction::ArmSwapReply { input_hashes: None }
        })
        .await
        .is_err()
    );
    assert!(
        mint.handle(BenchRequest::Collect {
            token: token.clone()
        })
        .await
        .unwrap_err()
        .contains("barrier")
    );
    assert!(
        mint.handle(BenchRequest::Issue {
            id: "blocked".into(),
            amount_sat: 1
        })
        .await
        .unwrap_err()
        .contains("barrier")
    );
    let generation = armed["generation"].as_u64().unwrap();
    assert!(
        mint.handle(BenchRequest::Fault {
            command: FaultAction::Release { generation }
        })
        .await
        .is_err()
    );
    let owner = cfg.clone();
    let incoming = token.clone();
    let import = tokio::spawn(async move {
        offline_wallet(&owner, WalletRequest::Import { token: incoming }).await
    });
    let held = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let state = mint
                .handle(BenchRequest::Fault {
                    command: FaultAction::Status,
                })
                .await
                .unwrap();
            if state["phase"] == "held" {
                break state;
            }
            assert!(!import.is_finished());
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        !import.is_finished(),
        "committed outputs must stay withheld"
    );
    assert_eq!(
        held["swaps"].as_u64().unwrap(),
        armed["swaps"].as_u64().unwrap() + 1
    );
    assert!(
        mint.handle(BenchRequest::Fault {
            command: FaultAction::Release {
                generation: generation + 1
            }
        })
        .await
        .is_err()
    );
    let release = BenchRequest::Fault {
        command: FaultAction::Release { generation },
    };
    assert_eq!(
        mint.handle(release.clone()).await.unwrap()["phase"],
        "released"
    );
    assert_eq!(mint.handle(release).await.unwrap()["phase"], "released");
    let received = import.await.unwrap().unwrap();
    assert_eq!(received["amount_sat"], 256);
    assert!(!received.to_string().contains("cashuB"));
    assert_eq!(
        offline_wallet(&cfg, WalletRequest::Import { token })
            .await
            .unwrap(),
        received
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
    use cashu_service::simulation::{PaymentNetwork, VirtualClock};
    use std::sync::Arc;

    let root = tempfile::tempdir().unwrap().keep();
    eprintln!("test mint startup fixture: {}", root.display());
    for address in [
        "0.0.0.0:30338",
        "8.8.8.8:30338",
        "[::]:30338",
        "224.0.0.1:30338",
    ] {
        let cfg = BenchConfig {
            state_directory: root.join("mint"),
            bind: address.parse().unwrap(),
            max_issued_sat: 10,
            fragmented_channel_keyset: false,
        };
        assert!(BenchMint::start(cfg).await.is_err());
        assert!(!root.join("mint").exists());
    }
    let cfg = BenchConfig {
        state_directory: root.join("mint"),
        bind: "127.0.0.1:0".parse().unwrap(),
        max_issued_sat: 10,
        fragmented_channel_keyset: false,
    };
    let mut mint = BenchMint::start(cfg.clone()).await.unwrap();
    let recovery_path = cfg.state_directory.join("recovery.json");
    let recovery_bytes = std::fs::read(&recovery_path).unwrap();
    let recovery: Value = serde_json::from_slice(&recovery_bytes).unwrap();
    assert_eq!(
        std::fs::metadata(&recovery_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(recovery["test_only"], true);
    assert_eq!(recovery["url"], mint.url());
    assert_eq!(recovery["mint_id"], "hardware-bench");
    assert_eq!(recovery["state_directory"], json!(cfg.state_directory));
    let network = PaymentNetwork::new(
        recovery["seed"].as_u64().unwrap(),
        0,
        Arc::new(VirtualClock::new(0)),
    );
    let stem: String = network.derive_seed("hardware-bench")[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let database = cfg
        .state_directory
        .join("mints")
        .join(format!("{stem}.sqlite"));
    assert!(database.is_file());
    assert_eq!(recovery["database_path"], json!(database));
    let keyset = cashu_service::fetch_spilman_keyset_info_json(mint.url(), "sat", None)
        .await
        .unwrap();
    assert_eq!(
        recovery["keyset"],
        serde_json::from_str::<Value>(&keyset).unwrap()
    );
    let report = mint.handle(BenchRequest::Report).await.unwrap();
    assert_eq!(report["issued_sat"], 0);
    assert_eq!(report["collected_sat"], 0);
    assert_eq!(report["conserved"], true);
    mint.shutdown().await;
    assert!(BenchMint::start(cfg).await.is_err());
    assert!(std::fs::read(recovery_path).unwrap() == recovery_bytes);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acknowledged_exports_preserve_custody_and_costs() {
    export_retirement::check_export_retirement(3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "128 retained real exports, then retirement and continued spending; run explicitly"]
async fn acknowledged_exports_outlive_the_request_limit_without_reusing_spends() {
    export_retirement::check_export_retirement(131).await;
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
            fragmented_channel_keyset: false,
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
        let pending = json!({"type":"export","id":3,"amount_sat":5});
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
                json!({"type":"export","id":1,"amount_sat":5}),
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
        let cached = relay.state_directory.join("exports/3.json");
        let (summary, token) = original.unwrap();
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
        let payment: Value = serde_json::from_slice(&token).unwrap();
        let collected = cli(
            env!("CARGO_BIN_EXE_fips-relay-test-mint"),
            "ctl",
            &path,
            json!({"type":"collect","token":payment["token"]}),
        )
        .await;
        assert!(collected.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&collected.stdout).unwrap()["amount_sat"],
            5
        );
        for _ in 0..2 {
            let acknowledged = cli(
                env!("CARGO_BIN_EXE_fips-relay"),
                "wallet",
                &relay_path,
                json!({"type":"acknowledge_exports","through":2}),
            )
            .await;
            assert!(acknowledged.status.success());
            let history: Value = serde_json::from_slice(&acknowledged.stdout).unwrap();
            assert_eq!(history["through"], 2);
            assert_eq!(history["requests"], 1);
            assert_eq!(history["requested_sat"], 5);
            assert_eq!(history["cost"]["wallet_debit_sat"], 5);
        }
        assert!(!Path::new(summary["path"].as_str().unwrap()).exists());
        assert!(
            std::fs::read(&cached).unwrap() == token,
            "unfinished evidence remains outside the acknowledged prefix"
        );
        for id in [1, 2] {
            assert!(
                !cli(
                    env!("CARGO_BIN_EXE_fips-relay"),
                    "wallet",
                    &relay_path,
                    json!({"type":"export","id":id,"amount_sat":5}),
                )
                .await
                .status
                .success(),
                "retired and skipped numbers cannot create another send"
            );
        }
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
            11
        );
        eprintln!(
            "wallet CLI retired collected exports without resetting costs or allowing replay"
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
