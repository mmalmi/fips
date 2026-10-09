//! Select one real mint swap without blocking unrelated wallet operations.
use super::*;
use sha2::{Digest, Sha256};
use std::{str::FromStr, time::Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn selected_inputs_hold_only_the_matching_committed_reply() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let root = tempfile::tempdir().unwrap();
        let mut mint = BenchMint::start(BenchConfig {
            state_directory: root.path().join("mint"),
            bind: "127.0.0.1:0".parse().unwrap(),
            max_issued_sat: 32,
        })
        .await
        .unwrap();
        let cfg = config(root.path(), mint.url());
        RelayService::initialize(cfg.clone()).await.unwrap();
        let mut tokens = Vec::new();
        for id in ["selected", "unrelated"] {
            let grant = mint
                .handle(BenchRequest::Issue {
                    id: id.into(),
                    amount_sat: 16,
                })
                .await
                .unwrap();
            let payment: Value =
                serde_json::from_slice(&std::fs::read(grant["path"].as_str().unwrap()).unwrap())
                    .unwrap();
            tokens.push(payment["token"].as_str().unwrap().to_owned());
        }
        let input_hashes: Vec<_> = cashu::nuts::Token::from_str(&tokens[0])
            .unwrap()
            .token_secrets()
            .iter()
            .map(|secret| format!("{:x}", Sha256::digest(secret.as_bytes())))
            .collect();
        for invalid in [
            vec![],
            vec!["invalid".into()],
            vec![input_hashes[0].clone(); 2],
            vec![input_hashes[0].clone(); 129],
        ] {
            assert!(
                mint.handle(BenchRequest::Fault {
                    command: FaultAction::ArmSwapReply {
                        input_hashes: Some(invalid)
                    },
                })
                .await
                .is_err()
            );
        }
        let armed = mint
            .handle(BenchRequest::Fault {
                command: FaultAction::ArmSwapReply {
                    input_hashes: Some(input_hashes),
                },
            })
            .await
            .unwrap();
        assert_eq!(armed["generation"], 1);
        let generation = armed["generation"].as_u64().unwrap();
        let unrelated = tokio::time::timeout(
            Duration::from_secs(10),
            offline_wallet(
                &cfg,
                WalletRequest::Import {
                    token: tokens.pop().unwrap(),
                },
            ),
        )
        .await
        .expect("unrelated swap must not wait for the selected barrier")
        .unwrap();
        assert_eq!(unrelated["amount_sat"], 16);
        assert_eq!(
            mint.handle(BenchRequest::Fault {
                command: FaultAction::Status,
            })
            .await
            .unwrap()["phase"],
            "armed"
        );
        let owner = cfg.clone();
        let importing = tokio::spawn(async move {
            offline_wallet(
                &owner,
                WalletRequest::Import {
                    token: tokens.pop().unwrap(),
                },
            )
            .await
        });
        let held = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let status = mint
                    .handle(BenchRequest::Fault {
                        command: FaultAction::Status,
                    })
                    .await
                    .unwrap();
                if status["phase"] == "held" {
                    break status;
                }
                assert!(!importing.is_finished());
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert!(!importing.is_finished());
        assert_eq!(
            held["swaps"].as_u64().unwrap(),
            armed["swaps"].as_u64().unwrap() + 2
        );
        assert_eq!(
            mint.handle(BenchRequest::Fault {
                command: FaultAction::Release { generation },
            })
            .await
            .unwrap()["phase"],
            "released"
        );
        assert_eq!(importing.await.unwrap().unwrap()["amount_sat"], 16);
        let exported = offline_wallet(
            &cfg,
            WalletRequest::Export {
                id: 1,
                amount_sat: 32,
            },
        )
        .await
        .unwrap();
        let payment: Value =
            serde_json::from_slice(&std::fs::read(exported["path"].as_str().unwrap()).unwrap())
                .unwrap();
        mint.handle(BenchRequest::Collect {
            token: payment["token"].as_str().unwrap().into(),
        })
        .await
        .unwrap();
        let report = mint.handle(BenchRequest::Report).await.unwrap();
        assert_eq!(report["collected_sat"], 32);
        assert_eq!(report["conserved"], true);
        mint.shutdown().await;
    })
    .await
    .expect("bounded selected mint reply test");
}
