//! Exact retained custody around the shared ordinary-command history setup.
use super::*;
use cdk_common::wallet::Transaction;

pub(super) const WALLET_BYTES: u64 = 20 * 1024 * 1024;

pub(super) fn requested() -> u64 {
    match std::env::var("FIPS_RELAY_RECEIVER_HISTORY_ROWS") {
        Err(std::env::VarError::NotPresent) => 0,
        value => {
            let rows = value.unwrap().parse().expect("integer receipt count");
            assert!((1..=5480).contains(&rows), "receipt count must be 1..=5480");
            rows
        }
    }
}

#[derive(Default)]
pub(super) struct Retained {
    pub coins: Coins,
    receipts: BTreeMap<String, Transaction>,
    pub observation: Value,
}

impl Retained {
    pub async fn unchanged(&self, db: &cdk_sqlite::WalletSqliteDatabase) {
        assert!(
            original_subset(db, &self.coins).await == self.coins,
            "cleanup changed the genuine retained-history coins"
        );
        for receipt in self.receipts.values() {
            assert_eq!(
                db.get_transaction(receipt.id()).await.unwrap().as_ref(),
                Some(receipt),
                "cleanup changed a genuine retained incoming receipt"
            );
        }
    }
}

pub(super) async fn prepare(bench: &mut setup::Bench, rows: u64) -> Retained {
    if rows == 0 {
        return Retained::default();
    }
    for child in &mut bench.children {
        stop(child).await;
    }
    let root = bench.paths[0].parent().unwrap().parent().unwrap();
    let wallet = bench.configs[1].state_directory.join("wallet");
    let db = cdk_sqlite::WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(&wallet))
        .await
        .unwrap();
    assert!(records(&db).await.is_empty());
    let result = Command::new("python3")
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../testing/chaos/sim/receiver_history.py"),
        )
        .arg("--binary")
        .arg(relay_program())
        .arg("--donor")
        .arg(&bench.paths[0])
        .arg("--receiver")
        .arg(&bench.paths[1])
        .arg("--rows")
        .arg(rows.to_string())
        .arg("--output")
        .arg(root.join("receiver-history-setup.json"))
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(root.join("receiver-history-setup.log")).unwrap())
        .status()
        .await
        .unwrap();
    // The shared command sequence returns its borrowed value even on a setup
    // refusal. Validate every mint proof and all original funds before asserting
    // setup success. Unrecoverable originals retain their private evidence.
    setup::verify_settled_wallets(bench, &bench.configs[0].terms.controller.mint_url, INITIAL)
        .await;
    std::fs::write(
        root.join("receiver-history-mint-audit.json"),
        serde_json::to_vec(&json!({"conserved_sat":INITIAL,
            "all_original_proof_states_checked":true,"incomplete_operations":0,
            "setup_exit_code":result.code()}))
        .unwrap(),
    )
    .unwrap();
    assert!(
        result.success(),
        "history setup failed; inspect original private setup evidence"
    );
    let observation = restore::read(&root.join("receiver-history-setup.json"));
    assert_eq!(observation["completed_receives"], rows);
    assert_eq!(observation["returned_original_value"], true);
    let coins = records(&db).await;
    // The audit above checked every one of these originals as mint-Spent.
    // CDK may retain PendingSpent on terminal sent-token rows after their saga
    // is deleted. It is not spendable value or an unfinished monetary owner.
    assert!(
        coins
            .values()
            .all(|p| matches!(p.state, State::Spent | State::PendingSpent))
    );
    let transactions = db.list_transactions(None, None, None).await.unwrap();
    assert_eq!(transactions.len() as u64, rows);
    assert!(transactions.iter().all(|t| t.direction
        == cdk_common::wallet::TransactionDirection::Incoming
        && t.status == cdk_common::wallet::TransactionStatus::Completed
        && t.amount.to_u64() == 1
        && t.fee.to_u64() == 0));
    let owned: BTreeSet<_> = transactions
        .iter()
        .flat_map(|t| t.ys.iter().copied())
        .collect();
    assert!(
        coins.values().all(|p| owned.contains(&p.y)),
        "finish ordinary eligible collection before freezing receipt-owned history"
    );
    let receipts: BTreeMap<_, _> = transactions
        .into_iter()
        .map(|t| (t.id().to_string(), t))
        .collect();
    assert_eq!(
        receipts.len() as u64,
        rows,
        "each self-receive adds a distinct genuine receipt"
    );
    assert!(db.get_incomplete_sagas().await.unwrap().is_empty());
    let sends = preopening_support::send_journal(&wallet).await;
    assert!(sends["entries"].as_object().unwrap().is_empty());
    assert!(sends["retirement"].is_null());
    assert_eq!(observation["final"]["incomplete_operations"], 0);
    let retained = Retained {
        coins,
        receipts,
        observation,
    };
    for (child, path) in bench.children.iter_mut().zip(&bench.paths) {
        *child = start(path).await;
    }
    ready_configured(&bench.configs, &bench.paths, &mut bench.children).await;
    retained.unchanged(&db).await;
    retained
}
