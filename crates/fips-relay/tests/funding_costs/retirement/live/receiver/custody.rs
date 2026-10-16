//! Read original daemon custody without acquiring a wallet service or recovering it.
use super::*;
use cashu::nuts::{CheckStateRequest, Proof};
use cdk_common::wallet::ProofInfo;

pub(super) type Coins = BTreeMap<String, ProofInfo>;

pub(super) async fn records(db: &cdk_sqlite::WalletSqliteDatabase) -> Coins {
    db.get_proofs(None, None, None, None)
        .await
        .unwrap()
        .into_iter()
        .map(|proof| (proof.y.to_string(), proof))
        .collect()
}

pub(super) async fn original_subset(
    db: &cdk_sqlite::WalletSqliteDatabase,
    originals: &Coins,
) -> Coins {
    records(db)
        .await
        .into_iter()
        .filter(|(y, _)| originals.contains_key(y))
        .collect()
}

pub(super) async fn retained_originals(
    db: &cdk_sqlite::WalletSqliteDatabase,
    originals: &Coins,
) -> Coins {
    let current = original_subset(db, originals).await;
    assert_eq!(
        current.len(),
        originals.len(),
        "receiver still owns every imported original"
    );
    for (key, saved) in originals {
        let coin = &current[key];
        assert!(
            coin.mint_url == saved.mint_url
                && coin.unit == saved.unit
                && coin.proof.keyset_id == saved.proof.keyset_id
                && coin.proof.secret == saved.proof.secret
                && coin.proof.c == saved.proof.c
                && coin.proof.amount == saved.proof.amount
                && coin.proof.p2pk_e == saved.proof.p2pk_e,
            "spending and outgoing retirement must preserve the receiver's original coin identity"
        );
        assert!(coin.created_by_operation.is_none() && coin.derivation_index.is_none());
    }
    current
}

pub(super) async fn payout(
    config: &ServiceConfig,
    channel: &str,
    db: &cdk_sqlite::WalletSqliteDatabase,
) -> Coins {
    let output = Command::new("python3").args(["-c",
        "import json,sqlite3,sys\nc=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True)\nr=c.execute('SELECT state,closed_json FROM spilman_channels WHERE channel_id=?',(sys.argv[2],)).fetchone()\nassert r and r[0]=='Closed'\nprint(r[1])"])
        .arg(cashu_service::spilman_receiver_store_path(&config.state_directory.join("receiver")))
        .arg(channel).output().await.unwrap();
    assert!(
        output.status.success(),
        "read the original receiver's committed payout"
    );
    let closed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(closed["receiver_sum"], PAYOUT);
    assert_eq!(closed["sender_sum"], 1);
    let proofs: Vec<Proof> =
        serde_json::from_str(closed["receiver_proofs_json"].as_str().unwrap()).unwrap();
    let rows = records(db).await;
    let mut originals = BTreeMap::new();
    for proof in proofs {
        let key = proof.y().unwrap().to_string();
        assert!(
            rows[&key].proof == proof,
            "wallet payout differs from original closed receiver"
        );
        assert!(originals.insert(key.clone(), rows[&key].clone()).is_none());
    }
    originals
}

pub(super) async fn original_inputs(wallet: &Path, funding: &Value) -> (BTreeSet<String>, String) {
    let journal = preopening_support::send_journal(wallet).await;
    let operation = funding["funded"]["wallet_operation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let entries: Vec<_> = journal["entries"]
        .as_object()
        .unwrap()
        .values()
        .filter(|entry| entry["preparation"]["planned"]["operation_id"] == operation)
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "one original wallet request must own this funding"
    );
    let plan = &entries[0]["preparation"]["planned"];
    let mut inputs = BTreeSet::new();
    for field in ["proofs_to_swap", "proofs_to_send"] {
        let proofs: Vec<Proof> = serde_json::from_value(plan[field].clone()).unwrap();
        for proof in proofs {
            assert_eq!(proof.amount.to_u64(), 1);
            assert!(inputs.insert(proof.y().unwrap().to_string()));
        }
    }
    (inputs, operation)
}

pub(super) async fn released_sends(
    db: &cdk_sqlite::WalletSqliteDatabase,
    wallet: &Path,
    operations: &BTreeSet<String>,
) {
    let journal = preopening_support::send_journal(wallet).await;
    assert!(
        journal["entries"]
            .as_object()
            .unwrap()
            .values()
            .all(|entry| {
                !operations.contains(
                    entry["preparation"]["planned"]["operation_id"]
                        .as_str()
                        .unwrap(),
                )
            }),
        "ordinary retirement must remove its original SDK send owner"
    );
    assert!(
        db.get_incomplete_sagas()
            .await
            .unwrap()
            .iter()
            .all(|s| !operations.contains(&s.id.to_string())),
        "original native claim is still nonterminal"
    );
    assert!(
        db.list_transactions(None, None, None)
            .await
            .unwrap()
            .iter()
            .all(|tx| tx
                .saga_id
                .is_none_or(|id| !operations.contains(&id.to_string()))),
        "original outgoing receipt is still an owner"
    );
}

pub(super) async fn verify_mint(bench: &setup::Bench, current: &Coins) {
    let state = bench
        .mint
        .mint()
        .check_state(&CheckStateRequest {
            ys: current.values().map(|p| p.y).collect(),
        })
        .await
        .unwrap();
    assert_eq!(state.states.len(), current.len());
    let mut seen = BTreeSet::new();
    for proof in state.states {
        let key = proof.y.to_string();
        assert!(seen.insert(key.clone()));
        assert_eq!(proof.state, current[&key].state);
    }
}

pub(super) async fn history_size(db: &cdk_sqlite::WalletSqliteDatabase, wallet: &Path) -> Value {
    let transactions = db.list_transactions(None, None, None).await.unwrap();
    let sagas = db.get_incomplete_sagas().await.unwrap();
    let coins = records(db).await;
    let sends = preopening_support::send_journal(wallet).await;
    let capacity = db.storage_capacity().await.unwrap().unwrap();
    json!({"native_receipts":transactions.len(),"native_operations":sagas.len(),
        "proof_rows":coins.len(),"send_requests":sends["entries"].as_object().unwrap().len(),
        "receipt_json_bytes":serde_json::to_vec(&transactions).unwrap().len(),
        "operation_json_bytes":serde_json::to_vec(&sagas).unwrap().len(),
        "send_journal_json_bytes":serde_json::to_vec(&sends).unwrap().len(),
        "charged_bytes":capacity.charged_bytes,"capacity_bytes":capacity.maximum_bytes,
        "wallet_db_bytes":std::fs::metadata(cashu_service::cashu_wallet_db_path(wallet)).unwrap().len(),
        "client_json_bytes":std::fs::metadata(cashu_service::spilman_client_store_path(wallet)).unwrap().len()})
}
