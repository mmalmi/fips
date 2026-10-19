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
    if originals.is_empty() {
        return BTreeMap::new();
    }
    // Do not scan thousands of unrelated retained-history proofs on every
    // progress sample. The exact payout identities define this observation.
    db.get_proofs_by_ys(originals.values().map(|proof| proof.y).collect())
        .await
        .unwrap()
        .into_iter()
        .map(|proof| (proof.y.to_string(), proof))
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
    // A held-writer observation needs only this payout. Scanning unrelated
    // receipt history here can consume the outgoing channel's remaining life.
    let rows: Coins = db
        .get_proofs_by_ys(proofs.iter().map(|proof| proof.y().unwrap()).collect())
        .await
        .unwrap()
        .into_iter()
        .map(|proof| (proof.y.to_string(), proof))
        .collect();
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

pub(super) async fn transit_slots(db: &cdk_sqlite::WalletSqliteDatabase) -> Value {
    let bytes = db
        .kv_read("cashu_service", "proof_history", "journal")
        .await
        .unwrap()
        .expect("original incoming payout reserved proof history");
    let history: Value = serde_json::from_slice(&bytes).unwrap();
    let queued = history["candidates"].as_object().unwrap().len() as u64;
    let reserved: u64 = history["reservations"]
        .as_object()
        .unwrap()
        .values()
        .map(|r| r["remaining"].as_u64().unwrap())
        .sum();
    assert_eq!(reserved, 960, "retain the original receiver reservation");
    assert!(
        queued + reserved + TRANSIT_CAPACITY <= 1024,
        "new transit funding must fit the existing proof-history limit"
    );
    json!({"queued":queued,"reserved":reserved,"planned":TRANSIT_CAPACITY,"limit":1024})
}

pub(super) fn transit_opening(bench: &setup::Bench, channel: &str) -> usize {
    let (_, funded) = funding(bench, SOURCE, channel);
    assert_eq!(funded["capacity_sat"], TRANSIT_CAPACITY);
    let saved = journal(&bench.configs[SOURCE]);
    let route = saved["outgoing"]
        .as_object()
        .unwrap()
        .values()
        .find(|r| r["purchase"]["channel"]["id"] == channel)
        .unwrap();
    let payment: cashu_service::CashuSpilmanPayment =
        serde_json::from_value(funded["funded"]["opening"].clone()).unwrap();
    let proofs: Vec<Proof> =
        serde_json::from_value(payment.funding_proofs.clone().unwrap()).unwrap();
    assert_eq!(proofs.len(), TRANSIT_CAPACITY as usize);
    assert!(proofs.iter().all(|p| p.amount.to_u64() == 1));
    let request = fips_relay::controller::ControllerRequest::Accept {
        offer_id: route["offer"]["id"].as_str().unwrap().to_owned(),
        channel: serde_json::from_value(funded["funded"]["terms"].clone()).unwrap(),
        payment: Box::new(payment),
        replaces: None,
    };
    let bytes = serde_json::to_vec(&request).unwrap().len();
    assert!(bytes <= fips_relay::control_transport::MAX_RECORD_BYTES);
    bytes
}

pub(super) fn transit_exposure(
    before: &[Value; 2],
    warm: [&Value; 2],
    current: [&Value; 2],
    channels: [&str; 2],
    profile: Traffic,
    packets: u32,
) -> Value {
    let mut hops = Vec::new();
    for (index, channel) in channels.into_iter().enumerate() {
        let evidence = |state: &Value| {
            state["payment_progress"][channel]["evidence_msat"]
                .as_u64()
                .unwrap()
        };
        let delta = evidence(warm[index])
            .checked_sub(evidence(&before[index]))
            .unwrap();
        // The first probe can include additional priced traffic. Keep that
        // conservative exposure estimate, with one msat for cumulative rounding,
        // but bound steady cadence using only payload bytes at the accepted price.
        let upper = delta + 1;
        let purchase = current[index]["purchases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["channel"]["id"] == channel)
            .expect("the original channel must still have an accepted purchase");
        let price: fips_relay::ledger::BytePrice =
            serde_json::from_value(purchase["contract"]["price"].clone()).unwrap();
        let lower = u64::try_from(
            (profile.payload_bytes as u128 * u128::from(price.msat)) / u128::from(price.per_bytes),
        )
        .unwrap();
        assert!(
            lower > 0,
            "payload must accrue at least one msat per packet"
        );
        let current_msat = evidence(current[index]);
        let needed_msat = current_msat + upper * u64::from(packets);
        let needed_sat = needed_msat.div_ceil(1000);
        let capacity = purchase["channel"]["capacity_sat"].as_u64().unwrap();
        assert!(
            needed_sat < capacity,
            "hop {index}: warmup={delta} msat, current={current_msat} msat, \
             bound={upper} msat for {packets} remaining packets needs \
             {needed_msat} msat ({needed_sat} sat), capacity={capacity} sat"
        );
        let rate = profile.packets_per_second;
        let quantization_us = 1_000_000_000u64.div_ceil(lower * u64::from(rate));
        assert!(
            quantization_us + 500_000 < 2_000_000,
            "hop {index}: payload floor={lower} msat at {rate} packets/s needs \
             {quantization_us} us plus 500000 us cadence; limit=2000000 us"
        );
        hops.push(
            json!({"capacity_sat":capacity,"maximum_evidence_msat":needed_msat,
            "calibrated_warmup_msat":delta,"price":price,"minimum_payload_msat":lower,
            "maximum_quantization_us":quantization_us}),
        );
    }
    json!({"remaining_packets":packets,"hops":hops})
}
