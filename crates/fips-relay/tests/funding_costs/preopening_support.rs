//! Shared exact wallet-preparation boundary; no controller-state repair.
use super::{restore::*, *};
use cashu::nuts::ProofsMethods;
use cashu_service::{
    StreamingRouteOpenCashuSpilmanChannelFromWalletRequest as WalletRequest, cashu_wallet_db_path,
    revoke_pending_payment, simulation::MintProxy, spilman_client_store_path,
};
use cdk_common::database::WalletDatabase;
use serde_json::Value;
use std::{
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

pub(super) async fn send_journal(wallet: &Path) -> Value {
    // Reuse the SDK admission fixture's read-only durable-operation inspection;
    // opening another wallet service would acquire its cross-process money lock.
    let db = cdk_sqlite::WalletSqliteDatabase::new(cashu_wallet_db_path(wallet))
        .await
        .unwrap();
    db.kv_read("cashu_service", "send_requests", "journal")
        .await
        .unwrap()
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
        .unwrap_or_else(|| serde_json::json!({"entries": {}, "sequences": {}}))
}

pub(super) fn original_send(journal: &Value, request: &WalletRequest) -> (String, Value) {
    let matches: Vec<_> = journal["entries"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, entry)| {
            entry["request"]["metadata"]["spilman_request"]
                .as_str()
                .is_some_and(|json| {
                    serde_json::from_str::<WalletRequest>(json).is_ok_and(|saved| saved == *request)
                })
        })
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "exact admitted wallet request must be unique"
    );
    (matches[0].0.clone(), matches[0].1.clone())
}

pub(super) fn entries(state: &Value, field: &str) -> usize {
    // SDK maps may be omitted when empty, unlike the controller journal maps.
    state
        .get(field)
        .map_or(0, |value| value.as_object().unwrap().len())
}

pub(super) fn request_count(journal: &Value) -> u64 {
    journal["entries"].as_object().unwrap().len() as u64
        + journal["sequences"]
            .as_object()
            .unwrap()
            .values()
            .map(|history| history["requests"].as_u64().unwrap())
            .sum::<u64>()
}

pub(super) fn check(errors: &mut Vec<&'static str>, condition: bool, message: &'static str) {
    if !condition && !errors.contains(&message) {
        errors.push(message);
    }
}

pub(super) fn terminal_refund(
    journal: &Value,
    status: &Value,
    id: &str,
    operation: &str,
    allowance: &std::ops::RangeInclusive<u64>,
) -> bool {
    let budget = &status["funding_budget"];
    let Some(debit) = budget["wallet_debited_sat"].as_u64() else {
        return false;
    };
    let Some(refund) = budget["wallet_refunded_sat"].as_u64() else {
        return false;
    };
    if !allowance.contains(&debit)
        || refund == 0
        || refund > debit
        || budget["pending_reserved_sat"] != 0
        || budget["locked_sat"] != 0
        || budget["exposure_sat"] != debit - refund
    {
        return false;
    }
    if let Some(intent) = journal["funding"].get(id) {
        if intent["reclaim"]["state"] == "complete" {
            let result = &intent["reclaim"]["result"];
            return intent["funded"].is_null()
                && result["wallet_operation_id"] == operation
                && result["wallet_cost"]["wallet_debit_sat"] == debit
                && result["recovered_amount_sat"] == refund;
        }
        let funded = &intent["funded"];
        let Some(channel) = funded["terms"]["id"].as_str() else {
            return false;
        };
        let settlement = &journal["buyer_settlements"][channel];
        // Match BuyerSettlement::terminal: an expiry refund is terminal before
        // channel retirement removes the retained financial evidence.
        funded["wallet_operation_id"] == operation
            && funded["wallet_cost"]["wallet_debit_sat"] == debit
            && funded["opening"]["balance"] == 0
            && settlement["refunded"] == true
            && (settlement["kind"] == "expiry" || settlement["released"] == true)
            && settlement["channel"] == funded["terms"]
            && settlement["wallet_refund_sat"] == refund
    } else {
        let history = &journal["history"]["channels"]["totals"];
        journal["funding"].as_object().unwrap().is_empty()
            && ((history["channels"] == 1
                && history["abandoned_requests"].as_u64().unwrap_or(0) == 0)
                || (history["channels"] == 0 && history["abandoned_requests"] == 1))
            && history["cost"]["wallet_debit_sat"] == debit
            && history["refund_sat"] == refund
            && history["signed_sat"] == 0
    }
}

pub(super) fn funding_authority(intent: &Value) -> Value {
    let mut authority = intent.clone();
    authority["funded"] = Value::Null;
    authority.as_object_mut().unwrap().remove("reclaim");
    authority
}

/// Match only a wallet preparation response before any channel opening exists.
pub(super) fn preparation_match(
    store: &Path,
    matched: &Mutex<Option<cashu::nuts::SwapRequest>>,
    seen: &AtomicUsize,
    request: &cashu::nuts::SwapRequest,
) -> bool {
    seen.fetch_add(1, Ordering::SeqCst);
    let Ok(bytes) = std::fs::read(store) else {
        return false;
    };
    let state: Value = serde_json::from_slice(&bytes).unwrap();
    if !state["admissions"].as_object().is_some_and(|admitted| {
        admitted.len() == 1
            && admitted
                .values()
                .all(|entry| entry["funding_started"] == true)
    }) || entries(&state, "openings") != 0
    {
        return false;
    }
    *matched.lock().unwrap() = Some(request.clone());
    true
}

pub(super) struct OriginalSend {
    pub controller: Value,
    pub sdk: Value,
    pub intent_id: String,
    pub intent: Value,
    pub request: WalletRequest,
    pub send_id: String,
    pub entry: Value,
    pub operation: String,
}

/// Compare the committed wire inputs to the one exact persisted send plan.
pub(super) async fn inspect_original(
    cfg: &fips_relay::service::ServiceConfig,
    funding_keyset: &str,
    matched: &Mutex<Option<cashu::nuts::SwapRequest>>,
) -> Result<OriginalSend, &'static str> {
    let wallet = cfg.state_directory.join("wallet");
    let controller = read(&cfg.state_directory.join("controller/controller.json"));
    let intents = controller["funding"].as_object().unwrap();
    if intents.len() != 1 {
        return Err("expected one original funding intent");
    }
    let (id, intent) = intents.iter().next().unwrap();
    let sdk = read(&spilman_client_store_path(&wallet));
    if !intent["funded"].is_null()
        || entries(&sdk, "admissions") != 1
        || sdk["admissions"][id]["funding_started"] != true
        || entries(&sdk, "openings") != 0
        || entries(&sdk, "funding") != 0
    {
        return Err("capture was not an admitted send before channel opening");
    }
    let request: WalletRequest =
        serde_json::from_value(sdk["admissions"][id]["request"].clone()).unwrap();
    if request.client_request_id.as_ref() != Some(id)
        || request.route_created_at_unix != intent["created_unix"].as_u64()
        || request.max_total_amount_sat != intent["max_wallet_debit_sat"].as_u64()
        || request.expiry_unix != intent["expires_unix"].as_u64().unwrap() + 60
        || request.capacity_sat != intent["capacity_sat"].as_u64().unwrap()
        || Some(request.receiver_pubkey_hex.as_str()) != intent["receiver_pubkey_hex"].as_str()
    {
        return Err("admitted request differs from original funding authority");
    }
    let journal = send_journal(&wallet).await;
    if request_count(&journal) != 1 {
        return Err("expected one original wallet send");
    }
    let (send_id, entry) = original_send(&journal, &request);
    let operation = entry["plan"]["operation_id"].as_str().unwrap().to_owned();
    let proofs: cashu::nuts::Proofs =
        serde_json::from_value(entry["plan"]["proofs_to_swap"].clone()).unwrap();
    let matched = matched.lock().unwrap();
    if entry["request"]["request_id"] != send_id
        || !entry["result"].is_null()
        || proofs.is_empty()
        || proofs
            .iter()
            .any(|p| p.keyset_id.to_string() == funding_keyset)
        || entry["request"]["required_keyset_id"] != funding_keyset
        || matched
            .as_ref()
            .is_none_or(|wire| proofs.without_dleqs() != *wire.inputs())
    {
        return Err("committed reply differs from the exact persisted preparation swap");
    }
    Ok(OriginalSend {
        intent_id: id.clone(),
        intent: intent.clone(),
        controller,
        sdk,
        request,
        send_id,
        entry,
        operation,
    })
}

/// Last-resort fixture cleanup, strictly after autonomous acceptance is recorded.
/// Settle through real services, then revoke only sends with no possible channel.
pub(super) async fn cleanup_wallet_sends(
    configs: &[fips_relay::service::ServiceConfig],
    children: &mut [tokio::process::Child],
    proxy: &MintProxy,
) -> bool {
    for (cfg, child) in configs.iter().zip(children.iter_mut()) {
        if child.try_wait().unwrap().is_some() {
            continue;
        }
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            request(cfg, &AdminRequest::PauseRouteRefresh),
        )
        .await;
        let _ = tokio::time::timeout(Duration::from_secs(20), request(cfg, &AdminRequest::Settle))
            .await;
    }
    for child in children {
        if child.try_wait().unwrap().is_none() {
            stop(child).await;
        }
    }
    let mut available = 0;
    let mut unchanged = true;
    for cfg in configs {
        let wallet = cfg.state_directory.join("wallet");
        let sdk_path = spilman_client_store_path(&wallet);
        let sdk = if sdk_path.exists() {
            read(&sdk_path)
        } else {
            Value::default()
        };
        let journal_path = cfg.state_directory.join("controller/controller.json");
        let controller = read(&journal_path);
        let sends = send_journal(&wallet).await;
        // A channel may own these proofs even if its control reply was lost.
        if entries(&sdk, "openings") == 0 && entries(&sdk, "funding") == 0 {
            for entry in sends["entries"].as_object().unwrap().values() {
                if let Some(operation) = entry["plan"]["operation_id"].as_str() {
                    let refund = tokio::time::timeout(
                        Duration::from_secs(30),
                        revoke_pending_payment(&wallet, &proxy.url, operation),
                    )
                    .await;
                    eprintln!(
                        "pre-opening fixture_revoke_completed={}",
                        matches!(refund, Ok(Ok(_)))
                    );
                }
            }
        }
        unchanged &=
            read(&journal_path) == controller && (!sdk_path.exists() || read(&sdk_path) == sdk);
        available += load_mint_balance(&wallet, &proxy.url)
            .await
            .unwrap()
            .balance_sat;
    }
    let fees = proxy.state.fees_collected.load(Ordering::SeqCst);
    let issued = configs.len() as u64 * 128;
    eprintln!(
        "pre-opening fixture_cleanup available_sat={available} fees_sat={fees} issued_sat={issued} authority_unchanged={unchanged}"
    );
    unchanged && available + fees == issued
}
