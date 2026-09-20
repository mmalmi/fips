//! A committed wallet send must not remain reserved forever before channel opening.
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
    sync::Mutex,
    sync::atomic::{AtomicUsize, Ordering},
};

async fn send_journal(wallet: &Path) -> Value {
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

fn original_send(journal: &Value, request: &WalletRequest) -> (String, Value) {
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

fn entries(state: &Value, field: &str) -> usize {
    // SDK maps may be omitted when empty, unlike the controller journal maps.
    state
        .get(field)
        .map_or(0, |value| value.as_object().unwrap().len())
}

fn request_count(journal: &Value) -> u64 {
    journal["entries"].as_object().unwrap().len() as u64
        + journal["sequences"]
            .as_object()
            .unwrap()
            .values()
            .map(|history| history["requests"].as_u64().unwrap())
            .sum::<u64>()
}

fn check(errors: &mut Vec<&'static str>, condition: bool, message: &'static str) {
    if !condition && !errors.contains(&message) {
        errors.push(message);
    }
}

fn terminal_refund(
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

fn funding_authority(intent: &Value) -> Value {
    let mut authority = intent.clone();
    authority["funded"] = Value::Null;
    authority.as_object_mut().unwrap().remove("reclaim");
    authority
}

async fn premise_cleanup(
    configs: &[fips_relay::service::ServiceConfig],
    children: &mut [tokio::process::Child],
    proxy: &MintProxy,
) {
    // A failed boundary can mean Watch already completed. First let the ordinary
    // service settle any accepted channel while its provider is still reachable.
    let cfg = &configs[0];
    let _ = tokio::time::timeout(
        Duration::from_secs(3),
        request(cfg, &AdminRequest::PauseRouteRefresh),
    )
    .await;
    let settlement =
        tokio::time::timeout(Duration::from_secs(20), request(cfg, &AdminRequest::Settle)).await;
    eprintln!(
        "pre-opening premise_cleanup_service_settled={}",
        matches!(settlement, Ok(Ok(_)))
    );
    for child in children {
        if child.try_wait().unwrap().is_none() {
            stop(child).await;
        }
    }
    let wallet = cfg.state_directory.join("wallet");
    let path = spilman_client_store_path(&wallet);
    let sdk = if path.exists() {
        read(&path)
    } else {
        Value::default()
    };
    let sends = send_journal(&wallet).await;
    // Never revoke proofs which might already fund a channel. Those remain
    // represented in the retained SDK state if ordinary settlement did not finish.
    if entries(&sdk, "openings") == 0 && entries(&sdk, "funding") == 0 {
        for entry in sends["entries"].as_object().unwrap().values() {
            if let Some(operation) = entry["plan"]["operation_id"].as_str() {
                let refund = tokio::time::timeout(
                    Duration::from_secs(30),
                    revoke_pending_payment(&wallet, &proxy.url, operation),
                )
                .await;
                match refund {
                    Ok(Ok(amount)) => eprintln!("pre-opening premise_cleanup_refund_sat={amount}"),
                    _ => eprintln!("pre-opening premise_cleanup_refund_complete=false"),
                }
            }
        }
    }
    let mut available = 0;
    for cfg in configs {
        available += load_mint_balance(&cfg.state_directory.join("wallet"), &proxy.url)
            .await
            .unwrap()
            .balance_sat;
    }
    let fees = proxy.state.fees_collected.load(Ordering::SeqCst);
    eprintln!(
        "pre-opening premise_cleanup available_sat={available} fees_sat={fees} issued_sat=384 conserved={} retained_openings={}",
        available + fees == 384,
        entries(&sdk, "openings")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_wallet_send_recovers_after_offer_expiry_without_replacement_funding() {
    tokio::time::timeout(Duration::from_secs(240), async {
        let root = tempfile::tempdir().unwrap();
        let (mint, network) = setup::start_mint(root.path(), 9621).await;
        let proxy = MintProxy::start(mint.url()).await;
        // The forced keyset exchange costs more than the other fee fixtures.
        // Authorize this bounded allowance before starting any purchase.
        let setup::Bench {
            mint,
            configs,
            paths,
            npubs,
            mut children,
        } = setup::start_nodes_with_funding_limit(root.path(), mint, network, &proxy.url, 60, 5, 48).await;
        let cfg = &configs[0];
        let allowance = cfg.terms.controller.channel_capacity_sat + 1
            ..=cfg.terms.controller.max_wallet_spend_sat;
        let wallet = cfg.state_directory.join("wallet");
        let store = spilman_client_store_path(&wallet);
        let journal = cfg.state_directory.join("controller/controller.json");
        // As with the SDK's single-coin fixture, force a wallet preparation swap.
        // Existing denominations could otherwise satisfy a send without one.
        // Requiring a newly active keyset makes every old proof need exchange,
        // while retaining the same fee policy and the original 384 issued sats.
        let funding_keyset = mint.mint().rotate_keyset(
            "sat".parse().unwrap(), (0..=10).map(|b| 1u64 << b).collect(),
            500, false, None,
        ).await.unwrap().id;
        let retained = store.clone();
        let matched = Arc::new(Mutex::new(None));
        let capture = matched.clone();
        let seen = Arc::new(AtomicUsize::new(0));
        let seen_responses = seen.clone();
        let swaps_before = proxy.state.swaps.load(Ordering::SeqCst);
        let (committed, release) = proxy.state.pause_matching_swap_reply(move |request| {
            seen_responses.fetch_add(1, Ordering::SeqCst);
            let Ok(bytes) = std::fs::read(&retained) else {
                return false;
            };
            let state: Value = serde_json::from_slice(&bytes).unwrap();
            let admitted = state["admissions"].as_object();
            if !admitted.is_some_and(|entries| {
                entries.len() == 1
                    && entries.values().all(|entry| entry["funding_started"] == true)
            }) || entries(&state, "openings") != 0
            {
                return false;
            }
            *capture.lock().unwrap() = Some(request.clone());
            true
        });
        let owner = cfg.clone();
        let destination = npubs[2].clone();
        let mut buying = tokio::spawn(async move {
            request(
                &owner,
                &AdminRequest::Watch {
                    destination,
                    max_rate_msat_per_kib: 8_192,
                },
            )
            .await
        });
        let boundary = tokio::select! {
            signal = committed => signal.map_err(|_| "mint response barrier closed".to_owned()),
            result = &mut buying => Err(match result {
                Ok(Ok(_)) => "Watch completed before the pre-opening swap boundary".to_owned(),
                Ok(Err(error)) => format!("Watch failed before capture: {}",
                    error.lines().next().unwrap_or_default().chars().take(200).collect::<String>()),
                Err(_) => "Watch task failed before the pre-opening swap boundary".to_owned(),
            }),
            _ = tokio::time::sleep(Duration::from_secs(30)) =>
                Err("pre-opening swap boundary timed out".to_owned()),
        };
        if let Err(error) = boundary {
            let _ = release.send(());
            let sdk = if store.exists() { read(&store) } else { Value::default() };
            let controller = read(&journal);
            let sends = send_journal(&wallet).await;
            let started = sdk["admissions"].as_object().into_iter().flat_map(|a| a.values())
                .filter(|a| a["funding_started"] == true).count();
            let planned = sends["entries"].as_object().unwrap().values()
                .filter(|s| !s["plan"].is_null()).count();
            eprintln!("pre-opening premise={error}; admissions={} started={started} openings={} intents={} outgoing={} wallet_plans={planned} swap_delta={} inspected_responses={}",
                entries(&sdk, "admissions"), entries(&sdk, "openings"),
                entries(&controller, "funding"), entries(&controller, "outgoing"),
                proxy.state.swaps.load(Ordering::SeqCst) - swaps_before,
                seen.load(Ordering::SeqCst));
            premise_cleanup(&configs, &mut children, &proxy).await;
            if !buying.is_finished() { buying.abort(); }
            panic!("fixture did not reach the committed pre-opening wallet send: {error}");
        }
        children[0].kill().await.unwrap();
        assert!(!children[0].wait().await.unwrap().success());
        assert!(buying.await.unwrap().is_err());
        let _ = release.send(());

        let interrupted = read(&journal);
        let intents = interrupted["funding"].as_object().unwrap();
        assert_eq!(intents.len(), 1);
        let (id, intent) = intents.iter().next().unwrap();
        assert!(intent["funded"].is_null());
        let pending = read(&store);
        assert_eq!(pending["admissions"].as_object().unwrap().len(), 1);
        assert_eq!(pending["admissions"][id]["funding_started"], true);
        assert_eq!(entries(&pending, "openings"), 0);
        assert!(pending["funding"].as_object().unwrap().is_empty());
        let wanted: WalletRequest =
            serde_json::from_value(pending["admissions"][id]["request"].clone()).unwrap();
        assert!(wanted.client_request_id.as_ref() == Some(id));
        assert_eq!(wanted.route_created_at_unix, intent["created_unix"].as_u64());
        assert_eq!(wanted.max_total_amount_sat, intent["max_wallet_debit_sat"].as_u64());
        assert_eq!(wanted.expiry_unix, intent["expires_unix"].as_u64().unwrap() + 60);
        assert_eq!(wanted.capacity_sat, intent["capacity_sat"].as_u64().unwrap());
        assert!(Some(wanted.receiver_pubkey_hex.as_str()) == intent["receiver_pubkey_hex"].as_str());
        let original_journal = send_journal(&wallet).await;
        assert_eq!(request_count(&original_journal), 1);
        let (send_id, original) = original_send(&original_journal, &wanted);
        assert!(original["request"]["request_id"] == send_id);
        let operation = original["plan"]["operation_id"].as_str().unwrap().to_owned();
        let proofs: cashu::nuts::Proofs =
            serde_json::from_value(original["plan"]["proofs_to_swap"].clone()).unwrap();
        let old_inputs = !proofs.is_empty() && proofs.iter().all(|p| p.keyset_id != funding_keyset);
        let new_keyset = original["request"]["required_keyset_id"] == funding_keyset.to_string();
        let (exact_inputs, input_count, matching_inputs) = {
            let matched = matched.lock().unwrap();
            let inputs = matched.as_ref().unwrap().inputs();
            // SwapRequest::new strips DLEQ metadata for the wire. Compare every
            // remaining proof field and its exact cardinality/order, not amounts.
            let wire_proofs = proofs.without_dleqs();
            (wire_proofs == *inputs, inputs.len(),
                wire_proofs.iter().filter(|p| inputs.contains(p)).count())
        };
        if !old_inputs || !new_keyset || !exact_inputs {
            eprintln!("pre-opening capture_identity old_inputs={old_inputs} new_keyset={new_keyset} exact_inputs={exact_inputs} saved_count={} wire_count={input_count} matching_count={matching_inputs}", proofs.len());
            premise_cleanup(&configs, &mut children, &proxy).await;
            panic!("held response did not match the original persisted preparation swap");
        }
        assert!(original["result"].is_null());
        assert_eq!(proxy.state.swaps.load(Ordering::SeqCst), swaps_before + 1);
        let requested = interrupted["requested"].as_object().unwrap();
        assert_eq!(requested.len(), 1);
        let offer = requested.values().next().unwrap();
        let offer_id = offer["id"].as_str().unwrap();
        let expiry = offer["expires_unix"].as_u64().unwrap();
        stop(&mut children[1]).await;
        while now() <= expiry {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        children[0] = start(&paths[0]).await;

        let mut errors = Vec::new();
        let mut fenced = false;
        let mut automatic = false;
        let mut last_status = Value::Null;
        let mut observed_debit = None;
        // Give normal recovery the entire original channel expiry plus fifteen
        // seconds of its existing two-second upkeep. No fixture recovery runs here.
        while now() <= wanted.expiry_unix + 15 {
            let current = read(&journal);
            check(&mut errors, current["next_funding"] == interrupted["next_funding"],
                "recovery allocated replacement funding");
            check(&mut errors, current["outgoing"].as_object().unwrap().is_empty(),
                "expired or withdrawn route regained purchase authority");
            fenced |= current["recovery_only"].as_array().unwrap().iter().any(|v| v == offer_id);
            if let Some(saved) = current["funding"].get(id) {
                check(&mut errors, funding_authority(saved) == *intent, "original funding intent changed");
                if saved["reclaim"]["state"] == "complete" {
                    check(&mut errors, saved["reclaim"]["result"]["wallet_operation_id"] == operation,
                        "reclaim switched wallet operations");
                    observed_debit = saved["reclaim"]["result"]["wallet_cost"]["wallet_debit_sat"].as_u64();
                }
                if !saved["funded"].is_null() {
                    check(&mut errors, saved["funded"]["wallet_operation_id"] == operation,
                        "funding switched wallet operations");
                    observed_debit = saved["funded"]["wallet_cost"]["wallet_debit_sat"].as_u64();
                }
            }
            if let Ok(Ok(status)) = tokio::time::timeout(
                Duration::from_secs(2), request(cfg, &AdminRequest::Status),
            ).await {
                check(&mut errors, status["purchases"].as_array().unwrap().is_empty(),
                    "a purchase became active after withdrawal");
                check(&mut errors, status["remaining_budget_sat"] == cfg.terms.buyer_budget_sat,
                    "recovery consumed unapproved buyer authority");
                automatic = fenced && terminal_refund(&current, &status, id, &operation, &allowance);
                last_status = status;
            }
            if automatic { break; }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let observed = read(&journal);
        let sdk_observed = read(&store);
        eprintln!("pre-opening automatic={automatic} fenced={fenced} pending_intents={} admissions={} openings={} outgoing={} budget={} original_expired={}",
            observed["funding"].as_object().unwrap().len(),
            entries(&sdk_observed, "admissions"),
            entries(&sdk_observed, "openings"),
            observed["outgoing"].as_object().unwrap().len(),
            last_status["funding_budget"], now() > wanted.expiry_unix);
        for (i, child) in children.iter_mut().enumerate() {
            if i != 1 { stop(child).await; }
        }
        let stopped_journal = read(&journal);
        let stopped_sdk = read(&store);
        let before_cleanup = send_journal(&wallet).await;
        check(&mut errors, request_count(&before_cleanup) == 1, "a second wallet send was recorded");
        if let Some(saved) = before_cleanup["entries"].get(&send_id) {
            check(&mut errors, saved["request"] == original["request"] && saved["plan"] == original["plan"],
                "original wallet request or operation changed");
        }
        if !automatic {
            check(&mut errors, stopped_journal["funding"].get(id).is_some_and(|saved| funding_authority(saved) == *intent),
                "unresolved funding lost its original durable authority");
            check(&mut errors, stopped_sdk["admissions"][id]["request"] == pending["admissions"][id]["request"]
                && stopped_sdk["admissions"][id]["funding_started"] == true,
                "unresolved admission lost its original request");
            check(&mut errors, before_cleanup["entries"].get(&send_id).is_some(),
                "unresolved send lost its original operation mapping");
            check(&mut errors,
                last_status["funding_budget"]["pending_reserved_sat"] == intent["max_wallet_debit_sat"]
                    && last_status["funding_budget"]["locked_sat"] == intent["max_wallet_debit_sat"],
                "unresolved funding released its reserved capital");
            // Deliberate fixture cleanup, after the autonomous observation ends:
            // recover/revoke only the original send. Do not create an opening or
            // edit the controller's still-unresolved reservation to claim success.
            assert_eq!(entries(&stopped_sdk, "openings"), 0,
                "fixture cleanup cannot revoke a send now owned by a channel");
            let refund = tokio::time::timeout(Duration::from_secs(30),
                revoke_pending_payment(&wallet, &proxy.url, &operation))
                .await.expect("bounded original wallet-send fixture cleanup").unwrap();
            eprintln!("pre-opening fixture_cleanup_refund_sat={refund}; autonomous_recovery=false");
            check(&mut errors, refund > 0, "fixture cleanup recovered no test funds");
            check(&mut errors, read(&journal) == stopped_journal, "fixture cleanup changed FIPS authority");
            check(&mut errors, read(&store) == stopped_sdk, "fixture cleanup changed channel authority");
            let cleaned = send_journal(&wallet).await;
            let (cleaned_id, saved) = original_send(&cleaned, &wanted);
            check(&mut errors, request_count(&cleaned) == 1 && cleaned_id == send_id
                && saved["plan"] == original["plan"],
                "fixture cleanup replaced the original wallet operation");
            let debit = saved["result"]["cost"]["wallet_debit_sat"].as_u64().unwrap();
            check(&mut errors, allowance.contains(&debit),
                "original wallet send exceeded its cost allowance");
        }
        let mut spendable = 0;
        for (i, cfg) in configs.iter().enumerate() {
            let available = load_mint_balance(&cfg.state_directory.join("wallet"), &proxy.url)
                .await.unwrap().balance_sat;
            check(&mut errors, if i == 0 { available <= 128 } else { available == 128 },
                "unrelated wallet balance changed or buyer gained unissued money");
            if i == 0 && automatic {
                let budget = &last_status["funding_budget"];
                check(&mut errors, available == 128 - budget["wallet_debited_sat"].as_u64().unwrap()
                    + budget["wallet_refunded_sat"].as_u64().unwrap(),
                    "terminal controller refund did not reach the original wallet");
            }
            spendable += available;
        }
        let fees = proxy.state.fees_collected.load(Ordering::SeqCst);
        eprintln!("pre-opening closure spendable_sat={spendable} mint_fees_sat={fees} issued_sat=384");
        check(&mut errors, spendable + fees == 384, "test money and mint fees were not conserved");
        if let Some(debit) = observed_debit {
            check(&mut errors, allowance.contains(&debit), "original funding exceeded its cost allowance");
        }
        check(&mut errors, automatic, "pre-opening send stayed unresolved after original expiry; fixture cleanup is not service recovery");
        assert!(errors.is_empty(), "pre-opening recovery: {errors:?}");
    }).await.expect("bounded pre-opening process recovery and fixture cleanup");
}
