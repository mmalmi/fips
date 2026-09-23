//! A transit payer recovers its original wallet send without a local source Watch.
use super::{preopening_support::*, restore::*, *};
use cashu_service::{simulation::MintProxy, spilman_client_store_path};
use serde_json::Value;
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

fn journal(cfg: &fips_relay::service::ServiceConfig) -> Value {
    read(&cfg.state_directory.join("controller/controller.json"))
}

fn seller(cfg: &fips_relay::service::ServiceConfig) -> Value {
    read(&cfg.state_directory.join("seller/ledger.json"))
}

struct Upstream {
    source: Value,
    incoming: Value,
    terms: Value,
    offer_id: String,
    credit_msat: u64,
}

fn upstream_boundary(
    configs: &[fips_relay::service::ServiceConfig],
    middle: &Value,
) -> Result<Upstream, &'static str> {
    let source = journal(&configs[0]);
    let incoming = middle["incoming"].as_object().unwrap();
    if incoming.len() != 1
        || entries(middle, "watched_routes") != 0
        || entries(&source, "funding") != 1
        || entries(&source, "outgoing") != 1
    {
        return Err("capture did not have one genuine upstream-funded transit dependency");
    }
    let incoming = incoming.values().next().unwrap().clone();
    let terms = incoming["channel"].clone();
    let outgoing = source["outgoing"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    let funded = &source["funding"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap()["funded"];
    let ledger = seller(&configs[1]);
    let channels = ledger["ledger"]["channels"].as_array().unwrap();
    if incoming["phase"] != "Prepared"
        || channels.len() != 1
        || channels[0]["terms"] != terms
        || funded["terms"] != terms
        || outgoing["purchase"]["channel"] != terms
        || outgoing["purchase"]["contract"] != incoming["contract"]
        || incoming["downstream"].is_null()
        || !middle["requested"]
            .as_object()
            .unwrap()
            .values()
            .any(|o| *o == incoming["downstream"])
        || entries(middle, "outgoing") != 0
    {
        return Err("upstream funding was not verified before middle wallet preparation");
    }
    let credit_msat = channels[0]["usage"]["paid_msat"].as_u64().unwrap();
    if incoming["verified_paid_msat"] != credit_msat {
        return Err("upstream verified credit differs from the durable ledger");
    }
    let offer_id = outgoing["offer"]["id"].as_str().unwrap().to_owned();
    Ok(Upstream {
        source,
        incoming,
        terms,
        offer_id,
        credit_msat,
    })
}

fn upstream_preserved(
    errors: &mut Vec<&'static str>,
    original: &Upstream,
    current: &Value,
    ledger: &Value,
) {
    let id = original.terms["id"].as_str().unwrap();
    let contract = original.incoming["contract"]["id"].as_str().unwrap();
    if let Some(incoming) = current["incoming"].get(contract) {
        let mut expected = original.incoming.clone();
        expected["phase"] = incoming["phase"].clone();
        check(
            errors,
            *incoming == expected && incoming["phase"] != "Active",
            "upstream acceptance changed or activated after interruption",
        );
    }
    if let Some(channel) = ledger["ledger"]["channels"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["terms"]["id"] == id)
    {
        check(
            errors,
            channel["terms"] == original.terms
                && channel["usage"]["paid_msat"].as_u64().unwrap() >= original.credit_msat,
            "upstream channel terms or verified credit were lost",
        );
    } else {
        let history = &current["history"]["seller"]["totals"];
        check(
            errors,
            history["accounting"]["channels"] == 1
                && history["accounting"]["capacity_sat"] == original.terms["capacity_sat"]
                && history["accounting"]["usage"]["paid_msat"]
                    .as_u64()
                    .unwrap_or(0)
                    >= original.credit_msat,
            "upstream channel disappeared without durable seller accounting",
        );
    }
}

async fn source_withdrawn(
    cfg: &fips_relay::service::ServiceConfig,
    middle: &str,
    destination: &str,
    original: &Upstream,
) -> bool {
    let mut last_observed = Value::Null;
    let withdrawn = tokio::time::timeout(Duration::from_secs(100), async {
        loop {
            if let Ok(status) = request(cfg, &AdminRequest::Status).await {
                let peers = status["peers"].as_array().unwrap();
                let current = journal(cfg);
                let watches = current["watched_routes"].as_object().unwrap();
                // Configured peers can remain listed while disconnected. Use
                // the same live-connection boundary as ordinary withdrawal.
                let connected = peers.iter().any(|p| p["npub"] == middle && p["connected"] == true);
                last_observed = serde_json::json!({
                    "connected_middle": connected,
                    "watches": watches.len(),
                    "pending": watches.get(destination).map(|w| !w["pending"].is_null()),
                    "paused": watches.get(destination).map(|w| &w["paused"]),
                    "fenced": current["recovery_only"].as_array().unwrap().iter()
                        .any(|id| id == &original.offer_id),
                    "original_funding_sequence": current["next_funding"] == original.source["next_funding"],
                });
                if !connected
                    && watches.len() == 1
                    && watches
                        .get(destination)
                        .is_some_and(|watch| watch["paused"] == false && watch["pending"].is_null())
                    && current["recovery_only"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|id| id == &original.offer_id)
                    && current["next_funding"] == original.source["next_funding"]
                {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .is_ok();
    if !withdrawn {
        eprintln!("transit source withdrawal not observed: {last_observed}");
    }
    withdrawn
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_transit_wallet_send_recovers_without_a_middle_watch() {
    tokio::time::timeout(Duration::from_secs(360), async {
        let root = tempfile::tempdir().unwrap();
        let (mint, network) = setup::start_mint(root.path(), 9622).await;
        let proxy = MintProxy::start(mint.url()).await;
        // Bound each payer's original fee-bearing operation. Assertions reject
        // replacement funding. All four wallets receive exactly 128 test sats.
        let setup::Bench { mint, configs, paths, npubs, mut children } =
            setup::start_line(root.path(), mint, network, &proxy.url, 60, 5,
                              &[48, 48, 40, 40]).await;
        let initial: Vec<_> = configs.iter().map(journal).collect();
        let cfg = &configs[1];
        let wallet = cfg.state_directory.join("wallet");
        let store = spilman_client_store_path(&wallet);
        let keyset = mint.mint().rotate_keyset("sat".parse().unwrap(),
            (0..=10).map(|b| 1u64 << b).collect(), 500, false, None).await.unwrap().id;
        let retained = store.clone();
        let matched = Arc::new(Mutex::new(None));
        let capture = matched.clone();
        let seen = Arc::new(AtomicUsize::new(0));
        let responses = seen.clone();
        let (committed, release) = proxy.state.pause_matching_swap_reply(move |wire| {
            preparation_match(&retained, &capture, &responses, wire)
        });
        let source = configs[0].clone();
        let destination = npubs[3].clone();
        let mut buying = tokio::spawn(async move {
            request(&source, &AdminRequest::Watch { destination, max_rate_msat_per_kib: 8192 }).await
        });
        let captured = tokio::select! {
            signal = committed => signal.is_ok(),
            _ = &mut buying => false,
            _ = tokio::time::sleep(Duration::from_secs(30)) => false,
        };
        if !captured {
            let _ = release.send(());
            let conserved = cleanup_wallet_sends(&configs, &mut children, &proxy).await;
            buying.abort();
            panic!("transit preparation boundary absent; fixture conserved={conserved}");
        }
        children[1].kill().await.unwrap();
        assert!(!children[1].wait().await.unwrap().success());
        let _ = release.send(());
        let original = match inspect_original(cfg, &keyset.to_string(), &matched).await {
            Ok(original) => original,
            Err(error) => {
                let conserved = cleanup_wallet_sends(&configs, &mut children, &proxy).await;
                buying.abort();
                panic!("transit preparation capture: {error}; fixture conserved={conserved}");
            }
        };
        let upstream = match upstream_boundary(&configs, &original.controller) {
            Ok(upstream) => upstream,
            Err(error) => {
                let conserved = cleanup_wallet_sends(&configs, &mut children, &proxy).await;
                buying.abort();
                panic!("transit upstream premise: {error}; fixture conserved={conserved}");
            }
        };
        let offer = original.controller["requested"].as_object().unwrap().values().next().unwrap();
        let offer_id = offer["id"].as_str().unwrap();
        let expiry = offer["expires_unix"].as_u64().unwrap();
        stop(&mut children[2]).await;
        // No pause or settlement request can stand in for native peer removal
        // and the original source Watch's durable automatic withdrawal.
        let withdrew = source_withdrawn(&configs[0], &npubs[1], &npubs[3], &upstream).await;
        if !withdrew {
            children[1] = start(&paths[1]).await;
            let conserved = cleanup_wallet_sends(&configs, &mut children, &proxy).await;
            buying.abort();
            panic!("source eviction/Watch withdrawal not observed; fixture conserved={conserved}");
        }
        while now() <= expiry { tokio::time::sleep(Duration::from_millis(100)).await; }
        // Joining back to the source is allowed; the downstream provider stays
        // absent for the entire autonomous observation. Middle receives no admin
        // Buy, Watch, Settle, Pause or recovery request.
        children[1] = start(&paths[1]).await;
        let mut errors = Vec::new();
        let mut fenced = false;
        let mut retired_dependency = false;
        let mut automatic = false;
        let mut upstream_closed = false;
        let mut last_status = Value::Null;
        let allowance = cfg.terms.controller.channel_capacity_sat + 1
            ..=cfg.terms.controller.max_wallet_spend_sat;
        let contract = upstream.incoming["contract"]["id"].as_str().unwrap();
        let channel = upstream.terms["id"].as_str().unwrap();
        // Existing expiry plus normal upkeep; no fixture rescue occurs here.
        while now() <= original.request.expiry_unix + 45 {
            let current = journal(cfg);
            let sdk = read(&store);
            check(&mut errors, entries(&sdk, "openings") == 0 && entries(&sdk, "funding") == 0,
                "expired transit recovery created a channel opening");
            check(&mut errors, current["history"]["channels"]["totals"]["channels"].as_u64().unwrap_or(0) == 0,
                "transit recovery opened and retired an unauthorized channel");
            check(&mut errors, entries(&current, "watched_routes") == 0,
                "transit recovery acquired a local source Watch");
            check(&mut errors, current["next_funding"] == original.controller["next_funding"]
                && entries(&current, "outgoing") == 0,
                "transit recovery allocated funding or activated onward traffic");
            if let Some(saved) = current["funding"].get(&original.intent_id) {
                check(&mut errors, funding_authority(saved) == original.intent && saved["funded"].is_null(),
                    "transit recovery changed original funding authority");
                if saved["reclaim"]["state"] == "complete" {
                    check(&mut errors, saved["reclaim"]["result"]["wallet_operation_id"] == original.operation,
                        "transit recovery changed the original wallet operation");
                }
            }
            fenced |= current["recovery_only"].as_array().unwrap().iter().any(|id| id == offer_id);
            retired_dependency |= current["incoming"].get(contract).is_none()
                && current["history"]["sellers"][channel] == upstream.terms;
            upstream_preserved(&mut errors, &upstream, &current, &seller(cfg));
            let source_now = journal(&configs[0]);
            check(&mut errors, source_now["next_funding"] == upstream.source["next_funding"]
                && source_now["policy"] == upstream.source["policy"]
                && current["policy"] == original.controller["policy"],
                "source Watch allocated replacement funding or spending caps changed");
            for intent in source_now["funding"].as_object().unwrap().values() {
                check(&mut errors, upstream.source["funding"].as_object().unwrap().values().any(|old| old == intent),
                    "upstream original funding evidence changed");
            }
            if let Ok(Ok(status)) = tokio::time::timeout(Duration::from_secs(2),
                request(cfg, &AdminRequest::Status)).await {
                check(&mut errors, status["purchases"].as_array().unwrap().is_empty()
                    && status["remaining_budget_sat"] == cfg.terms.buyer_budget_sat,
                    "middle gained purchase authority or signed unapproved traffic");
                automatic = fenced && retired_dependency && terminal_refund(&current, &status,
                    &original.intent_id, &original.operation, &allowance);
                last_status = status;
            }
            let settlements = &source_now["buyer_settlements"][channel];
            upstream_closed |= settlements["refunded"] == true
                && (settlements["released"] == true || settlements["kind"] == "expiry")
                && settlements["channel"] == upstream.terms;
            if automatic && upstream_closed { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let before_cleanup = journal(cfg);
        let source_status = tokio::time::timeout(Duration::from_secs(2),
            request(&configs[0], &AdminRequest::Status)).await.ok().and_then(Result::ok);
        let upstream_budget = source_status.as_ref().map(|status| status["funding_budget"].clone());
        check(&mut errors, upstream_budget.as_ref().is_some_and(|budget|
            budget["pending_reserved_sat"] == 0 && budget["locked_sat"] == 0
            && budget["wallet_debited_sat"].as_u64().is_some_and(|n| (33..=48).contains(&n))),
            "upstream original capital did not close automatically");
        let send_before = send_journal(&wallet).await;
        check(&mut errors, request_count(&send_before) == 1, "middle allocated another wallet send");
        if let Some(saved) = send_before["entries"].get(&original.send_id) {
            check(&mut errors, saved["request"] == original.entry["request"]
                && saved["preparation"]["planned"] == original.entry["preparation"]["planned"], "middle changed its original request or plan");
        }
        if !automatic {
            let sdk = read(&store);
            check(&mut errors, before_cleanup["funding"].get(&original.intent_id)
                .is_some_and(|saved| funding_authority(saved) == original.intent),
                "unresolved transit intent lost immutable authority");
            check(&mut errors, sdk["admissions"][&original.intent_id]["request"]
                == original.sdk["admissions"][&original.intent_id]["request"],
                "unresolved transit admission lost its exact request");
            check(&mut errors, last_status["funding_budget"]["pending_reserved_sat"]
                == original.intent["max_wallet_debit_sat"]
                && last_status["funding_budget"]["locked_sat"] == original.intent["max_wallet_debit_sat"],
                "unresolved transit send released its reserved capital");
        }
        eprintln!("transit pre-opening automatic={automatic} fenced={fenced} dependency_retired={retired_dependency} upstream_closed={upstream_closed} budget={} inspected_responses={}",
            last_status["funding_budget"], seen.load(Ordering::SeqCst));
        check(&mut errors, automatic && upstream_closed,
            "ordinary transit upkeep did not recover; fixture cleanup is not autonomous success");
        if automatic {
            let budget = &last_status["funding_budget"];
            let retained_proceeds: u64 = before_cleanup["seller_settlements"].as_object().unwrap()
                .values().map(|s| s["report"]["paid_sat"].as_u64().unwrap_or(0)
                    + s["report"]["receiver_fee_reserve_sat"].as_u64().unwrap_or(0)).sum();
            let history = &before_cleanup["history"]["seller"]["totals"];
            let proceeds = retained_proceeds + history["paid_sat"].as_u64().unwrap_or(0)
                + history["receiver_fee_reserve_sat"].as_u64().unwrap_or(0);
            let balance = spendable_balance(&wallet, &proxy.url).await;
            let expected = 128 - budget["wallet_debited_sat"].as_u64().unwrap()
                + budget["wallet_refunded_sat"].as_u64().unwrap();
            check(&mut errors, proceeds == 0 && balance == expected,
                "original transit refund was not spendable before fixture cleanup");
            eprintln!("transit pre-cleanup spendable_sat={balance} expected_sat={expected} seller_proceeds_sat={proceeds}");
        }
        // Stop the acceptance window before any cleanup-only administrative call.
        // Cleanup can reclaim only original unowned sends, never edit a journal.
        let conserved = cleanup_wallet_sends(&configs, &mut children, &proxy).await;
        buying.abort();
        check(&mut errors, conserved, "all four wallet balances plus mint fees were not conserved");
        let final_send = send_journal(&wallet).await;
        check(&mut errors, request_count(&final_send) == 1,
            "fixture cleanup allocated another middle send");
        if let Some(saved) = final_send["entries"].get(&original.send_id) {
            check(&mut errors, saved["request"] == original.entry["request"]
                && saved["preparation"]["planned"] == original.entry["preparation"]["planned"], "fixture cleanup replaced the middle send");
        }
        for (index, cfg) in configs.iter().enumerate() {
            let state = journal(cfg);
            let balance = load_mint_balance(&cfg.state_directory.join("wallet"), &proxy.url).await.unwrap().balance_sat;
            if index < 2 {
                let before = if index == 0 { &upstream.source } else { &original.controller };
                check(&mut errors, state["next_funding"] == before["next_funding"],
                    "cleanup allocated replacement funding");
            }
            if index == 0 && automatic && upstream_closed {
                let budget = upstream_budget.as_ref().unwrap();
                check(&mut errors, balance == 128 - budget["wallet_debited_sat"].as_u64().unwrap()
                    + budget["wallet_refunded_sat"].as_u64().unwrap(),
                    "upstream refund did not reach its original wallet");
            }
            if index >= 2 {
                check(&mut errors, balance == 128 && entries(&state, "funding") == 0
                    && state["next_funding"] == initial[index]["next_funding"],
                    "downstream wallets acquired unapproved funding");
            }
        }
        assert!(errors.is_empty(), "transit pre-opening recovery: {errors:?}");
    }).await.expect("bounded four-daemon transit recovery and fixture closure");
}
