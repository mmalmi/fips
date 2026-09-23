//! A refunded selected trial must not own another abandoned send to its provider.
use super::{preopening_support::*, restore::*, *};
use cashu_service::{
    StreamingRouteOpenCashuSpilmanChannelFromWalletRequest as WalletRequest,
    revoke_pending_payment, simulation::MintProxy, spilman_client_store_path,
};
use fips_relay::{route_quotes::PriceSelectionPolicy, service::ServiceConfig};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

fn journal(cfg: &ServiceConfig) -> Value {
    read(&cfg.state_directory.join("controller/controller.json"))
}
fn buyer(cfg: &ServiceConfig) -> Value {
    read(&cfg.state_directory.join("buyer/buyer.json"))
}
fn ensure(condition: bool, message: &'static str) -> Result<(), String> {
    condition.then_some(()).ok_or_else(|| message.to_owned())
}

struct OldTrial {
    destination: String,
    contract: String,
    channel: String,
    outgoing: Value,
    controller: Value,
    buyer: Value,
    status: Value,
}

impl OldTrial {
    async fn prepare(configs: &[ServiceConfig], npubs: &[String]) -> Result<Self, String> {
        let cfg = &configs[0];
        let access = request(
            cfg,
            &AdminRequest::Watch {
                destination: npubs[2].clone(),
                max_rate_msat_per_kib: 8192,
            },
        )
        .await?;
        request(cfg, &AdminRequest::PauseRouteRefresh).await?;
        let purchase = &access["purchase"];
        let contract = purchase["contract"]["id"]
            .as_str()
            .ok_or("old Watch did not buy")?
            .to_owned();
        let channel = purchase["channel"]["id"]
            .as_str()
            .ok_or("old channel missing")?
            .to_owned();
        ensure(
            purchase["contract"]["max_units"] == PriceSelectionPolicy::default().trial_max_units,
            "old Watch did not begin with the configured trial",
        )?;
        // Pause the Watch, not the ordinary payment worker or admitted traffic.
        // Two distinct bounded payloads prove real use without exhausting quota.
        for sequence in 0..2 {
            let payload = format!("retained-trial-{sequence}:{}", "x".repeat(850));
            let digest = format!("{:x}", Sha256::digest(payload.as_bytes()));
            request(
                cfg,
                &AdminRequest::Send {
                    destination: npubs[2].clone(),
                    payload,
                },
            )
            .await?;
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if request(&configs[2], &AdminRequest::Status).await?["received"]["last_sha256"]
                        == digest
                    {
                        return Ok::<_, String>(());
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .map_err(|_| "old paid trial did not deliver fresh payload")??;
        }
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let state = buyer(cfg);
                let signed = state["channels"][&channel]["authorized_sat"]
                    .as_u64()
                    .unwrap();
                let provider = read(&configs[1].state_directory.join("seller/ledger.json"));
                let credited = provider["ledger"]["channels"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|c| c["terms"]["id"] == channel)
                    .and_then(|c| c["usage"]["paid_msat"].as_u64())
                    .unwrap_or(0);
                if signed > 0 && credited >= signed * 1000 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .map_err(|_| "old trial did not receive automatic signed and credited payment")?;
        let settlement = request(cfg, &AdminRequest::Settle).await?;
        ensure(
            settlement["settlements"]
                .as_array()
                .is_some_and(|s| s.len() == 1),
            "old fixture did not settle exactly one channel",
        )?;
        let controller = journal(cfg);
        let buyer = buyer(cfg);
        let status = request(cfg, &AdminRequest::Status).await?;
        let outgoing = controller["outgoing"][&contract].clone();
        let used = buyer["quotes"][&contract]["observed_units"]
            .as_u64()
            .unwrap_or(0);
        let cap = purchase["contract"]["max_units"].as_u64().unwrap();
        let closed = &controller["buyer_settlements"][&channel];
        ensure(
            controller["watched_routes"][&npubs[2]]["selected_trial"] == contract
                && controller["watched_routes"][&npubs[2]]["paused"] == true
                && outgoing["offer"]["trial"] == true
                && outgoing["accepted"] == true
                && outgoing["purchase"] == *purchase
                && used > 0
                && used < cap
                && closed["refunded"] == true
                && closed["released"] == true
                && closed["channel"] == purchase["channel"]
                && closed["report"]["paid_sat"] == buyer["channels"][&channel]["authorized_sat"]
                && status["funding_budget"]["locked_sat"] == 0,
            "paid refunded trial was not naturally retained by its original Watch",
        )?;
        Ok(Self {
            destination: npubs[2].clone(),
            contract,
            channel,
            outgoing,
            controller,
            buyer,
            status,
        })
    }

    fn preserved(&self, cfg: &ServiceConfig, current: &Value, status: &Value) -> bool {
        let current_buyer = buyer(cfg);
        let old = &current["outgoing"][&self.contract];
        let watch = &current["watched_routes"][&self.destination];
        watch["selected_trial"] == self.contract
            && watch["paused"] == true
            && watch["pending"].is_null()
            && old["offer"] == self.outgoing["offer"]
            && old["purchase"] == self.outgoing["purchase"]
            && old["funding_id"] == self.outgoing["funding_id"]
            && old["accepted"] == true
            && current["buyer_settlements"][&self.channel]
                == self.controller["buyer_settlements"][&self.channel]
            && current_buyer["total_budget_sat"] == self.buyer["total_budget_sat"]
            && current_buyer["channels"][&self.channel] == self.buyer["channels"][&self.channel]
            && ["contract", "observed_units", "submitted_units"]
                .iter()
                .all(|field| {
                    current_buyer["quotes"][&self.contract][field]
                        == self.buyer["quotes"][&self.contract][field]
                })
            && status["remaining_budget_sat"] == self.status["remaining_budget_sat"]
            && current["policy"] == self.controller["policy"]
    }
}

/// This is deliberately post-acceptance fixture rescue, never an observation.
/// Old openings may remain, but every opening/funding record must exactly match
/// the settled baseline before the distinct original send can be revoked.
async fn cleanup(
    configs: &[ServiceConfig],
    children: &mut [tokio::process::Child],
    proxy: &MintProxy,
    history: Option<&PreparationHistory>,
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
    let cfg = &configs[0];
    let wallet = cfg.state_directory.join("wallet");
    if let Some(history) = history {
        let controller = journal(cfg);
        let sdk_path = spilman_client_store_path(&wallet);
        let sdk = read(&sdk_path);
        if let Some(id) = history.new_request_id(&controller, &sdk) {
            let wanted: WalletRequest =
                serde_json::from_value(sdk["admissions"][&id]["request"].clone()).unwrap();
            let sends = send_journal(&wallet).await;
            if request_count(&sends) == request_count(&history.sends) + 1 {
                let (send_id, entry) = original_send(&sends, &wanted);
                if let Some(operation) = entry["preparation"]["planned"]["operation_id"].as_str() {
                    let distinct = history.sends["entries"]
                        .as_object()
                        .unwrap()
                        .values()
                        .all(|old| old["preparation"]["planned"]["operation_id"] != operation);
                    if distinct && controller["funding"][&id]["reclaim"]["state"] != "complete" {
                        let result = tokio::time::timeout(
                            Duration::from_secs(30),
                            revoke_pending_payment(&wallet, &proxy.url, operation),
                        )
                        .await;
                        eprintln!(
                            "terminal-history exact-send fixture revoke completed={}",
                            matches!(result, Ok(Ok(_)))
                        );
                        let after = send_journal(&wallet).await;
                        if journal(cfg) != controller
                            || read(&sdk_path) != sdk
                            || after["entries"][&send_id]["request"] != entry["request"]
                            || after["entries"][&send_id]["preparation"]["planned"]
                                != entry["preparation"]["planned"]
                            || request_count(&after) != request_count(&sends)
                            || history.sends["entries"]
                                .as_object()
                                .unwrap()
                                .iter()
                                .any(|(key, old)| after["entries"].get(key) != Some(old))
                        {
                            return false;
                        }
                    }
                }
            }
        }
    }
    let mut spendable = 0;
    for cfg in configs {
        spendable += spendable_balance(&cfg.state_directory.join("wallet"), &proxy.url).await;
    }
    let fees = proxy.state.fees_collected.load(Ordering::SeqCst);
    eprintln!("terminal-history closure spendable_sat={spendable} fees_sat={fees} issued_sat=512");
    spendable + fees == 512
}

fn recovered(
    original: &OriginalSend,
    old: &OldTrial,
    current: &Value,
    status: &Value,
) -> Option<(u64, u64)> {
    let intent = &current["funding"][&original.intent_id];
    let result = &intent["reclaim"]["result"];
    if intent["reclaim"]["state"] != "complete"
        || !intent["funded"].is_null()
        || result["wallet_operation_id"] != original.operation
    {
        return None;
    }
    let debit = result["wallet_cost"]["wallet_debit_sat"].as_u64()?;
    let refund = result["recovered_amount_sat"].as_u64()?;
    let before = &old.status["funding_budget"];
    let budget = &status["funding_budget"];
    (debit > 32
        && debit <= 48
        && refund > 0
        && refund <= debit
        && budget["wallet_debited_sat"].as_u64()? == before["wallet_debited_sat"].as_u64()? + debit
        && budget["wallet_refunded_sat"].as_u64()?
            == before["wallet_refunded_sat"].as_u64()? + refund
        && budget["pending_reserved_sat"] == 0
        && budget["locked_sat"] == 0
        && budget["exposure_sat"].as_u64()? == before["exposure_sat"].as_u64()? + debit - refund)
        .then_some((debit, refund))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refunded_selected_trial_does_not_pin_another_original_send_to_same_provider() {
    tokio::time::timeout(Duration::from_secs(360), async {
        let root = tempfile::tempdir().unwrap();
        let (mint, network) = setup::start_mint(root.path(), 9623).await;
        let proxy = MintProxy::start(mint.url()).await;
        let setup::Bench { mint, configs, paths, npubs, mut children } =
            setup::start_configured_line(root.path(), mint, network, &proxy.url,
                setup::LineConfig { lifetime: 60, quote_lifetime: 30, funding_limits: &[48, 40, 40, 40] },
                |index, cfg| {
                    cfg.terms.billing = fips_relay::ledger::BillingBasis::ForwardingData;
                    cfg.return_allowance = true;
                    cfg.terms.quote_max_units = 131_072;
                    if index == 0 {
                        cfg.price_selection = Some(PriceSelectionPolicy::default());
                        cfg.terms.controller.max_wallet_spend_sat = 96;
                    }
                }).await;
        let initial: Vec<_> = configs.iter().map(journal).collect();
        let old = match OldTrial::prepare(&configs, &npubs).await {
            Ok(old) => old,
            Err(error) => {
                let conserved = cleanup(&configs, &mut children, &proxy, None).await;
                if !conserved { let _ = root.keep(); }
                panic!("terminal-history old-trial premise: {error}; conserved={conserved}");
            }
        };
        let cfg = &configs[0];
        let wallet = cfg.state_directory.join("wallet");
        let sdk_path = spilman_client_store_path(&wallet);
        let history = PreparationHistory::capture(cfg).await;
        let keyset = mint.mint().rotate_keyset("sat".parse().unwrap(),
            (0..=10).map(|b| 1u64 << b).collect(), 500, false, None).await.unwrap().id;
        let before = history.clone();
        let owner = cfg.clone();
        let matched = Arc::new(Mutex::new(None));
        let captured_wire = matched.clone();
        let seen = Arc::new(AtomicUsize::new(0));
        let inspected = seen.clone();
        let (committed, release) = proxy.state.pause_matching_swap_reply(move |wire| {
            before.preparation_match(&owner, &captured_wire, &inspected, wire)
        });
        let owner = cfg.clone();
        let destination = npubs[3].clone();
        let mut buying = tokio::spawn(async move {
            request(&owner, &AdminRequest::Watch { destination, max_rate_msat_per_kib: 8192 }).await
        });
        let captured = tokio::select! {
            signal = committed => signal.is_ok(),
            _ = &mut buying => false,
            _ = tokio::time::sleep(Duration::from_secs(30)) => false,
        };
        if !captured {
            let _ = release.send(());
            let conserved = cleanup(&configs, &mut children, &proxy, Some(&history)).await;
            buying.abort();
            if !conserved { let _ = root.keep(); }
            panic!("second exact preparation boundary absent; conserved={conserved}");
        }
        children[0].kill().await.unwrap();
        assert!(!children[0].wait().await.unwrap().success());
        let _ = release.send(());
        buying.abort();
        let original = match history.inspect_next(cfg, &keyset.to_string(), &matched).await {
            Ok(original) => original,
            Err(error) => {
                let conserved = cleanup(&configs, &mut children, &proxy, Some(&history)).await;
                if !conserved { let _ = root.keep(); }
                panic!("second preparation identity: {error}; conserved={conserved}");
            }
        };
        let mut errors = Vec::new();
        let pending = &original.controller["watched_routes"][&npubs[3]]["pending"];
        let offer_id = pending["id"].as_str().unwrap().to_owned();
        let expiry = pending["expires_unix"].as_u64().unwrap();
        check(&mut errors, pending["provider"] == old.outgoing["purchase"]["provider"]
            && pending["destination"] != old.outgoing["offer"]["destination"]
            && original.controller["next_funding"].as_u64() == old.controller["next_funding"].as_u64().map(|n| n + 1),
            "new original intent was not the distinct authorized same-provider purchase");
        stop(&mut children[1]).await;
        while now() <= expiry { tokio::time::sleep(Duration::from_millis(100)).await; }
        children[0] = start(&paths[0]).await;
        let mut automatic = false;
        let mut fenced = false;
        let mut last_status = Value::Null;
        while now() <= original.request.expiry_unix + 30 {
            let current = journal(cfg);
            let sdk = read(&sdk_path);
            check(&mut errors, current["next_funding"] == original.controller["next_funding"]
                && entries(&current, "funding") == 2 && entries(&current, "outgoing") == 1
                && entries(&current, "watched_routes") == 2,
                "recovery created or removed original funding/route authority");
            check(&mut errors, history.same_channels(&sdk),
                "abandoned recovery created a channel or changed old SDK channel evidence");
            let intent = &current["funding"][&original.intent_id];
            check(&mut errors, funding_authority(intent) == original.intent && intent["funded"].is_null(),
                "recovery changed the second original funding authority");
            if let Ok(Ok(status)) = tokio::time::timeout(Duration::from_secs(2), request(cfg, &AdminRequest::Status)).await {
                check(&mut errors, old.preserved(cfg, &current, &status),
                    "refunded old selected-trial quota, signature or lifetime budget changed");
                let new_watch = &current["watched_routes"][&npubs[3]];
                let disconnected = status["peers"].as_array().unwrap().iter()
                    .all(|peer| peer["npub"] != npubs[1] || peer["connected"] != true);
                fenced |= disconnected && new_watch["paused"] == false && new_watch["pending"].is_null()
                    && current["recovery_only"].as_array().unwrap().iter().any(|id| id == &offer_id);
                if let Some((debit, refund)) = recovered(&original, &old, &current, &status) {
                    let budget = &old.status["funding_budget"];
                    let expected = 128 - budget["wallet_debited_sat"].as_u64().unwrap()
                        + budget["wallet_refunded_sat"].as_u64().unwrap() - debit + refund;
                    automatic = fenced && spendable_balance(&wallet, &proxy.url).await == expected;
                }
                last_status = status;
            }
            if automatic { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let sends = send_journal(&wallet).await;
        check(&mut errors, request_count(&sends) == request_count(&history.sends) + 1
            && sends["entries"][&original.send_id]["request"] == original.entry["request"]
            && sends["entries"][&original.send_id]["preparation"]["planned"] == original.entry["preparation"]["planned"],
            "recovery replaced the original wallet request or send plan");
        check(&mut errors, automatic,
            "refunded selected history pinned the other abandoned send; fixture cleanup is not recovery");
        eprintln!("terminal-history automatic={automatic} fenced={fenced} trial_used={} old_signed_sat={} remaining_budget_sat={} budget={} inspected_responses={}",
            old.buyer["quotes"][&old.contract]["observed_units"], old.buyer["channels"][&old.channel]["authorized_sat"],
            last_status["remaining_budget_sat"], last_status["funding_budget"], seen.load(Ordering::SeqCst));
        // The acceptance result is fixed before any cleanup-only administrative
        // action or the exact original-send revoke used to conserve failed runs.
        let conserved = cleanup(&configs, &mut children, &proxy, Some(&history)).await;
        check(&mut errors, conserved, "four-wallet test money and mint fees were not conserved");
        let final_state = journal(cfg);
        check(&mut errors, final_state["next_funding"] == original.controller["next_funding"],
            "cleanup allocated third funding");
        let final_sends = send_journal(&wallet).await;
        check(&mut errors, request_count(&final_sends) == request_count(&history.sends) + 1
            && final_sends["entries"][&original.send_id]["request"] == original.entry["request"]
            && final_sends["entries"][&original.send_id]["preparation"]["planned"] == original.entry["preparation"]["planned"],
            "cleanup replaced the original request or plan");
        for index in 1..4 {
            check(&mut errors, journal(&configs[index])["next_funding"] == initial[index]["next_funding"],
                "other daemons acquired unapproved funding");
        }
        if !conserved { let _ = root.keep(); }
        assert!(errors.is_empty(), "terminal selected-history recovery: {errors:?}");
    }).await.expect("bounded retained-trial process recovery and exact-operation cleanup");
}
