//! Spent incoming payout custody under ordinary transit forwarding and upkeep.
use super::*;
use cashu::nuts::State;
use cdk_common::database::WalletDatabase;
use std::collections::BTreeMap;

#[path = "receiver/custody.rs"]
mod custody;
#[path = "receiver/observation.rs"]
mod observation;
use custody::*;

const PAYOUT: usize = 959;
const RETIRED: usize = 28;
const GUARD_COINS: usize = 32;
const UNSPENT: usize = 31;
// Keep R's original 960-slot reservation while admitting an independent
// 64-slot payer. The payout still spans eight ordinary 128-proof release batches.
const SOURCE: usize = 4;
const TRANSIT_CAPACITY: u64 = 64;
const HELD_PACKETS: u32 = 64;
const ACTIVE_PACKETS: u32 = 432;
const PAYLOAD_BYTES: usize = 40;
const PACKET_RATE: u32 = 72;
const INITIAL: u64 = 3072;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "opt-in ordinary eight-batch spent receiver retirement with transit traffic"]
async fn spent_receiver_payout_retires_during_paid_forwarding() {
    tokio::time::timeout(Duration::from_secs(1200), exercise())
        .await
        .expect("bounded spent-payout scenario; preserve original failed evidence");
}

async fn mutate(
    bench: &setup::Bench,
    source: usize,
    action: AdminRequest,
    settlement: Option<&str>,
) -> Value {
    tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            let before = journal(&bench.configs[source]);
            if let Some(channel) = settlement {
                let original = &before["buyer_settlements"][channel];
                if original.is_object() {
                    if original["released"] == true && original["refunded"] == true {
                        return json!({"settlements": [original["report"]]});
                    }
                    // A failed aggregate Settle can already have started this
                    // channel. Ordinary upkeep resumes its original intent.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            }
            let history = &before["history"];
            if [
                &history["pending"],
                &history["channels"]["pending"],
                &history["seller"]["pending"],
            ]
            .iter()
            .any(|plan| !plan.is_null())
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            assert!(
                before["funding"]
                    .as_object()
                    .unwrap()
                    .values()
                    .all(|intent| intent["funded"].is_object()),
                "never retry unresolved original funding"
            );
            match request(&bench.configs[source], &action).await {
                Ok(response) => return response,
                Err(error) if error == HISTORY_PENDING => {
                    // Upkeep can start after the read. Retry only a refusal that
                    // allocated no funding; settlement effects are read above.
                    // Retirement may remove old funding records concurrently.
                    let after = journal(&bench.configs[source]);
                    for key in ["local", "epoch", "policy", "next_funding"] {
                        assert_eq!(after[key], before[key], "refused command changed {key}");
                    }
                    assert!(
                        after["funding"]
                            .as_object()
                            .unwrap()
                            .iter()
                            .all(|(id, intent)| before["funding"].get(id) == Some(intent)),
                        "refused command created or changed funding; preserve it without replay"
                    );
                    use std::io::Write;
                    let root = bench.paths[0].parent().unwrap().parent().unwrap();
                    let mut log = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(root.join("control-backpressure.jsonl"))
                        .unwrap();
                    writeln!(
                        log,
                        "{}",
                        json!({"source":source,"action":action,
                        "error":error,"before":before,"after":after})
                    )
                    .unwrap();
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => control_failed(bench, source, &error).await,
            }
        }
    })
    .await
    .expect("ordinary upkeep must permit or finish the original command")
}

async fn buy(bench: &setup::Bench, source: usize, sink: usize) -> String {
    mutate(
        bench,
        source,
        AdminRequest::Buy {
            destination: bench.npubs[sink].clone(),
        },
        None,
    )
    .await;
    let state = status(&bench.configs[source]).await;
    assert_eq!(state["purchases"].as_array().unwrap().len(), 1);
    state["purchases"][0]["channel"]["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn funding(bench: &setup::Bench, source: usize, channel: &str) -> (String, Value) {
    journal(&bench.configs[source])["funding"]
        .as_object()
        .unwrap()
        .iter()
        .find(|(_, value)| value["funded"]["terms"]["id"] == channel)
        .map(|(id, value)| (id.clone(), value.clone()))
        .unwrap()
}

async fn traffic(
    bench: &setup::Bench,
    source: usize,
    sink: usize,
    stream: &mut u64,
    count: u32,
    bytes: usize,
    rate: u32,
) -> Value {
    *stream += 1;
    let sending = probe_between(bench, source, sink, *stream, count, rate, bytes).await;
    delivered_to(bench, sink, sending, count).await
}

// The normal payment worker signs observed ciphertext bytes. Calibrate one
// genuine packet, then stop within the target satoshi's rounding interval.
async fn earn(
    bench: &setup::Bench,
    source: usize,
    sink: usize,
    channel: &str,
    target: u64,
    stream: &mut u64,
) {
    let current = |value: &Value| {
        value["payment_progress"][channel]["evidence_msat"]
            .as_u64()
            .unwrap()
    };
    let before = current(&status(&bench.configs[source]).await);
    traffic(bench, source, sink, stream, 1, 1000, 1).await;
    let mut state = caught_up(&bench.configs[source], channel).await;
    let unit = current(&state).checked_sub(before).unwrap();
    assert!(unit > 0);
    for _ in 0..100 {
        let evidence = current(&state);
        let signed = state["payment_progress"][channel]["authorized_sat"]
            .as_u64()
            .unwrap();
        assert!(signed <= target && evidence <= target * 1000);
        if signed == target {
            return;
        }
        let remaining = (target - 1) * 1000 + 1 - evidence;
        let count = (remaining / unit).min(1024) as u32;
        let (count, bytes) = if count == 0 { (1, 40) } else { (count, 1000) };
        traffic(bench, source, sink, stream, count, bytes, 128).await;
        state = caught_up(&bench.configs[source], channel).await;
    }
    panic!("ordinary traffic did not reach the exact paid amount");
}

async fn settle(bench: &setup::Bench, source: usize, channel: &str, paid: u64) {
    let response = mutate(bench, source, AdminRequest::Settle, Some(channel)).await;
    let reports = response["settlements"].as_array().unwrap();
    let report = reports.iter().find(|r| r["channel_id"] == channel).unwrap();
    assert_eq!(report["paid_sat"], paid);
    assert_eq!(report["fee_sat"], 0);
    assert_eq!(report["receiver_fee_reserve_sat"], 0);
}

async fn expired_prefix(bench: &setup::Bench, old: &BTreeSet<String>) {
    tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            let current = journal(&bench.configs[1]);
            if current["funding"]
                .as_object()
                .unwrap()
                .values()
                .all(|f| !old.contains(f["funded"]["terms"]["id"].as_str().unwrap()))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("ordinary upkeep must retire the original funding prefix");
}

async fn exercise() {
    let root = retained_tempdir();
    let network = PaymentNetwork::new(9631, 0, Arc::new(VirtualClock::new(now())));
    let mint = LocalMint::start_with_limits(
        root.path(),
        network.clone(),
        "spent-payout",
        IssuerMode::ClosedLoop,
        4096,
        4096,
    )
    .await
    .unwrap();
    mint.mint()
        .rotate_keyset("sat".parse().unwrap(), vec![1, 960, 1024], 0, false, None)
        .await
        .unwrap();
    let url = mint.url().to_owned();
    let mut bench = setup::start_funded_topology(
        root.path(),
        mint,
        network,
        &url,
        setup::LineConfig {
            lifetime: 120,
            quote_lifetime: 60,
            funding_limits: &[960, 1024, 32, 32, TRANSIT_CAPACITY],
        },
        &[2048, 0, 0, 0, 1024],
        &[(0, 1), (1, 2), (2, 3), (SOURCE, 1)],
        |index, cfg| {
            cfg.terms.billing = BillingBasis::ForwardingData;
            cfg.terms.controller.channel_capacity_sat = match index {
                0 | 1 => 960,
                SOURCE => TRANSIT_CAPACITY,
                _ => 32,
            };
            cfg.terms.controller.channel_lifetime_secs = if index == 0 { 720 } else { 120 };
            cfg.terms.controller.max_funding_overhead_sat = 0;
            cfg.terms.wallet_capacity_bytes = Some(NATIVE_LIMIT);
            cfg.terms.buyer_budget_sat = if index == 0 { 2048 } else { 1024 };
            cfg.terms.fee_msat_per_kib = match index {
                1 | 2 => 256, // Frequent whole-sat progress within the original channel budgets.
                _ => 32,
            };
            cfg.terms.max_rate_msat_per_kib = 2048;
            cfg.terms.quote_max_units = 4 * 1024 * 1024;
            if index == 1 {
                cfg.terms.window_msat = 64_000;
                cfg.terms.grace_msat = 64_000;
            }
            cfg.funding_request_budget = Some(FundingRequestBudget {
                burst: NonZeroU32::new(128).unwrap(),
                requests_per_minute: NonZeroU32::new(60_000).unwrap(),
            });
        },
    )
    .await;
    let wallet = bench.configs[1].state_directory.join("wallet");
    let db = cdk_sqlite::WalletSqliteDatabase::new(cashu_service::cashu_wallet_db_path(&wallet))
        .await
        .unwrap();
    assert!(records(&db).await.is_empty());
    let mut stream = 10_000;
    let incoming = buy(&bench, 0, 2).await;
    let (_, incoming_funding) = funding(&bench, 0, &incoming);
    assert_eq!(incoming_funding["capacity_sat"], 960);
    let deadline = incoming_funding["refund_after_unix"].as_u64().unwrap();
    earn(&bench, 0, 2, &incoming, PAYOUT as u64, &mut stream).await;
    settle(&bench, 0, &incoming, PAYOUT as u64).await;
    let originals = payout(&bench.configs[1], &incoming, &db).await;
    assert_eq!(originals.len(), PAYOUT);
    assert_eq!(originals.len().div_ceil(128), 8);
    assert!(
        originals
            .values()
            .all(|p| p.state == State::Unspent && p.proof.amount.to_u64() == 1)
    );
    assert!(
        records(&db).await == originals,
        "payout must be R's only funding"
    );
    let mut old = BTreeSet::new();
    let mut old_inputs = BTreeSet::new();
    let mut old_operations = BTreeSet::new();
    for _ in 0..2 {
        for _ in 0..RETIRED / 2 {
            let channel = buy(&bench, 1, 3).await;
            let (_, opened) = funding(&bench, 1, &channel);
            assert_eq!(opened["capacity_sat"], 32);
            let (inputs, operation) = original_inputs(&wallet, &opened).await;
            assert_eq!(inputs.len(), 32);
            for key in inputs {
                assert!(originals.contains_key(&key) && old_inputs.insert(key));
            }
            assert!(old_operations.insert(operation));
            earn(&bench, 1, 3, &channel, 32, &mut stream).await;
            settle(&bench, 1, &channel, 32).await;
            assert!(old.insert(channel));
            assert!(
                journal(&bench.configs[1])["funding"]
                    .as_object()
                    .unwrap()
                    .len()
                    <= 16
            );
        }
        expired_prefix(&bench, &old).await;
        released_sends(&db, &wallet, &old_operations).await;
        retained_originals(&db, &originals).await;
    }
    assert_eq!(old.len(), RETIRED);
    assert_eq!(old_inputs.len(), RETIRED * GUARD_COINS);
    assert!(
        now() < deadline - 40,
        "preparation must leave the original receiver owner intact"
    );
    wait_until(deadline - 30).await;
    let guard = buy(&bench, 1, 3).await;
    let (guard_request, guard_funding) = funding(&bench, 1, &guard);
    let guard_deadline = guard_funding["refund_after_unix"].as_u64().unwrap();
    let (guard_inputs, guard_operation) = original_inputs(&wallet, &guard_funding).await;
    assert_eq!(guard_inputs.len(), GUARD_COINS);
    assert!(guard_inputs.is_disjoint(&old_inputs));
    let before = retained_originals(&db, &originals).await;
    let unspent: BTreeSet<_> = before
        .iter()
        .filter(|(_, p)| p.state == State::Unspent)
        .map(|(y, _)| y.clone())
        .collect();
    assert_eq!(unspent.len(), UNSPENT);
    assert!(
        old_inputs
            .iter()
            .chain(&guard_inputs)
            .all(|y| before[y].state == State::Spent)
    );
    assert!(guard_inputs.iter().all(|key| originals.contains_key(key)));
    verify_mint(&bench, &before).await;
    assert_eq!(
        status(&bench.configs[1]).await["funding_budget"]["wallet_debited_sat"],
        (RETIRED + 1) * GUARD_COINS
    );
    let proof_slots = transit_slots(&db).await;
    let transit = buy(&bench, SOURCE, 3).await;
    let opening_bytes = transit_opening(&bench, &transit);
    assert_eq!(funding(&bench, 1, &guard).1, guard_funding);
    let before_warm = [
        status(&bench.configs[SOURCE]).await,
        status(&bench.configs[1]).await,
    ];
    traffic(&bench, SOURCE, 3, &mut stream, 1, PAYLOAD_BYTES, 1).await;
    let warm_a = caught_up(&bench.configs[SOURCE], &transit).await;
    let warm_r = caught_up(&bench.configs[1], &guard).await;
    let exposure = transit_exposure(
        &before_warm,
        [&warm_a, &warm_r],
        [&warm_a, &warm_r],
        [&transit, &guard],
        HELD_PACKETS + ACTIVE_PACKETS,
    );
    let history_size = history_size(&db, &wallet).await;
    let original_sale = journal(&bench.configs[1])["seller_settlements"][&incoming].clone();
    assert!(original_sale["released"] == true && original_sale["report"].is_object());
    let mut measured = observation::Window::new(bench.children[1].id().unwrap());
    let mut writer = hold_wallet_writer(&wallet).await;
    assert!(
        now() < deadline,
        "hold the writer before receiver retirement becomes eligible"
    );
    wait_until(deadline + 3).await;
    // Opening the wallet can need a write transaction before preparation saves
    // its retirement plan. The held writer must preserve the eligible original,
    // not force the controller to persist an unverified plan.
    let eligible = journal(&bench.configs[1]);
    assert_eq!(eligible["seller_settlements"][&incoming], original_sale);
    assert!(
        eligible["incoming"]
            .as_object()
            .unwrap()
            .values()
            .all(|route| route["channel"]["id"] != incoming)
    );
    let held_originals = payout(&bench.configs[1], &incoming, &db).await;
    assert!(held_originals == before);
    let warm_credit = [credit(&bench, 1, &transit), credit(&bench, 2, &guard)];
    let held = traffic(
        &bench,
        SOURCE,
        3,
        &mut stream,
        HELD_PACKETS,
        PAYLOAD_BYTES,
        PACKET_RATE,
    )
    .await;
    let held_a = caught_up(&bench.configs[SOURCE], &transit).await;
    let held_r = caught_up(&bench.configs[1], &guard).await;
    assert_eq!(
        journal(&bench.configs[1])["seller_settlements"][&incoming],
        original_sale,
        "paid progress must preserve the same eligible original settlement"
    );
    assert!(payout(&bench.configs[1], &incoming, &db).await == held_originals);
    for (warm, held, channel, seller) in [
        (&warm_a, &held_a, &transit, 1),
        (&warm_r, &held_r, &guard, 2),
    ] {
        assert!(
            held["payment_progress"][channel]["authorized_sat"]
                .as_u64()
                .unwrap()
                > warm["payment_progress"][channel]["authorized_sat"]
                    .as_u64()
                    .unwrap()
        );
        assert!(credit(&bench, seller, channel) > warm_credit[seller - 1]);
    }
    let live_exposure = transit_exposure(
        &before_warm,
        [&warm_a, &warm_r],
        [&held_a, &held_r],
        [&transit, &guard],
        ACTIVE_PACKETS,
    );
    let credit_before = [credit(&bench, 1, &transit), credit(&bench, 2, &guard)];
    measured.sample();
    let progress_baseline = json!({"elapsed_us":measured.elapsed_us(),"delivered":0,
        "credits":credit_before,"payments":[held_a["payment_progress"][&transit],
            held_r["payment_progress"][&guard]]});
    stream += 1;
    let sending = probe_between(
        &bench,
        SOURCE,
        3,
        stream,
        ACTIVE_PACKETS,
        PACKET_RATE,
        PAYLOAD_BYTES,
    )
    .await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while status(&bench.configs[3]).await["probe"]["unique_packets"]
            .as_u64()
            .unwrap()
            == 0
        {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("transit stream must be active before maintenance resumes");
    measured.release();
    drop(writer.stdin.take());
    assert!(writer.wait().await.unwrap().success());
    let mut samples = Vec::new();
    let mut resources = None;
    let mut cleanup_finished_us = None;
    let mut traffic_finished_us = None;
    let mut payments_finished = false;
    tokio::time::timeout(Duration::from_secs(35), async {
        loop {
            if resources.is_none() {
                measured.sample();
            }
            let j = journal(&bench.configs[1]);
            let remaining = original_subset(&db, &originals).await;
            assert_eq!(j["funding"][&guard_request], guard_funding);
            for key in guard_inputs.iter().chain(&unspent) {
                assert!(
                    remaining[key] == before[key],
                    "collection changed an original still owned by guard or spendable balance"
                );
            }
            let cleanup_pending = j["seller_settlements"][&incoming].is_object()
                || remaining.len() != GUARD_COINS + UNSPENT;
            if !payments_finished {
                let delivered = status(&bench.configs[3]).await["probe"]["unique_packets"]
                    .as_u64()
                    .unwrap();
                let payments = [
                    status(&bench.configs[SOURCE]).await["payment_progress"][&transit].clone(),
                    status(&bench.configs[1]).await["payment_progress"][&guard].clone(),
                ];
                let credits = [credit(&bench, 1, &transit), credit(&bench, 2, &guard)];
                let elapsed = measured.elapsed_us();
                if delivered == u64::from(ACTIVE_PACKETS) {
                    traffic_finished_us.get_or_insert(elapsed);
                    payments_finished = payments.iter().all(payment_caught_up);
                }
                samples.push(json!({"elapsed_us":elapsed,
                    "receiver_retained":j["seller_settlements"][&incoming].is_object(),
                    "cleanup_pending":cleanup_pending,"remaining_originals":remaining.len(),
                    "delivered":delivered,"credits":credits,"payments":payments}));
            }
            if !cleanup_pending && resources.is_none() {
                cleanup_finished_us = Some(measured.elapsed_us());
                resources = Some(measured.finish());
            }
            if !cleanup_pending && payments_finished {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("whole receiver retirement must finish while the original outgoing guard is active");
    let resources = resources.unwrap();
    // Preserve the 500-ms cadence and financial terms. The two-second bound is
    // an acceptance limit for observed progress under this paced workload.
    let mut progress = observation::progress(&progress_baseline, &samples, 2_000_000);
    let cleanup_finished_us = cleanup_finished_us.unwrap();
    let traffic_finished_us = traffic_finished_us.unwrap();
    progress["cleanup_finished_us"] = json!(cleanup_finished_us);
    progress["traffic_finished_us"] = json!(traffic_finished_us);
    progress["traffic_covers_cleanup"] = json!(cleanup_finished_us <= traffic_finished_us);
    let live = delivered_to(&bench, 3, sending, ACTIVE_PACKETS).await;
    let after_a = caught_up(&bench.configs[SOURCE], &transit).await;
    let after_r = caught_up(&bench.configs[1], &guard).await;
    for (before_state, after_state, channel, seller) in [
        (&held_a, &after_a, &transit, 1),
        (&held_r, &after_r, &guard, 2),
    ] {
        assert!(
            after_state["payment_progress"][channel]["authorized_sat"]
                .as_u64()
                .unwrap()
                > before_state["payment_progress"][channel]["authorized_sat"]
                    .as_u64()
                    .unwrap()
        );
        assert!(credit(&bench, seller, channel) > credit_before[seller - 1]);
    }
    let overlap = samples.windows(2).any(|w| {
        w[0]["receiver_retained"] == true
            && w[1]["delivered"].as_u64().unwrap() > w[0]["delivered"].as_u64().unwrap()
            && w[1]["credits"][1].as_u64().unwrap() > w[0]["credits"][1].as_u64().unwrap()
    });
    let mut result = json!({"profile":{"originals":PAYOUT,"release_batches":PAYOUT.div_ceil(128),"released_spent":RETIRED*GUARD_COINS,
        "guard_spent":GUARD_COINS,"retained_unspent":UNSPENT,"initial_sat":INITIAL,
        "held_packets":HELD_PACKETS,"live_packets":ACTIVE_PACKETS,"payload_bytes":PAYLOAD_BYTES,
        "packets_per_second":PACKET_RATE},"history_size":history_size,
        "proof_slots_before_transit":proof_slots,"transit_opening_bytes":opening_bytes,"exposure":exposure,"live_exposure":live_exposure,
        "resources":resources,"held_probe":held,"live_probe":live,"samples":samples,
        "progress_baseline":progress_baseline,"progress":progress,
        "held_progress":{"warm":[warm_a["payment_progress"][&transit],warm_r["payment_progress"][&guard]],
            "held":[held_a["payment_progress"][&transit],held_r["payment_progress"][&guard]],
            "warm_credit":warm_credit,"held_credit":credit_before,
            "eligible_original_preserved_during_wallet_hold":true,
            "retirement_plan_observed_during_wallet_hold":eligible["history"]["seller"]["pending"].is_object()},
        "progress_observed_during_retirement":overlap,"guard_operation":guard_operation,
        "final_progress":[after_a["payment_progress"][&transit],after_r["payment_progress"][&guard]]});
    save(root.path(), &result);
    // Finish the original financial obligations even if the progress observation
    // failed. A fast cleanup may have no interior payment sample; keep that fact
    // separate from the bounded-progress check across the complete traffic window.
    for (source, channel, progress) in [(SOURCE, &transit, &after_a), (1, &guard, &after_r)] {
        settle(
            &bench,
            source,
            channel,
            progress["payment_progress"][channel]["authorized_sat"]
                .as_u64()
                .unwrap(),
        )
        .await;
    }
    wait_until(guard_deadline + 1).await;
    expired_prefix(&bench, &BTreeSet::from([guard.clone()])).await;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let remaining = original_subset(&db, &originals).await;
            if remaining.keys().cloned().collect::<BTreeSet<_>>() == unspent {
                for key in &unspent {
                    assert!(remaining[key] == before[key], "unspent original changed");
                }
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("ordinary guard retirement must release its exact original payout inputs");
    old_operations.insert(guard_operation);
    released_sends(&db, &wallet, &old_operations).await;
    for child in &mut bench.children {
        stop(child).await;
    }
    setup::verify_settled_wallets(&bench, &url, INITIAL).await;
    result["conserved_sat"] = json!(INITIAL);
    result["final_original_unspent"] = json!(UNSPENT);
    save(root.path(), &result);
    for field in [
        "all_counters_advanced",
        "within_limit",
        "traffic_covers_cleanup",
    ] {
        assert_eq!(
            result["progress"][field], true,
            "failed live progress observation: {field}"
        );
    }
}

fn save(root: &Path, value: &Value) {
    std::fs::write(
        root.join("spent-payout.json"),
        serde_json::to_vec_pretty(value).unwrap(),
    )
    .unwrap();
}
