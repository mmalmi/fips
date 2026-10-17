//! Renewal keeps its original intent across a delayed, lost committed mint reply.
use super::restore::{read, wait_journal};
use super::*;
use fips_relay::{
    controller::RenewalPolicy,
    probe::{ReceiveProbe, SendProbe},
    service::ServiceConfig,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{path::Path, sync::atomic::Ordering};

#[derive(Clone, Copy)]
enum Boundary {
    Capacity,
    Quote,
    Channel,
    AdmissionWait,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delayed_lost_mint_close_reply_renews_once_and_keeps_other_buyers_paid() {
    exercise(Boundary::Capacity).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn near_expiry_mint_close_rejects_stale_forwarding_and_renews_once() {
    exercise(Boundary::Quote).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_committed_mint_close_recovers_after_channel_refund_deadline() {
    exercise(Boundary::Channel).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_renewal_expires_unbilled_originals_and_delivers_fresh_waiters_once() {
    exercise(Boundary::AdmissionWait).await;
}

async fn exercise(boundary: Boundary) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().to_owned();
    let result = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(240), scenario(&path, boundary))
            .await
            .expect("bounded delayed-mint renewal recovery");
    })
    .await;
    if let Err(error) = result {
        panic!(
            "{error}; retained failed fixture at {}",
            root.keep().display()
        );
    }
}

async fn scenario(root: &Path, boundary: Boundary) {
    let near_expiry = matches!(boundary, Boundary::Quote | Boundary::Channel);
    let (mint, network) = setup::start_mint(root, 9631).await;
    let proxy = MintProxy::start(mint.url()).await;
    let setup::Bench {
        mint: _mint,
        configs,
        paths,
        npubs,
        mut children,
    } = setup::start_configured_line(
        root,
        mint,
        network,
        &proxy.url,
        setup::LineConfig {
            lifetime: 600,
            quote_lifetime: if matches!(boundary, Boundary::Quote) {
                30
            } else {
                300
            },
            funding_limits: &[80, 40, 40],
        },
        |index, config| {
            if matches!(boundary, Boundary::AdmissionWait) {
                config.terms.billing = fips_relay::ledger::BillingBasis::ForwardingData;
            }
            if index == 0 {
                if matches!(boundary, Boundary::Channel) {
                    config.terms.controller.channel_lifetime_secs = 60;
                }
                config.terms.controller.max_locked_sat = 40;
                config.terms.controller.max_funding_overhead_sat = 8;
                config.terms.controller.renewal = Some(RenewalPolicy {
                    at_capacity_percent: if near_expiry { 100 } else { 25 },
                    before_expiry_secs: if near_expiry { 8 } else { 30 },
                });
            }
        },
    )
    .await;
    request(&configs[0], &AdminRequest::PauseRenewals)
        .await
        .unwrap();
    for (source, destination) in [(0, 2), (2, 0)] {
        request(
            &configs[source],
            &AdminRequest::Buy {
                destination: npubs[destination].clone(),
            },
        )
        .await
        .unwrap();
    }
    for round in 0..10 {
        send(&configs, &npubs, 0, round).await;
    }
    let journal = configs[0]
        .state_directory
        .join("controller/controller.json");
    let seller_journal = configs[1]
        .state_directory
        .join("controller/controller.json");
    let before = read(&journal);
    let funding = before["funding"].as_object().unwrap();
    assert_eq!(funding.len(), 1);
    let (funding_id, original) = funding.iter().next().unwrap();
    let id = original["funded"]["terms"]["id"].as_str().unwrap();
    let status = request(&configs[0], &AdminRequest::Status).await.unwrap();
    let expiry = status["purchases"][0]["contract"]["expires_unix"]
        .as_u64()
        .unwrap();
    let refund_deadline = if matches!(boundary, Boundary::Channel) {
        assert_eq!(expiry, original["expires_unix"].as_u64().unwrap());
        let refund = original["refund_after_unix"].as_u64().unwrap();
        let outgoing = before["outgoing"].as_object().unwrap();
        assert!(
            outgoing
                .values()
                .all(|old| { old["offer"]["expires_unix"].as_u64().unwrap() > refund })
        );
        Some(refund)
    } else {
        None
    };
    let reverse = request(&configs[2], &AdminRequest::Status).await.unwrap();
    let reverse_id = reverse["purchases"][0]["channel"]["id"].as_str().unwrap();
    let reverse_before = usage(&configs[1], reverse_id);
    let swaps_before = proxy.state.swaps.load(Ordering::SeqCst);
    let (committed, release) =
        setup::pause_channel_close(&proxy, &configs[0].state_directory.join("wallet"), id);
    request(&configs[0], &AdminRequest::ResumeRenewals)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), committed)
        .await
        .expect("original mint close must commit")
        .unwrap();
    let held_at = tokio::time::Instant::now();
    if near_expiry {
        assert!(restore::now() < expiry && restore::now() + 8 >= expiry);
        assert!(
            status["payment_progress"][id]["authorized_sat"]
                .as_u64()
                .unwrap()
                < 32
        );
        assert!(usage(&configs[1], id).0 < configs[1].terms.quote_max_units);
    }
    // A different buyer needs no new mint funds to keep forwarding and paying.
    send(&configs, &npubs, 2, 100).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !new_usage_paid(&configs[1], reverse_id, reverse_before, 1) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("held mint close cannot stall another buyer's payment");
    // Restart needs paid session replies; keep that reverse channel until final
    // settlement. Other cases also check independent settlement while held.
    if !matches!(boundary, Boundary::Channel) {
        tokio::time::timeout(
            Duration::from_secs(10),
            request(&configs[2], &AdminRequest::Settle),
        )
        .await
        .expect("held mint close cannot stall another buyer's settlement")
        .unwrap();
    }
    if matches!(boundary, Boundary::AdmissionWait) {
        admission_cohorts(&configs, &npubs, id).await;
    } else {
        tokio::time::sleep_until(held_at + Duration::from_secs(7)).await;
    }
    let expired_probe = if near_expiry {
        while restore::now() <= expiry {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let received =
            request(&configs[2], &AdminRequest::Status).await.unwrap()["received"]["packets"]
                .as_u64()
                .unwrap();
        // Native datagrams do not promise delivery through a long policy hold.
        // An expired grant must reject this original, including after renewal.
        request(
            &configs[0],
            &AdminRequest::Send {
                destination: npubs[2].clone(),
                payload: "expired-renewal-original".into(),
            },
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(
            request(&configs[2], &AdminRequest::Status).await.unwrap()["received"]["packets"],
            received
        );
        Some(received)
    } else {
        None
    };
    assert!(
        !release.is_closed(),
        "the committed response must remain held"
    );
    assert_eq!(
        proxy.state.swaps.load(Ordering::SeqCst),
        swaps_before + 1 + usize::from(!matches!(boundary, Boundary::Channel)),
        "only the requested closes reach the mint while held"
    );
    let pending = read(&journal);
    assert_eq!(pending["renewals"][id]["completed"], false);
    assert!(read(&seller_journal)["seller_settlements"][id]["report"].is_null());
    assert_eq!(pending["funding"], before["funding"]);
    assert_eq!(pending["next_funding"], before["next_funding"]);
    // Keep the admission-wait case within one live renewal operation. A lost
    // reply ends that operation's pause before retrying; closed grants reject
    // waiting originals during that gap, even if their queue age is still valid.
    proxy.state.lose_swap_reply.store(
        !matches!(boundary, Boundary::AdmissionWait | Boundary::Channel),
        Ordering::SeqCst,
    );
    // Lose both peers after the mint committed, before either saved a report.
    // The original live mint retains its spend records and payment-network state.
    if matches!(boundary, Boundary::Channel) {
        for index in [0, 1] {
            children[index].kill().await.unwrap();
            assert!(!children[index].wait().await.unwrap().success());
            std::fs::rename(
                paths[index].with_extension("log"),
                paths[index].with_extension("before-restart.log"),
            )
            .unwrap();
        }
        assert!(read(&journal)["buyer_settlements"][id]["report"].is_null());
        assert!(read(&seller_journal)["seller_settlements"][id]["report"].is_null());
        // Keep the peers offline until the refund deadline. Keeping them alive
        // here would let the HTTP timeout retry/restore the committed close,
        // save its report and activate a successor before the intended crash.
        while restore::now() <= refund_deadline.unwrap() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    let released_at = tokio::time::Instant::now();
    if matches!(boundary, Boundary::Channel) {
        // The disconnected HTTP request may already have dropped its barrier.
        let _ = release.send(());
        for index in [0, 1] {
            children[index] = start(&paths[index]).await;
        }
        ready(&configs, &paths, &npubs, &mut children).await;
    } else {
        release.send(()).unwrap();
    }
    // Quote retirement may remove the completed intent before this reader sees
    // it. Retained buyer history survives that same validated transition.
    let renewed = wait_journal(&journal, 60, |j| {
        j["buyer_settlements"][id]["refunded"] == true
            && (j["renewals"][id]["completed"] == true
                || (j["renewals"][id].is_null()
                    && j["history"]["buyers"]
                        .as_array()
                        .is_some_and(|ids| ids.iter().any(|saved| saved == id))))
    })
    .await;
    if matches!(boundary, Boundary::AdmissionWait) {
        eprintln!(
            "renewal admission release to completion: {} ms",
            released_at.elapsed().as_millis()
        );
    }
    request(&configs[0], &AdminRequest::PauseRenewals)
        .await
        .unwrap();
    assert!(!proxy.state.lose_swap_reply.load(Ordering::SeqCst));
    assert_eq!(renewed["policy"], before["policy"]);
    assert_eq!(renewed["funding"][funding_id], *original);
    assert_eq!(renewed["funding"].as_object().unwrap().len(), 2);
    assert_eq!(
        renewed["next_funding"].as_u64().unwrap(),
        before["next_funding"].as_u64().unwrap() + 1
    );
    assert_eq!(renewed["buyer_settlements"][id]["refunded"], true);
    if matches!(boundary, Boundary::Channel) {
        // Expiry refunds are terminal without a cooperative report or receipt.
        // Independently recovered seller proceeds must match the wallet refund.
        let refund = &renewed["buyer_settlements"][id];
        assert_eq!(refund["kind"], "expiry");
        let closed = wait_journal(&seller_journal, 10, |j| {
            j["seller_settlements"][id]["report"].is_object()
        })
        .await;
        let report = &closed["seller_settlements"][id]["report"];
        assert_eq!(report["refunded_sat"], refund["wallet_refund_sat"]);
        assert_eq!(report["signed_sat"], refund["payment"]["balance"]);
    } else {
        // Report cleanup is retried independently after replacement credit resumes.
        let released = wait_journal(&journal, 10, |j| {
            j["buyer_settlements"][id]["released"] == true
        })
        .await;
        let refund = &released["buyer_settlements"][id];
        assert_eq!(refund["refunded"], true);
        assert_eq!(refund["released"], true);
        let closed = read(&seller_journal);
        assert_eq!(closed["seller_settlements"][id]["report"], refund["report"]);
        assert_eq!(closed["seller_settlements"][id]["released"], true);
    }
    let after = request(&configs[0], &AdminRequest::Status).await.unwrap();
    assert_eq!(after["purchases"].as_array().unwrap().len(), 1);
    let replacement = after["purchases"][0]["channel"]["id"].as_str().unwrap();
    assert_ne!(replacement, id);
    assert_eq!(after["funding_budget"]["pending_reserved_sat"], 0);
    assert!(after["funding_budget"]["locked_sat"].as_u64().unwrap() <= 40);
    assert!(
        after["funding_budget"]["wallet_debited_sat"]
            .as_u64()
            .unwrap()
            <= 80
    );
    assert!(
        after["remaining_budget_sat"].as_u64().unwrap()
            <= status["remaining_budget_sat"].as_u64().unwrap()
    );
    let admission_report = if matches!(boundary, Boundary::AdmissionWait) {
        // Keep observing after renewal so expired originals cannot arrive late
        // or disappear from the fresh receiver's ignored-packet accounting.
        tokio::time::sleep(Duration::from_secs(3)).await;
        let probe = request(&configs[2], &AdminRequest::Status).await.unwrap()["probe"].clone();
        Some(probe)
    } else {
        None
    };
    let before_usage = usage(&configs[1], replacement);
    let mut fresh_bytes = send(&configs, &npubs, 0, 101).await;
    let first_send = request(&configs[0], &AdminRequest::Status).await.unwrap();
    // A single small payload can fit within an already rounded sat of credit.
    // Two payloads exceed that rounding allowance without forcing a payment.
    fresh_bytes += send(&configs, &npubs, 0, 102).await;
    let price: fips_relay::ledger::BytePrice =
        serde_json::from_value(after["purchases"][0]["contract"]["price"].clone()).unwrap();
    assert_eq!(
        price.msat, price.per_bytes,
        "fixture costs one msat per byte"
    );
    let minimum_new_msat = price.amount_due_msat(fresh_bytes).unwrap();
    let payment = tokio::time::timeout(Duration::from_secs(5), async {
        while !new_usage_paid(&configs[1], replacement, before_usage, minimum_new_msat) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let paid_usage = usage(&configs[1], replacement);
    let progress = request(&configs[0], &AdminRequest::Status).await.unwrap();
    eprintln!(
        "replacement payment: before={before_usage:?} minimum_new_msat={minimum_new_msat} first_send_evidence={} after={paid_usage:?} progress={} error={}",
        first_send["payment_progress"][replacement]["evidence_msat"],
        progress["payment_progress"][replacement],
        progress["last_error"]
    );
    if let Some(received) = expired_probe {
        assert_eq!(
            request(&configs[2], &AdminRequest::Status).await.unwrap()["received"]["packets"],
            received + 2,
            "only the fresh replacement payloads arrive"
        );
    }
    for config in &configs {
        request(config, &AdminRequest::Settle).await.unwrap();
        let status = request(config, &AdminRequest::Status).await.unwrap();
        assert_eq!(status["funding_budget"]["locked_sat"], 0);
        assert_eq!(status["funding_budget"]["pending_reserved_sat"], 0);
    }
    for child in &mut children {
        stop(child).await;
    }
    let final_state = read(&journal);
    assert_eq!(final_state["funding"], renewed["funding"]);
    assert_eq!(final_state["next_funding"], renewed["next_funding"]);
    let mut available = 0;
    for config in &configs {
        available += load_mint_balance(&config.state_directory.join("wallet"), &proxy.url)
            .await
            .unwrap()
            .balance_sat;
    }
    assert_eq!(
        available + proxy.state.fees_collected.load(Ordering::SeqCst),
        384
    );
    if let Some(probe) = admission_report {
        assert_eq!(probe["unique_packets"], 16);
        assert_eq!(probe["unique_bytes"], 16 * 80);
        for field in [
            "missing_packets",
            "duplicate_packets",
            "invalid_packets",
            "ignored_packets",
        ] {
            assert_eq!(probe[field], 0, "fresh cohort: {field}");
        }
        eprintln!(
            "renewal admission boundary: 16 expired originals unbilled; 16 fresh waiters delivered once"
        );
    }
    eprintln!(
        "Delayed/lost committed mint reply: one replacement, other buyer paid, all 384 test sats accounted for"
    );
    assert!(payment.is_ok(), "replacement must resume automatic payment");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delayed_successor_funding_keeps_original_forwarding_and_paying() {
    exercise_prefunding(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_successor_funding_recovers_one_original_operation() {
    exercise_prefunding(true).await;
}

async fn exercise_prefunding(restart: bool) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().to_owned();
    let result = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(180),
            prefunding_scenario(&path, restart),
        )
        .await
        .expect("bounded successor preopening");
    })
    .await;
    if let Err(error) = result {
        panic!(
            "{error}; retained failed fixture at {}",
            root.keep().display()
        );
    }
}

async fn prefunding_scenario(root: &Path, restart: bool) {
    use super::preopening_support::{PreparationHistory, cleanup_wallet_sends};
    use std::sync::{Mutex, atomic::AtomicUsize};
    let (mint, network) = setup::start_mint(root, 9632).await;
    let proxy = MintProxy::start(mint.url()).await;
    let setup::Bench {
        mint,
        configs,
        paths,
        npubs,
        mut children,
        ..
    } = setup::start_configured_line(
        root,
        mint,
        network,
        &proxy.url,
        setup::LineConfig {
            lifetime: 600,
            quote_lifetime: 300,
            funding_limits: &[96, 40, 40],
        },
        |index, config| {
            if index == 0 {
                // Match the existing forced-exchange fixture: two channels with
                // at most 48 sats each, including their explicitly allowed fees.
                config.terms.controller.max_locked_sat = 96;
                config.terms.controller.max_funding_overhead_sat = 16;
                config.terms.controller.renewal = Some(RenewalPolicy {
                    at_capacity_percent: 25,
                    before_expiry_secs: 30,
                });
            }
        },
    )
    .await;
    request(&configs[0], &AdminRequest::PauseRenewals)
        .await
        .unwrap();
    for (source, destination) in [(0, 2), (2, 0)] {
        request(
            &configs[source],
            &AdminRequest::Buy {
                destination: npubs[destination].clone(),
            },
        )
        .await
        .unwrap();
    }
    for round in 0..10 {
        send(&configs, &npubs, 0, round).await;
    }
    let journal = configs[0]
        .state_directory
        .join("controller/controller.json");
    let before = read(&journal);
    let (funding_id, original) = before["funding"]
        .as_object()
        .unwrap()
        .iter()
        .next()
        .unwrap();
    let channel = original["funded"]["terms"]["id"].as_str().unwrap();
    let history = PreparationHistory::capture(&configs[0]).await;
    // Guarantee a preparation swap even if the wallet's denominations would
    // otherwise fit. Only the test mint changes keyset; its fee policy remains.
    mint.mint()
        .rotate_keyset(
            "sat".parse().unwrap(),
            (0..=10).map(|b| 1u64 << b).collect(),
            500,
            false,
            None,
        )
        .await
        .unwrap();
    let matched = Arc::new(Mutex::new(None));
    let seen = Arc::new(AtomicUsize::new(0));
    let cfg = configs[0].clone();
    let (capture, inspected) = (matched.clone(), seen.clone());
    let (reached, release) = proxy.state.pause_matching_swap_reply(move |request| {
        history.preparation_match(&cfg, &capture, &inspected, request)
    });
    request(&configs[0], &AdminRequest::ResumeRenewals)
        .await
        .unwrap();
    if !matches!(
        tokio::time::timeout(Duration::from_secs(30), reached).await,
        Ok(Ok(()))
    ) {
        let _ = release.send(());
        cleanup_wallet_sends(&configs, &mut children, &proxy).await;
        panic!("successor must reach its own committed preparation before old settlement");
    }
    let pending = read(&journal);
    let intact = pending["funding"][funding_id] == *original
        && pending["buyer_settlements"].as_object().unwrap().is_empty()
        && pending["outgoing"] == before["outgoing"]
        && pending["requested"] == before["requested"]
        && pending["funding"].as_object().unwrap().len() == 2
        && pending["renewals"][channel]["preopening"]["funding_id"].is_string();
    let held_usage = usage(&configs[1], channel);
    let bytes = send(&configs, &npubs, 0, 100).await + send(&configs, &npubs, 0, 101).await;
    let old_paid = tokio::time::timeout(Duration::from_secs(5), async {
        while !new_usage_paid(&configs[1], channel, held_usage, bytes) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    send(&configs, &npubs, 2, 100).await;
    let still_unsettled = read(&journal)["buyer_settlements"]
        .as_object()
        .unwrap()
        .is_empty();
    if restart {
        children[0].kill().await.unwrap();
        assert!(!children[0].wait().await.unwrap().success());
    }
    let _ = release.send(());
    if restart {
        children[0] = start(&paths[0]).await;
        ready(&configs, &paths, &npubs, &mut children).await;
    }
    let renewed = wait_journal(&journal, 30, |j| {
        j["renewals"][channel]["completed"] == true
    })
    .await;
    request(&configs[0], &AdminRequest::PauseRenewals)
        .await
        .unwrap();
    let status = request(&configs[0], &AdminRequest::Status).await.unwrap();
    let successor = status["purchases"][0]["channel"]["id"].as_str().unwrap();
    let successor_usage = usage(&configs[1], successor);
    let fresh = send(&configs, &npubs, 0, 102).await + send(&configs, &npubs, 0, 103).await;
    let new_paid = tokio::time::timeout(Duration::from_secs(5), async {
        while !new_usage_paid(&configs[1], successor, successor_usage, fresh) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    for cfg in &configs {
        request(cfg, &AdminRequest::Settle).await.unwrap();
    }
    for child in &mut children {
        stop(child).await;
    }
    let mut available = 0;
    for cfg in &configs {
        available += load_mint_balance(&cfg.state_directory.join("wallet"), &proxy.url)
            .await
            .unwrap()
            .balance_sat;
    }
    assert_eq!(
        available + proxy.state.fees_collected.load(Ordering::SeqCst),
        384
    );
    eprintln!(
        "Successor preopening: restart={restart}; old traffic delivered and paid while mint reply held; all 384 test sats accounted for"
    );
    assert!(
        intact && still_unsettled,
        "funding preparation preserves old authorization"
    );
    assert!(
        old_paid.is_ok() && new_paid.is_ok(),
        "both original and successor pay automatically"
    );
    assert_eq!(renewed["funding"].as_object().unwrap().len(), 2);
    assert_eq!(
        renewed["next_funding"].as_u64().unwrap(),
        before["next_funding"].as_u64().unwrap() + 1
    );
    assert_eq!(renewed["funding"][funding_id], *original);
}

async fn admission_cohorts(configs: &[ServiceConfig], npubs: &[String], channel: &str) {
    let path = configs[0].state_directory.join("buyer/buyer.json");
    let before = read(&path);
    let sealed = usage(&configs[1], channel);
    for cohort in 0..2 {
        let stream_id = format!("{cohort:032x}");
        request(
            &configs[2],
            &AdminRequest::ReceiveProbe {
                probe: ReceiveProbe {
                    source: npubs[0].clone(),
                    stream_id: stream_id.clone(),
                    packet_count: 16,
                    payload_bytes: 80,
                    lifetime_secs: None,
                    measure_one_way_latency: false,
                    reflect: false,
                },
            },
        )
        .await
        .unwrap();
        let sent = request(
            &configs[0],
            &AdminRequest::SendProbe {
                probe: SendProbe {
                    destination: npubs[2].clone(),
                    stream_id,
                    packet_count: 16,
                    payload_bytes: 80,
                    packets_per_second: 140,
                    max_duration_secs: None,
                    measure_round_trip: false,
                },
            },
        )
        .await
        .unwrap();
        assert_eq!(sent["probe"]["submitted_packets"], 16);
        assert!(sent["probe"]["stopped_reason"].is_null());
        if cohort == 0 {
            // The ordinary source queue owns originals for at most two seconds.
            // Keep the grant valid and release no mint response during this wait.
            tokio::time::sleep(Duration::from_millis(2500)).await;
        }
        let probe = request(&configs[2], &AdminRequest::Status).await.unwrap()["probe"].clone();
        assert_eq!(
            probe["unique_packets"], 0,
            "no delivery before replacement acceptance"
        );
        assert_eq!(probe["missing_packets"], 16);
        let after = read(&path);
        assert_eq!(
            after["channels"][channel]["authorized_sat"],
            before["channels"][channel]["authorized_sat"]
        );
        for (id, quote) in before["quotes"].as_object().unwrap() {
            for field in ["observed_units", "submitted_units"] {
                assert_eq!(
                    after["quotes"][id][field], quote[field],
                    "held originals are unbilled"
                );
            }
        }
        assert_eq!(usage(&configs[1], channel), sealed);
    }
}

fn usage(config: &ServiceConfig, channel: &str) -> (u64, u64) {
    let ledger = read(&config.state_directory.join("seller/ledger.json"));
    let usage = &ledger["ledger"]["channels"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["terms"]["id"] == channel)
        .unwrap()["usage"];
    (
        usage["submitted_msat"].as_u64().unwrap(),
        usage["paid_msat"].as_u64().unwrap(),
    )
}

fn new_usage_paid(
    config: &ServiceConfig,
    channel: &str,
    before: (u64, u64),
    minimum_new_msat: u64,
) -> bool {
    let (submitted, paid) = usage(config, channel);
    submitted >= before.0 + minimum_new_msat && paid > before.1 && paid >= submitted
}

async fn send(configs: &[ServiceConfig], npubs: &[String], source: usize, round: u8) -> u64 {
    let destination = 2 - source;
    let payload = format!("renewal-mint-loss-{source}-{round}:{}", "x".repeat(700));
    let bytes = payload.len() as u64;
    let digest = format!("{:x}", Sha256::digest(payload.as_bytes()));
    request(
        &configs[source],
        &AdminRequest::Send {
            destination: npubs[destination].clone(),
            payload,
        },
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status: Value = request(&configs[destination], &AdminRequest::Status)
                .await
                .unwrap();
            if status["received"]["last_sha256"] == digest {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("fresh paid payload must arrive without retries");
    bytes
}
