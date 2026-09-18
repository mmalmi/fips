//! Concurrent free and paid service traffic through the same forwarding neighbor pair.
//! FIPS_RELAY_REQUIRE_BACKGROUND_PRESSURE=1 also requires observed queue overflow
//! during paid delivery; a fast uncongested host otherwise proves concurrency only.
use super::*;
use fips_relay::{
    free_routes::FreeBandwidthPolicy,
    probe::{ReceiveProbe, SendProbe},
};

const FREE_PACKETS: u32 = 64_000;
const FREE_RATE: u32 = 16_000;
const FREE_BYTES: usize = 1_000;
const FREE_BURST: u32 = 32_768;
const FREE_BYTES_PER_SECOND: u32 = 32_768;
const PAID_PACKETS: u32 = 24;
const PAID_BYTES: usize = 128;
const FUNDED_SAT: u64 = 256;

async fn arm_probe(
    bench: &Bench,
    source: usize,
    destination: usize,
    id: u128,
    packet_count: u32,
    payload_bytes: usize,
) {
    request(
        &bench.configs[destination],
        &AdminRequest::ReceiveProbe {
            probe: ReceiveProbe {
                source: bench.npubs[source].clone(),
                stream_id: format!("{id:032x}"),
                packet_count,
                payload_bytes,
                measure_one_way_latency: source == 1,
                reflect: false,
            },
        },
    )
    .await
    .unwrap();
}

fn send_probe(
    bench: &Bench,
    destination: usize,
    id: u128,
    packet_count: u32,
    payload_bytes: usize,
    packets_per_second: u32,
) -> AdminRequest {
    AdminRequest::SendProbe {
        probe: SendProbe {
            destination: bench.npubs[destination].clone(),
            stream_id: format!("{id:032x}"),
            packet_count,
            payload_bytes,
            packets_per_second,
            measure_round_trip: false,
        },
    }
}

fn assert_submitted(sent: &Value, count: u32) {
    assert_eq!(sent["probe"]["submitted_packets"], count, "{sent}");
    assert!(sent["probe"]["stopped_reason"].is_null(), "{sent}");
}

async fn probe_report(bench: &Bench, destination: usize) -> Value {
    request(&bench.configs[destination], &AdminRequest::Status)
        .await
        .unwrap()["probe"]
        .clone()
}

async fn receive_all(bench: &Bench, destination: usize, count: u32, bytes: usize) -> Value {
    let mut report = Value::Null;
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            report = probe_report(bench, destination).await;
            if report["unique_packets"] == count {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("destination {destination} probe incomplete: {report}"));
    assert_eq!(report["unique_bytes"], u64::from(count) * bytes as u64);
    assert_eq!(report["missing_packets"], 0);
    assert_eq!(report["invalid_packets"], 0);
    assert_eq!(report["duplicate_packets"], 0);
    if !report["latency"].is_null() {
        assert_eq!(report["latency"]["samples"], count);
        assert_eq!(report["latency"]["invalid_timestamps"], 0);
    }
    report
}

async fn free_counters(bench: &Bench) -> Value {
    request(&bench.configs[2], &AdminRequest::Status)
        .await
        .unwrap()["free_routes"]["bandwidth"]
        .clone()
}

fn counter(state: &Value, field: &str) -> u64 {
    state[field]
        .as_u64()
        .unwrap_or_else(|| panic!("missing counter {field}: {state}"))
}

async fn free_progress_after(bench: &Bench, before: &Value) -> Value {
    let mut observed = Value::Null;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            observed = free_counters(bench).await;
            if counter(&observed, "admitted_packets") > counter(before, "admitted_packets") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("free stream made no progress: {before} -> {observed}"));
    observed
}

async fn paid_during_free(bench: &Bench, before: &Value) -> Value {
    let active = free_progress_after(bench, before).await;
    let pressure_before = background_pressure(bench).await;
    #[cfg(feature = "measurements")]
    let evidence_before = counter(&paid_progress(bench).await, "evidence_msat");
    let send = send_probe(bench, 3, 2, PAID_PACKETS, PAID_BYTES, 20);
    let (sent, received) = tokio::join!(
        request(&bench.configs[1], &send),
        receive_all(bench, 3, PAID_PACKETS, PAID_BYTES),
    );
    assert_submitted(&sent.unwrap(), PAID_PACKETS);
    let pressure_after = background_pressure(bench).await;
    let after = free_progress_after(bench, &active).await;
    assert!(counter(&after, "rate_denied") > counter(before, "rate_denied"));
    let pressure_observed = pressure_before
        .iter()
        .zip(&pressure_after)
        .any(|(old, new)| counter(new, "packets") > counter(old, "packets"));
    if std::env::var("FIPS_RELAY_REQUIRE_BACKGROUND_PRESSURE").as_deref() == Ok("1") {
        assert!(
            pressure_observed,
            "offered traffic did not create background queue pressure"
        );
    }
    let result = json!({"paid_receiver": received, "free_before_paid": active, "free_after_paid": after,
        "pressure_before_paid": pressure_before, "pressure_after_paid": pressure_after,
        "pressure_observed_during_paid_delivery": pressure_observed});
    #[cfg(feature = "measurements")]
    let result = {
        let mut result = result;
        result["payment_before_free_ended"] = reconciled_payment(bench, evidence_before).await;
        result
    };
    result
}

#[cfg(feature = "measurements")]
async fn paid_progress(bench: &Bench) -> Value {
    let state = request(&bench.configs[1], &AdminRequest::Status)
        .await
        .unwrap();
    let channels = state["payment_progress"].as_object().unwrap();
    assert_eq!(channels.len(), 1);
    channels.values().next().unwrap().clone()
}

#[cfg(feature = "measurements")]
async fn reconciled_payment(bench: &Bench, evidence_before: u64) -> Value {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let progress = paid_progress(bench).await;
            let evidence = counter(&progress, "evidence_msat");
            let due = evidence.max(counter(&progress, "authorized_sat") * 1_000);
            if evidence > evidence_before
                && progress["in_flight"] == false
                && progress["acknowledged_msat"]
                    .as_u64()
                    .is_some_and(|paid| paid >= due)
            {
                return progress;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("automatic payments must reconcile during the active free stream")
}

async fn background_pressure(bench: &Bench) -> Vec<Value> {
    let mut result = Vec::new();
    for index in [1, 2] {
        let status = native_request(&bench.configs[index], &json!({"command": "show_status"}))
            .await
            .unwrap();
        let forwarding = &status["data"]["forwarding"];
        result.push(json!({
            "node": index,
            "packets": counter(forwarding, "drop_background_full_packets"),
            "bytes": counter(forwarding, "drop_background_full_bytes"),
        }));
    }
    result
}

async fn warm_paid(bench: &Bench) {
    arm_probe(bench, 1, 3, 1, 1, PAID_BYTES).await;
    let send = send_probe(bench, 3, 1, 1, PAID_BYTES, 1);
    assert_submitted(&request(&bench.configs[1], &send).await.unwrap(), 1);
    receive_all(bench, 3, 1, PAID_BYTES).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paid_delivery_progresses_during_free_traffic_and_free_resumes_idle() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let mint_root = tempfile::tempdir().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let network = PaymentNetwork::new(103, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            mint_root.path(), network.clone(), "free-paid-concurrency", IssuerMode::ClosedLoop,
        ).await.unwrap();
        let mut bench = Bench::start_configured(
            std::array::from_fn(|_| mint.url().to_owned()),
            Pricing::MixedDestinations,
            None,
            |index, config| {
                // The finite free stream must not exhaust its negotiated grant;
                // this test isolates local bandwidth/scheduling from renewal.
                config.terms.quote_max_units = 96 * 1_024 * 1_024;
                if index == 2 {
                    config.free_bandwidth = Some(FreeBandwidthPolicy {
                        global_bytes_per_second: FREE_BYTES_PER_SECOND,
                        global_burst_bytes: FREE_BURST,
                        peer_bytes_per_second: FREE_BYTES_PER_SECOND,
                        peer_burst_bytes: FREE_BURST,
                    });
                }
            },
        ).await;
        let free_finances = monetary_journals(&bench.configs[0]);
        let free_open = bench.open(4).await;
        assert!(free_open["purchase"].is_null());
        assert_eq!(free_open["free_route"]["price"]["msat"], 0);
        bench.deliver(4, "warm unfunded free session").await;

        let wallet = bench.configs[1].state_directory.join("wallet");
        let quote = create_topup_quote(&wallet, mint.url(), FUNDED_SAT).await.unwrap();
        network.orchestrator_funding().settle_external(&quote.payment_request).unwrap();
        assert!(load_wallet_overview(&wallet, true).await.unwrap().warnings.is_empty());
        let paid_open = request(&bench.configs[1], &AdminRequest::Buy {
            destination: bench.npubs[3].clone(),
        }).await.unwrap();
        assert_eq!(paid_open["purchase"]["contract"]["price"]["msat"], 2_048);
        warm_paid(&bench).await;
        arm_probe(&bench, 0, 4, 3, FREE_PACKETS, FREE_BYTES).await;
        arm_probe(&bench, 1, 3, 2, PAID_PACKETS, PAID_BYTES).await;
        let pressure_before = background_pressure(&bench).await;
        let before = free_counters(&bench).await;
        let started = tokio::time::Instant::now();
        let overlap = {
        let free_send = send_probe(&bench, 4, 3, FREE_PACKETS, FREE_BYTES, FREE_RATE);
        let free_sender = request(&bench.configs[0], &free_send);
        tokio::pin!(free_sender);
        // An unfinished sender alone is insufficient evidence: the other branch
        // also observes free admission before and after the paid receiver fills.
        let observed = tokio::select! {
            ended = &mut free_sender => panic!("free sender ended before paid overlap: {ended:?}"),
            observed = paid_during_free(&bench, &before) => observed,
        };
        assert_submitted(&free_sender.await.unwrap(), FREE_PACKETS);
            observed
        };
        let after = free_counters(&bench).await;
        let elapsed = started.elapsed().as_secs() + 1;
        let free_units = counter(&after, "charged_units") - counter(&before, "charged_units");
        assert!(free_units <= u64::from(FREE_BURST) + elapsed * u64::from(FREE_BYTES_PER_SECOND),
            "free allowance exceeded: {before} -> {after}, elapsed={elapsed}");
        assert_eq!(counter(&after, "tracked_peers"), 1);
        assert_eq!(counter(&after, "peer_capacity_denied"), 0);
        let free_received = probe_report(&bench, 4).await;
        assert!(free_received["unique_packets"].as_u64().unwrap() > 0);
        assert_eq!(free_received["invalid_packets"], 0);
        assert_eq!(free_received["duplicate_packets"], 0);
        let pressure_after = background_pressure(&bench).await;
        eprintln!("mixed free/paid concurrency: {overlap}; free_receiver={free_received}; free_limits={after}; background_pressure_before={pressure_before:?}; background_pressure_after={pressure_after:?}");

        // Refill one burst after the finite load stops, then verify a fresh
        // stream through the same grant and native route, without a retry.
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        arm_probe(&bench, 0, 4, 4, 4, FREE_BYTES).await;
        let idle_send = send_probe(&bench, 4, 4, 4, FREE_BYTES, 10);
        assert_submitted(&request(&bench.configs[0], &idle_send).await.unwrap(), 4);
        receive_all(&bench, 4, 4, FREE_BYTES).await;
        assert_eq!(monetary_journals(&bench.configs[0]), free_finances);
        let states = bench.states().await;
        for (index, state) in states.iter().enumerate() {
            assert!(state["last_error"].is_null(), "node {index}: {state}");
            if index == 1 {
                assert_eq!(state["purchases"].as_array().unwrap().len(), 1);
            } else {
                assert!(state["purchases"].as_array().unwrap().is_empty());
                assert!(state["history"].as_array().unwrap().is_empty());
                assert_eq!(state["funding_budget"]["wallet_debited_sat"], 0);
            }
        }
        let mut settlements = 0;
        for config in &bench.configs {
            settlements += request(config, &AdminRequest::Settle).await.unwrap()["settlements"]
                .as_array().unwrap().len();
        }
        assert_eq!(settlements, 1);
        bench.stop().await;
        assert_eq!(monetary_journals(&bench.configs[0]), free_finances);
        let mut total = 0;
        for (index, config) in bench.configs.iter().enumerate() {
            let balance = load_mint_balance(&config.state_directory.join("wallet"), mint.url())
                .await.unwrap().balance_sat;
            match index {
                1 => assert!(balance < FUNDED_SAT),
                2 => assert!(balance > 0),
                _ => assert_eq!(balance, 0),
            }
            total += balance;
        }
        assert_eq!(total, FUNDED_SAT);
        assert!(network.accounting().unwrap().is_conserved());
    }).await.expect("mixed free/paid concurrency deadline");
}
