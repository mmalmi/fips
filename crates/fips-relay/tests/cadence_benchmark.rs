//! Opt-in experiment over real service processes and isolated simulated money.
#![cfg(all(unix, feature = "measurements"))]

mod process_support;
use cashu_service::{
    create_topup_quote, load_mint_balance, load_wallet_overview, receive_payment_token,
    send_payment_token,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use fips_core::config::PeerConfig;
use fips_relay::{
    controller::PaymentCadence,
    ledger::BillingBasis,
    probe::{ReceiveProbe, SendProbe},
    service::{AdminRequest, ServiceConfig, request},
};
use process_support::*;
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::Write,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const FUNDING: u64 = 1_024;

async fn sample(configs: &[ServiceConfig]) -> Vec<Value> {
    let mut values = Vec::new();
    for cfg in configs {
        let status = request(cfg, &AdminRequest::Status).await.unwrap();
        assert!(
            status["measurements"].is_object(),
            "measurement build required"
        );
        values.push(json!({
            "measurements": status["measurements"],
            "payment_progress": status["payment_progress"],
            "control_traffic": status["control_traffic"],
            "peers": status["peers"],
            "last_error": status["last_error"],
        }));
    }
    values
}

async fn stream(
    configs: &[ServiceConfig],
    npubs: &[String],
    id: u64,
    count: u32,
    rate: u32,
    drain_secs: u64,
) -> Value {
    let stream_id = format!("{id:032x}");
    request(
        &configs[4],
        &AdminRequest::ReceiveProbe {
            probe: ReceiveProbe {
                source: npubs[0].clone(),
                stream_id: stream_id.clone(),
                packet_count: count,
                payload_bytes: 1_000,
                measure_one_way_latency: true,
            },
        },
    )
    .await
    .unwrap();
    let sent = request(
        &configs[0],
        &AdminRequest::SendProbe {
            probe: SendProbe {
                destination: npubs[4].clone(),
                stream_id,
                packet_count: count,
                payload_bytes: 1_000,
                packets_per_second: rate,
            },
        },
    )
    .await
    .unwrap();
    // A bounded drain reports loss; it must never retry measured application data.
    let deadline = Instant::now() + Duration::from_secs(drain_secs);
    let received = loop {
        let status = request(&configs[4], &AdminRequest::Status).await.unwrap();
        if status["probe"]["unique_packets"] == count || Instant::now() >= deadline {
            break status["probe"].clone();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    json!({"sender":sent["probe"], "receiver":received})
}

async fn workload(configs: &[ServiceConfig], npubs: &[String], name: &str, id: u64) -> Value {
    let before_guard = sample(configs).await;
    let before = sample(configs).await;
    let started = Instant::now();
    let mut probes = Vec::new();
    match name {
        "idle" => tokio::time::sleep(Duration::from_secs(4)).await,
        "bursty" => {
            for burst in 0..8 {
                probes.push(stream(configs, npubs, id + burst, 64, 1_000, 2).await);
                tokio::time::sleep(Duration::from_millis(800)).await;
            }
        }
        "steady" => probes.push(stream(configs, npubs, id, 3_200, 400, 2).await),
        "high_rate" => probes.push(stream(configs, npubs, id, 32_000, 4_000, 2).await),
        _ => unreachable!(),
    }
    let offered_elapsed_ms = started.elapsed().as_millis();
    // Identical tail for every policy; the report validator rejects unreconciled
    // payment work at either boundary. Never flush or extend a selected trial.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let after = sample(configs).await;
    let observation_elapsed_ms = started.elapsed().as_millis();
    // A provider's cost snapshot can precede its buyer's acknowledgment in a
    // sequential status pass. A second full pass must show no deferred work,
    // including after the final workload where there is no next gap check.
    let after_guard = sample(configs).await;
    json!({"workload":name, "offered_elapsed_ms":offered_elapsed_ms,
        "observation_elapsed_ms":observation_elapsed_ms,
        "before_guard":before_guard, "before":before, "after":after,
        "after_guard":after_guard, "probes":probes})
}

async fn trial(delay: u64, trial_id: usize, output: &mut std::fs::File) {
    let root = tempfile::tempdir().unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let network = PaymentNetwork::new(731, 0, Arc::new(VirtualClock::new(now)));
    let mint = LocalMint::start(
        root.path(),
        network.clone(),
        "cadence-benchmark",
        IssuerMode::ClosedLoop,
    )
    .await
    .unwrap();
    let mut configs = Vec::new();
    let mut paths = Vec::new();
    let mut npubs = Vec::new();
    let mut reservations = Vec::new();
    for i in 0..5 {
        let directory = root.path().join(format!("n{i}"));
        std::fs::create_dir(&directory).unwrap();
        let mut cfg = config(&directory, mint.url());
        cfg.payment_cadence = PaymentCadence {
            max_delay_ms: delay,
            unpaid_percent: 50,
        };
        cfg.terms.billing = BillingBasis::ForwardingAttempt;
        cfg.terms.controller.channel_capacity_sat = 256;
        cfg.terms.controller.max_locked_sat = 512;
        cfg.terms.buyer_budget_sat = 512;
        cfg.terms.fee_msat_per_kib = 1;
        cfg.terms.max_rate_msat_per_kib = 8;
        cfg.terms.quote_max_units = 128 * 1024 * 1024;
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        cfg.transports = udp_transports(socket.local_addr().unwrap());
        reservations.push(socket);
        let path = directory.join("config.json");
        std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
        let init = command(&path, "init").await;
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        npubs.push(String::from_utf8(init.stdout).unwrap().trim().to_string());
        let wallet = cfg.state_directory.join("wallet");
        let quote = create_topup_quote(&wallet, mint.url(), FUNDING)
            .await
            .unwrap();
        network
            .orchestrator_funding()
            .settle_external(&quote.payment_request)
            .unwrap();
        assert!(
            load_wallet_overview(&wallet, true)
                .await
                .unwrap()
                .warnings
                .is_empty()
        );
        configs.push(cfg);
        paths.push(path);
    }
    let addresses: Vec<_> = configs.iter().map(udp_bind).collect();
    for (i, cfg) in configs.iter_mut().enumerate() {
        cfg.neighbors = npubs
            .iter()
            .enumerate()
            .filter(|(j, _)| i.abs_diff(*j) == 1)
            .map(|(j, npub)| PeerConfig::new(npub, "udp", addresses[j].to_string()))
            .collect();
        std::fs::write(&paths[i], serde_json::to_vec(&cfg).unwrap()).unwrap();
    }
    drop(reservations);
    let mut children = Vec::new();
    for path in &paths {
        children.push(start(path).await);
    }
    ready(&configs, &paths, &npubs, &mut children).await;
    let purchase = request(
        &configs[0],
        &AdminRequest::Buy {
            destination: npubs[4].clone(),
        },
    )
    .await
    .unwrap();
    assert_eq!(purchase["purchase"]["contract"]["price"]["msat"], 3);
    // Fund both paying directions to keep this cadence comparison matched with
    // its historical baseline. Unfunded return setup has separate acceptance.
    request(
        &configs[4],
        &AdminRequest::Buy {
            destination: npubs[0].clone(),
        },
    )
    .await
    .unwrap();
    // Match the existing service regression's bounded native session-discovery
    // warmup. Setup attempts are recorded, excluded from timed windows, and do
    // not add retries to any measured stream.
    let mut warmup = Vec::new();
    for attempt in 1..=6 {
        warmup.push(stream(&configs, &npubs, attempt, 1, 1, 10).await);
        if warmup.last().unwrap()["receiver"]["unique_packets"] == 1 {
            break;
        }
    }
    writeln!(
        output,
        "{}",
        json!({"trial":trial_id, "max_delay_ms":delay, "warmup":warmup})
    )
    .unwrap();
    output.flush().unwrap();
    assert_eq!(
        warmup.last().unwrap()["receiver"]["unique_packets"],
        1,
        "native session warmup failed"
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    for (index, name) in ["idle", "bursty", "steady", "high_rate"]
        .into_iter()
        .enumerate()
    {
        let data = workload(&configs, &npubs, name, (index as u64 + 1) * 100).await;
        writeln!(
            output,
            "{}",
            json!({"trial":trial_id, "max_delay_ms":delay, "data":data})
        )
        .unwrap();
        output.flush().unwrap();
        eprintln!("cadence={delay} trial={trial_id} workload={name} recorded");
    }
    // Settlement is outside the measurement windows, but conservation is required.
    let mut settled = 0;
    for cfg in &configs {
        let result = request(cfg, &AdminRequest::Settle).await.unwrap();
        settled += result["settlements"].as_array().unwrap().len();
    }
    assert_eq!(settled, 6);
    for child in &mut children {
        stop(child).await;
    }
    let redeemed = root.path().join("redeemed");
    let mut total = 0;
    for cfg in &configs {
        let wallet = cfg.state_directory.join("wallet");
        let balance = load_mint_balance(&wallet, mint.url())
            .await
            .unwrap()
            .balance_sat;
        total += balance;
        if balance > 0 {
            let token = send_payment_token(&wallet, mint.url(), balance)
                .await
                .unwrap();
            receive_payment_token(&redeemed, &token.token)
                .await
                .unwrap();
        }
        assert_eq!(
            load_mint_balance(&wallet, mint.url())
                .await
                .unwrap()
                .balance_sat,
            0
        );
    }
    assert_eq!(total, FUNDING * 5);
    assert_eq!(
        load_mint_balance(&redeemed, mint.url())
            .await
            .unwrap()
            .balance_sat,
        total
    );
    assert!(network.accounting().unwrap().is_conserved());
    writeln!(
        output,
        "{}",
        json!({"trial":trial_id, "max_delay_ms":delay,
        "settled_channels":settled, "issued_sat":FUNDING * 5, "collected_sat":total,
        "conserved":true})
    )
    .unwrap();
    output.flush().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "matched multi-process measurement; run alone with --release and FIPS_CADENCE_REPORT"]
async fn matched_cadence_matrix() {
    use std::os::unix::fs::OpenOptionsExt;
    let path = std::env::var_os("FIPS_CADENCE_REPORT").expect("set a new output JSONL path");
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    writeln!(output, "{}", json!({"schema":2, "optimized":!cfg!(debug_assertions),
        "platform":std::env::consts::OS, "architecture":std::env::consts::ARCH,
        "nodes":5, "paid_relays":3, "funded_directions":2, "transport":"UDP loopback",
        "repeats":2, "unpaid_percent":50, "window_msat":4_000, "grace_msat":8_000,
        "channel_capacity_sat":256, "fee_msat_per_kib":1,
        "scope":"synchronous payment CPU; logical relay journal I/O; framed control bytes; aggregate link bytes",
        "excludes":"Cashu SQLite/physical writes, payment-specific full carrier bytes, impaired links, radio performance"})).unwrap();
    for (trial_id, delay) in [250, 500, 1_000, 2_000, 2_000, 1_000, 500, 250]
        .into_iter()
        .enumerate()
    {
        tokio::time::timeout(
            Duration::from_secs(180),
            trial(delay, trial_id, &mut output),
        )
        .await
        .expect("cadence trial deadline");
    }
}
