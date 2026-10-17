//! Real fragmented funding, automatic retirement and ordinary paid data overlap.
use super::*;
use fips_relay::{
    controller::{FundingRequestBudget, HISTORY_PENDING},
    ledger::BillingBasis,
    probe::{ReceiveProbe, SendProbe},
    service::ServiceConfig,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, num::NonZeroU32, path::Path, process::Stdio, time::Instant};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    task::JoinHandle,
};

#[path = "live/purchase.rs"]
mod purchase;
#[path = "live/receiver.rs"]
#[cfg(target_os = "linux")]
mod receiver;
#[path = "live/renewal.rs"]
mod renewal;

const CAPACITY: u64 = 32;
const OLD_CHANNELS: usize = 15;
const LIVE_PACKETS: u32 = 4096;
const FUNDING: u64 = 128;
const NATIVE_LIMIT: u64 = 64 * 1024 * 1024;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn journal(config: &ServiceConfig) -> Value {
    restore::read(&config.state_directory.join("controller/controller.json"))
}

fn pending(value: &Value) -> bool {
    value["history"]["channels"]["pending"].is_object()
}

async fn status(config: &ServiceConfig) -> Value {
    request(config, &AdminRequest::Status).await.unwrap()
}

async fn node_statuses(bench: &setup::Bench) -> Vec<Value> {
    let mut nodes = Vec::new();
    for config in &bench.configs {
        nodes.push(
            match tokio::time::timeout(
                Duration::from_secs(2),
                request(config, &AdminRequest::Status),
            )
            .await
            {
                Ok(Ok(value)) => value,
                other => json!({"status_error": format!("{other:?}")}),
            },
        );
    }
    nodes
}

#[cfg(target_os = "linux")]
async fn control_failed(bench: &setup::Bench, source: usize, error: &str) -> ! {
    // The provider's rejection reason is memory-only. Capture it before a
    // failed assertion drops the processes, without retrying a money command.
    let nodes: Vec<_> = node_statuses(bench)
        .await
        .into_iter()
        .map(|state| {
            json!({"last_error": state["last_error"],
                "status_error": state["status_error"],
                "funding_budget": state["funding_budget"]})
        })
        .collect();
    let root = bench.paths[0].parent().unwrap().parent().unwrap();
    let path = root.join("failed-control.json");
    let output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    serde_json::to_writer(
        output,
        &json!({"source": source, "error": error, "nodes": nodes}),
    )
    .unwrap();
    panic!(
        "control command failed without replay: {error}; inspect {}",
        path.display()
    );
}

fn credit(bench: &setup::Bench, seller: usize, channel: &str) -> u64 {
    let ledger = restore::read(
        &bench.configs[seller]
            .state_directory
            .join("seller/ledger.json"),
    );
    ledger["ledger"]["channels"]
        .as_array()
        .unwrap()
        .iter()
        .find(|sale| sale["terms"]["id"] == channel)
        .unwrap()["usage"]["paid_msat"]
        .as_u64()
        .unwrap()
}

async fn wait_until(unix: u64) {
    while now() < unix {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn probe(bench: &setup::Bench, id: u8, count: u32, rate: u32) -> JoinHandle<Value> {
    probe_to(bench, 2, id, count, rate).await
}

async fn probe_to(
    bench: &setup::Bench,
    sink: usize,
    id: u8,
    count: u32,
    rate: u32,
) -> JoinHandle<Value> {
    probe_between(bench, 0, sink, u64::from(id), count, rate, 1000).await
}

#[allow(clippy::too_many_arguments)] // Both endpoints share the exact ordinary probe shape.
async fn probe_between(
    bench: &setup::Bench,
    source: usize,
    sink: usize,
    id: u64,
    count: u32,
    rate: u32,
    payload_bytes: usize,
) -> JoinHandle<Value> {
    let stream_id = format!("{id:032x}");
    request(
        &bench.configs[sink],
        &AdminRequest::ReceiveProbe {
            probe: ReceiveProbe {
                source: bench.npubs[source].clone(),
                stream_id: stream_id.clone(),
                packet_count: count,
                payload_bytes,
                lifetime_secs: Some(90),
                measure_one_way_latency: false,
                reflect: false,
            },
        },
    )
    .await
    .unwrap();
    let config = bench.configs[source].clone();
    let destination = bench.npubs[sink].clone();
    tokio::spawn(async move {
        request(
            &config,
            &AdminRequest::SendProbe {
                probe: SendProbe {
                    destination,
                    stream_id,
                    packet_count: count,
                    payload_bytes,
                    packets_per_second: rate,
                    max_duration_secs: Some(60),
                    measure_round_trip: false,
                },
            },
        )
        .await
        .unwrap()["probe"]
            .clone()
    })
}

async fn delivered(bench: &setup::Bench, sending: JoinHandle<Value>, count: u32) -> Value {
    delivered_to(bench, 2, sending, count).await
}

async fn delivered_to(
    bench: &setup::Bench,
    sink: usize,
    sending: JoinHandle<Value>,
    count: u32,
) -> Value {
    let sent = sending.await.unwrap();
    let mut received = Value::Null;
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            received = status(&bench.configs[sink]).await["probe"].clone();
            assert_eq!(sent["stream_id"], received["stream_id"]);
            if received["unique_packets"] == count {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let mut observation = json!({"sender":sent,"receiver":received});
    if result.is_err()
        || sent["stopped_reason"] != Value::Null
        || sent["submitted_packets"] != count
    {
        observation["nodes"] = json!(node_statuses(bench).await);
        let root = bench.paths[0].parent().unwrap().parent().unwrap();
        let path = root.join(format!(
            "failed-probe-{}.json",
            sent["stream_id"].as_str().unwrap()
        ));
        std::fs::write(&path, serde_json::to_vec(&observation).unwrap()).unwrap();
        panic!(
            "all original packets must arrive without replay; inspect {}",
            path.display()
        );
    }
    observation
}

fn payment_caught_up(progress: &Value) -> bool {
    progress["in_flight"] == false
        && progress["acknowledged_msat"].as_u64().is_some_and(|ack| {
            ack >= progress["authorized_sat"].as_u64().unwrap() * 1000
                && ack >= progress["evidence_msat"].as_u64().unwrap()
        })
}

async fn caught_up(config: &ServiceConfig, channel: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let state = status(config).await;
            let p = &state["payment_progress"][channel];
            if payment_caught_up(p) {
                return state;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("ordinary automatic payment must be acknowledged")
}

async fn hold_wallet_writer(wallet: &Path) -> Child {
    // The test never modifies rows. Closing stdin or dropping the child releases
    // the external writer, including when an assertion unwinds the fixture.
    let mut child = Command::new("python3")
        .args(["-c", "import sqlite3,sys\nc=sqlite3.connect(sys.argv[1])\nc.execute('BEGIN IMMEDIATE')\nprint('held',flush=True)\nsys.stdin.read()\nc.rollback()"])
        .arg(cashu_service::cashu_wallet_db_path(wallet))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("this opt-in contention test requires Python 3 with sqlite3");
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(10), output.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(line.trim(), "held");
    child
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "opt-in real fragmented-channel retirement with concurrent paid traffic"]
async fn ordinary_payments_progress_during_fragmented_sender_retirement() {
    tokio::time::timeout(Duration::from_secs(900), exercise(false))
        .await
        .unwrap();
}

async fn exercise(with_renewal: bool) {
    let root = retained_tempdir();
    let network = PaymentNetwork::new(9621, 0, Arc::new(VirtualClock::new(now())));
    let mint = LocalMint::start_with_limits(
        root.path(),
        network.clone(),
        "live-retirement",
        IssuerMode::ClosedLoop,
        4096,
        4096,
    )
    .await
    .unwrap();
    // Ordinary funding uses the mint's real denomination set, without a relay override.
    mint.mint()
        .rotate_keyset("sat".parse().unwrap(), vec![1], 0, false, None)
        .await
        .unwrap();
    let proxy = if with_renewal {
        Some(MintProxy::start(mint.url()).await)
    } else {
        None
    };
    let url = proxy
        .as_ref()
        .map_or_else(|| mint.url().to_owned(), |proxy| proxy.url.clone());
    let line = setup::LineConfig {
        lifetime: 360,
        quote_lifetime: 180,
        funding_limits: if with_renewal { &[1536; 3] } else { &[1536; 5] },
    };
    let configure = |index, cfg: &mut ServiceConfig| {
        // A one-way purchase needs the bounded free session handshake.
        cfg.terms.billing = BillingBasis::ForwardingData;
        // This fixture owns its mint; public-mint pacing must not consume
        // the real expiry window while preparing fragmented old channels.
        cfg.funding_request_budget = Some(FundingRequestBudget {
            burst: NonZeroU32::new(128).unwrap(),
            requests_per_minute: NonZeroU32::new(60_000).unwrap(),
        });
        cfg.terms.controller.channel_capacity_sat = CAPACITY;
        cfg.terms.controller.max_funding_overhead_sat = 0;
        cfg.terms.wallet_capacity_bytes = Some(NATIVE_LIMIT);
        cfg.terms.buyer_budget_sat = 256;
        cfg.terms.fee_msat_per_kib = 4;
        cfg.terms.max_rate_msat_per_kib = 4;
        cfg.terms.quote_max_units = 6 * 1024 * 1024;
        if index == 0 {
            cfg.terms.controller.max_locked_sat = 2 * CAPACITY;
            cfg.terms.controller.max_wallet_spend_sat = FUNDING;
            if with_renewal {
                renewal::configure(cfg);
            }
        }
    };
    let mut bench = if with_renewal {
        setup::start_configured_line(root.path(), mint, network, &url, line, configure).await
    } else {
        setup::start_configured_fork(root.path(), mint, network, &url, line, configure).await
    };
    let buy = AdminRequest::Buy {
        destination: bench.npubs[2].clone(),
    };
    let source = &bench.configs[0];
    let wallet = source.state_directory.join("wallet");
    let mut old = BTreeSet::new();
    for _ in 0..OLD_CHANNELS {
        request(source, &buy).await.unwrap();
        let state = status(source).await;
        let id = state["purchases"][0]["channel"]["id"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(old.insert(id));
        request(source, &AdminRequest::Settle).await.unwrap();
        // Distinct real expiries keep otherwise identical channel terms unique.
        let created = journal(source)["funding"]
            .as_object()
            .unwrap()
            .values()
            .map(|v| v["created_unix"].as_u64().unwrap())
            .max()
            .unwrap();
        wait_until(created + 1).await;
    }
    let before = journal(source);
    assert_eq!(before["funding"].as_object().unwrap().len(), OLD_CHANNELS);
    let expiries: Vec<_> = before["funding"]
        .as_object()
        .unwrap()
        .values()
        .map(|v| v["refund_after_unix"].as_u64().unwrap())
        .collect();
    let first = *expiries.iter().min().unwrap();
    let last = *expiries.iter().max().unwrap();
    assert!(
        last - first <= 30,
        "old deadlines must leave time for the later active channel"
    );
    assert!(
        now() < first - 35,
        "setup must finish before the real expiry window"
    );
    let client_path = cashu_service::spilman_client_store_path(&wallet);
    let client = restore::read(&client_path);
    let refund_coins: usize = client["settled_refunds"]
        .as_object()
        .unwrap()
        .values()
        .map(|v| {
            serde_json::from_str::<Vec<cashu::nuts::Proof>>(v["proofs_json"].as_str().unwrap())
                .unwrap()
                .len()
        })
        .sum();
    assert_eq!(refund_coins, OLD_CHANNELS * CAPACITY as usize);
    drop(client);
    let client_bytes = std::fs::metadata(&client_path).unwrap().len();
    assert!(client_bytes > 1024 * 1024 && client_bytes <= 32 * 1024 * 1024);
    eprintln!(
        "LIVE_RETIREMENT_PREPARED {}",
        json!({"root":root.path(),
        "refund_coins":refund_coins,"client_bytes":client_bytes,"first_refund_deadline":first,
        "last_refund_deadline":last,"wallet_capacity_bytes":NATIVE_LIMIT})
    );
    wait_until(first - 30).await;
    request(source, &buy).await.unwrap();
    let purchase = status(source).await["purchases"][0].clone();
    assert!(purchase["contract"]["expires_unix"].as_u64().unwrap() > last + 110);
    let active = purchase["channel"]["id"].as_str().unwrap().to_owned();
    assert!(!old.contains(&active));
    let active_before = journal(source)["funding"]
        .as_object()
        .unwrap()
        .values()
        .find(|v| v["funded"]["terms"]["id"] == active)
        .unwrap()
        .clone();
    let warmup = delivered(&bench, probe(&bench, 0, 1, 1).await, 1).await;
    let warm = caught_up(source, &active).await;
    let signed_warm = warm["payment_progress"][&active]["authorized_sat"]
        .as_u64()
        .unwrap();
    if with_renewal {
        // Settling the old channels deliberately paused this worker. Warmup
        // must stay below its threshold before normal automatic work resumes.
        assert!(signed_warm < renewal::DUE_SAT);
        request(source, &AdminRequest::ResumeRenewals)
            .await
            .unwrap();
    }
    assert!(
        now() < first,
        "the active channel must precede old-channel expiry"
    );
    let mut writer = hold_wallet_writer(&wallet).await;
    tokio::time::timeout(Duration::from_secs(70), async {
        while !pending(&journal(source)) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    let mut renewal = match &proxy {
        Some(proxy) => Some(renewal::Check::arm(&bench, proxy, &active).await),
        None => None,
    };
    let mut purchase = if with_renewal {
        None
    } else {
        Some(purchase::Check::arm(&bench, &active).await)
    };
    let held_probe = delivered(&bench, probe(&bench, 1, 512, 128).await, 512).await;
    if let Some(check) = &mut purchase {
        check.rejected(&bench).await;
    }
    let held = caught_up(source, &active).await;
    let signed_before = held["payment_progress"][&active]["authorized_sat"]
        .as_u64()
        .unwrap();
    assert!(
        signed_before > signed_warm && pending(&journal(source)),
        "active payments must progress while maintenance waits"
    );
    if let Some(check) = &mut renewal {
        assert!(writer.try_wait().unwrap().is_none());
        check.deferred(&bench).await;
        assert!(writer.try_wait().unwrap().is_none());
    }
    wait_until(last + 1).await;
    let before_release = caught_up(source, &active).await;
    let signed_before = before_release["payment_progress"][&active]["authorized_sat"]
        .as_u64()
        .unwrap();
    drop(writer.stdin.take());
    assert!(writer.wait().await.unwrap().success());
    let mut observation = if let Some(check) = renewal {
        check.finish(&bench).await
    } else {
        let started = Instant::now();
        let sending = probe(&bench, 2, LIVE_PACKETS, 1024).await;
        let mut samples = Vec::new();
        let after = tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let j = journal(source);
            let state = status(source).await;
            let ledger = restore::read(
                &bench.configs[1].state_directory.join("seller/ledger.json"),
            );
            let credit = ledger["ledger"]["channels"]
                .as_array()
                .unwrap()
                .iter()
                .find(|channel| channel["terms"]["id"] == active)
                .unwrap()["usage"]["paid_msat"]
                .as_u64()
                .unwrap();
            let delivered = status(&bench.configs[2]).await["probe"]["unique_packets"]
                .as_u64()
                .unwrap();
            let after = journal(source);
            samples.push(json!({"elapsed_us":started.elapsed().as_micros(),
                "pending_before":pending(&j),"pending_after":pending(&after),
                "same_pending_plan":pending(&j)
                    && j["history"]["channels"]["pending"] == after["history"]["channels"]["pending"],
                "pending_through":j["history"]["channels"]["pending"]["after"]["through"],
                "credited_msat":credit,"delivered":delivered,
                "payment":state["payment_progress"][&active]}));
            let remaining = after["funding"]
                .as_object()
                .unwrap()
                .values()
                .filter(|v| old.contains(v["funded"]["terms"]["id"].as_str().unwrap()))
                .count();
            if remaining == 0 {
                break after;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("old history must finish without replacing the active channel");
        let maintenance_window_us = started.elapsed().as_micros();
        let live_probe = delivered(&bench, sending, LIVE_PACKETS).await;
        let paid = caught_up(source, &active).await;
        let progressed = samples.windows(2).any(|pair| {
            let (a, b) = (&pair[0], &pair[1]);
            a["same_pending_plan"] == true
                && b["same_pending_plan"] == true
                && a["pending_through"] == b["pending_through"]
                && b["credited_msat"].as_u64().unwrap() > a["credited_msat"].as_u64().unwrap()
                && b["delivered"].as_u64().unwrap() > a["delivered"].as_u64().unwrap()
        });
        assert!(
            after["funding"]
                .as_object()
                .unwrap()
                .values()
                .any(|v| *v == active_before)
        );
        assert_eq!(
            paid["funding_budget"]["wallet_debited_sat"],
            before_release["funding_budget"]["wallet_debited_sat"]
        );
        assert_eq!(
            paid["funding_budget"]["wallet_debited_sat"],
            (OLD_CHANNELS as u64 + 1) * CAPACITY
        );
        json!({"progressed_during_cleanup":progressed,
        "maintenance_window_us":maintenance_window_us,
        "live_probe":live_probe,"samples":samples,"final_progress":paid["payment_progress"][&active]})
    };
    if let Some(check) = purchase {
        observation["purchase"] = check.finish(&bench).await;
    }
    observation["root"] = json!(root.path());
    observation["refund_coins"] = json!(refund_coins);
    observation["client_bytes"] = json!(client_bytes);
    observation["warmup"] = warmup;
    observation["held_probe"] = held_probe;
    observation["signed_before_release_sat"] = json!(signed_before);
    std::fs::write(
        root.path().join("live-retirement.json"),
        serde_json::to_vec(&observation).unwrap(),
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let j = journal(&bench.configs[1]);
            let h = &j["history"];
            let unfinished = h["pending"].is_object()
                || h["channels"]["pending"].is_object()
                || h["seller"]["pending"].is_object();
            let retained = [&j["seller_settlements"], &h["sellers"]]
                .iter()
                .filter_map(|v| v.as_object())
                .any(|entries| entries.keys().any(|id| old.contains(id)));
            let sender = journal(source);
            let sender_retained = sender["funding"].as_object().unwrap().values().any(|v| {
                v["funded"]["terms"]["id"]
                    .as_str()
                    .is_some_and(|id| old.contains(id))
            });
            if !unfinished && !retained && !pending(&sender) && !sender_retained {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("receiver retirement must finish before final settlement");
    for config in &bench.configs {
        request(config, &AdminRequest::Settle).await.unwrap();
    }
    for child in &mut bench.children {
        stop(child).await;
    }
    let mut total = 0;
    for cfg in &bench.configs {
        total += load_mint_balance(&cfg.state_directory.join("wallet"), &url)
            .await
            .unwrap()
            .balance_sat;
    }
    assert_eq!(
        total,
        3 * FUNDING,
        "the original mint and wallets conserve every test sat"
    );
    setup::verify_settled_wallets(&bench, &url, 3 * FUNDING).await;
    let mut result = json!({"refunded_coins":refund_coins,"conserved_test_sat":total,
        "fixture":root.path()});
    if with_renewal {
        result["renewal_completed"] = observation["renewal_completed"].clone();
        eprintln!("LIVE_RETIREMENT_RENEWAL_RESULT {result}");
    } else {
        result["progressed_during_cleanup"] = observation["progressed_during_cleanup"].clone();
        result["maintenance_window_us"] = observation["maintenance_window_us"].clone();
        result["purchase_completed"] = observation["purchase"]["completed"].clone();
        eprintln!("LIVE_RETIREMENT_RESULT {result}");
    }
    let acceptance = if with_renewal {
        "renewal_completed"
    } else {
        "progressed_during_cleanup"
    };
    assert_eq!(observation[acceptance], true, "{acceptance}");
}
