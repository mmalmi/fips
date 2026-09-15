#![cfg(unix)]

use cashu_service::{
    create_topup_quote, load_mint_balance, load_wallet_overview, receive_payment_token,
    send_payment_token,
    simulation::{IssuerMode, LocalMint, PaymentNetwork, VirtualClock},
};
use fips_core::config::PeerConfig;
use fips_relay::{
    controller::ControllerPolicy,
    ledger::BillingBasis,
    probe::{ReceiveProbe, SendProbe},
    service::{AdminRequest, ServiceConfig, ServiceTerms, native_request, request},
};
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::process::{Child, Command};

struct DiagnosticLogs(PathBuf);
impl Drop for DiagnosticLogs {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        if let Some(directory) = std::env::var_os("FIPS_RELAY_TEST_LOG_DIR") {
            use std::{io::Write, os::unix::fs::OpenOptionsExt};
            let directory = PathBuf::from(directory);
            for i in 0..5 {
                if let Ok(bytes) = std::fs::read(self.0.join(format!("n{i}/config.log")))
                    && let Ok(mut file) = std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(0o600)
                        .open(directory.join(format!("node-{i}.log")))
                {
                    let _ = file.write_all(&bytes);
                }
            }
        }
    }
}

fn config(root: &Path, mint: &str) -> ServiceConfig {
    ServiceConfig {
        state_directory: root.join("state"),
        udp_bind: Some("127.0.0.1:0".parse().unwrap()),
        customer_network: None,
        ethernet_interfaces: vec![],
        neighbors: vec![],
        terms: ServiceTerms {
            billing: Default::default(),
            controller: ControllerPolicy {
                mint_url: mint.into(),
                channel_capacity_sat: 32,
                max_locked_sat: 64,
                channel_lifetime_secs: 600,
                renewal: None,
            },
            buyer_budget_sat: 64,
            window_msat: 4_000,
            grace_msat: 8_000,
            fee_msat_per_kib: 1_024,
            max_rate_msat_per_kib: 8_192,
            quote_lifetime_secs: 300,
            quote_max_units: 30_000,
        },
    }
}

async fn start(path: &Path) -> Child {
    let log = std::fs::File::create(path.with_extension("log")).unwrap();
    Command::new(env!("CARGO_BIN_EXE_fips-relay"))
        .arg("run")
        .arg(path)
        .stdout(Stdio::null())
        .env(
            "RUST_LOG",
            std::env::var("FIPS_RELAY_TEST_LOG").unwrap_or_else(|_| "warn".into()),
        )
        .stderr(log)
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

async fn stop(child: &mut Child) {
    let pid = child.id().expect("owned test child");
    assert!(
        Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status()
            .await
            .unwrap()
            .success()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(40), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

fn has_line_peers(status: &serde_json::Value, npubs: &[String], index: usize) -> bool {
    let actual = status["peers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["connected"] == true)
        .map(|p| p["npub"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    let expected = npubs
        .iter()
        .enumerate()
        .filter(|(j, _)| index.abs_diff(*j) == 1)
        .map(|(_, p)| p.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    actual == expected
}

async fn ready(
    configs: &[ServiceConfig],
    paths: &[PathBuf],
    npubs: &[String],
    children: &mut [Child],
) {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let mut ready_nodes = 0;
            for (i, cfg) in configs.iter().enumerate() {
                if let Some(status) = children[i].try_wait().unwrap() {
                    panic!(
                        "node {i} exited {status}: {}",
                        std::fs::read_to_string(paths[i].with_extension("log")).unwrap()
                    );
                }
                if let Ok(status) = request(cfg, &AdminRequest::Status).await
                    && has_line_peers(&status, npubs, i)
                {
                    ready_nodes += 1;
                }
            }
            if ready_nodes == configs.len() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("all five processes should establish exactly the intended line peers");
}

async fn deliver(configs: &[ServiceConfig], npubs: &[String], epoch: u8) {
    for round in 0..3 {
        for (source, destination) in [(0, 4), (4, 0)] {
            let payload = format!("{epoch}:{source}:{round}{}", "x".repeat(970));
            let digest = format!("{:x}", Sha256::digest(payload.as_bytes()));
            let mut delivered = false;
            // Endpoint retry is application behavior. Freshly encrypted attempts
            // remain independently billable best-effort network packets.
            // Simultaneous restart can exhaust the native discovery ladder
            // while routers' lookups share per-target rate limits. FIPS then
            // backs off for 30 seconds. Allow that bounded retry cycle, not
            // just the first 30 seconds after links become connected.
            let started = tokio::time::Instant::now();
            for attempt in 0..6 {
                request(
                    &configs[source],
                    &AdminRequest::Send {
                        destination: npubs[destination].clone(),
                        payload: payload.clone(),
                    },
                )
                .await
                .unwrap();
                if tokio::time::timeout(Duration::from_secs(10), async {
                    loop {
                        let status = request(&configs[destination], &AdminRequest::Status)
                            .await
                            .unwrap();
                        if status["received"]["last_sha256"] == digest {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(30)).await;
                    }
                })
                .await
                .is_ok()
                {
                    if attempt > 0 {
                        eprintln!(
                            "recovery epoch={epoch} round={round} direction={source}->{destination} attempts={} elapsed={:?}",
                            attempt + 1,
                            started.elapsed()
                        );
                    }
                    delivered = true;
                    break;
                }
            }
            if !delivered {
                let mut states = Vec::new();
                for cfg in configs {
                    let status = request(cfg, &AdminRequest::Status).await.unwrap();
                    let seller: serde_json::Value = serde_json::from_slice(
                        &std::fs::read(cfg.state_directory.join("seller/ledger.json")).unwrap(),
                    )
                    .unwrap();
                    states.push(serde_json::json!({"error": status["last_error"], "budget": status["remaining_budget_sat"],
                        "received": status["received"]["packets"], "channels": seller["ledger"]["channels"].as_array().unwrap().iter().map(|c| c["usage"].clone()).collect::<Vec<_>>(),
                        "diagnostic": std::fs::read_to_string(cfg.state_directory.parent().unwrap().join("config.log")).unwrap().lines().rev().take(4).collect::<Vec<_>>() }));
                }
                panic!(
                    "paid delivery epoch={epoch} round={round} direction={source}->{destination}; states={states:?}"
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(600)).await;
    }
}

async fn measured_paid_traffic(configs: &[ServiceConfig], npubs: &[String]) {
    let attempts = configs[0].terms.billing == BillingBasis::ForwardingAttempt;
    let (packet_count, payload_bytes, packets_per_second) = if attempts {
        (6_000, 1_000, 600)
    } else {
        (6, 80, 10)
    };
    for (source, destination) in [(0, 4), (4, 0)] {
        let id = format!("{:032x}", source + 1);
        request(
            &configs[destination],
            &AdminRequest::ReceiveProbe {
                probe: ReceiveProbe {
                    source: npubs[source].clone(),
                    stream_id: id.clone(),
                    packet_count,
                    payload_bytes,
                    measure_one_way_latency: true,
                },
            },
        )
        .await
        .unwrap();
        let send = AdminRequest::SendProbe {
            probe: SendProbe {
                destination: npubs[destination].clone(),
                stream_id: id.clone(),
                packet_count,
                payload_bytes,
                packets_per_second,
            },
        };
        let concurrent = async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let second = request(&configs[source], &send).await.unwrap_err();
            assert!(second.contains("already running"));
            assert_eq!(
                request(&configs[source], &AdminRequest::Status)
                    .await
                    .unwrap()["npub"],
                npubs[source]
            );
        };
        let (sent, ()) = tokio::join!(request(&configs[source], &send), concurrent);
        let sent = sent.unwrap();
        assert_eq!(sent["probe"]["submitted_packets"], packet_count);
        assert!(sent["probe"]["stopped_reason"].is_null());
        assert!(sent["probe"]["elapsed_us"].as_u64().unwrap() >= 450_000);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status = request(&configs[destination], &AdminRequest::Status)
                    .await
                    .unwrap();
                if status["probe"]["unique_packets"] == packet_count {
                    assert_eq!(
                        status["probe"]["unique_bytes"],
                        u64::from(packet_count) * payload_bytes as u64
                    );
                    assert_eq!(status["probe"]["missing_packets"], 0);
                    assert_eq!(status["probe"]["duplicate_packets"], 0);
                    assert_eq!(status["probe"]["latency"]["samples"], packet_count);
                    assert_eq!(status["probe"]["latency"]["invalid_timestamps"], 0);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("paid probe delivery");
    }
}

async fn private_native_control(config: &ServiceConfig) {
    assert_eq!(
        std::fs::metadata(&config.state_directory)
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
    let response = native_request(config, &serde_json::json!({"command":"show_status"}))
        .await
        .unwrap();
    assert_eq!(response["status"], "ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn five_real_processes_preserve_paid_accounts_across_shutdown_and_router_crash() {
    five_process_run(BillingBasis::UniqueSessionEnvelope).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_customer_buys_long_paid_streams_and_recovers_without_static_enrollment() {
    five_process_run(BillingBasis::ForwardingAttempt).await;
}

async fn five_process_run(billing: BillingBasis) {
    tokio::time::timeout(Duration::from_secs(300), async {
        let root = tempfile::tempdir().unwrap();
        let _diagnostic_logs = DiagnosticLogs(root.path().to_path_buf());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let network = PaymentNetwork::new(95, 0, Arc::new(VirtualClock::new(now)));
        let mint = LocalMint::start(
            root.path(),
            network.clone(),
            "process-relay-test",
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
            cfg.terms.controller.channel_capacity_sat = 64;
            cfg.terms.controller.max_locked_sat = 128;
            cfg.terms.buyer_budget_sat = 128;
            cfg.terms.billing = billing;
            if billing == BillingBasis::ForwardingAttempt {
                cfg.terms.fee_msat_per_kib = 1;
                cfg.terms.quote_max_units = 64 * 1024 * 1024;
            }
            let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            cfg.udp_bind = Some(reservation.local_addr().unwrap());
            reservations.push(reservation);
            let path = directory.join("config.json");
            std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
            let initialized = command(&path, "init").await;
            assert!(
                initialized.status.success(),
                "{}",
                String::from_utf8_lossy(&initialized.stderr)
            );
            npubs.push(
                String::from_utf8(initialized.stdout)
                    .unwrap()
                    .trim()
                    .to_string(),
            );
            let wallet = cfg.state_directory.join("wallet");
            let quote = create_topup_quote(&wallet, mint.url(), 256).await.unwrap();
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
        let addresses: Vec<_> = configs.iter().map(|c| c.udp_bind.unwrap()).collect();
        for (i, cfg) in configs.iter_mut().enumerate() {
            cfg.neighbors = npubs
                .iter()
                .enumerate()
                .filter(|(j, _)| i.abs_diff(*j) == 1)
                .filter(|(j, _)| !(billing == BillingBasis::ForwardingAttempt && i == 1 && *j == 0))
                .map(|(j, p)| PeerConfig::new(p, "udp", addresses[j].to_string()))
                .collect();
            if billing == BillingBasis::ForwardingAttempt && i == 1 {
                cfg.customer_network = Some("127.0.0.1/32".parse().unwrap());
                assert!(cfg.neighbors.iter().all(|p| p.npub != npubs[0]));
            }
            std::fs::write(&paths[i], serde_json::to_vec(cfg).unwrap()).unwrap();
        }
        drop(reservations);
        let mut children = Vec::new();
        for path in &paths {
            children.push(start(path).await);
        }
        ready(&configs, &paths, &npubs, &mut children).await;
        for cfg in &configs {
            private_native_control(cfg).await;
        }
        if billing == BillingBasis::ForwardingAttempt {
            // Connected customer control is not a purchase or free data allowance.
            let _ = request(
                &configs[0],
                &AdminRequest::Send {
                    destination: npubs[4].clone(),
                    payload: "unpaid customer".into(),
                },
            )
            .await;
            tokio::time::sleep(Duration::from_millis(500)).await;
            for cfg in &configs {
                let status = request(cfg, &AdminRequest::Status).await.unwrap();
                assert_eq!(status["locked_sat"], 0);
                assert_eq!(status["remaining_budget_sat"], 128);
                assert!(status["purchases"].as_array().unwrap().is_empty());
                assert_eq!(status["received"]["packets"], 0);
            }
        }
        let forward_request = AdminRequest::Buy {
            destination: npubs[4].clone(),
        };
        let reverse_request = AdminRequest::Buy {
            destination: npubs[0].clone(),
        };
        let (forward, reverse) = tokio::join!(
            request(&configs[0], &forward_request),
            request(&configs[4], &reverse_request),
        );
        for purchase in [forward.unwrap(), reverse.unwrap()] {
            let contract: fips_relay::ledger::Contract =
                serde_json::from_value(purchase["purchase"]["contract"].clone()).unwrap();
            assert_eq!(contract.billing, billing);
        }
        deliver(&configs, &npubs, 1).await;
        measured_paid_traffic(&configs, &npubs).await;
        let mut before = Vec::new();
        for cfg in &configs {
            before.push(request(cfg, &AdminRequest::Status).await.unwrap());
        }
        for child in &mut children {
            stop(child).await;
        }
        if billing == BillingBasis::ForwardingAttempt {
            for cfg in &configs {
                for relative in ["seller/ledger.json", "buyer/buyer.json"] {
                    let path = cfg.state_directory.join(relative);
                    assert!(
                        std::fs::metadata(&path).unwrap().len() < 20_000,
                        "packet history must not grow with the 12,000 delivered packets"
                    );
                    let saved: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                    let records: Vec<_> = if relative.starts_with("seller") {
                        saved["ledger"]["accounts"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .collect()
                    } else {
                        saved["quotes"].as_object().unwrap().values().collect()
                    };
                    for r in records {
                        assert!(r["attempts"].as_array().unwrap().is_empty());
                    }
                }
            }
        }
        for (i, child) in children.iter_mut().enumerate() {
            *child = start(&paths[i]).await;
        }
        ready(&configs, &paths, &npubs, &mut children).await;
        for (cfg, old) in configs.iter().zip(&before) {
            let current = request(cfg, &AdminRequest::Status).await.unwrap();
            assert_eq!(current["npub"], old["npub"]);
            assert_eq!(
                current["history"], old["history"],
                "restart must preserve exact funded accounts"
            );
            assert_eq!(current["locked_sat"], old["locked_sat"]);
            assert!(
                current["remaining_budget_sat"].as_u64().unwrap()
                    <= old["remaining_budget_sat"].as_u64().unwrap()
            );
        }
        deliver(&configs, &npubs, 2).await;
        // Kill one real router without its shutdown checkpoints, retaining its disk.
        let prior = request(&configs[2], &AdminRequest::Status).await.unwrap();
        children[2].kill().await.unwrap();
        children[2] = start(&paths[2]).await;
        ready(&configs, &paths, &npubs, &mut children).await;
        let recovered = request(&configs[2], &AdminRequest::Status).await.unwrap();
        assert_eq!(recovered["history"], prior["history"]);
        assert_eq!(recovered["locked_sat"], prior["locked_sat"]);
        deliver(&configs, &npubs, 3).await;
        let mut reports = Vec::new();
        for (i, cfg) in configs.iter().enumerate() {
            let status = request(cfg, &AdminRequest::Status).await.unwrap();
            assert!(
                has_line_peers(&status, &npubs, i),
                "settlement must retain the intended peer path"
            );
            reports.push(request(cfg, &AdminRequest::Settle).await.unwrap());
        }
        assert_eq!(
            reports
                .iter()
                .map(|r| r["settlements"].as_array().unwrap().len())
                .sum::<usize>(),
            6
        );
        for child in &mut children {
            stop(child).await;
        }
        let redeemed = root.path().join("redeemed");
        let mut total = 0;
        for (i, cfg) in configs.iter().enumerate() {
            let wallet = cfg.state_directory.join("wallet");
            let balance = load_mint_balance(&wallet, mint.url())
                .await
                .unwrap()
                .balance_sat;
            total += balance;
            if (1..=3).contains(&i) {
                assert!(balance > 256, "router {i} must earn a positive net margin");
            }
            let token = send_payment_token(&wallet, mint.url(), balance)
                .await
                .unwrap();
            receive_payment_token(&redeemed, &token.token)
                .await
                .unwrap();
            assert_eq!(
                load_mint_balance(&wallet, mint.url())
                    .await
                    .unwrap()
                    .balance_sat,
                0
            );
        }
        assert_eq!(total, 1_280);
        assert_eq!(
            load_mint_balance(&redeemed, mint.url())
                .await
                .unwrap()
                .balance_sat,
            1_280
        );
        assert!(network.accounting().unwrap().is_conserved());
    })
    .await
    .expect("real-process restart test deadline");
}

async fn command(path: &Path, action: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_fips-relay"))
        .arg(action)
        .arg(path)
        .output()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_initialization_cannot_reset_missing_state_or_raise_saved_limits() {
    let root = tempfile::tempdir().unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let network = PaymentNetwork::new(94, 0, Arc::new(VirtualClock::new(now)));
    let mint = LocalMint::start(root.path(), network, "service-test", IssuerMode::ClosedLoop)
        .await
        .unwrap();
    let mut cfg = config(root.path(), mint.url());
    let path = root.path().join("config.json");
    std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
    assert!(
        !command(&path, "run").await.status.success(),
        "run must not initialize missing state"
    );
    let initialized = command(&path, "init").await;
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    assert!(
        !command(&path, "init").await.status.success(),
        "init must not overwrite existing accounts"
    );
    let mut running = start(&path).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while request(&cfg, &AdminRequest::Status).await.is_err() {
            assert!(running.try_wait().unwrap().is_none());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    private_native_control(&cfg).await;
    let mut native_cli = Command::new(env!("CARGO_BIN_EXE_fips-relay"))
        .args(["native", path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    {
        use tokio::io::AsyncWriteExt;
        let mut input = native_cli.stdin.take().unwrap();
        input
            .write_all(b"{\"command\":\"show_status\"}")
            .await
            .unwrap();
    }
    let native_reply = native_cli.wait_with_output().await.unwrap();
    assert!(native_reply.status.success());
    let native_reply: serde_json::Value = serde_json::from_slice(&native_reply.stdout).unwrap();
    assert_eq!(native_reply["status"], "ok");
    stop(&mut running).await;
    cfg.terms.buyer_budget_sat += 1;
    std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
    let changed = command(&path, "run").await;
    assert!(!changed.status.success());
    assert!(String::from_utf8_lossy(&changed.stderr).contains("saved terms"));
    cfg.terms.buyer_budget_sat -= 1;
    std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
    let native_path = cfg.state_directory.join("native.sock");
    std::fs::write(&native_path, b"retained operator file").unwrap();
    let occupied = command(&path, "run").await;
    assert!(!occupied.status.success());
    assert!(
        String::from_utf8_lossy(&occupied.stderr).contains("native control path is not a socket")
    );
    assert_eq!(
        std::fs::read(&native_path).unwrap(),
        b"retained operator file"
    );
    std::fs::remove_file(native_path).unwrap();
    std::fs::rename(
        cfg.state_directory.join("buyer/buyer.json"),
        root.path().join("buyer.saved"),
    )
    .unwrap();
    let missing = command(&path, "run").await;
    assert!(!missing.status.success());
    assert!(!cfg.state_directory.join("buyer/buyer.json").exists());
}
