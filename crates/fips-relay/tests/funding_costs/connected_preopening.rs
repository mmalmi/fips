//! Quote expiry must release a pending Watch without a native peer departure.
use super::{preopening_support::*, restore::*, *};
use cashu_service::{simulation::MintProxy, spilman_client_store_path};
use fips_relay::service::ServiceConfig;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

fn connected_link(status: &Value, peer: &str) -> Option<Value> {
    status["peers"]
        .as_array()?
        .iter()
        .find(|p| p["npub"] == peer && p["connected"] == true)?
        .get("link_id")
        .filter(|id| !id.is_null())
        .cloned()
}

async fn source_and_provider(configs: &[ServiceConfig]) -> Result<[Value; 2], String> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let (source, provider) = tokio::try_join!(
            request(&configs[0], &AdminRequest::Status),
            request(&configs[1], &AdminRequest::Status),
        )?;
        Ok([source, provider])
    })
    .await
    .map_err(|_| "bounded connected-pair status timed out".to_owned())?
}

fn same_links(status: &[Value; 2], npubs: &[String], links: &[Value; 2]) -> bool {
    connected_link(&status[0], &npubs[1]).as_ref() == Some(&links[0])
        && connected_link(&status[1], &npubs[0]).as_ref() == Some(&links[1])
}

#[derive(Default)]
struct DirectProgress {
    rounds: u64,
    verified_at: Option<tokio::time::Instant>,
    failed: bool,
}

struct DirectTraffic {
    progress: Arc<Mutex<DirectProgress>>,
    job: tokio::task::JoinHandle<()>,
}

impl DirectTraffic {
    fn start(configs: &[ServiceConfig], npubs: &[String]) -> Self {
        let configs = configs[..2].to_vec();
        let npubs = npubs[..2].to_vec();
        let progress = Arc::new(Mutex::new(DirectProgress::default()));
        let recorded = progress.clone();
        let job = tokio::spawn(async move {
            let mut cadence = tokio::time::interval(Duration::from_secs(1));
            cadence.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut sequence = 0;
            loop {
                cadence.tick().await;
                sequence += 1;
                let result = tokio::time::timeout(
                    Duration::from_secs(3),
                    direct_exchange(&configs, &npubs, sequence),
                )
                .await;
                let mut progress = recorded.lock().unwrap();
                if !matches!(result, Ok(Ok(()))) {
                    progress.failed = true;
                    return;
                }
                progress.rounds += 1;
                progress.verified_at = Some(tokio::time::Instant::now());
            }
        });
        Self { progress, job }
    }

    fn fresh(&self) -> bool {
        let progress = self.progress.lock().unwrap();
        !progress.failed
            && progress
                .verified_at
                .is_some_and(|at| at.elapsed() < Duration::from_secs(3))
    }

    async fn stop(&mut self) {
        self.job.abort();
        let _ = (&mut self.job).await;
    }
}

impl Drop for DirectTraffic {
    fn drop(&mut self) {
        self.job.abort();
    }
}

async fn direct_exchange(
    configs: &[ServiceConfig],
    npubs: &[String],
    sequence: u64,
) -> Result<(), String> {
    // Final-neighbor traffic has no relay purchase. Only fresh application
    // receipt, never the Send command's queue acknowledgment, proves activity.
    let payloads = [
        format!("expiry-link-{sequence}-forward"),
        format!("expiry-link-{sequence}-reverse"),
    ];
    let digests = payloads
        .each_ref()
        .map(|p| format!("{:x}", Sha256::digest(p.as_bytes())));
    let forward = AdminRequest::Send {
        destination: npubs[1].clone(),
        payload: payloads[0].clone(),
    };
    let reverse = AdminRequest::Send {
        destination: npubs[0].clone(),
        payload: payloads[1].clone(),
    };
    tokio::try_join!(
        request(&configs[0], &forward),
        request(&configs[1], &reverse)
    )?;
    loop {
        let status = source_and_provider(configs).await?;
        if status[0]["received"]["last_sha256"] == digests[1]
            && status[1]["received"]["last_sha256"] == digests[0]
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn authority_unchanged(current: &Value, original: &OriginalSend, destination: &str) -> bool {
    let mut watch = current["watched_routes"][destination].clone();
    let mut before = original.controller["watched_routes"][destination].clone();
    watch["pending"] = Value::Null;
    before["pending"] = Value::Null;
    current["next_funding"] == original.controller["next_funding"]
        && current["policy"] == original.controller["policy"]
        && entries(current, "watched_routes") == 1
        && watch == before
        && current["outgoing"].as_object().unwrap().is_empty()
        && current["funding"]
            .as_object()
            .unwrap()
            .iter()
            .all(|(id, intent)| {
                id == &original.intent_id
                    && funding_authority(intent) == original.intent
                    && intent["funded"].is_null()
            })
        && current["history"]["channels"]["totals"]["channels"]
            .as_u64()
            .unwrap_or(0)
            == 0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_preparation_reply_recovers_after_expiry_with_continuously_connected_provider() {
    tokio::time::timeout(Duration::from_secs(240), async {
        let root = tempfile::tempdir().unwrap();
        let (mint, network) = setup::start_mint(root.path(), 9624).await;
        let proxy = MintProxy::start(mint.url()).await;
        // Keep the existing single-funding lifetime allowance. Ten seconds gives
        // the held real preparation time for positive observations before expiry.
        let setup::Bench { mint, configs, paths: _, npubs, mut children } =
            setup::start_nodes_with_funding_limit(root.path(), mint, network,
                &proxy.url, 60, 10, 48).await;
        let cfg = &configs[0];
        let wallet = cfg.state_directory.join("wallet");
        let store = spilman_client_store_path(&wallet);
        let journal = cfg.state_directory.join("controller/controller.json");
        let mut direct = DirectTraffic::start(&configs, &npubs);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !direct.fresh() {
                assert!(!direct.progress.lock().unwrap().failed,
                    "direct-neighbor fixture warmup must deliver both fresh payloads");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.expect("bounded direct-neighbor application warmup");
        let initial = source_and_provider(&configs).await.unwrap();
        let links = [connected_link(&initial[0], &npubs[1]).unwrap(),
            connected_link(&initial[1], &npubs[0]).unwrap()];
        let initial_funding: Vec<_> = configs.iter().map(|c|
            read(&c.state_directory.join("controller/controller.json"))["next_funding"].clone()).collect();
        let pids: Vec<_> = children.iter().map(|child| child.id()).collect();
        let keyset = mint.mint().rotate_keyset("sat".parse().unwrap(),
            (0..=10).map(|bit| 1u64 << bit).collect(), 500, false, None).await.unwrap().id;
        let retained = store.clone();
        let matched = Arc::new(Mutex::new(None));
        let capture = matched.clone();
        let seen = Arc::new(AtomicUsize::new(0));
        let inspected = seen.clone();
        let swaps = proxy.state.swaps.load(Ordering::SeqCst);
        let (committed, release) = proxy.state.pause_matching_swap_reply(move |wire| {
            preparation_match(&retained, &capture, &inspected, wire)
        });
        let owner = cfg.clone();
        let destination = npubs[2].clone();
        let mut buying = tokio::spawn(async move {
            request(&owner, &AdminRequest::Watch {
                destination, max_rate_msat_per_kib: 8192,
            }).await
        });
        let captured = tokio::select! {
            signal = committed => signal.is_ok(),
            _ = &mut buying => false,
            _ = tokio::time::sleep(Duration::from_secs(30)) => false,
        };
        let original = if captured {
            inspect_original(cfg, &keyset.to_string(), &matched).await
        } else {
            Err("exact committed preparation boundary absent")
        };
        let original = match original {
            Ok(original) => original,
            Err(error) => {
                let _ = release.send(());
                direct.stop().await;
                let conserved = cleanup_wallet_sends(&configs, &mut children, &proxy).await;
                buying.abort();
                if !conserved { let _ = root.keep(); }
                panic!("connected preparation premise: {error}; conserved={conserved}");
            }
        };
        let offer = original.controller["watched_routes"][&npubs[2]]["pending"].clone();
        let offer_id = offer["id"].as_str().unwrap();
        let expiry = offer["expires_unix"].as_u64().unwrap();
        let mut errors = Vec::new();
        check(&mut errors, entries(&original.controller, "requested") == 1
            && original.controller["requested"][offer_id] == offer
            && original.controller["watched_routes"][&npubs[2]]["paused"] == false,
            "the pending Watch did not own its exact original offer");
        check(&mut errors, proxy.state.swaps.load(Ordering::SeqCst) == swaps + 1,
            "preparation was not the sole committed swap");
        let mut before_expiry = false;
        let mut after_expiry = false;
        let mut samples = 0;
        let mut fenced = false;
        // Preserve the live source and native link epochs. Before release there
        // is no reply loss, admin pause, restart, or peer-disconnection shortcut.
        loop {
            let started = now();
            let status = source_and_provider(&configs).await;
            let current = read(&journal);
            let timestamp = now();
            let connected = status.as_ref().is_ok_and(|s| same_links(s, &npubs, &links));
            check(&mut errors, connected, "native connection or link epoch changed across expiry");
            check(&mut errors, direct.fresh(), "fresh bidirectional direct data stopped across expiry");
            check(&mut errors, children.iter_mut().zip(&pids).all(|(child, pid)|
                child.id() == *pid && child.try_wait().unwrap().is_none()),
                "an original daemon exited during connected expiry");
            check(&mut errors, authority_unchanged(&current, &original, &npubs[2]),
                "held preparation changed the original financial or Watch authority");
            let pending = &current["watched_routes"][&npubs[2]]["pending"];
            let withdrawn = current["recovery_only"].as_array().unwrap().iter().any(|id| id == offer_id);
            check(&mut errors, *pending == offer || (pending.is_null() && withdrawn),
                "held Watch neither retained nor atomically fenced its exact offer");
            fenced |= withdrawn;
            before_expiry |= connected && direct.fresh() && timestamp < expiry && *pending == offer;
            after_expiry |= connected && direct.fresh() && started > expiry;
            samples += 1;
            if started > expiry { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        check(&mut errors, before_expiry && after_expiry,
            "missing positive connected observations bracketing actual quote expiry");
        // The pinned HTTP client treats this explicit 503 as terminal, retaining
        // the Confirming operation. No replay-blocking fault affects its refund.
        proxy.state.lose_swap_reply.store(true, Ordering::SeqCst);
        let released = release.send(()).is_ok();
        let failed_reply = matches!(tokio::time::timeout(Duration::from_secs(15), &mut buying).await,
            Ok(Ok(Err(_))));
        check(&mut errors, released && failed_reply
            && !proxy.state.lose_swap_reply.load(Ordering::SeqCst),
            "the live original Watch did not receive the injected committed-reply error");
        proxy.state.lose_swap_reply.store(false, Ordering::SeqCst);
        let allowance = cfg.terms.controller.channel_capacity_sat + 1
            ..=cfg.terms.controller.max_wallet_spend_sat;
        let mut automatic = false;
        let mut fresh_quote = false;
        let mut last_status = Value::Null;
        while now() <= original.request.expiry_unix + 15 {
            let current = read(&journal);
            let sdk = read(&store);
            check(&mut errors, authority_unchanged(&current, &original, &npubs[2]),
                "connected recovery changed authority or allocated replacement funding");
            check(&mut errors, entries(&sdk, "openings") == 0 && entries(&sdk, "funding") == 0,
                "connected preparation recovery opened a channel");
            check(&mut errors, children.iter_mut().zip(&pids).all(|(child, pid)|
                child.id() == *pid && child.try_wait().unwrap().is_none()),
                "an original daemon exited during connected recovery");
            fenced |= current["recovery_only"].as_array().unwrap().iter().any(|id| id == offer_id);
            let pending = &current["watched_routes"][&npubs[2]]["pending"];
            fresh_quote |= !pending.is_null() && pending["id"] != offer_id;
            if let Ok(status) = source_and_provider(&configs).await {
                let connected = same_links(&status, &npubs, &links);
                check(&mut errors, connected, "connected recovery lost its original native links");
                check(&mut errors, direct.fresh(), "fresh bidirectional direct data stopped during recovery");
                check(&mut errors, status[0]["purchases"].as_array().unwrap().is_empty()
                    && status[0]["remaining_budget_sat"] == cfg.terms.buyer_budget_sat,
                    "expired preparation gained purchase or buyer authority");
                automatic = connected && direct.fresh() && fenced && terminal_refund(&current, &status[0],
                    &original.intent_id, &original.operation, &allowance);
                if automatic {
                    let budget = &status[0]["funding_budget"];
                    automatic = spendable_balance(&wallet, &proxy.url).await ==
                        128 - budget["wallet_debited_sat"].as_u64().unwrap()
                            + budget["wallet_refunded_sat"].as_u64().unwrap();
                }
                last_status = status[0].clone();
                samples += 1;
            } else {
                check(&mut errors, false, "connected recovery status became unavailable");
            }
            if automatic { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let sends = send_journal(&wallet).await;
        check(&mut errors, request_count(&sends) == 1, "a replacement wallet send was created");
        if let Some(saved) = sends["entries"].get(&original.send_id) {
            check(&mut errors, saved["request"] == original.entry["request"]
                && saved["plan"] == original.entry["plan"], "the original wallet request or plan changed");
        }
        let mut available = 0;
        for (index, config) in configs.iter().enumerate() {
            let balance = spendable_balance(&config.state_directory.join("wallet"), &proxy.url).await;
            check(&mut errors, if index == 0 { balance <= 128 } else { balance == 128 },
                "unrelated wallet balance changed or source gained unissued funds");
            if index != 0 {
                check(&mut errors, read(&config.state_directory.join("controller/controller.json"))["next_funding"]
                    == initial_funding[index], "an unrelated daemon funded a channel");
            }
            available += balance;
        }
        if automatic {
            check(&mut errors, available + proxy.state.fees_collected.load(Ordering::SeqCst) == 384,
                "automatic recovery did not conserve all test funds before cleanup");
        }
        check(&mut errors, automatic,
            "connected expired Watch retained original uncertain funding; cleanup is not autonomous recovery");
        eprintln!("connected-preparation automatic={automatic} fenced={fenced} before_expiry={before_expiry} after_expiry={after_expiry} fresh_quote={fresh_quote} samples={samples} direct_rounds={} spendable_sat={available} fees_sat={} budget={}",
            direct.progress.lock().unwrap().rounds, proxy.state.fees_collected.load(Ordering::SeqCst), last_status["funding_budget"]);
        // Acceptance is fixed before administrative settlement or the shared
        // exact-original-send rescue. No process was stopped during observation.
        direct.stop().await;
        let conserved = cleanup_wallet_sends(&configs, &mut children, &proxy).await;
        buying.abort();
        check(&mut errors, conserved, "failed-run cleanup did not conserve 384 test sats including fees");
        let final_sends = send_journal(&wallet).await;
        check(&mut errors, request_count(&final_sends) == 1
            && read(&journal)["next_funding"] == original.controller["next_funding"],
            "cleanup allocated replacement financial authority");
        if !conserved { let _ = root.keep(); }
        assert!(errors.is_empty(), "connected preparation recovery: {errors:?}");
    }).await.expect("bounded live connected-offer expiry and test-money cleanup");
}
