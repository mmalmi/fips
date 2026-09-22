//! A second crowded encounter must reuse authority after native peer eviction.
use super::*;

#[path = "repeated/witness.rs"]
mod witness;

#[path = "repeated/loss.rs"]
mod loss;

#[path = "repeated/finite.rs"]
mod finite;

#[path = "repeated/payment_snapshot.rs"]
mod payment_snapshot;

#[derive(Clone, Copy, Debug)]
struct EncounterProfile {
    seed: u64,
    staged_root: bool,
    bridge_link: SimLink,
    finite_contacts: bool,
    post_split_absence: Duration,
}

impl EncounterProfile {
    fn baseline(staged_root: bool) -> Self {
        Self {
            seed: 126,
            staged_root,
            finite_contacts: false,
            post_split_absence: Duration::ZERO,
            bridge_link: SimLink {
                latency_ms: 2,
                ..Default::default()
            },
        }
    }
}

async fn run(profile: EncounterProfile) {
    eprintln!("repeated full-roster profile: {profile:?}");
    tokio::time::timeout(
        Duration::from_secs(480),
        Box::pin(exercise_repeated(profile)),
    )
    .await
    .expect("repeated full-roster encounters and collection deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_full_rosters_recover_paid_routes_without_candidate_departures() {
    run(EncounterProfile::baseline(false)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn root_change_full_rosters_recover_paid_routes_without_candidate_departures() {
    run(EncounterProfile::baseline(true)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_absence_reuses_paid_routes_with_full_rosters() {
    assert_eq!(Config::new().node.rate_limit.handshake_timeout_secs, 30);
    run(EncounterProfile {
        seed: 139,
        finite_contacts: true,
        post_split_absence: Duration::from_secs(31),
        ..EncounterProfile::baseline(false)
    })
    .await;
}

async fn crowded_split(bench: &Bench, candidates: &[Candidate]) -> bool {
    if !occupied(&bench.nodes, &bench.peers, candidates).await {
        return false;
    }
    let mut roots = Vec::new();
    for (component, boundary) in [(0..3, 2), (3..6, 3)] {
        let mut root = None;
        for node in component.clone() {
            let state = tree(bench, node).await;
            let actual = state["root"].as_str().unwrap().to_owned();
            let local = component
                .clone()
                .any(|i| bench.peers[i].node_addr().to_string() == actual)
                || candidates.iter().any(|candidate| {
                    candidate.bridge == boundary && candidate.peer.node_addr().to_string() == actual
                });
            if !local || root.as_ref().is_some_and(|expected| *expected != actual) {
                return false;
            }
            root = Some(actual);
        }
        roots.push(root.unwrap());
    }
    // occupied() requires the internal peer plus an authenticated candidate at
    // each boundary, leaving no slot for a retained cross-component peer.
    roots[0] != roots[1]
}

async fn bridge_epochs(bench: &Bench) -> Option<[(u64, u64); 2]> {
    let mut epochs = [(0, 0); 2];
    for (direction, (node, remote)) in [(2, 3), (3, 2)].into_iter().enumerate() {
        let reply = native_query(bench.root.path(), node, "show_peers").await;
        let peer = reply["peers"].as_array().unwrap().iter().find(|peer| {
            peer["npub"] == bench.peers[remote].npub() && peer["connectivity"] == "connected"
        })?;
        epochs[direction] = (
            peer["link_id"].as_u64().unwrap(),
            peer["authenticated_at_ms"].as_u64().unwrap(),
        );
    }
    Some(epochs)
}

async fn encounters(
    bench: &mut Bench,
    anchor: &[Account],
    candidates: &[Candidate],
    profile: EncounterProfile,
) -> Result<(), &'static str> {
    let staged_root = profile.staged_root;
    let mut previous_bridge: Option<[(u64, u64); 2]> = None;
    let mut checkpoint = anchor.to_vec();
    for encounter in 0..2 {
        if encounter > 0 {
            let start = Instant::now();
            bench.network.set_link_up("2", "3", false);
            tokio::time::timeout(Duration::from_secs(60), async {
                while !crowded_split(bench, candidates).await {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                no_cross_delivery(bench, 220).await;
            })
            .await
            .map_err(|_| "split must evict the bridge and refill both rosters within 60s")?;
            eprintln!(
                "repeated full-roster split_ms={}",
                start.elapsed().as_millis()
            );
            hold_split(bench, profile.post_split_absence).await;
            let current = accounts(bench).await;
            retain(&checkpoint, &current, true);
            checkpoint = current;
            assert_watches(bench).await;
        }
        let before = hop_usage(bench).await;
        // Outstanding bridge usage cannot be acknowledged while partitioned.
        // Snapshot credited amounts now; reconcile supported usage after join.
        let credited: BTreeMap<_, _> = before
            .iter()
            .map(|((_, seller), usage)| {
                let paid = bench.sellers[*seller]
                    .channel_usage(&usage.channel)
                    .unwrap()
                    .paid_msat;
                (usage.channel.clone(), paid)
            })
            .collect();
        assert!(occupied(&bench.nodes, &bench.peers, candidates).await);
        assert!(bridge_epochs(bench).await.is_none());
        if encounter == 0 && staged_root {
            let root = candidates
                .iter()
                .find(|c| c.address == "candidate-2-1")
                .unwrap();
            let root_addr = root.peer.node_addr().to_string();
            for node in 0..3 {
                assert_eq!(tree(bench, node).await["root"], root_addr);
            }
            let peers = bench.nodes[2].peers().await.unwrap();
            assert!(
                peers
                    .iter()
                    .any(|p| p.node_addr == *root.peer.node_addr() && p.connected)
            );
        }
        // Opt-in passive queries can perturb scheduling; retain ordinary runs
        // as the acceptance evidence for latency and bounded admission.
        let timing = if std::env::var("FIPS_CROWDED_TIMING").as_deref() == Ok("1") {
            Some(timing::Timing::start(bench, "crowded").await)
        } else {
            None
        };
        let network_before = bench.network.stats();
        let start = if profile.finite_contacts && encounter == 0 {
            // No bridge is established before these independently timed cuts.
            // Cohort draining consumes part of the same sustained-contact limit.
            finite::contacts(bench, &checkpoint, false).await.last_up()
        } else {
            Instant::now()
        };
        eprintln!(
            "repeated full-roster exposure: {}",
            serde_json::json!({
                "encounter": encounter,
                "observed_unix_ms": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(),
                "elapsed_since_opening_ms": start.elapsed().as_millis(),
                "nodes": bench.peers.iter().map(|peer| peer.node_addr().to_string()).collect::<Vec<_>>()
            })
        );
        if encounter == 0 && staged_root {
            // This controlled setup differs from the original startup race.
            // All competitors remain present from exposure through acceptance.
            for candidate in candidates {
                bench
                    .network
                    .set_link_up(&candidate.address, candidate.bridge.to_string(), true);
            }
        }
        if !profile.finite_contacts || encounter > 0 {
            bench.network.set_link_up("2", "3", true);
        }
        if let Some(timing) = &timing {
            timing.mark(&format!("encounter_{encounter}_exposure_observed"));
        }
        let recovered = tokio::time::timeout_at(start + Duration::from_secs(60), async {
            let mut first_bridge_ms = None;
            loop {
                if first_bridge_ms.is_none() && bridge_epochs(bench).await.is_some() {
                    first_bridge_ms = Some(start.elapsed().as_millis());
                    eprintln!("repeated full-roster encounter={encounter} first_bridge_ms={first_bridge_ms:?}");
                }
                if topology(bench, true).await {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            let tree_ms = start.elapsed().as_millis();
            let bridge = bridge_epochs(bench).await.unwrap();
            first_bridge_ms.get_or_insert(start.elapsed().as_millis());
            eprintln!("repeated full-roster encounter={encounter} tree_ms={tree_ms}");
            if let Some(timing) = &timing {
                timing.mark("tree_converged");
            }
            if let Some(previous) = previous_bridge {
                for (old, new) in previous.into_iter().zip(bridge) {
                    assert_ne!(old, new, "the departed bridge must authenticate again");
                }
            }
            previous_bridge = Some(bridge);
            payment_snapshot::capture(bench, "before_fresh_traffic", Some(encounter)).await;
            for (source, destination, tag) in
                [(0, 5, 230 + encounter * 2), (5, 0, 231 + encounter * 2)]
            {
                if let Some(timing) = &timing {
                    timing.mark(&format!("traffic_{source}_{destination}_started"));
                }
                traffic(bench, source, destination, tag).await;
                if let Some(timing) = &timing {
                    timing.mark(&format!("traffic_{source}_{destination}_delivered"));
                }
            }
            payment_snapshot::capture(bench, "after_fresh_traffic", Some(encounter)).await;
            let delivery_ms = start.elapsed().as_millis();
            let paid = payments(bench).await;
            fresh_hops(&before, &hop_usage(bench).await);
            assert_eq!(paid.len(), 8);
            for (channel, prior) in &credited {
                assert!(paid[channel] > *prior, "every original hop must earn again");
            }
            let current = accounts(bench).await;
            retain(&checkpoint, &current, true);
            checkpoint = current;
            assert_watches(bench).await;
            eprintln!(
                "repeated full-roster encounter={encounter} bridge_ms={first_bridge_ms:?} tree_ms={tree_ms} delivery_ms={delivery_ms} credited_ms={}",
                start.elapsed().as_millis()
            );
        })
        .await;
        if let Some(timing) = timing {
            timing.mark("recovery_wait_finished");
            timing.finish(recovered.is_ok()).await;
        }
        recovered
            .map_err(|_| "crowded encounter must resume delivery and all-hop credit within 60s")?;
        let network = bench.network.stats().delta_since(&network_before);
        eprintln!(
            "repeated full-roster network: {}",
            serde_json::json!({
                "encounter":encounter, "seed":profile.seed,
                "bridge_link":profile.bridge_link, "counters":network,
            })
        );
        if profile.bridge_link.loss_probability > 0.0 && network.packets_dropped_loss == 0 {
            return Err("lossy encounter must observe actual transport loss before acceptance");
        }
        if profile.finite_contacts && encounter == 0 {
            finite::contacts(bench, &checkpoint, true).await;
        }
    }
    Ok(())
}

async fn hold_split(bench: &Bench, duration: Duration) {
    if duration.is_zero() {
        return;
    }
    // crowded_split already observed both former owners removed and both
    // rosters refilled. Keep the physical link down beyond the former history
    // expiry; the outer monitors continue local traffic and all resource checks.
    let start = Instant::now();
    loop {
        for (boundary, remote) in [(2, 3), (3, 2)] {
            assert!(
                bench.nodes[boundary]
                    .peers()
                    .await
                    .unwrap()
                    .iter()
                    .all(|peer| peer.node_addr != *bench.peers[remote].node_addr()),
                "an absent bridge must not regain an authenticated owner"
            );
        }
        if start.elapsed() >= duration {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    eprintln!(
        "repeated full-roster absence after owner removal_ms={}",
        start.elapsed().as_millis()
    );
}

async fn exercise_repeated(profile: EncounterProfile) {
    let (mut bench, mut observer, anchor, candidates) = Box::pin(setup_crowded_with_staged_root(
        profile.seed,
        Some(fips_core::config::NeighborRotationConfig {
            idle_secs: 10,
            interval_secs: 2,
        }),
        profile.staged_root,
    ))
    .await;
    bench.network.set_link(
        "2",
        "3",
        SimLink {
            up: false,
            ..profile.bridge_link
        },
    );
    let root = bench.root.path().to_owned();
    let nodes = bench.nodes.clone();
    let identities = bench.peers.clone();
    let gates = bench.gates.clone();
    let controllers = bench.controllers.clone();
    let buyer = bench.buyers[0].clone();
    let mut witness = witness::BridgeWitness::new(&identities);
    let original_links =
        internal_links_observed(&root, &nodes, &identities, |node, a, b, reply| {
            witness.observe(node, a, b, reply);
        })
        .await;
    // One bounded 256-byte/s stream in each component persists through both
    // encounters and the split. It needs no extra funding or enlarged offers.
    let local = LocalTraffic::with_payload_len(&bench, 256).await;
    let monitor = async {
        loop {
            if let Some(failure) = local.failure() {
                return failure;
            }
            if internal_links_observed(&root, &nodes, &identities, |node, a, b, reply| {
                witness.observe(node, a, b, reply);
            })
            .await
                != original_links
            {
                return "an original boundary-to-internal link changed during an encounter".into();
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    };
    let outcome = catch_encounter(observer.during(async {
            tokio::select! {
                result = encounters(&mut bench, &anchor, &candidates, profile) => result.map_err(str::to_owned),
                failure = monitor => Err(failure),
            }
        }))
        .await;
    let outcome = outcome.and(
        (internal_links_observed(&root, &nodes, &identities, |node, a, b, reply| {
            witness.observe(node, a, b, reply);
        })
        .await
            == original_links)
            .then_some(())
            .ok_or_else(|| {
                "an original boundary-to-internal link changed during an encounter".into()
            }),
    );
    if let Err(reason) = &outcome {
        payment_snapshot::capture(&bench, "failure_before_drain", None).await;
        eprintln!("repeated full-roster bridge witness: {}", witness.summary());
        eprintln!("repeated full-roster failure before drain: {reason}");
        eprintln!(
            "repeated full-roster carrier snapshot: {}",
            local.snapshot()
        );
        local_traffic::capture_failure(&root, &identities, &gates, &controllers, &buyer).await;
    }
    // Keep a failure as failure while restoring reachability for collection.
    // Stopping the independent pump must not unwind before settlement runs.
    let outcome = outcome.and(local.finish().await);
    if let Err(reason) = &outcome {
        eprintln!("repeated full-roster outcome: {reason}");
        local_traffic::capture_failure(&root, &identities, &gates, &controllers, &buyer).await;
    }
    // Faults remain active throughout acceptance, including payment recovery.
    // Only the separate collection phase restores a reliable carrier.
    bench
        .network
        .set_link("2", "3", EncounterProfile::baseline(false).bridge_link);
    collect_crowded(bench, observer, &anchor, candidates).await;
    assert!(outcome.is_ok(), "{outcome:?}; all test money collected");
}

/// Retain failed assertions so test-money collection still runs before failure.
async fn catch_encounter(
    operation: impl Future<Output = Result<(), String>>,
) -> Result<(), String> {
    tokio::pin!(operation);
    std::future::poll_fn(|cx| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| operation.as_mut().poll(cx)))
        {
            Ok(result) => result,
            Err(panic) => std::task::Poll::Ready(Err(panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| {
                    panic
                        .downcast_ref::<&str>()
                        .map(|message| (*message).to_owned())
                })
                .unwrap_or_else(|| "non-string encounter assertion".into()))),
        }
    })
    .await
}
