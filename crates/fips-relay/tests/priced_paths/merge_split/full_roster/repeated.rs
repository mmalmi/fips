//! A second crowded encounter must reuse authority after native peer eviction.
use super::*;

#[path = "repeated/witness.rs"]
mod witness;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_full_rosters_recover_paid_routes_without_candidate_departures() {
    tokio::time::timeout(Duration::from_secs(480), Box::pin(exercise_repeated()))
        .await
        .expect("repeated full-roster encounters and collection deadline");
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
) -> Result<(), &'static str> {
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
        let start = Instant::now();
        bench.network.set_link_up("2", "3", true);
        tokio::time::timeout(Duration::from_secs(60), async {
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
            if let Some(previous) = previous_bridge {
                for (old, new) in previous.into_iter().zip(bridge) {
                    assert_ne!(old, new, "the departed bridge must authenticate again");
                }
            }
            previous_bridge = Some(bridge);
            for (source, destination, tag) in
                [(0, 5, 230 + encounter * 2), (5, 0, 231 + encounter * 2)]
            {
                traffic(bench, source, destination, tag).await;
            }
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
        .await
        .map_err(|_| "crowded encounter must resume delivery and all-hop credit within 60s")?;
    }
    Ok(())
}

async fn exercise_repeated() {
    let (mut bench, mut observer, anchor, candidates) = Box::pin(setup_crowded(
        126,
        Some(fips_core::config::NeighborRotationConfig {
            idle_secs: 10,
            interval_secs: 2,
        }),
    ))
    .await;
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
    let outcome = observer
        .during(async {
            tokio::select! {
                result = encounters(&mut bench, &anchor, &candidates) => result.map_err(str::to_owned),
                failure = monitor => Err(failure),
            }
        })
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
    collect_crowded(bench, observer, &anchor, candidates).await;
    assert!(outcome.is_ok(), "{outcome:?}; all test money collected");
}
