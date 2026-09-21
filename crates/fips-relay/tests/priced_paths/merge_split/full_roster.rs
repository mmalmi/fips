//! Stable full neighborhoods must find a bridge without a fixture-created vacancy.
use super::*;

#[path = "full_roster/local_traffic.rs"]
mod local_traffic;
use local_traffic::LocalTraffic;
#[path = "full_roster/repeated.rs"]
mod repeated;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_rosters_form_a_paid_bridge_without_forced_departure() {
    tokio::time::timeout(Duration::from_secs(480), Box::pin(exercise()))
        .await
        .expect("full-roster bridge and collection deadline");
}

fn local_progress(
    before: &BTreeMap<(usize, usize), HopUsage>,
    after: &BTreeMap<(usize, usize), HopUsage>,
    paid_before: &BTreeMap<String, u64>,
    paid_after: &BTreeMap<String, u64>,
) {
    for pair in [(0, 1), (5, 4)] {
        let old = &before[&pair];
        let current = &after[&pair];
        assert_eq!(current.channel, old.channel);
        assert!(current.evidence > old.evidence && current.submitted > old.submitted);
        assert!(paid_after[&current.channel] > paid_before[&old.channel]);
    }
}

async fn exercise() {
    let (mut bench, mut observer, anchor, candidates) = Box::pin(setup_crowded(
        125,
        Some(fips_core::config::NeighborRotationConfig {
            idle_secs: 10,
            interval_secs: 2,
        }),
    ))
    .await;
    assert!(occupied(&bench.nodes, &bench.peers, &candidates).await);
    let root = bench.root.path().to_owned();
    let nodes = bench.nodes.clone();
    let identities = bench.peers.clone();
    let gates = bench.gates.clone();
    let controllers = bench.controllers.clone();
    let buyer = bench.buyers[0].clone();
    let original_links = internal_links(&root, &nodes, &identities).await;
    let local_traffic = LocalTraffic::start(&bench).await;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(60);
    let mut rounds = 0;
    let mut bridge_observed_ms = None;
    let mut completion_ms = None;
    // This is the sole physical change during acceptance. All eight candidate
    // links remain available, including after native policy replaces a neighbor.
    bench.network.set_link_up("2", "3", true);
    let outcome = observer
        .during_checked(
            tokio::time::timeout_at(deadline, async {
                for round in 0..15 {
                    tokio::time::sleep_until(started + Duration::from_secs(round * 4)).await;
                    let before = hop_usage(&bench).await;
                    let paid_before = payments(&bench).await;
                    for (direction, (source, destination)) in
                        [(0, 2), (5, 3)].into_iter().enumerate()
                    {
                        traffic(
                            &mut bench,
                            source,
                            destination,
                            160 + round as u8 * 2 + direction as u8,
                        )
                        .await;
                    }
                    let paid_after = payments(&bench).await;
                    local_progress(&before, &hop_usage(&bench).await, &paid_before, &paid_after);
                    rounds += 1;
                    retain(&anchor, &accounts(&bench).await, true);
                    assert_watches(&bench).await;
                    // Exact topology requires the two-way authenticated bridge and
                    // working common tree, not merely discovery or a pending dial.
                    if topology(&bench, true).await {
                        bridge_observed_ms = Some(started.elapsed().as_millis());
                        let before = hop_usage(&bench).await;
                        let credited = payments(&bench).await;
                        for (source, destination, tag) in [(0, 5, 145), (5, 0, 146)] {
                            traffic(&mut bench, source, destination, tag).await;
                        }
                        fresh_hops(&before, &hop_usage(&bench).await);
                        let paid = payments(&bench).await;
                        assert_eq!(paid.len(), 8);
                        for (channel, prior) in credited {
                            assert!(paid[&channel] > prior);
                        }
                        retain(&anchor, &accounts(&bench).await, true);
                        assert_watches(&bench).await;
                        completion_ms = Some(started.elapsed().as_millis());
                        return;
                    }
                }
                // Exhausting the finite offered workload cannot become success.
                tokio::time::sleep_until(deadline).await;
                std::future::pending::<()>().await;
            }),
            || async {
                if let Some(failure) = local_traffic.failure() {
                    eprintln!("full-roster failure: {failure}");
                    local_traffic::capture_failure(
                        &root,
                        &identities,
                        &gates,
                        &controllers,
                        &buyer,
                    )
                    .await;
                    panic!("{failure}");
                }
                assert_eq!(
                    internal_links(&root, &nodes, &identities).await,
                    original_links,
                    "admission must preserve the original local paid link epochs"
                );
            },
        )
        .await;
    let automatic = outcome.is_ok() && completion_ms.is_some();
    local_traffic.stop().await;
    eprintln!(
        "full-roster encounter: automatic={automatic} local_paid_rounds={rounds} bridge_observed_ms={bridge_observed_ms:?} completed_ms={completion_ms:?} observation_ms={}",
        started.elapsed().as_millis()
    );
    assert!(
        rounds > 0,
        "the full-roster window must include real local paid progress"
    );
    retain(&anchor, &accounts(&bench).await, true);
    assert_watches(&bench).await;

    collect_crowded(bench, observer, &anchor, candidates).await;
    assert!(
        automatic,
        "full native rosters made no automatic paid bridge within 60s; all test money collected"
    );
}

async fn collect_crowded(
    bench: Bench,
    mut observer: Observer,
    anchor: &[Account],
    candidates: Vec<Candidate>,
) {
    // Restore reachability only after recording acceptance. Candidate departures
    // during collection cannot count as automatic admission or bridge recovery.
    bench.network.set_link_up("2", "3", true);
    for candidate in &candidates {
        bench
            .network
            .set_link_up(&candidate.address, candidate.bridge.to_string(), false);
    }
    observer
        .during(converge(&bench, true, "full-roster settlement cleanup"))
        .await;
    let paid = observer.during(payments(&bench)).await;
    retain(anchor, &accounts(&bench).await, true);
    assert_watches(&bench).await;
    for candidate in candidates {
        candidate.endpoint.shutdown().await.unwrap();
    }
    observer.settled().await;
    eprintln!(
        "full-roster encounter: {} native samples; maxima {:?}",
        observer.samples, observer.maxima
    );
    Box::pin(collect(bench, anchor, &paid)).await;
}
