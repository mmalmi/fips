//! Single-attempt traffic during short contacts, with fresh paid recovery probes.
use super::*;
use fips_core::{FipsEndpointServiceDatagram, FipsEndpointServiceReceiver};
use tokio::task::JoinSet;

const WARM: &[(u64, bool)] = &[
    (1_000, false),
    (2_000, true),
    (3_500, false),
    (6_500, true),
    (8_000, false),
    (10_000, true),
];
const COLD: &[(u64, bool)] = &[
    (1_000, true),
    (1_400, false),
    (2_300, true),
    (3_800, false),
    (4_500, true),
    (4_800, false),
    (5_400, true),
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brief_mesh_contacts_preserve_authority_and_recover_original_paid_routes() {
    tokio::time::timeout(Duration::from_secs(480), exercise_brief())
        .await
        .expect("brief paid mesh encounters and collection deadline");
}

#[derive(Default)]
struct Progress {
    sent: [AtomicU64; 2],
    received: [AtomicU64; 2],
}

#[derive(Debug)]
struct Event {
    planned_ms: u64,
    actual_ms: u64,
    up: bool,
    sent: [u64; 2],
    received: [u64; 2],
}

#[derive(Default)]
struct Cohort {
    sent: [Vec<u64>; 2],
    received: [BTreeMap<u8, u64>; 2],
    duplicates: [usize; 2],
}

#[derive(Clone, Copy)]
struct CohortPlan {
    start: Instant,
    port: u16,
    tag: u8,
    count: usize,
}

enum Finished {
    Flaps(Vec<Event>),
    Traffic(Cohort),
}

async fn flap(
    network: SimNetwork,
    start: Instant,
    schedule: &'static [(u64, bool)],
    progress: Arc<Progress>,
) -> Vec<Event> {
    let mut events = Vec::new();
    for &(planned_ms, up) in schedule {
        tokio::time::sleep_until(start + Duration::from_millis(planned_ms)).await;
        network.set_link_up("2", "3", up);
        let event = Event {
            planned_ms,
            actual_ms: start.elapsed().as_millis() as u64,
            up,
            sent: std::array::from_fn(|i| progress.sent[i].load(Ordering::Relaxed)),
            received: std::array::from_fn(|i| progress.received[i].load(Ordering::Relaxed)),
        };
        assert!(event.actual_ms >= event.planned_ms);
        assert!(
            event.actual_ms - event.planned_ms < 500,
            "late mesh mutation: {event:?}"
        );
        events.push(event);
    }
    events
}

fn record(
    result: &mut Cohort,
    batch: &[FipsEndpointServiceDatagram],
    direction: usize,
    expected: PeerIdentity,
    plan: CohortPlan,
    progress: &Progress,
) {
    let CohortPlan {
        start, tag, count, ..
    } = plan;
    for message in batch {
        assert_eq!(message.source_peer.node_addr(), expected.node_addr());
        let bytes = message.data.as_slice();
        assert_eq!(bytes.len(), 256);
        assert!(bytes[1..].iter().all(|&b| b == tag + direction as u8));
        assert!((bytes[0] as usize) < count);
        if result.received[direction]
            .insert(bytes[0], start.elapsed().as_millis() as u64)
            .is_some()
        {
            result.duplicates[direction] += 1;
        } else {
            progress.received[direction].fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn cohort(
    nodes: [Arc<FipsEndpoint>; 2],
    peers: [PeerIdentity; 2],
    receivers: [FipsEndpointServiceReceiver; 2],
    progress: Arc<Progress>,
    plan: CohortPlan,
) -> Cohort {
    let CohortPlan {
        start,
        port,
        tag,
        count,
    } = plan;
    let mut result = Cohort::default();
    let mut batches = [Vec::new(), Vec::new()];
    let [left, right] = &mut batches;
    let deadline = start + Duration::from_millis((count as u64 - 1) * 250 + 5_000);
    let mut sent = 0;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(start + Duration::from_millis(sent as u64 * 250)), if sent < count => {
                for direction in 0..2 {
                    let mut payload = vec![tag + direction as u8; 256];
                    payload[0] = sent as u8;
                    nodes[direction].send_datagram(peers[1 - direction], port, port, payload).await.unwrap();
                    result.sent[direction].push(start.elapsed().as_millis() as u64);
                    progress.sent[direction].fetch_add(1, Ordering::Relaxed);
                }
                sent += 1;
            }
            found = receivers[1].recv_batch_into(left, 64) => {
                assert!(found.is_some(), "forward cohort receiver closed");
                record(&mut result, left, 0, peers[0], plan, &progress);
            }
            found = receivers[0].recv_batch_into(right, 64) => {
                assert!(found.is_some(), "reverse cohort receiver closed");
                record(&mut result, right, 1, peers[1], plan, &progress);
            }
            _ = tokio::time::sleep_until(deadline) => break,
        }
    }
    assert_eq!(
        sent, count,
        "the finite cohort must continue through each cut"
    );
    result
}

async fn bridge(bench: &Bench) -> Option<[(u64, u64); 2]> {
    let mut result = [(0, 0); 2];
    for (direction, (node, remote)) in [(2, 3), (3, 2)].into_iter().enumerate() {
        if !bench.nodes[node]
            .peers()
            .await
            .unwrap()
            .iter()
            .any(|peer| peer.connected && peer.node_addr == *bench.peers[remote].node_addr())
        {
            return None;
        }
        let peers = native_query(bench.root.path(), node, "show_peers").await;
        let peer = peers["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["npub"] == bench.peers[remote].npub())?;
        assert_eq!(peer["transport_type"], "sim");
        result[direction] = (
            peer["link_id"].as_u64().unwrap(),
            peer["authenticated_at_ms"].as_u64().unwrap(),
        );
    }
    Some(result)
}

async fn interrupted(
    bench: &Bench,
    observer: &mut Observer,
    anchor: &[Account],
    warm: bool,
) -> Instant {
    let nodes = [bench.nodes[0].clone(), bench.nodes[5].clone()];
    let peers = [bench.peers[0], bench.peers[5]];
    let (port, tag, count, schedule) = if warm {
        (44_750, 150, 64, WARM)
    } else {
        (44_751, 160, 32, COLD)
    };
    let receivers = [
        nodes[0].register_service_receiver(port).await.unwrap(),
        nodes[1].register_service_receiver(port).await.unwrap(),
    ];
    let original_bridge = if warm {
        Some(bridge(bench).await.unwrap())
    } else {
        None
    };
    let before = bench.network.stats();
    let start = Instant::now() + Duration::from_millis(250);
    let progress = Arc::new(Progress::default());
    // JoinSet aborts both owned drivers if a surrounding assertion fails.
    let mut drivers = JoinSet::new();
    let network = bench.network.clone();
    let flaps_progress = progress.clone();
    drivers.spawn(
        async move { Finished::Flaps(flap(network, start, schedule, flaps_progress).await) },
    );
    drivers.spawn(async move {
        Finished::Traffic(
            cohort(
                nodes,
                peers,
                receivers,
                progress,
                CohortPlan {
                    start,
                    port,
                    tag,
                    count,
                },
            )
            .await,
        )
    });
    let (mut events, mut traffic) = (None, None);
    observer
        .during_checked(
            async {
                while let Some(result) = drivers.join_next().await {
                    match result.unwrap() {
                        Finished::Flaps(value) => events = Some(value),
                        Finished::Traffic(value) => traffic = Some(value),
                    }
                }
            },
            || async {
                retain(anchor, &accounts(bench).await, true);
                assert_watches(bench).await;
                if let Some(expected) = &original_bridge {
                    assert_eq!(
                        bridge(bench).await.as_ref(),
                        Some(expected),
                        "warm flaps recreated an authenticated bridge peer"
                    );
                }
            },
        )
        .await;
    let events = events.unwrap();
    let traffic = traffic.unwrap();
    for pair in events.windows(2) {
        let planned = pair[1].planned_ms - pair[0].planned_ms;
        let actual = pair[1].actual_ms - pair[0].actual_ms;
        assert!(
            actual >= planned / 2 && actual <= planned + planned / 2,
            "scheduled mesh interval collapsed or stretched: {pair:?}"
        );
    }
    if warm {
        assert!(events[0].received.iter().all(|&n| n > 0));
    }
    for event in &events {
        assert!(event.sent.iter().all(|&n| n > 0 && n < count as u64));
    }
    for (direction, sent) in traffic.sent.iter().enumerate() {
        assert_eq!(sent.len(), count);
        for cut in events.windows(2).filter(|pair| !pair[0].up) {
            assert!(
                sent.iter()
                    .any(|&at| at >= cut[0].actual_ms && at < cut[1].actual_ms),
                "no direction {direction} workload inside cut {cut:?}"
            );
        }
        let unobserved: Vec<_> = (0..count as u8)
            .filter(|id| !traffic.received[direction].contains_key(id))
            .collect();
        eprintln!(
            "brief warm={warm} direction={direction}: submitted={count} unique={} duplicates={} unobserved_at_deadline={unobserved:?}",
            traffic.received[direction].len(),
            traffic.duplicates[direction]
        );
    }
    let delta = bench.network.stats().delta_since(&before);
    assert!(
        delta.packets_dropped_down > 0,
        "the carrier schedule must interrupt real network traffic"
    );
    eprintln!(
        "brief warm={warm}: events={events:?}; aggregate network drops while down={} (includes control traffic)",
        delta.packets_dropped_down
    );
    let last = events.last().unwrap();
    assert!(last.up);
    // This timestamp observes the completed mutation at millisecond resolution.
    // Later elapsed time includes the remaining cohort and drain interval.
    start + Duration::from_millis(last.actual_ms)
}

async fn recovered(bench: &mut Bench, observer: &mut Observer, tag: u8) -> BTreeMap<String, u64> {
    observer
        .during(converge(
            bench,
            true,
            "sustained contact after brief encounters",
        ))
        .await;
    let before = hop_usage(bench).await;
    for (source, destination, tag) in [(0, 5, tag), (5, 0, tag + 1)] {
        observer
            .during(traffic(bench, source, destination, tag))
            .await;
    }
    fresh_hops(&before, &hop_usage(bench).await);
    observer.during(payments(bench)).await
}

async fn exercise_brief() {
    let mut bench = bench::start(0, Scenario::MergeSplit, 123).await;
    let mut observer = Observer::new(&bench);
    converge(&bench, false, "brief independent components").await;
    for (source, destination) in [(0, 2), (5, 3)] {
        watch(&bench, source, destination).await;
    }
    bench.network.set_link(
        "2",
        "3",
        SimLink {
            latency_ms: 2,
            ..Default::default()
        },
    );
    converge(&bench, true, "brief initial merge").await;
    for (source, destination) in [(0, 5), (5, 0)] {
        watch(&bench, source, destination).await;
    }
    let initial_paid = recovered(&mut bench, &mut observer, 170).await;
    let anchor = accounts(&bench).await;
    assert_eq!(initial_paid.len(), 8);
    assert_watches(&bench).await;
    observer.settled().await;
    let original_bridge = bridge(&bench).await.unwrap();
    let warm_up = interrupted(&bench, &mut observer, &anchor, true).await;
    let warm_paid = recovered(&mut bench, &mut observer, 172).await;
    eprintln!(
        "brief warm: elapsed from recorded link-up observation to fresh bidirectional payloads and all-hop credit {:.3}s (includes cohort/drain/polling)",
        warm_up.elapsed().as_secs_f64()
    );
    for (channel, prior) in initial_paid {
        assert!(warm_paid[&channel] > prior);
    }
    bench.network.set_link_up("2", "3", false);
    observer
        .during(converge(&bench, false, "brief full separation"))
        .await;
    assert!(bridge(&bench).await.is_none());
    no_cross_delivery(&mut bench, 180).await;
    retain(&anchor, &accounts(&bench).await, true);

    let encounter_started = Instant::now();
    bench.network.set_link_up("2", "3", true);
    let new_bridge = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(peers) = bridge(&bench).await {
                return peers;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("short returning encounter needs an observed bidirectional adjacency");
    let observed = Instant::now();
    bench.network.set_link_up("2", "3", false);
    let observed_to_cut = observed.elapsed();
    assert!(observed_to_cut < Duration::from_millis(250));
    for direction in 0..2 {
        assert_ne!(new_bridge[direction].0, original_bridge[direction].0);
    }
    eprintln!(
        "brief return: new bidirectional adjacency after {:.3}s; observed-to-cut {}us, without a convergence/payment wait",
        encounter_started.elapsed().as_secs_f64(),
        observed_to_cut.as_micros()
    );
    let cold_up = interrupted(&bench, &mut observer, &anchor, false).await;
    let paid = recovered(&mut bench, &mut observer, 174).await;
    eprintln!(
        "brief cold: elapsed from recorded link-up observation to fresh bidirectional payloads and all-hop credit {:.3}s (includes cohort/drain/polling)",
        cold_up.elapsed().as_secs_f64()
    );
    for (channel, prior) in warm_paid {
        assert!(paid[&channel] > prior);
    }
    retain(&anchor, &accounts(&bench).await, true);
    assert_watches(&bench).await;
    observer.settled().await;
    eprintln!(
        "brief mesh: {} native observation rounds; maxima {:?}",
        observer.samples, observer.maxima
    );
    collect(bench, &anchor, &paid).await;
}
