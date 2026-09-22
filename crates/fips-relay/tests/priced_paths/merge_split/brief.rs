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
    run_brief(0, 123).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn brief_mesh_contacts_with_opposite_root_deliver_before_each_cut() {
    run_brief(3, 124).await;
}

async fn run_brief(root_node: usize, seed: u64) {
    eprintln!("brief scenario root_node={root_node} seed={seed}");
    tokio::time::timeout(Duration::from_secs(480), exercise_brief(root_node, seed))
        .await
        .expect("brief paid mesh encounters and collection deadline");
}

#[derive(Default)]
struct Progress {
    sent: [AtomicU64; 2],
    received: [AtomicU64; 2],
}

#[derive(Debug, serde::Serialize)]
struct Event {
    planned_ms: u64,
    actual_ms: u64,
    mutation_us: [u64; 2],
    up: bool,
    sent: [u64; 2],
    received: [u64; 2],
}

#[derive(Default)]
struct Cohort {
    sent: [Vec<[u64; 2]>; 2],
    received: [BTreeMap<u8, u64>; 2],
    duplicates: [usize; 2],
}

#[derive(Debug, serde::Serialize)]
pub(super) struct ContactProgress {
    pub(super) warm: bool,
    pub(super) direction: usize,
    pub(super) window_us: [u64; 2],
    pub(super) offered_ids: Vec<u8>,
    pub(super) received_before_cut: BTreeMap<u8, u64>,
    pub(super) received_after_cut: BTreeMap<u8, u64>,
    pub(super) unobserved_at_deadline: Vec<u8>,
}

pub(super) struct ContactResult {
    last_up: Instant,
    contacts: Vec<ContactProgress>,
    duplicates: [usize; 2],
    received_at_first_cut: [u64; 2],
    dropped_while_down: u64,
}

impl ContactResult {
    pub(super) fn assert_carrier_interrupted(&self) {
        assert!(
            self.dropped_while_down > 0,
            "the carrier schedule must interrupt real network traffic"
        );
    }

    pub(super) fn last_up(&self) -> Instant {
        self.last_up
    }

    /// Validate offered traffic without requiring every short contact to deliver.
    /// Receives after its cut remain separate from before-cut progress.
    pub(super) fn validate_offers(&self) -> &[ContactProgress] {
        assert_eq!(self.duplicates, [0, 0]);
        assert_eq!(
            self.contacts.len(),
            6,
            "three finite contacts, both directions"
        );
        for contact in &self.contacts {
            assert!(
                !contact.offered_ids.is_empty(),
                "no fresh offer: {contact:?}"
            );
        }
        &self.contacts
    }

    fn assert_progress(&self) {
        for contact in self.validate_offers() {
            assert!(
                !contact.received_before_cut.is_empty(),
                "contact ended without fresh payload delivery: {contact:?}"
            );
        }
    }
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
        let before = start.elapsed().as_micros() as u64;
        network.set_link_up("2", "3", up);
        let after = start.elapsed().as_micros() as u64;
        let event = Event {
            planned_ms,
            actual_ms: after / 1000,
            mutation_us: [before, after],
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
        match result.received[direction].entry(bytes[0]) {
            std::collections::btree_map::Entry::Occupied(_) => result.duplicates[direction] += 1,
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(start.elapsed().as_micros() as u64);
                progress.received[direction].fetch_add(1, Ordering::Relaxed);
            }
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
                    let before = start.elapsed().as_micros() as u64;
                    nodes[direction].send_datagram(peers[1 - direction], port, port, payload).await.unwrap();
                    result.sent[direction].push([before, start.elapsed().as_micros() as u64]);
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
    clock: Option<Instant>,
) -> ContactResult {
    let original_bridge = if warm {
        Some(bridge(bench).await.unwrap())
    } else {
        None
    };
    let result = observer
        .during_checked(contact_cohort(bench, warm, clock), || async {
            retain(anchor, &accounts(bench).await, true);
            assert_watches(bench).await;
            if let Some(expected) = &original_bridge {
                assert_eq!(
                    bridge(bench).await.as_ref(),
                    Some(expected),
                    "warm flaps recreated an authenticated bridge peer"
                );
            }
        })
        .await;
    result.assert_carrier_interrupted();
    if warm {
        assert!(result.received_at_first_cut.iter().all(|&n| n > 0));
    }
    result
}

/// Run the existing timed cuts and one-shot cohort without owning an observer.
/// The caller supplies the initial link state: up for warm, down for cold.
/// Crowded cold callers must also establish that no reciprocal bridge exists.
/// Final link-up is followed by the existing cohort drain; use `last_up()` to
/// anchor a recovery deadline to the physical opening, not this return time.
pub(super) async fn contact_cohort(
    bench: &Bench,
    warm: bool,
    clock: Option<Instant>,
) -> ContactResult {
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
    let before = bench.network.stats();
    let start = Instant::now() + Duration::from_millis(250);
    let cohort_start_us = start.duration_since(clock.unwrap_or(start)).as_micros() as u64;
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
    while let Some(result) = drivers.join_next().await {
        match result.unwrap() {
            Finished::Flaps(value) => events = Some(value),
            Finished::Traffic(value) => traffic = Some(value),
        }
    }
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
    for event in &events {
        assert!(event.mutation_us[0] <= event.mutation_us[1]);
        assert_eq!(event.actual_ms, event.mutation_us[1] / 1000);
        assert!(event.sent.iter().all(|&n| n > 0 && n < count as u64));
    }
    for (direction, sent) in traffic.sent.iter().enumerate() {
        assert_eq!(sent.len(), count);
        for cut in events.windows(2).filter(|pair| !pair[0].up) {
            assert!(
                sent.iter()
                    .any(|span| span[0] >= cut[0].mutation_us[1]
                        && span[1] < cut[1].mutation_us[0]),
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
        eprintln!(
            "brief packet observations {}",
            serde_json::json!({
                "warm": warm, "direction": direction, "cohort_start_us": cohort_start_us,
                "send_bracket_us": sent, "receive_observed_us": traffic.received[direction],
            })
        );
    }
    let delta = bench.network.stats().delta_since(&before);
    eprintln!(
        "brief carrier observations {}",
        serde_json::json!({
            "warm": warm, "cohort_start_us": cohort_start_us, "events": events,
            "network_drops_while_down_including_control": delta.packets_dropped_down,
        })
    );
    let contacts = contact_progress(warm, &events, &traffic);
    let last = events.last().unwrap();
    assert!(last.up);
    // This timestamp observes the completed mutation at millisecond resolution.
    // Later elapsed time includes the remaining cohort and drain interval.
    ContactResult {
        last_up: start + Duration::from_millis(last.actual_ms),
        contacts,
        duplicates: traffic.duplicates,
        received_at_first_cut: events.iter().find(|event| !event.up).unwrap().received,
        dropped_while_down: delta.packets_dropped_down,
    }
}

fn contact_progress(warm: bool, events: &[Event], traffic: &Cohort) -> Vec<ContactProgress> {
    let mut opened = warm.then_some(0);
    let mut result = Vec::new();
    for event in events {
        if event.up {
            opened = Some(event.mutation_us[1]);
            continue;
        }
        let start = opened.take().expect("each cut ends an observed contact");
        let end = event.mutation_us[0];
        assert!(start < end);
        for direction in 0..2 {
            // Use the complete application submission span and observe the
            // receive before the cut. This excludes queued pre-contact offers
            // and packets delivered only after a later rejoin, without making
            // claims about a packet's exact time on any intermediate carrier.
            let offered_ids: Vec<_> = traffic.sent[direction]
                .iter()
                .enumerate()
                .filter(|(_, span)| span[0] >= start && span[1] < end)
                .map(|(id, _)| id as u8)
                .collect();
            let received_before_cut = offered_ids
                .iter()
                .filter_map(|id| {
                    traffic.received[direction]
                        .get(id)
                        .and_then(|&at| (at >= start && at < end).then_some((*id, at)))
                })
                .collect();
            let received_after_cut = offered_ids
                .iter()
                .filter_map(|id| {
                    traffic.received[direction]
                        .get(id)
                        .and_then(|&at| (at >= end).then_some((*id, at)))
                })
                .collect();
            let unobserved_at_deadline = offered_ids
                .iter()
                .filter(|id| !traffic.received[direction].contains_key(*id))
                .copied()
                .collect();
            let progress = ContactProgress {
                warm,
                direction,
                window_us: [start, end],
                offered_ids,
                received_before_cut,
                received_after_cut,
                unobserved_at_deadline,
            };
            eprintln!(
                "brief contact progress {}",
                serde_json::to_string(&progress).unwrap()
            );
            result.push(progress);
        }
    }
    result
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

async fn exercise_brief(root_node: usize, seed: u64) {
    let mut bench = bench::start(root_node, Scenario::MergeSplit, seed).await;
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
    let warm_up = interrupted(&bench, &mut observer, &anchor, true, None).await;
    let warm_paid = recovered(&mut bench, &mut observer, 172).await;
    eprintln!(
        "brief warm: elapsed from recorded link-up observation to fresh bidirectional payloads and all-hop credit {:.3}s (includes cohort/drain/polling)",
        warm_up.last_up().elapsed().as_secs_f64()
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

    let timing = timing::Timing::start(&bench).await;
    let encounter_started = Instant::now();
    bench.network.set_link_up("2", "3", true);
    timing.mark("initial_link_up_observed");
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
    timing.mark("authenticated_bridge_cut_observed");
    assert!(observed_to_cut < Duration::from_millis(250));
    for direction in 0..2 {
        assert_ne!(new_bridge[direction].0, original_bridge[direction].0);
    }
    eprintln!(
        "brief return: new bidirectional adjacency after {:.3}s; observed-to-cut {}us, without a convergence/payment wait",
        encounter_started.elapsed().as_secs_f64(),
        observed_to_cut.as_micros()
    );
    let cold_up = interrupted(&bench, &mut observer, &anchor, false, Some(timing.origin)).await;
    let paid = recovered(&mut bench, &mut observer, 174).await;
    timing.mark("fresh_bidirectional_payloads_and_all_hop_credit_observed");
    timing.finish().await;
    eprintln!(
        "brief cold: elapsed from recorded link-up observation to fresh bidirectional payloads and all-hop credit {:.3}s (includes cohort/drain/polling)",
        cold_up.last_up().elapsed().as_secs_f64()
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
    // Preserve full settlement and collection evidence even if a contact
    // carried no useful traffic. Eventual recovery cannot satisfy this gate.
    warm_up.assert_progress();
    cold_up.assert_progress();
}
