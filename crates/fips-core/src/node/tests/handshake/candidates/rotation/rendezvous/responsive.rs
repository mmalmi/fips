//! Responsive local candidates compete through initial and repeated bridge contacts.
use super::*;
use crate::node::wire::Msg2Header;

#[path = "responsive_timing.rs"]
mod timing;

#[path = "responsive_population.rs"]
mod population;
use population::Population;

#[path = "responsive_queued.rs"]
mod queued;

#[path = "responsive_late.rs"]
mod late;

#[path = "responsive_brief.rs"]
mod brief;
#[path = "responsive_idle.rs"]
mod idle;
#[path = "responsive_live.rs"]
#[cfg(unix)]
mod live;
#[path = "responsive_phase.rs"]
mod phase;
#[path = "responsive_brief_ready.rs"]
mod ready;
#[path = "responsive_round.rs"]
mod rounds;
#[path = "responsive_setup.rs"]
mod setup;
#[path = "responsive_turn.rs"]
mod turn;
#[path = "responsive_turn_timing.rs"]
mod turn_timing;

const IDLE_SECS: u64 = 10;
const INTERVAL_SECS: u64 = 2;
const RESPONSIVE_ADDRESSES: [&str; 20] = [
    "a",
    "b",
    "useful-a",
    "useful-b",
    "idle-a",
    "idle-b",
    "silent-a",
    "silent-b",
    "candidate-a-2",
    "candidate-b-2",
    "candidate-a-3",
    "candidate-b-3",
    "candidate-a-4",
    "candidate-b-4",
    "candidate-a-5",
    "candidate-b-5",
    "candidate-a-6",
    "candidate-b-6",
    "candidate-a-7",
    "candidate-b-7",
];

#[test]
fn offset_full_rosters_form_a_bridge_among_responsive_candidates() {
    run(2, Duration::from_secs(35));
}

#[test]
fn offset_full_rosters_form_a_bridge_among_four_responsive_candidates() {
    run(4, Duration::from_secs(60));
}

#[test]
fn repeated_full_rosters_recover_native_payload_without_explicit_dial() {
    run_encounters(4, Duration::from_secs(60), true, Duration::ZERO);
}

#[test]
fn repeated_full_rosters_recover_native_payload_with_staggered_maintenance() {
    run_encounters(4, Duration::from_secs(60), true, Duration::from_millis(500));
}

fn run(candidates_per_boundary: usize, window: Duration) {
    run_encounters(candidates_per_boundary, window, false, Duration::ZERO);
}

fn run_encounters(
    candidates_per_boundary: usize,
    window: Duration,
    repeated: bool,
    component_phase: Duration,
) {
    run_population(
        Population::baseline(candidates_per_boundary),
        window,
        repeated,
        component_phase,
    );
}

fn run_population(
    population: Population,
    window: Duration,
    repeated: bool,
    component_phase: Duration,
) {
    run_population_with_demand(population, window, repeated, component_phase, None);
}

fn run_population_with_demand(
    population: Population,
    window: Duration,
    repeated: bool,
    component_phase: Duration,
    demand: Option<queued::Demand>,
) {
    run_large_stack_async_test("rotation-responsive-rendezvous", move || async move {
        let _guard = lock_large_network_test().await;
        let name = format!("rotation-responsive-rendezvous-{}", std::process::id());
        let network = SimNetwork::new(89);
        network.set_default_link(SimLink {
            up: false,
            ..Default::default()
        });
        register_sim_network(name.clone(), network.clone());
        let addresses = &RESPONSIVE_ADDRESSES[..4 + 2 * population.candidates_per_boundary];
        let mut nodes = population::make_nodes(&name, population).await;
        let mut identity_order: Vec<_> = (0..nodes.len()).collect();
        identity_order.sort_unstable_by_key(|&i| *nodes[i].node.node_addr());
        eprintln!(
            "responsive population setup: {}",
            json!({"candidates_per_boundary":population.candidates_per_boundary,
                "first_scalar":population.first_scalar,"reversed":population.reversed,
                "idle_secs":population.idle_secs,"interval_secs":INTERVAL_SECS,
                "max_connections":population.capacity.connections,"max_links":population.capacity.links,
                "identity_order":identity_order,"maintenance_phase_ms":component_phase.as_millis(),
                "brief_contact":population.brief_contact})
        );
        let result = AssertUnwindSafe(exercise(
            &mut nodes,
            &network,
            addresses,
            EncounterOptions {
                window,
                repeated,
                component_phase,
                demand,
                diagnose_miss: population.diagnose_miss,
                brief_contact: population.brief_contact,
                capacity: population.capacity,
            },
        ))
        .catch_unwind()
        .await;
        cleanup_nodes(&mut nodes).await;
        unregister_sim_network(&name);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

struct Observation {
    capacity: CapacityLimits,
    post_deadline_diagnostic: bool,
    started: tokio::time::Instant,
    next_tick: [tokio::time::Instant; 2],
    component_phase: Duration,
    cohort_ticks: [usize; 2],
    bridge_msg1: [usize; 2],
    incumbents: [Option<(usize, LinkId, u64)>; 2],
    replacements: [usize; 2],
    ticks: usize,
    timing: timing::Ledger,
    queued_originals: Vec<queued::Original>,
    brief_payloads: Option<ready::Payloads>,
    initial_handshake: Option<setup::ScheduledHandshake>,
    contact_phase: Option<phase::Capture>,
    contact_idle: idle::Wait,
    last_turn_cost: Option<turn_timing::Capture>,
    contact_turn_cost: Option<turn_timing::Capture>,
}

fn pending_attempts(node: &Node, ids: &[PeerIdentity]) -> Value {
    let now = Node::now_ms();
    let attempts: Vec<_> = node
        .peers
        .connection_values()
        .map(|conn| {
            let identity = conn.expected_identity();
            let rotation_started =
                identity.and_then(|id| node.neighbor_rotation_started_at(id.node_addr()));
            json!({"node":identity.map(|id|label(ids,id.node_addr())),
            "link":conn.link_id().as_u64(),"outbound":conn.is_outbound(),
            "our_index":conn.our_index().map(|index|index.as_u32()),
            "their_index":conn.their_index().map(|index|index.as_u32()),
            "state":format!("{:?}",conn.handshake_state()),"has_session":conn.has_session(),
            "started_ms":conn.started_at(),"last_activity_ms":conn.last_activity(),
            "connection_age_ms":conn.duration(now),"rotation_started_ms":rotation_started,
            "rotation_age_ms":rotation_started.map(|start|now.saturating_sub(start))})
        })
        .collect();
    json!(attempts)
}

impl Observation {
    fn new(component_phase: Duration, capacity: CapacityLimits) -> Self {
        let started = tokio::time::Instant::now();
        Self {
            capacity,
            post_deadline_diagnostic: false,
            started,
            next_tick: [started, started + component_phase],
            component_phase,
            cohort_ticks: [0; 2],
            bridge_msg1: [0; 2],
            incumbents: [None; 2],
            replacements: [0; 2],
            ticks: 0,
            timing: timing::Ledger::with_maintenance_phase(
                component_phase.as_millis().try_into().unwrap(),
            ),
            queued_originals: Vec::new(),
            brief_payloads: None,
            initial_handshake: None,
            contact_phase: None,
            contact_idle: idle::Wait::default(),
            last_turn_cost: None,
            contact_turn_cost: None,
        }
    }

    fn incumbents(
        &mut self,
        nodes: &[TestNode],
        ids: &[PeerIdentity],
        before_packet: Option<(usize, Value)>,
    ) {
        let now = Node::now_ms();
        for i in 0..2 {
            let current = nodes[i]
                .node
                .peers
                .iter()
                .find(|(address, _)| **address != *ids[i + 2].node_addr())
                .map(|(address, peer)| {
                    (label(ids, address), peer.link_id(), peer.authenticated_at())
                });
            if current == self.incumbents[i] {
                continue;
            }
            if self.incumbents[i].is_some() && current.is_some() {
                self.replacements[i] += 1;
            }
            let describe = |entry: Option<(usize, LinkId, u64)>| {
                entry.map(|(peer, link, authenticated)| {
                    json!({"node":peer,"link":link.as_u64(),"authenticated_ms":authenticated,
                        "age_ms":now.saturating_sub(authenticated)})
                })
            };
            eprintln!(
                "responsive incumbent: {}",
                json!({"observed_ms":self.started.elapsed().as_millis(),"boundary":i,
                    "post_deadline_diagnostic":self.post_deadline_diagnostic,
                    "old":describe(self.incumbents[i]),"new":describe(current),
                    "attempts_before_packet":before_packet.as_ref()
                        .filter(|(boundary,_)|*boundary==i).map(|(_,attempts)|attempts)})
            );
            self.incumbents[i] = current;
        }
    }
}

async fn connect(
    observation: &mut Observation,
    nodes: &mut [TestNode],
    ids: &[PeerIdentity],
    network: &SimNetwork,
    addresses: &[&str],
    source: usize,
    destination: usize,
) {
    network.set_link(
        addresses[source],
        addresses[destination],
        SimLink::default(),
    );
    dial(nodes, source, destination).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        observation.turn(nodes, ids).await;
        if nodes[source]
            .node
            .get_peer(ids[destination].node_addr())
            .is_some()
            && nodes[destination]
                .node
                .get_peer(ids[source].node_addr())
                .is_some()
            && nodes[source].node.connection_count() == 0
            && nodes[destination].node.connection_count() == 0
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "initial real handshake"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

struct EncounterOptions {
    window: Duration,
    repeated: bool,
    component_phase: Duration,
    demand: Option<queued::Demand>,
    diagnose_miss: bool,
    brief_contact: Option<brief::Kind>,
    capacity: CapacityLimits,
}

async fn exercise(
    nodes: &mut [TestNode],
    network: &SimNetwork,
    addresses: &[&str],
    options: EncounterOptions,
) {
    let EncounterOptions {
        window,
        repeated,
        component_phase,
        demand,
        diagnose_miss,
        brief_contact,
        capacity,
    } = options;
    let ids = identities(nodes);
    let mut observation = Observation::new(component_phase, capacity);
    connect(&mut observation, nodes, &ids, network, addresses, 0, 2).await;
    connect(&mut observation, nodes, &ids, network, addresses, 1, 3).await;
    let mut endpoints: Vec<_> = nodes
        .iter_mut()
        .map(|n| n.node.attach_endpoint_data_io(16).unwrap())
        .collect();
    let original: Vec<_> = (0..2).map(|i| original_owner(nodes, &ids, i)).collect();
    let mut sequence = 0;
    observation
        .round(nodes, &mut endpoints, &ids, &mut sequence, &LOCAL_FLOWS)
        .await;
    if brief_contact.is_some() {
        brief::mature_useful_owners(
            &mut observation,
            nodes,
            &mut endpoints,
            &ids,
            &mut sequence,
            &original,
        )
        .await;
    }
    connect(&mut observation, nodes, &ids, network, addresses, 0, 4).await;
    let first = nodes[0]
        .node
        .get_peer(ids[4].node_addr())
        .unwrap()
        .authenticated_at();
    observation.initial_handshake = Some(setup::ScheduledHandshake::new(first, network.clone()));
    while !observation
        .initial_handshake
        .as_ref()
        .unwrap()
        .complete(nodes)
    {
        observation
            .round(nodes, &mut endpoints, &ids, &mut sequence, &LOCAL_FLOWS)
            .await;
        useful_retained(nodes, &ids, &original);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    observation
        .initial_handshake
        .take()
        .unwrap()
        .assert_finished(nodes);
    let second = nodes[1]
        .node
        .get_peer(ids[5].node_addr())
        .unwrap()
        .authenticated_at();
    assert!(
        (5_000..6_000).contains(&second.saturating_sub(first)),
        "actual incumbent authentication must have the intended five-second phase offset"
    );
    for (i, candidate) in [(0, 4), (1, 5)] {
        assert_eq!(nodes[i].node.peer_count(), 2);
        assert!(nodes[i].node.get_peer(ids[candidate].node_addr()).is_some());
        assert!(nodes[i].node.pending_connects.is_empty());
        assert_eq!(nodes[i].node.connection_count(), 0);
    }
    observation
        .round(nodes, &mut endpoints, &ids, &mut sequence, &LOCAL_FLOWS)
        .await;
    useful_retained(nodes, &ids, &original);
    if brief_contact == Some(brief::Kind::Mature) {
        ready::mature_idle_owners(
            &mut observation,
            nodes,
            &mut endpoints,
            &ids,
            &mut sequence,
            &original,
        )
        .await;
    }
    // Local candidates remain available through every encounter and split.
    // They have no configured peers, application load or forced departure.
    for candidate in 6..addresses.len() {
        network.set_link(
            addresses[candidate % 2],
            addresses[candidate],
            SimLink::default(),
        );
    }
    let first_exposure_requests = observation.bridge_msg1;
    let brief_acceptance = if let Some(kind) = brief_contact {
        assert!(
            demand.is_none(),
            "brief admission control adds no queued cross demand"
        );
        Some(
            brief::observe(
                &mut observation,
                nodes,
                &mut endpoints,
                &ids,
                &mut sequence,
                network,
                addresses,
                kind,
            )
            .await,
        )
    } else {
        None
    };
    let mut previous_bridge: Option<Vec<(LinkId, u64)>> = None;
    for encounter in 0..=usize::from(repeated) {
        eprintln!(
            "responsive encounter start: {}",
            json!({"encounter":encounter,
            "maintenance_phase_ms":component_phase.as_millis(),
            "observed_ms":observation.started.elapsed().as_millis()})
        );
        if encounter > 0 {
            partition_and_refill(
                &mut observation,
                nodes,
                &mut endpoints,
                &ids,
                &mut sequence,
                network,
                addresses,
            )
            .await;
            useful_retained(nodes, &ids, &original);
        }
        if let Some(demand) = demand.filter(|demand| demand.encounter == encounter) {
            for &source in demand.sources {
                observation.queued_originals.push(
                    queued::Original::offer(nodes, &ids, observation.started, encounter, source)
                        .await,
                );
            }
        }
        network.set_link(addresses[0], addresses[1], SimLink::default());
        let exposed = tokio::time::Instant::now();
        observation.timing.exposed(observation.started);
        for original in &mut observation.queued_originals {
            original.exposed(observation.started);
        }
        snapshot(
            nodes,
            &ids,
            observation.started,
            "responsive-bridge-exposed",
        );
        // Preparation from the brief opening may finish after re-exposure
        // without another Msg1. Count that genuine first discovery offer too.
        let before_requests = if brief_contact.is_some() && encounter == 0 {
            first_exposure_requests
        } else {
            observation.bridge_msg1
        };
        let mut bridge_at = None;
        let mut delivery_at = None;
        let mut next_local_round = None;
        while exposed.elapsed() < window {
            observation
                .round(nodes, &mut endpoints, &ids, &mut sequence, &LOCAL_FLOWS)
                .await;
            useful_retained(nodes, &ids, &original);
            if reciprocal_bridge(nodes, &ids) {
                bridge_at.get_or_insert_with(|| exposed.elapsed());
            }
            if reciprocal_bridge(nodes, &ids)
                && observation
                    .queued_originals
                    .iter()
                    .all(queued::Original::delivered)
            {
                let owners: Vec<_> = (0..2)
                    .map(|i| {
                        let peer = nodes[i].node.get_peer(ids[1 - i].node_addr()).unwrap();
                        (peer.link_id(), peer.authenticated_at())
                    })
                    .collect();
                if let Some(previous) = previous_bridge.as_ref() {
                    for (old, new) in previous.iter().zip(&owners) {
                        assert_ne!(
                            old, new,
                            "second encounter must authenticate new bridge owners"
                        );
                    }
                }
                previous_bridge = Some(owners);
                observation
                    .round(
                        nodes,
                        &mut endpoints,
                        &ids,
                        &mut sequence,
                        &[(0, 1), (1, 0)],
                    )
                    .await;
                observation
                    .round(nodes, &mut endpoints, &ids, &mut sequence, &LOCAL_FLOWS)
                    .await;
                useful_retained(nodes, &ids, &original);
                assert!(reciprocal_bridge(nodes, &ids));
                delivery_at = Some(exposed.elapsed());
                break;
            }
            // Continue processing between fresh half-second useful data rounds.
            let next_round = tokio::time::Instant::now() + Duration::from_millis(500);
            next_local_round = Some(next_round);
            while tokio::time::Instant::now() < next_round && exposed.elapsed() < window {
                observation.turn(nodes, &ids).await;
                useful_retained(nodes, &ids, &original);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        caps_with_limits(nodes, observation.capacity);
        snapshot(
            nodes,
            &ids,
            observation.started,
            "responsive-final-before-cleanup",
        );
        observation
            .timing
            .observe(nodes, &ids, observation.started, "final");
        observation.timing.summary(observation.started);
        for original in &observation.queued_originals {
            original.summary(nodes, &ids, observation.started);
        }
        eprintln!(
            "responsive rendezvous outcome: {}",
            json!({"encounter":encounter,"maintenance_phase_ms":component_phase.as_millis(),
                "max_connections":observation.capacity.connections,"max_links":observation.capacity.links,
                "cohort_maintenance_turns":observation.cohort_ticks,"candidates_per_boundary":(nodes.len()-4)/2,"window_ms":window.as_millis(),
                "elapsed_ms":exposed.elapsed().as_millis(),"bridge_ms":bridge_at.map(|d|d.as_millis()),
                "bridge_msg1":[observation.bridge_msg1[0]-before_requests[0],
                    observation.bridge_msg1[1]-before_requests[1]],
                "includes_initial_brief_requests":brief_contact.is_some() && encounter == 0,
                "delivery_ms":delivery_at.map(|d|d.as_millis()),"incumbent_changes":observation.replacements,
                "maintenance_turns":observation.ticks,"completed_payload_rounds":sequence})
        );
        let offered_bridge = observation
            .bridge_msg1
            .iter()
            .zip(before_requests)
            .any(|(after, before)| *after > before);
        let accepted = bridge_at.is_some_and(|elapsed| elapsed < window)
            && (!(repeated || brief_contact.is_some())
                || delivery_at.is_some_and(|elapsed| elapsed < window));
        if diagnose_miss && !accepted {
            // Keep the original outcome above and assertions below immutable.
            // Later success is diagnostic evidence, never a new acceptance.
            let diagnostic = AssertUnwindSafe(late::observe(
                nodes,
                &mut endpoints,
                &ids,
                &mut sequence,
                &original,
                &mut observation,
                late::MissedAcceptance {
                    encounter,
                    exposed,
                    window,
                    bridge_at,
                    delivery_at,
                    next_local_round,
                },
            ))
            .catch_unwind()
            .await;
            if let Err(panic) = diagnostic {
                let reason = panic
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| panic.downcast_ref::<&str>().copied())
                    .unwrap_or("non-string diagnostic panic");
                eprintln!(
                    "responsive post-deadline diagnostic aborted: {}",
                    json!({
                        "post_deadline_diagnostic":true,"encounter":encounter,
                        "observed_ms":observation.started.elapsed().as_millis(),
                        "native_now_ms":Node::now_ms(),"since_exposure_ms":exposed.elapsed().as_millis(),
                        "original_acceptance_passed":false,"reason":reason
                    })
                );
            }
        }
        assert!(
            offered_bridge,
            "diagnostic premise: discovery must actually offer the exposed bridge"
        );
        assert!(
            bridge_at.is_some_and(|elapsed| elapsed < window),
            "encounter {encounter}: responsive local replacements must not prevent the offset rosters forming a reciprocal bridge within {window:?}"
        );
        if repeated || brief_contact.is_some() {
            assert!(
                delivery_at.is_some_and(|elapsed| elapsed < window),
                "encounter {encounter}: both native payload directions must complete within the same {window:?}"
            );
        }
        for original in &observation.queued_originals {
            original.assert_delivered_within(nodes, &ids, window);
        }
    }
    if let Some(payloads) = &observation.brief_payloads {
        eprintln!(
            "responsive brief originals after recovery: {}",
            payloads.summary()
        );
    }
    assert!(
        brief_acceptance.is_none_or(|accepted| accepted),
        "mature contact must deliver both original multi-hop payloads before its independent cut; sustained recovery cannot satisfy brief acceptance"
    );
}

/// Keep all ordinary state and local competitors alive across a physical split.
/// Re-exposure requires two refilled rosters and genuinely separated local trees.
async fn partition_and_refill(
    observation: &mut Observation,
    nodes: &mut [TestNode],
    endpoints: &mut [EndpointDataIo],
    ids: &[PeerIdentity],
    sequence: &mut u16,
    network: &SimNetwork,
    addresses: &[&str],
) {
    let original: Vec<_> = (0..2).map(|i| original_owner(nodes, ids, i)).collect();
    eprintln!(
        "responsive split start: {}",
        json!({"encounter":1,
        "observed_ms":observation.started.elapsed().as_millis()})
    );
    network.set_link_up(addresses[0], addresses[1], false);
    let started = tokio::time::Instant::now();
    let window = Duration::from_secs(60);
    loop {
        observation
            .round(nodes, endpoints, ids, sequence, &LOCAL_FLOWS)
            .await;
        useful_retained(nodes, ids, &original);
        if refilled_components(nodes, ids) && started.elapsed() < window {
            snapshot(nodes, ids, observation.started, "responsive-refilled-split");
            eprintln!(
                "responsive split outcome: {}",
                json!({"encounter":1,
                "elapsed_ms":started.elapsed().as_millis(),"refilled":true})
            );
            return;
        }
        if started.elapsed() >= window {
            snapshot(nodes, ids, observation.started, "responsive-split-timeout");
            observation.timing.summary(observation.started);
            eprintln!(
                "responsive split outcome: {}",
                json!({"encounter":1,
                "elapsed_ms":started.elapsed().as_millis(),"refilled":false})
            );
            panic!(
                "physical split must evict the bridge and refill both rosters within {window:?}"
            );
        }
        // Preserve the cold fixture's offered local traffic and maintenance cadence.
        let next_round = tokio::time::Instant::now() + Duration::from_millis(500);
        while tokio::time::Instant::now() < next_round && started.elapsed() < window {
            observation.turn(nodes, ids).await;
            useful_retained(nodes, ids, &original);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

fn refilled_components(nodes: &[TestNode], ids: &[PeerIdentity]) -> bool {
    if nodes[0].node.tree_state().root() == nodes[1].node.tree_state().root() {
        return false;
    }
    (0..2).all(|i| {
        let node = &nodes[i].node;
        let root = node.tree_state().root();
        let local = |j: usize| j == i || j == i + 2 || (j >= 4 && j % 2 == i);
        node.peer_count() == 2
            && node.get_peer(ids[1 - i].node_addr()).is_none()
            && node.get_peer(ids[i + 2].node_addr()).is_some()
            && (4..nodes.len()).filter(|j| local(*j)).any(|j| {
                node.get_peer(ids[j].node_addr())
                    .is_some_and(|peer| peer.can_send())
            })
            && nodes[i + 2].node.tree_state().root() == root
            && (0..nodes.len()).any(|j| local(j) && ids[j].node_addr() == root)
    })
}
