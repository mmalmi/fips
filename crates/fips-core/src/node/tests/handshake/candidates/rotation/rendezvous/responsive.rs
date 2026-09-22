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
    run_population_with_queued_rejoin(population, window, repeated, component_phase, false);
}

fn run_population_with_queued_rejoin(
    population: Population,
    window: Duration,
    repeated: bool,
    component_phase: Duration,
    queued_rejoin: bool,
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
        let mut nodes = Vec::new();
        for (i, address) in addresses.iter().enumerate() {
            nodes.push(
                make_node_with(&name, address, i < 2, |config| {
                    // Public test-only scalars keep identity-based discovery order reproducible.
                    config.node.identity.nsec =
                        Some(format!("{:02x}", population.scalar(i, addresses.len())).repeat(32));
                    // Keep normal handshake/retry policy, independently from the
                    // unanswered-dial fixture's deliberately short timeout.
                    config.node.rate_limit = Config::new().node.rate_limit;
                    assert_eq!(config.node.rate_limit.handshake_timeout_secs, 30);
                    config.node.neighbor_rotation = (i < 2).then_some(NeighborRotationConfig {
                        idle_secs: population.idle_secs,
                        interval_secs: INTERVAL_SECS,
                    });
                    config.transports.sim = TransportInstances::Single(SimTransportConfig {
                        network: Some(name.clone()),
                        addr: Some(address.to_string()),
                        auto_connect: Some(true),
                        ..Default::default()
                    });
                })
                .await,
            );
        }
        let mut identity_order: Vec<_> = (0..nodes.len()).collect();
        identity_order.sort_unstable_by_key(|&i| *nodes[i].node.node_addr());
        eprintln!(
            "responsive population setup: {}",
            json!({"candidates_per_boundary":population.candidates_per_boundary,
                "first_scalar":population.first_scalar,"reversed":population.reversed,
                "idle_secs":population.idle_secs,"interval_secs":INTERVAL_SECS,
                "identity_order":identity_order,"maintenance_phase_ms":component_phase.as_millis()})
        );
        let result = AssertUnwindSafe(exercise(
            &mut nodes,
            &network,
            addresses,
            window,
            repeated,
            component_phase,
            queued_rejoin,
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
    started: tokio::time::Instant,
    next_tick: [tokio::time::Instant; 2],
    component_phase: Duration,
    cohort_ticks: [usize; 2],
    bridge_msg1: [usize; 2],
    incumbents: [Option<(usize, LinkId, u64)>; 2],
    replacements: [usize; 2],
    ticks: usize,
    timing: timing::Ledger,
    queued_original: Option<queued::Original>,
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
    fn new(component_phase: Duration) -> Self {
        let started = tokio::time::Instant::now();
        Self {
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
            queued_original: None,
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
                    "old":describe(self.incumbents[i]),"new":describe(current),
                    "attempts_before_packet":before_packet.as_ref()
                        .filter(|(boundary,_)|*boundary==i).map(|(_,attempts)|attempts)})
            );
            self.incumbents[i] = current;
        }
    }

    async fn turn(&mut self, nodes: &mut [TestNode], ids: &[PeerIdentity]) {
        if let Some(original) = &mut self.queued_original {
            original.observe(nodes, ids, self.started);
        }
        self.timing.observe(nodes, ids, self.started, "turn-entry");
        let due = if self.component_phase.is_zero() {
            // Preserve the original cold and repeated-control schedule/order.
            let due = tokio::time::Instant::now() >= self.next_tick[0];
            if due {
                self.next_tick = [tokio::time::Instant::now() + Duration::from_secs(1); 2];
            }
            [due; 2]
        } else {
            // The actual fixture numbering alternates complete components:
            // boundary, useful peer, and every responsive candidate. Offset
            // only their initial timers; ordinary late ticks never catch up.
            let now = tokio::time::Instant::now();
            std::array::from_fn(|cohort| {
                let due = now >= self.next_tick[cohort];
                if due {
                    self.next_tick[cohort] = now + Duration::from_secs(1);
                }
                due
            })
        };
        if due.into_iter().any(|due| due) {
            // Each node still performs one real maintenance turn per second.
            // All endpoints respond; no native request is held or lost.
            self.ticks += 1;
            for (cohort, ready) in due.into_iter().enumerate() {
                self.cohort_ticks[cohort] += usize::from(ready);
            }
            for (i, n) in nodes.iter_mut().enumerate() {
                if !due[i % 2] {
                    continue;
                }
                n.node.check_timeouts().await;
                n.node.check_link_heartbeats().await;
                let now = Node::now_ms();
                n.node.resend_pending_handshakes(now).await;
                n.node.resend_pending_rekeys(now).await;
                n.node.resend_pending_session_handshakes(now).await;
                n.node.resend_pending_session_msg3(now).await;
                n.node.retry_pending_session_traffic().await;
                n.node.check_mmp_reports().await;
                n.node.check_session_mmp_reports().await;
                n.node.check_rekey().await;
                n.node.check_session_rekey().await;
                n.node.check_pending_lookups(now).await;
                n.node.poll_pending_connects().await;
                n.node.process_pending_retries(now).await;
                n.node.poll_transport_discovery().await;
                n.node.check_tree_state().await;
                n.node.send_pending_tree_announces().await;
            }
            self.incumbents(nodes, ids, None);
            if let Some(original) = &mut self.queued_original {
                original.observe(nodes, ids, self.started);
            }
            self.timing
                .observe(nodes, ids, self.started, "maintenance-completed");
            snapshot(nodes, ids, self.started, "responsive-maintenance");
        }
        for destination in 0..nodes.len() {
            for _ in 0..256 {
                let Ok(packet) = nodes[destination].packet_rx.try_recv() else {
                    break;
                };
                let msg1 = (destination < 2)
                    .then(|| Msg1Header::parse(packet.data.as_slice()))
                    .flatten();
                let incoming = msg1.is_some();
                let bridge = incoming && packet.remote_addr == nodes[1 - destination].addr;
                let before_packet = (destination < 2)
                    .then(|| (destination, pending_attempts(&nodes[destination].node, ids)));
                let bridge_msg2 = (destination < 2
                    && packet.remote_addr == nodes[1 - destination].addr)
                    .then(|| Msg2Header::parse(packet.data.as_slice()))
                    .flatten();
                let transport_id = packet.transport_id;
                let received_ms = packet.timestamp_ms;
                // Read only bounded local ownership; never retain/reorder a packet
                // or query a routing selector while correlating these responses.
                let response_owner = |node: &Node| {
                    let response = bridge_msg2.as_ref().unwrap();
                    let key = (transport_id, response.receiver_idx.as_u32());
                    let active = node.get_peer(ids[1 - destination].node_addr()).map(|peer| {
                        json!({"link":peer.link_id().as_u64(),
                            "our_index":peer.our_index().map(|index|index.as_u32()),
                            "their_index":peer.their_index().map(|index|index.as_u32())})
                    });
                    json!({"pending":pending_attempts(node,ids),
                        "exact_pending_link":node.pending_outbound.get(&key).map(|link|link.as_u64()),
                        "matched_pending_link":node.pending_outbound.match_msg2(key.0,key.1)
                            .map(|(_,link)|link.as_u64()),
                        "receiver_index_allocated":node.index_allocator.is_allocated(response.receiver_idx),
                        "active_bridge":active})
                };
                let msg2_before = bridge_msg2.as_ref().map(|_| {
                    (
                        self.started.elapsed().as_millis(),
                        response_owner(&nodes[destination].node),
                    )
                });
                if incoming {
                    if bridge {
                        self.bridge_msg1[destination] += 1;
                    }
                    let source = nodes
                        .iter()
                        .position(|node| node.addr == packet.remote_addr)
                        .unwrap();
                    eprintln!(
                        "responsive incoming Msg1: {}",
                        json!({"source":source,"receiver":destination,"bridge":bridge,
                            "sender_index":msg1.as_ref().map(|header|header.sender_idx.as_u32()),
                            "observed_ms":self.started.elapsed().as_millis(),"received_ms":packet.timestamp_ms,
                            "attempts_before":before_packet.as_ref().map(|(_,attempts)|attempts)})
                    );
                    snapshot(nodes, ids, self.started, "responsive-msg1-before");
                }
                process_dataplane_packet(&mut nodes[destination], packet).await;
                if let Some(response) = bridge_msg2.as_ref() {
                    let (before_ms, before) = msg2_before.unwrap();
                    let after = response_owner(&nodes[destination].node);
                    eprintln!(
                        "responsive bridge Msg2: {}",
                        json!({"source":1-destination,"receiver":destination,
                            "sender_index":response.sender_idx.as_u32(),
                            "receiver_index":response.receiver_idx.as_u32(),
                            "received_ms":received_ms,
                            "observation_ms":[before_ms,self.started.elapsed().as_millis()],
                            "before":before,"after":after})
                    );
                }
                if incoming {
                    snapshot(nodes, ids, self.started, "responsive-msg1-after");
                }
                self.incumbents(nodes, ids, before_packet);
                if destination < 2 {
                    self.timing.observe_boundary(
                        &nodes[destination].node,
                        ids,
                        destination,
                        self.started,
                        "packet-completed",
                    );
                }
            }
        }
        caps(nodes);
        if let Some(original) = &mut self.queued_original {
            original.observe(nodes, ids, self.started);
        }
    }

    async fn round(
        &mut self,
        nodes: &mut [TestNode],
        endpoints: &mut [EndpointDataIo],
        ids: &[PeerIdentity],
        sequence: &mut u16,
        flows: &[(usize, usize)],
    ) {
        let current = *sequence;
        *sequence = sequence.checked_add(1).expect("bounded unique payloads");
        send_round_with_tag(nodes, ids, &current.to_le_bytes(), flows).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut received = Vec::new();
        loop {
            self.turn(nodes, ids).await;
            receive_round_with_tag_and_observer(
                endpoints,
                ids,
                &current.to_le_bytes(),
                flows,
                &mut received,
                |destination, source, payload| {
                    self.queued_original.as_mut().is_some_and(|original| {
                        original.receive(destination, source, payload, ids, self.started)
                    })
                },
            );
            if received.len() == flows.len() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "exact direct payloads must continue while candidates compete"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
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

async fn exercise(
    nodes: &mut [TestNode],
    network: &SimNetwork,
    addresses: &[&str],
    window: Duration,
    repeated: bool,
    component_phase: Duration,
    queued_rejoin: bool,
) {
    let ids = identities(nodes);
    let mut observation = Observation::new(component_phase);
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
    connect(&mut observation, nodes, &ids, network, addresses, 0, 4).await;
    let first = nodes[0]
        .node
        .get_peer(ids[4].node_addr())
        .unwrap()
        .authenticated_at();
    while Node::now_ms().saturating_sub(first) < 5_000 {
        observation
            .round(nodes, &mut endpoints, &ids, &mut sequence, &LOCAL_FLOWS)
            .await;
        useful_retained(nodes, &ids, &original);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    connect(&mut observation, nodes, &ids, network, addresses, 1, 5).await;
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
    // Local candidates remain available through every encounter and split.
    // They have no configured peers, application load or forced departure.
    for candidate in 6..addresses.len() {
        network.set_link(
            addresses[candidate % 2],
            addresses[candidate],
            SimLink::default(),
        );
    }
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
            if queued_rejoin {
                observation.queued_original =
                    Some(queued::Original::offer(nodes, &ids, observation.started).await);
            }
        }
        network.set_link(addresses[0], addresses[1], SimLink::default());
        let exposed = tokio::time::Instant::now();
        observation.timing.exposed(observation.started);
        if let Some(original) = &mut observation.queued_original {
            original.exposed(observation.started);
        }
        snapshot(
            nodes,
            &ids,
            observation.started,
            "responsive-bridge-exposed",
        );
        let before_requests = observation.bridge_msg1;
        let mut bridge_at = None;
        let mut delivery_at = None;
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
                    .queued_original
                    .as_ref()
                    .is_none_or(queued::Original::delivered)
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
            while tokio::time::Instant::now() < next_round && exposed.elapsed() < window {
                observation.turn(nodes, &ids).await;
                useful_retained(nodes, &ids, &original);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        caps(nodes);
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
        if let Some(original) = &observation.queued_original {
            original.summary(nodes, &ids, observation.started);
        }
        eprintln!(
            "responsive rendezvous outcome: {}",
            json!({"encounter":encounter,"maintenance_phase_ms":component_phase.as_millis(),
                "cohort_maintenance_turns":observation.cohort_ticks,"candidates_per_boundary":(nodes.len()-4)/2,"window_ms":window.as_millis(),
                "elapsed_ms":exposed.elapsed().as_millis(),"bridge_ms":bridge_at.map(|d|d.as_millis()),
                "bridge_msg1":[observation.bridge_msg1[0]-before_requests[0],
                    observation.bridge_msg1[1]-before_requests[1]],
                "delivery_ms":delivery_at.map(|d|d.as_millis()),"incumbent_changes":observation.replacements,
                "maintenance_turns":observation.ticks,"completed_payload_rounds":sequence})
        );
        assert!(
            observation
                .bridge_msg1
                .iter()
                .zip(before_requests)
                .any(|(after, before)| *after > before),
            "diagnostic premise: discovery must actually offer the exposed bridge"
        );
        assert!(
            bridge_at.is_some_and(|elapsed| elapsed < window),
            "encounter {encounter}: responsive local replacements must not prevent the offset rosters forming a reciprocal bridge within {window:?}"
        );
        if repeated {
            assert!(
                delivery_at.is_some_and(|elapsed| elapsed < window),
                "encounter {encounter}: both native payload directions must complete within the same {window:?}"
            );
        }
        if let Some(original) = &observation.queued_original {
            original.assert_delivered_within(window);
        }
    }
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
