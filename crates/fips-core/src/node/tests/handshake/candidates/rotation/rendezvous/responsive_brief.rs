//! Independently cut short contacts with protected or mature idle neighbors.
use super::*;
use tokio::sync::oneshot;

const CONTACT: Duration = Duration::from_millis(1_500);
const SEPARATION: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    Protected,
    Mature,
}

#[test]
fn initial_brief_contact_preserves_bounds_before_sustained_recovery() {
    run_population(
        Population {
            brief_contact: Some(Kind::Protected),
            capacity: CapacityLimits {
                connections: [4, 2],
                links: [4, 2],
            },
            ..Population::baseline(4)
        },
        Duration::from_secs(60),
        false,
        Duration::from_millis(500),
    );
}

#[test]
fn mature_full_rosters_deliver_originals_during_brief_contact() {
    run_population(
        Population {
            brief_contact: Some(Kind::Mature),
            capacity: CapacityLimits {
                connections: [4, 2],
                links: [4, 2],
            },
            ..Population::baseline(4)
        },
        Duration::from_secs(60),
        false,
        Duration::from_millis(500),
    );
}

#[derive(Debug)]
struct Mutation {
    observed_ms: [u128; 2],
    native_ms: [u64; 2],
}

fn mutate(
    network: &SimNetwork,
    addresses: &[String; 2],
    started: tokio::time::Instant,
    up: bool,
) -> Mutation {
    let before = (started.elapsed().as_millis(), Node::now_ms());
    if up {
        network.set_link(&addresses[0], &addresses[1], SimLink::default());
    } else {
        network.set_link_up(&addresses[0], &addresses[1], false);
    }
    Mutation {
        observed_ms: [before.0, started.elapsed().as_millis()],
        native_ms: [before.1, Node::now_ms()],
    }
}

type Owner = (NodeAddr, LinkId, u64);
type Owners = Vec<Owner>;

fn owners(node: &Node) -> Owners {
    let mut owners: Owners = node
        .peers
        .values()
        .map(|peer| (*peer.node_addr(), peer.link_id(), peer.authenticated_at()))
        .collect();
    owners.sort_unstable_by_key(|owner| owner.0);
    owners
}

struct Evidence {
    initial_owners: [Owners; 2],
    owners_retained: [bool; 2],
    useful_owners: [Owner; 2],
    idle_maturity_ms: [u64; 2],
    useful_demand_at_every_observation: [bool; 2],
    reciprocal_observation_ms: Option<[u128; 2]>,
    samples: usize,
}

impl Evidence {
    fn new(nodes: &[TestNode], ids: &[PeerIdentity]) -> Self {
        let initial_owners = std::array::from_fn(|at| {
            let node = &nodes[at].node;
            let config = node.config.node.neighbor_rotation.as_ref().unwrap();
            assert_eq!(config.idle_secs, 10);
            assert_eq!(config.interval_secs, 2);
            assert_eq!(node.config.node.limits.max_peers, 2);
            assert_eq!(node.peer_count(), 2);
            owners(node)
        });
        let useful_owners: [Owner; 2] = std::array::from_fn(|at| {
            *initial_owners[at]
                .iter()
                .find(|owner| owner.0 == *ids[at + 2].node_addr())
                .unwrap()
        });
        let idle_maturity_ms = std::array::from_fn(|at| {
            initial_owners[at]
                .iter()
                .find(|owner| owner.0 != useful_owners[at].0)
                .unwrap()
                .2
                + 10_000
        });
        Self {
            initial_owners,
            owners_retained: [true; 2],
            useful_owners,
            idle_maturity_ms,
            useful_demand_at_every_observation: [true; 2],
            reciprocal_observation_ms: None,
            samples: 0,
        }
    }

    fn observe(&mut self, nodes: &[TestNode], ids: &[PeerIdentity], started: tokio::time::Instant) {
        let before = started.elapsed().as_millis();
        let now = Node::now_ms();
        for (at, test) in nodes.iter().take(2).enumerate() {
            let retained = owners(&test.node) == self.initial_owners[at];
            self.owners_retained[at] &= retained;
            let useful = &self.useful_owners[at];
            assert!(
                now >= useful.2 + 10_000,
                "useful owner must already be mature"
            );
            let demanded = test.node.get_peer(&useful.0).is_some_and(|peer| {
                test.node
                    .peer_has_application_demand(&useful.0, now, 10_000)
                    || peer.has_recent_transit_demand(now, 10_000)
            });
            self.useful_demand_at_every_observation[at] &= demanded;
            assert!(
                demanded,
                "real local traffic must protect the mature useful owner"
            );
            if now < self.idle_maturity_ms[at] {
                assert!(
                    retained,
                    "demanded useful owner and immature idle owner stay retained"
                );
            }
        }
        if self.reciprocal_observation_ms.is_none() && reciprocal_bridge(nodes, ids) {
            self.reciprocal_observation_ms = Some([before, started.elapsed().as_millis()]);
        }
        self.samples += 1;
    }
}

// Match the paid premise without aging timestamps: useful links carry real
// traffic until mature, before either idle slot is filled. Other cases keep
// their original setup, traffic cadence and exposure time.
pub(super) async fn mature_useful_owners(
    observation: &mut Observation,
    nodes: &mut [TestNode],
    endpoints: &mut [EndpointDataIo],
    ids: &[PeerIdentity],
    sequence: &mut u16,
    useful: &[RetainedNeighbor],
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while useful
        .iter()
        .any(|owner| Node::now_ms().saturating_sub(owner.authenticated_at) < 10_000)
    {
        observation
            .round(nodes, endpoints, ids, sequence, &LOCAL_FLOWS)
            .await;
        useful_retained(nodes, ids, useful);
        assert!(
            nodes[..2].iter().all(|test| test.node.peer_count() == 1),
            "idle slots must remain empty until useful owners mature"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "bounded real useful-owner maturation"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn observe(
    observation: &mut Observation,
    nodes: &mut [TestNode],
    endpoints: &mut [EndpointDataIo],
    ids: &[PeerIdentity],
    sequence: &mut u16,
    network: &SimNetwork,
    addresses: &[&str],
    kind: Kind,
) -> bool {
    assert_eq!(observation.component_phase, Duration::from_millis(500));
    assert!(refilled_components(nodes, ids));
    assert!(!reciprocal_bridge(nodes, ids));
    if kind == Kind::Mature {
        // Maturation retained the exact original owners through an interval.
        // Initial simultaneous-connect carrier handover may precede that proof.
        ready::assert_ready(nodes, ids);
    }
    let useful: Vec<_> = (0..2).map(|at| original_owner(nodes, ids, at)).collect();
    let mut evidence = Evidence::new(nodes, ids);
    evidence.observe(nodes, ids, observation.started);
    let requests_before = observation.bridge_msg1;
    let local_rounds_before = *sequence;
    let network = network.clone();
    let addresses = [addresses[0].to_owned(), addresses[1].to_owned()];
    let started = observation.started;
    let (opened_tx, opened_rx) = oneshot::channel();
    // The carrier closes on its own task even if a local payload round, packet
    // handler or authentication wait has not returned. Never wait for a bridge.
    let driver = tokio::spawn(async move {
        let opened = mutate(&network, &addresses, started, true);
        let cut_at = tokio::time::Instant::now() + CONTACT;
        opened_tx.send(opened).unwrap();
        tokio::time::sleep_until(cut_at).await;
        let closed = mutate(&network, &addresses, started, false);
        tokio::time::sleep(SEPARATION).await;
        closed
    });
    let opened = opened_rx.await.unwrap();
    let result = AssertUnwindSafe(async {
        if kind == Kind::Mature {
            let mut payloads = ready::Payloads::default();
            payloads.offer(nodes, ids, observation.started).await;
            observation.brief_payloads = Some(payloads);
        }
        observation.timing.exposed(observation.started);
        observation
            .timing
            .observe(nodes, ids, observation.started, "brief-opened");
        snapshot(nodes, ids, observation.started, "brief-opened");
        let mut next_round = tokio::time::Instant::now();
        while !driver.is_finished() {
            if tokio::time::Instant::now() >= next_round {
                observation
                    .round(nodes, endpoints, ids, sequence, &LOCAL_FLOWS)
                    .await;
                next_round = tokio::time::Instant::now() + Duration::from_millis(500);
            } else {
                observation.turn(nodes, ids).await;
                if let Some(payloads) = &mut observation.brief_payloads {
                    payloads.drain(endpoints, ids, observation.started);
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            useful_retained(nodes, ids, &useful);
            evidence.observe(nodes, ids, observation.started);
        }
    })
    .catch_unwind()
    .await;
    // Join on failure too: a detached cut must never affect later cleanup or
    // the ordinary sustained opening. This wait is bounded by the contact task.
    let closed = driver.await.unwrap();
    observation
        .timing
        .observe(nodes, ids, observation.started, "brief-closed");
    snapshot(nodes, ids, observation.started, "brief-closed");
    let duration_bounds_ms = [
        closed.observed_ms[0].saturating_sub(opened.observed_ms[1]),
        closed.observed_ms[1].saturating_sub(opened.observed_ms[0]),
    ];
    let age_excluded: [bool; 2] = std::array::from_fn(|at| {
        evidence.owners_retained[at]
            && evidence.useful_demand_at_every_observation[at]
            && evidence.idle_maturity_ms[at] > closed.native_ms[1]
    });
    let reciprocal_in_contact = evidence
        .reciprocal_observation_ms
        .is_some_and(|bracket| bracket[1] <= closed.observed_ms[0]);
    let payloads_in_contact = observation
        .brief_payloads
        .as_ref()
        .is_some_and(|payloads| payloads.accepted(closed.observed_ms[0]));
    // An unchanged full roster with actual demand on its mature useful owner
    // and an idle owner immature through the cut proves this exclusion. Slot
    // counts and victim_selection_ready never establish full admissibility.
    let classification = if age_excluded.into_iter().any(|excluded| excluded) {
        assert!(!reciprocal_in_contact);
        "useful_demand_and_idle_minimum_age_exclude_admission"
    } else if payloads_in_contact && reciprocal_in_contact {
        "mature_contact_delivered_both_originals"
    } else if reciprocal_in_contact {
        "reciprocal_bridge_observed_before_cut"
    } else {
        "no_reciprocal_bridge_observed_admissibility_unproved"
    };
    eprintln!(
        "responsive brief contact outcome: {}",
        json!({"schema":1,"classification":classification,"contact_kind":kind,
            "opened_observation_ms":opened.observed_ms,"opened_native_ms":opened.native_ms,
            "closed_observation_ms":closed.observed_ms,"closed_native_ms":closed.native_ms,
            "actual_duration_bounds_ms":duration_bounds_ms,"scheduled_duration_ms":CONTACT.as_millis(),
            "idle_incumbent_maturity_ms":evidence.idle_maturity_ms,
            "useful_owner_authenticated_ms":evidence.useful_owners.map(|owner|owner.2),
            "useful_demand_at_every_observation":evidence.useful_demand_at_every_observation,
            "full_original_rosters_retained":evidence.owners_retained,
            "minimum_age_excluded":age_excluded,"state_samples":evidence.samples,
            "reciprocal_observation_ms":evidence.reciprocal_observation_ms,
            "requests_processed_including_post_cut":[observation.bridge_msg1[0]-requests_before[0],
                observation.bridge_msg1[1]-requests_before[1]],
            "completed_local_rounds":*sequence-local_rounds_before,
            "cross_boundary_payloads_offered":if kind == Kind::Mature {2} else {0},
            "payloads":observation.brief_payloads.as_ref().map(ready::Payloads::summary),
            "subsequent_sustained_window_ms":60_000})
    );
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    assert!(
        duration_bounds_ms[0] >= 1_499 && duration_bounds_ms[1] <= 2_000,
        "actual carrier mutation must retain the bounded 1.5-second contact"
    );
    if kind == Kind::Protected {
        assert!(
            age_excluded.into_iter().all(|excluded| excluded),
            "both boundaries must retain mature demanded useful and immature idle owners through the actual contact"
        );
    }
    assert!(
        *sequence > local_rounds_before,
        "useful local payloads must deliver"
    );
    useful_retained(nodes, ids, &useful);
    caps_with_limits(nodes, observation.capacity);
    kind == Kind::Protected || (reciprocal_in_contact && payloads_in_contact)
}
