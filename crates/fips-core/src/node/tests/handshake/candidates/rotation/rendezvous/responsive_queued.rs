//! Original endpoint demand competes during unchanged dense cold or warm encounters.
use super::*;

const ORIGINALS: [&[u8]; 2] = [
    b"dense encounter: one original application payload 0 to 1",
    b"dense encounter: one original application payload 1 to 0",
];

#[derive(Clone, Copy)]
pub(super) struct Demand {
    pub encounter: usize,
    pub sources: &'static [usize],
}

#[test]
fn eight_candidates_recover_one_queued_original_during_warm_rejoin() {
    run_population_with_demand(
        Population::baseline(8),
        Duration::from_secs(60),
        true,
        Duration::from_millis(500),
        Some(Demand {
            encounter: 1,
            sources: &[0],
        }),
    );
}

mod cold {
    use super::*;

    fn run(sources: &'static [usize]) {
        run_population_with_demand(
            Population {
                first_scalar: 33,
                ..Population::baseline(8)
            },
            Duration::from_secs(60),
            false,
            Duration::from_millis(500),
            Some(Demand {
                encounter: 0,
                sources,
            }),
        );
    }

    #[test]
    fn one_way_original() {
        run(&[0]);
    }

    #[test]
    fn reciprocal_originals() {
        run(&[0, 1]);
    }
}

pub(super) struct Original {
    encounter: usize,
    source: usize,
    last_demand_state: Option<Value>,
    demand_transitions: usize,
    requested_ms: u128,
    requested_native_ms: u64,
    exposed_ms: Option<u128>,
    first_bridge_attempt_while_queued: Option<Value>,
    reciprocal_ms: Option<u128>,
    delivered_ms: Option<u128>,
    received: usize,
}

impl Original {
    pub(super) async fn offer(
        nodes: &mut [TestNode],
        ids: &[PeerIdentity],
        started: tokio::time::Instant,
        encounter: usize,
        source: usize,
    ) -> Self {
        assert!(source < 2);
        assert!(refilled_components(nodes, ids));
        let destination = 1 - source;
        if encounter == 0 {
            assert!(
                nodes[source]
                    .node
                    .sessions
                    .get(ids[destination].node_addr())
                    .is_none()
            );
        }
        assert!(
            !nodes[source]
                .node
                .pending_session_traffic
                .has_traffic_for(ids[destination].node_addr())
        );
        let mut original = Self {
            encounter,
            source,
            last_demand_state: None,
            demand_transitions: 0,
            requested_ms: started.elapsed().as_millis(),
            requested_native_ms: Node::now_ms(),
            exposed_ms: None,
            first_bridge_attempt_while_queued: None,
            reciprocal_ms: None,
            delivered_ms: None,
            received: 0,
        };
        // Use the normal endpoint ingress once. No manual lookup, flush or dial
        // is allowed to help this retained original before or after exposure.
        nodes[source]
            .node
            .handle_endpoint_data_batch_no_established_flush(
                crate::node::NodeEndpointDataBatch::from_payloads(
                    ids[destination],
                    vec![
                        crate::node::EndpointDataPayload::from_packet_payload(
                            ORIGINALS[source].to_vec(),
                        )
                        .unwrap(),
                    ],
                    None,
                )
                .unwrap(),
            )
            .await;
        let queued = nodes[source]
            .node
            .pending_session_traffic
            .endpoint_data_for(ids[destination].node_addr())
            .map_or(0, |queue| queue.len());
        eprintln!(
            "responsive queued original offer: {}",
            json!({"encounter":encounter,"source":source,"destination":destination,
                "requested_observed_ms":original.requested_ms,
                "requested_native_ms":original.requested_native_ms,"queued_originals":queued})
        );
        assert_eq!(
            queued, 1,
            "the single original must really queue while the refilled components are split"
        );
        assert!(
            nodes[source]
                .node
                .peer_has_queued_application_demand(ids[destination].node_addr())
        );
        original.observe(nodes, ids, started);
        original
    }

    pub(super) fn exposed(&mut self, started: tokio::time::Instant) {
        assert!(
            self.exposed_ms
                .replace(started.elapsed().as_millis())
                .is_none()
        );
    }

    pub(super) fn observe(
        &mut self,
        nodes: &[TestNode],
        ids: &[PeerIdentity],
        started: tokio::time::Instant,
    ) {
        let observed_ms = started.elapsed().as_millis();
        let node = &nodes[self.source].node;
        let target = ids[1 - self.source].node_addr();
        let state = json!({
            "queued_originals":node.pending_session_traffic.endpoint_data_for(target).map_or(0, |queue|queue.len()),
            "queued_demand":node.peer_has_queued_application_demand(target),
            "session_present":node.sessions.get(target).is_some(),
            "session_established":node.sessions.get(target).is_some_and(|session|session.is_established()),
            "explicit_carrier":node.source_routes.get(target).map(|carrier|label(ids,carrier)),
            "session_carrier":node.dataplane.fsp_owner_next_hop(target).map(|carrier|label(ids,&carrier)),
            "lookup_attempt":node.pending_lookups.get(target).map(|lookup|lookup.attempt),
            "discovery_failures":node.discovery_backoff.failure_count(target),
        });
        if self.last_demand_state.as_ref() != Some(&state) {
            self.demand_transitions += 1;
            assert!(
                self.demand_transitions <= 64,
                "bounded demand-state observation"
            );
            eprintln!(
                "responsive queued demand transition: {}",
                json!({
                    "encounter":self.encounter,"source":self.source,"destination":1-self.source,
                    "observed_ms":observed_ms,"state":state,
                })
            );
            self.last_demand_state = Some(state);
        }
        if self.first_bridge_attempt_while_queued.is_none()
            && nodes[self.source]
                .node
                .pending_session_traffic
                .has_traffic_for(ids[1 - self.source].node_addr())
            && let Some(conn) = nodes[self.source]
                .node
                .peers
                .connection_values()
                .find(|conn| {
                    conn.is_outbound()
                        && conn
                            .expected_identity()
                            .is_some_and(|id| id.node_addr() == ids[1 - self.source].node_addr())
                })
        {
            self.first_bridge_attempt_while_queued = Some(json!({
                "observed_ms":observed_ms,"started_native_ms":conn.started_at(),
                "link":conn.link_id().as_u64(),
                "original_rotation_deadline_ms":nodes[self.source].node.neighbor_rotation_deadline(ids[1 - self.source].node_addr())
            }));
        }
        if self.reciprocal_ms.is_none() && reciprocal_bridge(nodes, ids) {
            self.reciprocal_ms = Some(observed_ms);
        }
    }

    pub(super) fn receive(
        &mut self,
        destination: usize,
        source: &PeerIdentity,
        payload: &[u8],
        ids: &[PeerIdentity],
        started: tokio::time::Instant,
    ) -> bool {
        if payload != ORIGINALS[self.source] {
            return false;
        }
        assert_eq!(
            destination,
            1 - self.source,
            "original delivered to the wrong endpoint"
        );
        assert_eq!(source.node_addr(), ids[self.source].node_addr());
        self.received += 1;
        assert_eq!(self.received, 1, "the one original must never arrive twice");
        self.delivered_ms = Some(started.elapsed().as_millis());
        true
    }

    pub(super) fn delivered(&self) -> bool {
        self.received == 1
    }

    pub(super) fn summary(
        &self,
        nodes: &[TestNode],
        ids: &[PeerIdentity],
        started: tokio::time::Instant,
    ) {
        let relative = |observed: Option<u128>| {
            observed
                .zip(self.exposed_ms)
                .map(|(at, exposed)| at.saturating_sub(exposed))
        };
        eprintln!(
            "responsive queued original outcome: {}",
            json!({"encounter":self.encounter,"source":self.source,"destination":1-self.source,
                "demand_transitions":self.demand_transitions,"last_demand_state":self.last_demand_state,
                "requested_observed_ms":self.requested_ms,"requested_native_ms":self.requested_native_ms,
                "exposed_observed_ms":self.exposed_ms,"final_observed_ms":started.elapsed().as_millis(),
                "first_bridge_attempt_while_queued":self.first_bridge_attempt_while_queued,
                "reciprocal_observed_ms":self.reciprocal_ms,"reciprocal_after_exposure_ms":relative(self.reciprocal_ms),
                "delivery_observed_ms":self.delivered_ms,"delivery_after_exposure_ms":relative(self.delivered_ms),
                "original_received":self.received,"queued_originals":nodes[self.source].node.pending_session_traffic
                    .endpoint_data_for(ids[1 - self.source].node_addr()).map_or(0,|queue|queue.len())})
        );
    }

    pub(super) fn assert_delivered_within(
        &self,
        nodes: &[TestNode],
        ids: &[PeerIdentity],
        window: Duration,
    ) {
        assert!(
            !nodes[self.source]
                .node
                .pending_session_traffic
                .has_traffic_for(ids[1 - self.source].node_addr()),
            "the delivered original must leave no queued copy"
        );
        assert_eq!(
            self.received, 1,
            "the queued original must deliver exactly once"
        );
        assert!(
            self.delivered_ms
                .zip(self.exposed_ms)
                .is_some_and(|(at, exposed)| {
                    at >= exposed && at - exposed < window.as_millis()
                }),
            "the original queued payload must arrive inside the unchanged encounter deadline"
        );
    }
}
