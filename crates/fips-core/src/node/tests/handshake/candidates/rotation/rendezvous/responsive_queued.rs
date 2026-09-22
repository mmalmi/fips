//! One queued original competes during the unchanged dense warm encounter.
use super::*;

const ORIGINAL: &[u8] = b"dense warm rejoin: one original application payload 0 to 1";

#[test]
fn eight_candidates_recover_one_queued_original_during_warm_rejoin() {
    run_population_with_queued_rejoin(
        Population::baseline(8),
        Duration::from_secs(60),
        true,
        Duration::from_millis(500),
        true,
    );
}

pub(super) struct Original {
    requested_ms: u128,
    requested_native_ms: u64,
    exposed_ms: Option<u128>,
    first_demanded_attempt: Option<Value>,
    reciprocal_ms: Option<u128>,
    delivered_ms: Option<u128>,
    received: usize,
}

impl Original {
    pub(super) async fn offer(
        nodes: &mut [TestNode],
        ids: &[PeerIdentity],
        started: tokio::time::Instant,
    ) -> Self {
        assert!(refilled_components(nodes, ids));
        assert!(
            !nodes[0]
                .node
                .pending_session_traffic
                .has_traffic_for(ids[1].node_addr())
        );
        let original = Self {
            requested_ms: started.elapsed().as_millis(),
            requested_native_ms: Node::now_ms(),
            exposed_ms: None,
            first_demanded_attempt: None,
            reciprocal_ms: None,
            delivered_ms: None,
            received: 0,
        };
        // Use the normal endpoint ingress once. No manual lookup, flush or dial
        // is allowed to help this retained original before or after exposure.
        nodes[0]
            .node
            .handle_endpoint_data_batch_no_established_flush(
                crate::node::NodeEndpointDataBatch::from_payloads(
                    ids[1],
                    vec![
                        crate::node::EndpointDataPayload::from_packet_payload(ORIGINAL.to_vec())
                            .unwrap(),
                    ],
                    None,
                )
                .unwrap(),
            )
            .await;
        let queued = nodes[0]
            .node
            .pending_session_traffic
            .endpoint_data_for(ids[1].node_addr())
            .map_or(0, |queue| queue.len());
        eprintln!(
            "responsive queued original offer: {}",
            json!({"encounter":1,"source":0,"destination":1,
                "requested_observed_ms":original.requested_ms,
                "requested_native_ms":original.requested_native_ms,"queued_originals":queued})
        );
        assert_eq!(
            queued, 1,
            "the single original must really queue while the refilled components are split"
        );
        assert!(
            nodes[0]
                .node
                .peer_has_queued_application_demand(ids[1].node_addr())
        );
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
        if self.first_demanded_attempt.is_none()
            && nodes[0]
                .node
                .pending_session_traffic
                .has_traffic_for(ids[1].node_addr())
            && let Some(conn) = nodes[0].node.peers.connection_values().find(|conn| {
                conn.is_outbound()
                    && conn
                        .expected_identity()
                        .is_some_and(|id| id.node_addr() == ids[1].node_addr())
            })
        {
            self.first_demanded_attempt = Some(json!({
                "observed_ms":observed_ms,"started_native_ms":conn.started_at(),
                "link":conn.link_id().as_u64(),
                "original_rotation_deadline_ms":nodes[0].node.neighbor_rotation_deadline(ids[1].node_addr())
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
        if payload != ORIGINAL {
            return false;
        }
        assert_eq!(destination, 1, "original delivered to the wrong endpoint");
        assert_eq!(source.node_addr(), ids[0].node_addr());
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
            json!({"encounter":1,"source":0,"destination":1,
                "requested_observed_ms":self.requested_ms,"requested_native_ms":self.requested_native_ms,
                "exposed_observed_ms":self.exposed_ms,"final_observed_ms":started.elapsed().as_millis(),
                "first_demanded_attempt":self.first_demanded_attempt,
                "reciprocal_observed_ms":self.reciprocal_ms,"reciprocal_after_exposure_ms":relative(self.reciprocal_ms),
                "delivery_observed_ms":self.delivered_ms,"delivery_after_exposure_ms":relative(self.delivered_ms),
                "original_received":self.received,"queued_originals":nodes[0].node.pending_session_traffic
                    .endpoint_data_for(ids[1].node_addr()).map_or(0,|queue|queue.len())})
        );
    }

    pub(super) fn assert_delivered_within(&self, window: Duration) {
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
