//! Initial admission eligibility and original payloads for a finite contact.
use super::*;
use crate::node::acl::PeerAclContext;

const IDLE_MS: u64 = 10_000;
const SPACING_MS: u64 = 2_000;
const FLOWS: [(usize, usize); 2] = [(2, 3), (3, 2)];
const ORIGINALS: [&[u8]; 2] = [
    b"ready brief contact: one original useful 2 to 3",
    b"ready brief contact: one original useful 3 to 2",
];

fn idle_owners(nodes: &[TestNode], ids: &[PeerIdentity]) -> [(LinkId, u64); 2] {
    std::array::from_fn(|at| {
        let peer = nodes[at].node.get_peer(ids[at + 4].node_addr()).unwrap();
        (peer.link_id(), peer.authenticated_at())
    })
}

pub(super) async fn mature_idle_owners(
    observation: &mut Observation,
    nodes: &mut [TestNode],
    endpoints: &mut [EndpointDataIo],
    ids: &[PeerIdentity],
    sequence: &mut u16,
    useful: &[RetainedNeighbor],
) {
    let original = idle_owners(nodes, ids);
    let replacements = observation.replacements;
    let started_ms = Node::now_ms();
    let deadline_ms = started_ms + 15_000;
    // Unchanged original owners for one replacement interval establish spacing
    // in this initial fixture. No private pacing clock is reset or synthesized.
    let ready_ms = original
        .iter()
        .map(|owner| owner.1 + IDLE_MS)
        .max()
        .unwrap()
        .max(started_ms + SPACING_MS);
    while Node::now_ms() < ready_ms {
        observation
            .round(nodes, endpoints, ids, sequence, &LOCAL_FLOWS)
            .await;
        useful_retained(nodes, ids, useful);
        assert_eq!(
            idle_owners(nodes, ids),
            original,
            "original idle owners stay retained"
        );
        caps_with_limits(nodes, observation.capacity);
        assert!(
            Node::now_ms() <= deadline_ms,
            "bounded real idle-owner maturation"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(Node::now_ms() <= deadline_ms);
    useful_retained(nodes, ids, useful);
    assert_eq!(idle_owners(nodes, ids), original);
    assert_eq!(observation.replacements, replacements);
    caps_with_limits(nodes, observation.capacity);
}

/// Read-only eligibility for this initial setup, after mature_idle_owners has
/// retained both original rosters through an existing replacement interval.
/// These checks do not promise future promotion: discovery ordering, live
/// capacity, the rate limiter, Noise proof and final admission remain in charge.
pub(super) fn assert_ready(nodes: &[TestNode], ids: &[PeerIdentity]) {
    let now = Node::now_ms();
    for at in 0..2 {
        let node = &nodes[at].node;
        let remote = &ids[1 - at];
        let address = &nodes[1 - at].addr;
        let transport_id = nodes[at].transport_id;
        let config = node.config.node.neighbor_rotation.as_ref().unwrap();
        assert_eq!((config.idle_secs, config.interval_secs), (10, 2));
        assert_eq!(node.peer_count(), 2);
        assert!(node.neighbor_roster_full());
        assert!(node.config.peers.is_empty());
        assert!(node.get_peer(remote.node_addr()).is_none());
        assert!(node.peers.connection_is_empty());
        assert!(node.pending_connects.is_empty());
        assert!(
            ids.iter()
                .all(|id| node.neighbor_rotation_deadline(id.node_addr()).is_none())
        );

        let idle = node.get_peer(ids[at + 4].node_addr()).unwrap();
        let useful = node.get_peer(ids[at + 2].node_addr()).unwrap();
        assert!(idle.is_healthy() && idle.can_send());
        assert!(useful.is_healthy() && useful.can_send());
        assert!(now.saturating_sub(idle.authenticated_at()) >= IDLE_MS);
        assert!(now.saturating_sub(useful.authenticated_at()) >= IDLE_MS);
        assert!(!node.is_configured_peer_identity(idle.identity()));
        assert!(!idle.has_recent_transit_demand(now, IDLE_MS));
        assert!(!node.peer_has_application_demand(idle.node_addr(), now, IDLE_MS));
        assert!(
            node.peer_has_application_demand(useful.node_addr(), now, IDLE_MS)
                || useful.has_recent_transit_demand(now, IDLE_MS)
        );

        // Preparation alone ignores minimum age; pair it with the mature
        // production opportunity and the exact independently checked victim.
        assert!(node.has_neighbor_rotation_opportunity(now));
        assert_eq!(node.discovery_rotation_victim(now), Some(*idle.node_addr()));
        assert!(!node.neighbor_rotation_discovery_turn_reserved(now));
        assert!(node.can_attempt_neighbor_rotation(remote.node_addr(), true, now));
        assert!(node.can_receive_neighbor_rotation(remote.node_addr(), now));
        // This fixture's four-link boundary can hold one candidate in each
        // direction without borrowing from the two authenticated incumbents.
        assert!(node.outbound_handshake_slots() >= 2);
        assert!(node.outbound_link_slots() >= 2);
        assert_eq!(node.msg1_rate_limiter.pending_count(), 0);

        let transport = node.transports.get(&transport_id).unwrap();
        assert!(transport.is_operational() && transport.auto_connect());
        assert!(transport.accept_connections());
        assert!(node.should_admit_msg1(transport_id, address));
        for context in [
            PeerAclContext::OutboundConnect,
            PeerAclContext::OutboundHandshake,
            PeerAclContext::InboundHandshake,
        ] {
            assert!(
                node.authorize_peer(remote, context, transport_id, address)
                    .is_ok()
            );
        }
    }
}

#[derive(Default)]
pub(super) struct Payloads {
    submitted_ms: [[Option<u128>; 2]; 2],
    received_ms: [Option<[u128; 2]>; 2],
    received: [usize; 2],
    last_state: [Option<Value>; 2],
    transitions: [usize; 2],
}

impl Payloads {
    pub(super) async fn offer(
        &mut self,
        nodes: &mut [TestNode],
        ids: &[PeerIdentity],
        started: tokio::time::Instant,
    ) {
        assert!(self.submitted_ms.iter().all(|span| *span == [None, None]));
        for (direction, &(source, destination)) in FLOWS.iter().enumerate() {
            assert!(
                nodes[source]
                    .node
                    .sessions
                    .get(ids[destination].node_addr())
                    .is_none(),
                "short-contact original starts without a warm end-to-end session"
            );
            assert!(
                !nodes[source]
                    .node
                    .pending_session_traffic
                    .has_traffic_for(ids[destination].node_addr()),
                "no earlier queued cross-component traffic"
            );
            self.submitted_ms[direction][0] = Some(started.elapsed().as_millis());
            // Normal ingress exactly once, without a lookup, explicit flush,
            // dial or later resubmission to help this original.
            nodes[source]
                .node
                .handle_endpoint_data_batch_no_established_flush(
                    crate::node::NodeEndpointDataBatch::from_payloads(
                        ids[destination],
                        vec![
                            crate::node::EndpointDataPayload::from_packet_payload(
                                ORIGINALS[direction].to_vec(),
                            )
                            .unwrap(),
                        ],
                        None,
                    )
                    .unwrap(),
                )
                .await;
            self.submitted_ms[direction][1] = Some(started.elapsed().as_millis());
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
        let before_ms = started.elapsed().as_millis();
        let Some(direction) = ORIGINALS.iter().position(|original| *original == payload) else {
            return false;
        };
        let expected = FLOWS[direction];
        assert_eq!(destination, expected.1);
        assert_eq!(source.node_addr(), ids[expected.0].node_addr());
        assert!(
            self.submitted_ms[direction][0].is_some(),
            "original was offered"
        );
        self.received[direction] += 1;
        assert_eq!(
            self.received[direction], 1,
            "one original cannot arrive twice"
        );
        self.received_ms[direction] = Some([before_ms, started.elapsed().as_millis()]);
        true
    }

    pub(super) fn drain(
        &mut self,
        endpoints: &mut [EndpointDataIo],
        ids: &[PeerIdentity],
        started: tokio::time::Instant,
    ) {
        // Between completed local rounds only the originals may arrive. Use
        // the common strict receiver and release its normal receive credits.
        receive_round_with_tag_and_observer(
            endpoints,
            ids,
            &[],
            &[],
            &mut Vec::new(),
            |destination, source, payload| self.receive(destination, source, payload, ids, started),
        );
    }

    pub(super) fn observe(
        &mut self,
        nodes: &[TestNode],
        ids: &[PeerIdentity],
        started: tokio::time::Instant,
    ) {
        for (direction, &(source, destination)) in FLOWS.iter().enumerate() {
            let before = started.elapsed().as_millis();
            let node = &nodes[source].node;
            let target = ids[destination].node_addr();
            let peers: Vec<_> = node
                .peers
                .iter()
                .map(|(address, peer)| {
                    json!({"node":label(ids,address),"can_send":peer.can_send(),
                    "healthy":peer.is_healthy(),"tree_peer":node.is_tree_peer(address),
                    "may_reach_target":peer.may_reach(target)})
                })
                .collect();
            let state = json!({
                "queued":node.pending_session_traffic.endpoint_data_for(target).map_or(0,|q|q.len()),
                "session_present":node.sessions.get(target).is_some(),
                "session_established":node.sessions.get(target).is_some_and(|s|s.is_established()),
                "lookup":node.pending_lookups.get(target).map(|lookup|json!({
                    "attempt":lookup.attempt,"initiated_ms":lookup.initiated_ms,
                    "last_sent_ms":lookup.last_sent_ms,"awaiting_first_request":lookup.awaiting_first_request(),
                    "deadline_ms":lookup.deadline_ms(&node.config.node.discovery.attempt_timeouts_secs)})),
                "discovery_failures":node.discovery_backoff.failure_count(target),
                "peers":peers,
                "root":label(ids,node.tree_state().root()),
                "explicit_carrier":node.source_routes.get(target).map(|peer|label(ids,peer)),
                "session_carrier":node.dataplane.fsp_owner_next_hop(target).map(|peer|label(ids,&peer))});
            if self.last_state[direction].as_ref() != Some(&state) {
                self.transitions[direction] += 1;
                assert!(
                    self.transitions[direction] <= 64,
                    "bounded original-state trace"
                );
                eprintln!(
                    "responsive brief original transition: {}",
                    json!({
                    "source":source,"destination":destination,
                    "observation_ms":[before,started.elapsed().as_millis()],
                    "native_ms":Node::now_ms(),"state":state})
                );
                self.last_state[direction] = Some(state);
            }
        }
    }

    pub(super) fn accepted(&self, cut_before_ms: u128) -> bool {
        (0..2).all(|direction| {
            let [Some(submitted_before), Some(submitted_after)] = self.submitted_ms[direction]
            else {
                return false;
            };
            let Some([received_before, received_after]) = self.received_ms[direction] else {
                return false;
            };
            self.received[direction] == 1
                && submitted_before <= submitted_after
                && submitted_after < cut_before_ms
                && received_before <= received_after
                && received_after < cut_before_ms
        })
    }

    pub(super) fn summary(&self) -> serde_json::Value {
        json!({"submission_observation_ms":self.submitted_ms,
            "receipt_observation_ms":self.received_ms,"received_counts":self.received,
            "transitions":self.transitions,"last_state":self.last_state})
    }
}
