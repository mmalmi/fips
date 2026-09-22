//! Bounded, read-only transition evidence on the existing fixture's clock.
use super::*;

const MAX_TRANSITIONS_PER_BOUNDARY: usize = 256;

#[derive(Default)]
pub(super) struct Ledger {
    maintenance_phase_ms: u64,
    last: [Option<Value>; 2],
    previous_read: [Option<[u64; 2]>; 2],
    emitted: [usize; 2],
    omitted: [usize; 2],
    samples: [usize; 2],
    exposure_ms: Option<u64>,
}

fn elapsed_ms(started: tokio::time::Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap()
}

impl Ledger {
    pub(super) fn with_maintenance_phase(maintenance_phase_ms: u64) -> Self {
        Self {
            maintenance_phase_ms,
            ..Self::default()
        }
    }

    pub(super) fn exposed(&mut self, started: tokio::time::Instant) {
        self.exposure_ms = Some(elapsed_ms(started));
    }

    pub(super) fn observe(
        &mut self,
        nodes: &[TestNode],
        ids: &[PeerIdentity],
        started: tokio::time::Instant,
        phase: &str,
    ) {
        for (boundary, node) in nodes.iter().take(2).enumerate() {
            self.observe_boundary(&node.node, ids, boundary, started, phase);
        }
    }

    pub(super) fn observe_boundary(
        &mut self,
        node: &Node,
        ids: &[PeerIdentity],
        boundary: usize,
        started: tokio::time::Instant,
        phase: &str,
    ) {
        let before = elapsed_ms(started);
        let now = Node::now_ms();
        let state = state(node, ids, now);
        let observed = [before, elapsed_ms(started)];
        self.samples[boundary] += 1;
        if self.last[boundary].as_ref() != Some(&state) {
            if self.emitted[boundary] < MAX_TRANSITIONS_PER_BOUNDARY {
                eprintln!(
                    "responsive timing transition: {}",
                    json!({"schema":1,"boundary":boundary,"phase":phase,
                        "initial_maintenance_offset_ms":if boundary == 1 { self.maintenance_phase_ms } else { 0 },
                        "observation_ms":observed,
                        "previous_observation_ms":self.previous_read[boundary],
                        "bridge_exposure_ms":self.exposure_ms,"native_now_ms":now,
                        "state":state})
                );
                self.emitted[boundary] += 1;
            } else {
                self.omitted[boundary] += 1;
            }
            self.last[boundary] = Some(state);
        }
        self.previous_read[boundary] = Some(observed);
    }

    pub(super) fn summary(&self, started: tokio::time::Instant) {
        eprintln!(
            "responsive timing summary: {}",
            json!({"schema":1,"observed_ms":elapsed_ms(started),
                "maintenance_phase_ms":self.maintenance_phase_ms,
                "bridge_exposure_ms":self.exposure_ms,"samples":self.samples,
                "transitions_emitted":self.emitted,"transitions_omitted":self.omitted,
                "complete":self.omitted == [0,0],"final_states":self.last})
        );
    }
}

fn state(node: &Node, ids: &[PeerIdentity], now: u64) -> Value {
    let config = node.config.node.neighbor_rotation.as_ref().unwrap();
    let idle_ms = config.idle_secs.saturating_mul(1000);
    let timeout_ms = node
        .config
        .node
        .rate_limit
        .handshake_timeout_secs
        .saturating_mul(1000);
    let mut peers: Vec<_> = node.peers.values().collect();
    peers.sort_by_key(|peer| *peer.node_addr());
    let incumbents: Vec<_> = peers
        .into_iter()
        .map(|peer| {
            json!({"node":label(ids,peer.node_addr()),"link":peer.link_id().as_u64(),
            "authenticated_ms":peer.authenticated_at(),
            "matures_ms":peer.authenticated_at().saturating_add(idle_ms),
            "mature":now.saturating_sub(peer.authenticated_at()) >= idle_ms,
            "recent_transit_demand":peer.has_recent_transit_demand(now,idle_ms),
            "application_demand":node.peer_has_application_demand(peer.node_addr(),now,idle_ms)})
        })
        .collect();
    let mut connections: Vec<_> = node.peers.connection_values().collect();
    connections.sort_by_key(|conn| conn.link_id().as_u64());
    let candidates: Vec<_> = connections.into_iter().map(|conn| {
        let identity = conn.expected_identity();
        let deadline = identity.and_then(|id|node.neighbor_rotation_deadline(id.node_addr()));
        let next_resend = conn.next_resend_at_ms();
        // This exact production helper is read-only. It checks victim/attempt
        // eligibility, but does not alone prove ACL, carrier or retained-proof
        // validity at the later handler. Never label it "fully ready" or assert
        // a promotion deadline from its result. The normal handler owns that.
        let victim_selection_ready = identity.is_some_and(|id|
            node.choose_neighbor_rotation_promotion(conn.link_id(),id).is_some());
        json!({"node":identity.map(|id|label(ids,id.node_addr())),
            "link":conn.link_id().as_u64(),"outbound":conn.is_outbound(),
            "our_index":conn.our_index().map(|index|index.as_u32()),
            "their_index":conn.their_index().map(|index|index.as_u32()),
            "state":format!("{:?}",conn.handshake_state()),"has_session":conn.has_session(),
            "connection_started_ms":conn.started_at(),
            "rotation_started_ms":identity.and_then(|id|node.neighbor_rotation_started_at(id.node_addr())),
            "original_rotation_deadline_ms":deadline,
            "rotation_expired":deadline.is_some_and(|at|now >= at),
            "connection_idle_deadline_ms":conn.last_activity().saturating_add(timeout_ms),
            "connection_timed_out":conn.is_timed_out(now,timeout_ms),
            "stored_inbound_msg2":conn.handshake_msg2().is_some(),
            "retained_outbound_msg2_received_ms":conn.completed_handshake_response().map(|p|p.timestamp_ms),
            "retained_confirmation_received_ms":conn.handshake_confirmation().map(|p|p.timestamp_ms),
            "victim_selection_ready":victim_selection_ready,
            "next_resend_ms":next_resend,"resend_due":next_resend > 0 && now >= next_resend,
            "resend_count":conn.resend_count()})
    }).collect();
    // No routing selector, manual flush, extra timer turn or packet mutation. Clock
    // crossings are observed, not exact wire timestamps. Native deadlines use
    // Node's wall clock; observation brackets use the fixture's monotonic clock.
    json!({"incumbents":incumbents,"candidates":candidates,
        "pending_transport_count":node.pending_connects.len(),
        "preparation_opportunity":node.has_neighbor_preparation_opportunity(now),
        "mature_rotation_opportunity":node.has_neighbor_rotation_opportunity(now),
        "outbound_turn_reserved":node.neighbor_rotation_discovery_turn_reserved(now),
        "discovery_victim":node.discovery_rotation_victim(now).map(|id|label(ids,&id))})
}
