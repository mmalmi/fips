//! Read-only observations on the unchanged fixture's monotonic clock.
//! Observation brackets are microseconds since the original offer; native
//! timestamps/deadlines retain their existing wall-clock millisecond domain.
//! Sequential samples bracket observed transitions, not wire-event timestamps.
use super::*;
use serde_json::{Value, json};

const MAX_TRANSITIONS: usize = 128;
const MAX_MAINTENANCE_BOUNDARIES: usize = 64;

pub(super) struct Ledger {
    case: Case,
    offered: Instant,
    destination_index: usize,
    source: NodeAddr,
    destination: NodeAddr,
    tun: bool,
    last: [Option<Value>; 2],
    previous_read_us: [Option<[u64; 2]>; 2],
    emitted: usize,
    omitted: usize,
    maintenance: Vec<Value>,
    omitted_maintenance: usize,
    delivered_us: Option<u64>,
}

impl Ledger {
    pub(super) fn new(
        case: Case,
        offered: Instant,
        destination_index: usize,
        source: NodeAddr,
        destination: NodeAddr,
        tun: bool,
    ) -> Self {
        Self {
            case,
            offered,
            destination_index,
            source,
            destination,
            tun,
            last: [None, None],
            previous_read_us: [None, None],
            emitted: 0,
            omitted: 0,
            maintenance: Vec::new(),
            omitted_maintenance: 0,
            delivered_us: None,
        }
    }

    fn elapsed_us(&self) -> u64 {
        self.offered.elapsed().as_micros().try_into().unwrap()
    }

    fn side(&self, index: usize) -> Option<usize> {
        if index == 0 {
            Some(0)
        } else if index == self.destination_index {
            Some(1)
        } else {
            None
        }
    }

    pub(super) fn observe(&mut self, nodes: &[TestNode], phase: &str) {
        self.observe_node(&nodes[0].node, 0, phase);
        self.observe_node(
            &nodes[self.destination_index].node,
            self.destination_index,
            phase,
        );
    }

    pub(super) fn observe_node(&mut self, node: &Node, index: usize, phase: &str) {
        let Some(side) = self.side(index) else {
            return;
        };
        let before = self.elapsed_us();
        let target = if side == 0 {
            self.destination
        } else {
            self.source
        };
        let state = state(node, &target, self.tun);
        let observed = [before, self.elapsed_us()];
        if self.last[side].as_ref() != Some(&state) {
            if self.emitted < MAX_TRANSITIONS {
                eprintln!(
                    "queued demand timing transition: {}",
                    json!({
                        "schema":1, "case":format!("{:?}",self.case), "side":side,
                        "phase":phase, "observation_us":observed,
                        "previous_observation_us":self.previous_read_us[side], "state":state
                    })
                );
                self.emitted += 1;
            } else {
                self.omitted += 1;
            }
            self.last[side] = Some(state);
        }
        self.previous_read_us[side] = Some(observed);
    }

    pub(super) fn maintenance(&mut self, node: &Node, index: usize, phase: &str) {
        let Some(side) = self.side(index) else {
            return;
        };
        if self.maintenance.len() < MAX_MAINTENANCE_BOUNDARIES {
            self.maintenance
                .push(json!({"side":side,"phase":phase,"observed_us":self.elapsed_us()}));
        } else {
            self.omitted_maintenance += 1;
        }
        self.observe_node(node, index, phase);
    }

    pub(super) fn delivered(&mut self, observed: Instant) {
        self.delivered_us = Some(
            observed
                .duration_since(self.offered)
                .as_micros()
                .try_into()
                .unwrap(),
        );
    }
}

impl Drop for Ledger {
    fn drop(&mut self) {
        // Emit the bounded summary on success and assertion unwind. No packet,
        // selector, maintenance or cleanup operation runs from this observer.
        eprintln!(
            "queued demand timing summary: {}",
            json!({
                "schema":1,"case":format!("{:?}",self.case),"elapsed_us":self.elapsed_us(),
                "delivered_observed_us":self.delivered_us,"transitions_emitted":self.emitted,
                "transitions_omitted":self.omitted,"maintenance_boundaries":self.maintenance,
                "maintenance_omitted":self.omitted_maintenance,
                "complete":self.omitted == 0 && self.omitted_maintenance == 0
            })
        );
    }
}

fn state(node: &Node, target: &NodeAddr, tun: bool) -> Value {
    let peer = node.get_peer(target).map(|peer| {
        json!({
            "link":peer.link_id().as_u64(),"authenticated_ms":peer.authenticated_at(),
            "current_epoch_authenticated":node
                .dataplane_fmp_link_metrics(target, Instant::now())
                .map(|metrics|metrics.current_epoch_authenticated)
        })
    });
    let lookup = node.pending_lookups.get(target).map(|lookup| {
        json!({
            "awaiting_first_request":lookup.awaiting_first_request(),
            "initiated_ms":lookup.initiated_ms,"last_sent_ms":lookup.last_sent_ms,
            "attempt":lookup.attempt
        })
    });
    let session = node.get_session(target).map(|session| {
        json!({
            "initiating":session.is_initiating(),"awaiting_msg3":session.is_awaiting_msg3(),
            "established":session.is_established(),"created_ms":session.created_at(),
            "established_ms":session.session_start_ms(),
            "next_resend_ms":session.next_resend_at_ms(),"resends":session.resend_count()
        })
    });
    let next = node.dataplane.fsp_owner_next_hop(target);
    // These existing &self queries neither select/refresh routes nor touch
    // cache recency (application_route_has_coordinates uses CoordCache::get).
    // Readiness is the staged application-route predicate, not a new promise
    // that all admission, crypto or delivery conditions hold.
    let route_ready = node.dataplane_application_route_ready(target);
    let discovery = &node.stats().discovery;
    json!({"peer":peer,"pending_connections":node.connection_count(),
        "lookup":lookup,"requests_initiated":discovery.req_initiated,
        "responses_accepted":discovery.resp_accepted,"session":session,
        "fsp_owner":node.dataplane_has_fsp_owner(target),"application_route_ready":route_ready,
        "staged_next_hop_is_target":next.map(|hop|hop == *target),
        "queued_original_direction":queued(node,target,tun)})
}
