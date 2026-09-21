use std::collections::{HashMap, VecDeque};

const FORWARDING_BULK_GLOBAL_IN_FLIGHT: usize = 512;
const FORWARDING_PRIORITY_GLOBAL_IN_FLIGHT: usize = 64;
const FORWARDING_BULK_OWNER_IN_FLIGHT: usize = 256;
const FORWARDING_PRIORITY_OWNER_IN_FLIGHT: usize = 8;
const FORWARDING_BULK_SOURCE_IN_FLIGHT: usize = 256;
const FORWARDING_PRIORITY_SOURCE_IN_FLIGHT: usize = 8;
const FORWARDING_BACKGROUND_GLOBAL_IN_FLIGHT: usize = 32;
// These include packets waiting for crypto. The crypto owner independently
// limits already-dispatched background work to one packet.
const FORWARDING_BACKGROUND_OWNER_IN_FLIGHT: usize = 16;
const FORWARDING_BACKGROUND_SOURCE_IN_FLIGHT: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
enum ForwardingLane {
    Priority,
    Bulk,
    Background,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ForwardingLaneCounts([usize; 3]);

impl ForwardingLaneCounts {
    fn get(self, lane: ForwardingLane) -> usize {
        self.0[lane as usize]
    }

    fn increment(&mut self, lane: ForwardingLane) {
        let count = &mut self.0[lane as usize];
        *count = count.saturating_add(1);
    }

    fn decrement(&mut self, lane: ForwardingLane) {
        let count = &mut self.0[lane as usize];
        *count = count.saturating_sub(1);
    }

    fn is_empty(self) -> bool {
        self.0 == [0; 3]
    }
}

#[derive(Default)]
struct ForwardingInFlightWindow {
    global: ForwardingLaneCounts,
    owners: HashMap<NodeAddr, ForwardingLaneCounts>,
    sources: HashMap<NodeAddr, ForwardingLaneCounts>,
}

impl ForwardingInFlightWindow {
    fn has_capacity(&self, owner: NodeAddr, source: NodeAddr, lane: ForwardingLane) -> bool {
        let (global_limit, owner_limit, source_limit) = match lane {
            ForwardingLane::Priority => (
                FORWARDING_PRIORITY_GLOBAL_IN_FLIGHT,
                FORWARDING_PRIORITY_OWNER_IN_FLIGHT,
                FORWARDING_PRIORITY_SOURCE_IN_FLIGHT,
            ),
            ForwardingLane::Bulk => (
                FORWARDING_BULK_GLOBAL_IN_FLIGHT,
                FORWARDING_BULK_OWNER_IN_FLIGHT,
                FORWARDING_BULK_SOURCE_IN_FLIGHT,
            ),
            ForwardingLane::Background => (
                FORWARDING_BACKGROUND_GLOBAL_IN_FLIGHT,
                FORWARDING_BACKGROUND_OWNER_IN_FLIGHT,
                FORWARDING_BACKGROUND_SOURCE_IN_FLIGHT,
            ),
        };
        self.global.get(lane) < global_limit
            && self
                .owners
                .get(&owner)
                .copied()
                .unwrap_or_default()
                .get(lane)
                < owner_limit
            && self
                .sources
                .get(&source)
                .copied()
                .unwrap_or_default()
                .get(lane)
                < source_limit
    }

    fn reserve(&mut self, owner: NodeAddr, source: NodeAddr, lane: ForwardingLane) {
        debug_assert!(self.has_capacity(owner, source, lane));
        self.global.increment(lane);
        self.owners.entry(owner).or_default().increment(lane);
        self.sources.entry(source).or_default().increment(lane);
    }

    fn release(&mut self, owner: NodeAddr, source: NodeAddr, lane: ForwardingLane) {
        self.global.decrement(lane);
        decrement_forwarding_lane_map(&mut self.owners, owner, lane);
        decrement_forwarding_lane_map(&mut self.sources, source, lane);
    }

    fn is_empty(&self) -> bool {
        self.global.is_empty() && self.owners.is_empty() && self.sources.is_empty()
    }
}

fn decrement_forwarding_lane_map(
    counts: &mut HashMap<NodeAddr, ForwardingLaneCounts>,
    key: NodeAddr,
    lane: ForwardingLane,
) {
    let remove = counts.get_mut(&key).is_some_and(|value| {
        value.decrement(lane);
        value.is_empty()
    });
    if remove {
        counts.remove(&key);
    }
}

struct PendingSessionForward {
    forward: PreparedSessionForward,
    lane: ForwardingLane,
}

#[derive(Default)]
pub(in crate::node) struct DeferredSessionForwards {
    window: ForwardingInFlightWindow,
    pending: HashMap<u64, PendingSessionForward>,
    completed: VecDeque<(PreparedSessionForward, Result<(), NodeError>)>,
}

impl DeferredSessionForwards {
    pub(in crate::node) fn has_demand_for(&self, peer: &NodeAddr) -> bool {
        self.pending
            .values()
            .map(|pending| &pending.forward)
            .chain(self.completed.iter().map(|(forward, _)| forward))
            .any(|forward| &forward.ingress_peer == peer || &forward.next_hop_addr == peer)
    }

    fn has_capacity(&self, forward: &PreparedSessionForward, lane: ForwardingLane) -> bool {
        self.window
            .has_capacity(forward.next_hop_addr, forward.src_addr, lane)
    }

    fn insert(&mut self, send_token: u64, forward: PreparedSessionForward, lane: ForwardingLane) {
        self.window
            .reserve(forward.next_hop_addr, forward.src_addr, lane);
        let replaced = self
            .pending
            .insert(send_token, PendingSessionForward { forward, lane });
        debug_assert!(replaced.is_none(), "forwarding send tokens must be unique");
    }

    fn take_pending(&mut self, send_token: u64) -> Option<PreparedSessionForward> {
        let pending = self.pending.remove(&send_token)?;
        self.window.release(
            pending.forward.next_hop_addr,
            pending.forward.src_addr,
            pending.lane,
        );
        Some(pending.forward)
    }

    fn abort_pending(&mut self, reason: &'static str, include_background: bool) {
        for (_, pending) in self.pending.extract_if(|_, pending| {
            include_background || pending.lane != ForwardingLane::Background
        }) {
            let next_hop_addr = pending.forward.next_hop_addr;
            self.window
                .release(next_hop_addr, pending.forward.src_addr, pending.lane);
            self.completed.push_back((
                pending.forward,
                Err(NodeError::SendFailed {
                    node_addr: next_hop_addr,
                    reason: reason.into(),
                }),
            ));
        }
        debug_assert!(!include_background || self.window.is_empty());
    }

    fn pending_len(&self) -> usize {
        self.pending.len()
    }

    fn drain_pending_len(&self, include_background: bool) -> usize {
        self.pending_len()
            - if include_background {
                0
            } else {
                self.window.global.get(ForwardingLane::Background)
            }
    }

    fn push_completed(&mut self, forward: PreparedSessionForward, result: Result<(), NodeError>) {
        self.completed.push_back((forward, result));
    }

    fn pop_completed(&mut self) -> Option<(PreparedSessionForward, Result<(), NodeError>)> {
        self.completed.pop_front()
    }
}

impl Node {
    pub(in crate::node) fn has_deferred_session_forwards(&self) -> bool {
        self.deferred_session_forwards.pending_len() > 0
    }
}
