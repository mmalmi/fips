//! Bounded observations only: polling, wakeups and fixture order are unchanged.
use super::*;
use std::{future::Future, pin::pin};

#[path = "responsive_turn_timing_tests.rs"]
mod tests;

#[derive(Clone, Default, serde::Serialize)]
pub(super) struct Polls {
    polls: usize,
    pending: usize,
    poll_wall_us: u128,
    pending_interval_us: u128,
    max_poll_wall_us: u128,
}

pub(super) async fn measured<F: Future>(enabled: bool, future: F) -> (F::Output, Polls) {
    if !enabled {
        return (future.await, Polls::default());
    }
    let mut future = pin!(future);
    let mut stats = Polls::default();
    let mut pending_since = None::<std::time::Instant>;
    let value = std::future::poll_fn(|cx| {
        let entered = std::time::Instant::now();
        if let Some(previous) = pending_since.take() {
            stats.pending_interval_us += entered.duration_since(previous).as_micros();
        }
        stats.polls += 1;
        let result = future.as_mut().poll(cx);
        let returned = std::time::Instant::now();
        let elapsed = returned.duration_since(entered).as_micros();
        stats.poll_wall_us += elapsed;
        stats.max_poll_wall_us = stats.max_poll_wall_us.max(elapsed);
        if result.is_pending() {
            stats.pending += 1;
            pending_since = Some(returned);
        }
        result
    })
    .await;
    (value, stats)
}

#[derive(Clone, serde::Serialize)]
pub(super) struct Snapshot {
    observed_us: [u128; 2],
    native_ms: [u64; 2],
    raw_queued: usize,
    runnable: bool,
    deferred_controls: usize,
    discovery_deadline_ms: Option<u64>,
    routing_deadline_ms: Option<u64>,
    // Six useful directed edges: 0->1/2, 1->0/3, 2->0, 3->1.
    directed_bloom_deadlines: [Option<(usize, Option<u64>)>; 2],
}

impl Snapshot {
    fn read(
        node: &TestNode,
        index: usize,
        ids: &[PeerIdentity],
        started: tokio::time::Instant,
    ) -> Self {
        let before = (started.elapsed().as_micros(), Node::now_ms());
        let peers = match index {
            0 => [Some(1), Some(2)],
            1 => [Some(0), Some(3)],
            2 => [Some(0), None],
            3 => [Some(1), None],
            _ => [None, None],
        };
        let mut result = Self {
            observed_us: [before.0; 2],
            native_ms: [before.1; 2],
            raw_queued: node.packet_rx.queued_packets_for_test(),
            runnable: node.node.dataplane.has_runnable_work(),
            deferred_controls: node.node.deferred_dataplane_control_turns.len(),
            discovery_deadline_ms: node.node.discovery_work_deadline_ms(),
            routing_deadline_ms: node.node.pending_routing_announce_deadline_ms(),
            directed_bloom_deadlines: peers.map(|peer| {
                peer.map(|peer| {
                    (
                        peer,
                        node.node
                            .bloom_state
                            .pending_peer_deadline_ms(ids[peer].node_addr()),
                    )
                })
            }),
        };
        result.native_ms[1] = Node::now_ms();
        result.observed_us[1] = started.elapsed().as_micros();
        result
    }
}

#[derive(Clone, serde::Serialize)]
struct Entry {
    node: usize,
    phase: &'static str,
    calls: usize,
    polls: Polls,
    elapsed_us: u128,
    slowest_us: u128,
    slowest_before: Snapshot,
    slowest_after: Snapshot,
}

#[derive(Clone)]
pub(super) struct Capture {
    enabled: bool,
    started: tokio::time::Instant,
    opened_us: u128,
    closed_us: u128,
    turns: usize,
    entries: Vec<Entry>,
}

impl Capture {
    pub(super) fn new(started: tokio::time::Instant, enabled: bool) -> Self {
        Self {
            enabled,
            started,
            opened_us: started.elapsed().as_micros(),
            closed_us: 0,
            turns: 0,
            entries: Vec::new(),
        }
    }

    pub(super) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(super) fn snapshot(
        &self,
        node: &TestNode,
        index: usize,
        ids: &[PeerIdentity],
    ) -> Option<Snapshot> {
        self.enabled
            .then(|| Snapshot::read(node, index, ids, self.started))
    }

    pub(super) fn record(
        &mut self,
        node: usize,
        phase: &'static str,
        before: Option<Snapshot>,
        after: Option<Snapshot>,
        polls: Polls,
    ) {
        let (Some(before), Some(after)) = (before, after) else {
            return;
        };
        let elapsed = after.observed_us[0].saturating_sub(before.observed_us[1]);
        let entry = Entry {
            node,
            phase,
            calls: 1,
            polls,
            elapsed_us: elapsed,
            slowest_us: elapsed,
            slowest_before: before,
            slowest_after: after,
        };
        self.add(entry);
    }

    fn add(&mut self, entry: Entry) {
        if let Some(old) = self
            .entries
            .iter_mut()
            .find(|old| old.node == entry.node && old.phase == entry.phase)
        {
            old.calls += entry.calls;
            old.elapsed_us += entry.elapsed_us;
            old.polls.polls += entry.polls.polls;
            old.polls.pending += entry.polls.pending;
            old.polls.poll_wall_us += entry.polls.poll_wall_us;
            old.polls.pending_interval_us += entry.polls.pending_interval_us;
            old.polls.max_poll_wall_us =
                old.polls.max_poll_wall_us.max(entry.polls.max_poll_wall_us);
            if entry.slowest_us > old.slowest_us {
                old.slowest_us = entry.slowest_us;
                old.slowest_before = entry.slowest_before;
                old.slowest_after = entry.slowest_after;
            }
        } else {
            // Four phases times the existing maximum twenty-node fixture.
            assert!(self.entries.len() < 80);
            self.entries.push(entry);
        }
    }

    pub(super) fn finish(&mut self) {
        self.closed_us = self.started.elapsed().as_micros();
        self.turns = 1;
    }

    pub(super) fn merge(&mut self, other: &Self) {
        self.closed_us = other.closed_us;
        self.turns += other.turns;
        for entry in &other.entries {
            self.add(entry.clone());
        }
    }

    pub(super) fn report(&self) -> Value {
        let measured_us: u128 = self.entries.iter().map(|entry| entry.elapsed_us).sum();
        json!({"opened_us":self.opened_us,"closed_us":self.closed_us,"turns":self.turns,
            "entries":self.entries,"measured_phase_us":measured_us,
            "outside_measured_phases_us":self.closed_us.saturating_sub(self.opened_us).saturating_sub(measured_us),
            "limits":"Poll wall time includes synchronous handler work and possible OS descheduling. Pending intervals include awaited work and scheduling delay; neither is CPU time. Slowest-call snapshots bracket sequential reads, not an atomic global state. Contact aggregate includes idle intervals outside measured phases."})
    }
}
