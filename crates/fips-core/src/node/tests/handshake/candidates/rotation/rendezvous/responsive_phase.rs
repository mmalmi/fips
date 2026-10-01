//! Bounded, failure-only observations of the existing contact maintenance phase.
use super::*;

const MAX_RECORDS: usize = 64;
const MAX_SLEEP_SAMPLES: usize = 4;

#[derive(serde::Serialize)]
struct Stamp {
    observed_us: u128,
    native_ms: u64,
}

#[derive(serde::Serialize)]
struct Outbound {
    link_id: u64,
    started_ms: u64,
    state: String,
}

#[derive(serde::Serialize)]
struct Boundary {
    bridge_peer_present: bool,
    bridge_rotation_started_ms: Option<u64>,
    bridge_outbound: Vec<Outbound>,
    rotation_opportunity: bool,
    discovery_turn_reserved: bool,
    handshake_slots: usize,
    link_slots: usize,
}

impl Boundary {
    fn read(node: &Node, at: usize, ids: &[PeerIdentity]) -> Self {
        let peer = ids[1 - at].node_addr();
        let now = Node::now_ms();
        Self {
            bridge_peer_present: node.get_peer(peer).is_some(),
            bridge_rotation_started_ms: node.neighbor_rotation_started_at(peer),
            bridge_outbound: node
                .peers
                .connection_values()
                .filter(|connection| {
                    connection.is_outbound()
                        && connection
                            .expected_identity()
                            .is_some_and(|id| id.node_addr() == peer)
                })
                .take(4)
                .map(|connection| Outbound {
                    link_id: connection.link_id().as_u64(),
                    started_ms: connection.started_at(),
                    state: format!("{:?}", connection.handshake_state()),
                })
                .collect(),
            rotation_opportunity: node.has_neighbor_rotation_opportunity(now),
            discovery_turn_reserved: node.neighbor_rotation_discovery_turn_reserved(now),
            handshake_slots: node.outbound_handshake_slots(),
            link_slots: node.outbound_link_slots(),
        }
    }
}

#[derive(serde::Serialize)]
struct Poll {
    boundary: usize,
    entered: Stamp,
    before: Boundary,
    returned: Option<(Stamp, Boundary)>,
}

#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Record {
    Due {
        detected: Stamp,
        scheduled_us: [u128; 2],
        next_tick_us: [u128; 2],
        due: [bool; 2],
    },
    DiscoveryPoll(Poll),
}

#[derive(Default, serde::Serialize)]
struct Sleeps {
    total: usize,
    ready_at_sleep: usize,
    raw_queued_node_observations: usize,
    runnable_node_observations: usize,
    first_ready_samples: Vec<SleepSample>,
}

#[derive(serde::Serialize)]
struct SleepSample {
    before: Stamp,
    after: Stamp,
    site: &'static str,
    raw_queued_nodes: Vec<usize>,
    runnable_nodes: Vec<usize>,
}

pub(super) struct Capture {
    started: tokio::time::Instant,
    opened_ms: [u128; 2],
    captured: Stamp,
    next_tick_at_open_us: [u128; 2],
    records: Vec<Record>,
    overflow: usize,
    sleeps: Sleeps,
}

impl Capture {
    pub(super) fn new(
        started: tokio::time::Instant,
        next_tick: [tokio::time::Instant; 2],
        opened_ms: [u128; 2],
    ) -> Self {
        Self {
            started,
            opened_ms,
            captured: Self::stamp(started),
            next_tick_at_open_us: next_tick.map(|at| at.duration_since(started).as_micros()),
            records: Vec::with_capacity(MAX_RECORDS),
            overflow: 0,
            sleeps: Sleeps::default(),
        }
    }

    fn stamp(started: tokio::time::Instant) -> Stamp {
        Stamp {
            observed_us: started.elapsed().as_micros(),
            native_ms: Node::now_ms(),
        }
    }

    fn record(&mut self, record: Record) {
        if self.records.len() < MAX_RECORDS {
            self.records.push(record);
        } else {
            self.overflow += 1;
        }
    }

    pub(super) fn due(
        &mut self,
        scheduled: [tokio::time::Instant; 2],
        next_tick: [tokio::time::Instant; 2],
        due: [bool; 2],
    ) {
        self.record(Record::Due {
            detected: Self::stamp(self.started),
            scheduled_us: scheduled.map(|at| at.duration_since(self.started).as_micros()),
            next_tick_us: next_tick.map(|at| at.duration_since(self.started).as_micros()),
            due,
        });
    }

    pub(super) fn before_poll(
        &mut self,
        at: usize,
        node: &Node,
        ids: &[PeerIdentity],
    ) -> Option<usize> {
        if at >= 2 {
            return None;
        }
        if self.records.len() == MAX_RECORDS {
            self.overflow += 1;
            return None;
        }
        let index = self.records.len();
        self.records.push(Record::DiscoveryPoll(Poll {
            boundary: at,
            entered: Self::stamp(self.started),
            before: Boundary::read(node, at, ids),
            returned: None,
        }));
        Some(index)
    }

    pub(super) fn after_poll(&mut self, index: usize, node: &Node, ids: &[PeerIdentity]) {
        let returned = Self::stamp(self.started);
        if let Record::DiscoveryPoll(poll) = &mut self.records[index] {
            poll.returned = Some((returned, Boundary::read(node, poll.boundary, ids)));
        }
    }

    pub(super) fn before_sleep(&mut self, nodes: &[TestNode], site: &'static str) {
        let before = Self::stamp(self.started);
        let sample = self.sleeps.first_ready_samples.len() < MAX_SLEEP_SAMPLES;
        let (mut raw_queued_nodes, mut runnable_nodes) = (Vec::new(), Vec::new());
        let (mut raw_count, mut runnable_count) = (0, 0);
        for (at, node) in nodes.iter().enumerate() {
            if node.packet_rx.queued_packets_for_test() > 0 {
                raw_count += 1;
                if sample {
                    raw_queued_nodes.push(at);
                }
            }
            if node.node.dataplane.has_runnable_work() {
                runnable_count += 1;
                if sample {
                    runnable_nodes.push(at);
                }
            }
        }
        let after = Self::stamp(self.started);
        self.sleeps.total += 1;
        self.sleeps.raw_queued_node_observations += raw_count;
        self.sleeps.runnable_node_observations += runnable_count;
        if raw_count + runnable_count > 0 {
            self.sleeps.ready_at_sleep += 1;
            if sample {
                self.sleeps.first_ready_samples.push(SleepSample {
                    before,
                    after,
                    site,
                    raw_queued_nodes,
                    runnable_nodes,
                });
            }
        }
    }

    pub(super) fn report(self, closed_ms: [u128; 2]) {
        eprintln!(
            "responsive contact maintenance phase: {}",
            json!({
                "schema":1,"opened_observation_ms":self.opened_ms,
                "closed_observation_ms":closed_ms,"capture":self.captured,
                "next_tick_at_open_us":self.next_tick_at_open_us,
            "records":self.records,"overflow":self.overflow,"before_sleep":self.sleeps,
                "limits":"poll brackets include observer cost; candidate state is not a wire-send timestamp"
            })
        );
    }
}
