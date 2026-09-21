//! Bounded observations from the monitor's existing queries, not atomic peer pairs.
use super::*;
use std::collections::VecDeque;

const MAX_TRANSITIONS: usize = 16;
const MAX_COMPETITORS: usize = 2;

#[derive(Clone, PartialEq, Eq, serde::Serialize)]
struct Owner {
    node_addr: Option<String>,
    link_id: Option<u64>,
    our_session_index: Option<String>,
    direction: Option<String>,
    authenticated_at_ms: Option<u64>,
    connectivity: Option<String>,
}

#[derive(Clone, serde::Serialize)]
struct PeerSample {
    owner: Owner,
    authenticated_age_ms: Option<u128>,
    packets_recv: Option<u64>,
    bytes_recv: Option<u64>,
    packets_sent: Option<u64>,
    bytes_sent: Option<u64>,
}

impl PeerSample {
    fn new(peer: &Value, observed_unix_ms: u128) -> Self {
        let authenticated_at_ms = peer["authenticated_at_ms"].as_u64();
        Self {
            owner: Owner {
                node_addr: peer["node_addr"].as_str().map(str::to_owned),
                link_id: peer["link_id"].as_u64(),
                our_session_index: peer["our_session_index"].as_str().map(str::to_owned),
                direction: peer["direction"].as_str().map(str::to_owned),
                authenticated_at_ms,
                connectivity: peer["connectivity"].as_str().map(str::to_owned),
            },
            authenticated_age_ms: authenticated_at_ms
                .map(|at| observed_unix_ms.saturating_sub(u128::from(at))),
            packets_recv: peer["stats"]["packets_recv"].as_u64(),
            bytes_recv: peer["stats"]["bytes_recv"].as_u64(),
            packets_sent: peer["stats"]["packets_sent"].as_u64(),
            bytes_sent: peer["stats"]["bytes_sent"].as_u64(),
        }
    }
}

#[derive(Clone, serde::Serialize)]
struct Sample {
    /// Monotonic milliseconds since the witness was created.
    query_ms: [u128; 2],
    /// Wall-clock observation time, used only to describe admission age.
    observed_unix_ms: u128,
    bridge: Option<PeerSample>,
    competitors: Vec<PeerSample>,
    competitors_total: usize,
}

impl Sample {
    fn same_owners(&self, other: &Self) -> bool {
        self.bridge.as_ref().map(|peer| &peer.owner)
            == other.bridge.as_ref().map(|peer| &peer.owner)
            && self.competitors_total == other.competitors_total
            && self
                .competitors
                .iter()
                .map(|peer| &peer.owner)
                .eq(other.competitors.iter().map(|peer| &peer.owner))
    }
}

#[derive(serde::Serialize)]
struct Transition {
    /// Last observation of the previous owner, not its exact retirement time.
    previous: Sample,
    current: Sample,
}

#[derive(serde::Serialize)]
struct Boundary {
    node: usize,
    remote: usize,
    first: Option<Sample>,
    latest: Option<Sample>,
    total_transitions: u64,
    dropped_transitions: u64,
    transitions: VecDeque<Transition>,
}

impl Boundary {
    fn new(node: usize, remote: usize) -> Self {
        Self {
            node,
            remote,
            first: None,
            latest: None,
            total_transitions: 0,
            dropped_transitions: 0,
            transitions: VecDeque::with_capacity(MAX_TRANSITIONS),
        }
    }

    fn record(&mut self, sample: Sample) {
        if let Some(previous) = self.latest.take() {
            if !previous.same_owners(&sample) {
                self.total_transitions += 1;
                if self.transitions.len() == MAX_TRANSITIONS {
                    self.transitions.pop_front();
                    self.dropped_transitions += 1;
                }
                self.transitions.push_back(Transition {
                    previous,
                    current: sample.clone(),
                });
            }
        } else {
            self.first = Some(sample.clone());
        }
        // Counter/age changes update the latest sample without creating chatter.
        self.latest = Some(sample);
    }
}

pub(super) struct BridgeWitness {
    started: Instant,
    started_unix_ms: u128,
    internal: [String; 2],
    remote: [String; 2],
    boundaries: [Boundary; 2],
}

impl BridgeWitness {
    pub(super) fn new(identities: &[PeerIdentity]) -> Self {
        Self {
            started: Instant::now(),
            started_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            internal: [identities[1].npub(), identities[4].npub()],
            remote: [identities[3].npub(), identities[2].npub()],
            boundaries: [Boundary::new(2, 3), Boundary::new(3, 2)],
        }
    }

    pub(super) fn observe(&mut self, node: usize, start: Instant, end: Instant, reply: &Value) {
        let index = match node {
            2 => 0,
            3 => 1,
            _ => return,
        };
        let observed_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let peers = reply["peers"].as_array().unwrap();
        let bridge = peers
            .iter()
            .find(|peer| peer["npub"].as_str() == Some(self.remote[index].as_str()))
            .map(|peer| PeerSample::new(peer, observed_unix_ms));
        let mut competitors = Vec::with_capacity(MAX_COMPETITORS);
        let mut competitors_total = 0;
        for peer in peers.iter().filter(|peer| {
            let npub = peer["npub"].as_str();
            npub != Some(self.internal[index].as_str()) && npub != Some(self.remote[index].as_str())
        }) {
            competitors_total += 1;
            if competitors.len() < MAX_COMPETITORS {
                competitors.push(PeerSample::new(peer, observed_unix_ms));
            }
        }
        competitors.sort_unstable_by(|a, b| a.owner.node_addr.cmp(&b.owner.node_addr));
        self.boundaries[index].record(Sample {
            query_ms: [
                start.duration_since(self.started).as_millis(),
                end.duration_since(self.started).as_millis(),
            ],
            observed_unix_ms,
            bridge,
            competitors,
            competitors_total,
        });
    }

    pub(super) fn summary(&self) -> Value {
        serde_json::json!({
            "started_unix_ms": self.started_unix_ms,
            "max_transitions_per_boundary": MAX_TRANSITIONS,
            "boundaries": self.boundaries,
        })
    }
}
