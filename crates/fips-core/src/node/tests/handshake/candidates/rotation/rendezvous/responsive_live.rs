//! The same finite encounter with production event loops owning all dispatch.
use super::*;
use crate::node::NodeState;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;

#[path = "responsive_live/bench.rs"]
mod bench;
#[path = "responsive_live/traffic.rs"]
mod traffic;
use bench::owner;

const CAPACITY: CapacityLimits = CapacityLimits {
    connections: [4, 2],
    links: [4, 2],
};
const CONTACT: Duration = Duration::from_millis(1500);

#[derive(Debug)]
struct Mutation {
    observed_ms: [u128; 2],
}

fn mutate(network: &SimNetwork, started: Instant, up: bool) -> Mutation {
    let before = started.elapsed().as_millis();
    if up {
        network.set_link(
            RESPONSIVE_ADDRESSES[0],
            RESPONSIVE_ADDRESSES[1],
            SimLink::default(),
        );
    } else {
        network.set_link_up(RESPONSIVE_ADDRESSES[0], RESPONSIVE_ADDRESSES[1], false);
    }
    Mutation {
        observed_ms: [before, started.elapsed().as_millis()],
    }
}

struct Bench {
    name: String,
    network: SimNetwork,
    root: tempfile::TempDir,
    started: Instant,
    ids: Vec<PeerIdentity>,
    controls: Vec<mpsc::Sender<crate::node::NodeEndpointControlCommand>>,
    traffic: traffic::Traffic,
    nodes: JoinSet<(usize, TestNode, bool)>,
    stops: Vec<oneshot::Sender<()>>,
    driver: Option<tokio::task::JoinHandle<Mutation>>,
    samples: usize,
    bridge_observed: Option<[u128; 2]>,
}

#[test]
fn mature_full_rosters_deliver_originals_with_production_rx_loops() {
    run_large_stack_async_test("mature-brief-live", || async {
        let _guard = lock_large_network_test().await;
        let mut bench = Bench::start().await;
        let result = AssertUnwindSafe(bench.exercise()).catch_unwind().await;
        bench.stop().await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

impl Bench {
    async fn wait_age(&mut self, boundary: usize, remote: usize, age_ms: u64, useful: &[Value]) {
        let initial = self.peers(boundary).await;
        let original = self.peer(&initial, remote).unwrap();
        let identity = owner(original);
        let ready = original["authenticated_at_ms"].as_u64().unwrap() + age_ms;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            self.sample(useful).await;
            let current = self.peers(boundary).await;
            assert_eq!(owner(self.peer(&current, remote).unwrap()), identity);
            if Node::now_ms() >= ready {
                break;
            }
            assert!(Instant::now() < deadline, "bounded native owner maturation");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn exercise(&mut self) {
        self.connect_initial(0, 2).await;
        self.connect_initial(1, 3).await;
        let useful = vec![
            owner(self.peer(&self.peers(0).await, 2).unwrap()),
            owner(self.peer(&self.peers(1).await, 3).unwrap()),
        ];
        self.traffic.start_local();
        self.wait_age(1, 3, 10_000, &useful).await;
        self.connect_initial(0, 4).await;
        self.wait_age(0, 4, 5000, &useful).await;
        self.connect_initial(1, 5).await;
        self.wait_age(1, 5, 10_000, &useful).await;

        // No cross-component exposure or application submission has occurred.
        // Establish stable mature owners with real app traffic, not link-control
        // packet counters. No observer asks the routing layer to find a path.
        let mut original_rosters = Vec::new();
        for index in 0..2 {
            let peers = self.peers(index).await;
            assert_eq!(peers.len(), 2);
            assert!(self.peer(&peers, 1 - index).is_none());
            for remote in [index + 2, index + 4] {
                let peer = self.peer(&peers, remote).unwrap();
                assert!(Node::now_ms() - peer["authenticated_at_ms"].as_u64().unwrap() >= 10_000);
            }
            assert_eq!(
                self.request(index, "show_status", Value::Null).await["connection_count"],
                0
            );
            original_rosters.push(peers.iter().map(owner).collect::<Vec<_>>());
        }
        let mut previous_sent = Vec::new();
        for (from, to) in LOCAL_FLOWS {
            let q = self.quality(from, to).await;
            assert_eq!(q.next_hop, Some(*self.ids[to].node_addr()));
            assert!(q.sent_packets > 0);
            previous_sent.push(q.sent_packets);
        }
        let stable_until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < stable_until {
            self.sample(&useful).await;
            for (index, original) in original_rosters.iter().enumerate() {
                let mut before = original.clone();
                let mut after: Vec<_> = self.peers(index).await.iter().map(owner).collect();
                before.sort_by_key(Value::to_string);
                after.sort_by_key(Value::to_string);
                assert_eq!(
                    before, after,
                    "initial full rosters stay stable through replacement interval"
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        for (index, (from, to)) in LOCAL_FLOWS.into_iter().enumerate() {
            let q = self.quality(from, to).await;
            assert_eq!(q.next_hop, Some(*self.ids[to].node_addr()));
            assert!(q.sent_packets > previous_sent[index]);
        }
        for (from, to) in [(2, 3), (3, 2)] {
            let sessions = self.request(from, "show_sessions", Value::Null).await;
            assert!(
                sessions["sessions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(
                        |s| s["remote_addr"].as_str().expect("session remote identity")
                            != self.ids[to].node_addr().to_string()
                    ),
                "cold original end-to-end session"
            );
        }
        eprintln!(
            "live brief ready: {}",
            json!({"observed_ms":self.started.elapsed().as_millis(),
            "original_rosters":original_rosters,"local_traffic":self.traffic.summary()})
        );

        // All other candidates remain available; the bridge cut never waits for
        // discovery, handshake, application delivery or a control observation.
        for candidate in 6..self.ids.len() {
            self.network.set_link(
                RESPONSIVE_ADDRESSES[candidate % 2],
                RESPONSIVE_ADDRESSES[candidate],
                SimLink::default(),
            );
        }
        let network = self.network.clone();
        let started = self.started;
        let (opened_tx, opened_rx) = oneshot::channel();
        self.driver = Some(tokio::spawn(async move {
            let opened = mutate(&network, started, true);
            let deadline = Instant::now() + CONTACT;
            opened_tx.send(opened).unwrap();
            tokio::time::sleep_until(deadline).await;
            mutate(&network, started, false)
        }));
        let opened = opened_rx.await.unwrap();
        self.traffic.offer_originals();
        while !self.driver.as_ref().unwrap().is_finished() {
            self.sample(&useful).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let closed = self.driver.take().unwrap().await.unwrap();
        let duration = [
            closed.observed_ms[0] - opened.observed_ms[1],
            closed.observed_ms[1] - opened.observed_ms[0],
        ];
        let accepted = self.traffic.originals_before(closed.observed_ms[0]);
        eprintln!(
            "live brief outcome: {}",
            json!({"opened_ms":opened.observed_ms,"closed_ms":closed.observed_ms,
            "actual_duration_bounds_ms":duration,"bridge_observed_ms":self.bridge_observed,
            "originals_accepted":accepted,"samples":self.samples,"traffic":self.traffic.summary()})
        );
        assert!(
            duration[0] >= 1499 && duration[1] <= 2000,
            "bounded independent carrier cutoff"
        );
        let bridge_in_contact = self
            .bridge_observed
            .is_some_and(|span| span[1] < closed.observed_ms[0]);

        // Preserve the short result even if a later reliable opening recovers.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let reopened = mutate(&self.network, self.started, true);
        let recovery = Instant::now() + Duration::from_secs(60);
        loop {
            self.sample(&useful).await;
            if self.traffic.originals_before(u128::MAX) {
                break;
            }
            assert!(
                Instant::now() < recovery,
                "original payload recovery within unchanged60s"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        self.traffic.stop_local().await;
        while !self.traffic.local_complete() {
            self.traffic.assert_local_progress(false);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        self.traffic.assert_local_progress(true);
        eprintln!(
            "live brief recovery: {}",
            json!({"reopened_ms":reopened.observed_ms,
            "finished_ms":self.started.elapsed().as_millis(),"traffic":self.traffic.summary()})
        );
        assert!(
            bridge_in_contact && accepted,
            "both cold-session originals must arrive during the1.5s contact; later recovery cannot satisfy it"
        );
    }
}
