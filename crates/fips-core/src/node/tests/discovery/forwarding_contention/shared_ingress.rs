//! Distinct origins behind one ingress retain independent forwarding slots.
use super::wire_tap::WireTap;
use super::*;
use crate::protocol::LinkMessageType;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

const SOURCE: usize = 0;
const INGRESS: usize = 1;
const TRANSIT: usize = 2;
const TARGET: usize = 3;

#[test]
fn distinct_origin_behind_shared_ingress_keeps_final_attempt_deadline() {
    run_large_stack_async_test("shared-lookup-ingress", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = Vec::new();
        for _ in 0..4 {
            nodes.push(make_test_node().await);
        }
        nodes.sort_by_key(|test| *test.node.node_addr());
        let result = AssertUnwindSafe(exercise(&mut nodes)).catch_unwind().await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

#[derive(Clone, Debug)]
struct Observation {
    origin: NodeAddr,
    request_id: u64,
    received_ms: u64,
}

struct IngressWitness {
    requests: Arc<Mutex<Vec<Observation>>>,
    tap: WireTap,
}

impl IngressWitness {
    fn start(nodes: &mut [TestNode]) -> Self {
        let target = *nodes[TARGET].node.node_addr();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = requests.clone();
        let tap = WireTap::start(nodes, TRANSIT, INGRESS, move |message, received_ms| {
            if message[0] == LinkMessageType::LookupRequest.to_byte() {
                let request = LookupRequest::decode(&message[1..]).unwrap();
                if request.target == target {
                    let mut requests = observed.lock().unwrap();
                    assert!(requests.len() < 8, "bounded complete wire witness");
                    requests.push(Observation {
                        origin: request.origin,
                        request_id: request.request_id,
                        received_ms,
                    });
                }
            }
            true
        });
        Self { requests, tap }
    }

    async fn restore(self, nodes: &mut [TestNode]) {
        self.tap.restore(nodes).await;
    }
}

async fn dial(nodes: &mut [TestNode], from: usize, to: usize) {
    let remote = nodes[to].addr.clone();
    let identity = PeerIdentity::from_pubkey_full(nodes[to].node.identity().pubkey_full());
    let source = &mut nodes[from];
    source
        .node
        .initiate_connection(source.transport_id, remote, identity)
        .await
        .unwrap();
}

fn existing_owners(nodes: &[TestNode]) -> Vec<PeerOwner> {
    [
        (SOURCE, INGRESS),
        (INGRESS, SOURCE),
        (INGRESS, TRANSIT),
        (TRANSIT, INGRESS),
    ]
    .into_iter()
    .map(|(local, remote)| {
        let peer = nodes[local]
            .node
            .get_peer(nodes[remote].node.node_addr())
            .unwrap();
        assert!(peer.is_healthy() && peer.can_send());
        (
            *peer.node_addr(),
            peer.link_id(),
            peer.our_index(),
            peer.session_generation(),
        )
    })
    .collect()
}

fn frozen_attempt(node: &Node, target: &NodeAddr, original: (u64, u64, u8)) {
    let pending = node
        .pending_lookups
        .get(target)
        .expect("original lookup still owns its deadline");
    assert_eq!(
        (pending.initiated_ms, pending.last_sent_ms, pending.attempt),
        original
    );
    assert_eq!(node.pending_lookup_deadline_ms(), Some(original.1 + 8_000));
}

async fn exercise(nodes: &mut [TestNode]) {
    let defaults = Config::new();
    for test in nodes.iter_mut() {
        test.node.config.node.rate_limit = defaults.node.rate_limit.clone();
        test.node.config.node.bloom = defaults.node.bloom.clone();
        test.node
            .bloom_state
            .set_update_debounce_ms(defaults.node.bloom.update_debounce_ms);
        test.node.config.node.discovery.lan.enabled = false;
        assert_eq!(
            test.node.config.node.discovery.attempt_timeouts_secs,
            [1, 2, 4, 8]
        );
        assert_eq!(test.node.config.node.discovery.forward_min_interval_secs, 2);
        assert_eq!(test.node.config.node.tree.announce_min_interval_ms, 500);
        assert_eq!(test.node.config.node.session.pending_max_destinations, 256);
    }
    dial(nodes, INGRESS, SOURCE).await;
    dial(nodes, TRANSIT, INGRESS).await;
    let root = *nodes[SOURCE].node.node_addr();
    let target = *nodes[TARGET].node.node_addr();
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        turn(nodes).await;
        let ready = nodes[..TARGET].iter().all(|test| {
            *test.node.tree_state().root() == root
                && test.node.peers.values().all(|peer| {
                    peer.is_healthy()
                        && peer.can_send()
                        && peer.filter_sequence() > 0
                        && test.node.is_tree_peer(peer.node_addr())
                })
        });
        if ready && nodes[TRANSIT].node.peers.len() == 1 && nodes[INGRESS].node.peers.len() == 2 {
            break;
        }
        assert!(
            Instant::now() < until,
            "real A-B-C tree and filters converge"
        );
    }
    let owners = existing_owners(nodes);
    assert_eq!(nodes[TARGET].node.peers.len(), 0);
    assert!(
        nodes[SOURCE]
            .node
            .peers
            .values()
            .all(|peer| !peer.may_reach(&target))
    );
    let _source_io = nodes[SOURCE].node.attach_endpoint_data_io(8).unwrap();
    let mut target_io = nodes[TARGET].node.attach_endpoint_data_io(8).unwrap();
    let destination = PeerIdentity::from_pubkey_full(nodes[TARGET].node.identity().pubkey_full());
    let payload = b"one original behind a shared lookup ingress";
    send_endpoint_data_via_dataplane(&mut nodes[SOURCE].node, destination, payload.to_vec())
        .await
        .unwrap();
    let initiated = nodes[SOURCE]
        .node
        .pending_lookups
        .get(&target)
        .unwrap()
        .initiated_ms;
    let mut attempts = vec![1];
    let original = loop {
        turn(nodes).await;
        assert_eq!(existing_owners(nodes), owners);
        let pending = nodes[SOURCE].node.pending_lookups.get(&target).unwrap();
        assert_eq!(pending.initiated_ms, initiated);
        assert!(pending.awaiting_first_request());
        if attempts.last() != Some(&pending.attempt) {
            attempts.push(pending.attempt);
        }
        // Join D with five seconds of the existing eight-second last attempt
        // left. Genuine handshake/filter propagation uses part of that time.
        if pending.attempt == 4 && Node::now_ms() >= pending.last_sent_ms + 3_000 {
            break (pending.initiated_ms, pending.last_sent_ms, pending.attempt);
        }
        assert!(
            Node::now_ms() < initiated + 12_000,
            "real lookup advances without an early expiry"
        );
    };
    assert_eq!(attempts, [1, 2, 3, 4]);
    let transit = *nodes[TRANSIT].node.node_addr();
    let witness = IngressWitness::start(nodes);
    dial(nodes, TARGET, TRANSIT).await;
    let actor = rx_loop::Transit::start(&mut nodes[TRANSIT]).await;
    let outcome = AssertUnwindSafe(async {
        order_competing_requests(nodes, transit, target, original, &witness).await;
        let deadline = original.1 + 8_000;
        let mut delivered = false;
        while Node::now_ms() < deadline + 100 {
            turn(nodes).await;
            if let Some(pending) = nodes[SOURCE].node.pending_lookups.get(&target) {
                assert_eq!((pending.initiated_ms, pending.last_sent_ms, pending.attempt), original);
            }
            assert_eq!(*nodes[SOURCE].node.tree_state().root(), root);
            if let Ok(event) = target_io.event_rx.try_recv() {
                assert_eq!(expect_single_endpoint_data_event(event).payload.as_slice(), payload);
                assert!(Node::now_ms() < deadline, "original deadline was not extended");
                delivered = true;
                break;
            }
        }
        eprintln!("shared ingress: delivered={delivered}, attempts={attempts:?}, remaining_ms={}, timed_out={}",
            deadline.saturating_sub(Node::now_ms()), nodes[SOURCE].node.stats().discovery.resp_timed_out);
        assert!(delivered, "an independent origin keeps its original deadline behind a shared ingress");
        let until = Instant::now() + Duration::from_millis(250);
        while Instant::now() < until {
            turn(nodes).await;
            assert!(target_io.event_rx.try_recv().is_err(), "only one original is delivered");
        }
    }).catch_unwind().await;
    actor.restore(&mut nodes[TRANSIT]).await;
    let observations = witness.requests.lock().unwrap().clone();
    witness.restore(nodes).await;
    assert_eq!(existing_owners(nodes), owners);
    let ingress = *nodes[INGRESS].node.node_addr();
    eprintln!("shared ingress wire requests: {observations:?}");
    for request in &observations {
        let received = nodes[TRANSIT]
            .node
            .recent_requests
            .get(&request.request_id)
            .unwrap();
        assert_eq!(received.from_peer, ingress);
        assert_eq!(received.target, target);
        let delivered = nodes[TARGET]
            .node
            .recent_requests
            .get(&request.request_id)
            .unwrap();
        assert!(
            delivered.timestamp_ms < request.received_ms + 1_000,
            "distinct origins must not wait for each other's two-second slot"
        );
    }
    assert_eq!(
        nodes[TRANSIT]
            .node
            .stats()
            .discovery
            .req_forward_rate_limited,
        0,
        "independent origins do not consume each other's retry slots"
    );
    assert_eq!(
        observations
            .iter()
            .filter(|request| request.origin == root)
            .count(),
        1,
        "A has only its original final-attempt request, not a later retry"
    );
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

async fn order_competing_requests(
    nodes: &mut [TestNode],
    transit: NodeAddr,
    target: NodeAddr,
    original: (u64, u64, u8),
    witness: &IngressWitness,
) {
    loop {
        // A is pumped before B. The first turn that gives B a positive filter
        // therefore stops before A can consume B's resulting advertisement.
        turn(nodes).await;
        frozen_attempt(&nodes[SOURCE].node, &target, original);
        if nodes[INGRESS]
            .node
            .get_peer(&transit)
            .unwrap()
            .may_reach(&target)
        {
            break;
        }
        assert!(
            Node::now_ms() < original.1 + 5_000,
            "genuine downstream join leaves time for the next slot"
        );
    }
    assert!(
        !nodes[SOURCE]
            .node
            .peers
            .values()
            .any(|peer| peer.may_reach(&target))
    );
    assert!(
        !nodes[INGRESS]
            .node
            .coord_cache()
            .contains(&target, Node::now_ms())
    );
    let destination = PeerIdentity::from_pubkey_full(nodes[TARGET].node.identity().pubkey_full());
    let (response_tx, response_rx) = oneshot::channel();
    nodes[INGRESS]
        .node
        .handle_endpoint_control(crate::node::NodeEndpointControlCommand::ResolveNextHop {
            destination,
            previous_hop: None,
            response_tx,
        })
        .await;
    assert!(response_rx.await.unwrap().is_none());
    assert!(nodes[INGRESS].node.pending_lookups.get(&target).is_some());
    let until = Instant::now() + Duration::from_millis(750);
    while witness.requests.lock().unwrap().is_empty() {
        // B's local query reaches C first. Keep D's response queued briefly so
        // it cannot warm B's coordinate cache before A's request crosses B.
        process_available_packets(&mut nodes[INGRESS..TARGET]).await;
        assert!(Instant::now() < until, "ordinary B query reaches C");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    while witness.requests.lock().unwrap().len() < 2 {
        turn(&mut nodes[..TARGET]).await;
        frozen_attempt(&nodes[SOURCE].node, &target, original);
        assert!(
            Instant::now() < until,
            "A resumes on its queued genuine filter"
        );
    }
    let requests = witness.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].origin, *nodes[INGRESS].node.node_addr());
    assert_eq!(requests[1].origin, *nodes[SOURCE].node.node_addr());
    assert_ne!(requests[0].request_id, requests[1].request_id);
    assert!(requests[1].received_ms < requests[0].received_ms + 1_000);
    assert!(
        !nodes[SOURCE]
            .node
            .pending_lookups
            .get(&target)
            .unwrap()
            .awaiting_first_request()
    );
    eprintln!(
        "shared ingress collision: gap_ms={}, remaining_ms={}",
        requests[1].received_ms - requests[0].received_ms,
        (original.1 + 8_000).saturating_sub(Node::now_ms())
    );
}
