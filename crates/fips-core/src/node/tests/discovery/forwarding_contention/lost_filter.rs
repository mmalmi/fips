//! One lost reachability update must not strand a stable authenticated route.
use super::wire_tap::WireTap;
use super::*;
use crate::protocol::{FilterAnnounce, LinkMessageType};
use std::sync::{Arc, Mutex};

const PARENT: usize = 0;
const SOURCE: usize = 1;
const TARGET: usize = 2;

#[test]
fn native_downstream_join_delivers_with_undropped_filter() {
    run(false);
}

#[test]
fn native_downstream_join_recovers_one_lost_filter_on_stable_tree() {
    run(true);
}

fn run(lose_filter: bool) {
    run_large_stack_async_test("lost-filter", move || async move {
        let _guard = lock_large_network_test().await;
        let mut nodes = Vec::new();
        for _ in 0..3 {
            nodes.push(make_test_node().await);
        }
        // The target joins as the source's sibling. Its coordinates cannot
        // arrive in the source's own ancestry; the original parent stays root.
        nodes.sort_by_key(|test| *test.node.node_addr());
        let result = AssertUnwindSafe(exercise(&mut nodes, lose_filter))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

#[derive(Debug, Default)]
struct Witness {
    target_announces: usize,
    dropped_sequence: Option<u64>,
    reports_after_drop: usize,
}

struct FilterGate {
    witness: Arc<Mutex<Witness>>,
    tap: WireTap,
}

impl FilterGate {
    fn start(nodes: &mut [TestNode], lose_filter: bool) -> Self {
        let target = *nodes[TARGET].node.node_addr();
        let witness = Arc::new(Mutex::new(Witness::default()));
        let observed = witness.clone();
        let tap = WireTap::start(nodes, SOURCE, PARENT, move |message, _received_ms| {
            let kind = LinkMessageType::from_byte(message[0]).unwrap();
            let mut witness = observed.lock().unwrap();
            if kind == LinkMessageType::FilterAnnounce {
                let announce = FilterAnnounce::decode(&message[1..]).unwrap();
                assert!(announce.is_valid() && announce.is_v1_compliant());
                if announce.filter.contains(&target) {
                    witness.target_announces += 1;
                    if lose_filter && witness.dropped_sequence.is_none() {
                        witness.dropped_sequence = Some(announce.sequence);
                        return false;
                    }
                }
            } else if witness.dropped_sequence.is_some()
                && matches!(
                    kind,
                    LinkMessageType::SenderReport | LinkMessageType::ReceiverReport
                )
            {
                witness.reports_after_drop += 1;
            }
            true
        });
        Self { witness, tap }
    }

    async fn restore(self, nodes: &mut [TestNode]) {
        self.tap.restore(nodes).await;
    }
}

async fn dial(nodes: &mut [TestNode], child: usize) {
    let remote = nodes[PARENT].addr.clone();
    let identity = PeerIdentity::from_pubkey_full(nodes[PARENT].node.identity().pubkey_full());
    let child = &mut nodes[child];
    child
        .node
        .initiate_connection(child.transport_id, remote, identity)
        .await
        .unwrap();
}

fn owner(nodes: &[TestNode], local: usize, remote: usize) -> PeerOwner {
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
}

fn stable_source(nodes: &[TestNode], parent: NodeAddr, original: &PeerOwner) {
    let tree = nodes[SOURCE].node.tree_state();
    assert_eq!(*tree.root(), parent);
    assert_eq!(*tree.my_declaration().parent_id(), parent);
    let peer = nodes[SOURCE].node.get_peer(&parent).unwrap();
    assert!(peer.is_healthy() && peer.can_send());
    assert_eq!(
        (
            *peer.node_addr(),
            peer.link_id(),
            peer.our_index(),
            peer.session_generation(),
        ),
        *original
    );
}

async fn exercise(nodes: &mut [TestNode], lose_filter: bool) {
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
        assert_eq!(test.node.bloom_state.update_debounce_ms(), 500);
    }
    let parent = *nodes[PARENT].node.node_addr();
    let target = *nodes[TARGET].node.node_addr();
    dial(nodes, SOURCE).await;
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        // Setup and endpoint turns dispatch real UDP packets and use actual
        // deadlines. No synthetic topology/filter refresh helper is called.
        turn(nodes).await;
        if *nodes[SOURCE].node.tree_state().root() == parent
            && nodes[PARENT]
                .node
                .is_tree_peer(nodes[SOURCE].node.node_addr())
            && nodes[SOURCE]
                .node
                .get_peer(&parent)
                .is_some_and(|peer| peer.filter_sequence() > 0)
        {
            break;
        }
        assert!(Instant::now() < until, "native source-parent setup");
    }
    let original = [owner(nodes, SOURCE, PARENT), owner(nodes, PARENT, SOURCE)];
    assert!(
        !nodes[SOURCE]
            .node
            .get_peer(&parent)
            .unwrap()
            .may_reach(&target)
    );
    assert_eq!(nodes[TARGET].node.peers.len(), 0);
    let gate = FilterGate::start(nodes, lose_filter);
    // Submit the real connection before handing P to its ordinary RX loop.
    // Only the new T-P edge changes; S's parent and root stay unchanged.
    dial(nodes, TARGET).await;
    let actor = rx_loop::Transit::start(&mut nodes[PARENT]).await;
    let result = AssertUnwindSafe(traffic(nodes, parent, target, &original[0], &gate))
        .catch_unwind()
        .await;
    actor.restore(&mut nodes[PARENT]).await;
    let witness = gate.witness.clone();
    gate.restore(nodes).await;
    assert_eq!(
        [owner(nodes, SOURCE, PARENT), owner(nodes, PARENT, SOURCE)],
        original
    );
    assert!(nodes[PARENT].node.is_tree_peer(&target));
    let witness = witness.lock().unwrap();
    eprintln!("native filter loss: lose_filter={lose_filter}, {witness:?}");
    assert_eq!(witness.dropped_sequence.is_some(), lose_filter);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

async fn traffic(
    nodes: &mut [TestNode],
    parent: NodeAddr,
    target: NodeAddr,
    original: &PeerOwner,
    gate: &FilterGate,
) {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        turn(nodes).await;
        stable_source(nodes, parent, original);
        if gate.witness.lock().unwrap().target_announces > 0
            && *nodes[TARGET].node.tree_state().root() == parent
        {
            break;
        }
        assert!(
            Instant::now() < until,
            "real target advertisement reaches loss gate"
        );
    }
    assert!(
        !nodes[SOURCE]
            .node
            .coord_cache()
            .contains(&target, Node::now_ms())
    );
    assert!(nodes[SOURCE].node.get_session(&target).is_none());
    let _source_io = nodes[SOURCE].node.attach_endpoint_data_io(8).unwrap();
    let mut target_io = nodes[TARGET].node.attach_endpoint_data_io(8).unwrap();
    let destination = PeerIdentity::from_pubkey_full(nodes[TARGET].node.identity().pubkey_full());
    let payload = b"one original after a downstream filter announcement";
    let offered = Instant::now();
    send_endpoint_data_via_dataplane(&mut nodes[SOURCE].node, destination, payload.to_vec())
        .await
        .unwrap();
    let mut delivered = false;
    while offered.elapsed() < Duration::from_millis(15_500) {
        turn(nodes).await;
        nodes[SOURCE].node.check_link_heartbeats().await;
        nodes[TARGET].node.check_link_heartbeats().await;
        stable_source(nodes, parent, original);
        if let Ok(event) = target_io.event_rx.try_recv() {
            assert_eq!(
                expect_single_endpoint_data_event(event).payload.as_slice(),
                payload
            );
            delivered = true;
            break;
        }
    }
    let advertised = nodes[SOURCE]
        .node
        .get_peer(&parent)
        .unwrap()
        .may_reach(&target);
    eprintln!(
        "native filter recovery: delivered={delivered}, advertised={advertised}, elapsed_ms={}, timed_out={}",
        offered.elapsed().as_millis(),
        nodes[SOURCE].node.stats().discovery.resp_timed_out,
    );
    if !delivered && gate.witness.lock().unwrap().dropped_sequence.is_some() {
        assert!(
            gate.witness.lock().unwrap().reports_after_drop > 0,
            "live MMP packets continue over the unchanged edge after the single loss"
        );
    }
    assert!(
        advertised,
        "ordinary maintenance must recover the lost reachability update"
    );
    assert!(
        delivered,
        "the single original must finish within its unchanged lookup ladder"
    );
    let until = Instant::now() + Duration::from_millis(250);
    while Instant::now() < until {
        turn(nodes).await;
        assert!(
            target_io.event_rx.try_recv().is_err(),
            "no duplicate original delivery"
        );
    }
}
