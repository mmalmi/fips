//! A genuine pending filter must use its debounce deadline between slow ticks.
use super::wire_tap::WireTap;
use super::*;
use crate::node::tests::spanning_tree::poll_available_packets;
use crate::protocol::{FilterAnnounce, LinkMessageType};
use std::sync::{Arc, Mutex};

const PARENT: usize = 0;
const OBSERVER: usize = 1;
const TARGET: usize = 2;

#[test]
fn native_pending_bloom_uses_its_debounce_deadline() {
    run_large_stack_async_test("bloom-deadline", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = Vec::new();
        for _ in 0..3 {
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

#[derive(Debug, Default)]
struct Witness {
    negative_received_ms: Option<u64>,
    positive_received_ms: Option<u64>,
    positives: usize,
}

fn stable_owners(nodes: &[TestNode]) -> Vec<Vec<PeerOwner>> {
    let root = *nodes[PARENT].node.node_addr();
    nodes
        .iter()
        .enumerate()
        .map(|(index, test)| {
            assert_eq!(*test.node.tree_state().root(), root);
            let mut owners = test
                .node
                .peers
                .values()
                .map(|peer| {
                    assert!(test.node.is_tree_peer(peer.node_addr()));
                    assert!(peer.is_healthy() && peer.can_send());
                    (
                        *peer.node_addr(),
                        peer.link_id(),
                        peer.our_index(),
                        peer.session_generation(),
                    )
                })
                .collect::<Vec<_>>();
            owners.sort_by_key(|owner| owner.0);
            assert_eq!(owners.len(), if index == PARENT { 2 } else { 1 });
            assert_eq!(test.node.link_count(), owners.len());
            assert_eq!(test.node.connection_count(), 0);
            owners
        })
        .collect()
}

async fn setup(nodes: &mut [TestNode]) {
    for test in nodes.iter_mut() {
        let defaults = Config::new();
        test.node.config.node.rate_limit = defaults.node.rate_limit;
        test.node.config.node.bloom = defaults.node.bloom;
        test.node.bloom_state.set_update_debounce_ms(500);
        test.node.config.node.discovery.lan.enabled = false;
        assert_eq!(test.node.config.node.tick_interval_secs, 1);
        assert_eq!(test.node.config.node.bloom.update_debounce_ms, 500);
        assert_eq!(
            test.node.config.node.bloom.announce_refresh_interval_secs,
            5
        );
        assert_eq!(test.node.config.node.tree.announce_min_interval_ms, 500);
        assert_eq!(
            test.node.config.node.discovery.attempt_timeouts_secs,
            [1, 2, 4, 8]
        );
        assert_eq!(test.node.config.node.discovery.forward_min_interval_secs, 2);
    }
    for child in [OBSERVER, TARGET] {
        let remote = nodes[PARENT].addr.clone();
        let identity = PeerIdentity::from_pubkey_full(nodes[PARENT].node.identity().pubkey_full());
        let child = &mut nodes[child];
        child
            .node
            .initiate_connection(child.transport_id, remote, identity)
            .await
            .unwrap();
    }
    let root = *nodes[PARENT].node.node_addr();
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        // Setup alone pumps real UDP/Noise/tree traffic. Initial filters stay
        // pending so their first genuine announcements provide the time anchor.
        poll_available_packets(nodes).await;
        for test in nodes.iter_mut() {
            test.node.poll_pending_connects().await;
            test.node.resend_pending_handshakes(Node::now_ms()).await;
            test.node.check_mmp_reports().await;
            test.node.check_tree_state().await;
            test.node.send_due_tree_announces().await;
        }
        if nodes.iter().enumerate().all(|(index, test)| {
            *test.node.tree_state().root() == root
                && test.node.peers.len() == if index == PARENT { 2 } else { 1 }
                && test.node.connection_count() == 0
                && test.node.peers.values().all(|peer| {
                    test.node.is_tree_peer(peer.node_addr())
                        && peer.is_healthy()
                        && peer.can_send()
                        && !peer.has_pending_tree_announce()
                })
        }) {
            break;
        }
        assert!(Instant::now() < until, "native authenticated tree setup");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn exercise(nodes: &mut [TestNode]) {
    setup(nodes).await;
    let owners = stable_owners(nodes);
    let parent = *nodes[PARENT].node.node_addr();
    let observer = *nodes[OBSERVER].node.node_addr();
    let target = *nodes[TARGET].node.node_addr();
    let witness = Arc::new(Mutex::new(Witness::default()));
    let observed = witness.clone();
    let tap = WireTap::start(nodes, OBSERVER, PARENT, move |message, received_ms| {
        if LinkMessageType::from_byte(message[0]) == Some(LinkMessageType::FilterAnnounce) {
            let announce = FilterAnnounce::decode(&message[1..]).unwrap();
            assert!(announce.is_valid() && announce.is_v1_compliant());
            let mut witness = observed.lock().unwrap();
            if announce.filter.contains(&target) {
                witness.positives += 1;
                witness.positive_received_ms.get_or_insert(received_ms);
            } else {
                witness.negative_received_ms = Some(received_ms);
            }
        }
        true
    });
    let mut actors = Vec::new();
    let result = AssertUnwindSafe(async {
        assert!(nodes[PARENT].node.get_peer(&target).unwrap().inbound_filter().is_none());
        assert!(nodes[PARENT].node.bloom_state.needs_update(&observer));
        let anchor_before_ms = Node::now_ms();
        nodes[PARENT].node.send_pending_filter_announces().await;
        let anchor_after_ms = Node::now_ms();
        assert!(!nodes[PARENT].node.bloom_state.needs_update(&observer));
        nodes[TARGET].node.send_pending_filter_announces().await;
        let setup_until = Instant::now() + Duration::from_millis(200);
        loop {
            poll_available_packets(nodes).await;
            if nodes[PARENT].node.get_peer(&target).unwrap().may_reach(&target)
                && witness.lock().unwrap().negative_received_ms.is_some()
            {
                break;
            }
            assert!(Instant::now() < setup_until, "genuine initial filter exchange");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(!nodes[OBSERVER].node.get_peer(&parent).unwrap().may_reach(&target));
        assert!(nodes[PARENT].node.bloom_state.needs_update(&observer));
        assert!(!nodes[PARENT].node.bloom_state.should_send_update(&observer, Node::now_ms()));
        assert!(Node::now_ms() < anchor_before_ms + 250, "native setup leaves debounce time");

        // From here onward every node runs its ordinary RX loop. No manual
        // maintenance, handler call, filter, timestamp or peer-state mutation
        // participates in the measured pending update.
        for (index, node) in nodes.iter_mut().enumerate() {
            actors.push((index, rx_loop::Transit::start(node).await));
        }
        let until = Instant::now() + Duration::from_secs(2);
        let received_ms = loop {
            if let Some(received_ms) = witness.lock().unwrap().positive_received_ms {
                break received_ms;
            }
            assert!(Instant::now() < until, "real target-positive encrypted announcement");
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        eprintln!(
            "native Bloom deadline: anchor=[{anchor_before_ms},{anchor_after_ms}], received={received_ms}, witness={:?}",
            witness.lock().unwrap()
        );
        // Give the ordinary observer RX turn time to authenticate the frame;
        // this does not change the captured wire-arrival acceptance timestamp.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(received_ms >= anchor_before_ms + 500, "existing debounce is preserved");
        assert!(
            received_ms <= anchor_after_ms + 850,
            "pending Bloom waited for coarse maintenance: anchor={anchor_after_ms}, received={received_ms}"
        );
    })
    .catch_unwind()
    .await;
    for (index, actor) in actors {
        actor.restore(&mut nodes[index]).await;
    }
    tap.restore(nodes).await;
    assert_eq!(
        stable_owners(nodes),
        owners,
        "all original FMP owners remain"
    );
    if result.is_ok() {
        assert!(
            nodes[OBSERVER]
                .node
                .get_peer(&parent)
                .unwrap()
                .may_reach(&target)
        );
        assert_eq!(witness.lock().unwrap().positives, 1);
    }
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
