//! Component controls for admission of one unsent-failure recovery cycle.
//!
//! Like the parent module's state-machine tests, these use a synthetic active
//! peer/filter and controlled tree membership. No Noise key or transport is
//! installed: an eligible plan reserves the real origin request before its
//! send fails. Native encrypted delivery is covered by reachable_after_backoff.
use super::*;
use crate::bloom::BloomFilter;
use crate::peer::ActivePeer;
use crate::transport::LinkId;

fn positive_peer() -> (Node, NodeAddr, NodeAddr) {
    let mut node = make_node();
    let target = make_node_addr(0xa1);
    let identity = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let peer_addr = *identity.node_addr();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), Node::now_ms());
    let mut filter = BloomFilter::new();
    filter.insert(&target);
    peer.update_filter(filter, 1, Node::now_ms());
    node.peers.insert(peer_addr, peer);
    assert!(node.get_peer(&peer_addr).unwrap().can_send());
    assert!(node.get_peer(&peer_addr).unwrap().may_reach(&target));
    assert!(!node.is_tree_peer(&peer_addr));
    (node, peer_addr, target)
}

fn make_child(node: &mut Node, peer: NodeAddr) {
    let local = *node.node_addr();
    let declaration = crate::tree::ParentDeclaration::new(peer, local, 1, Node::now_ms() / 1000);
    let coords = TreeCoordinate::from_addrs(vec![peer, local]).unwrap();
    assert!(node.tree_state_mut().update_peer(declaration, coords));
    assert!(node.is_tree_peer(&peer));
}

async fn admit_once(node: &mut Node, target: NodeAddr) {
    let before = node.stats().discovery.req_initiated;
    node.maybe_initiate_route_query_lookup(&target).await;
    let pending = node
        .pending_lookups
        .get(&target)
        .expect("preserved permission must admit a lookup");
    assert_eq!(pending.attempt, 1);
    assert!(
        !pending.awaiting_first_request(),
        "the normal peer plan must reserve an actual origin ID"
    );
    assert_eq!(node.stats().discovery.req_initiated, before + 1);
    assert_eq!(node.discovery_backoff.failure_count(&target), 1);
    assert!(
        node.discovery_backoff.is_suppressed(&target),
        "admission is not discovery success"
    );

    // Model retirement of this caller-owned lookup. The allowance must already
    // be spent even though the fixture has no transport to complete its send.
    node.pending_lookups.remove(&target).unwrap();
    let suppressed = node.stats().discovery.req_backoff_suppressed;
    node.maybe_initiate_route_query_lookup(&target).await;
    assert!(node.pending_lookups.get(&target).is_none());
    assert_eq!(node.stats().discovery.req_initiated, before + 1);
    assert_eq!(
        node.stats().discovery.req_backoff_suppressed,
        suppressed + 1
    );
    assert_eq!(node.discovery_backoff.failure_count(&target), 1);
}

#[tokio::test]
async fn ineligible_positive_hint_preserves_unsent_failure_retry() {
    for non_tree in [true, false] {
        let (mut node, peer, target) = positive_peer();
        if !non_tree {
            make_child(&mut node, peer);
            node.peers.get_mut(&peer).unwrap().mark_reconnecting();
            assert!(!node.get_peer(&peer).unwrap().can_send());
        }
        node.discovery_backoff.record_unsent_failure(&target);
        let initiated = node.stats().discovery.req_initiated;
        for _ in 0..2 {
            node.maybe_initiate_route_query_lookup(&target).await;
            assert!(node.pending_lookups.get(&target).is_none());
            assert_eq!(node.stats().discovery.req_initiated, initiated);
            assert_eq!(node.discovery_backoff.failure_count(&target), 1);
            assert!(node.discovery_backoff.is_suppressed(&target));
        }
        assert_eq!(node.stats().discovery.req_backoff_suppressed, 2);
        if non_tree {
            make_child(&mut node, peer);
        } else {
            node.peers
                .get_mut(&peer)
                .unwrap()
                .mark_connected(Node::now_ms());
        }
        admit_once(&mut node, target).await;
    }
}

#[tokio::test]
async fn pending_capacity_and_dedup_preserve_unsent_failure_retry() {
    for deduplicated in [false, true] {
        let (mut node, peer, target) = positive_peer();
        make_child(&mut node, peer);
        node.config.node.session.pending_max_destinations = 1;
        node.discovery_backoff.record_unsent_failure(&target);
        // Controlled existing admission, independent of the recovery caller.
        // Exercise both the full-other-target and same-target dedup branches.
        let occupied = if deduplicated {
            target
        } else {
            make_node_addr(0xa2)
        };
        let admitted_ms = Node::now_ms();
        node.pending_lookups.insert_new(occupied, admitted_ms);
        let initiated = node.stats().discovery.req_initiated;
        for _ in 0..2 {
            node.maybe_initiate_route_query_lookup(&target).await;
            assert_eq!(node.pending_lookups.len(), 1);
            let existing = node.pending_lookups.get(&occupied).unwrap();
            assert_eq!(
                (
                    existing.attempt,
                    existing.initiated_ms,
                    existing.last_sent_ms
                ),
                (1, admitted_ms, admitted_ms)
            );
            assert!(existing.awaiting_first_request());
            assert_eq!(node.stats().discovery.req_initiated, initiated);
            assert_eq!(node.stats().discovery.req_backoff_suppressed, 0);
        }
        assert_eq!(
            node.stats().discovery.req_deduplicated,
            if deduplicated { 2 } else { 0 }
        );
        node.pending_lookups.remove(&occupied).unwrap();
        admit_once(&mut node, target).await;
    }
}

#[tokio::test]
async fn previously_selected_peer_keeps_normal_backoff_after_route_disappears() {
    let (mut node, peer, target) = positive_peer();
    make_child(&mut node, peer);
    node.maybe_initiate_route_query_lookup(&target).await;
    let pending = node.pending_lookups.get(&target).unwrap();
    assert!(!pending.awaiting_first_request());
    let started = pending.last_sent_ms;
    let request = node
        .pending_lookups
        .last_origin_request_id(&target)
        .unwrap();
    node.peers.get_mut(&peer).unwrap().mark_reconnecting();
    assert!(!node.get_peer(&peer).unwrap().can_send());
    assert_eq!(
        node.config.node.discovery.attempt_timeouts_secs,
        [1, 2, 4, 8]
    );
    // This is a state-driven timeout control, not a timing measurement. Advance
    // the existing maintenance input through the unchanged ordinary deadlines.
    for (elapsed, attempt) in [(1_000, 2), (3_000, 3), (7_000, 4)] {
        node.check_pending_lookups(started + elapsed).await;
        let pending = node.pending_lookups.get(&target).unwrap();
        assert_eq!(pending.attempt, attempt);
        assert!(!pending.awaiting_first_request());
        assert_eq!(
            node.pending_lookups.last_origin_request_id(&target),
            Some(request)
        );
    }
    node.check_pending_lookups(started + 15_000).await;
    assert!(node.pending_lookups.get(&target).is_none());
    assert_eq!(node.stats().discovery.resp_timed_out, 1);
    assert_eq!(node.discovery_backoff.failure_count(&target), 1);
    assert!(node.discovery_backoff.is_suppressed(&target));
    node.peers
        .get_mut(&peer)
        .unwrap()
        .mark_connected(Node::now_ms());
    let initiated = node.stats().discovery.req_initiated;
    node.maybe_initiate_route_query_lookup(&target).await;
    assert!(
        node.pending_lookups.get(&target).is_none(),
        "a disappeared route cannot relabel an unanswered lookup as unsent"
    );
    assert_eq!(node.stats().discovery.req_initiated, initiated);
    assert_eq!(node.stats().discovery.req_backoff_suppressed, 1);
}
