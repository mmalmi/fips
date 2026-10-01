//! An accepted filter becomes usable when its authenticated peer becomes a child.
use super::*;
use crate::bloom::BloomFilter;
use crate::node::tests::session::{run_large_stack_async_test, send_endpoint_data_via_dataplane};
use crate::protocol::FilterAnnounce;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[test]
fn queued_lookup_wakes_when_filtered_non_tree_peer_becomes_child() {
    run_large_stack_async_test("tree-reachability-wakeup", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = run_tree_test(3, &[(0, 1), (1, 2), (2, 0)], false).await;
        let result = AssertUnwindSafe(exercise(&mut nodes)).catch_unwind().await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise(nodes: &mut [TestNode]) {
    // Reuse the existing triangle fixture only for authenticated setup. The
    // transition below is a controlled local parent choice, not a claim that
    // this topology was organically selected under a particular metric order.
    let (sender, source) = (0..nodes.len())
        .flat_map(|sender| (0..nodes.len()).map(move |source| (sender, source)))
        .find(|&(sender, source)| {
            sender != source
                && !nodes[source]
                    .node
                    .is_tree_peer(nodes[sender].node.node_addr())
                && !nodes[source]
                    .node
                    .tree_state()
                    .my_coords()
                    .contains(nodes[sender].node.node_addr())
        })
        .expect("triangle needs a loop-free non-tree orientation");
    let sender_addr = *nodes[sender].node.node_addr();
    let source_addr = *nodes[source].node.node_addr();
    let snapshot = |nodes: &[TestNode]| {
        nodes
            .iter()
            .map(|node| {
                let mut peers = node
                    .node
                    .peers
                    .values()
                    .map(|peer| {
                        assert!(peer.is_healthy() && peer.can_send());
                        (
                            *peer.node_addr(),
                            peer.link_id(),
                            peer.our_index(),
                            peer.session_generation(),
                        )
                    })
                    .collect::<Vec<_>>();
                peers.sort_by_key(|peer| peer.0);
                assert_eq!(peers.len(), 2);
                assert_eq!(node.node.connection_count(), 0);
                assert_eq!(node.node.link_count(), 2);
                peers
            })
            .collect::<Vec<_>>()
    };
    let owners = snapshot(nodes);
    let _source_io = nodes[source].node.attach_endpoint_data_io(8).unwrap();
    // The advertised target is deliberately synthetic: this tests an actual
    // first lookup crossing the carrier, not end-to-end reachability/delivery.
    let destination = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let target = *destination.node_addr();
    assert!(
        nodes[source]
            .node
            .peers
            .values()
            .all(|peer| !peer.may_reach(&target)),
        "the original queue must begin without any advertised target route"
    );
    assert!(nodes[source].node.get_session(&target).is_none());
    assert_eq!(
        nodes[source]
            .node
            .config
            .node
            .discovery
            .attempt_timeouts_secs,
        vec![1, 2, 4, 8]
    );
    let requests_before = nodes[source].node.stats().discovery.req_initiated;
    let received_before = nodes[sender].node.stats().discovery.req_received;
    send_endpoint_data_via_dataplane(
        &mut nodes[source].node,
        destination,
        b"original-before-child".to_vec(),
    )
    .await
    .unwrap();
    assert_eq!(
        nodes[source]
            .node
            .pending_session_traffic
            .endpoint_data_for(&target)
            .map(|queue| queue.len()),
        Some(1)
    );
    let pending = nodes[source]
        .node
        .pending_lookups
        .get(&target)
        .expect("normal ingress admits the unsent lookup");
    assert!(pending.awaiting_first_request());
    let original = (pending.attempt, pending.initiated_ms, pending.last_sent_ms);
    assert_eq!(original.0, 1);
    let deadline = nodes[source].node.pending_lookup_deadline_ms().unwrap();
    assert_eq!(deadline, original.2 + 1_000);

    let filter_sequence = nodes[source]
        .node
        .get_peer(&sender_addr)
        .unwrap()
        .filter_sequence()
        + 1;
    let mut filter = BloomFilter::new();
    filter.insert(&target);
    let encoded_filter = FilterAnnounce::new(filter, filter_sequence)
        .encode()
        .unwrap();
    nodes[sender]
        .node
        .send_dataplane_fmp_link_plaintext(&source_addr, &encoded_filter, false)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(250), async {
        while nodes[source]
            .node
            .get_peer(&sender_addr)
            .unwrap()
            .filter_sequence()
            != filter_sequence
        {
            poll_available_packets(nodes).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("accepted filter must cross the real encrypted non-tree carrier");
    assert!(!nodes[source].node.is_tree_peer(&sender_addr));
    assert!(
        nodes[source]
            .node
            .get_peer(&sender_addr)
            .unwrap()
            .may_reach(&target)
    );
    assert_eq!(
        nodes[source].node.stats().discovery.req_initiated,
        requests_before,
        "a non-tree advertisement must not initiate the lookup"
    );
    assert_eq!(
        nodes[sender].node.stats().discovery.req_received,
        received_before
    );
    assert!(
        nodes[source]
            .node
            .pending_lookups
            .get(&target)
            .unwrap()
            .awaiting_first_request()
    );

    let sequence = nodes[sender]
        .node
        .tree_state()
        .my_declaration()
        .sequence()
        .max(
            nodes[source]
                .node
                .tree_state()
                .peer_declaration(&sender_addr)
                .unwrap()
                .sequence(),
        )
        + 1;
    {
        let child = &mut nodes[sender].node;
        child
            .tree_state_mut()
            .set_parent(source_addr, sequence, crate::time::now_secs());
        child.tree_state_mut().recompute_coords();
        child.tree_state.sign_declaration(&child.identity).unwrap();
    }
    let announce = nodes[sender].node.build_tree_announce().unwrap();
    announce.validate_semantics().unwrap();
    assert_eq!(*announce.declaration.parent_id(), source_addr);
    let encoded_tree = announce.encode().unwrap();
    let accepted_before = nodes[source].node.stats().tree.accepted;
    nodes[sender]
        .node
        .send_dataplane_fmp_link_plaintext(&source_addr, &encoded_tree, false)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(250), async {
        while !nodes[source].node.is_tree_peer(&sender_addr) {
            poll_available_packets(nodes).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("signed child declaration must change receiver eligibility");
    assert_eq!(
        nodes[source].node.stats().tree.accepted,
        accepted_before + 1
    );
    assert_eq!(snapshot(nodes), owners);
    assert!(
        Node::now_ms() < deadline,
        "normal retry deadline has not arrived"
    );
    assert_eq!(
        nodes[source].node.stats().discovery.req_initiated,
        requests_before + 1,
        "new tree eligibility must release the already-admitted unsent lookup once"
    );
    let request_id = nodes[source]
        .node
        .pending_lookups
        .last_origin_request_id(&target)
        .expect("first request must have an actual origin ID");
    tokio::time::timeout(Duration::from_millis(250), async {
        while nodes[sender].node.stats().discovery.req_received == received_before {
            poll_available_packets(nodes).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first lookup must reach the peer over its existing encrypted carrier");
    assert_eq!(
        nodes[sender].node.stats().discovery.req_received,
        received_before + 1
    );

    // No timer or synthetic repair runs after the original ingress. Re-send
    // the same signed declaration in fresh authenticated FMP frames: neither
    // stale input nor duplicate eligibility may create another request.
    let stale_before = nodes[source].node.stats().tree.stale;
    for _ in 0..2 {
        nodes[sender]
            .node
            .send_dataplane_fmp_link_plaintext(&source_addr, &encoded_tree, false)
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_millis(250), async {
        while nodes[source].node.stats().tree.stale < stale_before + 2 {
            poll_available_packets(nodes).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both duplicate declarations must reach stale handling");
    assert!(Node::now_ms() < deadline);
    let pending = nodes[source].node.pending_lookups.get(&target).unwrap();
    assert_eq!(
        (pending.attempt, pending.initiated_ms, pending.last_sent_ms),
        original
    );
    assert_eq!(
        nodes[source].node.pending_lookup_deadline_ms(),
        Some(deadline)
    );
    assert_eq!(
        nodes[source]
            .node
            .pending_lookups
            .last_origin_request_id(&target),
        Some(request_id)
    );
    assert_eq!(
        nodes[source].node.stats().discovery.req_initiated,
        requests_before + 1
    );
    assert_eq!(
        nodes[sender].node.stats().discovery.req_received,
        received_before + 1
    );
    assert_eq!(
        nodes[source]
            .node
            .pending_session_traffic
            .endpoint_data_for(&target)
            .map(|queue| queue.len()),
        Some(1),
        "the one original remains owned by normal discovery"
    );
    assert_eq!(snapshot(nodes), owners);
}
