//! A downstream join must be distinguishable from an unchanged offline target.
use super::*;

const PARENT: usize = 0;
const SOURCE: usize = 1;
const TARGET: usize = 2;

#[test]
fn fresh_payload_discovers_newly_reachable_target_after_real_lookup_exhaustion() {
    run_large_stack_async_test("reachable-after-backoff", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = vec![
            make_test_node().await,
            make_test_node().await,
            make_test_node().await,
        ];
        // P remains the lowest root throughout. T joins as S's sibling, so its
        // coordinates cannot be learned just from S's own signed ancestry.
        nodes.sort_by_key(|test| *test.node.node_addr());
        let result = AssertUnwindSafe(exercise(&mut nodes)).catch_unwind().await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn dial_parent(nodes: &mut [TestNode], child: usize) {
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

fn source_path(nodes: &[TestNode]) -> (NodeAddr, NodeAddr) {
    let tree = nodes[SOURCE].node.tree_state();
    (*tree.root(), *tree.my_declaration().parent_id())
}

async fn assert_offline_still_suppressed(nodes: &mut [TestNode], identity: PeerIdentity) {
    let target = *identity.node_addr();
    let requests = nodes[SOURCE].node.stats().discovery.req_initiated;
    let suppressed = nodes[SOURCE].node.stats().discovery.req_backoff_suppressed;
    assert!(nodes[SOURCE].node.discovery_backoff.is_suppressed(&target));
    send_endpoint_data_via_dataplane(&mut nodes[SOURCE].node, identity, b"still offline".to_vec())
        .await
        .unwrap();
    assert!(nodes[SOURCE].node.discovery_backoff.is_suppressed(&target));
    assert_eq!(
        nodes[SOURCE].node.stats().discovery.req_backoff_suppressed,
        suppressed + 1
    );
    assert_eq!(nodes[SOURCE].node.stats().discovery.req_initiated, requests);
    assert!(nodes[SOURCE].node.pending_lookups.get(&target).is_none());
    assert!(nodes[SOURCE].node.get_session(&target).is_none());
}

async fn exercise(nodes: &mut [TestNode]) {
    for test in nodes.iter_mut() {
        test.node.config.node.rate_limit = Config::new().node.rate_limit;
        test.node.config.node.discovery.lan.enabled = false;
        assert_eq!(
            test.node.config.node.discovery.attempt_timeouts_secs,
            [1, 2, 4, 8]
        );
        assert_eq!(test.node.config.node.discovery.forward_min_interval_secs, 2);
        assert_eq!(test.node.config.node.discovery.backoff_base_secs, 30);
    }
    let parent = *nodes[PARENT].node.node_addr();
    let target = *nodes[TARGET].node.node_addr();
    let destination = PeerIdentity::from_pubkey_full(nodes[TARGET].node.identity().pubkey_full());
    // This absent identity is never advertised or connected. Its independent
    // failed demand guards against clearing all backoff on a positive filter.
    let offline = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let offline_addr = *offline.node_addr();
    let _source_io = nodes[SOURCE].node.attach_endpoint_data_io(8).unwrap();
    let mut target_io = nodes[TARGET].node.attach_endpoint_data_io(8).unwrap();
    dial_parent(nodes, SOURCE).await;
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        turn(nodes).await;
        if source_path(nodes) == (parent, parent)
            && nodes[SOURCE]
                .node
                .get_peer(&parent)
                .is_some_and(|peer| peer.filter_sequence() > 0)
            && nodes[PARENT]
                .node
                .is_tree_peer(nodes[SOURCE].node.node_addr())
        {
            break;
        }
        assert!(
            Instant::now() < until,
            "real source-parent tree/filter setup"
        );
    }
    let original = [owner(nodes, SOURCE, PARENT), owner(nodes, PARENT, SOURCE)];
    let path = source_path(nodes);
    assert_eq!(nodes[TARGET].node.peers.len(), 0);
    assert!(
        !nodes[SOURCE]
            .node
            .get_peer(&parent)
            .unwrap()
            .may_reach(&target)
    );
    assert!(nodes[SOURCE].node.get_session(&target).is_none());

    let requests = nodes[SOURCE].node.stats().discovery.req_initiated;
    let timed_out = nodes[SOURCE].node.stats().discovery.resp_timed_out;
    let parent_received = nodes[PARENT].node.stats().discovery.req_received;
    send_endpoint_data_via_dataplane(
        &mut nodes[SOURCE].node,
        destination,
        b"original while offline".to_vec(),
    )
    .await
    .unwrap();
    let initial = nodes[SOURCE]
        .node
        .pending_lookups
        .get(&target)
        .expect("ordinary ingress admits a bounded unsent lookup")
        .clone();
    assert_eq!(initial.attempt, 1);
    assert!(initial.awaiting_first_request());
    assert_eq!(
        nodes[SOURCE]
            .node
            .pending_session_traffic
            .endpoint_data_for(&target)
            .map(|queue| queue.len()),
        Some(1)
    );
    assert!(
        !nodes[SOURCE]
            .node
            .get_peer(&parent)
            .unwrap()
            .may_reach(&offline_addr)
    );
    send_endpoint_data_via_dataplane(
        &mut nodes[SOURCE].node,
        offline,
        b"unrelated offline original".to_vec(),
    )
    .await
    .unwrap();
    let offline_initial = nodes[SOURCE]
        .node
        .pending_lookups
        .get(&offline_addr)
        .expect("unrelated real demand owns its own lookup")
        .clone();
    assert_eq!(offline_initial.attempt, 1);
    let mut attempts = vec![(initial.attempt, initial.last_sent_ms)];
    let until = Instant::now() + Duration::from_secs(17);
    loop {
        // Existing native turn drives real deadlines and encrypted packets;
        // neither timestamps nor backoff entries are installed by the test.
        turn(nodes).await;
        assert_eq!(source_path(nodes), path);
        assert_eq!(
            [owner(nodes, SOURCE, PARENT), owner(nodes, PARENT, SOURCE)],
            original
        );
        if let Some(pending) = nodes[SOURCE].node.pending_lookups.get(&target) {
            assert_eq!(pending.initiated_ms, initial.initiated_ms);
            if attempts.last().unwrap().0 != pending.attempt {
                attempts.push((pending.attempt, pending.last_sent_ms));
            }
        } else if nodes[SOURCE]
            .node
            .pending_lookups
            .get(&offline_addr)
            .is_none()
        {
            break;
        }
        if let Some(pending) = nodes[SOURCE].node.pending_lookups.get(&offline_addr) {
            assert_eq!(pending.initiated_ms, offline_initial.initiated_ms);
        }
        assert!(Instant::now() < until, "normal lookup ladder must exhaust");
    }
    assert_eq!(
        attempts.iter().map(|attempt| attempt.0).collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );
    for (pair, interval) in attempts.windows(2).zip([1_000, 2_000, 4_000]) {
        assert!(
            pair[1].1 >= pair[0].1 + interval,
            "unchanged attempt deadline"
        );
    }
    assert!(Node::now_ms() >= attempts.last().unwrap().1 + 8_000);
    assert_eq!(
        nodes[SOURCE].node.stats().discovery.resp_timed_out,
        timed_out + 2
    );
    assert_eq!(
        nodes[SOURCE].node.stats().discovery.req_initiated,
        requests + 6,
        "both Bloom-negative targets plan the three remaining ordinary attempts"
    );
    assert_eq!(
        nodes[PARENT].node.stats().discovery.req_received,
        parent_received,
        "the empty peer plans emit no wire lookup to the parent"
    );
    assert!(nodes[SOURCE].node.discovery_backoff.is_suppressed(&target));
    assert_eq!(
        nodes[SOURCE].node.discovery_backoff.failure_count(&target),
        1
    );
    assert!(
        !nodes[SOURCE]
            .node
            .pending_session_traffic
            .has_traffic_for(&target)
    );
    assert!(nodes[SOURCE].node.get_session(&target).is_none());
    assert!(
        nodes[SOURCE]
            .node
            .discovery_backoff
            .is_suppressed(&offline_addr)
    );
    assert_eq!(
        nodes[SOURCE]
            .node
            .discovery_backoff
            .failure_count(&offline_addr),
        1
    );
    assert!(
        !nodes[SOURCE]
            .node
            .pending_session_traffic
            .has_traffic_for(&offline_addr)
    );
    assert!(target_io.event_rx.try_recv().is_err());
    let requests = nodes[SOURCE].node.stats().discovery.req_initiated;

    // Only the downstream physical link changes. S receives an actual new
    // FilterAnnounce through its existing authenticated parent; no peer or
    // root replacement at S can independently reset its post-failure state.
    let filter_sequence = nodes[SOURCE]
        .node
        .get_peer(&parent)
        .unwrap()
        .filter_sequence();
    let joined = Instant::now();
    dial_parent(nodes, TARGET).await;
    loop {
        turn(nodes).await;
        assert_eq!(source_path(nodes), path);
        assert_eq!(
            [owner(nodes, SOURCE, PARENT), owner(nodes, PARENT, SOURCE)],
            original
        );
        let peer = nodes[SOURCE].node.get_peer(&parent).unwrap();
        if peer.filter_sequence() > filter_sequence
            && peer.may_reach(&target)
            && nodes[SOURCE].node.is_tree_peer(&parent)
            && *nodes[TARGET].node.tree_state().root() == parent
            && nodes[PARENT].node.is_tree_peer(&target)
        {
            break;
        }
        assert!(
            joined.elapsed() < Duration::from_secs(5),
            "new downstream reachability is advertised"
        );
    }
    assert!(
        !nodes[SOURCE]
            .node
            .coord_cache()
            .contains(&target, Node::now_ms())
    );
    assert!(nodes[SOURCE].node.pending_lookups.get(&target).is_none());
    assert!(
        !nodes[SOURCE]
            .node
            .get_peer(&parent)
            .unwrap()
            .may_reach(&offline_addr)
    );
    assert_offline_still_suppressed(nodes, offline).await;
    let suppressed_before = nodes[SOURCE].node.stats().discovery.req_backoff_suppressed;
    let suppressed_at_join = nodes[SOURCE].node.discovery_backoff.is_suppressed(&target);
    let payload = b"one fresh original after downstream join";
    let offered = Instant::now();
    send_endpoint_data_via_dataplane(&mut nodes[SOURCE].node, destination, payload.to_vec())
        .await
        .unwrap();
    eprintln!(
        "reachable after backoff: attempts={attempts:?}, joined_ms={}, suppressed_at_join={suppressed_at_join}, fresh_suppressed={}, pending={}, queued={}",
        joined.elapsed().as_millis(),
        nodes[SOURCE].node.stats().discovery.req_backoff_suppressed - suppressed_before,
        nodes[SOURCE].node.pending_lookups.get(&target).is_some(),
        nodes[SOURCE]
            .node
            .pending_session_traffic
            .endpoint_data_for(&target)
            .map_or(0, |queue| queue.len())
    );
    assert!(
        nodes[SOURCE].node.pending_lookups.get(&target).is_some(),
        "fresh demand for the newly advertised target must admit a bounded lookup instead of retaining offline backoff"
    );
    loop {
        turn(nodes).await;
        assert_eq!(source_path(nodes), path);
        assert_eq!(
            [owner(nodes, SOURCE, PARENT), owner(nodes, PARENT, SOURCE)],
            original
        );
        if let Ok(event) = target_io.event_rx.try_recv() {
            assert_eq!(
                expect_single_endpoint_data_event(event).payload.as_slice(),
                payload
            );
            break;
        }
        assert!(
            offered.elapsed() < Duration::from_secs(5),
            "fresh original must use actual lookup, FSP and payload paths"
        );
    }
    assert!(
        nodes[SOURCE]
            .node
            .coord_cache()
            .contains(&target, Node::now_ms())
    );
    assert!(
        nodes[SOURCE]
            .node
            .get_session(&target)
            .unwrap()
            .is_established()
    );
    assert!(nodes[TARGET].node.stats().discovery.req_target_is_us > 0);
    assert!((1..=4).contains(&(nodes[SOURCE].node.stats().discovery.req_initiated - requests)));
    assert_offline_still_suppressed(nodes, offline).await;
    let drain = Instant::now() + Duration::from_millis(250);
    while Instant::now() < drain {
        turn(nodes).await;
        assert!(
            target_io.event_rx.try_recv().is_err(),
            "no old or duplicate payload may arrive"
        );
    }
    for (index, test) in nodes.iter().enumerate() {
        let expected = if index == PARENT { 2 } else { 1 };
        assert_eq!(test.node.peers.len(), expected);
        assert_eq!(test.node.link_count(), expected);
        assert_eq!(test.node.connection_count(), 0);
    }
    eprintln!(
        "reachable after backoff delivered once in {} ms",
        offered.elapsed().as_millis()
    );
}
