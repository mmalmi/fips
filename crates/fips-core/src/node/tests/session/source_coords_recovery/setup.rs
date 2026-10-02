//! Complete setup's admitted retries before measuring fresh coordinate recovery.
use super::*;
use futures::FutureExt;
use std::ops::Range;
use std::panic::AssertUnwindSafe;
use tokio::time::Instant;

pub(super) fn ready(nodes: &[TestNode], destination: &NodeAddr) -> bool {
    nodes[0]
        .node
        .coord_cache
        .get(destination, Node::now_ms())
        .is_some()
        && nodes
            .iter()
            .all(|node| node.node.discovery_work_deadline_ms().is_none())
}

#[test]
fn cached_coordinates_do_not_finish_an_admitted_setup_retry() {
    run(true);
}

#[test]
fn overdue_setup_retry_precedes_a_fresh_origin_request() {
    run(false);
}

fn run(settle: bool) {
    run_large_stack_async_test("coordinate-setup-retry", move || async move {
        let _guard = lock_large_network_test().await;
        let mut nodes = Vec::new();
        for _ in 0..3 {
            nodes.push(make_test_node().await);
        }
        nodes.sort_by_key(|node| std::cmp::Reverse(*node.node.node_addr()));
        let result = AssertUnwindSafe(exercise(&mut nodes, settle))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn poll_until(
    nodes: &mut [TestNode],
    range: Range<usize>,
    deadline: Instant,
    context: &str,
    done: impl Fn(&[TestNode]) -> bool,
) {
    loop {
        assert!(Instant::now() < deadline, "{context}");
        tokio::time::timeout_at(deadline, poll_available_packets(&mut nodes[range.clone()]))
            .await
            .expect(context);
        assert!(Instant::now() < deadline, "{context}");
        if done(nodes) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn sleep_to_native_deadline(due_ms: u64) {
    while Node::now_ms() < due_ms {
        tokio::time::sleep(Duration::from_millis(due_ms.saturating_sub(Node::now_ms()))).await;
    }
}

async fn admitted_retry(nodes: &mut [TestNode], target: NodeAddr, until: Instant) -> u64 {
    nodes[0]
        .node
        .maybe_initiate_route_query_lookup(&target)
        .await;
    let first = nodes[0]
        .node
        .pending_lookups
        .last_origin_request_id(&target)
        .unwrap();
    // Leave the genuine first response queued at its source while the source's
    // existing 1 s retry becomes due. No packet or clock is fabricated.
    poll_until(
        nodes,
        1..3,
        until,
        "first signed reply reaches its transit",
        |nodes| {
            nodes[1]
                .node
                .recent_requests
                .get(&first)
                .is_some_and(|request| request.response_forwarded)
        },
    )
    .await;
    sleep_to_native_deadline(nodes[0].node.pending_lookup_deadline_ms().unwrap()).await;
    nodes[0].node.check_pending_lookups(Node::now_ms()).await;
    let retry = nodes[0]
        .node
        .pending_lookups
        .last_origin_request_id(&target)
        .unwrap();
    assert_ne!(first, retry, "ordinary retry emits a fresh request ID");
    poll_until(
        nodes,
        1..3,
        until,
        "actual retry is deferred by the transit",
        |nodes| {
            nodes[1].node.recent_requests.contains_key(&retry)
                && nodes[1].node.discovery_work_deadline_ms().is_some()
                && nodes[1].node.stats().discovery.req_forward_rate_limited == 1
        },
    )
    .await;
    assert_eq!(nodes[1].node.stats().discovery.req_forwarded, 1);
    // Completing the first request removes both IDs from the source lookup;
    // the admitted retry at the transit retains its legitimate ownership.
    poll_until(
        nodes,
        0..1,
        until,
        "original reply completes source discovery",
        |nodes| !nodes[0].node.pending_lookups.contains_key(&target),
    )
    .await;
    assert_eq!(nodes[0].node.stats().discovery.resp_accepted, 1);
    assert!(
        nodes[0]
            .node
            .coord_cache
            .get(&target, Node::now_ms())
            .is_some()
    );
    assert!(
        !ready(nodes, &target),
        "cached coordinates must not finish setup while an admitted retry still waits"
    );
    retry
}

async fn settle_setup(nodes: &mut [TestNode], target: NodeAddr, retry: u64, until: Instant) {
    tokio::time::timeout_at(until, async {
        while !ready(nodes, &target) {
            discovery_turn(nodes).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("original 5 s setup budget services admitted retry");
    assert!(Instant::now() < until);
    assert_eq!(nodes[1].node.stats().discovery.req_forwarded, 2);
    poll_until(
        nodes,
        0..3,
        until,
        "old signed reply remains unsolicited",
        |nodes| nodes[0].node.stats().discovery.resp_unsolicited == 1,
    )
    .await;
    assert!(
        nodes[1]
            .node
            .recent_requests
            .get(&retry)
            .unwrap()
            .response_forwarded
    );
    assert_eq!(nodes[0].node.stats().discovery.resp_accepted, 1);
    assert!(ready(nodes, &target));
}

async fn compete(nodes: &mut [TestNode], target: NodeAddr, retry: u64, until: Instant) {
    // Reproduce a manual fixture that sleeps past a deferred deadline without
    // servicing it. The arriving fresh request must not erase that old owner.
    sleep_to_native_deadline(nodes[1].node.discovery_work_deadline_ms().unwrap()).await;
    nodes[0]
        .node
        .maybe_initiate_route_query_lookup(&target)
        .await;
    let fresh = nodes[0]
        .node
        .pending_lookups
        .last_origin_request_id(&target)
        .unwrap();
    assert_ne!(fresh, retry);
    let one_second = Instant::now() + Duration::from_secs(1);
    poll_until(
        nodes,
        0..3,
        one_second,
        "old reply cannot complete fresh lookup",
        |nodes| {
            nodes[0].node.stats().discovery.resp_unsolicited == 1
                && nodes[1]
                    .node
                    .recent_requests
                    .get(&retry)
                    .is_some_and(|request| request.response_forwarded)
                && nodes[1].node.recent_requests.contains_key(&fresh)
        },
    )
    .await;
    assert_eq!(nodes[1].node.stats().discovery.req_forwarded, 2);
    assert_eq!(nodes[1].node.stats().discovery.req_forward_rate_limited, 2);
    assert!(
        nodes[0]
            .node
            .pending_lookups
            .matches_origin_request(&target, fresh)
    );
    assert_eq!(nodes[0].node.stats().discovery.resp_accepted, 1);
    let fresh_due = nodes[1].node.discovery_work_deadline_ms().unwrap();
    assert!(
        fresh_due > Node::now_ms() + 1_000,
        "fresh request owns the next normal slot"
    );
    sleep_to_native_deadline(fresh_due).await;
    nodes[1].node.check_discovery_work(Node::now_ms()).await;
    poll_until(
        nodes,
        0..3,
        until,
        "fresh signed reply completes at its unchanged slot",
        |nodes| !nodes[0].node.pending_lookups.contains_key(&target),
    )
    .await;
    assert_eq!(nodes[0].node.stats().discovery.resp_accepted, 2);
    assert_eq!(nodes[0].node.stats().discovery.resp_unsolicited, 1);
    assert_eq!(nodes[1].node.stats().discovery.req_forwarded, 3);
    assert!(
        nodes[1]
            .node
            .recent_requests
            .get(&fresh)
            .unwrap()
            .response_forwarded
    );
    eprintln!(
        "retained setup request {retry} preceded fresh request {fresh}; both real replies arrived"
    );
}

async fn exercise(nodes: &mut [TestNode], settle: bool) {
    initiate_handshake(nodes, 0, 1).await;
    initiate_handshake(nodes, 1, 2).await;
    let remote = PeerIdentity::from_pubkey_full(nodes[2].node.identity().pubkey_full());
    let target = *remote.node_addr();
    assert!(converge(nodes, target, 3).await);
    nodes[0]
        .node
        .register_identity(target, remote.pubkey_full());
    advertise_reachability(nodes, target, false).await;
    assert!(
        nodes
            .iter()
            .all(|node| node.node.discovery_work_deadline_ms().is_none())
    );
    assert_eq!(
        nodes[1]
            .node
            .config
            .node
            .discovery
            .forward_min_interval_secs,
        2
    );
    assert_eq!(
        nodes[0].node.config.node.discovery.attempt_timeouts_secs,
        [1, 2, 4, 8]
    );
    let until = Instant::now() + Duration::from_secs(5);
    let retry = admitted_retry(nodes, target, until).await;
    if settle {
        settle_setup(nodes, target, retry, until).await;
    } else {
        compete(nodes, target, retry, until).await;
    }
}
