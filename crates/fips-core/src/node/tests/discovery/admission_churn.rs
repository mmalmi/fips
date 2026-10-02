//! Rate-rejected requests must not displace admitted reverse paths or waiters.
use super::*;
use crate::node::tests::session::run_large_stack_async_test;
use crate::node::tests::spanning_tree::{TestNode, complete_direct_handshake, make_test_node};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use tokio::time::Instant;

const INGRESS: usize = 0;
const TRANSIT: usize = 1;
const TARGET: usize = 2;
const PEER_COUNT: usize = 64;
const FIRST: u64 = 10_000;

#[test]
fn admitted_reverse_path_without_churn_control() {
    run(false, false);
}

#[test]
fn admitted_reverse_path_survives_rate_rejected_churn() {
    run(true, false);
}

#[test]
fn admitted_deferred_waiter_without_churn_control() {
    run(false, true);
}

#[test]
fn admitted_deferred_waiter_survives_rate_rejected_churn() {
    run(true, true);
}

fn run(churn: bool, deferred: bool) {
    run_large_stack_async_test("lookup-admission-churn", move || async move {
        let _guard = lock_large_network_test().await;
        let mut nodes = Vec::new();
        for _ in 0..3 {
            nodes.push(make_test_node().await);
        }
        let result = AssertUnwindSafe(exercise(&mut nodes, churn, deferred))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn prepare(nodes: &mut [TestNode]) {
    // Two real UDP/Noise links carry the lookup. The remaining completed Noise
    // fixtures supply the public seed's >=64-peer admission share, without
    // background traffic, topology convergence, or altered resource limits.
    complete_direct_handshake(nodes, INGRESS, TRANSIT).await;
    complete_direct_handshake(nodes, TARGET, TRANSIT).await;
    let node = &mut nodes[TRANSIT].node;
    node.config.node.routing.mode = RoutingMode::ReplyLearned;
    assert_eq!(node.config.node.discovery.recent_expiry_secs, 10);
    assert_eq!(node.config.node.discovery.forward_min_interval_secs, 2);
    assert_eq!(
        node.config.node.discovery.attempt_timeouts_secs,
        [1, 2, 4, 8]
    );
    for index in 2..PEER_COUNT {
        let link = LinkId::new(1_000 + index as u64);
        let (connection, identity) =
            make_completed_connection(node, link, TransportId::new(999), Node::now_ms());
        node.add_connection(connection).unwrap();
        node.promote_connection(link, identity, Node::now_ms())
            .unwrap();
    }
    assert_eq!(node.peers.len(), PEER_COUNT);
    assert_eq!(
        (crate::node::handlers::discovery::MAX_RECENT_DISCOVERY_REQUESTS / node.peers.len())
            .max(crate::node::handlers::discovery::MIN_RECENT_DISCOVERY_REQUESTS_PER_PEER),
        64
    );
    assert!(node.recent_requests.is_empty());
    assert_eq!(node.stats().discovery.req_forwarded, 0);
}

async fn request(nodes: &mut [TestNode], id: u64) {
    let ingress = *nodes[INGRESS].node.node_addr();
    let request = LookupRequest::new(
        id,
        *nodes[TARGET].node.node_addr(),
        ingress,
        nodes[INGRESS].node.tree_state().my_coords().clone(),
        4,
        0,
    );
    nodes[TRANSIT]
        .node
        .handle_lookup_request(&ingress, &request.encode()[1..])
        .await;
}

async fn exercise(nodes: &mut [TestNode], churn: bool, deferred: bool) {
    prepare(nodes).await;
    let ingress = *nodes[INGRESS].node.node_addr();
    let target = *nodes[TARGET].node.node_addr();
    assert!(nodes[TRANSIT].node.get_peer(&ingress).unwrap().can_send());
    assert!(nodes[TRANSIT].node.get_peer(&target).unwrap().can_send());
    let started = Instant::now();
    request(nodes, FIRST).await;
    assert_eq!(nodes[TRANSIT].node.stats().discovery.req_forwarded, 1);
    let original_id = if deferred {
        request(nodes, FIRST + 1).await;
        assert_eq!(
            nodes[TRANSIT]
                .node
                .stats()
                .discovery
                .req_forward_rate_limited,
            1
        );
        assert!(nodes[TRANSIT].node.discovery_work_deadline_ms().is_some());
        FIRST + 1
    } else {
        FIRST
    };
    let owner = nodes[TRANSIT]
        .node
        .recent_requests
        .get(&original_id)
        .unwrap()
        .clone();
    let deadline = nodes[TRANSIT].node.discovery_work_deadline_ms();
    let rejected_before = nodes[TRANSIT]
        .node
        .stats()
        .discovery
        .req_forward_rate_limited;
    if churn {
        for id in FIRST + 2..FIRST + 66 {
            request(nodes, id).await;
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "churn precedes the unchanged slot"
        );
        assert_eq!(nodes[TRANSIT].node.stats().discovery.req_forwarded, 1);
        assert_eq!(
            nodes[TRANSIT]
                .node
                .stats()
                .discovery
                .req_forward_rate_limited,
            rejected_before + 64
        );
    }
    let node = &nodes[TRANSIT].node;
    assert!(node.recent_requests.len() <= 4_096);
    assert_eq!(
        node.recent_requests.indexed_len(),
        node.recent_requests.len()
    );
    assert!(
        node.recent_requests.len() <= 64,
        "one ingress retains its original share"
    );
    assert!(Node::now_ms().saturating_sub(owner.timestamp_ms) < 10_000);
    if deferred {
        assert!(
            nodes[TRANSIT]
                .node
                .discovery_work_deadline_ms()
                .unwrap()
                .abs_diff(deadline.unwrap())
                <= 2
        );
        tokio::time::sleep_until(started + Duration::from_millis(2_050)).await;
        nodes[TRANSIT]
            .node
            .check_discovery_work(Node::now_ms())
            .await;
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "unchanged reverse-path expiry"
        );
        eprintln!(
            "deferred churn={churn}: forwarded={}, evicted={}, owner_present={}",
            nodes[TRANSIT].node.stats().discovery.req_forwarded,
            nodes[TRANSIT].node.stats().discovery.req_dedup_evicted,
            nodes[TRANSIT]
                .node
                .recent_requests
                .contains_key(&original_id)
        );
        assert_eq!(
            nodes[TRANSIT].node.stats().discovery.req_forwarded,
            2,
            "an admitted waiter must still dispatch at its existing slot after rejected arrivals"
        );
    } else {
        // Deliver the genuine target's signed reply after the intervening
        // requests, but before expiry. No origin lookup or synthetic reverse
        // record is inserted: the production request handler owns the route.
        let coords = nodes[TARGET].node.tree_state().my_coords().clone();
        let proof = nodes[TARGET]
            .node
            .identity()
            .sign(&LookupResponse::proof_bytes(original_id, &target, &coords));
        let response = LookupResponse::new(original_id, target, coords, proof);
        nodes[TRANSIT]
            .node
            .handle_lookup_response(&target, &response.encode()[1..])
            .await;
        eprintln!(
            "response churn={churn}: forwarded={}, unsolicited={}, evicted={}, owner_present={}, age_ms={}",
            nodes[TRANSIT].node.stats().discovery.resp_forwarded,
            nodes[TRANSIT].node.stats().discovery.resp_unsolicited,
            nodes[TRANSIT].node.stats().discovery.req_dedup_evicted,
            nodes[TRANSIT]
                .node
                .recent_requests
                .contains_key(&original_id),
            Node::now_ms().saturating_sub(owner.timestamp_ms)
        );
        assert_eq!(
            nodes[TRANSIT].node.stats().discovery.resp_forwarded,
            1,
            "an admitted late response must retain its reverse path despite rejected arrivals"
        );
        assert_eq!(nodes[TRANSIT].node.stats().discovery.resp_unsolicited, 0);
    }
}
