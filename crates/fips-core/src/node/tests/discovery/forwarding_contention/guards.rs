//! Controlled invalidation of real authenticated waiting requests.
use super::*;
use crate::node::tests::spanning_tree::{
    process_dataplane_completions, process_dataplane_packet_once,
};

#[derive(Clone, Copy, Debug)]
enum Case {
    Keep,
    ReverseOwnerChanged,
    ResponseClaimed,
    IngressGone,
    TargetGone,
    FrozenExpiry,
}

#[test]
fn deferred_ttl_one_and_original_owner_win_over_new_arrivals() {
    run_case(Case::Keep);
}
#[test]
fn same_millisecond_readmission_cannot_recreate_waiting_owner() {
    run_case(Case::ReverseOwnerChanged);
}
#[test]
fn already_claimed_response_cannot_forward_again() {
    run_case(Case::ResponseClaimed);
}
#[test]
fn disconnected_ingress_cannot_keep_a_forwarding_reservation() {
    run_case(Case::IngressGone);
}
#[test]
fn vanished_route_does_not_consume_a_forwarding_slot() {
    run_case(Case::TargetGone);
}
#[test]
fn configuration_increase_cannot_extend_original_expiry() {
    run_case(Case::FrozenExpiry);
}

fn run_case(case: Case) {
    run_large_stack_async_test("deferred-lookup-guard", move || async move {
        let _guard = lock_large_network_test().await;
        let mut nodes = Vec::new();
        for _ in 0..4 {
            nodes.push(make_test_node().await);
        }
        nodes.sort_by_key(|node| *node.node.node_addr());
        let result = AssertUnwindSafe(exercise(&mut nodes, case))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

fn record_status(node: &TestNode, id: u64, deadline: Instant) -> Option<bool> {
    if Instant::now() >= deadline {
        Some(false)
    } else {
        node.node.recent_requests.contains_key(&id).then_some(true)
    }
}

async fn record_within_deadline(nodes: &mut [TestNode], node: usize, id: u64) -> bool {
    let deadline = Instant::now() + Duration::from_millis(250);
    tokio::time::timeout_at(deadline, async {
        loop {
            // The general topology drain can await unrelated crypto readiness
            // for a second. Drive bounded ready turns and all nodes instead;
            // only the decoded request's admission satisfies this wait.
            for index in 0..nodes.len() {
                for _ in 0..64 {
                    if let Some(outcome) = record_status(&nodes[node], id, deadline) {
                        return outcome;
                    }
                    let Ok(packet) = nodes[index].packet_rx.try_recv() else {
                        break;
                    };
                    process_dataplane_packet_once(&mut nodes[index].node, packet).await;
                }
                if let Some(outcome) = record_status(&nodes[node], id, deadline) {
                    return outcome;
                }
                process_dataplane_completions(&mut nodes[index].node).await;
            }
            if let Some(outcome) = record_status(&nodes[node], id, deadline) {
                return outcome;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or(false)
}

async fn wait_record(nodes: &mut [TestNode], node: usize, id: u64) {
    assert!(
        record_within_deadline(nodes, node, id).await,
        "real lookup {id} reaches authenticated receiver {node} within 250ms"
    );
}

async fn source_request(nodes: &mut [TestNode], id: u64) {
    let request = LookupRequest::new(
        id,
        *nodes[2].node.node_addr(),
        *nodes[0].node.node_addr(),
        nodes[0].node.tree_state().my_coords().clone(),
        1,
        0,
    );
    let relay = *nodes[1].node.node_addr();
    nodes[0]
        .node
        .send_dataplane_fmp_link_plaintext(&relay, &request.encode(), false)
        .await
        .unwrap();
    wait_record(nodes, 1, id).await;
}

async fn exercise(nodes: &mut [TestNode], case: Case) {
    setup(nodes).await;
    if matches!(case, Case::IngressGone) {
        assert!(
            !record_within_deadline(nodes, 1, 100).await,
            "unrelated ready traffic cannot satisfy the absent request predicate"
        );
    }
    let source = *nodes[0].node.node_addr();
    let target = *nodes[2].node.node_addr();
    let started = Instant::now();
    source_request(nodes, 1).await;
    wait_record(nodes, 2, 1).await;
    if matches!(case, Case::FrozenExpiry) {
        nodes[1].node.config.node.discovery.recent_expiry_secs = 1;
    }
    source_request(nodes, 100).await;
    if matches!(case, Case::IngressGone) {
        assert_eq!(
            record_status(&nodes[1], 100, Instant::now()),
            Some(false),
            "even an admitted request cannot satisfy an elapsed wall deadline"
        );
    }
    assert_eq!(nodes[1].node.pending_lookups.len(), 0);
    let reserved = nodes[1]
        .node
        .discovery_work_deadline_ms()
        .expect("transit-only wait owns a deadline");
    assert!(!nodes[2].node.recent_requests.contains_key(&100));
    source_request(nodes, 101).await;
    // A fresh ID from the same ingress cannot replace the first request.
    let next = nodes[1].node.discovery_work_deadline_ms().unwrap();
    assert!(
        next.abs_diff(reserved) <= 2,
        "reservation not extended by a fresh ID"
    );
    let original = nodes[1].node.recent_requests.get(&100).unwrap().clone();
    match case {
        Case::Keep => {}
        Case::ReverseOwnerChanged => {
            nodes[1].node.recent_requests.remove(100).unwrap();
            let admitted = nodes[1].node.recent_requests.record_request(
                100,
                source,
                target,
                original.timestamp_ms,
                crate::node::RecentDiscoveryRequestLimits::new(4096, 3, 64),
            );
            assert!(admitted.accepted());
            let replacement = nodes[1].node.recent_requests.get(&100).unwrap();
            assert_eq!(replacement.timestamp_ms, original.timestamp_ms);
            assert_ne!(
                replacement.admission_generation,
                original.admission_generation
            );
        }
        Case::ResponseClaimed => {
            nodes[1]
                .node
                .recent_requests
                .claim_response_forward(100, target);
        }
        Case::IngressGone => {
            nodes[1].node.remove_active_peer(&source);
        }
        Case::TargetGone => {
            nodes[1].node.remove_active_peer(&target);
        }
        Case::FrozenExpiry => {
            nodes[1].node.config.node.discovery.recent_expiry_secs = 60;
        }
    }
    // Hold only lookup maintenance past the real slot. Incoming new traffic
    // must give the already-due waiter first consideration in the handler.
    while started.elapsed() < Duration::from_millis(2200) {
        process_available_packets(nodes).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    if matches!(case, Case::Keep) {
        source_request(nodes, 2).await;
        wait_record(nodes, 1, 2).await;
        wait_record(nodes, 2, 100).await;
        assert!(
            !nodes[2].node.recent_requests.contains_key(&2),
            "new request cannot steal its ingress's reserved slot"
        );
        assert!(
            !nodes[2].node.recent_requests.contains_key(&101),
            "first request keeps ownership"
        );
        assert_eq!(nodes[1].node.stats().discovery.req_forwarded, 2);
        // The original TTL of one still reached the direct target: deferred
        // dispatch must not decrement this hop's already-spent TTL again.
    } else {
        nodes[1].node.check_discovery_work(Node::now_ms()).await;
        process_available_packets(nodes).await;
        assert!(
            !nodes[2].node.recent_requests.contains_key(&100),
            "invalid reservation forwarded: {case:?}"
        );
        assert_eq!(nodes[1].node.discovery_work_deadline_ms(), None);
        assert_eq!(nodes[1].node.stats().discovery.req_forwarded, 1);
        let noisy = *nodes[3].node.node_addr();
        assert!(
            nodes[1]
                .node
                .discovery_forward_limiter
                .should_forward(&noisy, &target),
            "invalid waiter did not consume target slot"
        );
    }
    eprintln!("deferred lookup guard: {case:?}");
}
