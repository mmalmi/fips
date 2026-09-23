//! Competing authenticated ingress peers must not exhaust a working lookup.
use super::*;
use crate::node::tests::session::{
    expect_single_endpoint_data_event, run_large_stack_async_test, send_endpoint_data_via_dataplane,
};
use crate::node::tests::spanning_tree::{TestNode, initiate_handshake, make_test_node};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use tokio::time::Instant;

mod bloom_deadline;
mod guards;
mod late_reply_loss;
mod lost_filter;
mod reachable_after_backoff;
mod rx_loop;
mod shared_ingress;
mod wire_tap;

#[test]
fn original_payload_crosses_uncontended_lookup() {
    run(false);
}

#[test]
fn original_payload_survives_competing_same_target_lookups() {
    run(true);
}

fn run(competing: bool) {
    run_large_stack_async_test("lookup-contention", move || async move {
        let _guard = lock_large_network_test().await;
        let mut nodes = Vec::new();
        for _ in 0..4 {
            nodes.push(make_test_node().await);
        }
        // Genuine root source 0 cannot derive the leaf's coordinates from its
        // ancestry. Both source 0 and noisy peer 3 need relay 1 to reach leaf 2.
        nodes.sort_by_key(|node| *node.node.node_addr());
        let result = AssertUnwindSafe(exercise(&mut nodes, competing))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

// Endpoints use real UDP and production handlers, with maintenance driven at
// actual wall-clock deadlines. The relay runs its own production RX loop.
async fn turn(nodes: &mut [TestNode]) {
    for test in nodes.iter_mut() {
        let now = Node::now_ms();
        test.node.poll_pending_connects().await;
        test.node.resend_pending_handshakes(now).await;
        test.node.send_due_tree_announces().await;
        test.node.send_pending_filter_announces().await;
        test.node.check_mmp_reports().await;
        test.node.resend_pending_session_handshakes(now).await;
        test.node.resend_pending_session_msg3(now).await;
        test.node.check_discovery_work(now).await;
    }
    process_available_packets(nodes).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
}

async fn setup(nodes: &mut [TestNode]) {
    for test in nodes.iter_mut() {
        test.node.config.node.rate_limit = Config::new().node.rate_limit;
        assert_eq!(
            test.node.config.node.discovery.attempt_timeouts_secs,
            [1, 2, 4, 8]
        );
        assert_eq!(test.node.config.node.discovery.forward_min_interval_secs, 2);
    }
    for (from, to) in [(1, 0), (2, 1), (3, 1)] {
        initiate_handshake(nodes, from, to).await;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let root = *nodes[0].node.node_addr();
    let target = *nodes[2].node.node_addr();
    loop {
        turn(nodes).await;
        let ready = nodes.iter().enumerate().all(|(index, test)| {
            let expected = if index == 1 { 3 } else { 1 };
            *test.node.tree_state().root() == root
                && test.node.peers.len() == expected
                && test
                    .node
                    .peers
                    .values()
                    .all(|peer| peer.is_healthy() && peer.can_send())
        });
        let advertised = [0, 3].iter().all(|index| {
            nodes[*index]
                .node
                .get_peer(nodes[1].node.node_addr())
                .is_some_and(|peer| peer.may_reach(&target))
        });
        if ready && advertised {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "native four-node tree and filters converge"
        );
    }
    assert!(
        !nodes[0]
            .node
            .coord_cache()
            .contains(&target, Node::now_ms())
    );
}

type PeerOwner = (
    NodeAddr,
    LinkId,
    Option<crate::utils::index::SessionIndex>,
    u64,
);

fn owners(nodes: &[TestNode]) -> Vec<Vec<PeerOwner>> {
    nodes
        .iter()
        .enumerate()
        .map(|(index, test)| {
            let mut peers = test
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
            assert_eq!(peers.len(), if index == 1 { 3 } else { 1 });
            assert_eq!(test.node.link_count(), peers.len());
            assert_eq!(test.node.connection_count(), 0);
            peers
        })
        .collect()
}

async fn send_noise(nodes: &mut [TestNode], relay: NodeAddr, request_id: u64) {
    let request = LookupRequest::new(
        request_id,
        *nodes[2].node.node_addr(),
        *nodes[3].node.node_addr(),
        nodes[3].node.tree_state().my_coords().clone(),
        nodes[3].node.config.node.discovery.ttl,
        0,
    );
    // An authenticated noisy peer submits fresh valid requests even after it
    // has a route. No normal-client cache behavior is assumed for that peer.
    nodes[3]
        .node
        .send_dataplane_fmp_link_plaintext(&relay, &request.encode(), false)
        .await
        .unwrap();
}

async fn exercise(nodes: &mut [TestNode], competing: bool) {
    setup(nodes).await;
    let before = owners(nodes);
    let relay = *nodes[1].node.node_addr();
    let actor = rx_loop::Transit::start(&mut nodes[1]).await;
    let result = AssertUnwindSafe(traffic(nodes, relay, competing))
        .catch_unwind()
        .await;
    actor.restore(&mut nodes[1]).await;
    assert_eq!(
        owners(nodes),
        before,
        "authenticated carrier ownership is preserved"
    );
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

async fn traffic(nodes: &mut [TestNode], relay: NodeAddr, competing: bool) {
    let target = *nodes[2].node.node_addr();
    let destination = PeerIdentity::from_pubkey_full(nodes[2].node.identity().pubkey_full());
    let _source_io = nodes[0].node.attach_endpoint_data_io(8).unwrap();
    let mut target_io = nodes[2].node.attach_endpoint_data_io(8).unwrap();
    let payload = b"one original endpoint submission";
    let start = Instant::now();
    let mut noise_id = 1;
    if competing {
        send_noise(nodes, relay, noise_id).await;
        let deadline = start + Duration::from_millis(250);
        while !nodes[2].node.recent_requests.contains_key(&noise_id) {
            turn(nodes).await;
            assert!(
                Instant::now() < deadline,
                "noise must first reach the real target"
            );
        }
    }
    while start.elapsed() < Duration::from_millis(350) {
        turn(nodes).await;
    }
    assert!(nodes[0].node.pending_lookups.get(&target).is_none());
    let requests_before = nodes[0].node.stats().discovery.req_initiated;
    send_endpoint_data_via_dataplane(&mut nodes[0].node, destination, payload.to_vec())
        .await
        .unwrap();
    let initial = nodes[0]
        .node
        .pending_lookups
        .get(&target)
        .expect("original endpoint ingress starts lookup")
        .clone();
    assert_eq!(initial.attempt, 1);
    assert_eq!(
        nodes[0].node.pending_lookup_deadline_ms(),
        Some(initial.last_sent_ms + 1000)
    );
    let mut attempts = vec![(initial.attempt, initial.last_sent_ms - initial.initiated_ms)];
    let mut next_noise = start + Duration::from_millis(2100);
    let deadline = Instant::now() + Duration::from_millis(15_500);
    let mut delivered = false;
    loop {
        if competing && Instant::now() >= next_noise {
            noise_id += 1;
            send_noise(nodes, relay, noise_id).await;
            next_noise += Duration::from_millis(2100);
        }
        turn(nodes).await;
        if let Some(entry) = nodes[0].node.pending_lookups.get(&target) {
            assert_eq!(entry.initiated_ms, initial.initiated_ms);
            if entry.attempt != attempts.last().unwrap().0 {
                attempts.push((entry.attempt, entry.last_sent_ms - entry.initiated_ms));
            }
        }
        if let Ok(event) = target_io.event_rx.try_recv() {
            assert_eq!(
                expect_single_endpoint_data_event(event).payload.as_slice(),
                payload
            );
            delivered = true;
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
    }
    let source = nodes[0].node.stats().discovery.req_initiated - requests_before;
    let target_received = nodes[2].node.stats().discovery.req_target_is_us;
    eprintln!(
        "lookup contention: competing={competing}, delivered={delivered}, elapsed_ms={}, noise_requests={noise_id}, source_requests={source}, attempts={attempts:?}, target_received={target_received}",
        start.elapsed().as_millis()
    );
    assert!(
        nodes
            .iter()
            .all(|test| test.node.recent_requests.len() <= 4096)
    );
    assert!(source <= 4, "unchanged bounded origin retry ladder");
    if competing {
        assert!(
            target_received > 0,
            "target remains reachable through the same relay"
        );
    }
    assert!(
        delivered,
        "one competing ingress must not exhaust discovery for an original payload on a working route"
    );
    assert!(
        nodes[0]
            .node
            .coord_cache()
            .contains(&target, Node::now_ms())
    );
    assert!(nodes[0].node.pending_lookups.get(&target).is_none());
}
