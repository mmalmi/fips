use super::*;
use crate::node::tests::spanning_tree::{TestNode, poll_available_packets};
use tokio::time::{Instant, sleep_until, timeout_at};

async fn request_turn(nodes: &mut [TestNode], receiver: usize, request_id: u64) -> (usize, bool) {
    let active_turns = poll_available_packets(nodes).await;
    let matched = nodes[receiver]
        .node
        .recent_requests
        .contains_key(&request_id);
    (active_turns, matched)
}

pub(super) async fn wait_for_request(
    nodes: &mut [TestNode],
    receiver: usize,
    request_id: u64,
    deadline: Instant,
) -> usize {
    let mut active_turns = 0;
    loop {
        assert!(
            Instant::now() < deadline,
            "selected request deadline elapsed"
        );
        let (active, matched) = timeout_at(deadline, request_turn(nodes, receiver, request_id))
            .await
            .expect("selected request turn exceeded deadline");
        active_turns += active;
        if matched {
            assert!(
                Instant::now() < deadline,
                "selected request arrived too late"
            );
            return active_turns;
        }
        // Revisit every real node without spinning or waiting on another
        // node's advisory crypto notification. Never renew the caller's bound.
        sleep_until((Instant::now() + Duration::from_millis(1)).min(deadline)).await;
    }
}

#[test]
fn unrelated_activity_does_not_complete_a_withheld_lookup() {
    use crate::node::tests::session::run_large_stack_async_test;
    use crate::transport::{PacketBuffer, ReceivedPacket, packet_channel};
    use futures::FutureExt;
    use std::panic::AssertUnwindSafe;

    run_large_stack_async_test("forwarding-selected-request", || async {
        let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
        // Hold the actual UDP receiver: its original authenticated frames and
        // enqueue timestamps stay intact until the receiver is restored.
        let (unrelated_tx, gated_rx) = packet_channel(1);
        let mut real_rx = Some(std::mem::replace(&mut nodes[1].packet_rx, gated_rx));
        let result = AssertUnwindSafe(async {
            let origin = *nodes[0].node.node_addr();
            let target = *nodes[1].node.node_addr();
            let coords = TreeCoordinate::from_addrs(vec![origin, make_node_addr(0)]).unwrap();
            let request = LookupRequest::new(42, target, origin, coords, 5, 0);
            let deadline = Instant::now() + Duration::from_secs(1);
            timeout_at(
                deadline,
                nodes[0]
                    .node
                    .handle_lookup_request(&origin, &request.encode()[1..]),
            )
            .await
            .expect("single control lookup submission stays within original bound");
            unrelated_tx
                .send(ReceivedPacket::with_timestamp(
                    nodes[1].transport_id,
                    nodes[0].addr.clone(),
                    PacketBuffer::new(vec![0]),
                    Node::now_ms(),
                ))
                .expect("admit unrelated malformed packet");

            // This exact operation is used by the real fixture's wait loop.
            let (active, matched) = timeout_at(deadline, request_turn(&mut nodes, 1, 42))
                .await
                .expect("withheld receiver control turn stays within original bound");
            assert!(
                active > 0,
                "ordinary dataplane processed unrelated activity"
            );
            assert!(
                !matched,
                "unrelated activity must not complete the withheld selected request"
            );
            assert!(!nodes[1].node.recent_requests.contains_key(&42));

            nodes[1].packet_rx = real_rx.take().unwrap();
            wait_for_request(&mut nodes, 1, 42, deadline).await;
            assert!(nodes[1].node.recent_requests.contains_key(&42));
        })
        .catch_unwind()
        .await;
        if let Some(receiver) = real_rx {
            nodes[1].packet_rx = receiver;
        }
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}
