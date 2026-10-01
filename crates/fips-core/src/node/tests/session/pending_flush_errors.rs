//! Returned-error ownership through real UDP/Noise sessions and native ingress.
use super::*;
use crate::node::{
    EndpointDataPayload, ForwardingOutcome, NodeEndpointDataBatch, OriginatedSessionAdmission,
    OriginatedSessionIntent, OriginatedSessionObserver, OriginatedSessionRequest,
};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Copy)]
enum Case {
    PartialSubmission,
    DeferredOwnership,
}

#[test]
fn pending_endpoint_error_does_not_replay_partly_submitted_batch() {
    run(Case::PartialSubmission);
}

#[test]
fn prepared_endpoint_deferral_returns_one_owner_without_bypassing_queue_caps() {
    run(Case::DeferredOwnership);
}

fn run(case: Case) {
    run_large_stack_async_test("pending-flush-errors", move || async move {
        let _guard = lock_large_network_test().await;
        let mut nodes = run_tree_test(4, &[(0, 1), (0, 2), (1, 3), (2, 3)], false).await;
        let result = AssertUnwindSafe(exercise(&mut nodes, case))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

// A legitimate source admission decision: admit one application record, reject
// the next, then permit later demand. Protocol upkeep retains ordinary behavior.
#[derive(Debug)]
struct PartialAdmission {
    destination: NodeAddr,
    attempts: AtomicUsize,
    completions: Mutex<Vec<(u64, ForwardingOutcome)>>,
}

impl OriginatedSessionObserver for PartialAdmission {
    fn prepare(&self, intent: &OriginatedSessionIntent) -> OriginatedSessionAdmission {
        if intent.destination != self.destination || intent.session_bytes < 700 {
            return OriginatedSessionAdmission::Defer;
        }
        let attempt = self.attempts.fetch_add(1, Ordering::Relaxed);
        if attempt == 1 {
            OriginatedSessionAdmission::Reject
        } else {
            OriginatedSessionAdmission::Track(attempt as u64 + 1)
        }
    }

    fn observe(&self, _: &OriginatedSessionRequest<'_>) -> Option<u64> {
        None
    }

    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        self.completions.lock().unwrap().push((token, outcome));
    }
}

fn payloads(values: impl IntoIterator<Item = u8>) -> Vec<EndpointDataPayload> {
    values
        .into_iter()
        .map(|value| EndpointDataPayload::from_packet_payload(vec![value; 700]).unwrap())
        .collect()
}

// Observe original metadata without manufacturing queues, payloads, or ages.
fn queue_ages(node: &mut Node, destination: &NodeAddr) -> Vec<u64> {
    let Some(queue) = node.pending_session_traffic.take_endpoint_data(destination) else {
        return Vec::new();
    };
    let batches = queue.into_pending_payloads();
    let ages = batches.iter().map(|batch| batch.enqueued_at_ms()).collect();
    node.pending_session_traffic
        .restore_endpoint_data(*destination, batches);
    ages
}

fn queue_len(node: &Node, destination: &NodeAddr) -> usize {
    node.pending_session_traffic
        .endpoint_data_for(destination)
        .map_or(0, |queue| queue.len())
}

async fn exercise(nodes: &mut [TestNode], case: Case) {
    let peers = nodes
        .iter()
        .map(|node| PeerIdentity::from_pubkey_full(node.node.identity().pubkey_full()))
        .collect::<Vec<_>>();
    let source = *peers[0].node_addr();
    let destination = *peers[3].node_addr();
    for node in nodes.iter_mut() {
        // As in source_routes/queued_retry, isolate explicit carrier authority
        // from unrelated changes in which identity is the tree root.
        node.node.config.node.routing.mode = RoutingMode::ReplyLearned;
        assert_eq!(node.node.config.node.session.pending_packets_per_dest, 16);
    }
    let mut endpoint = nodes[3].node.attach_endpoint_data_io(32).unwrap();
    nodes[3]
        .node
        .set_endpoint_source_route(peers[0], Some(peers[1]))
        .unwrap();
    for (relay, value) in [(1, 201), (2, 202)] {
        nodes[0]
            .node
            .set_endpoint_source_route(peers[3], Some(peers[relay]))
            .unwrap();
        send_endpoint_data_via_dataplane(&mut nodes[0].node, peers[3], vec![value; 700])
            .await
            .unwrap();
        let event = recv_endpoint_event_while_draining(
            nodes,
            &mut endpoint.event_rx,
            Duration::from_secs(5),
            "warm source-bound session",
        )
        .await;
        endpoint.event_rx.release_messages(event.messages.len());
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            vec![value; 700]
        );
        drain_to_quiescence(nodes).await;
    }
    let session_hash = *nodes[0]
        .node
        .get_session(&destination)
        .unwrap()
        .handshake_hash()
        .unwrap();
    let prepared = nodes[0]
        .node
        .prepare_dataplane_cached_endpoint_send(&destination)
        .unwrap();
    let deferred_original =
        NodeEndpointDataBatch::from_payloads(peers[3], payloads([16, 17]), None).unwrap();
    let disconnect = crate::protocol::Disconnect::new(crate::protocol::DisconnectReason::Shutdown);
    nodes[2]
        .node
        .send_dataplane_fmp_link_plaintext(&source, &disconnect.encode(), false)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while nodes[0].node.get_peer(peers[2].node_addr()).is_some() {
            poll_available_packets(nodes).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("authenticated bound-carrier departure");
    drain_to_quiescence(nodes).await;
    assert_eq!(
        nodes[0].node.source_routes.get(&destination),
        Some(peers[2].node_addr())
    );
    assert!(!nodes[0].node.has_application_next_hop(&destination));
    assert!(nodes[0].node.dataplane_has_fsp_owner(&destination));

    let count = if matches!(case, Case::PartialSubmission) {
        2
    } else {
        16
    };
    let queued_from = Node::now_ms();
    let batch = NodeEndpointDataBatch::from_payloads(peers[3], payloads(0..count), None).unwrap();
    nodes[0]
        .node
        .handle_endpoint_data_batch_no_established_flush(batch)
        .await;
    let queued_until = Node::now_ms();
    let ages = queue_ages(&mut nodes[0].node, &destination);
    assert_eq!(ages.len(), 1);
    assert!((queued_from..=queued_until).contains(&ages[0]));
    assert_eq!(queue_len(&nodes[0].node, &destination), usize::from(count));

    // Preflight failure must not pop or age any queued original, even though an
    // alternative authenticated carrier is healthy and could physically send.
    assert!(
        nodes[0]
            .node
            .prepare_dataplane_cached_endpoint_send(&destination)
            .is_err()
    );
    for _ in 0..2 {
        nodes[0].node.flush_pending_packets(&destination).await;
    }
    assert_eq!(queue_len(&nodes[0].node, &destination), usize::from(count));
    assert_eq!(queue_ages(&mut nodes[0].node, &destination), ages);
    assert!(matches!(
        endpoint.event_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));

    let partial = Arc::new(PartialAdmission {
        destination,
        attempts: AtomicUsize::new(0),
        completions: Mutex::new(Vec::new()),
    });
    let expected = if matches!(case, Case::DeferredOwnership) {
        // Exercise the prepared helper across a REAL route removal. Ordinary
        // synchronous prepare->send has no such intervening control turn; this
        // is a helper ownership test, not a claim of a production race window.
        let (remote, originals, _, original_age) = deferred_original.into_parts();
        assert_eq!(remote, prepared);
        let failure = nodes[0]
            .node
            .send_dataplane_prepared_endpoint_payloads(prepared, originals)
            .await
            .expect_err("missing native endpoint route must defer the whole batch");
        assert!(matches!(failure.error, NodeError::SendFailed { .. }));
        assert_eq!(failure.unsent.len(), 2);
        for (payload, value) in failure.unsent.iter().zip([16, 17]) {
            assert_eq!(payload.clone().into_body().as_slice(), vec![value; 700]);
        }
        assert_eq!(
            queue_len(&nodes[0].node, &destination),
            16,
            "bookkeeping must not also requeue returned data"
        );
        assert_eq!(queue_ages(&mut nodes[0].node, &destination), ages);

        // The caller returns the actual owned data through bounded native
        // ingress, preserving its age. Existing overflow policy drops 0 and 1.
        let returned = NodeEndpointDataBatch::from_payloads_with_enqueued_at_ms(
            remote,
            failure.unsent,
            None,
            original_age,
        )
        .unwrap();
        nodes[0]
            .node
            .handle_endpoint_data_batch_no_established_flush(returned)
            .await;
        assert_eq!(queue_len(&nodes[0].node, &destination), 16);
        assert_eq!(
            queue_ages(&mut nodes[0].node, &destination),
            vec![ages[0], original_age]
        );
        (2..18).collect::<Vec<u8>>()
    } else {
        nodes[0]
            .node
            .set_originated_session_observer(Some(partial.clone()));
        vec![0]
    };

    nodes[0]
        .node
        .set_endpoint_source_route(peers[3], Some(peers[1]))
        .unwrap();
    nodes[0].node.flush_pending_packets(&destination).await;
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while received.len() < expected.len() {
            poll_available_packets(nodes).await;
            while let Ok(event) = endpoint.event_rx.try_recv() {
                endpoint.event_rx.release_messages(event.messages.len());
                for data in event.messages {
                    assert_eq!(data.source_peer.node_addr(), &source);
                    assert_eq!(data.payload.len(), 700);
                    let value = data.payload.as_slice()[0];
                    assert_eq!(data.payload.as_slice(), vec![value; 700]);
                    assert!(!received.contains(&value), "original payload was replayed");
                    received.push(value);
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("native receiver observes admitted originals");
    received.sort_unstable();
    assert_eq!(received, expected);
    assert_eq!(queue_len(&nodes[0].node, &destination), 0);
    for _ in 0..3 {
        nodes[0].node.retry_pending_session_traffic().await;
        drain_to_quiescence(nodes).await;
        assert!(
            matches!(
                endpoint.event_rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "no selected replay after returned error"
        );
    }
    if matches!(case, Case::PartialSubmission) {
        assert_eq!(partial.attempts.load(Ordering::Relaxed), 2);
        assert_eq!(
            *partial.completions.lock().unwrap(),
            vec![(1, ForwardingOutcome::Submitted)]
        );
    }
    assert_eq!(
        nodes[0]
            .node
            .get_session(&destination)
            .unwrap()
            .handshake_hash(),
        Some(&session_hash)
    );
}
