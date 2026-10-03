//! A policy publication must wake the production RX loop before timer fallback.
use super::*;
use crate::node::{ForwardingDecision, NodeState};
use futures::poll;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Notify;

#[derive(Debug, Default)]
struct PublishedAllowance {
    audit: Allowance,
    ready: AtomicBool,
    waiting: AtomicUsize,
    changed: Arc<Notify>,
}

impl ForwardingPolicy for PublishedAllowance {
    fn admit(&self, request: &ForwardingRequest<'_>) -> Option<u64> {
        self.decide(request).admission().map(|a| a.token)
    }

    fn decide(&self, request: &ForwardingRequest<'_>) -> ForwardingDecision {
        if self.ready.load(Ordering::Acquire) {
            self.audit.decide(request)
        } else {
            self.waiting.fetch_add(1, Ordering::Relaxed);
            ForwardingDecision::Retry
        }
    }

    fn admission_notify(&self) -> Option<Arc<Notify>> {
        Some(self.changed.clone())
    }

    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        self.audit.complete(token, outcome);
    }
}

#[test]
fn published_allowance_readmits_authenticated_packet_before_timer() {
    run_large_stack_async_test("fips-admission-publication", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
        verify_tree_convergence(&nodes);
        populate_all_coord_caches(&mut nodes);
        drain_to_quiescence(&mut nodes).await;
        let source = *nodes[0].node.node_addr();
        let destination = *nodes[2].node.node_addr();
        let ingress = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
        let policy = Arc::new(PublishedAllowance::default());
        policy.audit.0.lock().unwrap().allowance = 1_000_000;
        nodes[1].node.set_forwarding_policy(Some(policy.clone()));

        // Transit authenticates the link, not the opaque end-to-end ciphertext.
        let mut payload = vec![0; 64];
        payload[2..4].copy_from_slice(&36u16.to_le_bytes());
        nodes[0]
            .node
            .send_session_datagram(&mut SessionDatagram::new(source, destination, payload))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while policy.waiting.load(Ordering::Relaxed) == 0 {
                process_available_packets(&mut nodes).await;
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the authenticated packet must reach admission");

        let node = &mut nodes[1];
        assert_eq!(node.node.stats().forwarding.deferred_policy_packets, 1);
        assert_eq!(policy.audit.0.lock().unwrap().next_token, 0);
        let remaining = node.node.admission_work_delay().unwrap();
        assert!(
            remaining > Duration::from_millis(1),
            "fixture must precede fallback"
        );
        node.node.config.node.control.enabled = false;
        node.node.state = NodeState::Running;
        let (_unused_tx, unused_rx) = packet_channel(1);
        node.node.packet_rx = Some(std::mem::replace(&mut node.packet_rx, unused_rx));
        {
            tokio::time::pause();
            let start = tokio::time::Instant::now();
            let mut rx = Box::pin(node.node.run_rx_loop());
            assert!(poll!(&mut rx).is_pending());
            tokio::time::advance(Duration::from_millis(10).min(remaining / 2)).await;
            policy.ready.store(true, Ordering::Release);
            policy.changed.notify_one();
            assert!(poll!(&mut rx).is_pending());
            assert_eq!(
                policy.audit.0.lock().unwrap().next_token,
                1,
                "published allowance must be rechecked before the fallback timer"
            );
            assert!(start.elapsed() < remaining);
            tokio::time::resume();
            tokio::select! {
                result = &mut rx => panic!("RX loop ended: {result:?}"),
                completed = tokio::time::timeout(Duration::from_secs(2), async {
                    while policy.audit.0.lock().unwrap().completed.is_empty() {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }) => completed.expect("readmitted packet must reach its transport"),
            }
        }
        let audit = policy.audit.0.lock().unwrap();
        assert!(audit.pending.is_empty());
        assert_eq!(audit.completed.len(), 1);
        let (record, outcome) = &audit.completed[0];
        assert_eq!(*outcome, ForwardingOutcome::Submitted);
        assert_eq!(record.ingress, *ingress.node_addr());
        assert_eq!(record.destination, destination);
        drop(audit);
        assert_eq!(node.node.admission_work_delay(), None);
        assert_eq!(node.node.stats().forwarding.drop_policy_denied_packets, 0);
        cleanup_nodes(&mut nodes).await;
    });
}
