//! Expiry must run after discovery yields, before other slow maintenance.
use super::*;
use crate::node::{
    AuthenticatedSessionDatagram, ForwardingAdmission, ForwardingClass, ForwardingDecision,
    ForwardingOutcome, ForwardingPolicy, ForwardingRequest, NodeState,
};
use crate::protocol::SessionDatagram;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Allowance {
    network: SimNetwork,
    source: String,
    submitted: AtomicUsize,
    waiting: AtomicUsize,
    wire_before: u64,
}

impl std::fmt::Debug for Allowance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Allowance")
    }
}

impl ForwardingPolicy for Allowance {
    fn admit(&self, request: &ForwardingRequest<'_>) -> Option<u64> {
        self.decide(request).admission().map(|a| a.token)
    }

    fn decide(&self, request: &ForwardingRequest<'_>) -> ForwardingDecision {
        if request.session_payload[0] == 1 && self.waiting.load(Ordering::Relaxed) > 0 {
            assert!(
                self.network.stats().packets_sent > self.wire_before,
                "the lookup must reach its carrier before admission becomes due"
            );
            self.network.set_node_send_completion_delay(&self.source, 0);
            ForwardingDecision::Admit(ForwardingAdmission {
                token: 1,
                class: ForwardingClass::Normal,
            })
        } else {
            self.waiting.fetch_add(1, Ordering::Relaxed);
            ForwardingDecision::Retry
        }
    }

    fn complete(&self, _: u64, outcome: ForwardingOutcome) {
        assert_eq!(outcome, ForwardingOutcome::Submitted);
        self.submitted.fetch_add(1, Ordering::Relaxed);
        // Arm the existing carrier fault only after a real transit completion.
        // The subsequent lookup reaches the wire but its send cannot complete.
        self.network
            .set_node_send_completion_delay(&self.source, 60_000);
    }
}

pub(super) async fn exercise(nodes: &mut [TestNode], network: &SimNetwork) {
    let ids = setup(nodes, network).await;
    delivered(network).await;
    let ttl = nodes[0].node.config.node.discovery.ttl;
    assert_eq!(nodes[0].node.initiate_lookup(&ids[1], ttl).await, 1);
    delivered(network).await;
    // Leave the remote's original request unprocessed so its retry becomes due.
    let due = nodes[0].node.pending_lookup_deadline_ms().unwrap();
    while Node::now_ms() < due {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let policy = Arc::new(Allowance {
        network: network.clone(),
        source: nodes[0].addr.as_str().unwrap().to_owned(),
        submitted: AtomicUsize::new(0),
        waiting: AtomicUsize::new(0),
        wire_before: network.stats().packets_sent,
    });
    let ingress = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let node = &mut nodes[0];
    node.node.set_forwarding_policy(Some(policy.clone()));
    let forwarded = node.node.stats().forwarding.forwarded_packets;
    for value in [1, 2] {
        let packet = SessionDatagram::new(ids[1], ids[2], vec![value; 64]).encode();
        node.node
            .handle_session_datagram(AuthenticatedSessionDatagram::new(
                ingress,
                &packet[1..],
                false,
            ))
            .await;
    }
    assert_eq!(policy.waiting.load(Ordering::Relaxed), 2);
    assert!(
        node.node.admission_work_deadline_ms().unwrap() > Node::now_ms(),
        "fixture enters discovery before the ordinary first retry is due"
    );
    network.set_node_send_completion_delay(&policy.source, 60_000);
    node.node.config.node.control.enabled = false;
    node.node.state = NodeState::Running;
    let (_unused_tx, unused_rx) = packet_channel(1);
    node.node.packet_rx = Some(std::mem::replace(&mut node.packet_rx, unused_rx));
    {
        let rx = Box::pin(node.node.run_rx_loop());
        tokio::pin!(rx);
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = &mut rx => panic!("RX loop ended: {result:?}"),
                _ = async {
                    tokio::time::timeout(Duration::from_secs(1), async {
                        while policy.submitted.load(Ordering::Relaxed) == 0 {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    }).await.expect("stalled discovery must yield before the waiting packet expires");
                    tokio::time::sleep(Duration::from_millis(2_100)).await;
                } => {}
            }
        })
        .await
        .expect("transit and a real stalled lookup must reach their carrier");
    }
    network.set_node_send_completion_delay(&policy.source, 0);
    assert_eq!(policy.submitted.load(Ordering::Relaxed), 1);
    assert!(policy.waiting.load(Ordering::Relaxed) > 2);
    assert_eq!(node.node.pending_lookups.get(&ids[1]).unwrap().attempt, 2);
    assert_eq!(
        node.node.stats().forwarding.forwarded_packets,
        forwarded + 1
    );
    assert_eq!(
        node.node.stats().forwarding.drop_policy_denied_packets,
        1,
        "expired traffic must be released before another slow maintenance await"
    );
    assert_eq!(node.node.admission_work_deadline_ms(), None);
}
