//! Staggered admission while real local application traffic protects both carriers.
use super::*;
use crate::node::EndpointDataIo;
use std::collections::BTreeSet;

const AGE_MS: u64 = 10_000;
const STREAMS: [(usize, usize); 6] = [(0, 2), (2, 0), (1, 3), (3, 1), (0, 1), (1, 0)];

struct Traffic {
    io: Vec<EndpointDataIo>,
    ids: Vec<PeerIdentity>,
    sent: [u32; 6],
    received: [BTreeSet<u32>; 6],
    last_delivery: [Option<u64>; 6],
    max_gap_ms: [u64; 6],
    next_offer: u64,
    next_tick: [u64; 2],
}

impl Traffic {
    fn new(nodes: &mut [TestNode]) -> Self {
        Self {
            io: nodes
                .iter_mut()
                .take(4)
                .map(|node| node.node.attach_endpoint_data_io(128).unwrap())
                .collect(),
            ids: nodes
                .iter()
                .map(|node| PeerIdentity::from_pubkey_full(node.node.identity.pubkey_full()))
                .collect(),
            sent: [0; 6],
            received: std::array::from_fn(|_| BTreeSet::new()),
            last_delivery: [None; 6],
            max_gap_ms: [0; 6],
            next_offer: 0,
            next_tick: [Node::now_ms(), Node::now_ms() + 500],
        }
    }

    async fn offer(&mut self, nodes: &mut [TestNode], stream: usize) {
        let (source, destination) = STREAMS[stream];
        let sequence = self.sent[stream];
        assert!(sequence < 512, "bounded original application offers");
        let mut payload = vec![0x91; 64];
        payload[0] = stream as u8;
        payload[1..5].copy_from_slice(&sequence.to_le_bytes());
        send_endpoint_data_via_dataplane(&mut nodes[source].node, self.ids[destination], payload)
            .await
            .unwrap();
        self.sent[stream] += 1;
    }

    async fn turn(&mut self, nodes: &mut [TestNode]) {
        let now = Node::now_ms();
        if now >= self.next_offer {
            self.next_offer = now + 100;
            for stream in 0..4 {
                self.offer(nodes, stream).await;
            }
        }
        for cohort in 0..2 {
            if now < self.next_tick[cohort] {
                continue;
            }
            self.next_tick[cohort] = now + 1_000;
            // The two components have offset ordinary maintenance ticks. No
            // extra proof retry is scheduled specifically at peer maturity.
            for node in nodes.iter_mut().skip(cohort).step_by(2) {
                maintenance(node).await;
                node.node.check_link_heartbeats().await;
                node.node.resend_pending_session_handshakes(now).await;
                node.node.resend_pending_session_msg3(now).await;
                node.node.retry_pending_session_traffic().await;
                node.node.check_mmp_reports().await;
                node.node.check_session_mmp_reports().await;
                node.node.check_pending_lookups(now).await;
                node.node.check_tree_state().await;
                node.node.send_pending_tree_announces().await;
                node.node.check_bloom_state().await;
            }
        }
        // A timed population must not wait up to a second for one node's
        // crypto notification while every other node and deadline is stopped.
        for test in nodes.iter_mut() {
            for _ in 0..256 {
                let Ok(packet) = test.packet_rx.try_recv() else {
                    break;
                };
                crate::node::tests::spanning_tree::process_dataplane_packet_once(
                    &mut test.node,
                    packet,
                )
                .await;
            }
            crate::node::tests::spanning_tree::process_dataplane_completions(&mut test.node).await;
        }
        for (destination, io) in self.io.iter_mut().enumerate() {
            while let Ok(event) = io.event_rx.try_recv() {
                io.event_rx.release_messages(event.messages.len());
                for message in event.messages {
                    let bytes = message.payload.as_slice();
                    assert_eq!(bytes.len(), 64);
                    assert!(bytes[5..].iter().all(|byte| *byte == 0x91));
                    let stream = usize::from(bytes[0]);
                    let (source, target) = STREAMS[stream];
                    assert_eq!(target, destination);
                    assert_eq!(message.source_peer, self.ids[source]);
                    let sequence = u32::from_le_bytes(bytes[1..5].try_into().unwrap());
                    assert!(sequence < self.sent[stream]);
                    assert!(self.received[stream].insert(sequence), "duplicate original");
                    let now = Node::now_ms();
                    if let Some(previous) = self.last_delivery[stream].replace(now) {
                        self.max_gap_ms[stream] = self.max_gap_ms[stream].max(now - previous);
                    }
                }
            }
        }
        for node in nodes.iter().take(2) {
            let (peers, connections, links, indices) = resources(node);
            assert!(peers <= 2 && connections <= 2 && links <= 4 && indices <= 4);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    async fn until(&mut self, nodes: &mut [TestNode], deadline: u64) {
        while Node::now_ms() < deadline {
            self.turn(nodes).await;
        }
    }

    fn assert_protected(&self, nodes: &[TestNode], owners: &[Owner; 2]) {
        let now = Node::now_ms();
        for boundary in 0..2 {
            let useful = self.ids[boundary + 2].node_addr();
            assert_eq!(Owner::capture(&nodes[boundary], useful), owners[boundary]);
            assert!(
                nodes[boundary]
                    .node
                    .peer_has_application_demand(useful, now, AGE_MS)
            );
            assert!(
                nodes[boundary]
                    .node
                    .peer_has_recent_local_application_data(useful, now, AGE_MS)
            );
            assert!(
                nodes[boundary]
                    .node
                    .dataplane
                    .min_fsp_data_rx_age_for_next_hop(useful, now)
                    .is_some_and(|age| age < 1_000)
            );
        }
    }
}

fn candidates(node: &TestNode, remote: PeerIdentity) -> Vec<LinkId> {
    let candidates: Vec<_> = node
        .node
        .peers
        .connection_values()
        .filter(|conn| conn.expected_identity() == Some(&remote))
        .collect();
    assert_eq!(
        candidates.len(),
        2,
        "both crossed handshake owners must remain"
    );
    assert_eq!(
        candidates.iter().filter(|conn| conn.is_outbound()).count(),
        1
    );
    candidates
        .into_iter()
        .map(|conn| {
            assert!(conn.is_complete() && conn.has_session());
            assert!(conn.our_index().is_some() && conn.their_index().is_some());
            conn.link_id()
        })
        .collect()
}

fn reciprocal(nodes: &[TestNode], ids: &[PeerIdentity]) -> bool {
    let (Some(a), Some(b)) = (
        nodes[0].node.get_peer(ids[1].node_addr()),
        nodes[1].node.get_peer(ids[0].node_addr()),
    ) else {
        return false;
    };
    a.our_index() == b.their_index() && a.their_index() == b.our_index()
}

#[test]
fn crossed_ready_candidates_admit_after_maturity_while_local_data_continues() {
    run_large_stack_async_test("rotation-loaded-readiness", || async {
        let mut nodes = Vec::new();
        for _ in 0..6 {
            nodes.push(make_test_node().await);
        }
        let result = AssertUnwindSafe(tokio::time::timeout(
            Duration::from_secs(40),
            exercise(&mut nodes),
        ))
        .catch_unwind()
        .await;
        cleanup_nodes(&mut nodes).await;
        match result {
            Ok(result) => result.expect("loaded native readiness fixture deadline"),
            Err(panic) => std::panic::resume_unwind(panic),
        }
    });
}

async fn exercise(nodes: &mut [TestNode]) {
    for (i, node) in nodes.iter_mut().enumerate() {
        node.node.config.node.rekey.enabled = false;
        node.node.config.node.session.idle_timeout_secs = 0;
        node.node.config.node.rate_limit = crate::config::Config::new().node.rate_limit;
        assert_eq!(node.node.config.node.rate_limit.handshake_timeout_secs, 30);
        assert!(node.node.config.peers.is_empty());
        if i < 2 {
            node.node.max_peers = 2;
            node.node.max_connections = 2;
            node.node.max_links = 4;
            node.node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
                idle_secs: AGE_MS / 1_000,
                interval_secs: 2,
            });
        }
    }
    dial(nodes, 0, 2).await;
    dial(nodes, 1, 3).await;
    quiesce(nodes).await;
    let mut traffic = Traffic::new(nodes);
    let ids = traffic.ids.clone();
    let protected = [
        Owner::capture(&nodes[0], ids[2].node_addr()),
        Owner::capture(&nodes[1], ids[3].node_addr()),
    ];
    dial(nodes, 0, 4).await;
    quiesce(nodes).await;
    let a = Owner::capture(&nodes[0], ids[4].node_addr());
    traffic.until(nodes, a.authenticated_at + 6_000).await;
    dial(nodes, 1, 5).await;
    quiesce(nodes).await;
    let b = Owner::capture(&nodes[1], ids[5].node_addr());
    traffic.until(nodes, a.authenticated_at + AGE_MS + 50).await;
    traffic.assert_protected(nodes, &protected);
    assert!(Node::now_ms() < b.authenticated_at + AGE_MS);
    for boundary in 0..2 {
        let now = Node::now_ms();
        let elective = *ids[boundary + 4].node_addr();
        assert!(now - protected[boundary].authenticated_at >= AGE_MS);
        assert!(
            !nodes[boundary]
                .node
                .peer_has_application_demand(&elective, now, AGE_MS)
        );
        assert_eq!(
            nodes[boundary].node.discovery_rotation_victim(now),
            Some(elective)
        );
        assert_eq!(
            nodes[boundary].node.has_neighbor_rotation_opportunity(now),
            boundary == 0
        );
    }

    // Both real dials precede packet processing. A is eligible now; B's idle
    // incumbent still needs its original minimum age. No repair dial follows.
    dial(nodes, 0, 1).await;
    dial(nodes, 1, 0).await;
    traffic.until(nodes, Node::now_ms() + 500).await;
    let original = [candidates(&nodes[0], ids[1]), candidates(&nodes[1], ids[0])];
    assert!(original.iter().all(|links| !links.is_empty()));
    assert!(nodes.iter().take(2).all(|node| node.node.peer_count() == 2));
    assert!(!reciprocal(nodes, &ids));
    assert_eq!(Owner::capture(&nodes[0], ids[4].node_addr()), a);
    assert_eq!(Owner::capture(&nodes[1], ids[5].node_addr()), b);
    assert!(
        nodes[1]
            .node
            .peers
            .connection_values()
            .any(|conn| conn.expected_identity() == Some(&ids[0])
                && conn.handshake_confirmation().is_some()),
        "genuine peer readiness must be retained while B is immature"
    );
    let attempts = [
        nodes[0]
            .node
            .neighbor_rotation_started_at(ids[1].node_addr())
            .unwrap(),
        nodes[1]
            .node
            .neighbor_rotation_started_at(ids[0].node_addr())
            .unwrap(),
    ];
    let deadlines = std::array::from_fn::<_, 2, _>(|boundary| {
        nodes[boundary]
            .node
            .neighbor_rotation_deadline(ids[1 - boundary].node_addr())
            .unwrap()
    });
    let ready_at = b.authenticated_at + AGE_MS;
    while !reciprocal(nodes, &ids) && Node::now_ms() < ready_at + 2_500 {
        traffic.turn(nodes).await;
        traffic.assert_protected(nodes, &protected);
        if Node::now_ms() < ready_at {
            assert_eq!(Owner::capture(&nodes[1], ids[5].node_addr()), b);
            assert!(
                !nodes[1]
                    .node
                    .has_neighbor_rotation_opportunity(Node::now_ms())
            );
        }
        for boundary in 0..2 {
            if nodes[boundary]
                .node
                .get_peer(ids[1 - boundary].node_addr())
                .is_none()
            {
                assert_eq!(
                    nodes[boundary]
                        .node
                        .neighbor_rotation_started_at(ids[1 - boundary].node_addr()),
                    Some(attempts[boundary])
                );
                assert_eq!(
                    nodes[boundary]
                        .node
                        .neighbor_rotation_deadline(ids[1 - boundary].node_addr()),
                    Some(deadlines[boundary])
                );
            }
        }
    }
    assert!(
        reciprocal(nodes, &ids),
        "retained crossed candidates must admit through ordinary maintenance while local traffic continues"
    );
    for boundary in 0..2 {
        let peer = nodes[boundary]
            .node
            .get_peer(ids[1 - boundary].node_addr())
            .unwrap();
        assert!(original[boundary].contains(&peer.link_id()));
        assert!(peer.authenticated_at() >= ready_at);
        assert!(
            nodes[boundary]
                .node
                .get_peer(ids[boundary + 4].node_addr())
                .is_none()
        );
    }
    let admitted_at = Node::now_ms();
    traffic.offer(nodes, 4).await;
    traffic.offer(nodes, 5).await;
    traffic.until(nodes, admitted_at + 1_000).await;
    traffic.assert_protected(nodes, &protected);
    assert_eq!(traffic.received[4].len(), 1);
    assert_eq!(traffic.received[5].len(), 1);
    // A newly installed owner can precede its first received frame. The fresh
    // bidirectional exchange above must authenticate both active replay windows.
    for boundary in 0..2 {
        assert!(
            nodes[boundary]
                .node
                .dataplane_fmp_link_metrics(ids[1 - boundary].node_addr(), Instant::now())
                .unwrap()
                .current_epoch_authenticated
        );
    }
    // Acceptance above keeps all four local streams running. Only now stop
    // offering, then drain ordinary processing to check every original once.
    traffic.next_offer = u64::MAX;
    let drained_by = Node::now_ms() + 1_000;
    while traffic
        .received
        .iter()
        .zip(traffic.sent)
        .any(|(received, sent)| received.len() != sent as usize)
    {
        assert!(
            Node::now_ms() < drained_by,
            "every offered original must arrive"
        );
        traffic.turn(nodes).await;
    }
    for stream in 0..4 {
        assert!(traffic.received[stream].len() >= 100);
        assert!(
            traffic.max_gap_ms[stream] < 1_000,
            "useful local stream stalled"
        );
    }
    eprintln!(
        "loaded readiness: admission_after_maturity_ms={}, local_received={:?}, max_gap_ms={:?}",
        admitted_at - ready_at,
        traffic.received[..4]
            .iter()
            .map(BTreeSet::len)
            .collect::<Vec<_>>(),
        &traffic.max_gap_ms[..4]
    );
}
