//! A full initiator must wait for the full responder's real admission proof.
use super::*;
use crate::dataplane::FmpWireHeader;
use crate::node::tests::session::{
    expect_single_endpoint_data_event, recv_endpoint_event_while_draining,
    run_large_stack_async_test, send_endpoint_data_via_dataplane,
};
use crate::node::tests::spanning_tree::process_dataplane_packet;
use crate::node::wire::Msg1Header;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

const IDLE_MS: u64 = 2_000;
const TIMEOUT_MS: u64 = 6_000;

#[derive(Debug, PartialEq, Eq)]
struct Owner {
    link: LinkId,
    index: Option<SessionIndex>,
    epoch: Option<[u8; 8]>,
    generation: u64,
    authenticated_at: u64,
}

impl Owner {
    fn capture(node: &TestNode, peer: &NodeAddr) -> Self {
        let owner = node.node.get_peer(peer).expect("original incumbent exists");
        Self {
            link: owner.link_id(),
            index: owner.our_index(),
            epoch: owner.remote_epoch(),
            generation: owner.session_generation(),
            authenticated_at: owner.authenticated_at(),
        }
    }
}

struct Pending {
    link: LinkId,
    index: SessionIndex,
    started: u64,
    activity: u64,
    attempt: u64,
    outbound: bool,
}

impl Pending {
    fn capture(node: &TestNode, peer: &NodeAddr) -> Self {
        let conn = node.node.peers.connection_values().next().unwrap();
        assert_eq!(conn.expected_identity().unwrap().node_addr(), peer);
        let attempt = node.node.neighbor_rotation_started_at(peer).unwrap();
        Self {
            link: conn.link_id(),
            index: conn.our_index().unwrap(),
            started: conn.started_at(),
            // Retaining outbound Msg2 restores the original rotation deadline,
            // which may precede connection creation by a scheduling tick.
            activity: if conn.is_outbound() {
                attempt
            } else {
                conn.last_activity()
            },
            attempt,
            outbound: conn.is_outbound(),
        }
    }

    fn assert_held(&self, node: &TestNode, peer: &NodeAddr, old: &NodeAddr, owner: &Owner) {
        assert_eq!(Owner::capture(node, old), *owner);
        assert!(node.node.get_peer(peer).is_none());
        assert_eq!(resources(node), (1, 1, 2, 2));
        let conn = node
            .node
            .get_connection(&self.link)
            .expect("original bounded candidate remains owned");
        assert_eq!(conn.expected_identity().unwrap().node_addr(), peer);
        assert_eq!(conn.is_outbound(), self.outbound);
        assert_eq!(conn.our_index(), Some(self.index));
        assert_eq!(conn.started_at(), self.started);
        assert_eq!(conn.last_activity(), self.activity);
        assert_eq!(
            node.node.neighbor_rotation_started_at(peer),
            Some(self.attempt)
        );
        assert!(node.node.index_allocator.is_allocated(self.index));
        assert!(node.node.links.get(&self.link).is_some());
        assert!(Node::now_ms().saturating_sub(self.activity) < TIMEOUT_MS);
    }
}

async fn dial(nodes: &mut [TestNode], source: usize, destination: usize) {
    let identity = PeerIdentity::from_pubkey_full(nodes[destination].node.identity.pubkey_full());
    let address = nodes[destination].addr.clone();
    let source = &mut nodes[source];
    source
        .node
        .initiate_connection(source.transport_id, address, identity)
        .await
        .unwrap();
}

async fn next_packet(node: &mut TestNode) -> ReceivedPacket {
    tokio::time::timeout(Duration::from_secs(1), node.packet_rx.recv())
        .await
        .expect("actual UDP handshake or confirmation must arrive")
        .unwrap()
}

async fn quiesce(nodes: &mut [TestNode]) {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut idle = 0;
        while idle < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if process_available_packets(nodes).await == 0 {
                idle += 1;
            } else {
                idle = 0;
            }
        }
    })
    .await
    .expect("native UDP setup must settle without synthetic tree repair");
}

async fn wait_until(at: u64) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while Node::now_ms() < at {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("configured age must pass in real time");
}

async fn maintenance(node: &mut TestNode) {
    node.node.check_timeouts().await;
    node.node.resend_pending_handshakes(Node::now_ms()).await;
}

fn authenticate_proof(node: &TestNode, pending: &Pending, packet: &ReceivedPacket) {
    let conn = node.node.get_connection(&pending.link).unwrap();
    assert_eq!(conn.transport_id(), Some(packet.transport_id));
    assert_eq!(conn.source_addr(), Some(&packet.remote_addr));
    let header = FmpWireHeader::parse_encrypted(packet.data.as_slice()).unwrap();
    assert_eq!(header.receiver_idx(), pending.index.as_u32());
    let offset = usize::from(header.ciphertext_offset());
    // Read-only authentication does not consume the replay counter; the real
    // production receive path below owns confirmation, promotion and delivery.
    assert!(
        conn.session()
            .unwrap()
            .authenticate_with_counter_and_aad(
                &packet.data.as_slice()[offset..],
                header.counter(),
                &packet.data.as_slice()[..offset],
            )
            .is_ok()
    );
}

#[test]
fn staggered_full_rosters_wait_for_both_admission_and_fresh_peer_readiness() {
    run_large_stack_async_test("rotation-staggered-readiness", || async {
        let mut nodes = [
            make_test_node().await,
            make_test_node().await,
            make_test_node().await,
            make_test_node().await,
        ];
        let result = AssertUnwindSafe(exercise(&mut nodes)).catch_unwind().await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise(nodes: &mut [TestNode; 4]) {
    for (i, node) in nodes.iter_mut().enumerate() {
        node.node.config.node.rekey.enabled = false;
        node.node.config.node.session.idle_timeout_secs = 0;
        node.node.config.node.rate_limit = crate::config::Config::new().node.rate_limit;
        node.node.config.node.rate_limit.handshake_timeout_secs = TIMEOUT_MS / 1000;
        if i < 2 {
            node.node.max_peers = 1;
            node.node.max_connections = 1;
            node.node.max_links = 2;
            node.node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
                idle_secs: IDLE_MS / 1000,
                interval_secs: 1,
            });
        }
    }
    let ids: Vec<_> = nodes.iter().map(|node| *node.node.node_addr()).collect();
    dial(nodes, 0, 2).await;
    quiesce(nodes).await;
    let a_owner = Owner::capture(&nodes[0], &ids[2]);
    wait_until(a_owner.authenticated_at + 1_000).await;
    dial(nodes, 1, 3).await;
    quiesce(nodes).await;
    let b_owner = Owner::capture(&nodes[1], &ids[3]);
    assert!(b_owner.authenticated_at >= a_owner.authenticated_at + 1_000);
    assert_eq!(resources(&nodes[0]), (1, 0, 1, 1));
    assert_eq!(resources(&nodes[1]), (1, 0, 1, 1));
    wait_until(a_owner.authenticated_at + IDLE_MS + 50).await;
    assert!(
        nodes[0]
            .node
            .has_neighbor_rotation_opportunity(Node::now_ms())
    );
    assert!(Node::now_ms() - b_owner.authenticated_at < IDLE_MS);

    dial(nodes, 0, 1).await;
    let a_pending = Pending::capture(&nodes[0], &ids[1]);
    let request = next_packet(&mut nodes[1]).await;
    assert_eq!(request.remote_addr, nodes[0].addr);
    assert_eq!(
        Msg1Header::parse(request.data.as_slice())
            .unwrap()
            .sender_idx,
        a_pending.index
    );
    nodes[1].node.handle_msg1(request).await;
    let b_pending = Pending::capture(&nodes[1], &ids[0]);
    assert!(!b_pending.outbound);
    b_pending.assert_held(&nodes[1], &ids[0], &ids[3], &b_owner);

    // Msg2 acknowledges a bounded reservation before B's minimum peer age.
    // It does not authorize A to discard its incumbent or expose an app route.
    let response = next_packet(&mut nodes[0]).await;
    let response_header = Msg2Header::parse(response.data.as_slice()).unwrap();
    assert_eq!(response_header.sender_idx, b_pending.index);
    assert_eq!(response_header.receiver_idx, a_pending.index);
    assert!(Node::now_ms() - b_owner.authenticated_at < IDLE_MS);
    let before_ready = nodes[0]
        .node
        .get_connection(&a_pending.link)
        .unwrap()
        .link_stats()
        .clone();
    nodes[0].node.handle_msg2(response).await;
    a_pending.assert_held(&nodes[0], &ids[1], &ids[2], &a_owner);
    let a_conn = nodes[0].node.get_connection(&a_pending.link).unwrap();
    assert!(a_conn.is_complete() && a_conn.has_session());
    assert_eq!(a_conn.remote_epoch(), Some(nodes[1].node.startup_epoch));
    assert!(!nodes[0].node.dataplane_has_fmp_owner(&ids[1]));

    // A's real encrypted readiness reaches B while B still cannot replace its
    // incumbent. Queues are paused only to assert this exact protocol phase.
    let a_proof = next_packet(&mut nodes[1]).await;
    let ready_observed = Instant::now();
    let ready_counter = FmpWireHeader::parse_encrypted(a_proof.data.as_slice())
        .unwrap()
        .counter();
    let ready_bytes = a_proof.data.len() as u64;
    let a_conn = nodes[0].node.get_connection(&a_pending.link).unwrap();
    assert_eq!(
        a_conn.session().unwrap().current_send_counter(),
        ready_counter + 1
    );
    assert_eq!(
        a_conn.link_stats().packets_sent,
        before_ready.packets_sent + 1
    );
    assert_eq!(
        a_conn.link_stats().bytes_sent,
        before_ready.bytes_sent + ready_bytes
    );
    authenticate_proof(&nodes[1], &b_pending, &a_proof);
    assert!(Node::now_ms() - b_owner.authenticated_at < IDLE_MS);
    process_dataplane_packet(&mut nodes[1], a_proof).await;
    maintenance(&mut nodes[1]).await;
    b_pending.assert_held(&nodes[1], &ids[0], &ids[3], &b_owner);
    assert!(
        nodes[1]
            .node
            .get_connection(&b_pending.link)
            .unwrap()
            .handshake_confirmation()
            .is_some()
    );
    maintenance(&mut nodes[0]).await;
    a_pending.assert_held(&nodes[0], &ids[1], &ids[2], &a_owner);

    wait_until(b_owner.authenticated_at + IDLE_MS + 50).await;
    b_pending.assert_held(&nodes[1], &ids[0], &ids[3], &b_owner);
    maintenance(&mut nodes[1]).await;
    let b_active = nodes[1]
        .node
        .get_peer(&ids[0])
        .expect("B's retained proof promotes at real maturity");
    assert_eq!(b_active.link_id(), b_pending.link);
    assert_eq!(b_active.our_index(), Some(b_pending.index));
    assert!(b_active.authenticated_at() >= b_owner.authenticated_at + IDLE_MS);
    assert_eq!(resources(&nodes[1]), (1, 0, 1, 1));
    assert!(
        !nodes[1]
            .node
            .index_allocator
            .is_allocated(b_owner.index.unwrap())
    );

    // A is mature too, but maintenance alone cannot replace its incumbent:
    // B's actual newly encrypted proof has not been delivered to A yet.
    maintenance(&mut nodes[0]).await;
    a_pending.assert_held(&nodes[0], &ids[1], &ids[2], &a_owner);
    let b_proof = next_packet(&mut nodes[0]).await;
    authenticate_proof(&nodes[0], &a_pending, &b_proof);
    assert!(b_proof.timestamp_ms >= b_owner.authenticated_at + IDLE_MS);
    let a_conn = nodes[0].node.get_connection(&a_pending.link).unwrap();
    // Normal retry turns may have retransmitted readiness, but cannot consume
    // another Noise nonce or count the same wire packet twice in MMP.
    assert_eq!(
        a_conn.session().unwrap().current_send_counter(),
        ready_counter + 1
    );
    let ready_writes = a_conn.link_stats().packets_sent - before_ready.packets_sent;
    assert!(ready_writes >= 1);
    assert_eq!(
        a_conn.link_stats().bytes_sent - before_ready.bytes_sent,
        ready_writes * ready_bytes
    );
    let promotion_started = Instant::now();
    process_dataplane_packet(&mut nodes[0], b_proof).await;
    quiesce(nodes).await;

    let a = nodes[0]
        .node
        .get_peer(&ids[1])
        .expect("A needs genuine peer readiness");
    let b = nodes[1].node.get_peer(&ids[0]).unwrap();
    assert_eq!(a.link_id(), a_pending.link);
    assert_eq!(b.link_id(), b_pending.link);
    assert_eq!(a.our_index(), b.their_index());
    assert_eq!(a.their_index(), b.our_index());
    assert!(a.session_start() >= promotion_started);
    assert!(a.session_start() > ready_observed);
    // The active liveness clock starts at promotion, while its wire clock must
    // retain time spent waiting after the real pending heartbeat was sent.
    let elapsed_since_ready_ms = ready_observed.elapsed().as_millis() as u64;
    assert!(u64::from(a.session_elapsed_ms()) >= elapsed_since_ready_ms.saturating_sub(2));
    let metrics = nodes[0]
        .node
        .dataplane_fmp_link_metrics(&ids[1], Instant::now())
        .unwrap();
    let unique_frames = a.noise_session().unwrap().current_send_counter() - ready_counter;
    assert_eq!(
        metrics.tx_packets, unique_frames,
        "pending readiness must join the winning sender's unique MMP accounting"
    );
    assert_eq!(
        a.link_stats().packets_sent - before_ready.packets_sent,
        unique_frames + ready_writes - 1,
        "physical retries remain link writes, not extra unique MMP packets"
    );
    for i in 0..2 {
        assert_eq!(resources(&nodes[i]), (1, 0, 1, 1));
        assert!(nodes[i].node.pending_outbound.is_empty());
        assert!(nodes[i].node.get_peer(&ids[i + 2]).is_none());
        assert!(
            nodes[i]
                .node
                .dataplane_fmp_link_metrics(&ids[1 - i], Instant::now())
                .unwrap()
                .current_epoch_authenticated
        );
    }
    assert!(
        !nodes[0]
            .node
            .index_allocator
            .is_allocated(a_owner.index.unwrap())
    );

    let mut endpoints = [
        nodes[0].node.attach_endpoint_data_io(8).unwrap(),
        nodes[1].node.attach_endpoint_data_io(8).unwrap(),
    ];
    for (source, destination) in [(0, 1), (1, 0)] {
        let identity =
            PeerIdentity::from_pubkey_full(nodes[destination].node.identity.pubkey_full());
        let payload = vec![41 + source as u8; 64];
        send_endpoint_data_via_dataplane(&mut nodes[source].node, identity, payload.clone())
            .await
            .unwrap();
        let event = recv_endpoint_event_while_draining(
            nodes,
            &mut endpoints[destination].event_rx,
            Duration::from_secs(3),
            "staggered full-roster exact-once payload",
        )
        .await;
        endpoints[destination]
            .event_rx
            .release_messages(event.messages.len());
        let delivered = expect_single_endpoint_data_event(event);
        assert_eq!(delivered.payload.as_slice(), payload);
    }
    for _ in 0..3 {
        for node in nodes.iter_mut().take(2) {
            maintenance(node).await;
        }
        quiesce(nodes).await;
    }
    for endpoint in &mut endpoints {
        assert!(
            matches!(
                endpoint.event_rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "one submitted endpoint payload must not duplicate"
        );
    }
}
