use super::*;
use crate::dataplane::FmpWireHeader;
use crate::node::tests::session::{
    expect_single_endpoint_data_event, recv_endpoint_event_while_draining,
    run_large_stack_async_test, send_endpoint_data_via_dataplane,
};
use crate::node::tests::spanning_tree::process_dataplane_packet;
use crate::node::wire::Msg1Header;

async fn dial(nodes: &mut [TestNode], source: usize, destination: usize) {
    let identity = PeerIdentity::from_pubkey_full(nodes[destination].node.identity.pubkey_full());
    let address = nodes[destination].addr.clone();
    let node = &mut nodes[source];
    node.node
        .initiate_connection(node.transport_id, address, identity)
        .await
        .unwrap();
}

async fn next_packet(node: &mut TestNode) -> ReceivedPacket {
    tokio::time::timeout(Duration::from_secs(1), node.packet_rx.recv())
        .await
        .expect("real UDP packet must arrive")
        .unwrap()
}

async fn quiesce(nodes: &mut [TestNode]) {
    tokio::time::timeout(Duration::from_secs(1), async {
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
    .expect("owned native UDP traffic must settle");
}

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
        let owner = node.node.get_peer(peer).expect("useful incumbent survives");
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
}

impl Pending {
    fn assert_retained(&self, node: &TestNode, newcomer: &NodeAddr) {
        let conn = node
            .node
            .get_connection(&self.link)
            .expect("fresh proof must retain the candidate when new demand prevents promotion");
        assert!(conn.is_inbound() && conn.is_complete() && conn.has_session());
        assert_eq!(conn.our_index(), Some(self.index));
        assert_eq!(conn.started_at(), self.started);
        assert_eq!(conn.last_activity(), self.activity);
        assert_eq!(
            node.node.neighbor_rotation_started_at(newcomer),
            Some(self.attempt)
        );
        assert!(node.node.index_allocator.is_allocated(self.index));
        assert!(node.node.links.get(&self.link).is_some());
        assert!(node.node.get_peer(newcomer).is_none());
        assert_eq!(resources(node), (1, 1, 2, 2));
    }
}

async fn deliver_to_incumbent(
    nodes: &mut [TestNode],
    rx: &mut crate::node::EndpointEventReceiver,
    sequence: u8,
) {
    let old = PeerIdentity::from_pubkey_full(nodes[2].node.identity.pubkey_full());
    let payload = vec![sequence; 64];
    send_endpoint_data_via_dataplane(&mut nodes[0].node, old, payload.clone())
        .await
        .unwrap();
    let event = recv_endpoint_event_while_draining(
        nodes,
        rx,
        Duration::from_secs(2),
        "actual incumbent application demand",
    )
    .await;
    rx.release_messages(event.messages.len());
    assert_eq!(
        expect_single_endpoint_data_event(event).payload.as_slice(),
        payload
    );
    assert!(
        nodes[0]
            .node
            .peer_has_application_demand(old.node_addr(), Node::now_ms(), 1_000)
    );
}

struct ProofFixture {
    nodes: [TestNode; 3],
    local: NodeAddr,
    old: NodeAddr,
    newcomer: NodeAddr,
    owner: Owner,
    pending: Pending,
    endpoint: crate::node::EndpointDataIo,
    request_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
}

// Return immediately after the first real proof is dispatched. Later UDP
// bootstrap frames stay queued so positive replay accounting is observable.
async fn held_proof() -> ProofFixture {
    let mut nodes = [
        make_test_node().await,
        make_test_node().await,
        make_test_node().await,
    ];
    for node in &mut nodes {
        node.node.config.node.rekey.enabled = false;
        node.node.config.node.session.idle_timeout_secs = 0;
    }
    enable(&mut nodes[0], 1);
    nodes[0]
        .node
        .config
        .node
        .neighbor_rotation
        .as_mut()
        .unwrap()
        .interval_secs = 1;
    nodes[0].node.config.node.rate_limit.handshake_timeout_secs = 3;
    let local = *nodes[0].node.node_addr();
    let old = *nodes[2].node.node_addr();
    let newcomer = *nodes[1].node.node_addr();
    dial(&mut nodes, 0, 2).await;
    quiesce(&mut nodes).await;
    let owner = Owner::capture(&nodes[0], &old);
    // Real elapsed time makes the incumbent eligible at advertisement.
    while Node::now_ms() - owner.authenticated_at <= 1_050 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        nodes[0]
            .node
            .has_neighbor_rotation_opportunity(Node::now_ms())
    );

    dial(&mut nodes, 1, 0).await;
    let request = next_packet(&mut nodes[0]).await;
    assert!(Msg1Header::parse(request.data.as_slice()).is_some());
    let request_bytes = request.data.as_slice().to_vec();
    nodes[0].node.handle_msg1(request).await;
    let conn = nodes[0].node.peers.connection_values().next().unwrap();
    let pending = Pending {
        link: conn.link_id(),
        index: conn.our_index().unwrap(),
        started: conn.started_at(),
        activity: conn.last_activity(),
        attempt: nodes[0]
            .node
            .neighbor_rotation_started_at(&newcomer)
            .unwrap(),
    };
    let response = next_packet(&mut nodes[1]).await;
    assert_eq!(
        Msg2Header::parse(response.data.as_slice())
            .unwrap()
            .sender_idx,
        pending.index
    );
    pending.assert_retained(&nodes[0], &newcomer);

    // Pause the actual Msg2 delivery, not a fabricated admission decision.
    // New, successfully delivered application work now protects the peer
    // which was eligible when the response was advertised.
    let mut endpoint = nodes[2].node.attach_endpoint_data_io(8).unwrap();
    deliver_to_incumbent(&mut nodes, &mut endpoint.event_rx, 1).await;
    quiesce(&mut nodes).await;
    assert_eq!(Owner::capture(&nodes[0], &old), owner);
    nodes[1].node.handle_msg2(response).await;
    let proof = next_packet(&mut nodes[0]).await;
    assert_eq!(proof.remote_addr, nodes[1].addr);
    let header = FmpWireHeader::parse_encrypted(proof.data.as_slice()).unwrap();
    assert_eq!(header.receiver_idx(), pending.index.as_u32());
    let offset = usize::from(header.ciphertext_offset());
    // Read-only authentication proves that the real first frame is valid;
    // production dataplane dispatch below owns confirmation/promotion.
    assert!(
        nodes[0]
            .node
            .get_connection(&pending.link)
            .unwrap()
            .session()
            .unwrap()
            .authenticate_with_counter_and_aad(
                &proof.data.as_slice()[offset..],
                header.counter(),
                &proof.data.as_slice()[..offset],
            )
            .is_ok()
    );
    let proof_bytes = proof.data.as_slice().to_vec();
    process_dataplane_packet(&mut nodes[0], proof).await;
    pending.assert_retained(&nodes[0], &newcomer);
    assert_eq!(Owner::capture(&nodes[0], &old), owner);

    ProofFixture {
        nodes,
        local,
        old,
        newcomer,
        owner,
        pending,
        endpoint,
        request_bytes,
        proof_bytes,
    }
}

#[test]
fn incoming_proof_retains_candidate_when_advertised_victim_gains_application_demand() {
    run_large_stack_async_test("incoming-proof-demand-retention", || async {
        let ProofFixture {
            mut nodes,
            local,
            old,
            newcomer,
            owner,
            pending,
            mut endpoint,
            request_bytes,
            proof_bytes,
        } = held_proof().await;
        let deadline = pending.activity + 3_000;
        let bound = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut sequence = 2;
        loop {
            assert!(
                tokio::time::Instant::now() < bound,
                "original candidate deadline must bound retention"
            );
            deliver_to_incumbent(&mut nodes, &mut endpoint.event_rx, sequence).await;
            let now = Node::now_ms();
            if now.saturating_add(100) >= deadline {
                tokio::time::sleep(Duration::from_millis(deadline.saturating_sub(now) + 10)).await;
                break;
            }
            // Real retransmitted Msg1, duplicate encrypted proof, and a fresh
            // encrypted heartbeat must not renew the candidate's lifetime.
            let transport = nodes[1]
                .node
                .transports
                .get(&nodes[1].transport_id)
                .unwrap();
            transport
                .send(&nodes[0].addr, &request_bytes)
                .await
                .unwrap();
            transport.send(&nodes[0].addr, &proof_bytes).await.unwrap();
            nodes[1]
                .node
                .send_dataplane_fmp_link_plaintext(
                    &local,
                    &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
                    false,
                )
                .await
                .unwrap();
            quiesce(&mut nodes).await;
            pending.assert_retained(&nodes[0], &newcomer);
            nodes[0].node.check_timeouts().await;
            nodes[0]
                .node
                .resend_pending_handshakes(Node::now_ms())
                .await;
            pending.assert_retained(&nodes[0], &newcomer);
            assert_eq!(Owner::capture(&nodes[0], &old), owner);
            sequence += 1;
            tokio::time::sleep(Duration::from_millis(150)).await;
        }

        nodes[0].node.check_timeouts().await;
        assert_eq!(Owner::capture(&nodes[0], &old), owner);
        assert!(nodes[0].node.get_peer(&newcomer).is_none());
        assert!(nodes[0].node.get_connection(&pending.link).is_none());
        assert!(!nodes[0].node.index_allocator.is_allocated(pending.index));
        assert!(nodes[0].node.links.get(&pending.link).is_none());
        assert_eq!(resources(&nodes[0]), (1, 0, 1, 1));
        nodes[1]
            .node
            .transports
            .get(&nodes[1].transport_id)
            .unwrap()
            .send(&nodes[0].addr, &proof_bytes)
            .await
            .unwrap();
        quiesce(&mut nodes).await;
        assert_eq!(resources(&nodes[0]), (1, 0, 1, 1));
        deliver_to_incumbent(&mut nodes, &mut endpoint.event_rx, 255).await;
        assert_eq!(Owner::capture(&nodes[0], &old), owner);
        cleanup_nodes(&mut nodes).await;
    });
}

#[test]
fn incoming_retained_proof_promotes_after_demand_idles_and_replays_once() {
    run_large_stack_async_test("incoming-proof-idle-promotion", || async {
        let ProofFixture {
            mut nodes,
            old,
            newcomer,
            owner,
            pending,
            proof_bytes,
            ..
        } = held_proof().await;
        let saved = nodes[0].node.get_connection(&pending.link).unwrap();
        assert_eq!(
            saved.handshake_confirmation().unwrap().data.as_slice(),
            proof_bytes
        );
        let deadline = pending.activity + 3_000;
        while nodes[0]
            .node
            .peer_has_application_demand(&old, Node::now_ms(), 1_000)
        {
            assert!(
                Node::now_ms() < deadline,
                "real application demand must become idle before the original candidate deadline"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Do not drain raw UDP here: only the retained first heartbeat may
        // reach the newly installed dataplane owner before its count is read.
        pending.assert_retained(&nodes[0], &newcomer);
        assert_eq!(Owner::capture(&nodes[0], &old), owner);
        let promotion_at = Node::now_ms();
        assert!(promotion_at < deadline);
        nodes[0].node.check_timeouts().await;
        nodes[0]
            .node
            .resend_pending_handshakes(Node::now_ms())
            .await;
        let active = nodes[0]
            .node
            .get_peer(&newcomer)
            .expect("ordinary maintenance promotes the retained proof after demand idles");
        assert_eq!(active.link_id(), pending.link);
        assert_eq!(active.our_index(), Some(pending.index));
        assert!(
            active.authenticated_at() >= promotion_at,
            "promotion age must use current admission time, not the first proof receipt"
        );
        assert!(nodes[0].node.get_peer(&old).is_none());
        assert!(nodes[0].node.get_connection(&pending.link).is_none());
        assert_eq!(resources(&nodes[0]), (1, 0, 1, 1));

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                crate::node::tests::spanning_tree::process_dataplane_completions(
                    &mut nodes[0].node,
                )
                .await;
                let received = nodes[0]
                    .node
                    .dataplane_fmp_link_metrics(&newcomer, Instant::now())
                    .unwrap()
                    .rx_packets;
                assert!(
                    received <= 1,
                    "no later raw bootstrap frame has been dispatched"
                );
                if received == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("retained heartbeat must enter the ordinary dataplane exactly once");
        for _ in 0..3 {
            nodes[0]
                .node
                .resend_pending_handshakes(Node::now_ms())
                .await;
            crate::node::tests::spanning_tree::process_dataplane_completions(&mut nodes[0].node)
                .await;
            let metrics = nodes[0]
                .node
                .dataplane_fmp_link_metrics(&newcomer, Instant::now())
                .unwrap();
            assert_eq!(
                metrics.rx_packets, 1,
                "maintenance cannot replay the consumed proof again"
            );
            assert!(metrics.current_epoch_authenticated);
        }

        // Now allow the rest of the genuine bootstrap to run, then verify one
        // application submission delivers once over the newly matched owners.
        quiesce(&mut nodes).await;
        let local = *nodes[0].node.node_addr();
        let a = nodes[0].node.get_peer(&newcomer).unwrap();
        let b = nodes[1].node.get_peer(&local).unwrap();
        assert_eq!(a.our_index(), b.their_index());
        assert_eq!(a.their_index(), b.our_index());
        let remote = PeerIdentity::from_pubkey_full(nodes[1].node.identity.pubkey_full());
        let mut receiver = nodes[1].node.attach_endpoint_data_io(8).unwrap();
        send_endpoint_data_via_dataplane(
            &mut nodes[0].node,
            remote,
            b"retained-proof-once".to_vec(),
        )
        .await
        .unwrap();
        let event = recv_endpoint_event_while_draining(
            &mut nodes,
            &mut receiver.event_rx,
            Duration::from_secs(2),
            "payload after retained incoming proof promotion",
        )
        .await;
        receiver.event_rx.release_messages(event.messages.len());
        assert_eq!(
            expect_single_endpoint_data_event(event).payload.as_slice(),
            b"retained-proof-once"
        );
        for _ in 0..3 {
            nodes[0]
                .node
                .resend_pending_handshakes(Node::now_ms())
                .await;
            quiesce(&mut nodes).await;
        }
        assert!(matches!(
            receiver.event_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        cleanup_nodes(&mut nodes).await;
    });
}
