//! Deferred-ingress ownership, using real UDP/Noise and an ordinary allowance
//! rejection. This calls the production deferred-TUN handler explicitly; a
//! healthy packet entering the live TUN channel normally bypasses that handler.
use super::*;
use crate::dataplane::DataplaneLiveOutboundFirsts;
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

#[derive(Debug)]
struct Allowance {
    destination: NodeAddr,
    carrier: NodeAddr,
    attempts: AtomicUsize,
    completions: Mutex<Vec<(u64, ForwardingOutcome)>>,
}

impl OriginatedSessionObserver for Allowance {
    fn prepare(&self, intent: &OriginatedSessionIntent) -> OriginatedSessionAdmission {
        if intent.destination != self.destination || intent.session_bytes < 700 {
            return OriginatedSessionAdmission::Defer;
        }
        assert_eq!(intent.next_hop, self.carrier);
        let attempt = self.attempts.fetch_add(1, Ordering::Relaxed);
        if attempt == 0 {
            // Refuse the older endpoint record, not the selected TUN original.
            OriginatedSessionAdmission::Reject
        } else {
            OriginatedSessionAdmission::Track(attempt as u64)
        }
    }

    fn observe(&self, _: &OriginatedSessionRequest<'_>) -> Option<u64> {
        None
    }

    fn complete(&self, token: u64, outcome: ForwardingOutcome) {
        self.completions.lock().unwrap().push((token, outcome));
    }
}

#[test]
fn unrelated_admission_error_cannot_requeue_handed_off_tun_original() {
    run_large_stack_async_test("tun-send-ownership", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
        let result = AssertUnwindSafe(exercise(&mut nodes)).catch_unwind().await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

fn session_owner(node: &Node, destination: &NodeAddr) -> ([u8; 32], u64, u64) {
    let session = node.get_session(destination).unwrap();
    assert!(session.is_established() && node.dataplane_has_fsp_owner(destination));
    (
        *session.handshake_hash().unwrap(),
        session.created_at(),
        session.session_start_ms(),
    )
}

type CarrierSnapshot = Vec<Vec<(NodeAddr, LinkId, Option<SessionIndex>, u64)>>;

fn carriers(nodes: &[TestNode]) -> CarrierSnapshot {
    nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let expected = if index == 1 { 2 } else { 1 };
            assert_eq!(node.node.peer_count(), expected);
            assert_eq!(node.node.link_count(), expected);
            assert_eq!(node.node.index_allocator.count(), expected);
            assert_eq!(node.node.connection_count(), 0);
            let mut peers = node
                .node
                .peers
                .iter()
                .map(|(addr, peer)| {
                    assert!(peer.is_healthy() && peer.can_send());
                    (
                        *addr,
                        peer.link_id(),
                        peer.our_index(),
                        peer.session_generation(),
                    )
                })
                .collect::<Vec<_>>();
            peers.sort_by_key(|peer| peer.0);
            peers
        })
        .collect()
}

// No pending retry or new submission: only normal crypto/packet completion.
async fn receive_original(nodes: &mut [TestNode], rx: &crate::upper::tun::TunRx) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            process_available_packets(nodes).await;
            if let Ok(packet) = rx.try_recv_packet() {
                break packet.as_slice().to_vec();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the actually handed-off original reaches the real TUN receiver")
}

async fn exercise(nodes: &mut [TestNode]) {
    let peers = nodes
        .iter()
        .map(|node| PeerIdentity::from_pubkey_full(node.node.identity().pubkey_full()))
        .collect::<Vec<_>>();
    let source = *peers[0].node_addr();
    let relay = *peers[1].node_addr();
    let destination = *peers[2].node_addr();
    for node in nodes.iter_mut() {
        // Isolate explicit carrier ownership from incidental tree-root order.
        // All owners, reverse feedback and FSP keys still come from real frames.
        node.node.config.node.routing.mode = RoutingMode::ReplyLearned;
        assert_eq!(node.node.config.node.session.pending_packets_per_dest, 16);
    }
    nodes[0]
        .node
        .set_endpoint_source_route(peers[2], Some(peers[1]))
        .unwrap();
    nodes[2]
        .node
        .set_endpoint_source_route(peers[0], Some(peers[1]))
        .unwrap();
    let mut endpoint = nodes[2].node.attach_endpoint_data_io(8).unwrap();
    let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
    nodes[2].node.tun_tx = Some(tun_tx);
    send_endpoint_data_via_dataplane(&mut nodes[0].node, peers[2], vec![201; 700])
        .await
        .unwrap();
    let warm = recv_endpoint_event_while_draining(
        nodes,
        &mut endpoint.event_rx,
        Duration::from_secs(5),
        "warm actual routed FSP",
    )
    .await;
    endpoint.event_rx.release_messages(warm.messages.len());
    assert_eq!(
        expect_single_endpoint_data_event(warm).payload.as_slice(),
        vec![201; 700]
    );
    drain_to_quiescence(nodes).await;

    let packet = |byte, len| {
        build_ipv6_packet(
            &crate::FipsAddress::from_node_addr(&source),
            &crate::FipsAddress::from_node_addr(&destination),
            &vec![byte; len],
        )
    };
    // Warm the real IPv6 path through ordinary TUN ingress, independently of
    // the cached-send helper under test. A bounded cached send can return an
    // error with work still live, even without the staged allowance rejection.
    let control = packet(202, 900);
    send_tun_packet_via_dataplane(nodes, 0, control.clone()).await;
    assert_eq!(nodes[0].node.pending_session_traffic.tun_packet_count(), 0);
    assert_eq!(receive_original(nodes, &tun_rx).await, control);
    drain_to_quiescence(nodes).await;
    let original_carriers = carriers(nodes);
    let sessions = [
        session_owner(&nodes[0].node, &destination),
        session_owner(&nodes[2].node, &source),
    ];
    assert!(nodes[0].node.has_application_next_hop(&destination));
    assert!(
        nodes[0]
            .node
            .dataplane_application_route_ready(&destination)
    );
    assert_eq!(
        nodes[0].node.dataplane.fsp_owner_next_hop(&destination),
        Some(relay)
    );
    assert_eq!(
        nodes[0]
            .node
            .prepare_dataplane_cached_endpoint_send(&destination)
            .unwrap(),
        peers[2],
        "the real installed application route accepts a prepared send"
    );

    let allowance = Arc::new(Allowance {
        destination,
        carrier: relay,
        attempts: AtomicUsize::new(0),
        completions: Mutex::new(Vec::new()),
    });
    nodes[0]
        .node
        .set_originated_session_observer(Some(allowance.clone()));

    // Pre-handoff MTU rejection must not create a queued copy or consume an
    // allowance. No fabricated route/session state is needed for this guard.
    let oversized = packet(203, nodes[0].node.effective_ipv6_mtu() as usize);
    nodes[0]
        .node
        .handle_dataplane_deferred_tun_packet(oversized)
        .await;
    assert_eq!(allowance.attempts.load(Ordering::Relaxed), 0);
    assert_eq!(nodes[0].node.pending_session_traffic.tun_packet_count(), 0);

    let rejected = NodeEndpointDataBatch::from_payloads(
        peers[2],
        vec![EndpointDataPayload::from_packet_payload(vec![204; 700]).unwrap()],
        None,
    )
    .unwrap();
    // Stage a genuine routed record without dispatching it. The zero work
    // budget only isolates a production scheduling boundary; no owner, receipt,
    // queue timestamp or configured capacity is synthesized. Endpoint and TUN
    // records share this FSP owner's Bulk FIFO.
    let staged = nodes[0]
        .node
        .pump_dataplane_pending_outbound_firsts(
            DataplaneLiveOutboundFirsts {
                endpoint_data_batch: Some(rejected),
                ..Default::default()
            },
            1,
            0,
            0,
        )
        .await;
    assert_eq!(staged.summary().outbound_admitted(), 1);
    assert_eq!(staged.summary().dispatched(), 0);
    assert!(!staged.has_failures());
    assert_eq!(staged.transport_sent(), 0);
    assert_eq!(allowance.attempts.load(Ordering::Relaxed), 0);
    nodes[0].node.defer_dataplane_control_turn(staged);

    let original = packet(205, 900);
    nodes[0]
        .node
        .handle_dataplane_deferred_tun_packet(original.clone())
        .await;
    let queued_after_handoff = nodes[0].node.pending_session_traffic.tun_packet_count();
    assert_eq!(
        allowance.attempts.load(Ordering::Relaxed),
        2,
        "the older record was refused and this TUN original was admitted"
    );
    assert_eq!(receive_original(nodes, &tun_rx).await, original);
    assert_eq!(
        *allowance.completions.lock().unwrap(),
        vec![(1, ForwardingOutcome::Submitted)],
        "real transport completion belongs only to the admitted original"
    );
    assert_eq!(
        queued_after_handoff, 0,
        "unrelated failure must not give a handed-off TUN original a second queue owner"
    );

    // Exercising the ordinary retry after successful receipt must not reseal a
    // cloned packet with a new FSP counter. No second application submission.
    nodes[0].node.retry_pending_session_traffic().await;
    drain_to_quiescence(nodes).await;
    assert_eq!(allowance.attempts.load(Ordering::Relaxed), 2);
    assert_eq!(
        *allowance.completions.lock().unwrap(),
        vec![(1, ForwardingOutcome::Submitted)]
    );
    assert!(matches!(
        tun_rx.try_recv_packet(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    assert!(
        matches!(
            endpoint.event_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ),
        "the rejected endpoint record never reaches the receiver"
    );
    assert_eq!(nodes[0].node.pending_session_traffic.tun_packet_count(), 0);
    assert_eq!(nodes[0].node.source_routes.get(&destination), Some(&relay));
    assert_eq!(
        nodes[0].node.dataplane.fsp_owner_next_hop(&destination),
        Some(relay)
    );
    assert_eq!(session_owner(&nodes[0].node, &destination), sessions[0]);
    assert_eq!(session_owner(&nodes[2].node, &source), sessions[1]);
    assert_eq!(carriers(nodes), original_carriers);
}
