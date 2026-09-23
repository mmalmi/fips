//! A SessionAck's cached send must not consume unrelated deferred TUN ingress.
//!
//! This stages two genuine native reports before Node dispatch. The live pump
//! similarly combines ready crypto completions with fresh ingress before
//! `process_dataplane_control_ingress`, which visits session controls before
//! deferred TUN packets. This isolates that ordering, not RX scheduling timing.
use super::*;
use crate::dataplane::{DataplaneLiveNodeTurn, DataplaneLiveTurnFirsts};
use crate::node::session_wire::{FSP_PHASE_MSG2, FspCommonPrefix};
use crate::node::tests::spanning_tree::{make_test_node, process_node_packets};
use crate::node::{EndpointDataPayload, NodeEndpointDataBatch};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[test]
fn session_ack_endpoint_flush_preserves_coadmitted_tun_original() {
    run_large_stack_async_test("tun-deferred-ownership", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = vec![make_test_node().await, make_test_node().await];
        let result = AssertUnwindSafe(exercise(&mut nodes)).catch_unwind().await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

// Retain the real channels, but leave Node control dispatch to the caller so
// the authentic SessionAck completion can precede newly admitted TUN ingress.
async fn native_turn(
    node: &mut TestNode,
    packet_limit: usize,
    endpoint_limit: usize,
    tun_limit: usize,
) -> DataplaneLiveNodeTurn {
    let mut endpoint_rx = node.node.endpoint_data_rx.take().unwrap();
    let mut tun_rx = node.node.tun_outbound_rx.take().unwrap();
    let (_fast_tx, mut fast_rx) = tokio::sync::mpsc::channel(1);
    let endpoint_tx = node.node.endpoint_events.sender().unwrap();
    let mut io = crate::node::handlers::rx_loop_dataplane_io(
        &mut node.packet_rx,
        &mut fast_rx,
        &mut endpoint_rx,
        &mut tun_rx,
        &endpoint_tx,
    );
    let turn = Box::pin(node.node.drain_dataplane_turn_with_firsts(
        &mut io,
        DataplaneLiveTurnFirsts::default(),
        crate::node::handlers::RxLoopDataplaneTurnLimits::new(
            packet_limit,
            endpoint_limit,
            tun_limit,
            64,
        ),
    ))
    .await;
    node.node.endpoint_data_rx = Some(endpoint_rx);
    node.node.tun_outbound_rx = Some(tun_rx);
    turn
}

async fn finish(node: &mut Node, turn: &mut DataplaneLiveNodeTurn) {
    node.process_dataplane_control_ingress(turn).await;
    node.drain_deferred_dataplane_control_turns().await;
}

async fn connect(nodes: &mut [TestNode], destination: PeerIdentity) {
    let address = nodes[1].addr.clone();
    let transport = nodes[0].transport_id;
    nodes[0]
        .node
        .initiate_connection(transport, address, destination)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            process_available_packets(nodes).await;
            if nodes
                .iter()
                .all(|node| node.node.peer_count() == 1 && node.node.connection_count() == 0)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("ordinary UDP/Noise carrier establishment");
    drain_to_quiescence(nodes).await;
}

fn queued_endpoint_count(node: &Node, destination: &NodeAddr) -> usize {
    node.pending_session_traffic
        .endpoint_data_for(destination)
        .map_or(0, |queue| queue.len())
}

async fn hold_returned_ack(
    nodes: &mut [TestNode],
    destination: &NodeAddr,
) -> DataplaneLiveNodeTurn {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let receiver = &mut nodes[1];
            process_node_packets(&mut receiver.node, &mut receiver.packet_rx).await;
            let mut turn = native_turn(&mut nodes[0], 64, 0, 0).await;
            if !turn.fsp_local_session_ingress().is_empty() {
                assert_eq!(turn.fsp_local_session_ingress().len(), 1);
                // Inspect a copy only. The original authenticated ingress stays
                // owned by the native report and is dispatched exactly once.
                let (source, previous, _, _, payload) =
                    turn.fsp_local_session_ingress()[0].clone().into_parts();
                assert_eq!(source, *destination);
                assert_eq!(previous, *destination);
                assert_eq!(
                    FspCommonPrefix::parse(payload.as_slice()).unwrap().phase,
                    FSP_PHASE_MSG2
                );
                return turn;
            }
            finish(&mut nodes[0].node, &mut turn).await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("real returned SessionAck before Node dispatch")
}

async fn exercise(nodes: &mut [TestNode]) {
    let source = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
    let destination = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    connect(nodes, destination).await;
    assert!(nodes[0].node.get_session(destination.node_addr()).is_none());
    assert!(nodes[1].node.get_session(source.node_addr()).is_none());
    let source_io = nodes[0].node.attach_endpoint_data_io(8).unwrap();
    let mut destination_io = nodes[1].node.attach_endpoint_data_io(8).unwrap();
    let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
    nodes[1].node.tun_tx = Some(tun_tx);

    let endpoint_original = vec![211; 700];
    source_io
        .data_batch_tx
        .send_or_drop(
            NodeEndpointDataBatch::from_payloads(
                destination,
                vec![EndpointDataPayload::from_packet_payload(endpoint_original.clone()).unwrap()],
                None,
            )
            .unwrap(),
        )
        .unwrap();
    let mut submitted = native_turn(&mut nodes[0], 0, 1, 0).await;
    assert_eq!(submitted.endpoint_source_drained(), 1);
    finish(&mut nodes[0].node, &mut submitted).await;
    assert_eq!(
        queued_endpoint_count(&nodes[0].node, destination.node_addr()),
        1
    );

    let mut ack = hold_returned_ack(nodes, destination.node_addr()).await;
    assert!(
        nodes[0]
            .node
            .get_session(destination.node_addr())
            .unwrap()
            .is_initiating()
    );
    assert!(
        !nodes[0]
            .node
            .dataplane_has_fsp_owner(destination.node_addr())
    );
    assert!(
        nodes[1]
            .node
            .get_session(source.node_addr())
            .unwrap()
            .is_awaiting_msg3()
    );

    let tun_original = build_ipv6_packet(
        &crate::FipsAddress::from_node_addr(source.node_addr()),
        &crate::FipsAddress::from_node_addr(destination.node_addr()),
        &[212; 900],
    );
    nodes[0]
        .tun_outbound_tx
        .try_send(tun_original.clone())
        .unwrap();
    let mut admitted = native_turn(&mut nodes[0], 0, 0, 1).await;
    assert_eq!(admitted.tun_source_drained(), 1);
    assert_eq!(admitted.tun_deferred_packets(), 1);
    assert!(admitted.tun_outbound_drops().is_empty());
    assert_eq!(
        queued_endpoint_count(&nodes[0].node, destination.node_addr()),
        1
    );
    assert!(tun_rx.try_recv_packet().is_err());

    // Like the live completion-plus-admission report, visit the SessionAck
    // before global deferred TUN work. Its ordinary handshake handler performs
    // the cached endpoint flush; the test never invokes that send directly.
    finish(&mut nodes[0].node, &mut ack).await;
    finish(&mut nodes[0].node, &mut admitted).await;
    assert!(
        nodes[0]
            .node
            .get_session(destination.node_addr())
            .unwrap()
            .is_established()
    );
    assert_eq!(
        queued_endpoint_count(&nodes[0].node, destination.node_addr()),
        0
    );

    let event = recv_endpoint_event_while_draining(
        nodes,
        &mut destination_io.event_rx,
        Duration::from_secs(3),
        "SessionAck flush delivers the older endpoint original",
    )
    .await;
    destination_io
        .event_rx
        .release_messages(event.messages.len());
    let delivery = expect_single_endpoint_data_event(event);
    assert_eq!(delivery.source_peer, source);
    assert_eq!(delivery.payload.as_slice(), endpoint_original);
    let received = recv_tun_packet_while_draining(
        nodes,
        &tun_rx,
        Duration::from_secs(3),
        "cached endpoint flush must preserve unrelated deferred TUN ingress",
    )
    .await;
    assert_eq!(received, tun_original);
    drain_to_quiescence(nodes).await;
    assert!(destination_io.event_rx.try_recv().is_err());
    assert!(tun_rx.try_recv_packet().is_err());
    assert!(nodes.iter().all(|node| {
        node.node.peer_count() == 1
            && node.node.link_count() == 1
            && node.node.connection_count() == 0
    }));
}
