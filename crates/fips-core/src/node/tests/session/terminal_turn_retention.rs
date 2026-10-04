//! A synchronous send can retire unrelated ingress in its terminal turn.
use super::*;
use crate::dataplane::{DataplaneLiveNodeTurn, DataplaneLiveOutboundFirsts};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[test]
fn successful_send_retains_authenticated_ingress() {
    run(false);
}

#[test]
fn failed_send_retains_authenticated_ingress() {
    run(true);
}

fn run(fail_send: bool) {
    run_large_stack_async_test("terminal-turn-retention", move || async move {
        let _guard = lock_large_network_test().await;
        let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
        let result = AssertUnwindSafe(exercise(&mut nodes, fail_send))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise(nodes: &mut [TestNode], fail_send: bool) {
    populate_all_coord_caches(nodes);
    let _network = sim_harness::replace_session_100_node_carriers(nodes, &[(0, 1)]).await;
    let local = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
    let remote = *nodes[1].node.node_addr();
    let mut endpoint = nodes[0].node.attach_endpoint_data_io(8).unwrap();
    send_endpoint_data_via_dataplane(&mut nodes[1].node, local, vec![10])
        .await
        .unwrap();
    let warm = recv_endpoint_event_while_draining(
        nodes,
        &mut endpoint.event_rx,
        Duration::from_secs(5),
        "establish real FSP",
    )
    .await;
    endpoint.event_rx.release_messages(warm.message_count());
    assert_eq!(
        expect_single_endpoint_data_event(warm).payload.as_slice(),
        &[10]
    );
    drain_to_quiescence(nodes).await;

    // Hold real worker submissions before authenticated owner retirement, without
    // manufacturing plaintext, counters, receipts or an established owner.
    send_endpoint_data_via_dataplane(&mut nodes[1].node, local, vec![126, 1, 0])
        .await
        .unwrap();
    let packet = tokio::time::timeout(Duration::from_secs(2), nodes[0].packet_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        packet.data.as_slice()[1] & crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
        0,
        "the established peer uses direct FSP"
    );
    let transport_id = nodes[0].transport_id;
    let node = &mut nodes[0].node;
    node.dataplane.hold_crypto_submissions();
    let (_, mut packets) = crate::transport::packet_channel(1);
    let (_, mut fast) = tokio::sync::mpsc::channel(1);
    let (_, mut data) = crate::node::endpoint_data_batch_channel(1);
    let (_, mut tun) = crate::upper::tun::tun_outbound_channel(1);
    let tx = node.endpoint_events.sender().unwrap();
    let mut io = crate::node::handlers::rx_loop_dataplane_io(
        &mut packets,
        &mut fast,
        &mut data,
        &mut tun,
        &tx,
    );
    let turn = node
        .drain_dataplane_turn_with_firsts(
            &mut io,
            crate::dataplane::DataplaneLiveTurnFirsts {
                raw_packet: Some(packet),
                ..Default::default()
            },
            crate::node::handlers::RxLoopDataplaneTurnLimits::new(1, 0, 0, 1),
        )
        .await;
    assert_eq!(turn.summary().dispatched(), 1);
    assert!(!turn.has_failures());
    node.defer_dataplane_control_turn(turn);
    let before = node
        .dataplane
        .fsp_owner_activity(&remote)
        .unwrap()
        .traffic_counters()
        .1;
    let (outbound, send_token) = node
        .prepare_dataplane_fmp_link_outbound(
            remote,
            crate::transport::PacketBuffer::new(vec![
                crate::protocol::LinkMessageType::Heartbeat.to_byte(),
            ]),
            false,
            crate::dataplane::ActivityTick::new(Node::now_ms()),
            None,
        )
        .unwrap();
    let turn = node
        .pump_dataplane_pending_outbound_firsts(
            DataplaneLiveOutboundFirsts {
                initial_outbound: Some(outbound),
                ..Default::default()
            },
            0,
            0,
            1,
        )
        .await;
    assert_eq!(turn.summary().dispatched(), 1);
    assert_eq!(turn.transport_sent(), 0);
    node.defer_dataplane_control_turn(turn);
    assert_eq!(
        node.dataplane.release_crypto_submissions_and_wait().await,
        2
    );

    // Both owners are now ready. Removing the carrier tests the ordinary output
    // error branch; success uses the actual simulated transport completion.
    let transport = fail_send.then(|| node.transports.remove(&transport_id).unwrap());
    let result = node
        .drive_dataplane_pending_outbound_token_receipts(
            DataplaneLiveNodeTurn::default(),
            send_token,
            1,
            2,
            64,
        )
        .await;
    if let Some(transport) = transport {
        node.transports.insert(transport_id, transport);
    }
    assert_eq!(result.is_err(), fail_send);
    drop(result);
    assert_eq!(
        node.dataplane
            .fsp_owner_activity(&remote)
            .unwrap()
            .traffic_counters()
            .1,
        before + 1
    );
    node.drain_deferred_dataplane_control_turns().await;
    let event = endpoint
        .event_rx
        .try_recv()
        .expect("terminal send must retain authenticated ingress");
    endpoint.event_rx.release_messages(event.message_count());
    assert_eq!(
        expect_single_endpoint_data_event(event).payload.as_slice(),
        &[126, 1, 0]
    );
    node.drain_deferred_dataplane_control_turns().await;
    assert!(
        endpoint.event_rx.try_recv().is_err(),
        "retained ingress is delivered exactly once"
    );
}
