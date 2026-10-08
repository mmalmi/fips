use super::*;
use crate::dataplane::{ActivityTick, DataplaneLiveOutboundFirsts, FmpWireHeader};
use crate::node::tests::spanning_tree::process_dataplane_packet;
use crate::transport::PacketBuffer;

#[test]
fn warmed_control_turns_preserve_encrypted_wire_and_send_receipts() {
    run_large_stack_async_test("fips-idle-control", || async {
        let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
        drain_to_quiescence(&mut nodes).await;
        let peer = *nodes[1].node.node_addr();
        let _endpoint = nodes[0].node.attach_endpoint_data_io(8).unwrap();
        let heartbeat = [crate::protocol::LinkMessageType::Heartbeat.to_byte()];
        let source = *nodes[0].node.node_addr();
        let ready = nodes[0].node.dataplane.readiness_notify();
        let mut last_counter = None;

        // The first send warms the worker and reusable output buffers. The
        // remaining sends use the same actual UDP/Noise link and receipt path.
        for _ in 0..17 {
            let (outbound, token) = nodes[0]
                .node
                .prepare_dataplane_fmp_link_outbound(
                    peer,
                    PacketBuffer::new(heartbeat.to_vec()),
                    false,
                    ActivityTick::new(Node::now_ms()),
                    None,
                )
                .unwrap();
            let mut turn = nodes[0]
                .node
                .pump_dataplane_pending_outbound_firsts(
                    DataplaneLiveOutboundFirsts {
                        initial_outbound: Some(outbound),
                        collect_transport_sent_receipts: true,
                        ..Default::default()
                    },
                    0,
                    0,
                    1,
                )
                .await;
            let receipt = tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    assert!(turn.drops().is_empty());
                    assert!(turn.output_drops().is_empty());
                    let mut receipts = turn.take_transport_sent_receipts();
                    if !receipts.is_empty() {
                        assert_eq!(receipts.len(), 1);
                        break receipts.remove(0);
                    }
                    ready.notified().await;
                    turn = nodes[0]
                        .node
                        .pump_dataplane_pending_outbound_firsts(
                            DataplaneLiveOutboundFirsts {
                                collect_transport_sent_receipts: true,
                                ..Default::default()
                            },
                            0,
                            0,
                            8,
                        )
                        .await;
                }
            })
            .await
            .expect("control send completes");
            assert_eq!(receipt.send_token, Some(token));
            let packet = tokio::time::timeout(Duration::from_secs(1), nodes[1].packet_rx.recv())
                .await
                .unwrap()
                .unwrap();
            let header = FmpWireHeader::parse_encrypted(packet.data.as_slice()).unwrap();
            assert_eq!(header.counter(), receipt.counter);
            assert_eq!(packet.data.len(), receipt.payload_len);
            if let Some(last) = last_counter {
                assert!(
                    receipt.counter > last,
                    "warm sends must preserve owner order"
                );
            }
            last_counter = Some(receipt.counter);
            let received_before = nodes[1]
                .node
                .dataplane_fmp_link_metrics(&source, std::time::Instant::now())
                .unwrap()
                .rx_packets;
            assert!(process_dataplane_packet(&mut nodes[1], packet).await > 0);
            assert_eq!(
                nodes[1]
                    .node
                    .dataplane_fmp_link_metrics(&source, std::time::Instant::now())
                    .unwrap()
                    .rx_packets,
                received_before + 1,
                "the remote owner must authenticate each encrypted control frame"
            );
        }
        assert!(nodes[1].node.peers.contains_key(nodes[0].node.node_addr()));
        cleanup_nodes(&mut nodes).await;
    });
}
