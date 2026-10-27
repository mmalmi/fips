use super::*;
use crate::dataplane::{ActivityTick, DataplaneLiveOutboundFirsts, FmpWireHeader};
use crate::node::tests::spanning_tree::process_dataplane_packet;
use crate::transport::PacketBuffer;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[test]
fn cached_endpoint_send_preserves_ready_incoming_payload() {
    send_preserves_incoming_backlog(SendCase::EndpointSuccess);
}

#[test]
fn failed_cached_endpoint_send_preserves_ready_incoming_payload() {
    send_preserves_incoming_backlog(SendCase::EndpointFailure);
}

#[test]
fn failed_link_send_preserves_ready_incoming_payload() {
    send_preserves_incoming_backlog(SendCase::LinkFailure);
}

#[test]
fn failed_session_control_send_preserves_ready_incoming_payload() {
    send_preserves_incoming_backlog(SendCase::SessionControlFailure);
}

#[derive(Clone, Copy)]
enum SendCase {
    EndpointSuccess,
    EndpointFailure,
    LinkFailure,
    SessionControlFailure,
}

fn send_preserves_incoming_backlog(case: SendCase) {
    run_large_stack_async_test("send-ready-ingress", move || async move {
        let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
        let result = AssertUnwindSafe(async {
            populate_all_coord_caches(&mut nodes);
            let identities = nodes
                .iter()
                .map(|n| PeerIdentity::from_pubkey_full(n.node.identity().pubkey_full()))
                .collect::<Vec<_>>();
            let mut endpoints = nodes
                .iter_mut()
                .map(|n| n.node.attach_endpoint_data_io(8).unwrap())
                .collect::<Vec<_>>();
            nodes[0]
                .node
                .initiate_session(*identities[1].node_addr(), identities[1].pubkey_full())
                .await
                .unwrap();
            wait_for_session_established(
                &mut nodes,
                0,
                identities[1].node_addr(),
                Duration::from_secs(5),
                "cached send incoming ownership",
            )
            .await;
            drain_to_quiescence(&mut nodes).await;
            assert!(
                nodes[0]
                    .node
                    .dataplane
                    .owner_active_path(crate::dataplane::OwnerId::fsp_node(
                        *identities[1].node_addr()
                    ),)
                    .unwrap()
                    .is_some()
            );

            // Admit a real receive backlog with one crypto dispatch, then send
            // in the other direction while its completions remain outstanding.
            let originals = (0..8).map(|tag| vec![tag; 1200]).collect::<Vec<_>>();
            let (packet_tx, mut packet_rx) = crate::transport::packet_channel(8);
            for original in &originals {
                send_endpoint_data_via_dataplane(
                    &mut nodes[0].node,
                    identities[1],
                    original.clone(),
                )
                .await
                .unwrap();
                let packet =
                    tokio::time::timeout(Duration::from_secs(1), nodes[1].packet_rx.recv())
                        .await
                        .unwrap()
                        .unwrap();
                packet_tx.send(packet).unwrap();
            }
            let (_fast_tx, mut fast_rx) = tokio::sync::mpsc::channel(1);
            let (_endpoint_tx, mut endpoint_rx) = crate::node::endpoint_data_batch_channel(1);
            let (_tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
            let endpoint_tx = nodes[1].node.endpoint_events.sender().unwrap();
            let mut io = crate::node::handlers::rx_loop_dataplane_io(
                &mut packet_rx,
                &mut fast_rx,
                &mut endpoint_rx,
                &mut tun_rx,
                &endpoint_tx,
            );
            let turn = nodes[1]
                .node
                .drain_dataplane_turn_with_firsts(
                    &mut io,
                    crate::dataplane::DataplaneLiveTurnFirsts::default(),
                    crate::node::handlers::RxLoopDataplaneTurnLimits::new(8, 0, 0, 1),
                )
                .await;
            assert!(turn.drops().is_empty() && turn.raw_ingress_drops().is_empty());
            assert!(
                turn.fsp_session_ingress_count() < originals.len(),
                "receive backlog remains"
            );
            nodes[1].node.defer_dataplane_control_turn(turn);
            tokio::time::timeout(Duration::from_secs(1), async {
                let ready = nodes[1].node.dataplane.readiness_notify();
                while !nodes[1].node.dataplane.has_runnable_output_work() {
                    ready.notified().await;
                }
            })
            .await
            .expect("incoming crypto completes");

            let destination = *identities[0].node_addr();
            let remote = nodes[1]
                .node
                .prepare_dataplane_cached_endpoint_send(&destination)
                .unwrap();
            let payload =
                crate::node::EndpointDataPayload::from_packet_payload(vec![0x3c]).unwrap();
            if matches!(case, SendCase::EndpointSuccess) {
                nodes[1]
                    .node
                    .send_dataplane_prepared_endpoint_payloads(remote, vec![payload])
                    .await
                    .unwrap();
            } else {
                // A prepared native route can outlive transport registration.
                // Remove only its carrier after admitting real incoming records;
                // the production output sink must return its actual error.
                let transport_id = nodes[1].transport_id;
                let transport = nodes[1].node.transports.remove(&transport_id).unwrap();
                let result = match case {
                    SendCase::EndpointFailure => nodes[1]
                        .node
                        .send_dataplane_prepared_endpoint_payloads(remote, vec![payload])
                        .await
                        .map_err(|failure| failure.error),
                    SendCase::LinkFailure => {
                        nodes[1]
                            .node
                            .send_dataplane_fmp_link_plaintext(
                                &destination,
                                &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
                                false,
                            )
                            .await
                    }
                    SendCase::SessionControlFailure => {
                        nodes[1]
                            .node
                            .send_dataplane_fsp_coords_warmup(&destination)
                            .await
                    }
                    SendCase::EndpointSuccess => unreachable!(),
                };
                nodes[1].node.transports.insert(transport_id, transport);
                let expected_error = if matches!(case, SendCase::LinkFailure) {
                    matches!(result, Err(NodeError::LocalRouteUnavailable(_)))
                } else {
                    matches!(result, Err(NodeError::SendFailed { .. }))
                };
                assert!(
                    expected_error,
                    "native transport output must reject the missing carrier: {result:?}"
                );
            }
            drain_to_quiescence(&mut nodes).await;
            let mut received = Vec::new();
            while let Ok(event) = endpoints[1].event_rx.try_recv() {
                endpoints[1].event_rx.release_messages(event.messages.len());
                for delivered in event.messages {
                    assert_eq!(delivered.source_peer, identities[0]);
                    received.push(delivered.payload.as_slice().to_vec());
                }
            }
            // Deferred turns can dispatch after a newer ordinary receive turn.
            // Check exact datagram ownership, without imposing stream ordering.
            received.sort_unstable();
            assert_eq!(
                received, originals,
                "send completion must retain every unrelated completed incoming payload"
            );
        })
        .catch_unwind()
        .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

#[test]
fn retained_ingress_does_not_complete_a_nested_send_wait() {
    run_large_stack_async_test("retained-ingress-send-wait", || async {
        let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
        let result = AssertUnwindSafe(async {
            drain_to_quiescence(&mut nodes).await;
            let destination = *nodes[1].node.node_addr();
            nodes[0]
                .node
                .send_dataplane_fmp_link_plaintext(
                    &destination,
                    &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
                    false,
                )
                .await
                .unwrap();
            let packet = tokio::time::timeout(Duration::from_secs(1), nodes[1].packet_rx.recv())
                .await
                .unwrap()
                .unwrap();
            nodes[1].node.dataplane.defer_fmp_handshake_proof(packet);
            assert!(nodes[1].node.dataplane.has_runnable_work());
            assert!(!nodes[1].node.dataplane.has_runnable_output_work());

            // Promotion retains a genuine encrypted proof before bootstrap
            // sends. Their zero-ingress continuation must still await output
            // readiness instead of exhausting its allowance on this proof.
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(20),
                    nodes[1].node.wait_for_dataplane_completion(),
                )
                .await
                .is_err(),
                "retained raw ingress cannot satisfy an output-only wait"
            );
            assert!(nodes[1].node.dataplane.has_deferred_raw_ingress());
            drain_to_quiescence(&mut nodes).await;
            assert!(!nodes[1].node.dataplane.has_deferred_raw_ingress());
        })
        .catch_unwind()
        .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

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
                    assert!(!turn.has_node_control_ingress());
                    assert_eq!(
                        nodes[0]
                            .node
                            .process_dataplane_control_ingress(&mut turn)
                            .await,
                        0,
                        "an output-only turn has no node control work"
                    );
                    let mut receipts = turn.take_transport_sent_receipts();
                    if !receipts.is_empty() {
                        assert!(turn.has_activity(), "completed output remains activity");
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
