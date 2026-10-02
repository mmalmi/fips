use super::*;
use crate::node::{ForwardingOutcome, OriginatedSessionObserver, OriginatedSessionRequest};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

/// Passive evidence only: an unauthorized fallback must remain visible rather
/// than being hidden by a test observer rejecting it before transport.
#[derive(Debug)]
struct ApplicationCarriers {
    destination: NodeAddr,
    carriers: Mutex<BTreeSet<NodeAddr>>,
}

impl OriginatedSessionObserver for ApplicationCarriers {
    fn observe(&self, request: &OriginatedSessionRequest<'_>) -> Option<u64> {
        // These test application records contain 700 bytes. Small session
        // reports and lookup/handshake control are outside this observation.
        if request.destination == self.destination && request.session_payload.len() >= 700 {
            self.carriers.lock().unwrap().insert(request.next_hop);
        }
        None
    }

    fn complete(&self, _: u64, _: ForwardingOutcome) {
        panic!("passive observer does not reserve accounting tokens");
    }
}

#[test]
fn queued_endpoint_and_tun_retry_obey_rebound_source_carrier() {
    run_large_stack_async_test("source-bound-queued-retry", || async {
        let _guard = lock_large_network_test().await;
        let mut nodes = run_tree_test(4, &[(0, 1), (0, 2), (1, 3), (2, 3)], false).await;
        let peers: Vec<_> = nodes
            .iter()
            .map(|node| PeerIdentity::from_pubkey_full(node.node.identity().pubkey_full()))
            .collect();
        let source = *peers[0].node_addr();
        let destination = *peers[3].node_addr();
        for node in &mut nodes {
            // Exercise source binding independently of incidental tree-root
            // changes after Disconnect. All carriers still use real Noise/FMP.
            node.node.config.node.routing.mode = RoutingMode::ReplyLearned;
            node.node.config.node.rekey.enabled = false;
            node.node.config.node.session.idle_timeout_secs = 0;
        }
        nodes[0]
            .node
            .set_endpoint_source_route(peers[3], Some(peers[1]))
            .unwrap();
        // Keep the return path on the relay that will remain connected.
        nodes[3]
            .node
            .set_endpoint_source_route(peers[0], Some(peers[1]))
            .unwrap();
        let observed = Arc::new(ApplicationCarriers {
            destination,
            carriers: Mutex::new(BTreeSet::new()),
        });
        nodes[0]
            .node
            .set_originated_session_observer(Some(observed.clone()));
        let mut endpoint = nodes[3].node.attach_endpoint_data_io(8).unwrap();
        let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
        nodes[3].node.tun_tx = Some(tun_tx);

        // Establish the real end-to-end session through the original binding,
        // then exercise the public setter while both real carriers are usable.
        for (relay, byte) in [(1, 11), (2, 22)] {
            nodes[0]
                .node
                .set_endpoint_source_route(peers[3], Some(peers[relay]))
                .unwrap();
            observed.carriers.lock().unwrap().clear();
            send_endpoint_data_via_dataplane(&mut nodes[0].node, peers[3], vec![byte; 700])
                .await
                .unwrap();
            let event = recv_endpoint_event_while_draining(
                &mut nodes,
                &mut endpoint.event_rx,
                Duration::from_secs(5),
                "warm source-bound carrier",
            )
            .await;
            endpoint.event_rx.release_messages(event.messages.len());
            assert_eq!(
                expect_single_endpoint_data_event(event).payload.as_slice(),
                vec![byte; 700]
            );
            drain_to_quiescence(&mut nodes).await;
            assert_eq!(
                *observed.carriers.lock().unwrap(),
                BTreeSet::from([*peers[relay].node_addr()]),
                "the ordinary binding update must stop using the previous carrier"
            );
        }
        let session_hash = *nodes[0]
            .node
            .get_session(&destination)
            .unwrap()
            .handshake_hash()
            .unwrap();

        // The selected relay departs through an authenticated production
        // Disconnect. The old relay is still healthy and could carry traffic,
        // but its previous authorization is not a fallback authorization.
        let disconnect =
            crate::protocol::Disconnect::new(crate::protocol::DisconnectReason::Shutdown);
        nodes[2]
            .node
            .send_dataplane_fmp_link_plaintext(&source, &disconnect.encode(), false)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while nodes[0].node.get_peer(peers[2].node_addr()).is_some() {
                poll_available_packets(&mut nodes).await;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("authenticated Disconnect removes the bound relay");
        drain_to_quiescence(&mut nodes).await;
        assert!(
            nodes[0]
                .node
                .get_peer(peers[1].node_addr())
                .unwrap()
                .can_send()
        );
        assert_eq!(
            nodes[0].node.source_routes.get(&destination),
            Some(peers[2].node_addr())
        );
        assert!(nodes[0].node.dataplane_has_fsp_owner(&destination));
        observed.carriers.lock().unwrap().clear();

        let endpoint_payload = vec![33; 700];
        let tun_packet = build_ipv6_packet(
            &crate::FipsAddress::from_node_addr(&source),
            &crate::FipsAddress::from_node_addr(&destination),
            &[44; 700],
        );
        send_endpoint_data_via_dataplane(&mut nodes[0].node, peers[3], endpoint_payload.clone())
            .await
            .unwrap();
        send_tun_packet_via_dataplane(&mut nodes, 0, tun_packet.clone()).await;
        assert!(
            nodes[0]
                .node
                .pending_session_traffic
                .has_traffic_for(&destination)
        );
        assert_eq!(nodes[0].node.pending_session_traffic.tun_packet_count(), 1);
        assert_eq!(
            nodes[0]
                .node
                .pending_session_traffic
                .endpoint_data_for(&destination)
                .map(|queue| queue.len()),
            Some(1),
            "the original endpoint payload remains queued independently of TUN"
        );

        // Use the same retry that the runtime invokes. Neither the endpoint
        // batch nor the cached TUN route may escape over the old live relay.
        for _ in 0..3 {
            nodes[0].node.retry_pending_session_traffic().await;
            process_available_packets(&mut nodes).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert!(
                matches!(
                    endpoint.event_rx.try_recv(),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                ),
                "no endpoint fallback"
            );
            assert!(
                matches!(
                    tun_rx.try_recv_packet(),
                    Err(std::sync::mpsc::TryRecvError::Empty)
                ),
                "no TUN fallback"
            );
            assert!(
                nodes[0]
                    .node
                    .pending_session_traffic
                    .has_traffic_for(&destination)
            );
            assert_eq!(nodes[0].node.pending_session_traffic.tun_packet_count(), 1);
            assert_eq!(
                nodes[0]
                    .node
                    .pending_session_traffic
                    .endpoint_data_for(&destination)
                    .map(|queue| queue.len()),
                Some(1),
                "the original endpoint payload remains queued independently of TUN"
            );
            assert!(
                observed.carriers.lock().unwrap().is_empty(),
                "no application transport attempt on an unauthorized carrier"
            );
        }

        // Only an explicit new binding releases the originals. Do not inject
        // another payload or call flush_pending_packets to rescue the queue.
        nodes[0]
            .node
            .set_endpoint_source_route(peers[3], Some(peers[1]))
            .unwrap();
        let mut endpoint_received = false;
        let mut tun_received = false;
        tokio::time::timeout(Duration::from_secs(3), async {
            while !endpoint_received || !tun_received {
                nodes[0].node.retry_pending_session_traffic().await;
                poll_available_packets(&mut nodes).await;
                if let Ok(event) = endpoint.event_rx.try_recv() {
                    endpoint.event_rx.release_messages(event.messages.len());
                    assert!(!endpoint_received, "queued endpoint delivered only once");
                    assert_eq!(
                        expect_single_endpoint_data_event(event).payload.as_slice(),
                        endpoint_payload
                    );
                    endpoint_received = true;
                }
                if let Ok(packet) = tun_rx.try_recv_packet() {
                    assert!(!tun_received, "queued TUN packet delivered only once");
                    assert_eq!(packet.as_slice(), tun_packet);
                    tun_received = true;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("regular retry delivers both originals after explicit rebind");
        for _ in 0..3 {
            nodes[0].node.retry_pending_session_traffic().await;
            process_available_packets(&mut nodes).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            matches!(
                endpoint.event_rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "no duplicate endpoint"
        );
        assert!(
            matches!(
                tun_rx.try_recv_packet(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ),
            "no duplicate TUN packet"
        );
        assert!(
            !nodes[0]
                .node
                .pending_session_traffic
                .has_traffic_for(&destination)
        );
        assert_eq!(
            *observed.carriers.lock().unwrap(),
            BTreeSet::from([*peers[1].node_addr()]),
            "actual queued application sends use only the newly authorized carrier"
        );
        for (index, remote) in [(0, destination), (3, source)] {
            let session = nodes[index].node.get_session(&remote).unwrap();
            assert!(session.is_established());
            assert_eq!(session.handshake_hash(), Some(&session_hash));
        }
        cleanup_nodes(&mut nodes).await;
    });
}
