use super::*;
use crate::node::EndpointDataIo;
use crate::node::tests::session::send_endpoint_data_via_dataplane;
use crate::node::tests::spanning_tree::{process_available_packets, process_dataplane_packet};
use crate::node::wire::{Msg1Header, Msg2Header};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;

#[test]
fn fresh_ble_carrier_recovers_while_fmp_rekey_owns_the_old_path() {
    run(false);
}

#[test]
fn fresh_ble_carrier_recovers_after_unconfirmed_fmp_cutover() {
    run(true);
}

fn run(cutover: bool) {
    super::super::session::run_large_stack_async_test(
        "ble-reconnect-pending-fmp",
        move || async move {
            let mut nodes = vec![
                make_discovering_test_node_ble(1).await,
                make_discovering_test_node_ble(2).await,
            ];
            nodes.sort_by_key(|node| *node.node.node_addr());
            let result = AssertUnwindSafe(exercise(&mut nodes, cutover))
                .catch_unwind()
                .await;
            cleanup_nodes(&mut nodes).await;
            if let Err(panic) = result {
                std::panic::resume_unwind(panic);
            }
        },
    );
}

async fn exercise(nodes: &mut [TestNode], cutover: bool) {
    let bank: StreamBank = Arc::new(StdMutex::new(HashMap::new()));
    wire_ble_connection(nodes, 0, 1, &bank).await;
    install_connect_handler(nodes, 0, &bank);
    establish_ble_connection(nodes, 0, 1).await;
    initiate_handshake(nodes, 0, 1).await;
    drain_all_packets(nodes, false).await;

    let identities: Vec<_> = nodes
        .iter()
        .map(|node| PeerIdentity::from_pubkey_full(node.node.identity.pubkey_full()))
        .collect();
    let mut endpoints: Vec<_> = nodes
        .iter_mut()
        .map(|node| node.node.attach_endpoint_data_io(8).unwrap())
        .collect();
    round(nodes, &mut endpoints, &identities, 0).await;
    drain_all_packets(nodes, false).await;
    for node in nodes.iter() {
        node.node.transports[&node.transport_id].discover().unwrap();
    }

    let remote = *identities[1].node_addr();
    assert!(nodes[0].node.initiate_rekey(&remote).await);
    let pending_index = nodes[0]
        .node
        .get_peer(&remote)
        .unwrap()
        .rekey_our_index()
        .unwrap();
    assert!(nodes[0].node.index_allocator.is_allocated(pending_index));
    assert!(
        nodes[0]
            .node
            .pending_outbound
            .contains_key(&(nodes[0].transport_id, pending_index.as_u32()))
    );
    let msg1 = handshake_packet(&mut nodes[1], true).await;
    assert_eq!(
        Msg1Header::parse(msg1.data.as_slice()).unwrap().sender_idx,
        pending_index
    );
    let abandoned_responder_index = if cutover {
        // Complete real Noise, then let only the initiator's real 250 ms timer
        // run. No new-K receive is processed at either endpoint before loss.
        process_dataplane_packet(&mut nodes[1], msg1).await;
        let msg2 = handshake_packet(&mut nodes[0], false).await;
        assert_eq!(
            Msg2Header::parse(msg2.data.as_slice())
                .unwrap()
                .receiver_idx,
            pending_index
        );
        process_dataplane_packet(&mut nodes[0], msg2).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                nodes[0].node.check_rekey().await;
                if nodes[0].node.get_peer(&remote).unwrap().is_draining() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("initiator must reach its real FMP cutover");
        let source = nodes[0].node.get_peer(&remote).unwrap();
        assert_eq!(source.our_index(), Some(pending_index));
        assert!(source.pending_new_session().is_none());
        assert!(
            !nodes[0]
                .node
                .dataplane_fmp_link_metrics(&remote, std::time::Instant::now())
                .unwrap()
                .current_epoch_authenticated
        );
        let responder = nodes[1].node.get_peer(identities[0].node_addr()).unwrap();
        assert!(!responder.is_draining());
        assert!(responder.pending_new_session().is_some());
        Some(responder.pending_our_index().unwrap())
    } else {
        // Lose the real Msg1 while its advertised receiver index remains owned.
        drop(msg1);
        assert!(nodes[0].node.get_peer(&remote).unwrap().rekey_in_progress());
        None
    };
    let current: Vec<_> = nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let peer = node.node.get_peer(identities[1 - i].node_addr()).unwrap();
            (peer.link_id(), peer.our_index(), peer.session_generation())
        })
        .collect();

    for i in 0..2 {
        let TransportHandle::Ble(transport) = &nodes[i].node.transports[&nodes[i].transport_id]
        else {
            panic!("expected BLE transport");
        };
        transport.close_connection_async(&nodes[1 - i].addr).await;
    }
    // Physical loss also drops any queued frames from that old mock stream.
    // In particular, they must not accidentally confirm the held new epoch.
    for node in nodes.iter_mut() {
        while node.packet_rx.try_recv().is_ok() {}
    }
    wire_ble_connection(nodes, 0, 1, &bank).await;
    let TransportHandle::Ble(transport) = &nodes[0].node.transports[&nodes[0].transport_id] else {
        panic!("expected BLE transport");
    };
    transport
        .io()
        .inject_scan_result(node_ble_addr(&nodes[1]))
        .await;

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            // This is the production discovery entry point, including its
            // fresh BLE incarnation exception to same-path handshake ownership.
            nodes[0].node.poll_transport_discovery().await;
            if !nodes[0].node.pending_connects.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("fresh BLE discovery must not wait for the old FMP rekey timeout");
    assert_eq!(nodes[0].node.pending_connects.len(), 1);
    for (i, node) in nodes.iter().enumerate() {
        let peer = node.node.get_peer(identities[1 - i].node_addr()).unwrap();
        assert_eq!(
            (peer.link_id(), peer.our_index(), peer.session_generation()),
            current[i],
            "discovery must retain the old current key owner before fresh Noise succeeds"
        );
    }

    nodes[0].node.poll_pending_connects().await;
    assert!(nodes[0].node.pending_connects.is_empty());
    let refresh_index = nodes[0]
        .node
        .peers
        .connection_values()
        .next()
        .expect("fresh carrier must own a normal Noise handshake")
        .our_index()
        .unwrap();
    assert_ne!(refresh_index, pending_index);
    let msg1 = handshake_packet(&mut nodes[1], true).await;
    assert_eq!(
        Msg1Header::parse(msg1.data.as_slice()).unwrap().sender_idx,
        refresh_index
    );
    process_dataplane_packet(&mut nodes[1], msg1).await;
    let msg2 = handshake_packet(&mut nodes[0], false).await;
    assert_eq!(
        Msg2Header::parse(msg2.data.as_slice())
            .unwrap()
            .receiver_idx,
        refresh_index
    );
    process_dataplane_packet(&mut nodes[0], msg2).await;
    authenticate_current_fmp(nodes, &identities).await;
    round(nodes, &mut endpoints, &identities, 1).await;

    assert_index_retired_or_owned(&nodes[0], &remote, pending_index, cutover);
    if let Some(index) = abandoned_responder_index {
        assert_index_retired_or_owned(&nodes[1], identities[0].node_addr(), index, true);
    }
    if cutover {
        // A valid replacement may retain the previous current key during its
        // normal drain. Advance real time, then prove those old keys retire.
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                for node in nodes.iter_mut() {
                    node.node.check_rekey().await;
                }
                process_available_packets(nodes).await;
                if nodes.iter().enumerate().all(|(i, node)| {
                    !node
                        .node
                        .get_peer(identities[1 - i].node_addr())
                        .unwrap()
                        .is_draining()
                }) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("replacement's old FMP receive keys must drain in real time");
        authenticate_current_fmp(nodes, &identities).await;
        round(nodes, &mut endpoints, &identities, 2).await;
        assert_index_retired_or_owned(&nodes[0], &remote, pending_index, true);
        assert_index_retired_or_owned(
            &nodes[1],
            identities[0].node_addr(),
            abandoned_responder_index.unwrap(),
            true,
        );
    }
    for (i, node) in nodes.iter().enumerate() {
        let peer = node.node.get_peer(identities[1 - i].node_addr()).unwrap();
        assert!(peer.can_send());
        assert!(!peer.rekey_in_progress());
        assert!(node.node.peers.connection_is_empty());
        assert!(node.node.pending_connects.is_empty());
        assert!(node.node.pending_outbound.is_empty());
        // A normally owned pending/draining receive epoch may remain after the
        // fresh exchange. Every allocated index must still have that exact owner.
        let owned: std::collections::HashSet<_> = [
            peer.our_index(),
            peer.previous_our_index(),
            peer.pending_our_index(),
        ]
        .into_iter()
        .flatten()
        .collect();
        assert_eq!(node.node.index_allocator.count(), owned.len());
        for index in owned {
            assert!(node.node.index_allocator.is_allocated(index));
        }
    }
}

fn assert_index_retired_or_owned(
    node: &TestNode,
    remote: &NodeAddr,
    index: crate::utils::index::SessionIndex,
    allow_owned: bool,
) {
    let peer = node.node.get_peer(remote).unwrap();
    let owned = allow_owned
        && (peer.our_index() == Some(index) || peer.previous_our_index() == Some(index));
    assert_eq!(node.node.index_allocator.is_allocated(index), owned);
    assert_eq!(
        node.node
            .peers
            .lookup_session_index((node.transport_id, index.as_u32())),
        owned.then_some(*remote),
        "superseded indices may remain only as an actual current or draining receiver"
    );
}

fn paired_current_keys(nodes: &[TestNode], identities: &[PeerIdentity]) -> bool {
    let left = nodes[0].node.get_peer(identities[1].node_addr()).unwrap();
    let right = nodes[1].node.get_peer(identities[0].node_addr()).unwrap();
    left.our_index() == right.their_index()
        && left.their_index() == right.our_index()
        && left.current_k_bit() == right.current_k_bit()
        && nodes.iter().enumerate().all(|(i, node)| {
            node.node
                .dataplane_fmp_link_metrics(
                    identities[1 - i].node_addr(),
                    std::time::Instant::now(),
                )
                .is_some_and(|metrics| metrics.current_epoch_authenticated)
        })
}

async fn authenticate_current_fmp(nodes: &mut [TestNode], identities: &[PeerIdentity]) {
    // Direct FSP can survive even with broken link keys. Send actual encrypted
    // FMP in each direction and require current-epoch authentication plus the
    // exact reciprocal receive indices, not merely endpoint payload delivery.
    for source in 0..2 {
        nodes[source]
            .node
            .send_dataplane_fmp_link_plaintext(
                identities[1 - source].node_addr(),
                &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
                false,
            )
            .await
            .unwrap();
        for _ in 0..3 {
            process_available_packets(nodes).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            process_available_packets(nodes).await;
            if paired_current_keys(nodes, identities) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let snapshot: Vec<_> = nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let remote = identities[1 - i].node_addr();
            let peer = node.node.get_peer(remote).unwrap();
            (
                peer.our_index(),
                peer.their_index(),
                peer.pending_our_index(),
                peer.previous_our_index(),
                peer.current_k_bit(),
                node.node
                    .dataplane_fmp_link_metrics(remote, std::time::Instant::now())
                    .map(|metrics| metrics.current_epoch_authenticated),
            )
        })
        .collect();
    assert!(
        result.is_ok(),
        "fresh BLE FMP keys did not pair/authenticate: {snapshot:?}"
    );
}

async fn handshake_packet(node: &mut TestNode, msg1: bool) -> crate::transport::ReceivedPacket {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let packet = node
                .packet_rx
                .recv()
                .await
                .expect("BLE packet channel open");
            let matches = if msg1 {
                Msg1Header::parse(packet.data.as_slice()).is_some()
            } else {
                Msg2Header::parse(packet.data.as_slice()).is_some()
            };
            if matches {
                return packet;
            }
            process_dataplane_packet(node, packet).await;
        }
    })
    .await
    .expect("real BLE Noise flight must arrive")
}

async fn round(
    nodes: &mut [TestNode],
    endpoints: &mut [EndpointDataIo],
    identities: &[PeerIdentity],
    phase: u8,
) {
    for source in 0..2 {
        send_endpoint_data_via_dataplane(
            &mut nodes[source].node,
            identities[1 - source],
            vec![phase, source as u8],
        )
        .await
        .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut received = [false; 2];
        loop {
            for node in nodes.iter_mut() {
                node.node.poll_pending_connects().await;
                node.node.resend_pending_handshakes(Node::now_ms()).await;
                node.node
                    .resend_pending_session_handshakes(Node::now_ms())
                    .await;
                node.node.resend_pending_session_msg3(Node::now_ms()).await;
                node.node.check_mmp_reports().await;
                node.node.check_session_mmp_reports().await;
            }
            process_available_packets(nodes).await;
            for (destination, endpoint) in endpoints.iter_mut().enumerate() {
                while let Ok(event) = endpoint.event_rx.try_recv() {
                    let count = event.message_count();
                    for message in event.messages {
                        assert_eq!(message.source_peer, identities[1 - destination]);
                        assert_eq!(
                            message.payload.as_slice(),
                            &[phase, (1 - destination) as u8]
                        );
                        assert!(!received[destination], "duplicate application payload");
                        received[destination] = true;
                    }
                    endpoint.event_rx.release_messages(count);
                }
            }
            if received.iter().all(|received| *received) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("original endpoint sessions must deliver on the replacement BLE stream");
}
