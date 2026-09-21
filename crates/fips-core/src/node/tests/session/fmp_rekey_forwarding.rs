//! Routed FSP traffic must survive the first pending-epoch FMP receive.
use super::*;
use crate::dataplane::FmpWireHeader;
use crate::node::EndpointDataIo;
use crate::node::tests::spanning_tree::{
    initiate_handshake, make_test_node, process_dataplane_packet, process_node_packets,
};
use crate::node::wire::FLAG_KEY_EPOCH;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use tokio::time::Instant;

const FLOWS: [(usize, usize); 6] = [(0, 2), (0, 1), (1, 0), (1, 2), (2, 1), (2, 0)];

#[test]
fn source_fmp_rekey_preserves_direct_and_routed_fsp_payloads() {
    run(true);
}

#[test]
fn direct_and_routed_fsp_payloads_continue_without_rekey() {
    run(false);
}

fn run(rekey: bool) {
    run_large_stack_async_test("routed-fsp-over-fmp-rekey", move || async move {
        let _guard = lock_large_network_test().await;
        let mut nodes = vec![
            make_test_node().await,
            make_test_node().await,
            make_test_node().await,
        ];
        // The routed source is a leaf sending towards the component's root.
        nodes.sort_by_key(|node| std::cmp::Reverse(*node.node.node_addr()));
        let result = AssertUnwindSafe(exercise(&mut nodes, rekey))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn maintenance(nodes: &mut [TestNode]) {
    for node in nodes.iter_mut() {
        node.node.check_mmp_reports().await;
        node.node.check_session_mmp_reports().await;
        node.node.send_pending_tree_announces().await;
        node.node.check_bloom_state().await;
        node.node.check_pending_lookups(Node::now_ms()).await;
        node.node
            .resend_pending_session_handshakes(Node::now_ms())
            .await;
        node.node.resend_pending_session_msg3(Node::now_ms()).await;
    }
    process_available_packets(nodes).await;
}

async fn setup(nodes: &mut [TestNode]) {
    initiate_handshake(nodes, 0, 1).await;
    initiate_handshake(nodes, 1, 2).await;
    let root = *nodes[2].node.node_addr();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        maintenance(nodes).await;
        let ready = nodes.iter().enumerate().all(|(index, node)| {
            *node.node.tree_state().root() == root
                && node.node.peers.len() == if index == 1 { 2 } else { 1 }
                && node.node.peers.connection_is_empty()
                && node.node.peers.iter().all(|(remote, peer)| {
                    peer.can_send()
                        && node.node.dataplane_fmp_has_srtt(remote)
                        && node
                            .node
                            .tree_state()
                            .peer_coords(remote)
                            .is_some_and(|coords| {
                                coords.root_id() == &root && coords.node_addr() == remote
                            })
                })
        });
        if ready {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "real UDP tree must converge before rekey"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    verify_tree_convergence(nodes);
}

async fn send(
    nodes: &mut [TestNode],
    identities: &[PeerIdentity],
    phase: u8,
    flow: (usize, usize),
) {
    let (source, destination) = flow;
    send_endpoint_data_via_dataplane(
        &mut nodes[source].node,
        identities[destination],
        vec![phase, source as u8, destination as u8],
    )
    .await
    .unwrap();
}

async fn receive_round(
    nodes: &mut [TestNode],
    endpoints: &mut [EndpointDataIo],
    identities: &[PeerIdentity],
    phase: u8,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut received = [[false; 3]; 3];
    loop {
        maintenance(nodes).await;
        for (destination, endpoint) in endpoints.iter_mut().enumerate() {
            while let Ok(event) = endpoint.event_rx.try_recv() {
                let count = event.message_count();
                for message in event.messages {
                    let bytes = message.payload.as_slice();
                    assert_eq!(bytes.len(), 3, "unexpected endpoint payload");
                    assert_eq!(bytes[0], phase, "late or duplicate earlier-round payload");
                    let source = usize::from(bytes[1]);
                    assert!(source < 3 && source != destination);
                    assert_eq!(usize::from(bytes[2]), destination);
                    assert_eq!(message.source_peer, identities[source]);
                    assert!(
                        !received[source][destination],
                        "one-shot payload delivered twice"
                    );
                    received[source][destination] = true;
                }
                // Receiving observes the event; the consumer separately owns
                // returning its bounded message credits after consumption.
                endpoint.event_rx.release_messages(count);
            }
        }
        if FLOWS
            .iter()
            .all(|&(source, destination)| received[source][destination])
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "phase {phase}: one-shot delivery stalled: {received:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn round(
    nodes: &mut [TestNode],
    endpoints: &mut [EndpointDataIo],
    identities: &[PeerIdentity],
    phase: u8,
) {
    for flow in FLOWS {
        send(nodes, identities, phase, flow).await;
    }
    receive_round(nodes, endpoints, identities, phase).await;
}

async fn exercise(nodes: &mut [TestNode], rekey: bool) {
    setup(nodes).await;
    let identities: Vec<_> = nodes
        .iter()
        .map(|node| PeerIdentity::from_pubkey_full(node.node.identity().pubkey_full()))
        .collect();
    let addresses: Vec<_> = identities.iter().map(|peer| *peer.node_addr()).collect();
    let mut endpoints: Vec<_> = nodes
        .iter_mut()
        .map(|node| node.node.attach_endpoint_data_io(16).unwrap())
        .collect();
    // Use the same endpoint binding API as an explicitly selected paid first
    // hop. Coordinates and FSP sessions still come from real network traffic.
    for (source, destination) in [(0, 2), (2, 0)] {
        nodes[source]
            .node
            .set_endpoint_source_route(identities[destination], Some(identities[1]))
            .unwrap();
    }
    round(nodes, &mut endpoints, &identities, 0).await;
    round(nodes, &mut endpoints, &identities, 1).await;
    drain_to_quiescence(nodes).await;
    let session_epochs: Vec<_> = FLOWS
        .iter()
        .map(|&(source, destination)| {
            nodes[source]
                .node
                .get_session(&addresses[destination])
                .unwrap()
                .session_start_ms()
        })
        .collect();
    let edges: Vec<_> = [(0, 1), (1, 0), (1, 2), (2, 1)]
        .into_iter()
        .map(|(local, remote)| {
            let peer = nodes[local].node.get_peer(&addresses[remote]).unwrap();
            (local, remote, peer.link_id(), peer.authenticated_at())
        })
        .collect();
    let old_indices = [
        nodes[0]
            .node
            .get_peer(&addresses[1])
            .unwrap()
            .our_index()
            .unwrap(),
        nodes[1]
            .node
            .get_peer(&addresses[0])
            .unwrap()
            .our_index()
            .unwrap(),
    ];
    let old_k = nodes[0]
        .node
        .get_peer(&addresses[1])
        .unwrap()
        .current_k_bit();
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&addresses[0])
            .unwrap()
            .current_k_bit(),
        old_k
    );
    assert_eq!(
        nodes[0].node.dataplane.fsp_owner_next_hop(&addresses[2]),
        Some(addresses[1])
    );

    if rekey {
        assert!(nodes[0].node.initiate_rekey(&addresses[1]).await);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            // No synthetic crypto/session changes: receive the real Msg1 and Msg2.
            // Do not run a report/heartbeat timer that could confirm the new epoch
            // before the routed application packet below.
            process_available_packets(nodes).await;
            if (0..2).all(|local| {
                nodes[local]
                    .node
                    .get_peer(&addresses[1 - local])
                    .unwrap()
                    .pending_new_session()
                    .is_some()
            }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "real rekey handshake must finish"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let pending_middle_index = nodes[1]
            .node
            .get_peer(&addresses[0])
            .unwrap()
            .pending_our_index()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            // Wait for the production 250 ms initiator cutover, using real time.
            nodes[0].node.check_rekey().await;
            if nodes[0]
                .node
                .get_peer(&addresses[1])
                .unwrap()
                .current_k_bit()
                != old_k
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "source must reach its real cutover"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            nodes[1]
                .node
                .get_peer(&addresses[0])
                .unwrap()
                .current_k_bit(),
            old_k
        );
        assert!(nodes[0].node.get_peer(&addresses[1]).unwrap().is_draining());
        assert!(!nodes[1].node.get_peer(&addresses[0]).unwrap().is_draining());

        // Submit the routed payload first. Observe its actual carrier flight before
        // giving the responder any new-epoch traffic; no extra heartbeat repairs it.
        send(nodes, &identities, 2, FLOWS[0]).await;
        let flight = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let source = &mut nodes[0];
                process_node_packets(&mut source.node, &mut source.packet_rx).await;
                while let Ok(packet) = nodes[1].packet_rx.try_recv() {
                    if packet.remote_addr == nodes[0].addr {
                        return packet;
                    }
                    process_dataplane_packet(&mut nodes[1], packet).await;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("routed payload must produce a real UDP carrier frame");
        let header = FmpWireHeader::parse_encrypted(flight.data.as_slice()).unwrap();
        assert_eq!(header.receiver_idx(), pending_middle_index.as_u32());
        assert_eq!(header.flags() & FLAG_KEY_EPOCH != 0, !old_k);
        assert_eq!(
            nodes[1]
                .node
                .get_peer(&addresses[0])
                .unwrap()
                .current_k_bit(),
            old_k
        );
        process_dataplane_packet(&mut nodes[1], flight).await;
        for &flow in &FLOWS[1..] {
            send(nodes, &identities, 2, flow).await;
        }
        receive_round(nodes, &mut endpoints, &identities, 2).await;
        assert_eq!(
            nodes[1]
                .node
                .get_peer(&addresses[0])
                .unwrap()
                .current_k_bit(),
            !old_k
        );
        assert!(nodes[1].node.get_peer(&addresses[0]).unwrap().is_draining());
    } else {
        // Match the cutover wait and application phase without changing keys.
        tokio::time::sleep(Duration::from_millis(250)).await;
        round(nodes, &mut endpoints, &identities, 2).await;
    }

    // Keep both direct-neighbor sessions and the routed session useful across
    // the real ten-second old-key drain, without changing any epoch timestamp.
    let started = Instant::now();
    let deadline = started + Duration::from_secs(12);
    let mut phase = 3;
    loop {
        round(nodes, &mut endpoints, &identities, phase).await;
        for node in nodes.iter_mut() {
            node.node.check_rekey().await;
        }
        if started.elapsed() >= Duration::from_secs(10)
            && (0..2).all(|local| {
                !nodes[local]
                    .node
                    .get_peer(&addresses[1 - local])
                    .unwrap()
                    .is_draining()
            })
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "old FMP epochs must drain in real time"
        );
        phase += 1;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    round(nodes, &mut endpoints, &identities, phase + 1).await;
    for local in 0..2 {
        let remote = addresses[1 - local];
        let node = &nodes[local];
        let peer = node.node.get_peer(&remote).unwrap();
        let current = peer.our_index().unwrap();
        if rekey {
            assert_ne!(current, old_indices[local]);
        } else {
            assert_eq!(current, old_indices[local]);
        }
        assert_eq!(peer.current_k_bit(), old_k ^ rekey);
        assert!(!peer.rekey_in_progress());
        assert!(peer.pending_new_session().is_none() && peer.previous_session().is_none());
        assert!(node.node.index_allocator.is_allocated(current));
        assert_eq!(
            node.node.index_allocator.is_allocated(old_indices[local]),
            !rekey
        );
        assert_eq!(
            node.node
                .peers
                .lookup_session_index((node.transport_id, old_indices[local].as_u32())),
            (!rekey).then_some(remote)
        );
        assert_eq!(
            node.node
                .peers
                .lookup_session_index((node.transport_id, current.as_u32())),
            Some(remote)
        );
        assert_eq!(
            peer.their_index(),
            nodes[1 - local]
                .node
                .get_peer(&addresses[local])
                .unwrap()
                .our_index()
        );
    }
    for (local, remote, link, authenticated_at) in edges {
        let peer = nodes[local].node.get_peer(&addresses[remote]).unwrap();
        assert_eq!(peer.link_id(), link);
        assert_eq!(peer.authenticated_at(), authenticated_at);
        assert!(nodes[local].node.peers.connection_is_empty());
    }
    for ((source, destination), epoch) in FLOWS.into_iter().zip(session_epochs) {
        assert_eq!(
            nodes[source]
                .node
                .get_session(&addresses[destination])
                .unwrap()
                .session_start_ms(),
            epoch
        );
    }
    assert_eq!(
        nodes[0].node.dataplane.fsp_owner_next_hop(&addresses[2]),
        Some(addresses[1])
    );
    assert_eq!(
        nodes[2].node.dataplane.fsp_owner_next_hop(&addresses[0]),
        Some(addresses[1])
    );
}
