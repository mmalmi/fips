use super::*;
use crate::dataplane::FmpWireHeader;
use crate::node::tests::spanning_tree::{process_dataplane_completions, process_dataplane_packet};
use crate::node::wire::Msg2Header;

#[test]
fn promoted_peers_wait_for_the_held_authenticated_confirmation() {
    run_large_stack_async_test("rotation-held-confirmation", || async {
        let mut nodes = [make_test_node().await, make_test_node().await];
        let result = AssertUnwindSafe(exercise_held_confirmation(&mut nodes))
            .catch_unwind()
            .await;
        cleanup_nodes(&mut nodes).await;
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    });
}

async fn exercise_held_confirmation(nodes: &mut [TestNode; 2]) {
    let ids = [*nodes[0].node.node_addr(), *nodes[1].node.node_addr()];
    native_dial(nodes, 0, 1).await;
    let request = receive_request(&mut nodes[1], Duration::from_secs(1)).await;
    nodes[1].node.handle_msg1(request).await;

    tokio::time::timeout(Duration::from_secs(2), async {
        // Deliver only Msg2. Neither receiver dispatches encrypted traffic yet.
        let response = nodes[0].packet_rx.recv().await.unwrap();
        assert!(Msg2Header::parse(response.data.as_slice()).is_some());
        nodes[0].node.handle_msg2(response).await;
        let held = [
            nodes[0].packet_rx.recv().await.unwrap(),
            nodes[1].packet_rx.recv().await.unwrap(),
        ];
        for (i, packet) in held.iter().enumerate() {
            assert_eq!(packet.remote_addr, nodes[1 - i].addr);
            let peer = nodes[i].node.get_peer(&ids[1 - i]).unwrap();
            assert_eq!(nodes[i].node.connection_count(), 0);
            assert_eq!(peer.remote_epoch(), Some(nodes[1 - i].node.startup_epoch));
            let header = FmpWireHeader::parse_encrypted(packet.data.as_slice()).unwrap();
            assert_eq!(header.receiver_idx(), peer.our_index().unwrap().as_u32());
            let offset = usize::from(header.ciphertext_offset());
            assert!(
                peer.noise_session()
                    .unwrap()
                    .authenticate_with_counter_and_aad(
                        &packet.data.as_slice()[offset..],
                        header.counter(),
                        &packet.data.as_slice()[..offset],
                    )
                    .is_ok()
            );
            assert!(
                !nodes[i]
                    .node
                    .dataplane_fmp_link_metrics(&ids[1 - i], Instant::now())
                    .unwrap()
                    .current_epoch_authenticated
            );
        }
        // The former structural predicate is satisfied by these actual peers.
        assert!(nodes.iter().enumerate().all(|(i, node)| {
            node.node.get_peer(&ids[1 - i]).is_some() && node.node.connection_count() == 0
        }));
        assert!(
            !crossed_peers_authenticated(nodes, &ids),
            "promotion alone must not satisfy authenticated readiness"
        );

        // Move the same verified packets into production, without receiving any
        // other packet or emitting a replacement confirmation from the fixture.
        for (i, packet) in held.into_iter().enumerate() {
            process_dataplane_packet(&mut nodes[i], packet).await;
        }
        while !crossed_peers_authenticated(nodes, &ids) {
            for node in nodes.iter_mut() {
                process_dataplane_completions(&mut node.node).await;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the held confirmations must authenticate within the original two-second budget");
}
