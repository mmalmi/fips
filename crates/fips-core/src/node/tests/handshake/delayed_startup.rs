use super::super::spanning_tree::{
    cleanup_nodes, initiate_handshake, make_test_node, process_available_packets,
};
use super::*;
use crate::node::wire::{Msg1Header, Msg2Header};

#[test]
fn delayed_winning_initial_handshake_confirms_pending_receive_epoch() {
    super::super::session::run_large_stack_async_test("fmp-delayed-startup", || async {
        let mut nodes = vec![make_test_node().await, make_test_node().await];
        nodes.sort_by_key(|node| *node.node.node_addr());
        let addresses = [*nodes[0].node.node_addr(), *nodes[1].node.node_addr()];
        initiate_handshake(&mut nodes, 1, 0).await;
        initiate_handshake(&mut nodes, 0, 1).await;

        let first_msg1 = tokio::time::timeout(Duration::from_secs(1), nodes[0].packet_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(Msg1Header::parse(first_msg1.data.as_slice()).is_some());
        nodes[0].node.handle_msg1(first_msg1).await;

        let mut delayed_msg1 = None;
        let first_msg2 = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let packet = nodes[1].packet_rx.recv().await.unwrap();
                if Msg1Header::parse(packet.data.as_slice()).is_some() {
                    delayed_msg1 = Some(packet);
                } else if Msg2Header::parse(packet.data.as_slice()).is_some() {
                    break packet;
                }
            }
        })
        .await
        .unwrap();
        nodes[1].node.handle_msg2(first_msg2).await;

        // Authenticate the first connection before delivering the smaller
        // node's original Msg1, as can happen during simultaneous static dials.
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                process_available_packets(&mut nodes).await;
                if (0..2).all(|i| {
                    nodes[i]
                        .node
                        .dataplane_fmp_link_metrics(&addresses[1 - i], std::time::Instant::now())
                        .is_some_and(|metrics| metrics.current_epoch_authenticated)
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("initial connection must authenticate");
        let old_indices = [
            nodes[0].node.get_peer(&addresses[1]).unwrap().our_index(),
            nodes[1].node.get_peer(&addresses[0]).unwrap().our_index(),
        ];
        nodes[1]
            .node
            .handle_msg1(delayed_msg1.expect("original Msg1 retained"))
            .await;
        assert!(
            nodes[1]
                .node
                .get_peer(&addresses[0])
                .unwrap()
                .pending_new_session()
                .is_some()
        );

        let confirmed = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                process_available_packets(&mut nodes).await;
                let sender = nodes[0].node.get_peer(&addresses[1]).unwrap();
                let receiver = nodes[1].node.get_peer(&addresses[0]).unwrap();
                if sender.our_index() != old_indices[0]
                    && receiver.pending_new_session().is_none()
                    && sender.their_index() == receiver.our_index()
                    && receiver.their_index() == sender.our_index()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            confirmed.is_ok(),
            "winning full connection must confirm the pending receiver epoch: {:?}",
            (0..2)
                .map(|i| {
                    let peer = nodes[i].node.get_peer(&addresses[1 - i]).unwrap();
                    (
                        peer.our_index(),
                        peer.their_index(),
                        peer.pending_our_index(),
                        peer.current_k_bit(),
                    )
                })
                .collect::<Vec<_>>()
        );
        for i in 0..2 {
            nodes[i]
                .node
                .send_dataplane_fmp_link_plaintext(
                    &addresses[1 - i],
                    &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
                    false,
                )
                .await
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                process_available_packets(&mut nodes).await;
                if (0..2).all(|i| {
                    nodes[i]
                        .node
                        .dataplane_fmp_link_metrics(&addresses[1 - i], std::time::Instant::now())
                        .is_some_and(|metrics| metrics.current_epoch_authenticated)
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both confirmed current epochs must authenticate");
        for i in 0..2 {
            let peer = nodes[i].node.get_peer(&addresses[1 - i]).unwrap();
            assert!(
                !peer.current_k_bit(),
                "initial full connection keeps its initial flag"
            );
            assert_eq!(peer.previous_our_index(), old_indices[i]);
            assert_eq!(peer.previous_k_bit(), Some(false));
            assert!(
                nodes[i]
                    .node
                    .dataplane_fmp_link_metrics(&addresses[1 - i], std::time::Instant::now(),)
                    .is_some_and(|metrics| metrics.current_epoch_authenticated)
            );
        }
        cleanup_nodes(&mut nodes).await;
    });
}
