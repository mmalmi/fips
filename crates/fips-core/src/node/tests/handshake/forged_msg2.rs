use super::*;
use crate::node::tests::spanning_tree::{
    TestNode, cleanup_nodes, initiate_handshake, make_test_node, run_tree_test,
};
use crate::node::wire::{Msg1Header, Msg2Header};
use crate::transport::{PacketBuffer, ReceivedPacket};

async fn receive_handshake(node: &mut TestNode, msg2: bool) -> ReceivedPacket {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let packet = node
                .packet_rx
                .recv()
                .await
                .expect("UDP channel remains open");
            let matches = if msg2 {
                Msg2Header::parse(packet.data.as_slice()).is_some()
            } else {
                Msg1Header::parse(packet.data.as_slice()).is_some()
            };
            if matches {
                return packet;
            }
        }
    })
    .await
    .expect("handshake must arrive on the actual UDP transport")
}

fn forged_reply(reply: &ReceivedPacket, invalid_ephemeral: bool) -> ReceivedPacket {
    let mut bytes = reply.data.as_slice().to_vec();
    let offset = Msg2Header::parse(&bytes).unwrap().noise_msg2_offset;
    if invalid_ephemeral {
        bytes[offset..offset + crate::noise::PUBKEY_SIZE].fill(0);
    } else {
        // A valid ephemeral followed by a bad tag exercises rollback after
        // the read has already changed its transcript and cipher state.
        *bytes.last_mut().unwrap() ^= 1;
    }
    ReceivedPacket::with_timestamp(
        reply.transport_id,
        TransportAddr::from_string("127.0.0.1:9"),
        PacketBuffer::new(bytes),
        reply.timestamp_ms.saturating_add(1_000),
    )
}

#[test]
fn forged_msg2_preserves_initial_dial_until_the_genuine_reply() {
    super::super::session::run_large_stack_async_test("forged-initial-msg2", || async {
        let mut nodes = vec![make_test_node().await, make_test_node().await];
        initiate_handshake(&mut nodes, 0, 1).await;
        let msg1 = receive_handshake(&mut nodes[1], false).await;
        nodes[1].node.handle_msg1(msg1).await;
        let genuine = receive_handshake(&mut nodes[0], true).await;
        let header = Msg2Header::parse(genuine.data.as_slice()).unwrap();
        let key = (genuine.transport_id, header.receiver_idx.as_u32());
        let link = *nodes[0].node.pending_outbound.get(&key).unwrap();
        let connection = nodes[0].node.peers.get_connection(&link).unwrap();
        let original = (
            connection.started_at(),
            connection.last_activity(),
            connection.resend_count(),
            connection.source_addr().cloned(),
        );

        for invalid_ephemeral in [false, true, false] {
            nodes[0]
                .node
                .handle_msg2(forged_reply(&genuine, invalid_ephemeral))
                .await;
            let connection = nodes[0].node.peers.get_connection(&link).unwrap();
            assert_eq!(
                connection.handshake_state(),
                crate::peer::HandshakeState::SentMsg1
            );
            assert_eq!(nodes[0].node.pending_outbound.get(&key), Some(&link));
            assert_eq!(
                (
                    connection.started_at(),
                    connection.last_activity(),
                    connection.resend_count(),
                    connection.source_addr().cloned()
                ),
                original,
                "untrusted replies cannot refresh the deadline or replace the dial path"
            );
            assert!(!connection.has_session());
        }

        nodes[0].node.handle_msg2(genuine).await;
        let remote = *nodes[1].node.node_addr();
        assert!(nodes[0].node.get_peer(&remote).unwrap().has_session());
        assert!(!nodes[0].node.pending_outbound.contains_key(&key));
        cleanup_nodes(&mut nodes).await;
    });
}

#[test]
fn forged_msg2_preserves_rekey_and_bidirectional_cutover() {
    super::super::session::run_large_stack_async_test("forged-rekey-msg2", || async {
        let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
        let remote = *nodes[1].node.node_addr();
        nodes[0].node.config.node.rekey.after_secs = 0;
        nodes[0]
            .node
            .get_peer_mut(&remote)
            .unwrap()
            .set_rekey_jitter_secs_for_test(0);
        nodes[0].node.check_rekey().await;
        let msg1 = receive_handshake(&mut nodes[1], false).await;
        nodes[1].node.handle_msg1(msg1).await;
        let genuine = receive_handshake(&mut nodes[0], true).await;
        let header = Msg2Header::parse(genuine.data.as_slice()).unwrap();
        let key = (genuine.transport_id, header.receiver_idx.as_u32());
        let dispatch = *nodes[0].node.pending_outbound.get(&key).unwrap();
        let peer = nodes[0].node.get_peer(&remote).unwrap();
        let original_msg1 = peer.rekey_msg1().unwrap().to_vec();
        let original_index = peer.our_index();

        for invalid_ephemeral in [false, true, false] {
            nodes[0]
                .node
                .handle_msg2(forged_reply(&genuine, invalid_ephemeral))
                .await;
            let peer = nodes[0].node.get_peer(&remote).unwrap();
            assert_eq!(peer.rekey_msg1(), Some(original_msg1.as_slice()));
            assert_eq!(peer.rekey_msg1_resend_count(), 0);
            assert_eq!(peer.our_index(), original_index);
            assert!(peer.pending_new_session().is_none());
            assert_eq!(nodes[0].node.pending_outbound.get(&key), Some(&dispatch));
        }

        nodes[0].node.handle_msg2(genuine).await;
        assert!(
            nodes[0]
                .node
                .get_peer(&remote)
                .unwrap()
                .pending_new_session()
                .is_some()
        );
        super::early_rekey::complete_rekey(&mut nodes).await;
        assert_ne!(
            nodes[0].node.get_peer(&remote).unwrap().our_index(),
            original_index
        );
        cleanup_nodes(&mut nodes).await;
    });
}
