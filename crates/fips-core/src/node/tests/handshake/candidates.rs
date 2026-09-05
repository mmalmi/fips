use super::super::spanning_tree::{
    TestNode, cleanup_nodes, make_test_node, process_available_packets,
};
use super::*;
use crate::node::wire::{Msg2Header, build_msg1};
use crate::noise::{HandshakeState, NoiseSession};
use crate::transport::{PacketBuffer, ReceivedPacket};
use std::time::Instant;

struct Candidate {
    link: LinkId,
    index: SessionIndex,
    session: NoiseSession,
    source: TransportAddr,
}

impl Candidate {
    fn frame(&mut self, transport_id: TransportId, body: &[u8]) -> ReceivedPacket {
        let mut plaintext = 1u32.to_le_bytes().to_vec();
        plaintext.extend_from_slice(body);
        let header = crate::dataplane::build_fmp_established_header(
            self.index.as_u32(),
            self.session.current_send_counter(),
            0,
            plaintext.len() as u16,
        );
        let mut wire = header.to_vec();
        wire.extend(self.session.encrypt_with_aad(&plaintext, &header).unwrap());
        ReceivedPacket::with_timestamp(
            transport_id,
            self.source.clone(),
            PacketBuffer::new(wire),
            Node::now_ms(),
        )
    }
}

async fn local_path() -> (tokio::net::UdpSocket, TransportAddr) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = TransportAddr::from_string(&socket.local_addr().unwrap().to_string());
    (socket, addr)
}

async fn request(
    node: &mut TestNode,
    remote: &Node,
    source: &TransportAddr,
    sender_index: u32,
) -> HandshakeState {
    let mut handshake =
        HandshakeState::new_initiator(remote.identity.keypair(), node.node.identity.pubkey_full());
    handshake.set_local_epoch(remote.startup_epoch);
    let msg1 = build_msg1(
        SessionIndex::new(sender_index),
        &handshake.write_message_1().unwrap(),
    );
    node.node
        .handle_msg1(ReceivedPacket::with_timestamp(
            node.transport_id,
            source.clone(),
            PacketBuffer::new(msg1),
            Node::now_ms(),
        ))
        .await;
    handshake
}

async fn connect(
    node: &mut TestNode,
    remote: &Node,
    source: &TransportAddr,
    sender_index: u32,
) -> Candidate {
    let mut handshake = request(node, remote, source, sender_index).await;
    let link = node
        .node
        .links
        .lookup_addr(node.transport_id, source)
        .unwrap();
    let msg2 = node
        .node
        .peers
        .get_connection(&link)
        .and_then(PeerConnection::handshake_msg2)
        .or_else(|| {
            node.node
                .get_peer(remote.node_addr())
                .unwrap()
                .handshake_msg2()
        })
        .unwrap();
    let header = Msg2Header::parse(msg2).unwrap();
    handshake.read_message_2(header.noise_msg2(msg2)).unwrap();
    Candidate {
        link,
        index: header.sender_idx,
        session: handshake.into_session().unwrap(),
        source: source.clone(),
    }
}

#[test]
fn inbound_candidate_limits_and_timeout_preserve_current_owner() {
    super::super::session::run_large_stack_async_test("fmp-candidate-timeout", || async {
        let mut node = make_test_node().await;
        let remote = make_node();
        let (_socket, source) = local_path().await;
        let (_other_socket, other_source) = local_path().await;
        let mut current = connect(&mut node, &remote, &source, 10).await;

        // Exercise each configured cap independently, including a candidate
        // sharing the current carrier's reverse address-dispatch slot.
        for (max_connections, max_links) in [(1, 0), (0, 2)] {
            node.node.max_connections = max_connections;
            node.node.max_links = max_links;
            let pending = connect(&mut node, &remote, &source, 11).await;
            assert_eq!(node.node.connection_count(), 1);
            assert_eq!(node.node.index_allocator.count(), 2);
            request(&mut node, &remote, &other_source, 12).await;
            assert_eq!(node.node.connection_count(), 1);
            assert_eq!(node.node.link_count(), 2);

            // A concurrent outbound completion can reclaim the reverse
            // address slot. Its shadowed candidate still owns this retry.
            let retry = node
                .node
                .get_connection(&pending.link)
                .unwrap()
                .handshake_msg1()
                .unwrap()
                .to_vec();
            node.node.restore_link_address(current.link);
            node.node.max_connections = 0;
            node.node.max_links = 0;
            node.node
                .get_connection_mut(&pending.link)
                .unwrap()
                .touch(1);
            node.node
                .handle_msg1(ReceivedPacket::with_timestamp(
                    node.transport_id,
                    source.clone(),
                    PacketBuffer::new(retry),
                    Node::now_ms(),
                ))
                .await;
            assert_eq!(
                node.node.connection_count(),
                1,
                "retry must reuse its candidate"
            );
            assert_eq!(node.node.index_allocator.count(), 2);
            node.node.check_timeouts().await;
            assert_eq!(node.node.connection_count(), 0);
            assert_eq!(node.node.index_allocator.count(), 1);
            assert_eq!(node.node.link_count(), 1);
            assert_eq!(
                node.node.links.lookup_addr(node.transport_id, &source),
                Some(current.link)
            );
            let owner = node.node.get_peer(remote.node_addr()).unwrap();
            assert_eq!(owner.our_index(), Some(current.index));
            assert!(owner.has_session() && owner.can_send());
        }

        let heartbeat = [crate::protocol::LinkMessageType::Heartbeat.to_byte()];
        let packet = current.frame(node.transport_id, &heartbeat);
        super::super::spanning_tree::process_dataplane_packet(&mut node, packet).await;
        assert_eq!(
            node.node
                .dataplane_fmp_link_metrics(remote.node_addr(), Instant::now())
                .unwrap()
                .rx_packets,
            1
        );
        cleanup_nodes(std::slice::from_mut(&mut node)).await;
    });
}

#[test]
fn inbound_candidate_confirmation_delivers_the_whole_captured_batch_once() {
    super::super::session::run_large_stack_async_test("fmp-candidate-batch", || async {
        let mut node = make_test_node().await;
        let remote = make_node();
        let (_old_socket, old_source) = local_path().await;
        let (_new_socket, new_source) = local_path().await;
        let current = connect(&mut node, &remote, &old_source, 20).await;
        let mut pending = connect(&mut node, &remote, &new_source, 21).await;
        assert_eq!(
            node.node.get_peer(remote.node_addr()).unwrap().our_index(),
            Some(current.index)
        );
        node.node
            .get_peer_mut(remote.node_addr())
            .unwrap()
            .touch(Node::now_ms() - 1_001);

        let heartbeat = [crate::protocol::LinkMessageType::Heartbeat.to_byte()];
        let announce = remote.build_tree_announce().unwrap().encode().unwrap();
        let first = pending.frame(node.transport_id, &heartbeat);
        let next = pending.frame(node.transport_id, &announce);
        // Both frames were already diverted before the first confirms.
        assert!(node.node.confirm_inbound_handshake(first).await);
        assert!(node.node.confirm_inbound_handshake(next).await);
        assert_eq!(node.node.connection_count(), 0);
        assert_eq!(
            node.node.get_peer(remote.node_addr()).unwrap().our_index(),
            Some(pending.index)
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                process_available_packets(std::slice::from_mut(&mut node)).await;
                if node
                    .node
                    .get_peer(remote.node_addr())
                    .unwrap()
                    .coords()
                    .is_some()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the following TreeAnnounce must reach the normal handler");
        process_available_packets(std::slice::from_mut(&mut node)).await;
        let metrics = node
            .node
            .dataplane_fmp_link_metrics(remote.node_addr(), Instant::now())
            .unwrap();
        assert_eq!(
            metrics.rx_packets, 2,
            "confirmation must not count the first frame twice"
        );
        assert_eq!(
            node.node.get_peer(remote.node_addr()).unwrap().coords(),
            Some(remote.tree_state().my_coords())
        );
        cleanup_nodes(std::slice::from_mut(&mut node)).await;
    });
}

#[test]
fn inbound_candidate_from_before_a_completed_restart_is_cleaned_up() {
    super::super::session::run_large_stack_async_test("fmp-candidate-restart", || async {
        let mut node = make_test_node().await;
        let mut remote = make_node();
        let (_old_socket, old_source) = local_path().await;
        let (_pending_socket, pending_source) = local_path().await;
        let (_new_socket, new_source) = local_path().await;
        connect(&mut node, &remote, &old_source, 30).await;
        let mut pending = connect(&mut node, &remote, &pending_source, 31).await;
        remote.startup_epoch[0] ^= 1;
        node.node
            .get_peer_mut(remote.node_addr())
            .unwrap()
            .touch(Node::now_ms() - 60_000);
        let current = connect(&mut node, &remote, &new_source, 32).await;
        let heartbeat = [crate::protocol::LinkMessageType::Heartbeat.to_byte()];
        let late_confirmation = pending.frame(node.transport_id, &heartbeat);
        assert!(!node.node.confirm_inbound_handshake(late_confirmation).await);
        assert_eq!(node.node.connection_count(), 0);
        assert_eq!(node.node.index_allocator.count(), 1);
        assert_eq!(node.node.link_count(), 1);
        let owner = node.node.get_peer(remote.node_addr()).unwrap();
        assert_eq!(owner.our_index(), Some(current.index));
        assert_eq!(owner.remote_epoch(), Some(remote.startup_epoch));
        cleanup_nodes(std::slice::from_mut(&mut node)).await;
    });
}
