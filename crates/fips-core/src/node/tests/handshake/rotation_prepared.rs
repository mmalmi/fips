use super::*;
use crate::PromotionResult;
use crate::config::TcpConfig;
use crate::dataplane::FmpWireHeader;
use crate::transport::tcp::TcpTransport;
use crate::transport::{TransportHandle, packet_channel};
use tokio::io::AsyncWriteExt;

fn authenticate_confirmation(node: &mut TestNode, remote: &Node, candidate: &mut Candidate) {
    let proof = candidate.frame(
        node.transport_id,
        &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
    );
    let frame = proof.data.as_slice();
    let header = FmpWireHeader::parse_encrypted(frame).unwrap();
    let offset = usize::from(header.ciphertext_offset());
    // Exercise the real Noise proof before pausing at the prepared-decision
    // boundary. The full handler otherwise immediately prepares and promotes.
    node.node
        .peers
        .get_connection(&candidate.link)
        .unwrap()
        .session()
        .unwrap()
        .authenticate_with_counter_and_aad(&frame[offset..], header.counter(), &frame[..offset])
        .unwrap();
    node.node
        .confirm_neighbor_rotation_candidate(remote.node_addr(), candidate.link);
}

#[test]
fn prepared_rotation_keeps_exact_victim_after_demand_and_attempt_age_change() {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-prepared-victim",
        || async {
            let mut node = make_test_node().await;
            let selected = make_node();
            let protected = make_node();
            let newcomer = make_node();
            let (_selected_socket, selected_source) = local_path().await;
            let (_protected_socket, protected_source) = local_path().await;
            let (_new_socket, new_source) = local_path().await;
            let selected_owner =
                incumbent(&mut node, &selected, &selected_source, 100, 60_000).await;
            let mut protected_owner =
                incumbent(&mut node, &protected, &protected_source, 101, 70_000).await;
            enable(&mut node, 2);
            node.node.config.node.rate_limit.handshake_timeout_secs = 1;
            let demand_at = Node::now_ms();
            node.node
                .record_peer_transit_demand(protected.node_addr(), demand_at);
            let protected_peer = node.node.get_peer(protected.node_addr()).unwrap();
            let protected_generation = protected_peer.session_generation();
            let protected_epoch = protected_peer.remote_epoch();
            assert!(
                protected_peer.authenticated_at()
                    < node
                        .node
                        .get_peer(selected.node_addr())
                        .unwrap()
                        .authenticated_at()
            );
            let mut candidate = connect(&mut node, &newcomer, &new_source, 102).await;
            authenticate_confirmation(&mut node, &newcomer, &mut candidate);
            assert!(node.node.peer_has_application_demand(
                protected.node_addr(),
                Node::now_ms(),
                1000
            ));
            let identity = PeerIdentity::from_pubkey_full(newcomer.identity.pubkey_full());
            let prepared = node
                .node
                .prepare_neighbor_rotation_promotion(candidate.link, &identity)
                .await
                .expect("fresh confirmed candidate has one eligible victim");
            let prepared_at = Node::now_ms();

            // Model elapsed pool-wait time after the replacement was chosen.
            // Neither the candidate proof nor peer/session state is fabricated.
            tokio::time::timeout(Duration::from_secs(3), async {
                while Node::now_ms().saturating_sub(prepared_at) <= 1100 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert!(!node.node.peer_has_application_demand(
                protected.node_addr(),
                Node::now_ms(),
                1000
            ));
            assert!(
                node.node
                    .choose_neighbor_rotation_promotion(candidate.link, &identity)
                    .is_none(),
                "a fresh selection now rejects the expired attempt"
            );
            node.node.unregister_handshake_candidate(candidate.link);
            assert!(matches!(
                node.node
                    .promote_connection_with_rotation(
                        candidate.link,
                        identity,
                        Node::now_ms(),
                        Some(prepared),
                    )
                    .unwrap(),
                PromotionResult::Promoted(_)
            ));
            assert_eq!(resources(&node), (2, 0, 2, 2));
            assert!(node.node.get_peer(selected.node_addr()).is_none());
            assert!(!node.node.index_allocator.is_allocated(selected_owner.index));
            let retained = node.node.get_peer(protected.node_addr()).unwrap();
            assert_eq!(retained.link_id(), protected_owner.link);
            assert_eq!(retained.our_index(), Some(protected_owner.index));
            assert_eq!(retained.session_generation(), protected_generation);
            assert_eq!(retained.remote_epoch(), protected_epoch);
            assert_eq!(
                heartbeat(&mut node, &protected, &mut protected_owner).await,
                2
            );
            assert_eq!(
                node.node.get_peer(newcomer.node_addr()).unwrap().link_id(),
                candidate.link
            );
            assert_eq!(heartbeat(&mut node, &newcomer, &mut candidate).await, 1);
            cleanup_nodes(std::slice::from_mut(&mut node)).await;
        },
    );
}

#[test]
fn incomplete_or_wrong_identity_preparation_preserves_real_tcp_incumbent() {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-prepared-invalid-carrier",
        || async {
            let mut node = make_test_node().await;
            let old = make_node();
            let newcomer = make_node();
            let wrong = make_node();
            let tcp_id = TransportId::new(2);
            let (tx, mut rx) = packet_channel(16);
            let mut tcp = TcpTransport::new(
                tcp_id,
                None,
                TcpConfig {
                    bind_addr: Some("127.0.0.1:0".into()),
                    max_inbound_connections: Some(2),
                    ..Default::default()
                },
                tx,
            );
            tcp.start_async().await.unwrap();
            let listen = tcp.local_addr().unwrap();
            let stats = tcp.stats().clone();
            node.node
                .transports
                .insert(tcp_id, TransportHandle::Tcp(tcp));
            let (mut old_stream, mut old_owner) = rotation_success_carrier::tcp_candidate(
                &mut node, &mut rx, tcp_id, listen, &old, 110, 60_000,
            )
            .await;
            enable(&mut node, 1);
            let (_new_stream, mut candidate) = rotation_success_carrier::tcp_candidate(
                &mut node, &mut rx, tcp_id, listen, &newcomer, 111, 0,
            )
            .await;
            authenticate_confirmation(&mut node, &newcomer, &mut candidate);
            let identity = PeerIdentity::from_pubkey_full(newcomer.identity.pubkey_full());
            let wrong_identity = PeerIdentity::from_pubkey_full(wrong.identity.pubkey_full());
            assert!(
                node.node
                    .prepare_neighbor_rotation_promotion(candidate.link, &wrong_identity)
                    .await
                    .is_none()
            );

            let complete = node.node.peers.remove_connection(&candidate.link).unwrap();
            let mut incomplete = PeerConnection::outbound(candidate.link, identity, Node::now_ms());
            incomplete.set_our_index(candidate.index);
            incomplete.set_their_index(SessionIndex::new(111));
            incomplete.set_transport_id(tcp_id);
            incomplete.set_source_addr(candidate.source.clone());
            node.node
                .peers
                .insert_connection(candidate.link, incomplete);
            assert!(
                node.node
                    .prepare_neighbor_rotation_promotion(candidate.link, &identity)
                    .await
                    .is_none()
            );
            node.node.peers.remove_connection(&candidate.link).unwrap();
            node.node.peers.insert_connection(candidate.link, complete);

            assert_eq!(resources(&node), (1, 1, 2, 2));
            assert_eq!(stats.snapshot().pool_inbound, 2);
            assert_eq!(
                node.node.get_peer(old.node_addr()).unwrap().our_index(),
                Some(old_owner.index)
            );
            let heartbeat = old_owner.frame(
                tcp_id,
                &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
            );
            old_stream
                .write_all(heartbeat.data.as_slice())
                .await
                .unwrap();
            let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received.remote_addr, old_owner.source);
            super::super::super::super::spanning_tree::process_dataplane_packet(
                &mut node, received,
            )
            .await;
            assert_eq!(
                node.node
                    .dataplane_fmp_link_metrics(old.node_addr(), Instant::now())
                    .unwrap()
                    .rx_packets,
                1
            );
            assert_eq!(stats.snapshot().pool_inbound, 2);
            cleanup_nodes(std::slice::from_mut(&mut node)).await;
        },
    );
}
