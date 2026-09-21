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
                heartbeat(&mut node, &protected, &mut protected_owner, 2).await,
                2
            );
            assert_eq!(
                node.node.get_peer(newcomer.node_addr()).unwrap().link_id(),
                candidate.link
            );
            assert_eq!(heartbeat(&mut node, &newcomer, &mut candidate, 1).await, 1);
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

#[test]
fn expired_rotation_attempt_does_not_block_active_peer_alternate_carrier_response() {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-expired-maintenance-response",
        || async {
            let mut node = make_test_node().await;
            let old = make_node();
            let newcomer = make_node();
            let (_old_socket, old_source) = local_path().await;
            let (first_socket, first_source) = local_path().await;
            let (alternate_socket, alternate_source) = local_path().await;
            // Use real Noise ownership and real elapsed age, including the
            // first incumbent. No timestamp or session state is manufactured.
            let mut old_owner = incumbent(&mut node, &old, &old_source, 160, 0).await;
            enable(&mut node, 1);
            node.node.config.node.rate_limit.handshake_timeout_secs = 2;
            node.node.config.node.rekey.enabled = false;
            tokio::time::sleep(Duration::from_millis(1_050)).await;
            assert!(node.node.has_neighbor_rotation_opportunity(Node::now_ms()));

            let mut candidate = connect(&mut node, &newcomer, &first_source, 161).await;
            let started = node
                .node
                .neighbor_rotation_started_at(newcomer.node_addr())
                .expect("full-roster candidate owns the original rotation attempt");
            let initial_response = retained_response(&first_socket).await;
            assert_eq!(
                initial_response.as_slice(),
                node.node
                    .get_connection(&candidate.link)
                    .unwrap()
                    .handshake_msg2()
                    .unwrap()
            );
            assert_eq!(resources(&node), (1, 1, 2, 2));
            assert!(node.node.get_peer(newcomer.node_addr()).is_none());

            // The incumbent leaves before the candidate's confirmation. The
            // candidate therefore fills an empty slot rather than committing
            // a rotation; its original exploration bookkeeping can remain.
            let disconnect =
                crate::protocol::Disconnect::new(crate::protocol::DisconnectReason::Shutdown);
            let departure = old_owner.frame(node.transport_id, &disconnect.encode());
            super::super::super::super::spanning_tree::process_dataplane_packet(
                &mut node, departure,
            )
            .await;
            tokio::time::timeout(Duration::from_secs(1), async {
                while node.node.get_peer(old.node_addr()).is_some() {
                    super::super::super::super::spanning_tree::process_dataplane_completions(
                        &mut node.node,
                    )
                    .await;
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("authenticated incumbent departure must free the active slot");
            assert_eq!(resources(&node), (0, 1, 1, 1));
            let proof = candidate.frame(
                node.transport_id,
                &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
            );
            assert!(node.node.confirm_pending_handshake(proof).await);
            process_available_packets(std::slice::from_mut(&mut node)).await;
            assert_eq!(await_heartbeat(&mut node, &newcomer, 1).await, 1);
            assert_eq!(resources(&node), (1, 0, 1, 1));
            let active = node.node.get_peer(newcomer.node_addr()).unwrap();
            let original_owner = (
                active.link_id(),
                active.our_index(),
                active.their_index(),
                active.session_generation(),
                active.remote_epoch(),
            );
            assert_eq!(original_owner.0, candidate.link);

            tokio::time::timeout(Duration::from_secs(3), async {
                while Node::now_ms().saturating_sub(started) <= 2_100 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            node.node.check_timeouts().await;

            // A real fresh Noise request on a new UDP source is ordinary
            // maintenance of this active identity, not the expired attempt.
            let mut handshake = request(&mut node, &newcomer, &alternate_source, 162).await;
            assert_eq!(resources(&node), (1, 1, 2, 2));
            let active = node.node.get_peer(newcomer.node_addr()).unwrap();
            assert_eq!(
                (
                    active.link_id(),
                    active.our_index(),
                    active.their_index(),
                    active.session_generation(),
                    active.remote_epoch(),
                ),
                original_owner,
                "replayable Msg1 must preserve current keys until fresh proof"
            );
            let response = retained_response(&alternate_socket).await;
            let header = Msg2Header::parse(&response).unwrap();
            assert_eq!(header.receiver_idx, SessionIndex::new(162));
            handshake
                .read_message_2(header.noise_msg2(&response))
                .unwrap();
            let link = node
                .node
                .links
                .lookup_addr(node.transport_id, &alternate_source)
                .unwrap();
            let mut replacement = Candidate {
                link,
                index: header.sender_idx,
                session: handshake.into_session().unwrap(),
                source: alternate_source,
            };
            let proof = replacement.frame(
                node.transport_id,
                &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
            );
            assert!(node.node.confirm_pending_handshake(proof).await);
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    process_available_packets(std::slice::from_mut(&mut node)).await;
                    if node
                        .node
                        .dataplane_fmp_link_metrics(newcomer.node_addr(), Instant::now())
                        .is_some_and(|metrics| metrics.current_epoch_authenticated)
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("fresh proof authenticates the replacement's actual current FMP keys");
            // Same-epoch path replacement deliberately retains the old receive
            // index during its normal drain; it is owned, not a pending leak.
            assert_eq!(resources(&node), (1, 0, 1, 2));
            let active = node.node.get_peer(newcomer.node_addr()).unwrap();
            assert_eq!(active.link_id(), replacement.link);
            assert_eq!(active.our_index(), Some(replacement.index));
            assert_eq!(active.previous_our_index(), Some(candidate.index));
            assert_eq!(active.remote_epoch(), Some(newcomer.startup_epoch));
            assert_eq!(
                node.node
                    .peers
                    .lookup_session_index((node.transport_id, candidate.index.as_u32())),
                Some(*newcomer.node_addr())
            );
            let received = node
                .node
                .dataplane_fmp_link_metrics(newcomer.node_addr(), Instant::now())
                .unwrap()
                .rx_packets;
            assert_eq!(
                heartbeat(&mut node, &newcomer, &mut replacement, received + 1).await,
                received + 1
            );
            cleanup_nodes(std::slice::from_mut(&mut node)).await;
        },
    );
}

async fn retained_response(socket: &tokio::net::UdpSocket) -> Vec<u8> {
    let mut response = [0; 512];
    let length = tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut response))
        .await
        .expect("ordinary maintenance must advertise Msg2 despite an expired rotation attempt")
        .unwrap();
    response[..length].to_vec()
}
