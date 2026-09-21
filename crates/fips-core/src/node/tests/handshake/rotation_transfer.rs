use super::*;
use crate::config::TcpConfig;
use crate::node::acl::{PeerAclContext, PeerAclReloader};
use crate::node::wire::Msg1Header;
use crate::transport::tcp::{TcpTransport, stream::read_fmp_packet};
use crate::transport::{TransportHandle, packet_channel};
use tokio::io::AsyncReadExt;

#[test]
fn reciprocal_transfer_preserves_deadline_acl_and_one_candidate_bound() {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-reciprocal-transfer-bounds",
        || async {
            let mut node = make_test_node().await;
            let old = make_node();
            let active = make_node();
            let mut silent = make_node();
            let mut ready = make_node();
            // Make the public ordering observation distinguish the two cursors.
            if silent.node_addr() > ready.node_addr() {
                std::mem::swap(&mut silent, &mut ready);
            }
            let denied = make_node();
            let other = make_node();
            let (_old_socket, old_source) = local_path().await;
            let (_active_socket, active_source) = local_path().await;
            let (silent_socket, silent_source) = local_path().await;
            let (_ready_socket, ready_source) = local_path().await;
            let (_denied_socket, denied_source) = local_path().await;
            let (_other_socket, other_source) = local_path().await;
            let mut old_owner = incumbent(&mut node, &old, &old_source, 300, 60_000).await;
            let mut active_owner = incumbent(&mut node, &active, &active_source, 301, 50_000).await;
            let old_generation = node
                .node
                .get_peer(old.node_addr())
                .unwrap()
                .session_generation();
            let active_generation = node
                .node
                .get_peer(active.node_addr())
                .unwrap()
                .session_generation();
            node.node.pending_session_traffic.push_tun_packet(
                *active.node_addr(),
                vec![1],
                8,
                8,
                Some(1),
            );
            enable(&mut node, 2);
            node.node
                .config
                .node
                .neighbor_rotation
                .as_mut()
                .unwrap()
                .interval_secs = 1;
            node.node.config.node.rate_limit.handshake_timeout_secs = 3;

            let acl = tempfile::tempdir().unwrap();
            let allow_path = acl.path().join("peers.allow");
            let deny_path = acl.path().join("peers.deny");
            std::fs::write(&allow_path, "").unwrap();
            std::fs::write(&deny_path, denied.identity.npub()).unwrap();
            node.node.peer_acl = PeerAclReloader::with_paths(allow_path, deny_path);
            assert!(
                node.node
                    .authorize_peer(
                        &PeerIdentity::from_pubkey_full(denied.identity.pubkey_full()),
                        PeerAclContext::InboundHandshake,
                        node.transport_id,
                        &denied_source,
                    )
                    .is_err()
            );

            let started = tokio::time::Instant::now();
            node.node
                .initiate_connection(
                    node.transport_id,
                    silent_source.clone(),
                    PeerIdentity::from_pubkey_full(silent.identity.pubkey_full()),
                )
                .await
                .unwrap();
            let mut wire = [0; 512];
            let length =
                tokio::time::timeout(Duration::from_secs(1), silent_socket.recv(&mut wire))
                    .await
                    .expect("the unanswered outbound must really send its Noise request")
                    .unwrap();
            assert!(Msg1Header::parse(&wire[..length]).is_some());
            let outgoing = node.node.peers.connection_values().next().unwrap();
            assert!(outgoing.is_outbound() && !outgoing.has_session());
            let outgoing_link = outgoing.link_id();
            let outgoing_index = outgoing.our_index().unwrap();
            let original_activity = outgoing.last_activity();
            let attempt_start = node
                .node
                .neighbor_rotation_started_at(silent.node_addr())
                .unwrap();
            let original_deadline = attempt_start + 3_000;
            let cursor = node.node.neighbor_rotation_order(*ready.node_addr());
            assert!(!cursor.0);
            assert_eq!(resources(&node), (2, 1, 3, 3));

            // The new identity does not bypass the node-wide attempt interval.
            let _early = request(&mut node, &ready, &ready_source, 302).await;
            assert!(node.node.get_connection(&outgoing_link).is_some());
            assert_eq!(resources(&node), (2, 1, 3, 3));
            tokio::time::sleep_until(started + Duration::from_millis(1_050)).await;

            // Authentication alone cannot authorize releasing the old owner.
            let _denied = request(&mut node, &denied, &denied_source, 303).await;
            let retained = node.node.get_connection(&outgoing_link).unwrap();
            assert_eq!(retained.our_index(), Some(outgoing_index));
            assert_eq!(retained.last_activity(), original_activity);
            assert!(node.node.index_allocator.is_allocated(outgoing_index));
            assert_eq!(
                node.node.neighbor_rotation_order(*ready.node_addr()),
                cursor
            );
            assert_eq!(resources(&node), (2, 1, 3, 3));

            let mut handshake = request(&mut node, &ready, &ready_source, 304).await;
            let incoming = node
                .node
                .peers
                .connection_values()
                .find(|conn| {
                    conn.expected_identity()
                        .is_some_and(|id| id.node_addr() == ready.node_addr())
                })
                .expect("eligible reciprocal Noise must replace the unanswered outbound slot");
            assert!(incoming.is_inbound() && incoming.is_complete());
            let incoming_link = incoming.link_id();
            let incoming_index = incoming.our_index().unwrap();
            let msg1 = incoming.handshake_msg1().unwrap().to_vec();
            let msg2 = incoming.handshake_msg2().unwrap().to_vec();
            assert_eq!(incoming.last_activity(), attempt_start);
            let header = Msg2Header::parse(&msg2).unwrap();
            handshake.read_message_2(header.noise_msg2(&msg2)).unwrap();
            let mut candidate = Candidate {
                link: incoming_link,
                index: incoming_index,
                session: handshake.into_session().unwrap(),
                source: ready_source.clone(),
            };
            assert!(node.node.get_connection(&outgoing_link).is_none());
            assert!(!node.node.index_allocator.is_allocated(outgoing_index));
            assert!(
                !node
                    .node
                    .pending_outbound
                    .contains_key(&(node.transport_id, outgoing_index.as_u32()))
            );
            assert_eq!(resources(&node), (2, 1, 3, 3));
            assert_eq!(
                node.node.neighbor_rotation_started_at(ready.node_addr()),
                Some(attempt_start)
            );
            assert_eq!(
                node.node.neighbor_rotation_order(*ready.node_addr()),
                cursor
            );
            assert!(node.node.get_peer(ready.node_addr()).is_none());
            assert!(node.node.can_attempt_neighbor_rotation(
                ready.node_addr(),
                true,
                Node::now_ms()
            ));
            assert!(
                !node.node.can_attempt_neighbor_rotation(
                    ready.node_addr(),
                    true,
                    original_deadline
                ),
                "the original attempt deadline must survive the identity transfer"
            );

            // A valid Msg2 is not permission to evict either existing peer.
            for (peer, owner, generation) in [
                (&old, &old_owner, old_generation),
                (&active, &active_owner, active_generation),
            ] {
                let retained = node.node.get_peer(peer.node_addr()).unwrap();
                assert_eq!(retained.link_id(), owner.link);
                assert_eq!(retained.our_index(), Some(owner.index));
                assert_eq!(retained.remote_epoch(), Some(peer.startup_epoch));
                assert_eq!(retained.session_generation(), generation);
            }
            assert_eq!(heartbeat(&mut node, &active, &mut active_owner).await, 2);

            // Even after the new identity's cooldown elapses, an inbound owner
            // cannot be replaced by another identity's replayable Msg1.
            tokio::time::sleep_until(started + Duration::from_millis(2_150)).await;
            let _stranger = request(&mut node, &other, &other_source, 305).await;
            assert!(node.node.get_connection(&incoming_link).is_some());
            assert!(node.node.get_peer(other.node_addr()).is_none());
            node.node
                .handle_msg1(packet(&node, &ready_source, msg1))
                .await;
            let retained = node.node.get_connection(&incoming_link).unwrap();
            assert_eq!(retained.last_activity(), attempt_start);
            assert_eq!(retained.handshake_msg2(), Some(msg2.as_slice()));
            assert_eq!(resources(&node), (2, 1, 3, 3));
            assert_eq!(
                node.node.neighbor_rotation_order(*ready.node_addr()),
                cursor
            );

            // The real timeout cleans up at A's deadline, not B's arrival time.
            tokio::time::sleep_until(started + Duration::from_millis(3_250)).await;
            node.node.check_timeouts().await;
            assert_eq!(resources(&node), (2, 0, 2, 2));
            assert!(!node.node.index_allocator.is_allocated(incoming_index));
            assert!(node.node.pending_outbound.is_empty());
            let expired_proof = candidate.frame(
                node.transport_id,
                &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
            );
            assert!(!node.node.confirm_inbound_handshake(expired_proof).await);
            assert_eq!(resources(&node), (2, 0, 2, 2));
            assert!(node.node.has_neighbor_rotation_opportunity(Node::now_ms()));
            assert_eq!(heartbeat(&mut node, &old, &mut old_owner).await, 2);
            assert_eq!(heartbeat(&mut node, &active, &mut active_owner).await, 3);
            cleanup_nodes(std::slice::from_mut(&mut node)).await;
        },
    );
}

#[test]
fn cancelled_reciprocal_transfer_keeps_old_tcp_owner_until_close_completes() {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-reciprocal-transfer-cancel",
        || async {
            let mut node = make_test_node().await;
            let old = make_node();
            let silent = make_node();
            let ready = make_node();
            let (_old_socket, old_source) = local_path().await;
            let (ready_socket, ready_source) = local_path().await;
            let old_owner = incumbent(&mut node, &old, &old_source, 310, 60_000).await;
            let old_generation = node
                .node
                .get_peer(old.node_addr())
                .unwrap()
                .session_generation();
            enable(&mut node, 1);
            node.node
                .config
                .node
                .neighbor_rotation
                .as_mut()
                .unwrap()
                .interval_secs = 1;
            node.node.config.node.rate_limit.handshake_timeout_secs = 5;

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let silent_source =
                TransportAddr::from_string(&listener.local_addr().unwrap().to_string());
            let tcp_id = TransportId::new(2);
            let (tx, _rx) = packet_channel(16);
            let mut tcp = TcpTransport::new(tcp_id, None, TcpConfig::default(), tx);
            tcp.start_async().await.unwrap();
            let stats = tcp.stats().clone();
            node.node
                .transports
                .insert(tcp_id, TransportHandle::Tcp(tcp));
            node.node
                .initiate_connection(
                    tcp_id,
                    silent_source.clone(),
                    PeerIdentity::from_pubkey_full(silent.identity.pubkey_full()),
                )
                .await
                .unwrap();
            let (mut silent_stream, _) =
                tokio::time::timeout(Duration::from_secs(2), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while node.node.connection_count() == 0 {
                    node.node.poll_pending_connects().await;
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("TCP preparation must send the real Noise request");
            let msg1 = tokio::time::timeout(
                Duration::from_secs(2),
                read_fmp_packet(&mut silent_stream, u16::MAX),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(Msg1Header::parse(&msg1).is_some());
            let outgoing = node.node.peers.connection_values().next().unwrap();
            assert!(outgoing.is_outbound() && !outgoing.has_session());
            let outgoing_link = outgoing.link_id();
            let outgoing_index = outgoing.our_index().unwrap();
            let original_activity = outgoing.last_activity();
            let attempt_start = node
                .node
                .neighbor_rotation_started_at(silent.node_addr())
                .unwrap();
            let cursor = node.node.neighbor_rotation_order(*ready.node_addr());
            assert_eq!(resources(&node), (1, 1, 2, 2));
            assert_eq!(stats.snapshot().pool_outbound, 1);
            tokio::time::timeout(Duration::from_secs(2), async {
                while Node::now_ms().saturating_sub(attempt_start) < 1_050 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();

            let guard = match node.node.transports.get(&tcp_id).unwrap() {
                TransportHandle::Tcp(tcp) => tcp.test_pool_guard().await,
                _ => unreachable!(),
            };
            let mut handshake = HandshakeState::new_initiator(
                ready.identity.keypair(),
                node.node.identity.pubkey_full(),
            );
            handshake.set_local_epoch(ready.startup_epoch);
            let msg1 = build_msg1(
                SessionIndex::new(311),
                &handshake.write_message_1().unwrap(),
            );
            ready_socket
                .send_to(&msg1, node.addr.as_str().unwrap())
                .await
                .unwrap();
            let incoming = tokio::time::timeout(Duration::from_secs(1), node.packet_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(incoming.remote_addr, ready_source);
            assert_eq!(incoming.data.as_slice(), msg1.as_slice());
            let mut admission = Box::pin(node.node.handle_msg1(incoming));
            assert!(
                futures::poll!(admission.as_mut()).is_pending(),
                "real TCP close must wait for its pool lock"
            );
            drop(admission);

            // The cancelled handler must still own every old accounting/index
            // record while physical removal has not acquired the pool lock.
            assert_eq!(resources(&node), (1, 1, 2, 2));
            let retained = node.node.get_connection(&outgoing_link).unwrap();
            assert_eq!(retained.our_index(), Some(outgoing_index));
            assert_eq!(retained.last_activity(), original_activity);
            assert_eq!(
                node.node.links.lookup_addr(tcp_id, &silent_source),
                Some(outgoing_link)
            );
            assert_eq!(
                node.node
                    .pending_outbound
                    .get(&(tcp_id, outgoing_index.as_u32())),
                Some(&outgoing_link)
            );
            assert!(node.node.index_allocator.is_allocated(outgoing_index));
            assert_eq!(
                node.node.neighbor_rotation_started_at(silent.node_addr()),
                Some(attempt_start)
            );
            assert_eq!(
                node.node.neighbor_rotation_order(*ready.node_addr()),
                cursor
            );
            let retained = node.node.get_peer(old.node_addr()).unwrap();
            assert_eq!(retained.link_id(), old_owner.link);
            assert_eq!(retained.our_index(), Some(old_owner.index));
            assert_eq!(retained.session_generation(), old_generation);
            assert_eq!(stats.snapshot().pool_outbound, 1);
            drop(guard);

            ready_socket
                .send_to(&msg1, node.addr.as_str().unwrap())
                .await
                .unwrap();
            let replay = tokio::time::timeout(Duration::from_secs(1), node.packet_rx.recv())
                .await
                .unwrap()
                .unwrap();
            node.node.handle_msg1(replay).await;
            assert_eq!(resources(&node), (1, 1, 2, 2));
            assert_eq!(stats.snapshot().pool_outbound, 0);
            assert!(node.node.get_connection(&outgoing_link).is_none());
            assert!(!node.node.index_allocator.is_allocated(outgoing_index));
            assert_eq!(
                node.node.neighbor_rotation_started_at(ready.node_addr()),
                Some(attempt_start)
            );
            assert_eq!(
                node.node.neighbor_rotation_order(*ready.node_addr()),
                cursor
            );
            let mut byte = [0];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), silent_stream.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );

            let mut msg2 = [0; 512];
            let length = tokio::time::timeout(Duration::from_secs(1), ready_socket.recv(&mut msg2))
                .await
                .unwrap()
                .unwrap();
            let msg2 = &msg2[..length];
            let header = Msg2Header::parse(msg2).unwrap();
            handshake.read_message_2(header.noise_msg2(msg2)).unwrap();
            let link = node
                .node
                .links
                .lookup_addr(node.transport_id, &ready_source)
                .unwrap();
            assert_eq!(
                node.node.get_connection(&link).unwrap().last_activity(),
                attempt_start
            );
            let mut candidate = Candidate {
                link,
                index: header.sender_idx,
                session: handshake.into_session().unwrap(),
                source: ready_source,
            };
            let proof = candidate.frame(
                node.transport_id,
                &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
            );
            ready_socket
                .send_to(proof.data.as_slice(), node.addr.as_str().unwrap())
                .await
                .unwrap();
            let received = tokio::time::timeout(Duration::from_secs(1), node.packet_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(node.node.confirm_inbound_handshake(received).await);
            assert_eq!(resources(&node), (1, 0, 1, 1));
            assert!(node.node.get_peer(old.node_addr()).is_none());
            assert_eq!(
                node.node.get_peer(ready.node_addr()).unwrap().our_index(),
                Some(candidate.index)
            );
            assert!(!node.node.index_allocator.is_allocated(old_owner.index));
            assert_eq!(heartbeat(&mut node, &ready, &mut candidate).await, 2);
            cleanup_nodes(std::slice::from_mut(&mut node)).await;
        },
    );
}
