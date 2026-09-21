use super::*;
use crate::config::TcpConfig;
use crate::transport::tcp::{TcpTransport, stream::read_fmp_packet};
use crate::transport::{TransportHandle, packet_channel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn rejected_tcp_rotation_closes_candidate_carrier_and_preserves_incumbent() {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-tcp-rejected-carrier",
        || async {
            let mut node = make_test_node().await;
            let old = make_node();
            let newcomer = make_node();
            let (_old_socket, old_source) = local_path().await;
            let mut owner = incumbent(&mut node, &old, &old_source, 80, 60_000).await;
            enable(&mut node, 1);
            let original = node.node.get_peer(old.node_addr()).unwrap();
            let generation = original.session_generation();
            let epoch = original.remote_epoch();

            let tcp_id = TransportId::new(2);
            let (tx, mut rx) = packet_channel(16);
            let mut tcp = TcpTransport::new(
                tcp_id,
                None,
                TcpConfig {
                    bind_addr: Some("127.0.0.1:0".into()),
                    max_inbound_connections: Some(1),
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

            let mut stream = tokio::net::TcpStream::connect(listen).await.unwrap();
            let source = TransportAddr::from_string(&stream.local_addr().unwrap().to_string());
            let mut handshake = HandshakeState::new_initiator(
                newcomer.identity.keypair(),
                node.node.identity.pubkey_full(),
            );
            handshake.set_local_epoch(newcomer.startup_epoch);
            let msg1 = build_msg1(SessionIndex::new(81), &handshake.write_message_1().unwrap());
            // TCP carries native FMP records, without an extra length prefix.
            stream.write_all(&msg1).await.unwrap();
            let incoming = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(incoming.transport_id, tcp_id);
            assert_eq!(incoming.remote_addr, source);
            node.node.handle_msg1(incoming).await;
            assert_eq!(resources(&node), (1, 1, 2, 2));
            assert_eq!(stats.snapshot().pool_inbound, 1);

            let msg2 = tokio::time::timeout(
                Duration::from_secs(2),
                read_fmp_packet(&mut stream, u16::MAX),
            )
            .await
            .unwrap()
            .unwrap();
            let header = Msg2Header::parse(&msg2).unwrap();
            handshake.read_message_2(header.noise_msg2(&msg2)).unwrap();
            let candidate_link = node.node.links.lookup_addr(tcp_id, &source).unwrap();
            let mut candidate = Candidate {
                link: candidate_link,
                index: header.sender_idx,
                session: handshake.into_session().unwrap(),
                source,
            };
            let confirmation = candidate.frame(
                tcp_id,
                &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
            );
            stream
                .write_all(confirmation.data.as_slice())
                .await
                .unwrap();
            let confirmation = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap();
            // The proof is now on the real carrier, but promotion must recheck
            // demand that appeared since the candidate's Msg1 was admitted.
            node.node.pending_session_traffic.push_tun_packet(
                *old.node_addr(),
                vec![1, 2, 3],
                8,
                8,
                Some(1),
            );
            assert!(!node.node.confirm_inbound_handshake(confirmation).await);

            tokio::time::timeout(Duration::from_secs(2), async {
                while stats.snapshot().pool_inbound != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("rejected promotion must release the physical TCP pool slot");
            let mut byte = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
                .await
                .expect("candidate must see EOF without waiting for transport shutdown")
                .unwrap();
            assert_eq!(read, 0);
            assert_eq!(resources(&node), (1, 0, 1, 1));
            assert!(node.node.get_peer(newcomer.node_addr()).is_none());
            assert!(!node.node.index_allocator.is_allocated(candidate.index));
            assert!(
                node.node
                    .links
                    .lookup_addr(tcp_id, &candidate.source)
                    .is_none()
            );
            let retained = node.node.get_peer(old.node_addr()).unwrap();
            assert_eq!(retained.link_id(), owner.link);
            assert_eq!(retained.our_index(), Some(owner.index));
            assert_eq!(retained.session_generation(), generation);
            assert_eq!(retained.remote_epoch(), epoch);
            assert_eq!(heartbeat(&mut node, &old, &mut owner, 2).await, 2);
            cleanup_nodes(std::slice::from_mut(&mut node)).await;
        },
    );
}
