use super::*;
use crate::config::TcpConfig;
use crate::transport::tcp::{TcpTransport, stream::read_fmp_packet};
use crate::transport::{ConnectionState, PacketRx, TransportHandle, packet_channel};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub(super) async fn tcp_candidate(
    node: &mut TestNode,
    rx: &mut PacketRx,
    transport_id: TransportId,
    listen: SocketAddr,
    remote: &Node,
    sender_index: u32,
    arrival_age_ms: u64,
) -> (TcpStream, Candidate) {
    let mut stream = TcpStream::connect(listen).await.unwrap();
    let source = TransportAddr::from_string(&stream.local_addr().unwrap().to_string());
    let mut handshake =
        HandshakeState::new_initiator(remote.identity.keypair(), node.node.identity.pubkey_full());
    handshake.set_local_epoch(remote.startup_epoch);
    let msg1 = build_msg1(
        SessionIndex::new(sender_index),
        &handshake.write_message_1().unwrap(),
    );
    stream.write_all(&msg1).await.unwrap();
    let mut request = next_packet(rx).await;
    assert_eq!(request.transport_id, transport_id);
    assert_eq!(request.remote_addr, source);
    // Age only the initial incumbent arrival, as in the existing rotation
    // fixtures; both Noise flights still traverse real accepted TCP streams.
    request.timestamp_ms -= arrival_age_ms;
    node.node.handle_msg1(request).await;
    let msg2 = tokio::time::timeout(
        Duration::from_secs(2),
        read_fmp_packet(&mut stream, u16::MAX),
    )
    .await
    .unwrap()
    .unwrap();
    let header = Msg2Header::parse(&msg2).unwrap();
    handshake.read_message_2(header.noise_msg2(&msg2)).unwrap();
    let link = node.node.links.lookup_addr(transport_id, &source).unwrap();
    let candidate = Candidate {
        link,
        index: header.sender_idx,
        session: handshake.into_session().unwrap(),
        source,
    };
    (stream, candidate)
}

async fn next_packet(rx: &mut PacketRx) -> ReceivedPacket {
    tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("real TCP packet must arrive")
        .unwrap()
}

async fn write_heartbeat(stream: &mut TcpStream, owner: &mut Candidate, transport_id: TransportId) {
    let frame = owner.frame(
        transport_id,
        &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
    );
    stream.write_all(frame.data.as_slice()).await.unwrap();
}

#[test]
fn successful_tcp_rotation_releases_old_pool_slot_and_keeps_new_carrier_live() {
    super::super::super::super::session::run_large_stack_async_test(
        "rotation-tcp-success-carrier",
        || async {
            let mut node = make_test_node().await;
            let old = make_node();
            let newcomer = make_node();
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

            let (mut old_stream, mut old_owner) =
                tcp_candidate(&mut node, &mut rx, tcp_id, listen, &old, 90, 60_000).await;
            write_heartbeat(&mut old_stream, &mut old_owner, tcp_id).await;
            let old_frame = next_packet(&mut rx).await;
            super::super::super::super::spanning_tree::process_dataplane_packet(
                &mut node, old_frame,
            )
            .await;
            assert_eq!(resources(&node), (1, 0, 1, 1));
            assert_eq!(stats.snapshot().pool_inbound, 1);
            assert_eq!(await_heartbeat(&mut node, &old, 1).await, 1);
            enable(&mut node, 1);

            let (mut new_stream, mut candidate) =
                tcp_candidate(&mut node, &mut rx, tcp_id, listen, &newcomer, 91, 0).await;
            assert_eq!(resources(&node), (1, 1, 2, 2));
            assert_eq!(stats.snapshot().pool_inbound, 2);
            assert!(node.node.get_peer(old.node_addr()).is_some());
            assert!(node.node.get_peer(newcomer.node_addr()).is_none());
            write_heartbeat(&mut new_stream, &mut candidate, tcp_id).await;
            let confirmation = next_packet(&mut rx).await;
            assert!(node.node.confirm_inbound_handshake(confirmation).await);

            // These assertions precede transport shutdown. Logical counts alone
            // would pass even with the displaced socket still in the TCP pool.
            assert_eq!(resources(&node), (1, 0, 1, 1));
            assert_eq!(stats.snapshot().pool_inbound, 1);
            assert_eq!(stats.snapshot().pool_outbound, 0);
            assert!(node.node.get_peer(old.node_addr()).is_none());
            assert!(!node.node.index_allocator.is_allocated(old_owner.index));
            assert!(
                node.node
                    .links
                    .lookup_addr(tcp_id, &old_owner.source)
                    .is_none()
            );
            let transport = node.node.transports.get(&tcp_id).unwrap();
            assert_eq!(
                transport.connection_state(&old_owner.source),
                ConnectionState::None
            );
            assert_eq!(
                transport.connection_state(&candidate.source),
                ConnectionState::Connected
            );
            let retained = node.node.get_peer(newcomer.node_addr()).unwrap();
            assert_eq!(retained.link_id(), candidate.link);
            assert_eq!(retained.our_index(), Some(candidate.index));

            // Drain any initial TreeAnnounce already sent to the old owner,
            // then require EOF. A byte cap also bounds a failed closure test.
            let mut old_tail = Vec::new();
            tokio::time::timeout(
                Duration::from_secs(2),
                (&mut old_stream).take(65_536).read_to_end(&mut old_tail),
            )
            .await
            .expect("displaced TCP stream must close before shutdown")
            .unwrap();
            assert!(old_tail.len() < 65_536, "old stream must reach EOF");

            super::super::super::super::spanning_tree::process_node_packets(
                &mut node.node,
                &mut rx,
            )
            .await;
            let received = await_heartbeat(&mut node, &newcomer, 1).await;
            assert_eq!(received, 1);
            write_heartbeat(&mut new_stream, &mut candidate, tcp_id).await;
            let fresh = next_packet(&mut rx).await;
            super::super::super::super::spanning_tree::process_dataplane_packet(&mut node, fresh)
                .await;
            assert_eq!(
                await_heartbeat(&mut node, &newcomer, received + 1).await,
                received + 1
            );
            assert_eq!(stats.snapshot().pool_inbound, 1);
            cleanup_nodes(std::slice::from_mut(&mut node)).await;
        },
    );
}
