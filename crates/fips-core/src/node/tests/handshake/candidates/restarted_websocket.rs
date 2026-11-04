use super::*;
use crate::config::WebSocketConfig;
use crate::transport::websocket::WebSocketTransport;
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Copy)]
enum Owner {
    Recent,
    Silent,
    Replaced,
    Removed,
    Dampened,
}

#[test]
fn restarted_websocket_requires_fresh_proof_for_the_exact_udp_owner() {
    super::super::super::session::run_large_stack_async_test("restarted-websocket", || async {
        for owner in [
            Owner::Recent,
            Owner::Silent,
            Owner::Replaced,
            Owner::Removed,
            Owner::Dampened,
        ] {
            exercise_restart(owner).await;
        }
    });
}

async fn exercise_restart(case: Owner) {
    let mut node = make_test_node().await;
    let remote = make_node();
    let (_udp_socket, udp_addr) = local_path().await;
    let mut owner = connect(&mut node, &remote, &udp_addr, 11).await;
    let id = *remote.node_addr();
    deliver_owner_heartbeat(&mut node, &mut owner, &id).await;
    assert!(
        node.node
            .dataplane_fmp_link_metrics(&id, Instant::now())
            .unwrap()
            .current_epoch_authenticated
    );
    if matches!(case, Owner::Silent) {
        node.node
            .get_peer_mut(&id)
            .unwrap()
            .touch(Node::now_ms() - 16_000);
    }
    if matches!(case, Owner::Dampened) {
        node.node.restart_dampener.insert(id, Instant::now());
    }
    let websocket = TransportId::new(2);
    let (tx, mut rx) = packet_channel(32);
    let mut listener = WebSocketTransport::new(
        websocket,
        None,
        WebSocketConfig {
            bind_addr: Some("127.0.0.1:0".into()),
            ..Default::default()
        },
        tx,
        node.node.identity(),
    );
    listener.start_async().await.unwrap();
    let url = format!("ws://{}/fips", listener.local_addr().unwrap());
    node.node
        .transports
        .insert(websocket, TransportHandle::WebSocket(Box::new(listener)));
    let mut new_epoch = remote.startup_epoch;
    new_epoch[0] ^= 1;
    let mut handshake =
        HandshakeState::new_initiator(remote.identity.keypair(), node.node.identity.pubkey_full());
    handshake.set_local_epoch(new_epoch);
    let msg1 = build_msg1(SessionIndex::new(22), &handshake.write_message_1().unwrap());
    let (mut socket, _) = tokio_tungstenite::connect_async(url.as_str())
        .await
        .unwrap();
    socket
        .send(Message::Binary(msg1.clone().into()))
        .await
        .unwrap();
    let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    let source = first.remote_addr.clone();
    assert_eq!(first.data.as_slice(), msg1.as_slice());
    node.node.handle_msg1(first).await;
    let reply = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Binary(bytes))) => break Some(bytes),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break None,
                other => panic!("unexpected WebSocket frame: {other:?}"),
            }
        }
    })
    .await
    .expect("expected closure or Noise Msg2");
    let active = node.node.get_peer(&id).unwrap();
    assert_eq!(
        (active.link_id(), active.our_index(), active.remote_epoch()),
        (owner.link, Some(owner.index), Some(remote.startup_epoch))
    );
    if matches!(case, Owner::Dampened) {
        assert!(reply.is_none());
        assert_eq!(node.node.connection_count(), 0);
        cleanup_nodes(std::slice::from_mut(&mut node)).await;
        return;
    }

    let reply = reply.expect("a genuine alternate-path restart should get a fresh challenge");
    let header = Msg2Header::parse(&reply).unwrap();
    handshake.read_message_2(header.noise_msg2(&reply)).unwrap();
    let link = node.node.links.lookup_addr(websocket, &source).unwrap();
    let mut restarted = Candidate {
        link,
        index: header.sender_idx,
        session: handshake.into_session().unwrap(),
        source: source.clone(),
    };
    let proof = restarted.frame(
        websocket,
        &[crate::protocol::LinkMessageType::Heartbeat.to_byte()],
    );
    let mut corrupted = proof.data.as_slice().to_vec();
    *corrupted.last_mut().unwrap() ^= 1;
    let bad = ReceivedPacket::with_timestamp(
        websocket,
        source.clone(),
        PacketBuffer::new(corrupted),
        Node::now_ms(),
    );
    assert!(!node.node.confirm_pending_handshake(bad).await);
    assert_eq!(
        node.node.get_peer(&id).unwrap().our_index(),
        Some(owner.index)
    );
    assert!(
        node.node
            .get_connection(&link)
            .unwrap()
            .handshake_confirmation()
            .is_none()
    );
    assert!(node.node.restart_dampener.is_empty());
    match case {
        Owner::Recent | Owner::Silent => {
            assert!(node.node.confirm_pending_handshake(proof).await);
            let peer = node.node.get_peer(&id).unwrap();
            assert_eq!(peer.transport_id(), Some(websocket));
            assert_eq!(peer.remote_epoch(), Some(new_epoch));
            assert_eq!(peer.our_index(), Some(restarted.index));
            assert!(!node.node.index_allocator.is_allocated(owner.index));
            assert!(node.node.restart_dampener.contains_key(&id));
        }
        Owner::Removed | Owner::Replaced => {
            node.node.remove_active_peer(&id);
            let next = if matches!(case, Owner::Replaced) {
                let (_socket, addr) = local_path().await;
                Some(connect(&mut node, &remote, &addr, 33).await.index)
            } else {
                None
            };
            assert!(!node.node.confirm_pending_handshake(proof).await);
            assert_eq!(node.node.get_peer(&id).and_then(|p| p.our_index()), next);
            assert!(!node.node.index_allocator.is_allocated(restarted.index));
            assert!(node.node.restart_dampener.is_empty());
        }
        Owner::Dampened => unreachable!(),
    }
    cleanup_nodes(std::slice::from_mut(&mut node)).await;
}
