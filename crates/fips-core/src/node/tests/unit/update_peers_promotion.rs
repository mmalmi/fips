use super::*;

#[tokio::test]
async fn outbound_refresh_promotion_moves_active_peer_to_new_transport_tuple() {
    let mut node = make_node();
    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();

    let old_transport_id = TransportId::new(1);
    let old_link_id = LinkId::new(10);
    let old_addr = TransportAddr::from_string("127.0.0.1:7000");
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(old_transport_id, &old_addr);
    active_peer.mark_stale();
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            old_transport_id,
            old_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((old_transport_id, old_addr.clone()), old_link_id);

    let new_transport_id = TransportId::new(2);
    let new_link_id = LinkId::new(11);
    let new_addr = TransportAddr::from_string("127.0.0.1:9000");
    let mut conn = PeerConnection::outbound(new_link_id, peer_identity, 2_000);
    let our_index = node.index_allocator.allocate().unwrap();
    let noise_msg1 = conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 2_000)
        .unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(new_transport_id);
    conn.set_source_addr(new_addr.clone());
    node.links.insert(
        new_link_id,
        Link::connectionless(
            new_link_id,
            new_transport_id,
            new_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((new_transport_id, new_addr.clone()), new_link_id);
    node.peers.insert_connection(new_link_id, conn);
    node.pending_outbound
        .insert((new_transport_id, our_index.as_u32()), new_link_id);

    let mut responder = PeerConnection::inbound(LinkId::new(99), 2_000);
    let noise_msg2 = responder
        .receive_handshake_init(peer_full.keypair(), [0x42; 8], &noise_msg1, 2_000)
        .unwrap();
    let their_index = SessionIndex::new(77);
    let wire_msg2 = build_msg2(their_index, our_index, &noise_msg2);
    let packet = ReceivedPacket::with_timestamp(
        new_transport_id,
        new_addr.clone(),
        crate::transport::PacketBuffer::new(wire_msg2),
        2_100,
    );

    node.handle_msg2(packet).await;

    assert_eq!(node.connection_count(), 0);
    assert!(node.pending_outbound.is_empty());
    assert!(
        !node.links.contains_key(&old_link_id),
        "old active link should be retired after successful refresh"
    );
    assert!(
        node.links.contains_key(&new_link_id),
        "new outbound link should remain active"
    );
    assert_eq!(
        node.links.get_addr(&(old_transport_id, old_addr.clone())),
        None
    );
    assert_eq!(
        node.links
            .get_addr(&(new_transport_id, new_addr.clone()))
            .copied(),
        Some(new_link_id)
    );

    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), new_link_id);
    assert_eq!(active.transport_id(), Some(new_transport_id));
    assert_eq!(active.current_addr(), Some(&new_addr));
    assert_eq!(active.our_index(), Some(our_index));
    assert_eq!(active.their_index(), Some(their_index));
    assert_eq!(
        node.peers
            .get_session_index(&(new_transport_id, our_index.as_u32()))
            .copied(),
        Some(peer_node_addr)
    );
}

#[tokio::test]
async fn outbound_restart_promotion_clears_stale_fsp_session() {
    use crate::node::session::{EndToEndState, SessionEntry};
    use crate::noise::HandshakeState;

    let mut node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();

    let old_transport_id = TransportId::new(1);
    let old_link_id = LinkId::new(10);
    let old_addr = TransportAddr::from_string("127.0.0.1:7000");
    let mut old_conn = PeerConnection::outbound(old_link_id, peer_identity, 1_000);
    let old_msg1 = old_conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 1_000)
        .unwrap();
    let mut old_responder = PeerConnection::inbound(LinkId::new(98), 1_000);
    let old_msg2 = old_responder
        .receive_handshake_init(peer_full.keypair(), [0x11; 8], &old_msg1, 1_000)
        .unwrap();
    old_conn.complete_handshake(&old_msg2, 1_000).unwrap();
    let old_our_index = node.index_allocator.allocate().unwrap();
    old_conn.set_our_index(old_our_index);
    old_conn.set_their_index(SessionIndex::new(66));
    old_conn.set_transport_id(old_transport_id);
    old_conn.set_source_addr(old_addr.clone());
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            old_transport_id,
            old_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((old_transport_id, old_addr.clone()), old_link_id);
    node.peers.insert_connection(old_link_id, old_conn);
    node.promote_connection(old_link_id, peer_identity, 1_100)
        .unwrap();
    assert_eq!(
        node.get_peer(&peer_node_addr).unwrap().remote_epoch(),
        Some([0x11; 8])
    );

    let mut fsp_initiator =
        HandshakeState::new_initiator(node.identity.keypair(), peer_full.pubkey_full());
    let mut fsp_responder = HandshakeState::new_responder(peer_full.keypair());
    fsp_initiator.set_local_epoch([0x01; 8]);
    fsp_responder.set_local_epoch([0x02; 8]);
    let fsp_msg1 = fsp_initiator.write_message_1().unwrap();
    fsp_responder.read_message_1(&fsp_msg1).unwrap();
    let fsp_msg2 = fsp_responder.write_message_2().unwrap();
    fsp_initiator.read_message_2(&fsp_msg2).unwrap();
    let stale_session = fsp_initiator.into_session().unwrap();
    node.sessions.insert(
        peer_node_addr,
        SessionEntry::new(
            peer_node_addr,
            peer_full.pubkey_full(),
            EndToEndState::Established(stale_session),
            1_200,
            true,
        ),
    );
    assert!(node.sessions.get(&peer_node_addr).is_some());

    let new_transport_id = TransportId::new(2);
    let new_link_id = LinkId::new(11);
    let new_addr = TransportAddr::from_string("127.0.0.1:9000");
    let mut new_conn = PeerConnection::outbound(new_link_id, peer_identity, 2_000);
    let new_msg1 = new_conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 2_000)
        .unwrap();
    let mut new_responder = PeerConnection::inbound(LinkId::new(99), 2_000);
    let new_msg2 = new_responder
        .receive_handshake_init(peer_full.keypair(), [0x22; 8], &new_msg1, 2_000)
        .unwrap();
    new_conn.complete_handshake(&new_msg2, 2_100).unwrap();
    let new_our_index = node.index_allocator.allocate().unwrap();
    let their_index = SessionIndex::new(77);
    new_conn.set_our_index(new_our_index);
    new_conn.set_their_index(their_index);
    new_conn.set_transport_id(new_transport_id);
    new_conn.set_source_addr(new_addr.clone());
    node.links.insert(
        new_link_id,
        Link::connectionless(
            new_link_id,
            new_transport_id,
            new_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((new_transport_id, new_addr.clone()), new_link_id);
    node.peers.insert_connection(new_link_id, new_conn);

    let result = node
        .promote_connection(new_link_id, peer_identity, 2_100)
        .unwrap();
    assert!(matches!(result, PromotionResult::CrossConnectionWon { .. }));

    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), new_link_id);
    assert_eq!(active.remote_epoch(), Some([0x22; 8]));
    assert!(
        node.sessions.get(&peer_node_addr).is_none(),
        "old FSP session must be removed when the peer's startup epoch changes"
    );
}
