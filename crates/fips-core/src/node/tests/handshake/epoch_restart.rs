use super::*;

use crate::node::wire::build_msg1;
use crate::peer::ActivePeer;
use crate::transport::{PacketBuffer, ReceivedPacket};

const STALE_PEERING_AGE_MS: u64 = 60_000;

fn genuine_msg1(initiator: &Node, responder: &Node, sender_index: u32) -> PacketBuffer {
    let mut handshake = crate::noise::HandshakeState::new_initiator(
        initiator.identity.keypair(),
        responder.identity.pubkey_full(),
    );
    handshake.set_local_epoch(initiator.startup_epoch);
    PacketBuffer::new(build_msg1(
        SessionIndex::new(sender_index),
        &handshake.write_message_1().expect("write genuine msg1"),
    ))
}

fn install_peering_at_different_epoch(
    responder: &mut Node,
    initiator: &Node,
    transport_id: TransportId,
    source_addr: &TransportAddr,
    last_seen_ms: u64,
) -> LinkId {
    let peer_identity = PeerIdentity::from_pubkey_full(initiator.identity.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let link_id = responder.allocate_link_id();
    let mut peer = ActivePeer::new(peer_identity, link_id, last_seen_ms);
    peer.set_current_addr(transport_id, source_addr);
    peer.set_remote_epoch(Some([0xAA; 8]));
    responder.peers.insert(peer_addr, peer);
    responder.links.insert(
        link_id,
        Link::connectionless(
            link_id,
            transport_id,
            source_addr.clone(),
            LinkDirection::Inbound,
            Duration::from_millis(1),
        ),
    );
    responder
        .links
        .insert_addr((transport_id, source_addr.clone()), link_id);
    link_id
}

#[tokio::test]
async fn epoch_mismatch_against_live_peering_does_not_replace_it() {
    use crate::config::UdpConfig;
    use crate::transport::TransportHandle;
    use crate::transport::udp::UdpTransport;

    let mut responder = make_node();
    let initiator = make_node();
    let peer_addr = *initiator.node_addr();
    let transport_id = TransportId::new(1);
    let source_addr = TransportAddr::from_string("127.0.0.1:41001");
    let now_ms = Node::now_ms();
    let (packet_tx, _packet_rx) = packet_channel(8);
    responder.transports.insert(
        transport_id,
        TransportHandle::Udp(UdpTransport::new(
            transport_id,
            None,
            UdpConfig::default(),
            packet_tx,
        )),
    );
    let retained_link = install_peering_at_different_epoch(
        &mut responder,
        &initiator,
        transport_id,
        &source_addr,
        now_ms,
    );

    responder
        .handle_msg1(ReceivedPacket::with_timestamp(
            transport_id,
            source_addr,
            genuine_msg1(&initiator, &responder, 77),
            now_ms,
        ))
        .await;

    let retained = responder
        .get_peer(&peer_addr)
        .expect("live peer must survive a replayable epoch mismatch");
    assert_eq!(retained.link_id(), retained_link);
    assert_eq!(retained.remote_epoch(), Some([0xAA; 8]));
    assert_eq!(responder.connection_count(), 0);
}

#[tokio::test]
async fn second_accepted_epoch_change_is_dampened() {
    let mut responder = make_node();
    let initiator = make_node();
    let peer_addr = *initiator.node_addr();
    let transport_id = TransportId::new(1);
    let source_addr = TransportAddr::from_string("127.0.0.1:41002");
    let now_ms = Node::now_ms();

    install_peering_at_different_epoch(
        &mut responder,
        &initiator,
        transport_id,
        &source_addr,
        now_ms.saturating_sub(STALE_PEERING_AGE_MS),
    );
    responder
        .handle_msg1(ReceivedPacket::with_timestamp(
            transport_id,
            source_addr.clone(),
            genuine_msg1(&initiator, &responder, 78),
            now_ms,
        ))
        .await;

    responder.remove_active_peer(&peer_addr);
    let second_link = install_peering_at_different_epoch(
        &mut responder,
        &initiator,
        transport_id,
        &source_addr,
        now_ms.saturating_sub(STALE_PEERING_AGE_MS),
    );
    responder
        .handle_msg1(ReceivedPacket::with_timestamp(
            transport_id,
            source_addr,
            genuine_msg1(&initiator, &responder, 79),
            now_ms,
        ))
        .await;

    let retained = responder
        .get_peer(&peer_addr)
        .expect("second epoch change inside dampening interval must be refused");
    assert_eq!(retained.link_id(), second_link);
    assert_eq!(retained.remote_epoch(), Some([0xAA; 8]));
}

#[tokio::test]
async fn first_epoch_change_against_silent_peering_is_accepted() {
    let mut responder = make_node();
    let initiator = make_node();
    let peer_addr = *initiator.node_addr();
    let transport_id = TransportId::new(1);
    let source_addr = TransportAddr::from_string("127.0.0.1:41003");
    let now_ms = Node::now_ms();
    let stale_link = install_peering_at_different_epoch(
        &mut responder,
        &initiator,
        transport_id,
        &source_addr,
        now_ms.saturating_sub(STALE_PEERING_AGE_MS),
    );

    responder
        .handle_msg1(ReceivedPacket::with_timestamp(
            transport_id,
            source_addr,
            genuine_msg1(&initiator, &responder, 80),
            now_ms,
        ))
        .await;

    let replacement = responder
        .get_peer(&peer_addr)
        .expect("silent stale peering should accept a genuine restart");
    assert_ne!(replacement.link_id(), stale_link);
    assert_eq!(replacement.remote_epoch(), Some(initiator.startup_epoch));
}
