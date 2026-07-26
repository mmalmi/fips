use super::*;

#[cfg(feature = "sim-transport")]
use super::cleanup_and_resend::sim_test_transport;

#[cfg(feature = "sim-transport")]
#[tokio::test]
async fn responder_rekey_msg1_resends_duplicates_and_replaces_orphaned_pending_state() {
    use crate::node::wire::build_msg1;
    use crate::peer::{ActivePeer, ActivePeerSession};
    use crate::transport::{LinkStats, TransportHandle};
    use crate::{ReceivedPacket, SimNetwork};

    let mut responder = make_node();
    responder.config.node.rekey.enabled = true;
    let initiator = Identity::generate();
    let initiator_peer = PeerIdentity::from_pubkey_full(initiator.pubkey_full());
    let initiator_addr = *initiator_peer.node_addr();
    let transport_id = TransportId::new(1);
    let retained_link_id = responder.allocate_link_id();
    let remote_addr = TransportAddr::from_string("initiator");
    let current_our_index = responder.index_allocator.allocate().unwrap();
    let current_their_index = SessionIndex::new(20);
    let remote_epoch = [0xA1; 8];

    let mut current_initiator = crate::noise::HandshakeState::new_initiator(
        initiator.keypair(),
        responder.identity.pubkey_full(),
    );
    let mut current_responder =
        crate::noise::HandshakeState::new_responder(responder.identity.keypair());
    current_initiator.set_local_epoch(remote_epoch);
    current_responder.set_local_epoch(responder.startup_epoch);
    let current_msg1 = current_initiator.write_message_1().unwrap();
    current_responder.read_message_1(&current_msg1).unwrap();
    let current_msg2 = current_responder.write_message_2().unwrap();
    current_initiator.read_message_2(&current_msg2).unwrap();
    let current_session = current_responder.into_session().unwrap();

    let mut active = ActivePeer::with_session(
        initiator_peer,
        retained_link_id,
        1_000,
        ActivePeerSession {
            session: current_session,
            our_index: current_our_index,
            their_index: current_their_index,
            transport_id,
            current_addr: remote_addr.clone(),
            link_stats: LinkStats::new(),
            is_initiator: false,
            remote_epoch: Some(remote_epoch),
        },
    );
    active.set_session_established_at_for_test(std::time::Instant::now() - Duration::from_secs(31));
    responder
        .peers
        .insert_with_current_session_index(initiator_addr, active);
    responder.links.insert(
        retained_link_id,
        Link::connectionless(
            retained_link_id,
            transport_id,
            remote_addr.clone(),
            LinkDirection::Inbound,
            Duration::from_millis(1),
        ),
    );
    responder
        .links
        .insert_addr((transport_id, remote_addr.clone()), retained_link_id);
    assert!(responder.sync_dataplane_fmp_owner(&initiator_addr));

    let network_name = format!("duplicate-responder-rekey-{}", responder.node_addr());
    crate::register_sim_network(network_name.clone(), SimNetwork::new(13));
    let (mut initiator_transport, mut initiator_packet_rx) =
        sim_test_transport(&network_name, "initiator", transport_id, 8);
    initiator_transport.start_async().await.unwrap();
    let (mut responder_transport, _responder_packet_rx) =
        sim_test_transport(&network_name, "responder", transport_id, 8);
    responder_transport.start_async().await.unwrap();
    responder
        .transports
        .insert(transport_id, TransportHandle::Sim(responder_transport));

    let rekey_their_index = SessionIndex::new(77);
    let mut rekey_initiator = crate::noise::HandshakeState::new_initiator(
        initiator.keypair(),
        responder.identity.pubkey_full(),
    );
    rekey_initiator.set_local_epoch(remote_epoch);
    let rekey_msg1 = build_msg1(
        rekey_their_index,
        &rekey_initiator.write_message_1().unwrap(),
    );
    let packet = || {
        ReceivedPacket::with_timestamp(
            transport_id,
            remote_addr.clone(),
            crate::transport::PacketBuffer::new(rekey_msg1.clone()),
            1_001,
        )
    };

    responder.handle_msg1(packet()).await;
    let first_msg2 = tokio::time::timeout(Duration::from_millis(20), initiator_packet_rx.recv())
        .await
        .expect("first rekey Msg2 should be sent")
        .expect("initiator transport should remain open")
        .data
        .into_vec();
    let pending_our_index = responder
        .get_peer(&initiator_addr)
        .and_then(|peer| peer.pending_our_index())
        .expect("responder should retain the pending rekey session");

    responder.handle_msg1(packet()).await;
    let duplicate_pending_msg2 =
        tokio::time::timeout(Duration::from_millis(20), initiator_packet_rx.recv())
            .await
            .expect("duplicate rekey Msg1 should resend Msg2 while pending")
            .expect("initiator transport should remain open")
            .data
            .into_vec();
    assert_eq!(duplicate_pending_msg2, first_msg2);
    assert_eq!(
        responder
            .get_peer(&initiator_addr)
            .and_then(|peer| peer.pending_our_index()),
        Some(pending_our_index),
        "duplicate Msg1 must not replace the pending receive epoch"
    );

    // If every Msg2 reply is lost, the initiator eventually abandons its
    // sender index and starts a fresh rekey. The responder must replace the
    // orphaned responder-side pending epoch instead of dropping the new Msg1
    // forever merely because an unconfirmed pending session still exists.
    let replacement_their_index = SessionIndex::new(78);
    let mut replacement_initiator = crate::noise::HandshakeState::new_initiator(
        initiator.keypair(),
        responder.identity.pubkey_full(),
    );
    replacement_initiator.set_local_epoch(remote_epoch);
    let replacement_msg1 = build_msg1(
        replacement_their_index,
        &replacement_initiator.write_message_1().unwrap(),
    );
    let replacement_packet = || {
        ReceivedPacket::with_timestamp(
            transport_id,
            remote_addr.clone(),
            crate::transport::PacketBuffer::new(replacement_msg1.clone()),
            1_002,
        )
    };

    responder.handle_msg1(replacement_packet()).await;
    let replacement_msg2 =
        tokio::time::timeout(Duration::from_millis(20), initiator_packet_rx.recv())
            .await
            .expect("fresh rekey Msg1 should replace an orphaned responder pending epoch")
            .expect("initiator transport should remain open")
            .data
            .into_vec();
    assert_ne!(replacement_msg2, first_msg2);
    let replacement_our_index = responder
        .get_peer(&initiator_addr)
        .and_then(|peer| peer.pending_our_index())
        .expect("replacement responder pending epoch should own an index");
    assert_ne!(replacement_our_index, pending_our_index);
    assert_eq!(
        responder
            .get_peer(&initiator_addr)
            .and_then(|peer| peer.pending_their_index()),
        Some(replacement_their_index),
        "fresh sender index must own the replacement responder pending epoch"
    );

    responder
        .peers
        .get_mut(&initiator_addr)
        .unwrap()
        .handle_peer_kbit_flip()
        .expect("responder cutover should promote the pending session");
    responder.handle_msg1(replacement_packet()).await;
    let duplicate_after_cutover_msg2 =
        tokio::time::timeout(Duration::from_millis(20), initiator_packet_rx.recv())
            .await
            .expect("late duplicate rekey Msg1 should resend Msg2 after cutover")
            .expect("initiator transport should remain open")
            .data
            .into_vec();
    assert_eq!(duplicate_after_cutover_msg2, replacement_msg2);
    let retained = responder.get_peer(&initiator_addr).unwrap();
    assert_eq!(retained.our_index(), Some(replacement_our_index));
    assert!(retained.pending_new_session().is_none());

    match responder.transports.get_mut(&transport_id).unwrap() {
        TransportHandle::Sim(transport) => transport.stop_async().await.unwrap(),
        _ => unreachable!("sim transport fixture"),
    }
    initiator_transport.stop_async().await.unwrap();
    crate::unregister_sim_network(&network_name);
}

#[tokio::test]
async fn fresh_msg1_from_changed_udp_source_replaces_path_instead_of_starting_rekey() {
    use crate::ReceivedPacket;
    use crate::node::wire::build_msg1;
    use crate::peer::{ActivePeer, ActivePeerSession};
    use crate::transport::{LinkStats, TransportHandle};

    let mut responder = make_node();
    responder.config.node.rekey.enabled = true;
    let initiator = Identity::generate();
    let initiator_peer = PeerIdentity::from_pubkey_full(initiator.pubkey_full());
    let initiator_addr = *initiator_peer.node_addr();
    let transport_id = TransportId::new(1);
    let retained_link_id = responder.allocate_link_id();
    let old_remote_addr = TransportAddr::from_string("127.0.0.1:9");
    let current_our_index = responder.index_allocator.allocate().unwrap();
    let current_their_index = SessionIndex::new(20);
    let remote_epoch = [0xA1; 8];

    let mut current_initiator = crate::noise::HandshakeState::new_initiator(
        initiator.keypair(),
        responder.identity.pubkey_full(),
    );
    let mut current_responder =
        crate::noise::HandshakeState::new_responder(responder.identity.keypair());
    current_initiator.set_local_epoch(remote_epoch);
    current_responder.set_local_epoch(responder.startup_epoch);
    let current_msg1 = current_initiator.write_message_1().unwrap();
    current_responder.read_message_1(&current_msg1).unwrap();
    let current_msg2 = current_responder.write_message_2().unwrap();
    current_initiator.read_message_2(&current_msg2).unwrap();
    let current_session = current_responder.into_session().unwrap();
    let mut active = ActivePeer::with_session(
        initiator_peer,
        retained_link_id,
        1_000,
        ActivePeerSession {
            session: current_session,
            our_index: current_our_index,
            their_index: current_their_index,
            transport_id,
            current_addr: old_remote_addr.clone(),
            link_stats: LinkStats::new(),
            is_initiator: false,
            remote_epoch: Some(remote_epoch),
        },
    );
    active.set_session_established_at_for_test(std::time::Instant::now() - Duration::from_secs(31));
    responder
        .peers
        .insert_with_current_session_index(initiator_addr, active);
    responder.links.insert(
        retained_link_id,
        Link::connectionless(
            retained_link_id,
            transport_id,
            old_remote_addr.clone(),
            LinkDirection::Inbound,
            Duration::from_millis(1),
        ),
    );
    responder
        .links
        .insert_addr((transport_id, old_remote_addr), retained_link_id);
    assert!(responder.sync_dataplane_fmp_owner(&initiator_addr));

    let (packet_tx, _packet_rx) = packet_channel(16);
    let mut responder_transport = UdpTransport::new(
        transport_id,
        Some("changed-source-responder".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    responder_transport.start_async().await.unwrap();
    responder
        .transports
        .insert(transport_id, TransportHandle::Udp(responder_transport));

    let roamed_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let roamed_addr = TransportAddr::from_string(&roamed_socket.local_addr().unwrap().to_string());
    let replacement_their_index = SessionIndex::new(77);
    let mut replacement_initiator = crate::noise::HandshakeState::new_initiator(
        initiator.keypair(),
        responder.identity.pubkey_full(),
    );
    replacement_initiator.set_local_epoch(remote_epoch);
    let replacement_msg1 = build_msg1(
        replacement_their_index,
        &replacement_initiator.write_message_1().unwrap(),
    );

    responder
        .handle_msg1(ReceivedPacket::with_timestamp(
            transport_id,
            roamed_addr.clone(),
            crate::transport::PacketBuffer::new(replacement_msg1),
            2_000,
        ))
        .await;

    let mut msg2 = [0u8; 512];
    tokio::time::timeout(Duration::from_millis(100), roamed_socket.recv(&mut msg2))
        .await
        .expect("the changed UDP source must receive the replacement Msg2")
        .expect("replacement Msg2 receive");
    let replaced = responder.get_peer(&initiator_addr).unwrap();
    assert_eq!(replaced.current_addr(), Some(&roamed_addr));
    assert_eq!(replaced.their_index(), Some(replacement_their_index));
    assert!(
        replaced.pending_new_session().is_none(),
        "a changed UDP source is a full path replacement, not a responder-pending rekey"
    );

    for transport in responder.transports.values_mut() {
        transport.stop().await.ok();
    }
}
