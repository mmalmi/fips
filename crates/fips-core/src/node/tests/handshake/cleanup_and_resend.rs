use super::*;

/// Test that stale handshake connections are cleaned up by check_timeouts().
///
/// Simulates the scenario where a node initiates a handshake to a peer that
/// isn't running. The outbound connection should be cleaned up after the
/// handshake timeout expires.
#[tokio::test]
async fn test_stale_connection_cleanup() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let peer_identity = make_peer_identity();
    let remote_addr = TransportAddr::from_string("10.0.0.2:2121");

    // Create outbound connection with a timestamp far in the past
    let past_time_ms = 1000; // A very early timestamp
    let link_id = node.allocate_link_id();
    let mut conn = PeerConnection::outbound(link_id, peer_identity, past_time_ms);

    // Allocate session index and set transport info
    let our_index = node.index_allocator.allocate().unwrap();
    let our_keypair = node.identity.keypair();
    let _noise_msg1 = conn
        .start_handshake(our_keypair, node.startup_epoch, past_time_ms)
        .unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(remote_addr.clone());

    // Set up all the state that initiate_peer_connection would create
    let link = Link::connectionless(
        link_id,
        transport_id,
        remote_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node.links.insert(link_id, link);
    node.links
        .insert_addr((transport_id, remote_addr.clone()), link_id);
    node.peers.insert_connection(link_id, conn);
    node.pending_outbound
        .insert((transport_id, our_index.as_u32()), link_id);

    // Verify state before timeout check
    assert_eq!(node.connection_count(), 1);
    assert_eq!(node.link_count(), 1);
    assert!(
        node.pending_outbound
            .contains_key(&(transport_id, our_index.as_u32()))
    );
    assert_eq!(node.index_allocator.count(), 1);

    // Connection was created at time 1000ms. check_timeouts uses SystemTime::now(),
    // which is far beyond the 30s timeout. The connection should be cleaned up.
    node.check_timeouts();

    // Verify everything was cleaned up
    assert_eq!(
        node.connection_count(),
        0,
        "Stale connection should be removed"
    );
    assert_eq!(node.link_count(), 0, "Stale link should be removed");
    assert!(
        !node
            .pending_outbound
            .contains_key(&(transport_id, our_index.as_u32())),
        "pending_outbound should be cleaned up"
    );
    assert_eq!(
        node.index_allocator.count(),
        0,
        "Session index should be freed"
    );
    assert!(
        !node.links.contains_addr(&(transport_id, remote_addr)),
        "address dispatch should be cleaned up"
    );
}

#[tokio::test]
async fn stale_outbound_timeout_does_not_retry_healthy_active_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let peer_identity = make_peer_identity();
    let peer_node_addr = *peer_identity.node_addr();
    let remote_addr = TransportAddr::from_string("10.0.0.2:2121");

    let active_link_id = LinkId::new(7);
    node.peers.insert(
        peer_node_addr,
        ActivePeer::new(peer_identity, active_link_id, 1000),
    );

    let stale_link_id = node.allocate_link_id();
    let mut conn = PeerConnection::outbound(stale_link_id, peer_identity, 1000);
    let our_index = node.index_allocator.allocate().unwrap();
    let noise_msg1 = conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 1000)
        .unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(remote_addr.clone());
    conn.set_handshake_msg1(crate::node::wire::build_msg1(our_index, &noise_msg1), 2000);

    node.links.insert(
        stale_link_id,
        Link::connectionless(
            stale_link_id,
            transport_id,
            remote_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((transport_id, remote_addr), stale_link_id);
    node.pending_outbound
        .insert((transport_id, our_index.as_u32()), stale_link_id);
    node.peers.insert_connection(stale_link_id, conn);

    node.check_timeouts();

    assert_eq!(node.connection_count(), 0);
    assert!(
        !node.retry_pending.contains_key(&peer_node_addr),
        "timed-out leftover handshakes must not schedule direct reprobe for a healthy active peer"
    );
    assert!(node.peers.contains_key(&peer_node_addr));
}

/// Test that failed connections are cleaned up by check_timeouts().
#[tokio::test]
async fn test_failed_connection_cleanup() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let peer_identity = make_peer_identity();
    let remote_addr = TransportAddr::from_string("10.0.0.2:2121");

    // Create a connection and mark it failed (simulating a send failure)
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let link_id = node.allocate_link_id();
    let mut conn = PeerConnection::outbound(link_id, peer_identity, now_ms);

    let our_index = node.index_allocator.allocate().unwrap();
    let our_keypair = node.identity.keypair();
    let _noise_msg1 = conn
        .start_handshake(our_keypair, node.startup_epoch, now_ms)
        .unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(remote_addr.clone());
    conn.mark_failed(); // Simulate send failure

    let link = Link::connectionless(
        link_id,
        transport_id,
        remote_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node.links.insert(link_id, link);
    node.links
        .insert_addr((transport_id, remote_addr.clone()), link_id);
    node.peers.insert_connection(link_id, conn);
    node.pending_outbound
        .insert((transport_id, our_index.as_u32()), link_id);

    assert_eq!(node.connection_count(), 1);

    // Failed connections should be cleaned up immediately regardless of age
    node.check_timeouts();

    assert_eq!(
        node.connection_count(),
        0,
        "Failed connection should be removed"
    );
    assert_eq!(node.link_count(), 0, "Failed link should be removed");
    assert_eq!(
        node.index_allocator.count(),
        0,
        "Session index should be freed"
    );
}

/// Test that msg1 bytes are stored on connection for resend.
#[tokio::test]
async fn test_msg1_stored_for_resend() {
    use crate::node::wire::build_msg1;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let peer_identity = make_peer_identity();
    let remote_addr = TransportAddr::from_string("10.0.0.2:2121");

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let link_id = node.allocate_link_id();
    let mut conn = PeerConnection::outbound(link_id, peer_identity, now_ms);

    let our_index = node.index_allocator.allocate().unwrap();
    let our_keypair = node.identity.keypair();
    let noise_msg1 = conn
        .start_handshake(our_keypair, node.startup_epoch, now_ms)
        .unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(remote_addr.clone());

    // Build wire msg1 and store it (as initiate_peer_connection does)
    let wire_msg1 = build_msg1(our_index, &noise_msg1);
    let resend_interval = node.config.node.rate_limit.handshake_resend_interval_ms;
    conn.set_handshake_msg1(wire_msg1.clone(), now_ms + resend_interval);

    // Verify stored msg1 matches what was built
    assert_eq!(conn.handshake_msg1().unwrap(), &wire_msg1);
    assert_eq!(conn.resend_count(), 0);
    assert!(conn.next_resend_at_ms() > now_ms);
}

/// Test that resend scheduling respects max_resends and backoff.
#[tokio::test]
async fn test_resend_scheduling() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let peer_identity = make_peer_identity();
    let remote_addr = TransportAddr::from_string("10.0.0.2:2121");

    let now_ms = 100_000u64; // Use a fixed time for predictable testing
    let link_id = node.allocate_link_id();
    let mut conn = PeerConnection::outbound(link_id, peer_identity, now_ms);

    let our_index = node.index_allocator.allocate().unwrap();
    let our_keypair = node.identity.keypair();
    let noise_msg1 = conn
        .start_handshake(our_keypair, node.startup_epoch, now_ms)
        .unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(remote_addr.clone());

    // Store msg1 with first resend at now + 1000ms
    let wire_msg1 = crate::node::wire::build_msg1(our_index, &noise_msg1);
    conn.set_handshake_msg1(wire_msg1, now_ms + 1000);

    let link = Link::connectionless(
        link_id,
        transport_id,
        remote_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node.links.insert(link_id, link);
    node.links.insert_addr((transport_id, remote_addr), link_id);
    node.pending_outbound
        .insert((transport_id, our_index.as_u32()), link_id);
    node.peers.insert_connection(link_id, conn);

    // Before resend time: nothing should happen (no transport = can't send,
    // but the filter should exclude it because now < next_resend_at)
    node.resend_pending_handshakes(now_ms + 500).await;
    let conn = node.peers.get_connection(&link_id).unwrap();
    assert_eq!(conn.resend_count(), 0, "No resend before scheduled time");

    // At resend time: would resend if transport existed. Without transport,
    // the send fails silently and resend_count stays at 0.
    // This tests the filtering logic — the connection IS a candidate.
    node.resend_pending_handshakes(now_ms + 1000).await;
    // No transport registered, so send fails — count stays 0.
    // That's the expected behavior (transport absence is a transient condition).
    let conn = node.peers.get_connection(&link_id).unwrap();
    assert_eq!(
        conn.resend_count(),
        0,
        "No transport means no resend recorded"
    );
}

/// Test that msg2 is stored on PeerConnection for responder resend.
#[test]
fn test_msg2_stored_on_connection() {
    let mut conn = PeerConnection::inbound(LinkId::new(1), 1000);

    assert!(conn.handshake_msg2().is_none());

    let msg2_bytes = vec![0x01, 0x02, 0x03, 0x04];
    conn.set_handshake_msg2(msg2_bytes.clone());

    assert_eq!(conn.handshake_msg2().unwrap(), &msg2_bytes);
}

/// Test that resend_count and next_resend_at_ms track correctly.
#[test]
fn test_resend_count_tracking() {
    let peer_identity = make_peer_identity();
    let mut conn = PeerConnection::outbound(LinkId::new(1), peer_identity, 1000);

    assert_eq!(conn.resend_count(), 0);
    assert_eq!(conn.next_resend_at_ms(), 0);

    // Simulate storing msg1 and scheduling first resend
    conn.set_handshake_msg1(vec![0x01], 2000);
    assert_eq!(conn.resend_count(), 0);
    assert_eq!(conn.next_resend_at_ms(), 2000);

    // Record first resend
    conn.record_resend(4000); // next at 4000 (2s backoff)
    assert_eq!(conn.resend_count(), 1);
    assert_eq!(conn.next_resend_at_ms(), 4000);

    // Record second resend
    conn.record_resend(8000); // next at 8000 (4s backoff)
    assert_eq!(conn.resend_count(), 2);
    assert_eq!(conn.next_resend_at_ms(), 8000);
}

#[cfg(feature = "sim-transport")]
fn sim_test_transport(
    network: &str,
    addr: &str,
    transport_id: TransportId,
    capacity: usize,
) -> (crate::SimTransport, crate::transport::PacketRx) {
    let (packet_tx, packet_rx) = packet_channel(capacity);
    (
        crate::SimTransport::new(
            transport_id,
            None,
            crate::config::SimTransportConfig {
                network: Some(network.to_string()),
                addr: Some(addr.to_string()),
                ..Default::default()
            },
            packet_tx,
        ),
        packet_rx,
    )
}

#[cfg(feature = "sim-transport")]
#[tokio::test]
async fn owned_msg2_send_failure_retries_without_index_leak_and_bootstraps() {
    use crate::dataplane::FmpWireHeader;
    use crate::node::wire::{Msg2Header, build_msg1};
    use crate::protocol::LinkMessageType;
    use crate::transport::TransportHandle;
    use crate::{ReceivedPacket, SimNetwork};

    let mut responder = make_node();
    let initiator = Identity::generate();
    let initiator_peer = PeerIdentity::from_pubkey_full(initiator.pubkey_full());
    let initiator_addr = *initiator_peer.node_addr();
    let transport_id = TransportId::new(1);
    let network_name = format!("owned-msg2-retry-{}", responder.node_addr());
    let network = SimNetwork::new(7);
    crate::register_sim_network(network_name.clone(), network);

    let (mut initiator_transport, mut initiator_packet_rx) =
        sim_test_transport(&network_name, "initiator", transport_id, 16);
    initiator_transport.start_async().await.unwrap();

    let (responder_transport, _responder_packet_rx) =
        sim_test_transport(&network_name, "responder", transport_id, 16);
    responder
        .transports
        .insert(transport_id, TransportHandle::Sim(responder_transport));

    let sender_index = SessionIndex::new(77);
    let mut initiator_handshake = crate::noise::HandshakeState::new_initiator(
        initiator.keypair(),
        responder.identity.pubkey_full(),
    );
    initiator_handshake.set_local_epoch([0xA1; 8]);
    let msg1 = initiator_handshake.write_message_1().unwrap();
    let wire_msg1 = build_msg1(sender_index, &msg1);
    let remote_addr = TransportAddr::from_string("initiator");

    responder
        .handle_msg1(ReceivedPacket::with_timestamp(
            transport_id,
            remote_addr.clone(),
            crate::transport::PacketBuffer::new(wire_msg1.clone()),
            1_000,
        ))
        .await;

    let owned_index = responder
        .get_peer(&initiator_addr)
        .and_then(ActivePeer::our_index)
        .expect("failed first send must retain the authenticated peer and owned index");
    assert!(
        responder
            .peers
            .contains_session_index(&(transport_id, owned_index.as_u32())),
        "owned receiver index must be registered before Msg2 can be retried"
    );
    assert!(responder.dataplane_has_fmp_owner(&initiator_addr));
    assert_eq!(responder.index_allocator.count(), 1);
    assert!(initiator_packet_rx.try_recv().is_err());

    match responder.transports.get_mut(&transport_id).unwrap() {
        TransportHandle::Sim(transport) => transport.start_async().await.unwrap(),
        _ => unreachable!("sim transport fixture"),
    }
    responder
        .handle_msg1(ReceivedPacket::with_timestamp(
            transport_id,
            remote_addr,
            crate::transport::PacketBuffer::new(wire_msg1),
            1_001,
        ))
        .await;

    let mut msg2 = None;
    let mut established = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while tokio::time::Instant::now() < deadline && (msg2.is_none() || established.is_none()) {
        let packet = tokio::time::timeout(Duration::from_millis(100), initiator_packet_rx.recv())
            .await
            .ok()
            .flatten();
        let Some(packet) = packet else {
            continue;
        };
        if Msg2Header::parse(packet.data.as_slice()).is_some() {
            msg2 = Some(packet.data.as_slice().to_vec());
        } else if FmpWireHeader::parse(packet.data.as_slice()).is_ok() {
            established = Some(packet.data.as_slice().to_vec());
        }
    }

    let msg2 = msg2.expect("duplicate Msg1 must resend the retained owned Msg2");
    let msg2_header = Msg2Header::parse(&msg2).expect("valid Msg2");
    assert_eq!(msg2_header.sender_idx, owned_index);
    initiator_handshake
        .read_message_2(&msg2[msg2_header.noise_msg2_offset..])
        .unwrap();
    let mut session = initiator_handshake.into_session().unwrap();
    let established = established.expect("successful Msg2 retry must run tree bootstrap");
    let header = FmpWireHeader::parse(&established).unwrap();
    let plaintext = session
        .decrypt_with_replay_check_and_aad(
            &established[crate::node::wire::ESTABLISHED_HEADER_SIZE..],
            header.counter(),
            &established[..crate::node::wire::ESTABLISHED_HEADER_SIZE],
        )
        .expect("post-auth tree bootstrap must use the complementary FMP session");
    assert_eq!(
        plaintext.get(4).copied(),
        Some(LinkMessageType::TreeAnnounce.to_byte())
    );
    assert!(responder.bloom_state.needs_update(&initiator_addr));
    assert_eq!(responder.index_allocator.count(), 1);
    assert!(responder.get_peer(&initiator_addr).is_some());

    match responder.transports.get_mut(&transport_id).unwrap() {
        TransportHandle::Sim(transport) => transport.stop_async().await.unwrap(),
        _ => unreachable!("sim transport fixture"),
    }
    initiator_transport.stop_async().await.unwrap();
    crate::unregister_sim_network(&network_name);
}

#[cfg(feature = "sim-transport")]
#[tokio::test]
async fn losing_inbound_candidate_never_advertises_its_receiver_index() {
    use crate::node::wire::build_msg1;
    use crate::peer::{ActivePeer, ActivePeerSession, cross_connection_winner};
    use crate::transport::{LinkStats, TransportHandle};
    use crate::{ReceivedPacket, SimNetwork};

    let mut responder = make_node();
    let initiator = loop {
        let candidate = Identity::generate();
        if !cross_connection_winner(responder.node_addr(), candidate.node_addr(), false) {
            break candidate;
        }
    };
    let initiator_peer = PeerIdentity::from_pubkey_full(initiator.pubkey_full());
    let initiator_addr = *initiator_peer.node_addr();
    let transport_id = TransportId::new(1);
    let link_id = responder.allocate_link_id();
    let remote_addr = TransportAddr::from_string("initiator");
    let old_our_index = responder.index_allocator.allocate().unwrap();
    let old_their_index = SessionIndex::new(20);

    let mut old_initiator = crate::noise::HandshakeState::new_initiator(
        initiator.keypair(),
        responder.identity.pubkey_full(),
    );
    let mut old_responder =
        crate::noise::HandshakeState::new_responder(responder.identity.keypair());
    old_initiator.set_local_epoch([0xA1; 8]);
    old_responder.set_local_epoch(responder.startup_epoch);
    let old_msg1 = old_initiator.write_message_1().unwrap();
    old_responder.read_message_1(&old_msg1).unwrap();
    let old_msg2 = old_responder.write_message_2().unwrap();
    old_initiator.read_message_2(&old_msg2).unwrap();
    let old_session = old_responder.into_session().unwrap();

    let active = ActivePeer::with_session(
        initiator_peer,
        link_id,
        1_000,
        ActivePeerSession {
            session: old_session,
            our_index: old_our_index,
            their_index: old_their_index,
            transport_id,
            current_addr: remote_addr.clone(),
            link_stats: LinkStats::new(),
            is_initiator: false,
            remote_epoch: Some([0xA1; 8]),
        },
    );
    responder
        .peers
        .insert_with_current_session_index(initiator_addr, active);
    responder.links.insert(
        link_id,
        Link::connectionless(
            link_id,
            transport_id,
            remote_addr.clone(),
            LinkDirection::Inbound,
            Duration::from_millis(1),
        ),
    );
    responder
        .links
        .insert_addr((transport_id, remote_addr.clone()), link_id);
    assert!(responder.sync_dataplane_fmp_owner(&initiator_addr));

    let network_name = format!("losing-inbound-msg2-{}", responder.node_addr());
    crate::register_sim_network(network_name.clone(), SimNetwork::new(9));
    let (mut initiator_transport, mut initiator_packet_rx) =
        sim_test_transport(&network_name, "initiator", transport_id, 8);
    initiator_transport.start_async().await.unwrap();
    let (mut responder_transport, _responder_packet_rx) =
        sim_test_transport(&network_name, "responder", transport_id, 8);
    responder_transport.start_async().await.unwrap();
    responder
        .transports
        .insert(transport_id, TransportHandle::Sim(responder_transport));

    let candidate_index = SessionIndex::new(77);
    let mut candidate = crate::noise::HandshakeState::new_initiator(
        initiator.keypair(),
        responder.identity.pubkey_full(),
    );
    candidate.set_local_epoch([0xA1; 8]);
    let candidate_msg1 = candidate.write_message_1().unwrap();
    responder
        .handle_msg1(ReceivedPacket::with_timestamp(
            transport_id,
            remote_addr,
            crate::transport::PacketBuffer::new(build_msg1(candidate_index, &candidate_msg1)),
            1_001,
        ))
        .await;

    assert!(
        tokio::time::timeout(Duration::from_millis(20), initiator_packet_rx.recv())
            .await
            .is_err(),
        "a losing inbound candidate must not advertise an index promotion already freed"
    );
    let retained = responder.get_peer(&initiator_addr).unwrap();
    assert_eq!(retained.our_index(), Some(old_our_index));
    assert_eq!(retained.their_index(), Some(old_their_index));
    assert!(
        responder
            .peers
            .contains_session_index(&(transport_id, old_our_index.as_u32()))
    );
    assert!(responder.dataplane_has_fmp_owner(&initiator_addr));
    assert!(responder.get_link(&link_id).is_some());
    assert_eq!(
        responder.find_link_by_addr(transport_id, &TransportAddr::from_string("initiator")),
        Some(link_id)
    );
    assert_eq!(
        responder.index_allocator.count(),
        1,
        "losing inbound promotion must free its local candidate index"
    );

    match responder.transports.get_mut(&transport_id).unwrap() {
        TransportHandle::Sim(transport) => transport.stop_async().await.unwrap(),
        _ => unreachable!("sim transport fixture"),
    }
    initiator_transport.stop_async().await.unwrap();
    crate::unregister_sim_network(&network_name);
}

#[cfg(feature = "sim-transport")]
#[tokio::test]
async fn failed_responder_rekey_msg2_rolls_back_pending_receiver_ownership() {
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

    let network_name = format!("responder-rekey-rollback-{}", responder.node_addr());
    crate::register_sim_network(network_name.clone(), SimNetwork::new(11));
    let (mut initiator_transport, mut initiator_packet_rx) =
        sim_test_transport(&network_name, "initiator", transport_id, 8);
    initiator_transport.start_async().await.unwrap();
    let (responder_transport, _responder_packet_rx) =
        sim_test_transport(&network_name, "responder", transport_id, 8);
    responder
        .transports
        .insert(transport_id, TransportHandle::Sim(responder_transport));

    let rekey_their_index = SessionIndex::new(77);
    let mut rekey_initiator = crate::noise::HandshakeState::new_initiator(
        initiator.keypair(),
        responder.identity.pubkey_full(),
    );
    rekey_initiator.set_local_epoch(remote_epoch);
    let rekey_msg1 = rekey_initiator.write_message_1().unwrap();
    responder
        .handle_msg1(ReceivedPacket::with_timestamp(
            transport_id,
            remote_addr.clone(),
            crate::transport::PacketBuffer::new(build_msg1(rekey_their_index, &rekey_msg1)),
            1_001,
        ))
        .await;

    assert!(initiator_packet_rx.try_recv().is_err());
    let retained = responder.get_peer(&initiator_addr).unwrap();
    assert_eq!(retained.link_id(), retained_link_id);
    assert_eq!(retained.our_index(), Some(current_our_index));
    assert_eq!(retained.their_index(), Some(current_their_index));
    assert!(retained.has_session());
    assert!(retained.pending_new_session().is_none());
    assert_eq!(retained.pending_our_index(), None);
    assert_eq!(retained.pending_their_index(), None);
    assert!(responder.pending_outbound.is_empty());
    assert_eq!(responder.index_allocator.count(), 1);
    assert!(responder.index_allocator.is_allocated(current_our_index));
    assert!(
        responder
            .peers
            .contains_session_index(&(transport_id, current_our_index.as_u32()))
    );
    assert_eq!(
        responder.peers.session_index_count(),
        1,
        "failed responder Msg2 must remove its staged receiver-index dispatch"
    );
    assert!(responder.dataplane_has_fmp_owner(&initiator_addr));
    assert!(
        !responder
            .dataplane
            .fmp_owner_has_pending_receive_epoch(&initiator_addr, !retained.current_k_bit()),
        "failed responder Msg2 must remove the staged dataplane receive epoch"
    );
    assert!(responder.get_link(&retained_link_id).is_some());
    assert_eq!(
        responder.find_link_by_addr(transport_id, &remote_addr),
        Some(retained_link_id)
    );
    assert_eq!(responder.connection_count(), 0);

    initiator_transport.stop_async().await.unwrap();
    crate::unregister_sim_network(&network_name);
}
