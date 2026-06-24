use super::*;

#[tokio::test]
async fn fmp_rekey_responder_pending_session_does_not_time_cutover() {
    let mut node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let remote_addr = TransportAddr::from_string("127.0.0.1:5000");
    let old_our_index = SessionIndex::new(10);
    let old_their_index = SessionIndex::new(20);
    let pending_our_index = SessionIndex::new(11);
    let pending_their_index = SessionIndex::new(21);

    let current_session = make_test_fmp_session(&node.identity, &peer_full, [0x01; 8], [0x02; 8]);
    let pending_session = make_test_fmp_session(&node.identity, &peer_full, [0x03; 8], [0x04; 8]);
    let mut active_peer = ActivePeer::with_session(
        peer_identity,
        link_id,
        1_000,
        current_session,
        old_our_index,
        old_their_index,
        transport_id,
        remote_addr,
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([0x02; 8]),
    );
    active_peer.set_pending_session(
        pending_session,
        pending_our_index,
        pending_their_index,
        false,
    );

    node.peers.insert(peer_node_addr, active_peer);
    node.peers
        .insert_session_index((transport_id, old_our_index.as_u32()), peer_node_addr);
    node.peers
        .insert_session_index((transport_id, pending_our_index.as_u32()), peer_node_addr);

    node.check_rekey().await;

    let active_peer = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active_peer.our_index(), Some(old_our_index));
    assert_eq!(active_peer.their_index(), Some(old_their_index));
    assert!(active_peer.pending_new_session().is_some());
    assert!(
        !active_peer.pending_rekey_initiator(),
        "FMP responder must wait for peer K-bit instead of cutting over on its own tick"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn fmp_rekey_initiator_cutover_refreshes_connected_udp_fast_path() {
    let mut node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let remote_addr = TransportAddr::from_string("127.0.0.1:5000");
    let old_our_index = SessionIndex::new(10);
    let old_their_index = SessionIndex::new(20);
    let pending_our_index = SessionIndex::new(11);
    let pending_their_index = SessionIndex::new(21);

    let current_session = make_test_fmp_session(&node.identity, &peer_full, [0x01; 8], [0x02; 8]);
    let pending_session = make_test_fmp_session(&node.identity, &peer_full, [0x03; 8], [0x04; 8]);
    let mut active_peer = ActivePeer::with_session(
        peer_identity,
        link_id,
        1_000,
        current_session,
        old_our_index,
        old_their_index,
        transport_id,
        remote_addr,
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([0x02; 8]),
    );
    let k_before = active_peer.current_k_bit();
    active_peer.set_pending_session(
        pending_session,
        pending_our_index,
        pending_their_index,
        true,
    );
    let (socket, drain) = make_test_connected_udp_pair(transport_id);
    active_peer.set_connected_udp(socket, drain);

    node.peers.insert(peer_node_addr, active_peer);
    node.peers
        .insert_session_index((transport_id, old_our_index.as_u32()), peer_node_addr);
    node.peers
        .insert_session_index((transport_id, pending_our_index.as_u32()), peer_node_addr);

    tokio::time::sleep(std::time::Duration::from_millis(260)).await;
    node.check_rekey().await;

    let active_peer = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active_peer.our_index(), Some(pending_our_index));
    assert_eq!(active_peer.their_index(), Some(pending_their_index));
    assert_eq!(active_peer.current_k_bit(), !k_before);
    assert!(
        active_peer.connected_udp().is_none(),
        "connected UDP must refresh after cutover so canonical receive uses fresh session indexes"
    );
}

#[tokio::test]
async fn fmp_kbit_flip_requires_pending_authentication_before_promotion() {
    let mut node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let remote_addr = TransportAddr::from_string("127.0.0.1:5000");
    let old_our_index = SessionIndex::new(10);
    let old_their_index = SessionIndex::new(20);
    let pending_our_index = SessionIndex::new(11);
    let pending_their_index = SessionIndex::new(21);

    let (current_receiver, _current_sender) =
        make_test_fmp_session_pair(&node.identity, &peer_full, [0x01; 8], [0x02; 8]);
    let (pending_receiver, _pending_sender) =
        make_test_fmp_session_pair(&node.identity, &peer_full, [0x03; 8], [0x04; 8]);
    let (_stale_receiver, mut stale_sender) =
        make_test_fmp_session_pair(&node.identity, &peer_full, [0x05; 8], [0x06; 8]);

    let mut active_peer = ActivePeer::with_session(
        peer_identity,
        link_id,
        1_000,
        current_receiver,
        old_our_index,
        old_their_index,
        transport_id,
        remote_addr.clone(),
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([0x02; 8]),
    );
    let k_before = active_peer.current_k_bit();
    active_peer.set_pending_session(
        pending_receiver,
        pending_our_index,
        pending_their_index,
        false,
    );

    node.peers.insert(peer_node_addr, active_peer);
    node.peers
        .insert_session_index((transport_id, old_our_index.as_u32()), peer_node_addr);
    node.peers
        .insert_session_index((transport_id, pending_our_index.as_u32()), peer_node_addr);

    let packet_data = seal_test_fmp_packet(
        &mut stale_sender,
        pending_our_index,
        &[0, 0, 0, 0, 0xAA],
        !k_before,
    );
    let packet =
        ReceivedPacket::with_timestamp(transport_id, remote_addr.clone(), packet_data, 2_000);

    node.handle_encrypted_frame(packet).await;

    let active_peer = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active_peer.our_index(), Some(old_our_index));
    assert_eq!(active_peer.their_index(), Some(old_their_index));
    assert_eq!(active_peer.current_k_bit(), k_before);
    assert!(active_peer.pending_new_session().is_some());
    assert!(active_peer.previous_session().is_none());
}

#[tokio::test]
async fn fmp_rekey_msg1_resend_budget_zero_abandons_immediately() {
    let mut node = make_node();
    node.config.node.rate_limit.handshake_max_resends = 0;

    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let remote_addr = TransportAddr::from_string("127.0.0.1:5000");
    let old_our_index = SessionIndex::new(10);
    let old_their_index = SessionIndex::new(20);
    let rekey_our_index = SessionIndex::new(11);

    let mut active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        link_id,
        remote_addr,
        old_our_index,
        old_their_index,
    );
    arm_test_fmp_rekey(&mut active_peer, rekey_our_index);
    node.pending_outbound
        .insert((transport_id, rekey_our_index.as_u32()), link_id);
    node.peers.insert(peer_node_addr, active_peer);

    node.resend_pending_rekeys(0).await;

    let active_peer = node.get_peer(&peer_node_addr).unwrap();
    assert!(!active_peer.rekey_in_progress());
    assert!(active_peer.rekey_msg1().is_none());
    assert_eq!(active_peer.rekey_our_index(), None);
    assert!(
        !node
            .pending_outbound
            .contains_key(&(transport_id, rekey_our_index.as_u32())),
        "abandoned FMP rekey must remove pending_outbound dispatch state"
    );
}

#[tokio::test]
async fn fmp_rekey_msg1_resend_records_count_and_backoff() {
    let mut node = make_node();
    node.config.node.rate_limit.handshake_resend_interval_ms = 10;
    node.config.node.rate_limit.handshake_resend_backoff = 2.0;
    node.config.node.rate_limit.handshake_max_resends = 5;

    let transport_id = TransportId::new(1);
    let (packet_tx, _packet_rx) = packet_channel(64);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("rekey-resend-test".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let link_id = LinkId::new(1);
    let remote_addr = TransportAddr::from_string("127.0.0.1:9");
    let old_our_index = SessionIndex::new(10);
    let old_their_index = SessionIndex::new(20);
    let rekey_our_index = SessionIndex::new(11);

    let mut active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        link_id,
        remote_addr,
        old_our_index,
        old_their_index,
    );
    arm_test_fmp_rekey(&mut active_peer, rekey_our_index);
    node.peers.insert(peer_node_addr, active_peer);

    node.resend_pending_rekeys(100).await;

    let active_peer = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active_peer.rekey_msg1_resend_count(), 1);
    assert!(!active_peer.needs_msg1_resend(119));
    assert!(active_peer.needs_msg1_resend(120));

    let mut transport = node.transports.remove(&transport_id).unwrap();
    transport.stop().await.unwrap();
}

#[tokio::test]
async fn link_dead_heartbeat_suppressed_while_fmp_rekey_has_budget() {
    let mut node = make_node();
    node.config.node.link_dead_timeout_secs = 0;
    node.config.node.rate_limit.handshake_max_resends = 5;

    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let remote_addr = TransportAddr::from_string("127.0.0.1:5000");
    let old_our_index = SessionIndex::new(10);
    let old_their_index = SessionIndex::new(20);
    let rekey_our_index = SessionIndex::new(11);

    let mut active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        link_id,
        remote_addr,
        old_our_index,
        old_their_index,
    );
    arm_test_fmp_rekey(&mut active_peer, rekey_our_index);
    node.peers.insert(peer_node_addr, active_peer);

    node.check_link_heartbeats().await;

    let active_peer = node.get_peer(&peer_node_addr).unwrap();
    assert!(
        active_peer.is_healthy(),
        "link-dead cleanup must not stale a peer with an in-flight FMP rekey"
    );
}

/// `deregister_session_index` is used both for "peer is going away"
/// (where the connected UDP socket must be torn down) and for
/// "rekey drain completion — old session index retires while the
/// peer's NEW index keeps the connect()-ed 5-tuple". Pre-fix this
/// helper unconditionally cleared connected UDP, which would close
/// the per-peer kernel socket on every rekey on Linux. Validate
/// that when the peer still has another session-index entry in the active peer registry,
/// the connected UDP socket is preserved.
#[cfg(target_os = "linux")]
#[test]
fn test_deregister_session_index_preserves_connected_udp_on_rekey_drain() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Set up a peer with an established session at index_old.
    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();
    let index_old = node
        .get_peer(&node_addr)
        .unwrap()
        .our_index()
        .unwrap()
        .as_u32();

    // Pre-register a "new" index for the peer (as happens during a
    // rekey: msg1 receive pre-registers the new our_index in
    // active peer registry session-index dispatch while the old index stays around until drain
    // completes).
    let index_new: u32 = 9999;
    node.peers
        .insert_session_index((transport_id, index_new), node_addr);

    // Deregister the OLD index. This is the rekey-drain pattern.
    // The peer is still present, the NEW index is still in
    // active peer registry session-index dispatch, so the per-peer connected UDP socket
    // (if any was installed) must NOT be torn down. The test
    // doesn't install a real ConnectedPeerSocket; instead it
    // checks the peer is still in `node.peers` and has a peer-
    // alive observable state.
    node.deregister_session_index((transport_id, index_old));

    assert!(
        !node
            .peers
            .contains_session_index(&(transport_id, index_old)),
        "old index must be evicted"
    );
    assert!(
        node.peers
            .contains_session_index(&(transport_id, index_new)),
        "new index must survive the deregister"
    );
    assert!(
        node.get_peer(&node_addr).is_some(),
        "peer must still be present after rekey-drain deregistration"
    );
    assert!(
        !node
            .sessions
            .is_worker_registered(&crate::node::decrypt_worker::DecryptSessionKey::new(
                transport_id,
                index_old
            )),
        "old session must be evicted from the session registry worker-registration mirror"
    );
}
