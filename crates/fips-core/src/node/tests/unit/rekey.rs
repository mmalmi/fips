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
        ActivePeerSession {
            session: current_session,
            our_index: old_our_index,
            their_index: old_their_index,
            transport_id,
            current_addr: remote_addr,
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: Some([0x02; 8]),
        },
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

/// `deregister_session_index` is used both when a peer is going away
/// and during rekey drain. Retiring an old receiver index must not
/// remove the active peer or its newer receiver index.
#[test]
fn test_deregister_session_index_preserves_peer_on_rekey_drain() {
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

    // Deregister the OLD index. This is the rekey-drain pattern:
    // the peer is still present and the NEW index is still in active
    // peer registry session-index dispatch.
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
}
