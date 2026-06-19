use super::*;

#[tokio::test]
async fn fmp_recovery_rekey_epoch_change_clears_stale_fsp_session() {
    use crate::node::session::{EndToEndState, SessionEntry};
    use crate::noise::HandshakeState;

    let mut node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();

    let transport_id = TransportId::new(1);
    let (packet_tx, _packet_rx) = packet_channel(64);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("rekey-test".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let link_id = LinkId::new(10);
    let remote_addr = TransportAddr::from_string("127.0.0.1:9");
    let mut conn = PeerConnection::outbound(link_id, peer_identity, 1_000);
    let old_msg1 = conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 1_000)
        .unwrap();
    let mut old_responder = PeerConnection::inbound(LinkId::new(98), 1_000);
    let old_msg2 = old_responder
        .receive_handshake_init(peer_full.keypair(), [0x11; 8], &old_msg1, 1_000)
        .unwrap();
    conn.complete_handshake(&old_msg2, 1_000).unwrap();
    let our_index = node.index_allocator.allocate().unwrap();
    conn.set_our_index(our_index);
    conn.set_their_index(SessionIndex::new(66));
    conn.set_transport_id(transport_id);
    conn.set_source_addr(remote_addr.clone());
    node.links.insert(
        link_id,
        Link::connectionless(
            link_id,
            transport_id,
            remote_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((transport_id, remote_addr.clone()), link_id);
    node.peers.insert_connection(link_id, conn);
    node.promote_connection(link_id, peer_identity, 1_100)
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
    assert!(node.sessions.contains_key(&peer_node_addr));

    assert!(node.initiate_rekey(&peer_node_addr).await);
    let rekey_msg1 = node
        .get_peer(&peer_node_addr)
        .unwrap()
        .rekey_msg1()
        .expect("rekey msg1 should be stored")
        .to_vec();
    let header = Msg1Header::parse(&rekey_msg1).expect("valid rekey msg1");
    let noise_msg1 = &rekey_msg1[header.noise_msg1_offset..];

    let mut new_responder = HandshakeState::new_responder(peer_full.keypair());
    new_responder.set_local_epoch([0x22; 8]);
    new_responder.read_message_1(noise_msg1).unwrap();
    let new_msg2 = new_responder.write_message_2().unwrap();
    let their_index = SessionIndex::new(77);
    let wire_msg2 = build_msg2(their_index, header.sender_idx, &new_msg2);
    let packet =
        ReceivedPacket::with_timestamp(transport_id, remote_addr.clone(), wire_msg2, 2_100);

    node.handle_msg2(packet).await;

    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.remote_epoch(), Some([0x22; 8]));
    assert!(
        active.pending_new_session().is_some(),
        "FMP recovery rekey should still complete and await cutover"
    );
    assert!(
        !node.sessions.contains_key(&peer_node_addr),
        "old FSP session must be removed when FMP rekey learns a new peer startup epoch"
    );

    let mut transport = node.transports.remove(&transport_id).unwrap();
    transport.stop().await.unwrap();
}

#[tokio::test]
async fn update_peers_treats_seen_at_ms_as_metadata_not_a_change() {
    let mut node = make_node();
    let npub = npub_for_test();
    let baseline = auto_connect_peer(npub.clone(), "127.0.0.1:9");
    let _ = node.update_peers(vec![baseline]).await.unwrap();

    // Same identity + transport + addr + priority, but caller annotated
    // a freshness observation. Should NOT register as an "updated" diff.
    let mut refreshed = auto_connect_peer(npub, "127.0.0.1:9");
    refreshed.addresses[0] = refreshed.addresses[0]
        .clone()
        .with_seen_at_ms(1_700_000_000_000);

    let outcome = node.update_peers(vec![refreshed]).await.unwrap();
    assert_eq!(outcome.updated, 0);
    assert_eq!(outcome.unchanged, 1);
}

#[test]
fn overlay_adverts_share_priority_with_stamped_restart_hints() {
    let restart_hint = crate::config::PeerAddress::with_priority("udp", "203.0.113.10:51820", 100)
        .with_seen_at_ms(1_700_000_000_000);

    assert_eq!(
        Node::overlay_fallback_priority(&[restart_hint]),
        100,
        "fresh relay adverts must be able to replace restart-cache endpoints by freshness"
    );
}

#[test]
fn overlay_adverts_stay_below_operator_static_hints() {
    let operator_static = crate::config::PeerAddress::with_priority("udp", "192.0.2.10:51820", 10);
    let restart_hint = crate::config::PeerAddress::with_priority("udp", "203.0.113.10:51820", 100)
        .with_seen_at_ms(1_700_000_000_000);

    assert_eq!(
        Node::overlay_fallback_priority(&[operator_static, restart_hint]),
        101,
        "operator-provided static paths should remain preferred over overlay adverts"
    );
}

#[tokio::test]
async fn update_peers_rejects_invalid_npub_atomically() {
    let mut node = make_node();
    let valid = auto_connect_peer(npub_for_test(), "127.0.0.1:9");
    let invalid = crate::config::PeerConfig {
        npub: "not-a-real-npub".to_string(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };

    let result = node.update_peers(vec![valid, invalid]).await;
    assert!(result.is_err(), "invalid npub must reject the whole batch");
    assert!(
        node.config.peers.is_empty(),
        "rejected batch must not partially apply",
    );
}

#[test]
fn outbound_admission_check_direct() {
    let mut node = make_node();
    node.set_max_peers(3);

    assert!(node.outbound_admission_check());
    inject_dummy_peers(&mut node, 2);
    assert!(node.outbound_admission_check());
    inject_dummy_peers(&mut node, 1);
    assert!(!node.outbound_admission_check());
    inject_dummy_peers(&mut node, 1);
    assert!(!node.outbound_admission_check());

    let mut uncapped = make_node();
    uncapped.set_max_peers(0);
    assert!(uncapped.outbound_admission_check());
    inject_dummy_peers(&mut uncapped, 50);
    assert!(uncapped.outbound_admission_check());
}

#[test]
fn open_discovery_budget_counts_active_non_configured_peers() {
    let mut config = Config::new();
    config.node.discovery.nostr.open_discovery_max_pending = 2;
    let mut node = Node::new(config).unwrap();
    let configured_npubs = std::collections::HashSet::new();

    assert_eq!(node.open_discovery_enqueue_budget(&configured_npubs), 2);
    inject_dummy_peers(&mut node, 1);
    assert_eq!(node.open_discovery_enqueue_budget(&configured_npubs), 1);
    inject_dummy_peers(&mut node, 1);
    assert_eq!(
        node.open_discovery_enqueue_budget(&configured_npubs),
        0,
        "live open-discovery peers must consume the same cap as pending retries"
    );
}

#[test]
fn open_discovery_outbound_admission_stops_at_public_peer_budget() {
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = crate::config::NostrDiscoveryPolicy::Open;
    config.node.discovery.nostr.open_discovery_max_pending = 1;
    let mut node = Node::new(config).unwrap();

    assert!(node.open_discovery_outbound_admission_check());
    inject_dummy_peers(&mut node, 1);
    assert!(
        !node.open_discovery_outbound_admission_check(),
        "public traversal offers must not bypass the active open-discovery peer budget"
    );
}

#[test]
fn outbound_admission_check_respects_connection_and_link_caps() {
    let mut node = make_node();
    node.set_max_connections(2);
    node.set_max_links(2);
    assert!(node.outbound_admission_check());

    node.links.insert(
        LinkId::new(1),
        Link::connectionless(
            LinkId::new(1),
            TransportId::new(1),
            TransportAddr::from_string("127.0.0.1:10"),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links.insert(
        LinkId::new(2),
        Link::connectionless(
            LinkId::new(2),
            TransportId::new(1),
            TransportAddr::from_string("127.0.0.1:11"),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    assert!(
        !node.outbound_admission_check(),
        "bootstrap/open-discovery work must stop at max_links, not only max_peers"
    );

    let mut node = make_node();
    node.set_max_connections(1);
    let peer_identity = make_peer_identity();
    let link_id = LinkId::new(3);
    let remote_addr = TransportAddr::from_string("127.0.0.1:12");
    let mut conn = PeerConnection::outbound(link_id, peer_identity, 1_000);
    conn.set_transport_id(TransportId::new(1));
    conn.set_source_addr(remote_addr.clone());
    node.links.insert(
        link_id,
        Link::connectionless(
            link_id,
            TransportId::new(1),
            remote_addr,
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.peers.insert_connection(link_id, conn);
    assert!(
        !node.outbound_admission_check(),
        "bootstrap/open-discovery work must stop at max_connections"
    );
}

#[tokio::test]
async fn process_pending_retries_gated_at_capacity() {
    let mut node = make_node();
    node.set_max_peers(2);
    inject_dummy_peers(&mut node, 2);

    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();
    let mut state = super::super::retry::RetryState::new(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "127.0.0.1:9",
    ));
    state.retry_after_ms = 0;
    state.reconnect = true;
    node.retry_pending.insert(peer_node_addr, state);

    let before_peers = node.peer_count();
    let before_connections = node.connection_count();

    node.process_pending_retries(1_000).await;

    let state = node
        .retry_pending
        .get(&peer_node_addr)
        .expect("retry entry must be preserved when suppressed at capacity");
    assert_eq!(state.retry_count, 0);
    assert_eq!(state.retry_after_ms, 0);
    assert_eq!(node.peer_count(), before_peers);
    assert_eq!(node.connection_count(), before_connections);
}

#[tokio::test]
async fn poll_nostr_discovery_established_gated_at_capacity() {
    use crate::discovery::EstablishedTraversal;
    use std::net::UdpSocket;

    let mut node = make_node();
    node.set_max_peers(2);
    inject_dummy_peers(&mut node, 2);

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind local UDP socket");
    let remote_addr = "127.0.0.1:9999".parse().expect("parse remote addr");
    let peer_identity = Identity::generate();
    bootstrap.push_event_for_test(BootstrapEvent::Established {
        traversal: EstablishedTraversal::new(
            "cap-test-session",
            peer_identity.npub(),
            remote_addr,
            socket,
        ),
    });
    node.nostr_discovery = Some(bootstrap);

    let before_peers = node.peer_count();
    let before_links = node.link_count();
    let before_connections = node.connection_count();

    node.poll_nostr_discovery().await;

    assert_eq!(node.peer_count(), before_peers);
    assert_eq!(node.link_count(), before_links);
    assert_eq!(node.connection_count(), before_connections);
}

#[tokio::test]
async fn poll_nostr_discovery_failed_active_peer_keeps_quick_reprobe() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).expect("node");
    node.peers
        .insert(peer_addr, ActivePeer::new(peer, LinkId::new(7), 0));

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    bootstrap.push_event_for_test(BootstrapEvent::Failed {
        peer_config: peer_config.clone(),
        reason: "signal timeout waiting for answer".to_string(),
    });
    node.nostr_discovery = Some(bootstrap);

    let before_ms = Node::now_ms();
    node.poll_nostr_discovery().await;
    let after_ms = Node::now_ms();

    let state = node
        .retry_pending
        .get(&peer_addr)
        .expect("failed direct upgrade should keep active-peer retry");
    assert_eq!(
        state.retry_count, 0,
        "active direct refresh failure must not accumulate peer backoff"
    );
    assert!(
        state.retry_after_ms >= before_ms + 2_000 && state.retry_after_ms <= after_ms + 8_000,
        "failed direct upgrade should schedule quick jittered reprobe, got {}",
        state.retry_after_ms
    );
    assert_eq!(state.peer_config.npub, peer_config.npub);
    assert!(
        node.nostr_discovery
            .as_ref()
            .and_then(|bootstrap| bootstrap.cooldown_until(&peer_config.npub, after_ms))
            .is_none(),
        "active direct refresh failures should not install peer-wide traversal cooldown"
    );
}

#[test]
fn local_send_failure_fast_dead_signal_expires_quickly() {
    let mut node = make_node();
    let peer_addr = make_node_addr(0xA1);
    let now = std::time::Instant::now();
    let dead_timeout = std::time::Duration::from_secs(30);
    let fast_dead_timeout = std::time::Duration::from_secs(5);

    node.local_send_failures.record_failure(peer_addr, now);

    assert_eq!(
        node.local_send_failure_dead_timeout_for_peer(
            &peer_addr,
            now,
            dead_timeout,
            fast_dead_timeout
        ),
        fast_dead_timeout
    );
    assert!(node.local_send_failures.contains_key(&peer_addr));

    let later = now + std::time::Duration::from_secs(4);
    node.purge_expired_local_send_failures(later);
    assert_eq!(
        node.local_send_failure_dead_timeout_for_peer(
            &peer_addr,
            later,
            dead_timeout,
            fast_dead_timeout,
        ),
        dead_timeout
    );
    assert!(
        !node.local_send_failures.contains_key(&peer_addr),
        "stale route failures must not keep compressing link-dead timeout"
    );
}
