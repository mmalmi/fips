#[tokio::test]
async fn poll_nostr_discovery_established_active_peer_bypasses_peer_capacity() {
    use crate::discovery::EstablishedTraversal;
    use std::net::UdpSocket;

    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: false,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).expect("node");
    node.set_max_peers(1);
    node.peers
        .insert(peer_addr, ActivePeer::new(peer, LinkId::new(7), 0));

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind local UDP socket");
    let remote_addr = "127.0.0.1:9999".parse().expect("parse remote addr");
    bootstrap.push_event_for_test(BootstrapEvent::Established {
        traversal: EstablishedTraversal::new(
            "active-refresh-session",
            peer_identity.npub(),
            remote_addr,
            socket,
        ),
    });
    node.nostr_discovery = Some(bootstrap);

    node.poll_nostr_discovery().await;

    assert!(
        node.retry_pending.contains_key(&peer_addr),
        "active-peer traversal should reach adoption even when peer slots are full"
    );
}

#[tokio::test]
async fn poll_nostr_discovery_established_fresh_active_peer_skips_redundant_traversal() {
    use crate::discovery::EstablishedTraversal;
    use std::net::UdpSocket;

    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority(
            "udp",
            "203.0.113.9:2121",
            1,
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: false,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config);
    let mut node = Node::new(config).expect("node");
    node.set_max_peers(1);
    node.peers.insert(
        peer_addr,
        ActivePeer::new(peer, LinkId::new(7), Node::now_ms()),
    );

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind local UDP socket");
    let remote_addr = "127.0.0.1:9999".parse().expect("parse remote addr");
    bootstrap.push_event_for_test(BootstrapEvent::Established {
        traversal: EstablishedTraversal::new(
            "fresh-active-refresh-session",
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
    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "fresh active peers should ignore redundant traversal handoffs"
    );
}

#[tokio::test]
async fn poll_nostr_discovery_established_fresh_bootstrap_data_skips_redundant_traversal() {
    use crate::discovery::EstablishedTraversal;
    use std::net::UdpSocket;

    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let app_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority(
            "udp",
            "203.0.113.9:2121",
            1,
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: false,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();
    let app_peer = PeerIdentity::from_pubkey_full(app_identity.pubkey_full());
    let app_addr = *app_peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.peers.push(peer_config);
    let link_session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let endpoint_session = make_test_fmp_session(&local_identity, &app_identity, [3; 8], [4; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");
    node.set_max_peers(1);

    let bootstrap_transport = TransportId::new(77);
    let active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        Node::now_ms(),
        ActivePeerSession {
            session: link_session,
            our_index: crate::utils::index::SessionIndex::new(11),
            their_index: crate::utils::index::SessionIndex::new(12),
            transport_id: bootstrap_transport,
            current_addr: crate::transport::TransportAddr::from_string("198.51.100.9:44444"),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: None,
        },
    );
    node.peers.insert(peer_addr, active);
    node.bootstrap_transports.mark(bootstrap_transport);

    let now_ms = Node::now_ms();
    let session = crate::node::session::SessionEntry::new(
        app_addr,
        app_identity.pubkey_full(),
        crate::node::session::EndToEndState::Established(endpoint_session),
        1_000,
        true,
    );
    node.sessions.insert(app_addr, session);
    seed_dataplane_fsp_data_sent_for_test(&mut node, app_addr, peer_addr, now_ms);
    seed_dataplane_fsp_data_rx_for_test(&mut node, app_addr, peer_addr, now_ms);

    let bootstrap = std::sync::Arc::new(NostrDiscovery::new_for_test());
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind local UDP socket");
    let remote_addr = "127.0.0.1:9999".parse().expect("parse remote addr");
    bootstrap.push_event_for_test(BootstrapEvent::Established {
        traversal: EstablishedTraversal::new(
            "fresh-bootstrap-refresh-session",
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
    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "fresh endpoint data on a bootstrap path should ignore redundant traversal handoffs"
    );
}

#[test]
fn mesh_signaling_allows_configured_roster_peer_without_established_session() {
    use crate::node::session::{EndToEndState, SessionEntry};
    use crate::noise::HandshakeState;

    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: false,
    };
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).expect("node");

    assert!(
        node.mesh_signaling_allowed_for_peer(&peer_config),
        "configured roster peers should be allowed to use mesh signaling before the end-to-end session is warm"
    );

    let mut initiator =
        HandshakeState::new_initiator(node.identity.keypair(), peer_identity.pubkey_full());
    let mut responder = HandshakeState::new_responder(peer_identity.keypair());
    initiator.set_local_epoch([0x01; 8]);
    responder.set_local_epoch([0x02; 8]);
    let msg1 = initiator.write_message_1().expect("msg1");
    responder.read_message_1(&msg1).expect("read msg1");
    let msg2 = responder.write_message_2().expect("msg2");
    initiator.read_message_2(&msg2).expect("read msg2");
    let session = initiator.into_session().expect("session");

    let peer_addr = *PeerIdentity::from_npub(&peer_config.npub)
        .expect("peer identity")
        .node_addr();
    node.sessions.insert(
        peer_addr,
        SessionEntry::new(
            peer_addr,
            peer_identity.pubkey_full(),
            EndToEndState::Established(session),
            1_000,
            true,
        ),
    );

    assert!(node.mesh_signaling_allowed_for_peer(&peer_config));
    assert!(
        !node
            .configured_discovery_fallback_transit(&peer_addr)
            .expect("peer should still be configured"),
        "mesh signaling should not require ambient transit permission"
    );

    let unconfigured = Identity::generate();
    let unconfigured_peer = crate::config::PeerConfig::new(unconfigured.npub(), "udp", "nat");
    assert!(!node.mesh_signaling_allowed_for_peer(&unconfigured_peer));
}

async fn craft_and_send_msg1(
    node_b: &Node,
    sender_identity: &Identity,
    socket_a: &tokio::net::UdpSocket,
    addr_b: std::net::SocketAddr,
    timestamp_ms: u64,
) -> NodeAddr {
    use crate::node::wire::build_msg1;
    use crate::utils::index::SessionIndex;

    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity.pubkey_full());
    let sender_pubkey_id = PeerIdentity::from_pubkey_full(sender_identity.pubkey_full());
    let sender_node_addr = *sender_pubkey_id.node_addr();

    let link_id = LinkId::new(0xDEAD_BEEF);
    let mut conn = PeerConnection::outbound(link_id, peer_b_identity, timestamp_ms);

    let sender_keypair = sender_identity.keypair();
    let mut startup_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut startup_epoch);
    let noise_msg1 = conn
        .start_handshake(sender_keypair, startup_epoch, timestamp_ms)
        .expect("start_handshake should produce noise msg1");

    let sender_index = SessionIndex::new(0x5151);
    let wire_msg1 = build_msg1(sender_index, &noise_msg1);

    socket_a
        .send_to(&wire_msg1, addr_b)
        .await
        .expect("sender_socket.send_to");
    sender_node_addr
}

async fn pump_one_msg1_into_node(
    node: &mut Node,
    packet_rx: &mut crate::transport::PacketRx,
    timeout_ms: u64,
) -> Result<(), &'static str> {
    use tokio::time::{Duration, timeout};
    let packet = timeout(Duration::from_millis(timeout_ms), packet_rx.recv())
        .await
        .map_err(|_| "timed out waiting for msg1 on packet_rx")?
        .ok_or("packet channel closed")?;
    node.handle_msg1(packet).await;
    Ok(())
}

#[tokio::test]
async fn handle_msg1_silent_drops_at_cap_for_new_peer() {
    use crate::config::UdpConfig;
    use tokio::time::{Duration, timeout};

    let mut node = make_node();
    node.set_max_peers(2);
    inject_dummy_peers(&mut node, 2);
    assert_eq!(node.peer_count(), 2);

    let transport_id_b = TransportId::new(1);
    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };
    let (packet_tx_b, mut packet_rx_b) = packet_channel(64);
    let mut transport_b = UdpTransport::new(transport_id_b, None, udp_config, packet_tx_b);
    transport_b.start_async().await.unwrap();
    let addr_b = transport_b.local_addr().unwrap();
    node.transports
        .insert(transport_id_b, TransportHandle::Udp(transport_b));

    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind sender socket");

    let before_peers = node.peer_count();
    let before_pending = node.msg1_rate_limiter.pending_count();
    let sender = Identity::generate();
    let sender_node_addr = craft_and_send_msg1(&node, &sender, &socket_a, addr_b, 1000).await;

    assert!(!node.peers.contains_key(&sender_node_addr));

    pump_one_msg1_into_node(&mut node, &mut packet_rx_b, 1000)
        .await
        .expect("msg1 must reach packet_rx_b");

    assert_eq!(node.peer_count(), before_peers);
    assert!(!node.peers.contains_key(&sender_node_addr));
    assert_eq!(node.msg1_rate_limiter.pending_count(), before_pending);

    let mut buf = [0u8; 2048];
    let recv = timeout(Duration::from_millis(300), socket_a.recv_from(&mut buf)).await;
    let received_bytes = recv.ok().and_then(|inner| inner.ok()).map(|(n, _)| n);
    assert!(
        received_bytes.is_none(),
        "Msg2 must not be sent at max_peers cap; observed {received_bytes:?} bytes"
    );
}

#[tokio::test]
async fn handle_msg1_admits_existing_peer_at_cap() {
    use crate::config::UdpConfig;

    let mut node = make_node();
    node.set_max_peers(2);
    inject_dummy_peers(&mut node, 1);

    let existing_sender = Identity::generate();
    let existing_pid = PeerIdentity::from_pubkey_full(existing_sender.pubkey_full());
    let existing_node_addr = *existing_pid.node_addr();
    let existing_link_id = LinkId::new(7777);
    let peer = ActivePeer::new(existing_pid, existing_link_id, 0);
    node.peers.insert(existing_node_addr, peer);
    assert_eq!(node.peer_count(), 2);

    let transport_id_b = TransportId::new(1);
    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };
    let (packet_tx_b, mut packet_rx_b) = packet_channel(64);
    let mut transport_b = UdpTransport::new(transport_id_b, None, udp_config, packet_tx_b);
    transport_b.start_async().await.unwrap();
    let addr_b = transport_b.local_addr().unwrap();
    node.transports
        .insert(transport_id_b, TransportHandle::Udp(transport_b));

    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind sender socket");

    let before_pending = node.msg1_rate_limiter.pending_count();
    let sender_node_addr =
        craft_and_send_msg1(&node, &existing_sender, &socket_a, addr_b, 2000).await;
    assert_eq!(sender_node_addr, existing_node_addr);

    pump_one_msg1_into_node(&mut node, &mut packet_rx_b, 1000)
        .await
        .expect("msg1 must reach packet_rx_b");

    assert_eq!(node.peer_count(), 2);
    assert!(node.peers.contains_key(&existing_node_addr));
    assert_eq!(node.msg1_rate_limiter.pending_count(), before_pending);
}

#[tokio::test]
async fn handle_msg1_treats_same_epoch_stale_peer_as_recovery() {
    let mut node = make_node();
    let peer_identity_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_identity_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let old_link_id = LinkId::new(7);
    let transport_id = TransportId::new(1);
    let old_addr = crate::transport::TransportAddr::from_string("127.0.0.1:5000");
    let new_addr = crate::transport::TransportAddr::from_string("127.0.0.1:5001");
    let remote_epoch = [0x51; 8];
    let session = make_test_fmp_session(
        &node.identity,
        &peer_identity_full,
        node.startup_epoch,
        remote_epoch,
    );
    let mut active = ActivePeer::with_session(
        peer_identity,
        old_link_id,
        1_000,
        ActivePeerSession {
            session,
            our_index: crate::utils::index::SessionIndex::new(11),
            their_index: crate::utils::index::SessionIndex::new(12),
            transport_id,
            current_addr: old_addr.clone(),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: true,
            remote_epoch: Some(remote_epoch),
        },
    );
    active.set_handshake_msg2(vec![0x02, 0x03, 0x04]);
    active.mark_stale();
    node.peers.insert(peer_node_addr, active);
    node.peers
        .insert_session_index((transport_id, 11), peer_node_addr);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            old_addr,
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );

    let mut conn = PeerConnection::outbound(
        LinkId::new(99),
        PeerIdentity::from_pubkey_full(node.identity.pubkey_full()),
        2_000,
    );
    let noise_msg1 = conn
        .start_handshake(peer_identity_full.keypair(), remote_epoch, 2_000)
        .expect("msg1");
    let wire_msg1 =
        crate::node::wire::build_msg1(crate::utils::index::SessionIndex::new(0x5151), &noise_msg1);
    let packet = ReceivedPacket::with_timestamp(
        transport_id,
        new_addr.clone(),
        crate::transport::PacketBuffer::new(wire_msg1),
        2_000,
    );

    node.handle_msg1(packet).await;

    let active = node.get_peer(&peer_node_addr).expect("peer");
    assert!(active.is_healthy());
    assert_eq!(
        active.current_addr(),
        Some(&new_addr),
        "stale same-epoch msg1 should install the freshly authenticated recovery path"
    );
    assert_ne!(
        active.link_id(),
        old_link_id,
        "stale duplicate handling must not keep the dead link"
    );
}

#[tokio::test]
async fn handle_msg1_uses_fresh_msg2_for_same_epoch_alternate_path() {
    use crate::config::NostrRelayConfig;
    use crate::peer::cross_connection_winner;
    use crate::transport::nostr_relay::NostrRelayTransport;
    use crate::Transport;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let mut node = make_node();
    let peer_identity_full = loop {
        let candidate = Identity::generate();
        if cross_connection_winner(node.node_addr(), candidate.node_addr(), false) {
            break candidate;
        }
    };
    let peer_identity = PeerIdentity::from_pubkey_full(peer_identity_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let old_link_id = LinkId::new(7);
    let transport_id = TransportId::new(1);
    let old_addr = crate::transport::TransportAddr::from_string(&peer_identity.npub());
    let remote_epoch = [0x51; 8];
    let session = make_test_fmp_session(
        &node.identity,
        &peer_identity_full,
        node.startup_epoch,
        remote_epoch,
    );
    let mut active = ActivePeer::with_session(
        peer_identity,
        old_link_id,
        1_000,
        ActivePeerSession {
            session,
            our_index: crate::utils::index::SessionIndex::new(11),
            their_index: crate::utils::index::SessionIndex::new(12),
            transport_id,
            current_addr: old_addr.clone(),
            link_stats: crate::transport::LinkStats::new(),
            is_initiator: false,
            remote_epoch: Some(remote_epoch),
        },
    );
    active.set_handshake_msg2(vec![0x02, 0x03, 0x04]);
    node.peers.insert(peer_node_addr, active);
    node.peers
        .insert_session_index((transport_id, 11), peer_node_addr);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            old_addr.clone(),
            LinkDirection::Inbound,
            Duration::from_millis(100),
        ),
    );

    let (packet_tx, _packet_rx) = packet_channel(8);
    let mut relay = NostrRelayTransport::new(
        transport_id,
        None,
        NostrRelayConfig::default(),
        packet_tx,
        &node.identity,
    )
    .expect("Nostr relay transport");
    relay.start().expect("start Nostr relay transport");
    node.transports
        .insert(transport_id, TransportHandle::NostrRelay(Box::new(relay)));

    let mut conn = PeerConnection::outbound(
        LinkId::new(99),
        PeerIdentity::from_pubkey_full(node.identity.pubkey_full()),
        2_000,
    );
    let noise_msg1 = conn
        .start_handshake(peer_identity_full.keypair(), remote_epoch, 2_000)
        .expect("msg1");
    let fresh_sender_index = crate::utils::index::SessionIndex::new(0x5151);
    let packet = ReceivedPacket::with_timestamp(
        transport_id,
        old_addr,
        crate::transport::PacketBuffer::new(crate::node::wire::build_msg1(
            fresh_sender_index,
            &noise_msg1,
        )),
        2_000,
    );

    node.handle_msg1(packet).await;

    let TransportHandle::NostrRelay(relay) = node
        .transports
        .get(&transport_id)
        .expect("relay transport")
    else {
        panic!("expected Nostr relay transport");
    };
    let event = relay
        .drain_outbound_events(1)
        .pop()
        .expect("fresh msg2 response");
    let response = URL_SAFE_NO_PAD.decode(event.content).expect("msg2 base64");
    let header = crate::node::wire::Msg2Header::parse(&response).expect("msg2 header");
    assert_eq!(header.receiver_idx, fresh_sender_index);
}
