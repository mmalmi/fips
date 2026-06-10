use super::*;
use crate::discovery::nostr::{BootstrapEvent, NostrDiscovery};
use crate::node::wire::{
    EncryptedHeader, FLAG_CE, FLAG_KEY_EPOCH, FLAG_SP, Msg1Header, build_encrypted,
    build_established_header, build_msg2,
};
use crate::peer::{ActivePeer, PromotionResult};
use crate::transport::ReceivedPacket;
use crate::transport::udp::UdpTransport;
use crate::transport::{TransportHandle, packet_channel};
use std::sync::Arc;

fn make_test_fmp_session(
    local: &Identity,
    peer: &Identity,
    local_epoch: [u8; 8],
    peer_epoch: [u8; 8],
) -> crate::noise::NoiseSession {
    make_test_fmp_session_pair(local, peer, local_epoch, peer_epoch).0
}

fn make_test_fmp_session_pair(
    local: &Identity,
    peer: &Identity,
    local_epoch: [u8; 8],
    peer_epoch: [u8; 8],
) -> (crate::noise::NoiseSession, crate::noise::NoiseSession) {
    let mut initiator =
        crate::noise::HandshakeState::new_initiator(local.keypair(), peer.pubkey_full());
    let mut responder = crate::noise::HandshakeState::new_responder(peer.keypair());
    initiator.set_local_epoch(local_epoch);
    responder.set_local_epoch(peer_epoch);
    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();
    (
        initiator.into_session().unwrap(),
        responder.into_session().unwrap(),
    )
}

fn seal_test_fmp_packet(
    sender: &mut crate::noise::NoiseSession,
    receiver_idx: SessionIndex,
    plaintext: &[u8],
    k_bit: bool,
) -> Vec<u8> {
    let flags = if k_bit { FLAG_KEY_EPOCH } else { 0 };
    let counter = sender.current_send_counter();
    let header = build_established_header(receiver_idx, counter, flags, plaintext.len() as u16);
    let ciphertext = sender.encrypt_with_aad(plaintext, &header).unwrap();
    build_encrypted(&header, &ciphertext)
}

fn make_active_test_peer(
    node: &Node,
    peer_full: &Identity,
    peer_identity: PeerIdentity,
    transport_id: TransportId,
    link_id: LinkId,
    remote_addr: TransportAddr,
    our_index: SessionIndex,
    their_index: SessionIndex,
) -> ActivePeer {
    let session = make_test_fmp_session(&node.identity, peer_full, [0x01; 8], [0x02; 8]);
    ActivePeer::with_session(
        peer_identity,
        link_id,
        1_000,
        session,
        our_index,
        their_index,
        transport_id,
        remote_addr,
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([0x02; 8]),
    )
}

fn arm_test_fmp_rekey(peer: &mut ActivePeer, rekey_our_index: SessionIndex) {
    let remote = Identity::generate();
    let local = Identity::generate();
    let handshake =
        crate::noise::HandshakeState::new_initiator(local.keypair(), remote.pubkey_full());
    peer.set_rekey_state(handshake, rekey_our_index, vec![0xAB; 64], 0);
}

#[test]
fn endpoint_event_batch_scope_emits_one_batch_and_keeps_immediate_delivery_outside_scope() {
    let mut node = Node::new(Config::new()).expect("node");
    let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    node.deliver_endpoint_event_message(NodeEndpointMessage::new(source, b"single".to_vec()))
        .expect("single endpoint event");
    match endpoint_io.event_rx.try_recv().expect("single event") {
        NodeEndpointEvent::Data {
            source_peer,
            payload,
            ..
        } => {
            assert_eq!(source_peer, source);
            assert_eq!(payload, b"single");
        }
        event => panic!("expected single endpoint event, got {event:?}"),
    }

    node.begin_endpoint_event_batch();
    node.deliver_endpoint_event_message(NodeEndpointMessage::new(source, b"first".to_vec()))
        .expect("first batched endpoint event");
    node.deliver_endpoint_event_message(NodeEndpointMessage::new(source, b"second".to_vec()))
        .expect("second batched endpoint event");
    assert!(
        endpoint_io.event_rx.try_recv().is_err(),
        "batch scope should not flush before finish"
    );

    node.finish_endpoint_event_batch();
    match endpoint_io.event_rx.try_recv().expect("batched event") {
        NodeEndpointEvent::DataBatch { messages, .. } => {
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0].source_peer, source);
            assert_eq!(messages[0].payload, b"first");
            assert_eq!(messages[1].source_peer, source);
            assert_eq!(messages[1].payload, b"second");
        }
        event => panic!("expected endpoint event batch, got {event:?}"),
    }
}

#[test]
fn endpoint_event_runtime_owns_attach_batch_and_backlog() {
    let (event_tx, mut event_rx) = EndpointEventSender::channel();
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    let mut runtime = EndpointEventRuntime::default();

    assert!(!runtime.is_attached());
    runtime
        .deliver_message(NodeEndpointMessage::new(source, b"detached".to_vec()))
        .expect("detached endpoint runtime delivery should be a no-op");
    assert!(
        event_rx.try_recv().is_err(),
        "detached runtime must not enqueue endpoint events"
    );
    assert_eq!(event_tx.queued_messages(), 0);

    runtime.attach(event_tx.clone());
    runtime.begin_batch();
    runtime
        .deliver_message(NodeEndpointMessage::new(source, b"first".to_vec()))
        .expect("first batched endpoint event");
    runtime
        .deliver_message(NodeEndpointMessage::new(source, b"second".to_vec()))
        .expect("second batched endpoint event");
    assert!(
        event_rx.try_recv().is_err(),
        "runtime batch scope should not flush before finish"
    );

    runtime.finish_batch();
    assert_eq!(event_tx.queued_messages(), 2);
    match event_rx.try_recv().expect("batched event") {
        NodeEndpointEvent::DataBatch { messages, .. } => {
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0].source_peer, source);
            assert_eq!(messages[0].payload, b"first");
            assert_eq!(messages[1].source_peer, source);
            assert_eq!(messages[1].payload, b"second");
        }
        event => panic!("expected endpoint event batch, got {event:?}"),
    }
    assert_eq!(event_tx.queued_messages(), 0);
}

#[test]
fn endpoint_event_queue_owns_backlog_message_count() {
    let mut node = Node::new(Config::new()).expect("node");
    let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
    let source = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());

    assert_eq!(endpoint_io.event_tx.queued_messages(), 0);
    node.deliver_endpoint_event_message(NodeEndpointMessage::new(source, b"single".to_vec()))
        .expect("single endpoint event");
    assert_eq!(endpoint_io.event_tx.queued_messages(), 1);

    node.begin_endpoint_event_batch();
    node.deliver_endpoint_event_message(NodeEndpointMessage::new(source, b"first".to_vec()))
        .expect("first batched endpoint event");
    node.deliver_endpoint_event_message(NodeEndpointMessage::new(source, b"second".to_vec()))
        .expect("second batched endpoint event");
    node.finish_endpoint_event_batch();
    assert_eq!(
        endpoint_io.event_tx.queued_messages(),
        3,
        "backlog count should account for batch payloads, not channel items"
    );

    endpoint_io.event_rx.try_recv().expect("single event");
    assert_eq!(endpoint_io.event_tx.queued_messages(), 2);
    endpoint_io.event_rx.try_recv().expect("batched event");
    assert_eq!(endpoint_io.event_tx.queued_messages(), 0);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn make_test_connected_udp_pair(
    transport_id: TransportId,
) -> (
    Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>,
    crate::transport::udp::peer_drain::PeerRecvDrain,
) {
    let peer_udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind peer udp");
    let peer_socket_addr = peer_udp.local_addr().expect("peer udp local addr");
    let socket = Arc::new(
        crate::transport::udp::connected_peer::ConnectedPeerSocket::open(
            "127.0.0.1:0".parse().unwrap(),
            peer_socket_addr,
            1 << 20,
            1 << 20,
        )
        .expect("connected peer socket"),
    );
    let (packet_tx, _packet_rx) = packet_channel(16);
    let drain = crate::transport::udp::peer_drain::PeerRecvDrain::spawn(
        socket.clone(),
        transport_id,
        peer_socket_addr,
        packet_tx,
    )
    .expect("connected peer drain");
    (socket, drain)
}

#[cfg(unix)]
#[test]
fn fmp_worker_send_reservation_owns_counter_header_and_cipher() {
    let local = Identity::generate();
    let peer = Identity::generate();
    let (mut sender, mut receiver) =
        make_test_fmp_session_pair(&local, &peer, [0x01; 8], [0x02; 8]);
    let their_index = SessionIndex::new(0xA0B0_C0D0);
    let flags = FLAG_SP | FLAG_CE;
    let payload_len = 32;

    let reservation = reserve_fmp_worker_send(&mut sender, their_index, flags, payload_len)
        .expect("counter reservation should succeed")
        .expect("established session should expose a send cipher");

    assert_eq!(reservation.counter, 0);
    assert_eq!(
        sender.current_send_counter(),
        1,
        "reservation is the only session mutation before worker dispatch"
    );
    assert_eq!(
        reservation.header,
        build_established_header(their_index, reservation.counter, flags, payload_len)
    );

    let plaintext = vec![0x5A; payload_len as usize];
    let mut ciphertext = plaintext.clone();
    reservation
        .cipher
        .seal_in_place_append_tag(
            crate::noise::CipherState::counter_to_nonce(reservation.counter),
            ring::aead::Aad::from(&reservation.header),
            &mut ciphertext,
        )
        .expect("worker-style FMP seal should succeed");
    assert_eq!(
        sender.current_send_counter(),
        1,
        "worker cipher use must not mutate the owning session"
    );
    assert_eq!(
        receiver
            .decrypt_with_replay_check_and_aad(
                &ciphertext,
                reservation.counter,
                &reservation.header,
            )
            .expect("receiver should accept worker-sealed packet"),
        plaintext
    );
}

#[cfg(unix)]
#[tokio::test]
async fn fmp_worker_target_fallback_consumes_one_inline_counter() {
    let mut node = make_node();
    node.encrypt_workers = Some(crate::node::encrypt_worker::EncryptWorkerPool::spawn(1));

    let transport_id = TransportId::new(77);
    let link_id = LinkId::new(88);
    let (packet_tx, _packet_rx) = packet_channel(8);
    let udp = UdpTransport::new(
        transport_id,
        None,
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let remote_addr = TransportAddr::from_string("127.0.0.1:9");
    let peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        link_id,
        remote_addr,
        SessionIndex::new(11),
        SessionIndex::new(12),
    );
    node.peers.insert(peer_addr, peer);

    node.send_encrypted_link_message_with_ce(&peer_addr, b"fallback-inline", false)
        .await
        .expect_err("unstarted UDP transport should fail after inline encryption");

    let session = node
        .peers
        .get(&peer_addr)
        .and_then(|peer| peer.noise_session())
        .expect("peer should keep its session");
    assert_eq!(
        session.current_send_counter(),
        1,
        "worker-target fallback must not consume a worker counter before inline encryption"
    );
}

#[test]
fn test_node_creation() {
    let node = make_node();

    assert_eq!(node.state(), NodeState::Created);
    assert_eq!(node.peer_count(), 0);
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.link_count(), 0);
    assert!(!node.is_leaf_only());
}

#[test]
fn test_node_with_identity() {
    let identity = Identity::generate();
    let expected_node_addr = *identity.node_addr();
    let config = Config::new();

    let node = Node::with_identity(identity, config).unwrap();

    assert_eq!(node.node_addr(), &expected_node_addr);
}

#[test]
fn test_node_with_identity_validates_config() {
    let identity = Identity::generate();
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = false;
    config.peers = vec![crate::config::PeerConfig {
        npub: "npub1peer".to_string(),
        ..Default::default()
    }];

    let err = Node::with_identity(identity, config).expect_err("expected config validation error");
    assert!(matches!(err, NodeError::Config(_)));
}

#[test]
fn test_node_leaf_only() {
    let config = Config::new();
    let node = Node::leaf_only(config).unwrap();

    assert!(node.is_leaf_only());
    assert!(node.bloom_state().is_leaf_only());
}

#[tokio::test]
async fn test_nat_bootstrap_failure_falls_back_to_direct_udp_address() {
    let peer_identity = Identity::generate();
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "nat", 1),
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:9", 2),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer_identity = PeerIdentity::from_npub(&peer_config.npub).unwrap();

    node.try_peer_addresses(&peer_config, peer_identity, false)
        .await
        .unwrap();

    assert_eq!(node.connection_count(), 1);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_try_peer_addresses_races_all_concrete_udp_candidates() {
    let peer_identity = Identity::generate();
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:9", 1),
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:10", 2),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer_identity = PeerIdentity::from_npub(&peer_config.npub).unwrap();

    node.try_peer_addresses(&peer_config, peer_identity, false)
        .await
        .unwrap();

    let mut addrs = node
        .peers
        .connection_values()
        .filter_map(|conn| conn.source_addr().and_then(|addr| addr.as_str()))
        .collect::<Vec<_>>();
    addrs.sort();
    assert_eq!(addrs, vec!["127.0.0.1:10", "127.0.0.1:9"]);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_try_peer_addresses_skips_incompatible_udp_address_family() {
    let peer_identity = Identity::generate();
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "[fd00::1]:9", 1),
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:9", 2),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer_identity = PeerIdentity::from_npub(&peer_config.npub).unwrap();

    node.try_peer_addresses(&peer_config, peer_identity, false)
        .await
        .unwrap();

    assert_eq!(node.connection_count(), 1);
    assert_eq!(
        node.peers
            .connection_values()
            .next()
            .and_then(|conn| conn.source_addr())
            .and_then(|addr| addr.as_str()),
        Some("127.0.0.1:9")
    );
    assert!(
        node.find_link_by_addr(
            transport_id,
            &crate::transport::TransportAddr::from_string("[fd00::1]:9"),
        )
        .is_none(),
        "IPv6 candidate must not allocate a failed link on an IPv4-only socket"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_transport_discovery_skips_incompatible_udp_address_family() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let candidate = node.transport_discovery_candidate(
        transport_id,
        crate::transport::TransportAddr::from_string("[fd00::1]:9"),
    );

    assert!(
        candidate.is_none(),
        "transport discovery must not feed IPv6 candidates to an IPv4 UDP socket"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_transport_discovery_avoids_bootstrap_udp_transport() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let bootstrap_id = TransportId::new(1);
    let primary_id = TransportId::new(2);
    for (transport_id, name) in [(bootstrap_id, "bootstrap"), (primary_id, "main")] {
        let mut udp = UdpTransport::new(
            transport_id,
            Some(name.to_string()),
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx.clone(),
        );
        udp.start_async().await.unwrap();
        node.transports
            .insert(transport_id, TransportHandle::Udp(udp));
    }
    node.bootstrap_transports.mark(bootstrap_id);

    let candidate = node
        .transport_discovery_candidate(
            bootstrap_id,
            crate::transport::TransportAddr::from_string("127.0.0.1:9"),
        )
        .expect("primary UDP transport should be eligible");

    assert_eq!(candidate.0, primary_id);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_udp_transport_picker_ignores_bootstrap_transports() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let bootstrap_id = TransportId::new(1);
    let primary_id = TransportId::new(2);
    let other_primary_id = TransportId::new(3);

    for (transport_id, name) in [
        (bootstrap_id, "bootstrap"),
        (other_primary_id, "other-primary"),
        (primary_id, "primary"),
    ] {
        let mut udp = UdpTransport::new(
            transport_id,
            Some(name.to_string()),
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx.clone(),
        );
        udp.start_async().await.unwrap();
        node.transports
            .insert(transport_id, TransportHandle::Udp(udp));
    }

    node.bootstrap_transports.mark(bootstrap_id);

    assert_eq!(node.find_transport_for_type("udp"), Some(primary_id));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_node_state_transitions() {
    let mut node = make_node();

    assert!(!node.is_running());
    assert!(node.state().can_start());

    node.start().await.unwrap();
    assert!(node.is_running());
    assert!(!node.state().can_start());

    node.stop().await.unwrap();
    assert!(!node.is_running());
    assert_eq!(node.state(), NodeState::Stopped);
}

#[tokio::test]
async fn test_node_start_does_not_wait_for_nostr_relay_startup() {
    let mut config = Config::new();
    config.node.control.enabled = false;
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.advertise = true;
    config.node.discovery.nostr.policy = crate::config::NostrDiscoveryPolicy::Open;
    config.node.discovery.nostr.advert_relays = vec!["wss://127.0.0.1:9".to_string()];
    config.node.discovery.nostr.dm_relays = vec!["wss://127.0.0.1:9".to_string()];
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        advertise_on_nostr: Some(true),
        public: Some(false),
        accept_connections: Some(true),
        ..Default::default()
    });

    let mut node = Node::new(config).unwrap();
    tokio::time::timeout(std::time::Duration::from_millis(500), node.start())
        .await
        .expect("node start should not wait for relay I/O")
        .unwrap();

    assert!(node.is_running());
    assert!(node.nostr_discovery_handle().is_some());

    node.stop().await.unwrap();
}

#[tokio::test]
async fn test_node_double_start() {
    let mut node = make_node();
    node.start().await.unwrap();

    let result = node.start().await;
    assert!(matches!(result, Err(NodeError::AlreadyStarted)));

    // Clean up
    node.stop().await.unwrap();
}

#[tokio::test]
async fn test_node_stop_not_started() {
    let mut node = make_node();

    let result = node.stop().await;
    assert!(matches!(result, Err(NodeError::NotStarted)));
}

#[test]
fn test_node_link_management() {
    let mut node = make_node();

    let link_id = node.allocate_link_id();
    let link = Link::connectionless(
        link_id,
        TransportId::new(1),
        TransportAddr::from_string("test"),
        LinkDirection::Outbound,
        Duration::from_millis(50),
    );

    node.add_link(link).unwrap();
    assert_eq!(node.link_count(), 1);

    assert!(node.get_link(&link_id).is_some());

    // Test reverse address dispatch lookup.
    assert_eq!(
        node.find_link_by_addr(TransportId::new(1), &TransportAddr::from_string("test")),
        Some(link_id)
    );

    node.remove_link(&link_id);
    assert_eq!(node.link_count(), 0);

    // Lookup should be gone
    assert!(
        node.find_link_by_addr(TransportId::new(1), &TransportAddr::from_string("test"))
            .is_none()
    );
}

#[test]
fn test_node_link_limit() {
    let mut node = make_node();
    node.set_max_links(2);

    for i in 0..2 {
        let link_id = node.allocate_link_id();
        let link = Link::connectionless(
            link_id,
            TransportId::new(1),
            TransportAddr::from_string(&format!("test{}", i)),
            LinkDirection::Outbound,
            Duration::from_millis(50),
        );
        node.add_link(link).unwrap();
    }

    let link_id = node.allocate_link_id();
    let link = Link::connectionless(
        link_id,
        TransportId::new(1),
        TransportAddr::from_string("test_extra"),
        LinkDirection::Outbound,
        Duration::from_millis(50),
    );

    let result = node.add_link(link);
    assert!(matches!(result, Err(NodeError::MaxLinksExceeded { .. })));
}

#[test]
fn test_node_connection_management() {
    let mut node = make_node();

    let identity = make_peer_identity();
    let link_id = LinkId::new(1);
    let conn = PeerConnection::outbound(link_id, identity, 1000);

    node.add_connection(conn).unwrap();
    assert_eq!(node.connection_count(), 1);

    assert!(node.get_connection(&link_id).is_some());

    node.remove_connection(&link_id);
    assert_eq!(node.connection_count(), 0);
}

#[test]
fn test_node_connection_duplicate() {
    let mut node = make_node();

    let identity = make_peer_identity();
    let link_id = LinkId::new(1);
    let conn1 = PeerConnection::outbound(link_id, identity, 1000);
    let conn2 = PeerConnection::outbound(link_id, identity, 2000);

    node.add_connection(conn1).unwrap();
    let result = node.add_connection(conn2);

    assert!(matches!(result, Err(NodeError::ConnectionAlreadyExists(_))));
}

#[test]
fn test_node_promote_connection() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    assert_eq!(node.connection_count(), 1);
    assert_eq!(node.peer_count(), 0);

    let result = node.promote_connection(link_id, identity, 2000).unwrap();

    assert!(matches!(result, PromotionResult::Promoted(_)));
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.peer_count(), 1);

    let peer = node.get_peer(&node_addr).unwrap();
    assert_eq!(peer.authenticated_at(), 2000);
    assert!(peer.has_session(), "Promoted peer should have NoiseSession");
    assert!(
        peer.our_index().is_some(),
        "Promoted peer should have our_index"
    );
    assert!(
        peer.their_index().is_some(),
        "Promoted peer should have their_index"
    );

    // Verify active peer registry session-index dispatch is populated
    let our_index = peer.our_index().unwrap();
    assert_eq!(
        node.peers
            .get_session_index(&(transport_id, our_index.as_u32())),
        Some(&node_addr)
    );
}

#[test]
fn test_promote_open_discovery_retry_blocks_fallback_transit() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();

    let retry = crate::node::retry::RetryState::new(crate::config::PeerConfig {
        npub: identity.npub(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: false,
    });
    node.retry_pending.insert(node_addr, retry);

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();

    assert!(
        node.discovery_fallback_transit.is_blocked(&node_addr),
        "open-discovery retry peers should not become ambient lookup transit"
    );
}

#[test]
fn test_promote_nonconfigured_open_discovery_peer_blocks_fallback_transit() {
    let mut node = make_node();
    node.config.node.discovery.nostr.policy = crate::config::NostrDiscoveryPolicy::Open;
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();

    assert!(
        node.discovery_fallback_transit.is_blocked(&node_addr),
        "nonconfigured peers accepted under open discovery should not be fallback transit"
    );
}

#[test]
fn discovery_fallback_transit_owns_target_exception_block_and_bootstrap_policy() {
    let peer = make_node_addr(0xD1);
    let target = make_node_addr(0xD2);
    let bootstrap_transport = TransportId::new(7);
    let normal_transport = TransportId::new(8);
    let mut transit = DiscoveryFallbackTransit::default();

    assert!(
        transit.allows_lookup_fallback_peer(&peer, &target, Some(normal_transport), |_| false),
        "ordinary sendable peers should be eligible fallback transit"
    );

    transit.set_allowed(peer, false);
    assert!(
        !transit.allows_lookup_fallback_peer(&peer, &target, Some(normal_transport), |_| false),
        "explicitly blocked peers must not become ambient lookup transit"
    );
    assert!(
        transit.allows_lookup_fallback_peer(&peer, &peer, Some(normal_transport), |_| false),
        "direct lookups to the target peer must remain allowed even when ambient transit is blocked"
    );

    transit.set_allowed(peer, true);
    assert!(
        !transit.allows_lookup_fallback_peer(&peer, &target, Some(bootstrap_transport), |id| {
            id == bootstrap_transport
        }),
        "bootstrap transports should not be used as ambient fallback transit"
    );
    assert!(
        transit.allows_lookup_fallback_peer(&peer, &target, Some(normal_transport), |id| {
            id == bootstrap_transport
        }),
        "unblocked non-bootstrap peers should be eligible again"
    );
    assert!(
        transit.allows_lookup_fallback_peer(&peer, &target, None, |_| false),
        "peers without a transport id should not be treated as bootstrap"
    );
}

#[test]
fn bootstrap_transports_own_membership_peer_npub_and_cleanup() {
    let transport = TransportId::new(7);
    let other_transport = TransportId::new(8);
    let mut bootstrap = BootstrapTransports::default();

    bootstrap.register(transport, "npub-one".to_string());
    assert!(bootstrap.contains(&transport));
    assert_eq!(bootstrap.peer_npub(&transport), Some("npub-one"));
    assert_eq!(bootstrap.peer_npub(&other_transport), None);

    bootstrap.register(transport, "npub-two".to_string());
    assert!(bootstrap.contains(&transport));
    assert_eq!(
        bootstrap.peer_npub(&transport),
        Some("npub-two"),
        "re-registering a transport must update the peer npub in the same owner"
    );

    bootstrap.remove(&transport);
    assert!(!bootstrap.contains(&transport));
    assert_eq!(
        bootstrap.peer_npub(&transport),
        None,
        "removing bootstrap membership must also drop the peer npub"
    );
}

/// After `promote_connection`'s initial-promote branch the peer's
/// (transport_id, our_index) pair must be in
/// the session registry's worker-registration mirror. Unit tests construct `Node`
/// directly so `decrypt_workers` defaults to `None`; spawn a
/// 1-thread pool here so the registration code path actually runs.
#[test]
fn test_promote_registers_decrypt_worker() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    node.decrypt_workers = Some(crate::node::decrypt_worker::DecryptWorkerPool::spawn(1));

    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();

    let peer = node.get_peer(&node_addr).unwrap();
    let our_index = peer.our_index().unwrap();
    assert!(
        node.sessions
            .is_worker_registered(&crate::node::decrypt_worker::DecryptSessionKey::new(
                transport_id,
                our_index.as_u32()
            )),
        "session registry must contain the new worker registration after promote"
    );
}

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

#[test]
fn test_node_cross_connection_resolution() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // First connection and promotion (becomes active peer)
    let link_id1 = LinkId::new(1);
    let (conn1, identity) = make_completed_connection(&mut node, link_id1, transport_id, 1000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn1).unwrap();
    node.promote_connection(link_id1, identity, 1500).unwrap();

    assert_eq!(node.peer_count(), 1);
    assert_eq!(node.get_peer(&node_addr).unwrap().link_id(), link_id1);

    // Cross-connection tie-breaker logic is tested in peer/mod.rs tests.
    // The integration test will cover the real cross-connection path with
    // two actual nodes. Here we verify promotion works correctly.

    // Verify first promotion populated active peer registry session-index dispatch
    let peer = node.get_peer(&node_addr).unwrap();
    let our_idx = peer.our_index().unwrap();
    assert_eq!(
        node.peers
            .get_session_index(&(transport_id, our_idx.as_u32())),
        Some(&node_addr)
    );

    // Still only one peer
    assert_eq!(node.peer_count(), 1);
}

#[test]
fn test_node_peer_limit() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    node.set_max_peers(2);

    // Add two peers via promotion
    for i in 0..2 {
        let link_id = LinkId::new(i as u64 + 1);
        let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
        node.add_connection(conn).unwrap();
        node.promote_connection(link_id, identity, 2000).unwrap();
    }

    assert_eq!(node.peer_count(), 2);

    // Third should fail
    let link_id = LinkId::new(3);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 3000);
    node.add_connection(conn).unwrap();

    let result = node.promote_connection(link_id, identity, 4000);
    assert!(matches!(result, Err(NodeError::MaxPeersExceeded { .. })));
}

#[test]
fn test_node_link_id_allocation() {
    let mut node = make_node();

    let id1 = node.allocate_link_id();
    let id2 = node.allocate_link_id();
    let id3 = node.allocate_link_id();

    assert_ne!(id1, id2);
    assert_ne!(id2, id3);
    assert_eq!(id1.as_u64(), 1);
    assert_eq!(id2.as_u64(), 2);
    assert_eq!(id3.as_u64(), 3);
}

#[test]
fn test_node_transport_management() {
    let mut node = make_node();

    // Initially no transports (transports are created during start())
    assert_eq!(node.transport_count(), 0);

    // Allocating IDs still works
    let id1 = node.allocate_transport_id();
    let id2 = node.allocate_transport_id();
    assert_ne!(id1, id2);

    // get_transport returns None when transport doesn't exist
    assert!(node.get_transport(&id1).is_none());
    assert!(node.get_transport(&id2).is_none());

    // transport_ids() iterator is empty
    assert_eq!(node.transport_ids().count(), 0);
}

#[test]
fn test_node_sendable_peers() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Add a healthy peer
    let link_id1 = LinkId::new(1);
    let (conn1, identity1) = make_completed_connection(&mut node, link_id1, transport_id, 1000);
    let node_addr1 = *identity1.node_addr();
    node.add_connection(conn1).unwrap();
    node.promote_connection(link_id1, identity1, 2000).unwrap();

    // Add another peer and mark it stale (still sendable)
    let link_id2 = LinkId::new(2);
    let (conn2, identity2) = make_completed_connection(&mut node, link_id2, transport_id, 1000);
    node.add_connection(conn2).unwrap();
    node.promote_connection(link_id2, identity2, 2000).unwrap();

    // Add a third peer and mark it disconnected (not sendable)
    let link_id3 = LinkId::new(3);
    let (conn3, identity3) = make_completed_connection(&mut node, link_id3, transport_id, 1000);
    let node_addr3 = *identity3.node_addr();
    node.add_connection(conn3).unwrap();
    node.promote_connection(link_id3, identity3, 2000).unwrap();
    node.get_peer_mut(&node_addr3).unwrap().mark_disconnected();

    assert_eq!(node.peer_count(), 3);
    assert_eq!(node.sendable_peer_count(), 2);

    let sendable: Vec<_> = node.sendable_peers().collect();
    assert_eq!(sendable.len(), 2);
    assert!(sendable.iter().any(|p| p.node_addr() == &node_addr1));
}

// === RX Loop Tests ===

#[test]
fn test_node_index_allocator_initialized() {
    let node = make_node();
    // Index allocator should be empty on creation
    assert_eq!(node.index_allocator.count(), 0);
}

#[test]
fn test_node_pending_outbound_tracking() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    // Allocate an index
    let index = node.index_allocator.allocate().unwrap();

    // Track in pending_outbound
    node.pending_outbound
        .insert((transport_id, index.as_u32()), link_id);

    // Verify we can look it up
    let found = node.pending_outbound.get(&(transport_id, index.as_u32()));
    assert_eq!(found, Some(&link_id));

    // Clean up
    node.pending_outbound
        .remove(&(transport_id, index.as_u32()));
    let _ = node.index_allocator.free(index);

    assert_eq!(node.index_allocator.count(), 0);
    assert!(node.pending_outbound.is_empty());
}

#[test]
fn pending_outbound_handshakes_own_msg2_index_matching_and_cleanup() {
    let original_transport = TransportId::new(1);
    let reply_transport = TransportId::new(2);
    let ambiguous_transport = TransportId::new(3);
    let link_id = LinkId::new(11);
    let ambiguous_link_id = LinkId::new(12);
    let exact_link_id = LinkId::new(13);
    let receiver_idx = 42;

    let mut pending = PendingOutboundHandshakes::default();
    pending.insert((original_transport, receiver_idx), link_id);

    assert_eq!(
        pending.match_msg2(reply_transport, receiver_idx),
        Some(((original_transport, receiver_idx), link_id)),
        "a unique sender index must survive a reply that arrives on an equivalent transport"
    );

    pending.insert((ambiguous_transport, receiver_idx), ambiguous_link_id);
    assert_eq!(
        pending.match_msg2(reply_transport, receiver_idx),
        None,
        "cross-transport fallback must refuse ambiguous sender indexes"
    );

    pending.insert((reply_transport, receiver_idx), exact_link_id);
    assert_eq!(
        pending.match_msg2(reply_transport, receiver_idx),
        Some(((reply_transport, receiver_idx), exact_link_id)),
        "exact transport/index match must win even when other transports share the index"
    );

    pending.remove(&(reply_transport, receiver_idx));
    assert!(pending.contains_key(&(original_transport, receiver_idx)));
    assert!(pending.contains_key(&(ambiguous_transport, receiver_idx)));
    pending.remove(&(original_transport, receiver_idx));
    pending.remove(&(ambiguous_transport, receiver_idx));
    assert!(pending.is_empty());
}

#[test]
fn test_node_active_peer_registry_tracking() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let node_addr = make_node_addr(42);

    // Allocate an index
    let index = node.index_allocator.allocate().unwrap();

    // Track in active peer registry session-index dispatch
    node.peers
        .insert_session_index((transport_id, index.as_u32()), node_addr);

    // Verify lookup
    let found = node
        .peers
        .get_session_index(&(transport_id, index.as_u32()));
    assert_eq!(found, Some(&node_addr));

    // Clean up
    node.peers
        .remove_session_index(&(transport_id, index.as_u32()));
    let _ = node.index_allocator.free(index);

    assert!(node.peers.session_index_is_empty());
}

#[test]
fn session_index_registry_owns_lookup_replace_remove_and_peer_membership() {
    let transport_id = TransportId::new(1);
    let current_key = (transport_id, 10);
    let pending_key = (transport_id, 11);
    let peer_addr = make_node_addr(42);
    let stale_peer_addr = make_node_addr(43);

    let mut registry = SessionIndexRegistry::default();

    assert_eq!(registry.insert(current_key, peer_addr), None);
    assert_eq!(registry.insert(pending_key, peer_addr), None);
    assert_eq!(registry.lookup(current_key), Some(peer_addr));
    assert!(registry.peer_has_any_index(&peer_addr));

    assert_eq!(registry.remove(&current_key), Some(peer_addr));
    assert!(
        registry.peer_has_any_index(&peer_addr),
        "removing the old index during rekey drain must see the peer's new index"
    );

    assert_eq!(
        registry.insert(pending_key, stale_peer_addr),
        Some(peer_addr),
        "a repaired session index must report the stale previous owner"
    );
    assert_eq!(registry.lookup(pending_key), Some(stale_peer_addr));
    assert!(!registry.peer_has_any_index(&peer_addr));

    assert_eq!(registry.remove(&pending_key), Some(stale_peer_addr));
    assert!(!registry.peer_has_any_index(&stale_peer_addr));
    assert!(registry.is_empty());
}

#[test]
fn active_peer_registry_owns_storage_session_index_and_stale_safe_cleanup() {
    let transport_id = TransportId::new(1);
    let current_key = (transport_id, 10);
    let pending_key = (transport_id, 11);

    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();

    let stale_peer_full = Identity::generate();
    let stale_peer_identity = PeerIdentity::from_pubkey_full(stale_peer_full.pubkey_full());
    let stale_peer_addr = *stale_peer_identity.node_addr();

    let mut registry = ActivePeerRegistry::default();
    assert!(
        registry
            .insert(
                peer_addr,
                ActivePeer::new(peer_identity, LinkId::new(10), 1_000),
            )
            .is_none()
    );
    assert!(registry.contains_key(&peer_addr));

    assert_eq!(registry.insert_session_index(current_key, peer_addr), None);
    assert_eq!(registry.insert_session_index(pending_key, peer_addr), None);
    assert_eq!(registry.lookup_session_index(current_key), Some(peer_addr));
    assert!(registry.peer_has_any_session_index(&peer_addr));

    assert_eq!(registry.remove_session_index(&current_key), Some(peer_addr));
    assert!(
        registry.peer_has_any_session_index(&peer_addr),
        "removing an old index during rekey drain must see the peer's new index"
    );

    assert_eq!(
        registry.insert_session_index(pending_key, stale_peer_addr),
        Some(peer_addr),
        "a repaired session index must report the stale previous owner"
    );
    assert_eq!(
        registry.lookup_session_index(pending_key),
        Some(stale_peer_addr)
    );
    assert!(!registry.peer_has_any_session_index(&peer_addr));

    let removed = registry
        .remove(&peer_addr)
        .expect("peer storage should live in the same owner");
    assert_eq!(removed.node_addr(), &peer_addr);
    assert!(!registry.contains_key(&peer_addr));

    assert_eq!(
        registry.remove_session_index(&pending_key),
        Some(stale_peer_addr)
    );
    assert!(!registry.peer_has_any_session_index(&stale_peer_addr));
    assert!(registry.session_index_is_empty());
}

#[test]
fn peer_lifecycle_registry_owns_session_index_removal_and_remaining_owner_state() {
    let transport_id = TransportId::new(1);
    let current_key = (transport_id, 10);
    let pending_key = (transport_id, 11);

    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();

    let stale_peer_full = Identity::generate();
    let stale_peer_identity = PeerIdentity::from_pubkey_full(stale_peer_full.pubkey_full());
    let stale_peer_addr = *stale_peer_identity.node_addr();

    let mut registry = PeerLifecycleRegistry::default();
    assert!(
        registry
            .insert(
                peer_addr,
                ActivePeer::new(peer_identity, LinkId::new(10), 1_000),
            )
            .is_none()
    );
    assert_eq!(registry.insert_session_index(current_key, peer_addr), None);
    assert_eq!(registry.insert_session_index(pending_key, peer_addr), None);

    let removed_current = registry
        .remove_session_index_with_owner_state(&current_key)
        .expect("old index should be owned by the active peer");
    assert_eq!(removed_current.owner, peer_addr);
    assert!(
        removed_current.owner_has_remaining_index,
        "removing the old index during rekey drain must atomically see the new index"
    );

    assert_eq!(
        registry.insert_session_index(pending_key, stale_peer_addr),
        Some(peer_addr),
        "repairing a stale owner should still report the replaced peer"
    );

    let removed_pending = registry
        .remove_session_index_with_owner_state(&pending_key)
        .expect("pending index should be owned by the stale peer after replacement");
    assert_eq!(removed_pending.owner, stale_peer_addr);
    assert!(
        !removed_pending.owner_has_remaining_index,
        "last-index removal should atomically report no remaining peer index"
    );
    assert!(registry.session_index_is_empty());
}

#[test]
fn peer_lifecycle_registry_owns_active_peer_insert_and_current_session_index() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let stale_peer_full = Identity::generate();
    let stale_peer_identity = PeerIdentity::from_pubkey_full(stale_peer_full.pubkey_full());
    let stale_peer_addr = *stale_peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(10);
    let remote_addr = TransportAddr::from_string("insert-peer");
    let current_our_index = SessionIndex::new(10);
    let their_index = SessionIndex::new(20);
    let current_key = (transport_id, current_our_index.as_u32());

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        link_id,
        remote_addr,
        current_our_index,
        their_index,
    );

    assert_eq!(
        registry.insert_session_index(current_key, stale_peer_addr),
        None
    );
    let inserted = registry.insert_with_current_session_index(peer_addr, active_peer);

    assert!(
        inserted.previous_peer.is_none(),
        "first insert should not replace active peer storage"
    );
    assert_eq!(
        inserted.current_session_index,
        Some(RegisteredPeerSessionIndex {
            session_index: PeerSessionIndex {
                kind: PeerSessionIndexKind::Current,
                key: current_key,
                index: current_our_index,
            },
            previous_owner: Some(stale_peer_addr),
        }),
        "peer lifecycle insertion must own current receiver-index registration and stale-owner repair"
    );
    assert!(registry.contains_key(&peer_addr));
    assert_eq!(registry.lookup_session_index(current_key), Some(peer_addr));
}

#[test]
fn peer_lifecycle_registry_owns_current_session_index_repair() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let stale_peer_full = Identity::generate();
    let stale_peer_identity = PeerIdentity::from_pubkey_full(stale_peer_full.pubkey_full());
    let stale_peer_addr = *stale_peer_identity.node_addr();

    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(10);
    let remote_addr = TransportAddr::from_string("current-index-repair-peer");
    let current_our_index = SessionIndex::new(10);
    let their_index = SessionIndex::new(20);
    let current_key = (transport_id, current_our_index.as_u32());
    let current_session_index = PeerSessionIndex {
        kind: PeerSessionIndexKind::Current,
        key: current_key,
        index: current_our_index,
    };

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        link_id,
        remote_addr,
        current_our_index,
        their_index,
    );
    assert!(registry.insert(peer_addr, active_peer).is_none());

    let missing_repair = registry.ensure_current_session_index_registered(&peer_addr);
    assert_eq!(
        missing_repair,
        CurrentSessionIndexRegistration::Repaired(RegisteredPeerSessionIndex {
            session_index: current_session_index,
            previous_owner: None,
        }),
        "missing current receiver-index repair should be a lifecycle-owner operation"
    );
    assert_eq!(registry.lookup_session_index(current_key), Some(peer_addr));

    let already_registered = registry.ensure_current_session_index_registered(&peer_addr);
    assert_eq!(
        already_registered,
        CurrentSessionIndexRegistration::AlreadyRegistered(current_session_index),
        "already-correct current receiver-index state should not be repaired again"
    );

    assert_eq!(
        registry.insert_session_index(current_key, stale_peer_addr),
        Some(peer_addr)
    );
    let stale_owner_repair = registry.ensure_current_session_index_registered(&peer_addr);
    assert_eq!(
        stale_owner_repair,
        CurrentSessionIndexRegistration::Repaired(RegisteredPeerSessionIndex {
            session_index: current_session_index,
            previous_owner: Some(stale_peer_addr),
        }),
        "stale current receiver-index owner repair should stay with the lifecycle owner"
    );
    assert_eq!(registry.lookup_session_index(current_key), Some(peer_addr));

    assert_eq!(
        registry.ensure_current_session_index_registered(&make_node_addr(99)),
        CurrentSessionIndexRegistration::MissingActivePeer
    );

    let no_transport_full = Identity::generate();
    let no_transport_identity = PeerIdentity::from_pubkey_full(no_transport_full.pubkey_full());
    let no_transport_addr = *no_transport_identity.node_addr();
    assert!(
        registry
            .insert(
                no_transport_addr,
                ActivePeer::new(no_transport_identity, LinkId::new(77), 3_000),
            )
            .is_none()
    );
    assert_eq!(
        registry.ensure_current_session_index_registered(&no_transport_addr),
        CurrentSessionIndexRegistration::MissingTransportId
    );

    registry
        .get_mut(&no_transport_addr)
        .expect("no-transport peer should exist")
        .set_current_addr(
            TransportId::new(77),
            &TransportAddr::from_string("current-index-repair-no-index"),
        );
    assert_eq!(
        registry.ensure_current_session_index_registered(&no_transport_addr),
        CurrentSessionIndexRegistration::MissingLocalIndex
    );
}

#[test]
fn peer_lifecycle_registry_owns_current_session_replacement_and_index_handoff() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let stale_peer_full = Identity::generate();
    let stale_peer_identity = PeerIdentity::from_pubkey_full(stale_peer_full.pubkey_full());
    let stale_peer_addr = *stale_peer_identity.node_addr();

    let old_transport_id = TransportId::new(1);
    let new_transport_id = TransportId::new(2);
    let old_link_id = LinkId::new(10);
    let new_link_id = LinkId::new(20);
    let old_addr = TransportAddr::from_string("old-session-path");
    let new_addr = TransportAddr::from_string("new-session-path");
    let old_our_index = SessionIndex::new(10);
    let old_their_index = SessionIndex::new(20);
    let new_our_index = SessionIndex::new(11);
    let new_their_index = SessionIndex::new(21);
    let old_key = (old_transport_id, old_our_index.as_u32());
    let new_key = (new_transport_id, new_our_index.as_u32());

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        old_transport_id,
        old_link_id,
        old_addr,
        old_our_index,
        old_their_index,
    );
    registry.insert_with_current_session_index(peer_addr, active_peer);
    assert_eq!(registry.lookup_session_index(old_key), Some(peer_addr));
    assert_eq!(
        registry.insert_session_index(new_key, stale_peer_addr),
        None
    );
    registry
        .get_mut(&peer_addr)
        .expect("active peer should exist")
        .increment_replay_suppressed();

    let new_session = make_test_fmp_session(&node.identity, &peer_full, [0x03; 8], [0x04; 8]);
    let replaced = registry
        .replace_current_session_and_path(
            &peer_addr,
            new_session,
            new_our_index,
            new_their_index,
            new_link_id,
            new_transport_id,
            &new_addr,
            Some([0x04; 8]),
            2_000,
        )
        .expect("active peer replacement should be owned by the lifecycle registry");

    assert_eq!(replaced.old_link_id, old_link_id);
    assert_eq!(replaced.replay_suppressed_count, 1);
    assert_eq!(
        replaced.old_session_index,
        Some(PeerSessionIndex {
            kind: PeerSessionIndexKind::Current,
            key: old_key,
            index: old_our_index,
        }),
        "replacement should return the old current index for Node-owned teardown"
    );
    assert_eq!(
        replaced.new_session_index,
        RegisteredPeerSessionIndex {
            session_index: PeerSessionIndex {
                kind: PeerSessionIndexKind::Current,
                key: new_key,
                index: new_our_index,
            },
            previous_owner: Some(stale_peer_addr),
        },
        "replacement should install the new current receiver index and report stale-owner repair"
    );
    assert_eq!(registry.lookup_session_index(old_key), Some(peer_addr));
    assert_eq!(registry.lookup_session_index(new_key), Some(peer_addr));

    let removed_old = registry
        .remove_session_index_with_owner_state(&old_key)
        .expect("old key should still be present until Node performs teardown");
    assert_eq!(removed_old.owner, peer_addr);
    assert!(
        removed_old.owner_has_remaining_index,
        "new current index must be visible before old-index teardown runs"
    );

    let peer = registry
        .get(&peer_addr)
        .expect("replacement must keep active peer storage");
    assert_eq!(peer.link_id(), new_link_id);
    assert_eq!(peer.transport_id(), Some(new_transport_id));
    assert_eq!(peer.current_addr(), Some(&new_addr));
    assert_eq!(peer.our_index(), Some(new_our_index));
    assert_eq!(peer.their_index(), Some(new_their_index));
    assert_eq!(peer.remote_epoch(), Some([0x04; 8]));
    assert_eq!(peer.last_seen(), 2_000);
}

#[test]
fn peer_lifecycle_registry_owns_pending_rekey_session_and_index_registration() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let stale_peer_full = Identity::generate();
    let stale_peer_identity = PeerIdentity::from_pubkey_full(stale_peer_full.pubkey_full());
    let stale_peer_addr = *stale_peer_identity.node_addr();

    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(10);
    let current_addr = TransportAddr::from_string("pending-rekey-path");
    let current_our_index = SessionIndex::new(10);
    let current_their_index = SessionIndex::new(20);
    let pending_our_index = SessionIndex::new(11);
    let pending_their_index = SessionIndex::new(21);
    let current_key = (transport_id, current_our_index.as_u32());
    let pending_key = (transport_id, pending_our_index.as_u32());

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        link_id,
        current_addr,
        current_our_index,
        current_their_index,
    );
    registry.insert_with_current_session_index(peer_addr, active_peer);
    assert_eq!(registry.lookup_session_index(current_key), Some(peer_addr));
    assert_eq!(
        registry.insert_session_index(pending_key, stale_peer_addr),
        None
    );

    let pending_session = make_test_fmp_session(&node.identity, &peer_full, [0x05; 8], [0x06; 8]);
    let registered = registry
        .install_pending_rekey_session_and_index(
            &peer_addr,
            pending_session,
            pending_our_index,
            pending_their_index,
            false,
            None,
        )
        .expect("pending rekey session should be owned by the lifecycle registry");

    assert_eq!(
        registered,
        RegisteredPeerSessionIndex {
            session_index: PeerSessionIndex {
                kind: PeerSessionIndexKind::Pending,
                key: pending_key,
                index: pending_our_index,
            },
            previous_owner: Some(stale_peer_addr),
        },
        "installing a pending rekey session must also register its receiver index and report stale-owner repair"
    );
    assert_eq!(registry.lookup_session_index(current_key), Some(peer_addr));
    assert_eq!(registry.lookup_session_index(pending_key), Some(peer_addr));

    let peer = registry
        .get(&peer_addr)
        .expect("pending rekey install must keep active peer storage");
    assert_eq!(peer.pending_our_index(), Some(pending_our_index));
    assert_eq!(peer.pending_their_index(), Some(pending_their_index));
    assert!(peer.pending_new_session().is_some());
    assert!(!peer.pending_rekey_initiator());
    assert!(
        !peer.rekey_in_progress(),
        "completed pending rekey install should clear in-progress handshake state"
    );
}

#[test]
fn peer_lifecycle_registry_owns_authenticated_fmp_receive_bookkeeping() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();

    let old_transport_id = TransportId::new(1);
    let new_transport_id = TransportId::new(2);
    let link_id = LinkId::new(10);
    let old_addr = TransportAddr::from_string("authenticated-recv-old-path");
    let new_addr = TransportAddr::from_string("authenticated-recv-new-path");
    let ignored_addr = TransportAddr::from_string("authenticated-recv-ignored-path");
    let current_our_index = SessionIndex::new(10);
    let current_their_index = SessionIndex::new(20);

    let mut registry = PeerLifecycleRegistry::default();
    let mut active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        old_transport_id,
        link_id,
        old_addr,
        current_our_index,
        current_their_index,
    );
    active_peer.increment_decrypt_failures();
    active_peer.mark_stale();
    registry.insert_with_current_session_index(peer_addr, active_peer);

    let now = std::time::Instant::now();
    let update = registry
        .record_authenticated_fmp_receive(
            &peer_addr,
            new_transport_id,
            &new_addr,
            2_000,
            128,
            7,
            1_234,
            true,
            false,
            now,
            true,
        )
        .expect("authenticated receive bookkeeping should find active peer");

    assert!(
        update.address_changed,
        "path update should report that connected UDP must be cleared"
    );
    assert!(update.path_bookkeeping_recorded);
    assert!(update.mmp_recorded);
    assert!(
        update.spin_rtt.is_none(),
        "first initiator spin edge flips the bit but has no prior edge for RTT"
    );

    let peer = registry
        .get(&peer_addr)
        .expect("authenticated receive must keep active peer storage");
    assert_eq!(peer.consecutive_decrypt_failures(), 0);
    assert_eq!(peer.transport_id(), Some(new_transport_id));
    assert_eq!(peer.current_addr(), Some(&new_addr));
    assert_eq!(peer.last_seen(), 2_000);
    assert_eq!(peer.link_stats().packets_recv, 1);
    assert_eq!(peer.link_stats().bytes_recv, 128);
    assert_eq!(peer.link_stats().last_recv_ms, 2_000);
    let mmp = peer.mmp().expect("active FMP peer should have MMP state");
    assert_eq!(mmp.receiver.cumulative_packets_recv(), 1);
    assert_eq!(mmp.receiver.cumulative_bytes_recv(), 128);
    assert_eq!(mmp.receiver.highest_counter(), 7);
    assert_eq!(mmp.receiver.ecn_ce_count(), 1);
    assert!(
        mmp.spin_bit.tx_bit(),
        "authenticated receive bookkeeping should own spin-bit observation"
    );

    registry
        .get_mut(&peer_addr)
        .expect("peer should still exist")
        .increment_decrypt_failures();
    let skipped = registry
        .record_authenticated_fmp_receive(
            &peer_addr,
            new_transport_id,
            &ignored_addr,
            3_000,
            64,
            8,
            1_999,
            false,
            true,
            now,
            false,
        )
        .expect("disallowed path bookkeeping should still reset decrypt failures");

    assert!(!skipped.address_changed);
    assert!(!skipped.path_bookkeeping_recorded);
    assert!(!skipped.mmp_recorded);
    assert!(skipped.spin_rtt.is_none());
    let peer = registry
        .get(&peer_addr)
        .expect("skipped receive must keep active peer storage");
    assert_eq!(peer.consecutive_decrypt_failures(), 0);
    assert_eq!(peer.current_addr(), Some(&new_addr));
    assert_eq!(peer.last_seen(), 2_000);
    assert_eq!(peer.link_stats().packets_recv, 1);
    let mmp = peer.mmp().expect("active FMP peer should have MMP state");
    assert_eq!(mmp.receiver.cumulative_packets_recv(), 1);
}

#[test]
fn peer_runtime_receive_rejects_short_authenticated_fmp_plaintext() {
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let remote_addr = TransportAddr::from_string("short-authenticated-fmp");

    let result =
        PeerRuntimeReceive::from_authenticated_fmp_plaintext(AuthenticatedFmpPlaintext::new(
            peer_identity,
            TransportId::new(1),
            &remote_addr,
            1_000,
            32,
            1,
            0,
            &[1, 2, 3],
        ));

    assert!(matches!(
        result,
        Err(PeerRuntimeReceiveError::MissingInnerTimestamp)
    ));
}

#[test]
fn peer_runtime_receive_owns_bookkeeping_and_dispatch_metadata() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();

    let old_transport_id = TransportId::new(1);
    let new_transport_id = TransportId::new(2);
    let link_id = LinkId::new(10);
    let old_addr = TransportAddr::from_string("runtime-recv-old-path");
    let new_addr = TransportAddr::from_string("runtime-recv-new-path");
    let current_our_index = SessionIndex::new(10);
    let current_their_index = SessionIndex::new(20);

    let mut registry = PeerLifecycleRegistry::default();
    let mut active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        old_transport_id,
        link_id,
        old_addr,
        current_our_index,
        current_their_index,
    );
    active_peer.increment_decrypt_failures();
    registry.insert_with_current_session_index(peer_addr, active_peer);

    let fmp_plaintext = [
        0xd2,
        0x04,
        0x00,
        0x00,
        LinkMessageType::SessionDatagram.to_byte(),
        0xbb,
        0xcc,
    ];
    let receive =
        PeerRuntimeReceive::from_authenticated_fmp_plaintext(AuthenticatedFmpPlaintext::new(
            peer_identity,
            new_transport_id,
            &new_addr,
            2_000,
            128,
            7,
            FLAG_CE,
            &fmp_plaintext,
        ))
        .expect("valid authenticated FMP plaintext should build a receive runtime");

    let dispatch = receive.record_bookkeeping(&mut registry, std::time::Instant::now(), true);

    assert_eq!(dispatch.source_peer(), peer_identity);
    assert_eq!(dispatch.node_addr(), &peer_addr);
    assert!(dispatch.ce_flag());
    assert_eq!(
        dispatch.link_message(),
        &[LinkMessageType::SessionDatagram.to_byte(), 0xbb, 0xcc]
    );
    assert!(dispatch.address_changed());
    let bookkeeping = dispatch
        .bookkeeping()
        .expect("authenticated receive should find the active peer");
    assert!(bookkeeping.path_bookkeeping_recorded);
    assert!(bookkeeping.mmp_recorded);
    let link_message = dispatch
        .into_link_message()
        .expect("non-empty FMP link message should parse");
    assert_eq!(link_message.source_node_addr(), &peer_addr);
    assert_eq!(
        link_message.msg_type(),
        LinkMessageType::SessionDatagram.to_byte()
    );
    assert_eq!(link_message.payload(), &[0xbb, 0xcc]);
    assert!(link_message.ce_flag());
    let session_datagram = link_message.into_session_datagram();
    assert_eq!(session_datagram.previous_hop_addr(), &peer_addr);
    assert_eq!(session_datagram.payload(), &[0xbb, 0xcc]);
    assert!(session_datagram.ce_flag());
    let session_source = make_node_addr(0x44);
    let local_payload =
        session_datagram.local_session_payload(session_source, &[0xdd, 0xee], 1_280);
    assert_eq!(local_payload.source_addr(), &session_source);
    assert_eq!(local_payload.previous_hop_addr(), &peer_addr);
    assert_eq!(local_payload.payload(), &[0xdd, 0xee]);
    let encrypted_payload = local_payload.into_encrypted();
    assert_eq!(encrypted_payload.source_addr(), &session_source);
    assert_eq!(encrypted_payload.previous_hop_addr(), &peer_addr);
    assert_eq!(encrypted_payload.payload(), &[0xdd, 0xee]);
    assert_eq!(encrypted_payload.path_mtu(), 1_280);
    assert!(encrypted_payload.ce_flag());

    let peer = registry
        .get(&peer_addr)
        .expect("receive runtime must keep active peer storage");
    assert_eq!(peer.consecutive_decrypt_failures(), 0);
    assert_eq!(peer.transport_id(), Some(new_transport_id));
    assert_eq!(peer.current_addr(), Some(&new_addr));
    assert_eq!(peer.link_stats().packets_recv, 1);
    assert_eq!(peer.link_stats().bytes_recv, 128);
    let mmp = peer.mmp().expect("active FMP peer should have MMP state");
    assert_eq!(mmp.receiver.highest_counter(), 7);
    assert_eq!(mmp.receiver.ecn_ce_count(), 1);
}

#[test]
fn peer_lifecycle_registry_owns_fmp_send_bookkeeping() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();

    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(10);
    let remote_addr = TransportAddr::from_string("fmp-send-bookkeeping-peer");
    let current_our_index = SessionIndex::new(10);
    let current_their_index = SessionIndex::new(20);

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        link_id,
        remote_addr,
        current_our_index,
        current_their_index,
    );
    registry.insert_with_current_session_index(peer_addr, active_peer);

    let update = registry
        .record_fmp_send_bookkeeping(&peer_addr, 7, 1_234, 256)
        .expect("FMP send bookkeeping should find active peer");
    assert!(
        update.mmp_recorded,
        "active FMP peers should update MMP sender state with link send stats"
    );

    let peer = registry
        .get(&peer_addr)
        .expect("send bookkeeping must keep active peer storage");
    assert_eq!(peer.link_stats().packets_sent, 1);
    assert_eq!(peer.link_stats().bytes_sent, 256);
    let mmp = peer.mmp().expect("active FMP peer should have MMP state");
    assert_eq!(mmp.sender.cumulative_packets_sent(), 1);
    assert_eq!(mmp.sender.cumulative_bytes_sent(), 256);

    let second_update = registry
        .record_fmp_send_bookkeeping(&peer_addr, 8, 1_300, 128)
        .expect("second FMP send bookkeeping should find active peer");
    assert!(second_update.mmp_recorded);
    let peer = registry
        .get(&peer_addr)
        .expect("second send bookkeeping must keep active peer storage");
    assert_eq!(peer.link_stats().packets_sent, 2);
    assert_eq!(peer.link_stats().bytes_sent, 384);
    let mmp = peer.mmp().expect("active FMP peer should have MMP state");
    assert_eq!(mmp.sender.cumulative_packets_sent(), 2);
    assert_eq!(mmp.sender.cumulative_bytes_sent(), 384);

    let no_mmp_full = Identity::generate();
    let no_mmp_identity = PeerIdentity::from_pubkey_full(no_mmp_full.pubkey_full());
    let no_mmp_addr = *no_mmp_identity.node_addr();
    assert!(
        registry
            .insert(
                no_mmp_addr,
                ActivePeer::new(no_mmp_identity, LinkId::new(77), 3_000),
            )
            .is_none()
    );
    let legacy_update = registry
        .record_fmp_send_bookkeeping(&no_mmp_addr, 9, 1_400, 64)
        .expect("legacy active peer should still record link send stats");
    assert!(
        !legacy_update.mmp_recorded,
        "legacy peers without MMP state should not claim MMP sender updates"
    );
    let peer = registry
        .get(&no_mmp_addr)
        .expect("legacy send bookkeeping must keep active peer storage");
    assert_eq!(peer.link_stats().packets_sent, 1);
    assert_eq!(peer.link_stats().bytes_sent, 64);

    assert!(
        registry
            .record_fmp_send_bookkeeping(&make_node_addr(99), 10, 1_500, 32)
            .is_none(),
        "missing active peers should not record send bookkeeping"
    );
}

#[cfg(unix)]
#[test]
fn peer_lifecycle_registry_owns_fmp_send_preparation_and_seal_paths() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(7);
    let link_id = LinkId::new(9);
    let remote_addr = TransportAddr::from_string("fmp-send-prepare-peer");
    let our_index = SessionIndex::new(10);
    let their_index = SessionIndex::new(20);
    let (sender, mut receiver) =
        make_test_fmp_session_pair(&node.identity, &peer_full, [0x01; 8], [0x02; 8]);

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = ActivePeer::with_session(
        peer_identity,
        link_id,
        1_000,
        sender,
        our_index,
        their_index,
        transport_id,
        remote_addr.clone(),
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([0x02; 8]),
    );
    registry.insert_with_current_session_index(peer_addr, active_peer);

    let plaintext = b"owner-prepared-fmp";
    let payload_len = (4 + plaintext.len()) as u16;
    let prepared = registry
        .prepare_fmp_send(&peer_addr, true, payload_len)
        .expect("lifecycle owner should prepare FMP send metadata");

    assert_eq!(prepared.transport_id, transport_id);
    assert_eq!(prepared.remote_addr, remote_addr);
    assert_eq!(prepared.their_index, their_index);
    assert_eq!(prepared.payload_len, payload_len);
    assert_eq!(prepared.flags & FLAG_CE, FLAG_CE);
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        0,
        "preparation must not consume a Noise send counter"
    );

    let mismatched_prepared = registry
        .prepare_fmp_send(&peer_addr, true, payload_len + 1)
        .expect("lifecycle owner should prepare mismatched metadata for guard");
    assert!(
        matches!(
            registry.prepare_fmp_worker_send(&peer_addr, &mismatched_prepared, plaintext),
            Err(FmpSendPreparationError::PayloadLengthMismatch)
        ),
        "payload mismatch should be rejected before counter reservation"
    );
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        0,
        "payload mismatch must not consume a Noise send counter"
    );

    let worker = registry
        .prepare_fmp_worker_send(&peer_addr, &prepared, plaintext)
        .expect("worker packet preparation should be owner-managed")
        .expect("established FMP peer should expose a worker cipher");
    assert_eq!(worker.counter, 0);
    assert_eq!(
        worker.header,
        build_established_header(their_index, worker.counter, prepared.flags, payload_len)
    );
    assert_eq!(
        worker.predicted_bytes,
        ESTABLISHED_HEADER_SIZE + payload_len as usize + 16
    );
    assert_eq!(
        worker.wire_buf.len(),
        ESTABLISHED_HEADER_SIZE + payload_len as usize
    );
    assert!(
        worker.wire_buf.capacity() >= worker.predicted_bytes,
        "worker wire buffer should reserve room for the FMP AEAD tag"
    );
    assert_eq!(&worker.wire_buf[..ESTABLISHED_HEADER_SIZE], &worker.header);
    assert_eq!(
        &worker.wire_buf[ESTABLISHED_HEADER_SIZE..ESTABLISHED_HEADER_SIZE + 4],
        &prepared.timestamp_ms.to_le_bytes()
    );
    assert_eq!(&worker.wire_buf[ESTABLISHED_HEADER_SIZE + 4..], plaintext);
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        1,
        "worker reservation should consume exactly one counter"
    );

    let worker_inner_plaintext = prepend_inner_header(prepared.timestamp_ms, plaintext);
    let mut worker_wire = worker.wire_buf.clone();
    let worker_tag = {
        let (header, plaintext) = worker_wire.split_at_mut(ESTABLISHED_HEADER_SIZE);
        worker
            .cipher
            .seal_in_place_separate_tag(
                crate::noise::CipherState::counter_to_nonce(worker.counter),
                ring::aead::Aad::from(header),
                plaintext,
            )
            .expect("worker-style FMP seal should succeed")
    };
    worker_wire.extend_from_slice(worker_tag.as_ref());
    let worker_parsed = EncryptedHeader::parse(&worker_wire).expect("worker wire packet parses");
    assert_eq!(worker_parsed.counter, worker.counter);
    assert_eq!(worker_parsed.receiver_idx, their_index);
    assert_eq!(
        receiver
            .decrypt_with_replay_check_and_aad(
                worker_parsed.ciphertext(&worker_wire),
                worker_parsed.counter,
                &worker.header,
            )
            .expect("receiver should accept worker-sealed packet"),
        worker_inner_plaintext
    );

    let inline_prepared = registry
        .prepare_fmp_send(&peer_addr, false, payload_len)
        .expect("lifecycle owner should prepare inline FMP send metadata");
    let inline_inner_plaintext = prepend_inner_header(inline_prepared.timestamp_ms, plaintext);
    let inline = registry
        .seal_prepared_fmp_inline_send(&peer_addr, &inline_prepared, &inline_inner_plaintext)
        .expect("inline seal should be owner-managed");
    assert_eq!(inline.counter, 1);
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        2,
        "inline seal should consume exactly one counter"
    );
    let parsed = EncryptedHeader::parse(&inline.wire_packet).expect("inline wire packet parses");
    assert_eq!(parsed.counter, inline.counter);
    assert_eq!(parsed.receiver_idx, their_index);
    assert_eq!(
        receiver
            .decrypt_with_replay_check_and_aad(
                parsed.ciphertext(&inline.wire_packet),
                parsed.counter,
                &inline.header,
            )
            .expect("receiver should accept inline-sealed packet"),
        inline_inner_plaintext
    );

    let pipelined_link_plaintext_len = crate::protocol::SESSION_DATAGRAM_HEADER_SIZE
        + crate::node::session_wire::FSP_HEADER_SIZE
        + 32;
    let pipelined_payload_len = (4 + pipelined_link_plaintext_len + crate::noise::TAG_SIZE) as u16;
    let pipelined_prepared = registry
        .prepare_fmp_send(&peer_addr, false, pipelined_payload_len)
        .expect("lifecycle owner should prepare pipelined FMP metadata");
    let pipelined_snapshot = registry
        .prepare_peer_runtime_send_snapshot(&peer_addr, false, pipelined_payload_len)
        .expect("peer runtime owner should prepare pipelined FMP metadata with availability");
    assert!(
        pipelined_snapshot.fmp_worker_send_available(),
        "pipelined path should check FMP worker-cipher availability before reserving FSP"
    );
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        2,
        "worker availability check must not consume an FMP counter"
    );
    let pipelined_reservation = registry
        .reserve_prepared_fmp_worker_send(&peer_addr, &pipelined_prepared)
        .expect("pipelined FMP reservation should be owner-managed")
        .expect("established FMP peer should expose a worker cipher");
    assert_eq!(pipelined_reservation.counter, 2);
    assert_eq!(
        pipelined_reservation.header,
        build_established_header(
            their_index,
            pipelined_reservation.counter,
            pipelined_prepared.flags,
            pipelined_payload_len,
        )
    );
    assert_eq!(
        pipelined_reservation.predicted_bytes,
        ESTABLISHED_HEADER_SIZE + pipelined_payload_len as usize + crate::noise::TAG_SIZE,
        "predicted bytes should include the outer FMP AEAD tag"
    );
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        3,
        "pipelined worker reservation should consume exactly one FMP counter"
    );

    let mut pipelined_link_ciphertext = vec![0xA5; pipelined_link_plaintext_len];
    pipelined_link_ciphertext.extend_from_slice(&[0x5A; crate::noise::TAG_SIZE]);
    let pipelined_inner =
        prepend_inner_header(pipelined_prepared.timestamp_ms, &pipelined_link_ciphertext);
    let mut pipelined_wire = Vec::with_capacity(pipelined_reservation.predicted_bytes);
    pipelined_wire.extend_from_slice(&pipelined_reservation.header);
    pipelined_wire.extend_from_slice(&pipelined_inner);
    assert_eq!(
        pipelined_wire.len(),
        ESTABLISHED_HEADER_SIZE + pipelined_payload_len as usize
    );
    let pipelined_tag = {
        let (header, plaintext) = pipelined_wire.split_at_mut(ESTABLISHED_HEADER_SIZE);
        pipelined_reservation
            .cipher
            .seal_in_place_separate_tag(
                crate::noise::CipherState::counter_to_nonce(pipelined_reservation.counter),
                ring::aead::Aad::from(header),
                plaintext,
            )
            .expect("pipelined worker-style FMP seal should succeed")
    };
    pipelined_wire.extend_from_slice(pipelined_tag.as_ref());
    let pipelined_parsed =
        EncryptedHeader::parse(&pipelined_wire).expect("pipelined wire packet parses");
    assert_eq!(pipelined_parsed.counter, pipelined_reservation.counter);
    assert_eq!(pipelined_parsed.receiver_idx, their_index);
    assert_eq!(
        receiver
            .decrypt_with_replay_check_and_aad(
                pipelined_parsed.ciphertext(&pipelined_wire),
                pipelined_parsed.counter,
                &pipelined_reservation.header,
            )
            .expect("receiver should accept pipelined worker-sealed packet"),
        pipelined_inner
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn peer_lifecycle_registry_owns_connected_udp_activation_plan() {
    let node = make_node();
    let transport_id = TransportId::new(1);

    let configured_full = Identity::generate();
    let configured_identity = PeerIdentity::from_pubkey_full(configured_full.pubkey_full());
    let configured_addr = *configured_identity.node_addr();

    let discovered_full = Identity::generate();
    let discovered_identity = PeerIdentity::from_pubkey_full(discovered_full.pubkey_full());
    let discovered_addr = *discovered_identity.node_addr();

    let stale_full = Identity::generate();
    let stale_identity = PeerIdentity::from_pubkey_full(stale_full.pubkey_full());
    let stale_addr = *stale_identity.node_addr();

    let installed_full = Identity::generate();
    let installed_identity = PeerIdentity::from_pubkey_full(installed_full.pubkey_full());
    let installed_addr = *installed_identity.node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        configured_full.npub(),
        "udp",
        "127.0.0.1:1",
    ));
    let configured_peers = ConfiguredPeerSendWeights::from_config(&config);

    let mut registry = PeerLifecycleRegistry::default();
    registry.insert_with_current_session_index(
        discovered_addr,
        make_active_test_peer(
            &node,
            &discovered_full,
            discovered_identity,
            transport_id,
            LinkId::new(20),
            TransportAddr::from_string("connected-udp-discovered"),
            SessionIndex::new(20),
            SessionIndex::new(30),
        ),
    );
    registry.insert_with_current_session_index(
        configured_addr,
        make_active_test_peer(
            &node,
            &configured_full,
            configured_identity,
            transport_id,
            LinkId::new(10),
            TransportAddr::from_string("connected-udp-configured"),
            SessionIndex::new(10),
            SessionIndex::new(11),
        ),
    );

    let mut stale_peer = make_active_test_peer(
        &node,
        &stale_full,
        stale_identity,
        transport_id,
        LinkId::new(30),
        TransportAddr::from_string("connected-udp-stale"),
        SessionIndex::new(40),
        SessionIndex::new(41),
    );
    stale_peer.mark_stale();
    registry.insert_with_current_session_index(stale_addr, stale_peer);

    let mut installed_peer = make_active_test_peer(
        &node,
        &installed_full,
        installed_identity,
        transport_id,
        LinkId::new(40),
        TransportAddr::from_string("connected-udp-installed"),
        SessionIndex::new(50),
        SessionIndex::new(51),
    );
    let (socket, drain) = make_test_connected_udp_pair(transport_id);
    installed_peer.set_connected_udp(socket, drain);
    registry.insert_with_current_session_index(installed_addr, installed_peer);

    let plan = registry.connected_udp_activation_plan(&configured_peers);

    assert_eq!(
        plan.installed_count, 1,
        "lifecycle owner should count already-installed connected UDP peers"
    );
    assert_eq!(
        plan.candidates,
        vec![configured_addr, discovered_addr],
        "configured peers should be activated before discovered peers, while stale and already-connected peers are skipped"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn peer_lifecycle_registry_owns_connected_udp_install_and_clear() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        LinkId::new(10),
        TransportAddr::from_string("connected-udp-install"),
        SessionIndex::new(10),
        SessionIndex::new(11),
    );
    registry.insert_with_current_session_index(peer_addr, active_peer);

    let (socket, drain) = make_test_connected_udp_pair(transport_id);
    let installed = registry.install_connected_udp_if_eligible(&peer_addr, socket, drain);

    assert_eq!(
        installed,
        ConnectedUdpInstallResult::Installed,
        "lifecycle owner should install connected UDP only after eligibility recheck"
    );
    assert!(
        registry
            .get(&peer_addr)
            .expect("active peer")
            .connected_udp()
            .is_some(),
        "connected UDP socket should be visible through the active peer after lifecycle install"
    );

    let (second_socket, second_drain) = make_test_connected_udp_pair(transport_id);
    assert_eq!(
        registry.install_connected_udp_if_eligible(&peer_addr, second_socket, second_drain),
        ConnectedUdpInstallResult::NotEligible,
        "already-installed connected UDP peers must not get a replacement from the activation race path"
    );

    assert_eq!(
        registry.clear_connected_udp_for_peer(&peer_addr),
        ConnectedUdpClearResult::Cleared,
        "lifecycle owner should clear an installed connected UDP socket/drain pair"
    );
    assert!(
        registry
            .get(&peer_addr)
            .expect("active peer")
            .connected_udp()
            .is_none(),
        "connected UDP socket should be gone after lifecycle clear"
    );
    assert_eq!(
        registry.clear_connected_udp_for_peer(&peer_addr),
        ConnectedUdpClearResult::AlreadyClear,
        "clearing an already-clear peer should be idempotent"
    );
    assert_eq!(
        registry.clear_connected_udp_for_peer(&NodeAddr::from_bytes([0x42; 16])),
        ConnectedUdpClearResult::MissingPeer,
        "clear should report when the peer lifecycle owner has no active peer"
    );
}

#[test]
fn peer_lifecycle_registry_owns_link_dead_direct_path_degradation() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();

    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(10);
    let remote_addr = TransportAddr::from_string("link-dead-peer");
    let current_our_index = SessionIndex::new(10);
    let their_index = SessionIndex::new(20);

    let mut registry = PeerLifecycleRegistry::default();
    let mut active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        link_id,
        remote_addr,
        current_our_index,
        their_index,
    );

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let (socket, drain) = make_test_connected_udp_pair(transport_id);
        active_peer.set_connected_udp(socket, drain);
        assert!(
            active_peer.connected_udp().is_some(),
            "fixture should start with connected UDP installed"
        );
    }

    registry.insert_with_current_session_index(peer_addr, active_peer);

    let degraded = registry
        .mark_link_dead_direct_path(&peer_addr)
        .expect("link-dead degradation should find active peer");

    assert_eq!(
        degraded.link_id, link_id,
        "lifecycle owner should return the degraded link for logging and cleanup"
    );
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert!(
        degraded.connected_udp_cleared,
        "link-dead degradation should clear connected UDP through the lifecycle owner"
    );

    let peer = registry
        .get(&peer_addr)
        .expect("link-dead degradation must keep active peer storage");
    assert!(
        peer.can_send(),
        "stale direct paths remain probeable instead of becoming disconnected"
    );
    assert!(
        !peer.is_healthy(),
        "link-dead direct paths should no longer be healthy for payload routing"
    );
    assert_eq!(
        peer.link_id(),
        link_id,
        "link-dead degradation should not swap peer link identity"
    );
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert!(
        peer.connected_udp().is_none(),
        "connected UDP socket/drain pair must not outlive stale direct-path evidence"
    );
}

#[test]
fn peer_lifecycle_registry_owns_active_peer_teardown_session_indices() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(10);
    let remote_addr = TransportAddr::from_string("teardown-peer");
    let current_our_index = SessionIndex::new(10);
    let their_index = SessionIndex::new(20);
    let rekey_our_index = SessionIndex::new(11);

    let mut registry = PeerLifecycleRegistry::default();
    let mut active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        link_id,
        remote_addr,
        current_our_index,
        their_index,
    );
    arm_test_fmp_rekey(&mut active_peer, rekey_our_index);

    assert!(registry.insert(peer_addr, active_peer).is_none());
    assert_eq!(
        registry.insert_session_index((transport_id, current_our_index.as_u32()), peer_addr),
        None
    );
    assert_eq!(
        registry.insert_session_index((transport_id, rekey_our_index.as_u32()), peer_addr),
        None
    );

    let removed = registry
        .remove_with_session_indices(&peer_addr)
        .expect("active peer teardown should return the removed peer plus session indices");
    assert_eq!(removed.peer.node_addr(), &peer_addr);
    assert_eq!(
        removed.session_indices,
        vec![
            PeerSessionIndex {
                kind: PeerSessionIndexKind::Current,
                key: (transport_id, current_our_index.as_u32()),
                index: current_our_index,
            },
            PeerSessionIndex {
                kind: PeerSessionIndexKind::Rekey,
                key: (transport_id, rekey_our_index.as_u32()),
                index: rekey_our_index,
            },
        ],
        "peer lifecycle teardown must own which active-peer session indices need deregister/free"
    );
    assert!(
        registry.get(&peer_addr).is_none(),
        "teardown removal must remove active peer storage"
    );
}

#[test]
fn peer_lifecycle_registry_owns_connection_and_active_peer_storage() {
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();

    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(77);
    let session_key = (transport_id, 10);

    let mut registry = PeerLifecycleRegistry::default();
    let connection = PeerConnection::outbound(link_id, peer_identity.clone(), 1_000);

    assert!(registry.insert_connection(link_id, connection).is_none());
    assert_eq!(registry.connection_len(), 1);
    assert!(registry.contains_connection(&link_id));
    assert_eq!(
        registry
            .get_connection(&link_id)
            .and_then(|conn: &PeerConnection| conn.expected_identity())
            .map(|identity: &PeerIdentity| identity.node_addr()),
        Some(&peer_addr)
    );

    assert!(
        registry
            .insert(peer_addr, ActivePeer::new(peer_identity, link_id, 2_000))
            .is_none()
    );
    assert_eq!(registry.len(), 1);
    assert!(registry.contains_key(&peer_addr));
    assert_eq!(registry.insert_session_index(session_key, peer_addr), None);
    assert_eq!(registry.lookup_session_index(session_key), Some(peer_addr));

    let removed_connection = registry
        .remove_connection(&link_id)
        .expect("pending connection storage should live in the lifecycle owner");
    assert_eq!(removed_connection.link_id(), link_id);
    assert!(
        registry.get(&peer_addr).is_some(),
        "active peer storage must survive pending-connection teardown"
    );
    assert_eq!(registry.lookup_session_index(session_key), Some(peer_addr));

    let removed_peer = registry
        .remove(&peer_addr)
        .expect("active peer storage should live in the lifecycle owner");
    assert_eq!(removed_peer.node_addr(), &peer_addr);
    assert!(registry.connection_is_empty());
    assert!(registry.is_empty());
}

#[test]
fn session_registry_owns_endpoint_session_storage_and_worker_registration_mirror() {
    use crate::node::session::{EndToEndState, SessionEntry};

    let local = Identity::generate();
    let peer = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let session_key = crate::node::decrypt_worker::DecryptSessionKey::new(TransportId::new(1), 10);
    let other_key = crate::node::decrypt_worker::DecryptSessionKey::new(TransportId::new(2), 10);

    let mut registry = SessionRegistry::default();
    let first = SessionEntry::new(
        peer_addr,
        peer.pubkey_full(),
        EndToEndState::Established(make_test_fmp_session(&local, &peer, [0x01; 8], [0x02; 8])),
        1_000,
        true,
    );
    assert!(registry.insert(peer_addr, first).is_none());
    assert_eq!(registry.len(), 1);
    assert!(registry.contains_key(&peer_addr));
    assert_eq!(
        registry.get(&peer_addr).map(SessionEntry::remote_pubkey),
        Some(&peer.pubkey_full())
    );
    assert!(
        !registry.record_worker_registration(session_key, false),
        "a rejected worker registration must not mark the session worker-owned"
    );
    assert!(!registry.is_worker_registered(&session_key));
    assert!(!registry.unregister_worker_session_if_registered(&session_key));

    assert!(registry.record_worker_registration(session_key, true));
    assert!(registry.is_worker_registered(&session_key));
    assert!(!registry.is_worker_registered(&other_key));

    let replacement = SessionEntry::new(
        peer_addr,
        peer.pubkey_full(),
        EndToEndState::Established(make_test_fmp_session(&local, &peer, [0x03; 8], [0x04; 8])),
        2_000,
        true,
    );
    let replaced = registry
        .insert(peer_addr, replacement)
        .expect("session replacement should return the previous entry");
    assert_eq!(replaced.remote_pubkey(), &peer.pubkey_full());
    registry
        .get_mut(&peer_addr)
        .expect("mutable access should stay behind the same owner")
        .record_sent(123);

    assert_eq!(
        registry
            .iter()
            .map(|(addr, entry)| (*addr, entry.remote_pubkey()))
            .collect::<Vec<_>>(),
        vec![(peer_addr, &peer.pubkey_full())]
    );

    let removed = registry
        .remove(&peer_addr)
        .expect("session storage should live in the session owner");
    assert_eq!(removed.remote_pubkey(), &peer.pubkey_full());
    assert!(
        registry.unregister_worker_session_if_registered(&session_key),
        "worker registration mirror should be cleaned through the session owner"
    );
    assert!(!registry.is_worker_registered(&session_key));
    assert!(!registry.contains_key(&peer_addr));
    assert!(registry.is_empty());
    assert!(registry.worker_registration_is_empty());
}

#[test]
fn session_registry_owns_fsp_send_bookkeeping() {
    use crate::node::session::{EndToEndState, SessionEntry};

    let local = Identity::generate();
    let peer = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let next_hop = make_node_addr(77);

    let mut registry = SessionRegistry::default();
    let mut entry = SessionEntry::new(
        peer_addr,
        peer.pubkey_full(),
        EndToEndState::Established(make_test_fmp_session(&local, &peer, [0x01; 8], [0x02; 8])),
        1_000,
        true,
    );
    entry.init_mmp(&crate::config::SessionMmpConfig::default());
    assert!(registry.insert(peer_addr, entry).is_none());

    let data_update =
        FspSendBookkeepingInput::data(123, 7, 1_234, 256, 2_000).with_next_hop(next_hop);
    let data_result = registry
        .record_fsp_send_bookkeeping(&peer_addr, data_update)
        .expect("FSP data send bookkeeping should find session entry");
    assert!(data_result.data_recorded);
    assert!(data_result.mmp_recorded);
    assert!(data_result.touched);
    assert!(data_result.next_hop_recorded);

    let entry = registry
        .get(&peer_addr)
        .expect("send bookkeeping must keep session storage");
    assert_eq!(entry.traffic_counters(), (1, 0, 123, 0));
    assert_eq!(entry.last_activity(), 2_000);
    assert_eq!(entry.last_outbound_next_hop(), Some(next_hop));
    let mmp = entry.mmp().expect("session should have MMP state");
    assert_eq!(mmp.sender.cumulative_packets_sent(), 1);
    assert_eq!(mmp.sender.cumulative_bytes_sent(), 256);

    let control_result = registry
        .record_fsp_send_bookkeeping(&peer_addr, FspSendBookkeepingInput::control(8, 1_300, 64))
        .expect("FSP control send bookkeeping should find session entry");
    assert!(!control_result.data_recorded);
    assert!(control_result.mmp_recorded);
    assert!(!control_result.touched);
    assert!(!control_result.next_hop_recorded);
    let entry = registry
        .get(&peer_addr)
        .expect("control bookkeeping must keep session storage");
    assert_eq!(
        entry.traffic_counters(),
        (1, 0, 123, 0),
        "control/MMP bookkeeping must not inflate data counters"
    );
    assert_eq!(
        entry.last_activity(),
        2_000,
        "control/MMP bookkeeping must not reset idle activity"
    );
    let mmp = entry.mmp().expect("session should have MMP state");
    assert_eq!(mmp.sender.cumulative_packets_sent(), 2);
    assert_eq!(mmp.sender.cumulative_bytes_sent(), 320);

    let legacy_full = Identity::generate();
    let legacy_identity = PeerIdentity::from_pubkey_full(legacy_full.pubkey_full());
    let legacy_addr = *legacy_identity.node_addr();
    let legacy_entry = SessionEntry::new(
        legacy_addr,
        legacy_full.pubkey_full(),
        EndToEndState::Established(make_test_fmp_session(
            &local,
            &legacy_full,
            [0x03; 8],
            [0x04; 8],
        )),
        3_000,
        true,
    );
    assert!(registry.insert(legacy_addr, legacy_entry).is_none());
    let legacy_result = registry
        .record_fsp_send_bookkeeping(
            &legacy_addr,
            FspSendBookkeepingInput::data(10, 9, 1_400, 32, 4_000),
        )
        .expect("legacy session without MMP should still record data bookkeeping");
    assert!(legacy_result.data_recorded);
    assert!(!legacy_result.mmp_recorded);
    assert!(legacy_result.touched);
    let entry = registry
        .get(&legacy_addr)
        .expect("legacy bookkeeping must keep session storage");
    assert_eq!(entry.traffic_counters(), (1, 0, 10, 0));
    assert_eq!(entry.last_activity(), 4_000);

    assert!(
        registry
            .record_fsp_send_bookkeeping(
                &make_node_addr(99),
                FspSendBookkeepingInput::control(10, 1_500, 48),
            )
            .is_none(),
        "missing sessions should not record FSP send bookkeeping"
    );
}

#[cfg(unix)]
#[test]
fn session_registry_owns_endpoint_fsp_worker_reservation_and_path_mtu_seed() {
    use crate::node::session::{EndToEndState, SessionEntry};
    use ring::aead::Aad;

    let local = Identity::generate();
    let peer = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let (send_session, mut recv_session) =
        make_test_fmp_session_pair(&local, &peer, [0x01; 8], [0x02; 8]);

    let mut registry = SessionRegistry::default();
    let mut entry = SessionEntry::new(
        peer_addr,
        peer.pubkey_full(),
        EndToEndState::Established(send_session),
        1_000,
        true,
    );
    entry.init_mmp(&crate::config::SessionMmpConfig::default());
    assert_eq!(
        entry.mmp().expect("MMP initialized").path_mtu.current_mtu(),
        u16::MAX
    );
    assert!(registry.insert(peer_addr, entry).is_none());

    let plaintext = b"endpoint-fsp-worker-frame";
    let input = FspWorkerSendReservationInput {
        flags: crate::node::session_wire::FSP_FLAG_K,
        payload_len: plaintext.len() as u16,
        path_mtu: 1_280,
    };
    let reservation = registry
        .reserve_endpoint_data_fsp_worker_send(&peer_addr, input)
        .expect("session registry should own established FSP worker reservation")
        .expect("established session should expose a worker cipher");

    assert_eq!(reservation.counter, 0);
    assert_eq!(
        reservation.header,
        crate::node::session_wire::build_fsp_header(
            reservation.counter,
            input.flags,
            input.payload_len,
        )
    );
    let entry = registry
        .get(&peer_addr)
        .expect("reservation must keep session storage");
    assert_eq!(
        entry.send_counter(),
        1,
        "reservation should consume exactly one FSP counter"
    );
    assert_eq!(
        entry
            .mmp()
            .expect("MMP should remain initialized")
            .path_mtu
            .current_mtu(),
        input.path_mtu,
        "endpoint-data FSP reservation should seed source path MTU"
    );

    let mut ciphertext = plaintext.to_vec();
    reservation
        .cipher
        .seal_in_place_append_tag(
            crate::noise::CipherState::counter_to_nonce(reservation.counter),
            Aad::from(&reservation.header),
            &mut ciphertext,
        )
        .expect("worker-style FSP seal should succeed");
    assert_eq!(
        recv_session
            .decrypt_with_replay_check_and_aad(
                &ciphertext,
                reservation.counter,
                &reservation.header,
            )
            .expect("receiver should accept worker-sealed FSP frame"),
        plaintext
    );

    assert!(
        matches!(
            registry.reserve_endpoint_data_fsp_worker_send(&make_node_addr(99), input),
            Err(FspWorkerSendReservationError::MissingSession)
        ),
        "missing sessions should fail before reservation"
    );

    let pending_peer = Identity::generate();
    let pending_identity = PeerIdentity::from_pubkey_full(pending_peer.pubkey_full());
    let pending_addr = *pending_identity.node_addr();
    let pending_entry = SessionEntry::new(
        pending_addr,
        pending_peer.pubkey_full(),
        EndToEndState::Initiating(crate::noise::HandshakeState::new_initiator(
            local.keypair(),
            pending_peer.pubkey_full(),
        )),
        2_000,
        true,
    );
    assert!(registry.insert(pending_addr, pending_entry).is_none());
    assert!(
        matches!(
            registry.reserve_endpoint_data_fsp_worker_send(&pending_addr, input),
            Err(FspWorkerSendReservationError::NotEstablished)
        ),
        "non-established sessions should fail before counter reservation"
    );
    assert_eq!(
        registry
            .get(&pending_addr)
            .expect("pending session remains stored")
            .send_counter(),
        0,
        "non-established reservation failure must not consume a counter"
    );
}

#[test]
fn decrypt_session_registrations_own_worker_acceptance_and_unregister_gate() {
    let session_key = crate::node::decrypt_worker::DecryptSessionKey::new(TransportId::new(1), 10);
    let other_key = crate::node::decrypt_worker::DecryptSessionKey::new(TransportId::new(2), 10);
    let mut registrations = DecryptSessionRegistrations::default();

    assert!(!registrations.record_worker_registration(session_key, false));
    assert!(
        !registrations.is_registered(&session_key),
        "a full worker queue must not make rx-loop dispatch to an unregistered shard"
    );
    assert!(
        !registrations.unregister_if_registered(&session_key),
        "worker unregister should be skipped when local registration never succeeded"
    );

    assert!(registrations.record_worker_registration(session_key, true));
    assert!(registrations.is_registered(&session_key));
    assert!(!registrations.is_registered(&other_key));

    assert!(registrations.unregister_if_registered(&session_key));
    assert!(!registrations.is_registered(&session_key));
    assert!(registrations.is_empty());
}

#[test]
fn configured_peer_send_weights_own_identity_parse_and_default_policy() {
    let configured = Identity::generate();
    let configured_npub = configured.npub();
    let configured_addr = *PeerIdentity::from_npub(&configured_npub)
        .expect("configured peer identity")
        .node_addr();
    let unknown_addr =
        *PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full()).node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        configured_npub,
        "udp",
        "127.0.0.1:1",
    ));
    config.peers.push(crate::config::PeerConfig::new(
        "not-a-valid-peer-id",
        "udp",
        "127.0.0.1:2",
    ));

    let weights = ConfiguredPeerSendWeights::from_config(&config);

    assert_eq!(
        weights.weight_for(&configured_addr),
        encrypt_worker::EXPLICIT_PEER_SEND_WEIGHT,
        "configured peers reserve the explicit send-scheduling lane"
    );
    assert_eq!(
        weights.weight_for(&unknown_addr),
        encrypt_worker::DEFAULT_SEND_WEIGHT,
        "unconfigured peers must stay on the default send-scheduling lane"
    );
    assert_eq!(
        weights.len(),
        1,
        "invalid peer identities must not create phantom scheduling policy"
    );
}

#[test]
fn link_address_index_owns_lookup_replace_and_stale_safe_remove() {
    let transport_id = TransportId::new(1);
    let addr = TransportAddr::from_string("127.0.0.1:7000");
    let key = (transport_id, addr.clone());
    let first_link = LinkId::new(10);
    let winning_link = LinkId::new(11);

    let mut index = LinkAddressIndex::default();

    assert_eq!(index.insert(key.clone(), first_link), None);
    assert_eq!(index.lookup(transport_id, &addr), Some(first_link));

    assert_eq!(
        index.insert(key.clone(), winning_link),
        Some(first_link),
        "replacement must report the stale owner for cross-connection cleanup"
    );
    assert!(
        !index.remove_if_points_to(&key, &first_link),
        "stale loser cleanup must not delete a newer winner's route entry"
    );
    assert_eq!(index.lookup(transport_id, &addr), Some(winning_link));

    assert!(index.remove_if_points_to(&key, &winning_link));
    assert_eq!(index.lookup(transport_id, &addr), None);
    assert!(index.is_empty());
}

#[test]
fn link_registry_owns_storage_address_index_and_stale_safe_cleanup() {
    let transport_id = TransportId::new(1);
    let addr = TransportAddr::from_string("127.0.0.1:7000");
    let first_link_id = LinkId::new(10);
    let winning_link_id = LinkId::new(11);
    let first_link = Link::connectionless(
        first_link_id,
        transport_id,
        addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    let winning_link = Link::connectionless(
        winning_link_id,
        transport_id,
        addr.clone(),
        LinkDirection::Inbound,
        Duration::from_millis(100),
    );

    let mut registry = LinkRegistry::default();

    assert!(registry.insert(first_link_id, first_link).is_none());
    assert_eq!(
        registry.get(&first_link_id).map(Link::link_id),
        Some(first_link_id)
    );
    assert_eq!(
        registry.lookup_addr(transport_id, &addr),
        Some(first_link_id)
    );

    assert!(registry.insert(winning_link_id, winning_link).is_none());
    assert_eq!(
        registry.lookup_addr(transport_id, &addr),
        Some(winning_link_id),
        "newer link for the same address must own receive dispatch"
    );

    let removed = registry.remove(&first_link_id).expect("remove stale loser");
    assert_eq!(removed.link_id(), first_link_id);
    assert_eq!(
        registry.lookup_addr(transport_id, &addr),
        Some(winning_link_id),
        "removing a stale loser must not delete the winner's address mapping"
    );

    let removed = registry.remove(&winning_link_id).expect("remove winner");
    assert_eq!(removed.link_id(), winning_link_id);
    assert_eq!(registry.lookup_addr(transport_id, &addr), None);
    assert!(registry.is_empty());
}

#[tokio::test]
async fn test_node_rx_loop_requires_start() {
    let mut node = make_node();

    // RX loop should fail if node not started (no packet_rx)
    let result = node.run_rx_loop().await;
    assert!(matches!(result, Err(NodeError::NotStarted)));
}

#[tokio::test]
async fn test_node_rx_loop_takes_channel() {
    let mut node = make_node();
    node.start().await.unwrap();

    // packet_rx should be available after start
    assert!(node.packet_rx.is_some());

    // After run_rx_loop takes ownership, it should be None
    // We can't actually run the loop (it blocks), but we can test the take
    let rx = node.packet_rx.take();
    assert!(rx.is_some());
    assert!(node.packet_rx.is_none());

    node.stop().await.unwrap();
}

#[test]
fn test_rate_limiter_initialized() {
    let mut node = make_node();

    // Rate limiter should allow handshakes initially
    assert!(node.msg1_rate_limiter.can_start_handshake());

    // Start a handshake
    assert!(node.msg1_rate_limiter.start_handshake());
    assert_eq!(node.msg1_rate_limiter.pending_count(), 1);

    // Complete it
    node.msg1_rate_limiter.complete_handshake();
    assert_eq!(node.msg1_rate_limiter.pending_count(), 0);
}

// === Promotion / Retry Tests ===

/// Test that promoting a connection cleans up a pending outbound to the same peer.
///
/// Simulates the scenario where node A has a pending outbound handshake to B
/// (unanswered because B wasn't running), then B starts and initiates to A.
/// When A promotes B's inbound connection, it should immediately clean up the
/// stale pending outbound rather than waiting for the 30s timeout.
#[test]
fn test_promote_cleans_up_pending_outbound_to_same_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Generate peer B's identity (shared between the two connections)
    let peer_b_full = Identity::generate();
    let peer_b_identity = PeerIdentity::from_pubkey_full(peer_b_full.pubkey_full());
    let peer_b_node_addr = *peer_b_identity.node_addr();

    // --- Set up the pending outbound to B (link_id 1) ---
    // This simulates A having sent msg1 to B before B was running.
    let pending_link_id = LinkId::new(1);
    let pending_time_ms = 1000;
    let mut pending_conn =
        PeerConnection::outbound(pending_link_id, peer_b_identity, pending_time_ms);

    let our_keypair = node.identity.keypair();
    let _msg1 = pending_conn
        .start_handshake(our_keypair, node.startup_epoch, pending_time_ms)
        .unwrap();

    let pending_index = node.index_allocator.allocate().unwrap();
    pending_conn.set_our_index(pending_index);
    pending_conn.set_transport_id(transport_id);
    let pending_addr = TransportAddr::from_string("10.0.0.2:2121");
    pending_conn.set_source_addr(pending_addr.clone());

    let pending_link = Link::connectionless(
        pending_link_id,
        transport_id,
        pending_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node.links.insert(pending_link_id, pending_link);
    node.links
        .insert_addr((transport_id, pending_addr.clone()), pending_link_id);
    node.peers.insert_connection(pending_link_id, pending_conn);
    node.pending_outbound
        .insert((transport_id, pending_index.as_u32()), pending_link_id);

    // Verify pending state
    assert_eq!(node.connection_count(), 1);
    assert_eq!(node.link_count(), 1);
    assert_eq!(node.index_allocator.count(), 1);

    // --- Set up the completing inbound from B (link_id 2) ---
    // Simulate B's outbound arriving at A and completing the handshake.
    // We use make_completed_connection's pattern but with B's known identity.
    let completing_link_id = LinkId::new(2);
    let completing_time_ms = 2000;

    let mut completing_conn =
        PeerConnection::outbound(completing_link_id, peer_b_identity, completing_time_ms);

    let our_keypair = node.identity.keypair();
    let msg1 = completing_conn
        .start_handshake(our_keypair, node.startup_epoch, completing_time_ms)
        .unwrap();

    // B responds
    let mut resp_conn = PeerConnection::inbound(LinkId::new(999), completing_time_ms);
    let peer_keypair = peer_b_full.keypair();
    let mut resp_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut resp_epoch);
    let msg2 = resp_conn
        .receive_handshake_init(peer_keypair, resp_epoch, &msg1, completing_time_ms)
        .unwrap();

    completing_conn
        .complete_handshake(&msg2, completing_time_ms)
        .unwrap();

    let completing_index = node.index_allocator.allocate().unwrap();
    completing_conn.set_our_index(completing_index);
    completing_conn.set_their_index(SessionIndex::new(99));
    completing_conn.set_transport_id(transport_id);
    completing_conn.set_source_addr(TransportAddr::from_string("10.0.0.2:4001"));

    node.add_connection(completing_conn).unwrap();

    // Now 2 connections, 1 link (pending has link, completing doesn't yet need one for this test)
    assert_eq!(node.connection_count(), 2);
    assert_eq!(node.index_allocator.count(), 2);

    // --- Promote the completing connection ---
    let result = node
        .promote_connection(completing_link_id, peer_b_identity, completing_time_ms)
        .unwrap();

    assert!(matches!(result, PromotionResult::Promoted(_)));

    // The pending outbound should NOT be cleaned up during promotion —
    // it's deferred so handle_msg2 can learn the peer's inbound index.
    assert_eq!(
        node.connection_count(),
        1,
        "Pending outbound should be preserved (deferred cleanup)"
    );
    assert_eq!(node.peer_count(), 1, "Promoted peer should exist");
    assert!(
        node.pending_outbound
            .contains_key(&(transport_id, pending_index.as_u32())),
        "pending_outbound entry should still exist (awaiting msg2)"
    );
    assert_eq!(
        node.index_allocator.count(),
        2,
        "Both indices should remain until msg2 cleanup"
    );

    // Verify the promoted peer is correct
    let peer = node.get_peer(&peer_b_node_addr).unwrap();
    assert_eq!(peer.link_id(), completing_link_id);
}

/// Test that schedule_retry creates a retry entry for auto-connect peers.
#[test]
fn test_schedule_retry_creates_entry() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    assert!(node.retry_pending.is_empty());

    node.schedule_retry(peer_node_addr, 1000);

    assert_eq!(node.retry_pending.len(), 1);
    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert_eq!(state.retry_count, 1);
    assert!(
        state.reconnect,
        "auto-connect peers default to unlimited auto-reconnect"
    );
    // Default base = 5s, 2^1 = 10s, but first retry is 2^0... let me check:
    // retry_count is set to 1, backoff_ms(5000) = 5000 * 2^1 = 10000
    assert_eq!(state.retry_after_ms, 1000 + 10_000);
}

/// Test that schedule_retry increments on subsequent calls.
#[test]
fn test_schedule_retry_increments() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    // First failure
    node.schedule_retry(peer_node_addr, 1000);
    assert_eq!(
        node.retry_pending.get(&peer_node_addr).unwrap().retry_count,
        1
    );

    // Second failure
    node.schedule_retry(peer_node_addr, 11_000);
    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert_eq!(state.retry_count, 2);
    // backoff_ms(5000) with retry_count=2 = 5000 * 4 = 20000
    assert_eq!(state.retry_after_ms, 11_000 + 20_000);
}

#[test]
fn test_local_route_transport_error_is_classified() {
    let error =
        crate::transport::TransportError::SendFailed("No route to host (os error 65)".to_string());

    let node_error = NodeError::from_transport_error(error);
    assert!(matches!(node_error, NodeError::LocalRouteUnavailable(_)));
}

#[test]
fn test_schedule_local_route_retry_does_not_increase_backoff() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    node.schedule_retry(peer_node_addr, 1_000);
    {
        let state = node.retry_pending.get(&peer_node_addr).unwrap();
        assert_eq!(state.retry_count, 1);
        assert_eq!(state.retry_after_ms, 11_000);
    }

    node.schedule_local_route_retry(peer_node_addr, 2_000);

    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert_eq!(
        state.retry_count, 1,
        "local route outages must not count as peer failures"
    );
    assert_eq!(
        state.retry_after_ms, 4_000,
        "route recovery should be retried quickly instead of waiting on prior backoff"
    );
    assert!(state.reconnect);
}

/// Retry processing is paced so a large due set cannot start every
/// handshake candidate in one maintenance tick.
#[tokio::test]
async fn test_process_pending_retries_is_budgeted_per_tick() {
    let mut node = make_node();
    let mut addrs = Vec::new();

    for _ in 0..20 {
        let identity = Identity::generate();
        let npub = identity.npub();
        let peer_identity = PeerIdentity::from_npub(&npub).unwrap();
        let node_addr = *peer_identity.node_addr();
        node.retry_pending.insert(
            node_addr,
            crate::node::retry::RetryState {
                peer_config: crate::config::PeerConfig::new(npub, "udp", "10.0.0.2:2121"),
                retry_count: 0,
                retry_after_ms: 0,
                reconnect: true,
                expires_at_ms: None,
            },
        );
        addrs.push(node_addr);
    }

    node.process_pending_retries(1).await;

    let processed = addrs
        .iter()
        .filter(|addr| {
            node.retry_pending
                .get(addr)
                .is_some_and(|state| state.retry_count > 0)
        })
        .count();
    let deferred = addrs.len().saturating_sub(processed);

    assert_eq!(processed, 16);
    assert_eq!(deferred, 4);
    assert_eq!(node.retry_pending.len(), 20);
}

#[tokio::test]
async fn active_direct_refresh_retries_are_background_budgeted() {
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    let mut node = Node::new(config).unwrap();
    node.nostr_discovery = Some(Arc::new(NostrDiscovery::new_for_test()));
    let mut addrs = Vec::new();

    for _ in 0..6 {
        let identity = Identity::generate();
        let npub = identity.npub();
        let peer_identity = PeerIdentity::from_npub(&npub).unwrap();
        let node_addr = *peer_identity.node_addr();
        let peer_config = crate::config::PeerConfig {
            npub,
            alias: None,
            addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
            connect_policy: crate::config::ConnectPolicy::AutoConnect,
            auto_reconnect: true,
            discovery_fallback_transit: true,
        };
        node.config.peers.push(peer_config.clone());
        node.peers
            .insert(node_addr, ActivePeer::new(peer_identity, LinkId::new(7), 0));
        node.retry_pending.insert(
            node_addr,
            crate::node::retry::RetryState {
                peer_config,
                retry_count: 0,
                retry_after_ms: 0,
                reconnect: true,
                expires_at_ms: None,
            },
        );
        addrs.push(node_addr);
    }

    node.process_pending_retries(1_000).await;

    let processed = addrs
        .iter()
        .filter(|addr| {
            node.retry_pending
                .get(addr)
                .is_some_and(|state| state.retry_after_ms > 1_000)
        })
        .count();

    assert_eq!(
        processed, 2,
        "active direct refresh retries should be paced as background probes"
    );
    assert!(addrs.iter().all(|addr| {
        node.retry_pending
            .get(addr)
            .is_some_and(|state| state.retry_count == 0)
    }));
    assert_eq!(node.retry_pending.len(), 6);
}

/// Test that auto-connect peers with auto-reconnect enabled retry indefinitely
/// (never exhaust).
#[test]
fn test_schedule_retry_auto_reconnect_never_exhausts() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.node.retry.max_retries = 2;
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    // All attempts should keep the entry alive despite max_retries=2.
    node.schedule_retry(peer_node_addr, 1000);
    assert!(node.retry_pending.contains_key(&peer_node_addr));

    node.schedule_retry(peer_node_addr, 2000);
    assert!(node.retry_pending.contains_key(&peer_node_addr));

    // Attempt 3 would have exhausted before, but now retries indefinitely
    node.schedule_retry(peer_node_addr, 3000);
    assert!(
        node.retry_pending.contains_key(&peer_node_addr),
        "Auto-connect peers should never exhaust retries"
    );
    assert_eq!(
        node.retry_pending.get(&peer_node_addr).unwrap().retry_count,
        3
    );
}

/// Test that auto-connect peers with auto-reconnect disabled remain bounded.
#[test]
fn test_schedule_retry_auto_connect_without_auto_reconnect_exhausts() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut peer_config = crate::config::PeerConfig::new(peer_npub, "udp", "10.0.0.2:2121");
    peer_config.auto_reconnect = false;

    let mut config = Config::new();
    config.node.retry.max_retries = 2;
    config.peers.push(peer_config);

    let mut node = Node::new(config).unwrap();

    node.schedule_retry(peer_node_addr, 1000);
    {
        let state = node.retry_pending.get(&peer_node_addr).unwrap();
        assert_eq!(state.retry_count, 1);
        assert!(
            !state.reconnect,
            "auto_reconnect=false should keep failed-handshake retries bounded"
        );
    }

    node.schedule_retry(peer_node_addr, 2000);
    assert!(node.retry_pending.contains_key(&peer_node_addr));

    node.schedule_retry(peer_node_addr, 3000);
    assert!(
        !node.retry_pending.contains_key(&peer_node_addr),
        "finite auto-connect retries should exhaust at max_retries"
    );
}

/// Test that schedule_retry does nothing when max_retries is 0.
#[test]
fn test_schedule_retry_disabled() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.node.retry.max_retries = 0;
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    node.schedule_retry(peer_node_addr, 1000);
    assert!(
        node.retry_pending.is_empty(),
        "No retry should be scheduled when max_retries=0"
    );
}

/// Test that schedule_retry does nothing for non-auto-connect peers.
#[test]
fn test_schedule_retry_ignores_non_autoconnect() {
    let peer_identity = Identity::generate();
    let peer_node_addr = *peer_identity.node_addr();

    // No peers configured at all
    let mut node = make_node();

    node.schedule_retry(peer_node_addr, 1000);
    assert!(
        node.retry_pending.is_empty(),
        "No retry for unconfigured peer"
    );
}

/// Test that schedule_retry does nothing if peer is already connected.
#[test]
fn test_schedule_retry_skips_connected_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Promote a peer so it's in the peers map
    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();
    assert_eq!(node.peer_count(), 1);

    // Scheduling a retry for an already-connected peer should be a no-op
    node.schedule_retry(node_addr, 3000);
    assert!(
        node.retry_pending.is_empty(),
        "No retry for already-connected peer"
    );
}

#[test]
fn test_schedule_retry_keeps_connected_bootstrap_peer_refreshable() {
    let peer_full = Identity::generate();
    let peer_npub = peer_full.npub();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "127.0.0.1:9",
    ));
    let mut node = Node::new(config).unwrap();

    let bootstrap_id = TransportId::new(99);
    node.bootstrap_transports.mark(bootstrap_id);
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), 1_000);
    active_peer.set_current_addr(bootstrap_id, &TransportAddr::from_string("127.0.0.1:9"));
    node.peers.insert(peer_node_addr, active_peer);

    node.schedule_retry(peer_node_addr, 3_000);

    assert!(
        node.retry_pending.contains_key(&peer_node_addr),
        "bootstrap/fallback paths should not permanently suppress direct refresh retries"
    );
}

#[test]
fn test_schedule_retry_active_fallback_uses_quick_direct_reprobe() {
    let peer_full = Identity::generate();
    let peer_npub = peer_full.npub();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();

    let peer_config = crate::config::PeerConfig {
        npub: peer_npub,
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).unwrap();

    let bootstrap_id = TransportId::new(99);
    node.bootstrap_transports.mark(bootstrap_id);
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), 1_000);
    active_peer.set_current_addr(bootstrap_id, &TransportAddr::from_string("127.0.0.1:9"));
    node.peers.insert(peer_node_addr, active_peer);

    let mut state = super::super::retry::RetryState::new(peer_config);
    state.retry_count = 8;
    state.retry_after_ms = 120_000;
    state.reconnect = true;
    node.retry_pending.insert(peer_node_addr, state);

    node.schedule_retry(peer_node_addr, 3_000);

    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert_eq!(
        state.retry_count, 0,
        "active fallback direct refresh must not inherit peer-level exponential backoff"
    );
    assert!(
        (5_000..=10_000).contains(&state.retry_after_ms),
        "active fallback direct refresh should use a quick jittered reprobe, got {}",
        state.retry_after_ms
    );
}

#[tokio::test]
async fn test_try_peer_addresses_skips_connected_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let (conn, peer_identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_config = crate::config::PeerConfig::new(peer_identity.npub(), "udp", "127.0.0.1:9");

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, peer_identity, 2000)
        .unwrap();
    let link_count = node.link_count();
    let connection_count = node.connection_count();

    node.try_peer_addresses(&peer_config, peer_identity, true)
        .await
        .unwrap();

    assert_eq!(
        node.link_count(),
        link_count,
        "stale retry/traversal fallback must not create a duplicate link"
    );
    assert_eq!(
        node.connection_count(),
        connection_count,
        "stale retry/traversal fallback must not create a duplicate handshake"
    );
}

#[tokio::test]
async fn test_try_peer_addresses_skips_connecting_peer() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer_identity = make_peer_identity();
    let peer_config = crate::config::PeerConfig::new(peer_identity.npub(), "udp", "127.0.0.1:9");
    let mut pending = PeerConnection::outbound(LinkId::new(1), peer_identity, 1000);
    pending.set_transport_id(transport_id);
    pending.set_source_addr(TransportAddr::from_string("127.0.0.1:9"));
    node.add_connection(pending).unwrap();

    node.try_peer_addresses(&peer_config, peer_identity, true)
        .await
        .unwrap();

    assert_eq!(
        node.connection_count(),
        1,
        "stale retry/traversal fallback must not start a second handshake"
    );
    assert_eq!(
        node.link_count(),
        0,
        "stale retry/traversal fallback must not allocate a link for the duplicate path"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_nostr_traversal_failure_skips_connected_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let now_ms = Node::now_ms();
    let (conn, peer_identity) = make_completed_connection(&mut node, link_id, transport_id, now_ms);
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, peer_identity, now_ms)
        .unwrap();
    let peer_addr = *peer_identity.node_addr();
    let current_addr = node
        .peers
        .get(&peer_addr)
        .and_then(|peer| peer.current_addr().cloned())
        .expect("promoted test peer has a current address");
    node.peers
        .get_mut(&peer_addr)
        .expect("promoted test peer")
        .touch(Node::now_ms());

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    bootstrap.push_event_for_test(BootstrapEvent::Failed {
        peer_config: crate::config::PeerConfig::new(
            peer_identity.npub(),
            "udp",
            current_addr.to_string(),
        ),
        reason: "stale traversal failure".to_string(),
    });
    node.nostr_discovery = Some(bootstrap.clone());

    node.poll_nostr_discovery().await;

    assert!(
        bootstrap.failure_state_snapshot().is_empty(),
        "stale failures for connected peers must not affect traversal cooldown"
    );
    assert!(
        node.retry_pending.is_empty(),
        "stale failures for connected peers must not enqueue reconnect attempts"
    );
}

#[tokio::test]
async fn process_packet_ignores_punch_and_non_fmp_noise_for_bootstrap_cooldown() {
    let mut node = make_node();
    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let transport_id = TransportId::new(44);
    let peer = Identity::generate();
    let peer_npub = peer.npub();

    node.nostr_discovery = Some(bootstrap.clone());
    node.bootstrap_transports
        .register(transport_id, peer_npub.clone());

    let remote = crate::transport::TransportAddr::from_string("127.0.0.1:9");
    let mut punch = vec![0u8; 24];
    punch[..4].copy_from_slice(&crate::discovery::PUNCH_MAGIC.to_be_bytes());
    node.process_packet(ReceivedPacket::new(transport_id, remote.clone(), punch))
        .await;

    node.process_packet(ReceivedPacket::new(
        transport_id,
        remote.clone(),
        vec![0x45, 0x00, 0x00, 0x00],
    ))
    .await;

    assert!(
        bootstrap.failure_state_snapshot().is_empty(),
        "stray punch/IPv4-looking datagrams must not poison bootstrap cooldown"
    );

    node.process_packet(ReceivedPacket::new(
        transport_id,
        remote,
        vec![0x11, 0x00, 0x00, 0x00],
    ))
    .await;

    assert_eq!(
        bootstrap.failure_state_snapshot().len(),
        1,
        "a plausible FMP packet with a different version should still be treated as structural"
    );
}

#[tokio::test]
async fn test_process_pending_retries_drops_expired_entries() {
    let mut node = make_node();
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut state = super::super::retry::RetryState::new(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "127.0.0.1:9",
    ));
    state.retry_after_ms = 0;
    state.expires_at_ms = Some(1_000);
    state.reconnect = true;
    node.retry_pending.insert(peer_node_addr, state);

    node.process_pending_retries(1_000).await;

    assert!(
        !node.retry_pending.contains_key(&peer_node_addr),
        "expired retry entries should be dropped before retry processing"
    );
}

/// Test that schedule_reconnect preserves accumulated backoff across link-dead cycles.
///
/// Regression test for issue #5: previously `schedule_reconnect` always created a
/// fresh `RetryState` with `retry_count=0`, discarding any backoff accumulated by
/// prior failed handshake attempts. On repeated link-dead evictions the node would
/// restart exponential backoff from the base interval every time instead of
/// continuing to back off.
#[test]
fn test_schedule_reconnect_preserves_backoff() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    // Simulate two stale handshake timeouts incrementing the retry count.
    node.schedule_retry(peer_node_addr, 1_000); // count=1, delay=10s
    node.schedule_retry(peer_node_addr, 11_000); // count=2, delay=20s
    {
        let state = node.retry_pending.get(&peer_node_addr).unwrap();
        assert_eq!(state.retry_count, 2, "Two failures should yield count=2");
    }

    // Now simulate a link-dead removal triggering schedule_reconnect.
    // The existing retry entry (count=2) should be preserved and bumped to 3,
    // NOT reset to 0 as it was before the fix.
    node.schedule_reconnect(peer_node_addr, 31_000);

    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert!(state.reconnect, "Entry should be marked as reconnect");
    assert_eq!(
        state.retry_count, 3,
        "schedule_reconnect should increment existing count (was 2), not reset to 0 (regression: issue #5)"
    );

    // With count=3, backoff should be 5s * 2^3 = 40s.
    let base_ms = node.config.node.retry.base_interval_secs * 1000;
    let max_ms = node.config.node.retry.max_backoff_secs * 1000;
    let expected_delay = state.backoff_ms(base_ms, max_ms);
    assert_eq!(
        state.retry_after_ms,
        31_000 + expected_delay,
        "retry_after_ms should reflect count=3 backoff"
    );
}

/// Test that schedule_reconnect on a fresh peer (no prior retry entry) starts at count=0.
#[test]
fn test_schedule_reconnect_fresh_state() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    // No prior retry entry — first reconnect should use base delay.
    node.schedule_reconnect(peer_node_addr, 1_000);

    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert!(state.reconnect, "Entry should be marked as reconnect");
    assert_eq!(
        state.retry_count, 0,
        "Fresh reconnect should start at count=0"
    );
    // Base delay: 5s * 2^0 = 5s
    let base_ms = node.config.node.retry.base_interval_secs * 1000;
    let max_ms = node.config.node.retry.max_backoff_secs * 1000;
    let expected_delay = state.backoff_ms(base_ms, max_ms);
    assert_eq!(state.retry_after_ms, 1_000 + expected_delay);
}

#[test]
fn test_schedule_link_dead_reprobe_resets_backoff() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();
    node.schedule_retry(peer_node_addr, 1_000);
    node.schedule_retry(peer_node_addr, 11_000);
    assert_eq!(
        node.retry_pending.get(&peer_node_addr).unwrap().retry_count,
        2
    );

    node.schedule_link_dead_reprobe(peer_node_addr, 31_000);

    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert!(state.reconnect);
    assert_eq!(
        state.retry_count, 0,
        "link-dead direct paths should not preserve peer-level exponential backoff"
    );
    assert!(
        (33_000..=38_000).contains(&state.retry_after_ms),
        "link-dead should schedule a quick jittered direct re-probe, got {}",
        state.retry_after_ms
    );
}

#[tokio::test]
async fn active_direct_refresh_retries_process_oldest_due_peers_first() {
    let peers = (0..3)
        .map(|idx| {
            let identity = Identity::generate();
            let peer_config = crate::config::PeerConfig {
                npub: identity.npub(),
                alias: None,
                addresses: vec![crate::config::PeerAddress::with_priority(
                    "udp",
                    format!("127.0.0.1:{}", 31_000 + idx),
                    1,
                )],
                connect_policy: crate::config::ConnectPolicy::AutoConnect,
                auto_reconnect: true,
                discovery_fallback_transit: true,
            };
            (identity, peer_config)
        })
        .collect::<Vec<_>>();

    let mut config = Config::new();
    config.peers = peers.iter().map(|(_, peer)| peer.clone()).collect();
    let mut node = Node::new(config).unwrap();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let retry_times = [100, 200, 300];
    let peer_addrs = peers
        .iter()
        .zip(retry_times)
        .map(|((identity, peer_config), retry_after_ms)| {
            let peer_identity = PeerIdentity::from_npub(&peer_config.npub).unwrap();
            let node_addr = *peer_identity.node_addr();
            let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), 1_000);
            active_peer.set_current_addr(
                transport_id,
                &TransportAddr::from_string(&format!("127.0.0.1:{}", 32_000 + retry_after_ms)),
            );
            node.peers.insert(node_addr, active_peer);

            let mut retry = super::super::retry::RetryState::new(peer_config.clone());
            retry.retry_after_ms = retry_after_ms;
            retry.reconnect = true;
            node.retry_pending.insert(node_addr, retry);

            (node_addr, identity.npub(), retry_after_ms)
        })
        .collect::<Vec<_>>();

    node.process_pending_retries(1_000).await;

    for (node_addr, _npub, _retry_after_ms) in peer_addrs.iter().take(2) {
        let retry = node
            .retry_pending
            .get(node_addr)
            .expect("retry remains queued");
        assert!(
            retry.retry_after_ms > 1_000,
            "oldest active retry should be processed before newer due peers"
        );
    }
    let newest = node
        .retry_pending
        .get(&peer_addrs[2].0)
        .expect("newest retry remains queued");
    assert_eq!(
        newest.retry_after_ms, 300,
        "active retry cap should defer the newest due peer on the first tick"
    );

    node.process_pending_retries(2_000).await;

    let newest = node
        .retry_pending
        .get(&peer_addrs[2].0)
        .expect("newest retry remains queued after processing");
    assert!(
        newest.retry_after_ms > 2_000,
        "deferred active retry should become oldest and run on the next tick"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn link_dead_direct_path_initiates_fallback_lookup_without_peer_backoff() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority(
            "udp",
            "10.0.0.2:2121",
            1,
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let transit_identity = Identity::generate();
    let transit_peer = PeerIdentity::from_pubkey(transit_identity.pubkey());
    let transit_addr = *transit_peer.node_addr();

    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).unwrap();
    node.peers.insert(
        transit_addr,
        ActivePeer::new(transit_peer, LinkId::new(9), 0),
    );

    node.discovery_backoff.record_failure(&peer_addr);
    assert!(
        node.discovery_backoff.is_suppressed(&peer_addr),
        "fixture should start with stale discovery backoff"
    );

    node.schedule_link_dead_reprobe(peer_addr, 10_000);
    node.maybe_initiate_link_dead_fallback_lookup(&peer_addr)
        .await;

    let retry = node
        .retry_pending
        .get(&peer_addr)
        .expect("direct retry should stay queued");
    assert!(
        (12_000..=17_000).contains(&retry.retry_after_ms),
        "link-dead fallback lookup should preserve the quick jittered direct retry, got {}",
        retry.retry_after_ms
    );
    assert!(
        node.pending_lookups.contains_key(&peer_addr),
        "link-dead should immediately ask fallback peers for a route"
    );
    assert!(
        !node.discovery_backoff.is_suppressed(&peer_addr),
        "dead direct paths should not inherit stale peer discovery backoff"
    );
}

/// Test that a graceful Disconnect from an auto-connect peer schedules reconnect.
///
/// Regression test for issue #60: `handle_disconnect` previously called
/// `remove_active_peer` without `schedule_reconnect`, orphaning auto-connect
/// entries on a clean upstream shutdown. Other peer-removal paths (link-dead,
/// decrypt failure, peer restart) all schedule reconnect.
#[test]
fn test_disconnect_schedules_reconnect() {
    use crate::protocol::{Disconnect, DisconnectReason};

    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    let payload = Disconnect::new(DisconnectReason::Shutdown).encode();
    node.handle_disconnect(&peer_node_addr, &payload);

    let state = node
        .retry_pending
        .get(&peer_node_addr)
        .expect("handle_disconnect should schedule reconnect for auto-connect peer");
    assert!(state.reconnect, "Entry should be marked as reconnect");
    assert_eq!(
        state.retry_count, 0,
        "Fresh reconnect after disconnect should start at count=0"
    );
}

/// Test that promote_connection clears retry_pending.
#[test]
fn test_promote_clears_retry_pending() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();

    // Simulate a retry entry existing for this peer
    node.retry_pending.insert(
        node_addr,
        super::super::retry::RetryState::new(crate::config::PeerConfig::default()),
    );
    assert_eq!(node.retry_pending.len(), 1);

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();

    assert!(
        !node.retry_pending.contains_key(&node_addr),
        "retry_pending should be cleared on successful promotion"
    );
}

#[test]
fn test_promote_keeps_retry_pending_for_bootstrap_path() {
    let mut node = make_node();
    let bootstrap_id = TransportId::new(1);
    node.bootstrap_transports.mark(bootstrap_id);

    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, bootstrap_id, 1000);
    let node_addr = *identity.node_addr();
    let peer_config = crate::config::PeerConfig::new(identity.npub(), "udp", "127.0.0.1:5000");

    node.retry_pending
        .insert(node_addr, super::super::retry::RetryState::new(peer_config));

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();

    assert!(
        node.retry_pending.contains_key(&node_addr),
        "promotion over bootstrap/fallback transport should keep direct refresh retry state"
    );
}

/// Initial peer-init failure at startup must enqueue a retry. Otherwise a peer
/// whose addresses cannot be dialed at boot (no operational transport for the
/// configured transport types, all addresses unreachable, NAT rebind, etc.)
/// stays dead forever — pings arrive but cannot be answered until the daemon
/// is manually restarted.
#[tokio::test]
async fn test_initiate_peer_connections_schedules_retry_on_no_transport() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    // udp address but no UDP transport registered on the node — every dial
    // attempt resolves to NodeError::NoTransportForType.
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();
    assert!(node.retry_pending.is_empty());

    node.initiate_peer_connections().await;

    assert!(
        node.retry_pending.contains_key(&peer_node_addr),
        "startup peer-init failure must enqueue a retry so the peer can recover \
         without a daemon restart"
    );
}

// ============================================================================
// transport_mtu() — ISSUE-2026-0011 regression coverage
// ============================================================================

/// Helper: spawn a UdpTransport with the given mtu, started and operational.
async fn make_udp_transport_with_mtu(id: u32, mtu: u16) -> TransportHandle {
    let (packet_tx, _packet_rx) = packet_channel(64);
    let transport_id = TransportId::new(id);
    let mut udp = UdpTransport::new(
        transport_id,
        Some(format!("udp{}", id)),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(mtu),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    TransportHandle::Udp(udp)
}

#[tokio::test]
async fn test_transport_mtu_returns_min_across_operational() {
    // Multiple operational transports with varied MTUs. The picker must
    // return the smallest, deterministically, regardless of HashMap
    // iteration order. This is the core ISSUE-2026-0011 regression test.
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp1 = make_udp_transport_with_mtu(1, 1497).await;
    let udp2 = make_udp_transport_with_mtu(2, 1280).await;
    let udp3 = make_udp_transport_with_mtu(3, 1400).await;

    node.transports.insert(TransportId::new(1), udp1);
    node.transports.insert(TransportId::new(2), udp2);
    node.transports.insert(TransportId::new(3), udp3);

    // Expect the smallest (UDP-1280), not whichever HashMap iterates first.
    assert_eq!(node.transport_mtu(), 1280);

    // effective_ipv6_mtu = 1280 - 77 = 1203, max_mss = 1203 - 60 = 1143
    // (verifies the downstream clamp value).
    assert_eq!(node.effective_ipv6_mtu(), 1203);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_transport_mtu_fallback_when_no_operational_transports() {
    // No transports configured at all → falls back to 1280 (IPv6 minimum).
    let node = make_node();
    assert_eq!(node.transport_mtu(), 1280);
}

#[tokio::test]
async fn test_transport_mtu_min_with_single_operational() {
    // Single transport: trivially returns its MTU. Pins the picker doesn't
    // accidentally drop down to a smaller fallback when one transport is
    // operational.
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1452).await;
    node.transports.insert(TransportId::new(1), udp);

    assert_eq!(node.transport_mtu(), 1452);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

// path_mtu_lookup seeding for direct-link (configured) peers — closes the
// B3 coverage gap where configured/auto-connect peers never go through the
// discovery Lookup flow and so their FipsAddress was missing from
// path_mtu_lookup, causing the SYN-time TCP MSS clamp to fall back to the
// global ceiling.

#[tokio::test]
async fn test_seed_path_mtu_inserts_when_empty() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1452).await;
    node.transports.insert(TransportId::new(1), udp);

    let peer_addr = make_node_addr(0xAA);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.2:2121");

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);

    let stored = node
        .path_mtu_lookup
        .read()
        .unwrap()
        .get(&fips_addr)
        .copied();
    assert_eq!(
        stored,
        Some(1452),
        "Empty lookup should be seeded with the link MTU"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_seed_path_mtu_keeps_tighter_existing_value() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1452).await;
    node.transports.insert(TransportId::new(1), udp);

    let peer_addr = make_node_addr(0xBB);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.3:2121");

    // Pre-populate with a tighter value, e.g. learned from discovery's
    // reverse-path bottleneck.
    node.path_mtu_lookup
        .write()
        .unwrap()
        .insert(fips_addr, 1280);

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);

    let stored = node
        .path_mtu_lookup
        .read()
        .unwrap()
        .get(&fips_addr)
        .copied();
    assert_eq!(
        stored,
        Some(1280),
        "Existing tighter value (1280) must not be loosened by direct-link seed (1452)"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_seed_path_mtu_tightens_looser_existing_value() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1280).await;
    node.transports.insert(TransportId::new(1), udp);

    let peer_addr = make_node_addr(0xCC);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.4:2121");

    // Pre-populate with a looser stale value.
    node.path_mtu_lookup
        .write()
        .unwrap()
        .insert(fips_addr, 1452);

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);

    let stored = node
        .path_mtu_lookup
        .read()
        .unwrap()
        .get(&fips_addr)
        .copied();
    assert_eq!(
        stored,
        Some(1280),
        "Direct-link seed (1280) must overwrite looser existing value (1452)"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

/// On retry, configured direct addresses keep priority but fresh overlay
/// fallbacks still race inside the per-peer candidate budget. A stale static
/// LAN/nvpn hint must not pin the peer to a path that cannot reply.
#[tokio::test]
async fn test_retry_races_overlay_advert_alongside_static_udp_hint() {
    use crate::config::NostrDiscoveryPolicy;
    use crate::discovery::nostr::{NostrDiscovery, OverlayEndpointAdvert, OverlayTransportKind};

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
    let mut node = Node::new(config).unwrap();

    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();

    let static_sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind static sink");
    let stale_static_addr = static_sink
        .local_addr()
        .expect("static sink local addr")
        .to_string();
    let fresh_overlay_addr = "127.0.0.1:55180";

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let endpoint = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: fresh_overlay_addr.to_string(),
    };
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let advert = NostrDiscovery::cached_advert_for_test(peer_npub.clone(), endpoint, now_secs);
    bootstrap
        .insert_advert_for_test(peer_npub.clone(), advert)
        .await;
    node.nostr_discovery = Some(bootstrap);

    let peer_config = crate::config::PeerConfig {
        npub: peer_npub.clone(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::new(
            "udp",
            stale_static_addr.clone(),
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers.push(peer_config.clone());

    node.initiate_peer_retry_connection(&peer_config)
        .await
        .unwrap();

    let fresh = TransportAddr::from_string(fresh_overlay_addr);
    let stale = TransportAddr::from_string(&stale_static_addr);
    let fresh_link = node.find_link_by_addr(transport_id, &fresh);
    let stale_link = node.find_link_by_addr(transport_id, &stale);
    assert!(
        fresh_link.is_some(),
        "retry should race fresh overlay advert {fresh_overlay_addr} alongside the static candidate"
    );
    assert!(
        stale_link.is_some(),
        "retry should keep stale static {stale_static_addr} in the bounded path race"
    );
    assert_eq!(node.connection_count(), 2);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

/// Cold-start dial keeps explicitly configured direct hints first, but does
/// not let them suppress a fresh overlay advert. This avoids getting stuck on
/// stale private hints after a network move.
#[tokio::test]
async fn test_bootstrap_races_static_address_and_overlay_advert() {
    use crate::config::NostrDiscoveryPolicy;
    use crate::discovery::nostr::{NostrDiscovery, OverlayEndpointAdvert, OverlayTransportKind};

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
    let mut node = Node::new(config).unwrap();

    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();

    let static_sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind static sink");
    let static_addr = static_sink
        .local_addr()
        .expect("static sink local addr")
        .to_string();
    let overlay_addr = "127.0.0.1:55181";

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let endpoint = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: overlay_addr.to_string(),
    };
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let advert = NostrDiscovery::cached_advert_for_test(peer_npub.clone(), endpoint, now_secs);
    bootstrap
        .insert_advert_for_test(peer_npub.clone(), advert)
        .await;
    node.nostr_discovery = Some(bootstrap);

    let peer_config = crate::config::PeerConfig {
        npub: peer_npub.clone(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::new("udp", static_addr.clone())],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers.push(peer_config.clone());

    node.initiate_peer_connection(&peer_config).await.unwrap();

    let stat = TransportAddr::from_string(&static_addr);
    let overlay = TransportAddr::from_string(overlay_addr);
    let overlay_link = node.find_link_by_addr(transport_id, &overlay);
    let static_link = node.find_link_by_addr(transport_id, &stat);
    assert!(
        overlay_link.is_some(),
        "cold-start should race fresh overlay fallback alongside a static candidate"
    );
    assert!(
        static_link.is_some(),
        "cold-start should keep the unstamped static address in the bounded path race"
    );
    assert_eq!(node.connection_count(), 2);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_static_priority_preempts_fresh_overlay_when_budget_tight() {
    use crate::config::NostrDiscoveryPolicy;
    use crate::discovery::nostr::{NostrDiscovery, OverlayEndpointAdvert, OverlayTransportKind};

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
    config.node.limits.max_connections = 1;
    config.node.limits.max_links = 1;
    let mut node = Node::new(config).unwrap();
    node.set_max_connections(1);
    node.set_max_links(1);

    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();

    let static_sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind static sink");
    let stale_static_addr = static_sink
        .local_addr()
        .expect("static sink local addr")
        .to_string();
    let overlay_sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind overlay sink");
    let fresh_overlay_addr = overlay_sink
        .local_addr()
        .expect("overlay sink local addr")
        .to_string();

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let endpoint = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: fresh_overlay_addr.clone(),
    };
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let advert = NostrDiscovery::cached_advert_for_test(peer_npub.clone(), endpoint, now_secs);
    bootstrap
        .insert_advert_for_test(peer_npub.clone(), advert)
        .await;
    node.nostr_discovery = Some(bootstrap);

    let peer_config = crate::config::PeerConfig {
        npub: peer_npub.clone(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::new(
            "udp",
            stale_static_addr.clone(),
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers.push(peer_config.clone());

    node.initiate_peer_retry_connection(&peer_config)
        .await
        .unwrap();

    assert!(
        node.find_link_by_addr(
            transport_id,
            &TransportAddr::from_string(&stale_static_addr)
        )
        .is_some(),
        "explicit static priority should get the first candidate slot"
    );
    assert!(
        node.find_link_by_addr(
            transport_id,
            &TransportAddr::from_string(&fresh_overlay_addr)
        )
        .is_none(),
        "fresh overlay hint should remain a candidate but not outrank explicit priority"
    );
    assert_eq!(node.connection_count(), 1);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_retry_races_fresh_overlay_udp_candidates_without_static_direct() {
    use crate::config::NostrDiscoveryPolicy;
    use crate::discovery::nostr::{NostrDiscovery, OverlayEndpointAdvert, OverlayTransportKind};

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
    let mut node = Node::new(config).unwrap();

    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();

    let first_sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind first sink");
    let second_sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind second sink");
    let first_addr = first_sink
        .local_addr()
        .expect("first sink addr")
        .to_string();
    let second_addr = second_sink
        .local_addr()
        .expect("second sink addr")
        .to_string();

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let first_endpoint = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: first_addr.clone(),
    };
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut advert =
        NostrDiscovery::cached_advert_for_test(peer_npub.clone(), first_endpoint, now_secs);
    advert.advert.endpoints.push(OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: second_addr.clone(),
    });
    bootstrap
        .insert_advert_for_test(peer_npub.clone(), advert)
        .await;
    node.nostr_discovery = Some(bootstrap);

    let peer_config = crate::config::PeerConfig {
        npub: peer_npub.clone(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers.push(peer_config.clone());

    node.initiate_peer_retry_connection(&peer_config)
        .await
        .unwrap();

    assert!(
        node.find_link_by_addr(transport_id, &TransportAddr::from_string(&first_addr))
            .is_some(),
        "first overlay UDP candidate should be raced"
    );
    assert!(
        node.find_link_by_addr(transport_id, &TransportAddr::from_string(&second_addr))
            .is_some(),
        "a fresh overlay attempt must not suppress a later direct UDP candidate"
    );
    assert_eq!(node.connection_count(), 2);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_seed_path_mtu_noop_for_unknown_transport() {
    let node = make_node();
    let peer_addr = make_node_addr(0xDD);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.5:2121");

    // No transport registered — call must be a no-op, not panic.
    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(99), &transport_addr);

    let map = node.path_mtu_lookup.read().unwrap();
    assert!(
        map.get(&fips_addr).is_none(),
        "Seed must be a no-op when transport_id is not registered"
    );
}

// === update_peers ============================================================

fn npub_for_test() -> String {
    Identity::generate().npub()
}

fn peer_identity_for_outbound_refresh_owner(node: &Node) -> (Identity, PeerIdentity) {
    loop {
        let identity = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(identity.pubkey_full());
        if node.identity.node_addr() < peer_identity.node_addr() {
            return (identity, peer_identity);
        }
    }
}

fn peer_identity_for_outbound_refresh_loser(node: &Node) -> (Identity, PeerIdentity) {
    loop {
        let identity = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey_full(identity.pubkey_full());
        if node.identity.node_addr() > peer_identity.node_addr() {
            return (identity, peer_identity);
        }
    }
}

fn auto_connect_peer(npub: String, addr: &str) -> crate::config::PeerConfig {
    crate::config::PeerConfig {
        npub,
        alias: None,
        addresses: vec![crate::config::PeerAddress::new("udp", addr)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    }
}

#[tokio::test]
async fn update_peers_preserves_input_priority_order() {
    let mut node = make_node();
    let first = Identity::generate();
    let second = Identity::generate();
    let third = Identity::generate();

    let first_original = auto_connect_peer(first.npub(), "127.0.0.1:9");
    let second_peer = auto_connect_peer(second.npub(), "127.0.0.1:10");
    let third_peer = auto_connect_peer(third.npub(), "127.0.0.1:11");
    let first_updated = auto_connect_peer(first.npub(), "127.0.0.1:12");

    let outcome = node
        .update_peers(vec![
            first_original,
            second_peer.clone(),
            third_peer.clone(),
            first_updated.clone(),
        ])
        .await
        .unwrap();

    assert_eq!(outcome.added, 3);
    assert_eq!(
        node.config
            .peers
            .iter()
            .map(|peer| peer.npub.as_str())
            .collect::<Vec<_>>(),
        vec![
            first_updated.npub.as_str(),
            second_peer.npub.as_str(),
            third_peer.npub.as_str(),
        ],
        "caller priority order should survive de-duplication"
    );
    assert_eq!(node.config.peers[0].addresses, first_updated.addresses);
}

#[tokio::test]
async fn update_peers_races_alternate_path_even_when_outbound_would_lose() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_loser(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let old_addr = TransportAddr::from_string("127.0.0.1:7");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &old_addr);
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            old_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );

    let peer = auto_connect_peer(peer_full.npub(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.unchanged, 1);
    assert_eq!(node.peer_count(), 1, "current active peer must remain live");
    assert_eq!(
        node.connection_count(),
        1,
        "alternate path should be attempted even when our outbound would lose cross-connection"
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&old_addr));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_returns_zero_on_empty_diff() {
    let mut node = make_node();

    let outcome = node.update_peers(Vec::new()).await.unwrap();
    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 0);
    assert_eq!(outcome.unchanged, 0);
}

#[tokio::test]
async fn update_peers_adds_new_peer_and_registers_alias() {
    let mut node = make_node();
    let npub = npub_for_test();
    let mut peer = auto_connect_peer(npub.clone(), "127.0.0.1:9");
    peer.alias = Some("alice".to_string());

    let outcome = node.update_peers(vec![peer.clone()]).await.unwrap();

    assert_eq!(outcome.added, 1);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 0);
    assert_eq!(outcome.unchanged, 0);
    assert_eq!(node.config.peers.len(), 1);
    let identity = PeerIdentity::from_npub(&peer.npub).unwrap();
    assert_eq!(
        node.peer_aliases.get(identity.node_addr()),
        Some(&"alice".to_string())
    );
}

#[tokio::test]
async fn update_peers_removes_dropped_peer_and_clears_retry_state() {
    let mut node = make_node();
    let npub = npub_for_test();
    let peer = auto_connect_peer(npub.clone(), "127.0.0.1:9");

    let _ = node.update_peers(vec![peer.clone()]).await.unwrap();

    let identity = PeerIdentity::from_npub(&peer.npub).unwrap();
    let node_addr = *identity.node_addr();
    // Cold-add scheduled a retry because there's no transport.
    assert!(node.retry_pending.contains_key(&node_addr));

    let outcome = node.update_peers(Vec::new()).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 1);
    assert!(node.config.peers.is_empty());
    assert!(!node.retry_pending.contains_key(&node_addr));
    assert!(!node.peer_aliases.contains_key(&node_addr));
}

#[tokio::test]
async fn update_peers_reports_updated_when_addresses_change() {
    let mut node = make_node();
    let npub = npub_for_test();
    let original = auto_connect_peer(npub.clone(), "127.0.0.1:9");
    let _ = node.update_peers(vec![original]).await.unwrap();

    let new_version = auto_connect_peer(npub.clone(), "127.0.0.1:55180");
    let outcome = node.update_peers(vec![new_version.clone()]).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 1);
    assert_eq!(outcome.unchanged, 0);
    assert_eq!(node.config.peers.len(), 1);
    assert_eq!(node.config.peers[0].addresses[0].addr, "127.0.0.1:55180");
}

#[tokio::test]
async fn update_peers_reports_unchanged_for_identical_entry() {
    let mut node = make_node();
    let npub = npub_for_test();
    let peer = auto_connect_peer(npub, "127.0.0.1:9");
    let _ = node.update_peers(vec![peer.clone()]).await.unwrap();

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 0);
    assert_eq!(outcome.unchanged, 1);
}

#[tokio::test]
async fn update_peers_refreshes_stale_retry_config_even_when_peer_is_unchanged() {
    let mut node = make_node();
    let npub = npub_for_test();
    let peer = auto_connect_peer(npub, "127.0.0.1:9");
    let identity = PeerIdentity::from_npub(&peer.npub).unwrap();
    let node_addr = *identity.node_addr();
    node.config.peers = vec![peer.clone()];

    let mut stale_retry = super::super::retry::RetryState::new(auto_connect_peer(
        peer.npub.clone(),
        "203.0.113.99:51820",
    ));
    stale_retry.retry_after_ms = 123_456;
    stale_retry.reconnect = true;
    node.retry_pending.insert(node_addr, stale_retry);

    let outcome = node.update_peers(vec![peer.clone()]).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.updated, 0);
    assert_eq!(outcome.unchanged, 1);
    let retry = node.retry_pending.get(&node_addr).unwrap();
    assert_eq!(retry.peer_config.addresses, peer.addresses);
}

#[tokio::test]
async fn update_peers_redials_existing_auto_peer_with_direct_hint() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let npub = npub_for_test();
    let original = crate::config::PeerConfig {
        npub: npub.clone(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers = vec![original];

    let refreshed = auto_connect_peer(npub, "127.0.0.1:9");
    let outcome = node.update_peers(vec![refreshed]).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 1);
    assert_eq!(node.connection_count(), 1);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_redials_unchanged_auto_peer_without_link() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer = auto_connect_peer(npub_for_test(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.added, 0);
    assert_eq!(outcome.removed, 0);
    assert_eq!(outcome.updated, 0);
    assert_eq!(outcome.unchanged, 1);
    assert_eq!(node.connection_count(), 1);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_races_alternate_path_for_active_peer_without_dropping_current_link() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let old_addr = TransportAddr::from_string("127.0.0.1:7");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &old_addr);
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            old_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );

    let peer = auto_connect_peer(peer_full.npub(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.unchanged, 1);
    assert_eq!(node.peer_count(), 1, "current active peer must remain live");
    assert_eq!(
        node.connection_count(),
        1,
        "alternate path should be a pending handshake, not a peer replacement"
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&old_addr));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_does_not_churn_active_peer_already_on_known_candidate() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);

    let peer = auto_connect_peer(peer_full.npub(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.unchanged, 1);
    assert_eq!(node.peer_count(), 1);
    assert_eq!(
        node.connection_count(),
        0,
        "known-good active concrete path should not be redialed every refresh"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[test]
fn active_peer_same_path_discovery_skips_fresh_peer() {
    let mut node = make_node();
    let (_peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), Node::now_ms());
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);
    let candidate = crate::config::PeerAddress::new("udp", "127.0.0.1:9");

    assert!(node.active_peer_candidate_is_fresh_enough_to_skip(
        &peer_node_addr,
        std::slice::from_ref(&candidate),
    ));
}

#[test]
fn active_peer_same_path_discovery_refreshes_stale_peer() {
    let mut node = make_node();
    let (_peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let stale_at = Node::now_ms().saturating_sub(
        node.config
            .node
            .heartbeat_interval_secs
            .saturating_add(1)
            .saturating_mul(1000),
    );
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), stale_at);
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);
    let candidate = crate::config::PeerAddress::new("udp", "127.0.0.1:9");

    assert!(!node.active_peer_candidate_is_fresh_enough_to_skip(
        &peer_node_addr,
        std::slice::from_ref(&candidate),
    ));
}

#[tokio::test]
async fn update_peers_races_new_alternative_even_when_current_path_is_still_known() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let new_addr = TransportAddr::from_string("127.0.0.1:10");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            current_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );

    let peer = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::new("udp", "127.0.0.1:9"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:10"),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers = vec![peer.clone()];

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.unchanged, 1);
    assert_eq!(node.peer_count(), 1, "existing link must stay live");
    assert_eq!(node.connection_count(), 1);
    assert_eq!(
        node.peers
            .connection_values()
            .next()
            .and_then(|conn| conn.source_addr()),
        Some(&new_addr)
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&current_addr));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_races_more_alternatives_while_peer_is_connecting_with_budget() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(transport_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            current_addr,
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );

    let first = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::new("udp", "127.0.0.1:9"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:10"),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers = vec![first.clone()];
    let _ = node.update_peers(vec![first]).await.unwrap();
    assert_eq!(node.connection_count(), 1);

    let refreshed = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::new("udp", "127.0.0.1:9"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:10"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:11"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:12"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:13"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:14"),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };

    let outcome = node.update_peers(vec![refreshed]).await.unwrap();

    assert_eq!(outcome.updated, 1);
    assert_eq!(
        node.connection_count(),
        4,
        "one existing in-flight path plus three new paths should hit the per-peer race budget"
    );
    let attempted: std::collections::HashSet<_> = node
        .peers
        .connection_values()
        .filter_map(|conn| conn.source_addr().map(ToString::to_string))
        .collect();
    for addr in [
        "127.0.0.1:10",
        "127.0.0.1:11",
        "127.0.0.1:12",
        "127.0.0.1:13",
    ] {
        assert!(attempted.contains(addr), "missing attempted path {addr}");
    }
    assert!(
        !attempted.contains("127.0.0.1:14"),
        "candidate racing should be bounded per peer"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn update_peers_races_primary_path_when_active_peer_uses_bootstrap_transport() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let bootstrap_id = TransportId::new(1);
    let primary_id = TransportId::new(2);
    for (transport_id, name) in [(bootstrap_id, "nostr-nat"), (primary_id, "main")] {
        let mut udp = UdpTransport::new(
            transport_id,
            Some(name.to_string()),
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx.clone(),
        );
        udp.start_async().await.unwrap();
        node.transports
            .insert(transport_id, TransportHandle::Udp(udp));
    }
    node.bootstrap_transports.mark(bootstrap_id);

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, 1_000);
    active_peer.set_current_addr(bootstrap_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);

    let peer = auto_connect_peer(peer_full.npub(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];

    let outcome = node.update_peers(vec![peer]).await.unwrap();

    assert_eq!(outcome.unchanged, 1);
    assert_eq!(node.peer_count(), 1);
    assert_eq!(
        node.connection_count(),
        1,
        "bootstrap NAT path should not suppress a primary-transport refresh"
    );
    let conn = node.peers.connection_values().next().unwrap();
    assert_eq!(conn.transport_id(), Some(primary_id));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn process_pending_retries_races_primary_path_for_active_bootstrap_peer() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let bootstrap_id = TransportId::new(1);
    let primary_id = TransportId::new(2);
    for (transport_id, name) in [(bootstrap_id, "nostr-nat"), (primary_id, "main")] {
        let mut udp = UdpTransport::new(
            transport_id,
            Some(name.to_string()),
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx.clone(),
        );
        udp.start_async().await.unwrap();
        node.transports
            .insert(transport_id, TransportHandle::Udp(udp));
    }
    node.bootstrap_transports.mark(bootstrap_id);

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), 1_000);
    active_peer.set_current_addr(bootstrap_id, &TransportAddr::from_string("127.0.0.1:8"));
    node.peers.insert(peer_node_addr, active_peer);

    let peer = auto_connect_peer(peer_full.npub(), "127.0.0.1:9");
    node.config.peers = vec![peer.clone()];
    let mut state = super::super::retry::RetryState::new(peer);
    state.retry_after_ms = 0;
    state.reconnect = true;
    node.retry_pending.insert(peer_node_addr, state);

    node.process_pending_retries(1_000).await;

    assert_eq!(node.peer_count(), 1);
    assert_eq!(
        node.connection_count(),
        2,
        "retry maintenance should race the configured direct path and re-probe the old UDP path while fallback remains active"
    );
    let attempted: std::collections::HashSet<_> = node
        .peers
        .connection_values()
        .filter_map(|conn| {
            (conn.transport_id() == Some(primary_id))
                .then(|| conn.source_addr().map(ToString::to_string))
                .flatten()
        })
        .collect();
    assert!(attempted.contains("127.0.0.1:8"));
    assert!(attempted.contains("127.0.0.1:9"));
    assert!(
        node.retry_pending
            .get(&peer_node_addr)
            .is_some_and(|state| (3_000..=9_000).contains(&state.retry_after_ms)),
        "active fallback direct refresh should stay on quick reprobe cadence, got {:?}",
        node.retry_pending
            .get(&peer_node_addr)
            .map(|state| state.retry_after_ms)
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn active_direct_refresh_reclaims_inflight_slot_for_configured_static_path() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let primary_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        primary_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(primary_id, TransportHandle::Udp(udp));

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let current_addr = TransportAddr::from_string("127.0.0.1:20000");
    let active_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, active_link_id, 1_000);
    active_peer.set_current_addr(primary_id, &current_addr);
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        active_link_id,
        Link::connectionless(
            active_link_id,
            primary_id,
            current_addr,
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );

    let static_addr = "127.0.0.1:9";
    let peer_config = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority(
            "udp",
            static_addr,
            10,
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers = vec![peer_config.clone()];

    for port in [10, 11, 12, 13] {
        node.initiate_connection(
            primary_id,
            TransportAddr::from_string(&format!("127.0.0.1:{port}")),
            peer_identity,
        )
        .await
        .unwrap();
    }
    assert_eq!(
        node.connection_count(),
        4,
        "test setup should fill the per-peer path-candidate budget"
    );

    let mut state = super::super::retry::RetryState::new(peer_config);
    state.retry_after_ms = 0;
    state.reconnect = true;
    node.retry_pending.insert(peer_node_addr, state);

    node.process_pending_retries(1_000).await;

    let static_transport_addr = TransportAddr::from_string(static_addr);
    assert!(
        node.find_link_by_addr(primary_id, &static_transport_addr)
            .is_some(),
        "a configured static path must be able to reclaim a lower-priority in-flight slot"
    );
    assert_eq!(
        node.connection_count(),
        4,
        "refresh should replace one lower-priority candidate instead of exceeding the cap"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn active_fallback_static_hint_also_queues_nostr_traversal() {
    use crate::config::NostrDiscoveryPolicy;
    use crate::node::session::{EndToEndState, SessionEntry};
    use crate::noise::HandshakeState;

    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let peer_config = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::new("udp", "127.0.0.1:9")],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: false,
    };

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
    config.peers = vec![peer_config.clone()];
    let mut node = Node::new(config).expect("node");
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let bootstrap_id = TransportId::new(1);
    let primary_id = TransportId::new(2);
    for (transport_id, name) in [(bootstrap_id, "fips-mesh"), (primary_id, "main")] {
        let mut udp = UdpTransport::new(
            transport_id,
            Some(name.to_string()),
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx.clone(),
        );
        udp.start_async().await.unwrap();
        node.transports
            .insert(transport_id, TransportHandle::Udp(udp));
    }
    node.bootstrap_transports.mark(bootstrap_id);

    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), 1_000);
    active_peer.set_current_addr(bootstrap_id, &TransportAddr::from_string("127.0.0.1:8"));
    node.peers.insert(peer_node_addr, active_peer);

    let mut initiator =
        HandshakeState::new_initiator(node.identity.keypair(), peer_full.pubkey_full());
    let mut responder = HandshakeState::new_responder(peer_full.keypair());
    initiator.set_local_epoch([0x01; 8]);
    responder.set_local_epoch([0x02; 8]);
    let msg1 = initiator.write_message_1().expect("msg1");
    responder.read_message_1(&msg1).expect("read msg1");
    let msg2 = responder.write_message_2().expect("msg2");
    initiator.read_message_2(&msg2).expect("read msg2");
    node.sessions.insert(
        peer_node_addr,
        SessionEntry::new(
            peer_node_addr,
            peer_full.pubkey_full(),
            EndToEndState::Established(initiator.into_session().expect("session")),
            1_000,
            true,
        ),
    );

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    node.nostr_discovery = Some(bootstrap.clone());
    let mut state = super::super::retry::RetryState::new(peer_config);
    state.retry_after_ms = 0;
    state.reconnect = true;
    node.retry_pending.insert(peer_node_addr, state);

    node.process_pending_retries(1_000).await;

    assert_eq!(
        node.connection_count(),
        2,
        "static direct hint and old UDP path should be raced while fallback remains active"
    );
    assert_eq!(
        bootstrap.active_initiator_count_for_test().await,
        1,
        "stale static hints must not suppress Nostr/mesh traversal refresh"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn active_nostr_peer_without_static_addresses_retests_observed_udp_path() {
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    let mut node = Node::new(config).expect("node");
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let primary_id = TransportId::new(2);
    let mut udp = UdpTransport::new(
        primary_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(primary_id, TransportHandle::Udp(udp));

    let (peer_full, peer_identity) = peer_identity_for_outbound_refresh_owner(&node);
    let peer_node_addr = *peer_identity.node_addr();
    let peer_config = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    node.config.peers = vec![peer_config.clone()];

    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), 1_000);
    active_peer.set_current_addr(primary_id, &current_addr);
    active_peer.mark_reconnecting();
    node.peers.insert(peer_node_addr, active_peer);

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    node.nostr_discovery = Some(bootstrap.clone());
    let mut state = super::super::retry::RetryState::new(peer_config);
    state.retry_after_ms = 0;
    state.reconnect = true;
    node.retry_pending.insert(peer_node_addr, state);

    node.process_pending_retries(1_000).await;

    assert_eq!(
        node.connection_count(),
        1,
        "reconnecting active peers with no static hints should still probe the last observed UDP endpoint"
    );
    let conn = node.peers.connection_values().next().unwrap();
    assert_eq!(conn.transport_id(), Some(primary_id));
    assert_eq!(conn.source_addr(), Some(&current_addr));
    assert_eq!(
        bootstrap.active_initiator_count_for_test().await,
        1,
        "direct refresh should also send a Nostr/mesh call-me-maybe request"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn configured_direct_refresh_ignores_traversal_cooldown_for_mesh_signal() {
    use crate::config::NostrDiscoveryPolicy;

    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::ConfiguredOnly;
    config.peers = vec![peer_config.clone()];
    let mut node = Node::new(config).expect("node");

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    for i in 0..5 {
        bootstrap.record_traversal_failure(&peer_config.npub, 1_000 + i * 1_000);
    }
    assert!(
        bootstrap.cooldown_until(&peer_config.npub, 6_000).is_some(),
        "fixture should put the peer in traversal cooldown"
    );
    node.nostr_discovery = Some(bootstrap.clone());

    assert!(
        node.request_nostr_bootstrap(&peer_config).await,
        "configured direct refresh should still send a call-me-maybe style mesh/Nostr request"
    );
    assert_eq!(
        bootstrap.active_initiator_count_for_test().await,
        1,
        "cooldown must not suppress immediate direct refresh probing for configured peers"
    );
}

#[tokio::test]
async fn mesh_signal_warms_session_instead_of_dropping_without_established_session() {
    use super::spanning_tree::{run_tree_test, verify_tree_convergence};
    use crate::discovery::nostr::{MeshTraversalSignal, TraversalOffer};

    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let peer_node_addr = *nodes[1].node.node_addr();
    let peer_npub = nodes[1].node.identity().npub();
    let peer_config = crate::config::PeerConfig {
        npub: peer_npub.clone(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: false,
    };

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    bootstrap.push_mesh_signal_for_test(MeshTraversalSignal::Offer {
        peer_npub: peer_npub.clone(),
        offer: TraversalOffer {
            message_type: "offer".to_string(),
            session_id: "session".to_string(),
            issued_at: 1,
            expires_at: 2,
            nonce: "nonce".to_string(),
            sender_npub: nodes[0].node.identity().npub(),
            recipient_npub: peer_npub,
            reflexive_address: None,
            local_addresses: Vec::new(),
            stun_server: None,
        },
    });
    nodes[0].node.config.node.discovery.nostr.enabled = true;
    nodes[0].node.config.peers = vec![peer_config];
    nodes[0].node.nostr_discovery = Some(bootstrap.clone());

    nodes[0].node.poll_nostr_discovery().await;

    assert!(
        nodes[0]
            .node
            .sessions
            .get(&peer_node_addr)
            .is_some_and(|entry| entry.is_initiating()),
        "mesh signal delivery should warm an end-to-end session over the existing mesh route"
    );
    assert_eq!(
        bootstrap.drain_mesh_signals().await.len(),
        1,
        "mesh signal should be deferred until the warmed session is established"
    );
}

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
    let packet =
        ReceivedPacket::with_timestamp(new_transport_id, new_addr.clone(), wire_msg2, 2_100);

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
    assert!(node.sessions.contains_key(&peer_node_addr));

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
        !node.sessions.contains_key(&peer_node_addr),
        "old FSP session must be removed when the peer's startup epoch changes"
    );
}

#[tokio::test]
async fn fresh_handshake_replaces_reconnecting_peer_even_if_tie_breaker_would_lose() {
    let mut node = make_node();
    let peer_full = loop {
        let candidate = Identity::generate();
        if candidate.node_addr() < node.node_addr() {
            break candidate;
        }
    };
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    assert!(
        !crate::peer::cross_connection_winner(node.node_addr(), &peer_node_addr, true),
        "fixture should make our outbound lose the normal cross-connection tie-breaker"
    );

    let old_transport_id = TransportId::new(1);
    let old_link_id = LinkId::new(10);
    let old_addr = TransportAddr::from_string("127.0.0.1:8000");
    let old_our_index = SessionIndex::new(11);
    let old_their_index = SessionIndex::new(12);
    let old_session =
        make_test_fmp_session(&node.identity, &peer_full, node.startup_epoch, [0x11; 8]);
    let mut old_peer = ActivePeer::with_session(
        peer_identity,
        old_link_id,
        1_000,
        old_session,
        old_our_index,
        old_their_index,
        old_transport_id,
        old_addr.clone(),
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([0x11; 8]),
    );
    old_peer.mark_reconnecting();
    node.peers.insert(peer_node_addr, old_peer);
    node.peers
        .insert_session_index((old_transport_id, old_our_index.as_u32()), peer_node_addr);

    let new_transport_id = TransportId::new(2);
    let new_link_id = LinkId::new(11);
    let new_addr = TransportAddr::from_string("127.0.0.1:9000");
    let mut new_conn = PeerConnection::outbound(new_link_id, peer_identity, 2_000);
    let msg1 = new_conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 2_000)
        .unwrap();
    let mut responder = PeerConnection::inbound(LinkId::new(99), 2_000);
    let msg2 = responder
        .receive_handshake_init(peer_full.keypair(), [0x11; 8], &msg1, 2_000)
        .unwrap();
    new_conn.complete_handshake(&msg2, 2_100).unwrap();
    let new_our_index = node.index_allocator.allocate().unwrap();
    let new_their_index = SessionIndex::new(77);
    new_conn.set_our_index(new_our_index);
    new_conn.set_their_index(new_their_index);
    new_conn.set_transport_id(new_transport_id);
    new_conn.set_source_addr(new_addr);
    node.peers.insert_connection(new_link_id, new_conn);

    let result = node
        .promote_connection(new_link_id, peer_identity, 2_100)
        .unwrap();

    assert!(
        matches!(result, PromotionResult::CrossConnectionWon { .. }),
        "fresh authenticated path should replace reconnecting peer"
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), new_link_id);
    assert!(active.can_send());
    assert_eq!(active.remote_epoch(), Some([0x11; 8]));
}

#[tokio::test]
async fn fresh_outbound_alternate_path_replaces_healthy_peer_even_if_tie_breaker_would_lose() {
    let mut node = make_node();
    let peer_full = loop {
        let candidate = Identity::generate();
        if candidate.node_addr() < node.node_addr() {
            break candidate;
        }
    };
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    assert!(
        !crate::peer::cross_connection_winner(node.node_addr(), &peer_node_addr, true),
        "fixture should make our outbound lose the normal cross-connection tie-breaker"
    );

    let old_transport_id = TransportId::new(1);
    let old_link_id = LinkId::new(10);
    let old_addr = TransportAddr::from_string("127.0.0.1:8000");
    let old_our_index = SessionIndex::new(11);
    let old_their_index = SessionIndex::new(12);
    let old_session =
        make_test_fmp_session(&node.identity, &peer_full, node.startup_epoch, [0x11; 8]);
    let old_peer = ActivePeer::with_session(
        peer_identity,
        old_link_id,
        1_000,
        old_session,
        old_our_index,
        old_their_index,
        old_transport_id,
        old_addr,
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([0x11; 8]),
    );
    assert!(old_peer.can_send());
    node.peers.insert(peer_node_addr, old_peer);
    node.peers
        .insert_session_index((old_transport_id, old_our_index.as_u32()), peer_node_addr);

    let new_transport_id = TransportId::new(2);
    let new_link_id = LinkId::new(11);
    let new_addr = TransportAddr::from_string("127.0.0.1:9000");
    let mut new_conn = PeerConnection::outbound(new_link_id, peer_identity, 2_000);
    let msg1 = new_conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 2_000)
        .unwrap();
    let mut responder = PeerConnection::inbound(LinkId::new(99), 2_000);
    let msg2 = responder
        .receive_handshake_init(peer_full.keypair(), [0x11; 8], &msg1, 2_000)
        .unwrap();
    new_conn.complete_handshake(&msg2, 2_100).unwrap();
    let new_our_index = node.index_allocator.allocate().unwrap();
    let new_their_index = SessionIndex::new(77);
    new_conn.set_our_index(new_our_index);
    new_conn.set_their_index(new_their_index);
    new_conn.set_transport_id(new_transport_id);
    new_conn.set_source_addr(new_addr.clone());
    node.peers.insert_connection(new_link_id, new_conn);

    let result = node
        .promote_connection(new_link_id, peer_identity, 2_100)
        .unwrap();

    assert!(
        matches!(result, PromotionResult::CrossConnectionWon { .. }),
        "fresh authenticated outbound alternate path should replace the old healthy link"
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), new_link_id);
    assert_eq!(active.current_addr(), Some(&new_addr));
    assert!(active.can_send());
}

#[tokio::test]
async fn handle_msg2_promotes_active_peer_outbound_alternate_path_even_if_tie_breaker_would_lose() {
    let mut node = make_node();
    let peer_full = loop {
        let candidate = Identity::generate();
        if candidate.node_addr() < node.node_addr() {
            break candidate;
        }
    };
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    assert!(
        !crate::peer::cross_connection_winner(node.node_addr(), &peer_node_addr, true),
        "fixture should make our outbound lose the normal cross-connection tie-breaker"
    );

    let old_transport_id = TransportId::new(1);
    let old_link_id = LinkId::new(10);
    let old_addr = TransportAddr::from_string("127.0.0.1:8000");
    let old_our_index = SessionIndex::new(11);
    let old_their_index = SessionIndex::new(12);
    let old_session =
        make_test_fmp_session(&node.identity, &peer_full, node.startup_epoch, [0x11; 8]);
    let old_peer = ActivePeer::with_session(
        peer_identity,
        old_link_id,
        1_000,
        old_session,
        old_our_index,
        old_their_index,
        old_transport_id,
        old_addr.clone(),
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([0x11; 8]),
    );
    assert!(old_peer.can_send());
    node.peers.insert(peer_node_addr, old_peer);
    node.peers
        .insert_session_index((old_transport_id, old_our_index.as_u32()), peer_node_addr);
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
    let mut new_conn = PeerConnection::outbound(new_link_id, peer_identity, 2_000);
    let msg1 = new_conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 2_000)
        .unwrap();
    let our_index = node.index_allocator.allocate().unwrap();
    new_conn.set_our_index(our_index);
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
    node.pending_outbound
        .insert((new_transport_id, our_index.as_u32()), new_link_id);

    let mut responder = PeerConnection::inbound(LinkId::new(99), 2_000);
    let noise_msg2 = responder
        .receive_handshake_init(peer_full.keypair(), [0x11; 8], &msg1, 2_000)
        .unwrap();
    let their_index = SessionIndex::new(77);
    let wire_msg2 = build_msg2(their_index, our_index, &noise_msg2);
    let packet =
        ReceivedPacket::with_timestamp(new_transport_id, new_addr.clone(), wire_msg2, 2_100);

    node.handle_msg2(packet).await;

    assert_eq!(node.connection_count(), 0);
    assert!(node.pending_outbound.is_empty());
    assert!(
        !node.links.contains_key(&old_link_id),
        "old active link should be retired after successful path refresh"
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
async fn handle_msg2_does_not_demote_healthy_static_path_to_lower_priority_alternate() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
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

    let static_addr = TransportAddr::from_string("127.0.0.1:8000");
    let lower_priority_addr = TransportAddr::from_string("127.0.0.1:9000");
    node.config.peers = vec![crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:8000", 10),
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:9000", 100),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    }];

    let old_link_id = LinkId::new(10);
    let old_our_index = SessionIndex::new(11);
    let old_their_index = SessionIndex::new(12);
    let old_session =
        make_test_fmp_session(&node.identity, &peer_full, node.startup_epoch, [0x11; 8]);
    let old_peer = ActivePeer::with_session(
        peer_identity,
        old_link_id,
        1_000,
        old_session,
        old_our_index,
        old_their_index,
        transport_id,
        static_addr.clone(),
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([0x11; 8]),
    );
    assert!(old_peer.can_send());
    node.peers.insert(peer_node_addr, old_peer);
    node.peers
        .insert_session_index((transport_id, old_our_index.as_u32()), peer_node_addr);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            static_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((transport_id, static_addr.clone()), old_link_id);

    let new_link_id = LinkId::new(11);
    let mut new_conn = PeerConnection::outbound(new_link_id, peer_identity, 2_000);
    let msg1 = new_conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 2_000)
        .unwrap();
    let our_index = node.index_allocator.allocate().unwrap();
    new_conn.set_our_index(our_index);
    new_conn.set_transport_id(transport_id);
    new_conn.set_source_addr(lower_priority_addr.clone());
    node.links.insert(
        new_link_id,
        Link::connectionless(
            new_link_id,
            transport_id,
            lower_priority_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((transport_id, lower_priority_addr.clone()), new_link_id);
    node.peers.insert_connection(new_link_id, new_conn);
    node.pending_outbound
        .insert((transport_id, our_index.as_u32()), new_link_id);

    let mut responder = PeerConnection::inbound(LinkId::new(99), 2_000);
    let noise_msg2 = responder
        .receive_handshake_init(peer_full.keypair(), [0x11; 8], &msg1, 2_000)
        .unwrap();
    let their_index = SessionIndex::new(77);
    let wire_msg2 = build_msg2(their_index, our_index, &noise_msg2);
    let packet =
        ReceivedPacket::with_timestamp(transport_id, lower_priority_addr.clone(), wire_msg2, 2_100);

    node.handle_msg2(packet).await;

    assert_eq!(node.connection_count(), 0);
    assert!(node.pending_outbound.is_empty());
    assert!(
        node.links.contains_key(&old_link_id),
        "healthy preferred static link should remain active"
    );
    assert!(
        !node.links.contains_key(&new_link_id),
        "lower-priority alternate link should be discarded"
    );
    assert_eq!(
        node.links
            .get_addr(&(transport_id, static_addr.clone()))
            .copied(),
        Some(old_link_id)
    );
    assert_eq!(
        node.links
            .get_addr(&(transport_id, lower_priority_addr.clone())),
        None
    );

    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&static_addr));
    assert_eq!(active.our_index(), Some(old_our_index));
    assert_eq!(active.their_index(), Some(old_their_index));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn authenticated_lower_priority_packet_does_not_rotate_configured_static_path() {
    let local_identity = Identity::generate();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let static_addr = TransportAddr::from_string("127.0.0.1:8000");
    let public_addr = TransportAddr::from_string("203.0.113.9:9000");

    let mut config = Config::new();
    config.peers = vec![crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:8000", 10),
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:9000", 200),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    }];
    let session = make_test_fmp_session(&local_identity, &peer_full, [1; 8], [2; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));
    let active = ActivePeer::with_session(
        peer_identity,
        LinkId::new(10),
        1_000,
        session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        transport_id,
        static_addr.clone(),
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([2; 8]),
    );
    assert!(active.can_send());
    node.peers.insert(peer_node_addr, active);

    node.process_authentic_fmp_plaintext(AuthenticatedFmpPlaintext::new(
        peer_identity,
        transport_id,
        &public_addr,
        2_000,
        64,
        1,
        0,
        &[0, 0, 0, 0],
    ))
    .await;

    let active = node.get_peer(&peer_node_addr).expect("peer");
    assert_eq!(
        active.current_addr(),
        Some(&static_addr),
        "healthy static path should not be rewritten by lower-priority authenticated traffic"
    );
    assert_eq!(
        active.idle_time(2_500),
        1_500,
        "suppressed lower-priority traffic should not refresh selected-path liveness"
    );

    node.mark_session_direct_path_degraded(peer_node_addr, 3_000);
    node.process_authentic_fmp_plaintext(AuthenticatedFmpPlaintext::new(
        peer_identity,
        transport_id,
        &public_addr,
        3_100,
        64,
        2,
        0,
        &[0, 0, 0, 0],
    ))
    .await;

    let active = node.get_peer(&peer_node_addr).expect("peer");
    assert_eq!(
        active.current_addr(),
        Some(&static_addr),
        "session degradation alone should not rotate away from an operator-configured static path"
    );
    assert_eq!(
        active.idle_time(3_100),
        2_100,
        "suppressed lower-priority traffic should still not refresh selected-path liveness"
    );

    node.config.peers[0].addresses[0].seen_at_ms = Some(2_000);
    node.process_authentic_fmp_plaintext(AuthenticatedFmpPlaintext::new(
        peer_identity,
        transport_id,
        &public_addr,
        3_200,
        64,
        3,
        0,
        &[0, 0, 0, 0],
    ))
    .await;

    let active = node.get_peer(&peer_node_addr).expect("peer");
    assert_eq!(
        active.current_addr(),
        Some(&public_addr),
        "degraded discovered paths should still be allowed to roam to an authenticated alternate"
    );
    assert_eq!(active.idle_time(3_200), 0);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn handle_msg2_matches_pending_outbound_by_index_when_reply_transport_id_changes() {
    let mut node = make_node();
    let peer_full = loop {
        let candidate = Identity::generate();
        if candidate.node_addr() < node.node_addr() {
            break candidate;
        }
    };
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();

    let old_transport_id = TransportId::new(1);
    let old_link_id = LinkId::new(10);
    let old_addr = TransportAddr::from_string("203.0.113.24:51820");
    let old_our_index = SessionIndex::new(11);
    let old_their_index = SessionIndex::new(12);
    let old_session =
        make_test_fmp_session(&node.identity, &peer_full, node.startup_epoch, [0x11; 8]);
    let old_peer = ActivePeer::with_session(
        peer_identity,
        old_link_id,
        1_000,
        old_session,
        old_our_index,
        old_their_index,
        old_transport_id,
        old_addr.clone(),
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([0x11; 8]),
    );
    node.peers.insert(peer_node_addr, old_peer);
    node.peers
        .insert_session_index((old_transport_id, old_our_index.as_u32()), peer_node_addr);
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

    let dial_transport_id = TransportId::new(2);
    let recv_transport_id = TransportId::new(3);
    let new_link_id = LinkId::new(11);
    let gateway_addr = TransportAddr::from_string("198.51.100.91:51830");
    let mut new_conn = PeerConnection::outbound(new_link_id, peer_identity, 2_000);
    let msg1 = new_conn
        .start_handshake(node.identity.keypair(), node.startup_epoch, 2_000)
        .unwrap();
    let our_index = node.index_allocator.allocate().unwrap();
    new_conn.set_our_index(our_index);
    new_conn.set_transport_id(dial_transport_id);
    new_conn.set_source_addr(gateway_addr.clone());
    node.links.insert(
        new_link_id,
        Link::connectionless(
            new_link_id,
            dial_transport_id,
            gateway_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );
    node.links
        .insert_addr((dial_transport_id, gateway_addr.clone()), new_link_id);
    node.peers.insert_connection(new_link_id, new_conn);
    node.pending_outbound
        .insert((dial_transport_id, our_index.as_u32()), new_link_id);

    let mut responder = PeerConnection::inbound(LinkId::new(99), 2_000);
    let noise_msg2 = responder
        .receive_handshake_init(peer_full.keypair(), [0x11; 8], &msg1, 2_000)
        .unwrap();
    let their_index = SessionIndex::new(77);
    let wire_msg2 = build_msg2(their_index, our_index, &noise_msg2);
    let packet =
        ReceivedPacket::with_timestamp(recv_transport_id, gateway_addr.clone(), wire_msg2, 2_100);

    node.handle_msg2(packet).await;

    assert_eq!(node.connection_count(), 0);
    assert!(node.pending_outbound.is_empty());
    assert!(
        !node.links.contains_key(&old_link_id),
        "old public path should be retired after gateway reply completes"
    );

    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), new_link_id);
    assert_eq!(active.transport_id(), Some(dial_transport_id));
    assert_eq!(active.current_addr(), Some(&gateway_addr));
    assert_eq!(active.our_index(), Some(our_index));
    assert_eq!(active.their_index(), Some(their_index));
}

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

fn inject_dummy_peers(node: &mut Node, count: usize) {
    for i in 0..count {
        let identity = make_peer_identity();
        let addr = *identity.node_addr();
        let peer = ActivePeer::new(identity, LinkId::new((i + 1) as u64), 0);
        node.peers.insert(addr, peer);
    }
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

#[cfg(unix)]
#[test]
fn peer_runtime_send_snapshot_owns_fmp_metadata_and_worker_availability() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(7);
    let link_id = LinkId::new(9);
    let remote_addr = TransportAddr::from_string("peer-runtime-send-snapshot");
    let our_index = SessionIndex::new(10);
    let their_index = SessionIndex::new(20);
    let sender = make_test_fmp_session(&node.identity, &peer_full, [0x01; 8], [0x02; 8]);

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = ActivePeer::with_session(
        peer_identity,
        link_id,
        1_000,
        sender,
        our_index,
        their_index,
        transport_id,
        remote_addr.clone(),
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([0x02; 8]),
    );
    registry.insert_with_current_session_index(peer_addr, active_peer);

    let payload_len = 96;
    let snapshot = registry
        .prepare_peer_runtime_send_snapshot(&peer_addr, true, payload_len)
        .expect("peer runtime owner should prepare one send snapshot");

    assert_eq!(snapshot.node_addr(), peer_addr);
    assert_eq!(snapshot.fmp_prepared().transport_id, transport_id);
    assert_eq!(snapshot.fmp_prepared().remote_addr, remote_addr);
    assert_eq!(snapshot.fmp_prepared().their_index, their_index);
    assert_eq!(snapshot.fmp_prepared().payload_len, payload_len);
    assert_eq!(snapshot.fmp_prepared().flags & FLAG_CE, FLAG_CE);
    assert!(
        snapshot.fmp_worker_send_available(),
        "snapshot should carry worker-send availability from the same peer read"
    );
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        0,
        "snapshot preparation must not consume a Noise send counter"
    );

    let reservation = registry
        .reserve_peer_runtime_fmp_worker_send(&snapshot)
        .expect("peer runtime snapshot should reserve the FMP worker send")
        .expect("established FMP peer should expose a worker cipher");
    assert_eq!(reservation.counter, 0);
    assert_eq!(
        reservation.header,
        build_established_header(
            their_index,
            reservation.counter,
            snapshot.fmp_prepared().flags,
            payload_len,
        )
    );
    assert_eq!(
        reservation.predicted_bytes,
        ESTABLISHED_HEADER_SIZE + payload_len as usize + crate::noise::TAG_SIZE,
    );
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        1,
        "snapshot reservation should consume exactly one FMP counter"
    );
}

#[cfg(unix)]
#[test]
fn peer_runtime_route_snapshot_owns_path_seed_and_send_snapshot_inputs() {
    let node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(11);
    let link_id = LinkId::new(12);
    let remote_addr = TransportAddr::from_string("127.0.0.1:19191");
    let our_index = SessionIndex::new(13);
    let their_index = SessionIndex::new(14);
    let sender = make_test_fmp_session(&node.identity, &peer_full, [0x03; 8], [0x04; 8]);

    let mut registry = PeerLifecycleRegistry::default();
    let active_peer = ActivePeer::with_session(
        peer_identity,
        link_id,
        1_000,
        sender,
        our_index,
        their_index,
        transport_id,
        remote_addr.clone(),
        crate::transport::LinkStats::new(),
        true,
        &node.config.node.mmp,
        Some([0x04; 8]),
    );
    registry.insert_with_current_session_index(peer_addr, active_peer);

    let route_snapshot = registry
        .prepare_peer_runtime_route_snapshot(&peer_addr)
        .expect("peer runtime owner should prepare route snapshot");
    assert_eq!(route_snapshot.node_addr(), peer_addr);
    assert_eq!(route_snapshot.transport_id(), transport_id);
    assert_eq!(route_snapshot.remote_addr(), &remote_addr);

    let (packet_tx, _packet_rx) = packet_channel(4);
    let udp = UdpTransport::new(
        transport_id,
        None,
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(1234),
            ..Default::default()
        },
        packet_tx,
    );
    let transport = TransportHandle::Udp(udp);
    assert_eq!(
        route_snapshot.path_mtu(&transport),
        1234,
        "route snapshot should seed path MTU from its own transport/current-address pair"
    );

    let payload_len = 104;
    let send_snapshot = route_snapshot.prepare_send_snapshot(true, payload_len);
    assert_eq!(send_snapshot.node_addr(), peer_addr);
    assert_eq!(send_snapshot.fmp_prepared().transport_id, transport_id);
    assert_eq!(send_snapshot.fmp_prepared().remote_addr, remote_addr);
    assert_eq!(send_snapshot.fmp_prepared().their_index, their_index);
    assert_eq!(send_snapshot.fmp_prepared().payload_len, payload_len);
    assert_eq!(send_snapshot.fmp_prepared().flags & FLAG_CE, FLAG_CE);
    assert!(
        send_snapshot.fmp_worker_send_available(),
        "route snapshot should carry worker-send availability into send snapshots"
    );
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        0,
        "route/send snapshot preparation must not consume a Noise send counter"
    );

    let reservation = registry
        .reserve_peer_runtime_fmp_worker_send(&send_snapshot)
        .expect("peer runtime send snapshot should reserve the FMP worker send")
        .expect("established FMP peer should expose a worker cipher");
    assert_eq!(reservation.counter, 0);
    assert_eq!(
        reservation.header,
        build_established_header(
            their_index,
            reservation.counter,
            send_snapshot.fmp_prepared().flags,
            payload_len,
        )
    );
    assert_eq!(
        registry
            .get(&peer_addr)
            .and_then(|peer| peer.noise_session())
            .expect("peer session")
            .current_send_counter(),
        1,
        "route-owned send snapshot should reserve exactly one FMP counter"
    );
}

#[cfg(unix)]
#[test]
fn peer_runtime_route_decision_owns_next_hop_snapshot_weight_and_policy() {
    let local = Identity::generate();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(21);
    let remote_addr = TransportAddr::from_string("127.0.0.1:20202");
    let mut config = crate::config::Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_full.npub(),
        "udp",
        "127.0.0.1:20202",
    ));
    let mut node = Node::with_identity(local, config).expect("node");
    let active_peer = make_active_test_peer(
        &node,
        &peer_full,
        peer_identity,
        transport_id,
        LinkId::new(22),
        remote_addr.clone(),
        SessionIndex::new(23),
        SessionIndex::new(24),
    );
    node.peers
        .insert_with_current_session_index(peer_addr, active_peer);

    let decision = node
        .resolve_peer_runtime_route_decision(&peer_addr, 0x0102_0304)
        .expect("peer runtime route decision should resolve configured active peer");

    assert_eq!(decision.next_hop_addr(), peer_addr);
    assert_eq!(
        decision.scheduling_weight(),
        crate::node::encrypt_worker::EXPLICIT_PEER_SEND_WEIGHT,
        "route decision should carry configured-peer send weight"
    );
    assert!(
        !decision.direct_path_blocks_direct_payload(),
        "configured static UDP direct peer should keep direct payload eligible"
    );
    let snapshot = decision.peer_snapshot();
    assert_eq!(snapshot.node_addr(), peer_addr);
    assert_eq!(snapshot.transport_id(), transport_id);
    assert_eq!(snapshot.remote_addr(), &remote_addr);

    let missing_dest = make_node_addr(0xE1);
    assert!(matches!(
        node.resolve_peer_runtime_route_decision(&missing_dest, 0x0102_0304),
        Err(PeerRuntimeRouteDecisionError::NoRoute { dest_addr })
            if dest_addr == missing_dest
    ));
}

#[test]
fn local_send_failures_own_peer_scoped_fast_dead_clear_and_expiry() {
    let failed_peer = make_node_addr(0xA1);
    let quiet_peer = make_node_addr(0xA2);
    let now = std::time::Instant::now();
    let dead_timeout = std::time::Duration::from_secs(30);
    let fast_dead_timeout = std::time::Duration::from_secs(5);
    let route_error = Err(crate::transport::TransportError::SendFailed(
        "No route to host (os error 65)".to_string(),
    ));

    let mut failures = LocalSendFailures::default();
    failures.note_send_outcome(&failed_peer, &route_error, now);

    assert!(failures.contains_key(&failed_peer));
    assert!(!failures.contains_key(&quiet_peer));
    assert_eq!(
        failures.dead_timeout_for_peer(&failed_peer, now, dead_timeout, fast_dead_timeout),
        fast_dead_timeout
    );
    assert_eq!(
        failures.dead_timeout_for_peer(&quiet_peer, now, dead_timeout, fast_dead_timeout),
        dead_timeout,
        "local route failure must remain scoped to the peer whose send failed"
    );

    let non_local_error = Err(crate::transport::TransportError::SendFailed(
        "connection refused".to_string(),
    ));
    failures.note_send_outcome(&quiet_peer, &non_local_error, now);
    assert!(
        !failures.contains_key(&quiet_peer),
        "non-local send errors must not create a fast-dead route signal"
    );

    failures.note_send_outcome(&failed_peer, &Ok(1), now);
    assert!(
        !failures.contains_key(&failed_peer),
        "successful sends must clear that peer's local route failure signal"
    );

    failures.record_failure(failed_peer, now);
    let later = now + std::time::Duration::from_secs(4);
    failures.purge_expired(later);
    assert!(!failures.contains_key(&failed_peer));
}

#[test]
fn session_direct_degradation_owns_hold_extension_expiry_and_clear() {
    let dest = make_node_addr(0xB1);
    let other = make_node_addr(0xB2);
    let hold_ms = 20_000;
    let mut degradation = SessionDirectDegradation::default();

    assert!(degradation.mark_degraded(dest, 1_000, hold_ms));
    assert!(degradation.is_degraded(&dest, 20_999));
    assert!(
        !degradation.mark_degraded(dest, 2_000, hold_ms),
        "marking an already-degraded direct path should extend the hold without reporting a new transition"
    );
    assert!(degradation.is_degraded(&dest, 21_999));
    assert!(
        !degradation.is_degraded(&other, 21_999),
        "direct degradation must remain scoped to the destination that produced bad session evidence"
    );
    assert!(
        !degradation.is_degraded(&dest, 22_000),
        "the owner must expire and remove stale degradation holds"
    );
    assert!(
        !degradation.clear(&dest),
        "expired degradation state should already be removed"
    );

    assert!(degradation.mark_degraded(dest, 30_000, hold_ms));
    assert!(degradation.clear(&dest));
    assert!(!degradation.is_degraded(&dest, 30_000));
}

#[tokio::test]
async fn local_route_failure_for_one_peer_does_not_fast_dead_unrelated_direct_peer() {
    let local_identity = Identity::generate();
    let quiet_identity = Identity::generate();
    let failed_identity = Identity::generate();
    let quiet_config = crate::config::PeerConfig {
        npub: quiet_identity.npub(),
        alias: Some("quiet-lan-peer".to_string()),
        addresses: vec![crate::config::PeerAddress::with_priority(
            "udp",
            "198.51.100.57:51820",
            1,
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let quiet_peer = PeerIdentity::from_npub(&quiet_config.npub).expect("quiet peer identity");
    let quiet_addr = *quiet_peer.node_addr();
    let failed_peer =
        PeerIdentity::from_pubkey(failed_identity.pubkey_full().x_only_public_key().0);
    let failed_addr = *failed_peer.node_addr();

    let mut config = Config::new();
    config.peers.push(quiet_config);
    let session = make_test_fmp_session(&local_identity, &quiet_identity, [1; 8], [2; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");
    node.config.node.heartbeat_interval_secs = 2;
    node.config.node.link_dead_timeout_secs = 30;
    node.config.node.fast_link_dead_timeout_secs = 5;

    let mut quiet_active = ActivePeer::with_session(
        quiet_peer,
        LinkId::new(7),
        0,
        session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("198.51.100.57:51820"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    quiet_active.mmp_mut().expect("mmp").receiver.record_recv(
        1,
        100,
        64,
        false,
        std::time::Instant::now() - std::time::Duration::from_secs(6),
    );
    node.peers.insert(quiet_addr, quiet_active);

    // Simulate a route-unavailable send to some other peer. The quiet peer
    // has exceeded the fast timeout, but not the normal link-dead timeout.
    node.local_send_failures
        .record_failure(failed_addr, std::time::Instant::now());

    node.check_link_heartbeats().await;

    assert!(
        node.peers.contains_key(&quiet_addr),
        "a local route failure for {} must not demote unrelated healthy direct peer {}",
        failed_addr,
        quiet_addr
    );
    assert!(
        !node.retry_pending.contains_key(&quiet_addr),
        "unrelated local route failures must not schedule direct reconnect for the quiet peer"
    );
}

#[test]
fn fmp_bulk_classifier_detects_established_session_datagrams() {
    let src = make_node_addr(1);
    let dst = make_node_addr(2);
    let fsp_payload = crate::node::session_wire::build_fsp_header(7, 0, 0).to_vec();
    let datagram = crate::protocol::SessionDatagram::new(src, dst, fsp_payload);
    assert!(fmp_plaintext_is_bulk_session_datagram(&datagram.encode()));
    let traffic = classify_fmp_plaintext_traffic(&datagram.encode());
    assert!(traffic.bulk_endpoint_data);
    assert!(
        !traffic.drop_on_backpressure,
        "encrypted FSP bulk may carry TCP endpoint data, so the generic FMP path must not drop it"
    );

    let coords_payload =
        crate::node::session_wire::build_fsp_header(8, crate::node::session_wire::FSP_FLAG_CP, 0)
            .to_vec();
    let coords_datagram = crate::protocol::SessionDatagram::new(src, dst, coords_payload);
    assert!(
        !fmp_plaintext_is_bulk_session_datagram(&coords_datagram.encode()),
        "coordinate-carrying session packets warm fallback routes and must stay in the control lane"
    );
    let traffic = classify_fmp_plaintext_traffic(&coords_datagram.encode());
    assert!(!traffic.bulk_endpoint_data);
    assert!(!traffic.drop_on_backpressure);

    let heartbeat = [crate::protocol::LinkMessageType::Heartbeat.to_byte()];
    assert!(!fmp_plaintext_is_bulk_session_datagram(&heartbeat));

    let setup_prefix = crate::node::session_wire::build_fsp_handshake_prefix(
        crate::node::session_wire::FSP_PHASE_MSG1,
        0,
    );
    let setup_datagram = crate::protocol::SessionDatagram::new(src, dst, setup_prefix.to_vec());
    assert!(!fmp_plaintext_is_bulk_session_datagram(
        &setup_datagram.encode()
    ));
}

#[test]
fn endpoint_payload_tcp_classifier_handles_common_ip_packets() {
    let mut ipv4_tcp = [0u8; 20];
    ipv4_tcp[0] = 0x45;
    ipv4_tcp[9] = 6;
    assert!(endpoint_payload_is_tcp(&ipv4_tcp));

    let mut ipv4_udp = ipv4_tcp;
    ipv4_udp[9] = 17;
    assert!(!endpoint_payload_is_tcp(&ipv4_udp));

    let mut ipv4_tcp_with_options = [0u8; 24];
    ipv4_tcp_with_options[0] = 0x46;
    ipv4_tcp_with_options[9] = 6;
    assert!(endpoint_payload_is_tcp(&ipv4_tcp_with_options));

    let mut ipv6_tcp = [0u8; 40];
    ipv6_tcp[0] = 0x60;
    ipv6_tcp[6] = 6;
    assert!(endpoint_payload_is_tcp(&ipv6_tcp));

    let mut ipv6_udp = ipv6_tcp;
    ipv6_udp[6] = 17;
    assert!(!endpoint_payload_is_tcp(&ipv6_udp));

    let mut ipv6_hop_tcp = vec![0u8; 48];
    ipv6_hop_tcp[0] = 0x60;
    ipv6_hop_tcp[6] = 0;
    ipv6_hop_tcp[40] = 6;
    ipv6_hop_tcp[41] = 0;
    assert!(endpoint_payload_is_tcp(&ipv6_hop_tcp));

    let mut ipv6_frag_tcp = vec![0u8; 48];
    ipv6_frag_tcp[0] = 0x60;
    ipv6_frag_tcp[6] = 44;
    ipv6_frag_tcp[40] = 6;
    assert!(endpoint_payload_is_tcp(&ipv6_frag_tcp));

    assert!(!endpoint_payload_is_tcp(&[]));
    assert!(!endpoint_payload_is_tcp(&[0x60; 8]));
}

#[test]
fn endpoint_payload_traffic_classifier_prioritizes_control_sized_packets() {
    fn ipv6_tcp_packet(flags: u8, tcp_payload_len: usize) -> Vec<u8> {
        let tcp_len = 20 + tcp_payload_len;
        let mut packet = vec![0u8; 40 + tcp_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
        packet[6] = 6;
        packet[40 + 12] = 5 << 4;
        packet[40 + 13] = flags;
        packet
    }

    let tcp_ack_packet = ipv6_tcp_packet(0x10, 0);
    let tcp_ack = classify_endpoint_payload(&tcp_ack_packet);
    assert!(!tcp_ack.bulk_endpoint_data);
    assert!(!tcp_ack.drop_on_backpressure);
    assert_eq!(
        endpoint_command_lane_for_payload(&tcp_ack_packet),
        EndpointCommandLane::Priority
    );

    let tcp_syn_packet = ipv6_tcp_packet(0x02, 0);
    let tcp_syn = classify_endpoint_payload(&tcp_syn_packet);
    assert!(!tcp_syn.bulk_endpoint_data);
    assert!(!tcp_syn.drop_on_backpressure);
    assert_eq!(
        endpoint_command_lane_for_payload(&tcp_syn_packet),
        EndpointCommandLane::Priority
    );

    let tiny_tcp_data_packet = ipv6_tcp_packet(0x18, 64);
    let tiny_tcp_data = classify_endpoint_payload(&tiny_tcp_data_packet);
    assert!(!tiny_tcp_data.bulk_endpoint_data);
    assert!(!tiny_tcp_data.drop_on_backpressure);
    assert_eq!(
        endpoint_command_lane_for_payload(&tiny_tcp_data_packet),
        EndpointCommandLane::Priority
    );

    let bulk_tcp_data_packet = ipv6_tcp_packet(0x18, 512);
    let bulk_tcp_data = classify_endpoint_payload(&bulk_tcp_data_packet);
    assert!(bulk_tcp_data.bulk_endpoint_data);
    assert!(!bulk_tcp_data.drop_on_backpressure);
    assert_eq!(
        endpoint_command_lane_for_payload(&bulk_tcp_data_packet),
        EndpointCommandLane::Bulk
    );

    let mut icmpv6_packet = vec![0u8; 48];
    icmpv6_packet[0] = 0x60;
    icmpv6_packet[4..6].copy_from_slice(&8u16.to_be_bytes());
    icmpv6_packet[6] = 58;
    let icmpv6 = classify_endpoint_payload(&icmpv6_packet);
    assert!(!icmpv6.bulk_endpoint_data);
    assert!(!icmpv6.drop_on_backpressure);
    assert_eq!(
        endpoint_command_lane_for_payload(&icmpv6_packet),
        EndpointCommandLane::Priority
    );

    let mut udp_packet = vec![0u8; 48];
    udp_packet[0] = 0x60;
    udp_packet[4..6].copy_from_slice(&8u16.to_be_bytes());
    udp_packet[6] = 17;
    let udp = classify_endpoint_payload(&udp_packet);
    assert!(udp.bulk_endpoint_data);
    assert!(udp.drop_on_backpressure);
    assert_eq!(
        endpoint_command_lane_for_payload(&udp_packet),
        EndpointCommandLane::Bulk
    );
}

#[test]
fn endpoint_payload_traffic_classifier_prioritizes_ipv4_icmp_ping() {
    let mut icmpv4_packet = vec![0u8; 28];
    icmpv4_packet[0] = 0x45;
    icmpv4_packet[2..4].copy_from_slice(&28u16.to_be_bytes());
    icmpv4_packet[9] = 1;
    icmpv4_packet[20] = 8;

    let icmpv4 = classify_endpoint_payload(&icmpv4_packet);
    assert!(
        !icmpv4.bulk_endpoint_data,
        "IPv4 tunnel ping must use the reserved lane"
    );
    assert!(
        !icmpv4.drop_on_backpressure,
        "IPv4 tunnel ping is the interactive canary and must not be bulk-dropped"
    );
    assert_eq!(
        endpoint_command_lane_for_payload(&icmpv4_packet),
        EndpointCommandLane::Priority
    );
}

#[tokio::test]
async fn link_dead_recent_endpoint_path_reprobes_without_traversal_cooldown() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .with_seen_at_ms(10),
        ],
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
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let mut active = ActivePeer::new(peer, LinkId::new(7), 0);
    active.set_current_addr(
        transport_id,
        &crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
    );
    node.peers.insert(peer_addr, active);

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    node.nostr_discovery = Some(bootstrap.clone());
    node.config.node.heartbeat_interval_secs = 10;
    node.config.node.link_dead_timeout_secs = 30;
    node.config.node.fast_link_dead_timeout_secs = 5;

    let recent_path_timeout = node
        .traversal_path_link_dead_timeout(
            &peer_addr,
            std::time::Duration::from_secs(node.config.node.link_dead_timeout_secs),
            std::time::Duration::from_secs(node.config.node.fast_link_dead_timeout_secs),
        )
        .expect("recent endpoint path should get bounded liveness timeout");
    assert_eq!(recent_path_timeout, std::time::Duration::from_secs(22));

    node.record_link_dead_path_failure(&peer_addr, 1_000).await;

    assert!(
        bootstrap.cooldown_until(&peer_config.npub, 1_000).is_none(),
        "one transient link-dead event should not suppress direct traversal"
    );

    node.schedule_link_dead_reprobe(peer_addr, 1_000);
    let state = node
        .retry_pending
        .get(&peer_addr)
        .expect("link-dead reconnect should seed retry state");
    assert!(state.reconnect);
    assert_eq!(state.peer_config.npub, peer_config.npub);
    assert_eq!(state.retry_count, 0);
    assert!(
        (3_000..=8_000).contains(&state.retry_after_ms),
        "link-dead retry should stay quick but jittered, got {}",
        state.retry_after_ms
    );

    for now_ms in [2_000, 3_000, 4_000, 5_000] {
        node.record_link_dead_path_failure(&peer_addr, now_ms).await;
    }

    assert!(
        bootstrap.cooldown_until(&peer_config.npub, 5_000).is_none(),
        "repeated link-dead endpoint paths should not install peer traversal cooldown"
    );
    let state = node
        .retry_pending
        .get(&peer_addr)
        .expect("threshold link-dead penalty should preserve retry state");
    let first_retry_after_ms = state.retry_after_ms;
    assert!(
        (3_000..=8_000).contains(&first_retry_after_ms),
        "link-dead diagnostics must not push retry behind traversal cooldown"
    );

    node.schedule_link_dead_reprobe(peer_addr, 5_000);
    let state = node
        .retry_pending
        .get(&peer_addr)
        .expect("reconnect should preserve cooled-down retry state");
    assert!(
        (7_000..=12_000).contains(&state.retry_after_ms),
        "each link-dead removal should make direct probing eligible again quickly"
    );
    assert_eq!(state.retry_count, 0);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn proven_recent_endpoint_path_uses_bounded_dead_timeout() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.peers.push(peer_config);
    let session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");
    node.config.node.heartbeat_interval_secs = 10;
    node.config.node.link_dead_timeout_secs = 30;
    node.config.node.fast_link_dead_timeout_secs = 5;
    let mut active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    active.mmp_mut().expect("mmp").receiver.record_recv(
        1,
        100,
        64,
        false,
        std::time::Instant::now() - std::time::Duration::from_secs(23),
    );
    node.peers.insert(peer_addr, active);

    node.check_link_heartbeats().await;

    assert!(
        node.peers.contains_key(&peer_addr),
        "link-dead should keep the authenticated peer identity"
    );
    assert!(
        !node.get_peer(&peer_addr).expect("peer").is_healthy(),
        "a proven traversal/recent path at 23s silence should use the bounded 22s liveness window, not the 30s normal dead timeout"
    );
    assert!(
        node.retry_pending.contains_key(&peer_addr),
        "bounded traversal liveness should schedule direct reprobe"
    );
}

#[tokio::test]
async fn link_dead_after_rx_loop_timeout_does_not_cool_down_traversal_path() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).expect("node");
    node.config.node.link_dead_timeout_secs = 30;

    let mut active = ActivePeer::new(peer, LinkId::new(7), 0);
    active.set_current_addr(
        TransportId::new(1),
        &crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
    );
    node.peers.insert(peer_addr, active);

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    node.nostr_discovery = Some(bootstrap.clone());
    node.mark_rx_loop_maintenance_timeout();

    for now_ms in [1_000, 2_000, 3_000, 4_000, 5_000] {
        node.record_link_dead_path_failure(&peer_addr, now_ms).await;
    }

    assert!(
        bootstrap.cooldown_until(&peer_config.npub, 5_000).is_none(),
        "local rx-loop stalls must not be counted as repeated bad traversal paths"
    );
    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "skipping traversal penalty must not seed cooldown retry state"
    );
}

#[tokio::test]
async fn link_dead_marks_direct_path_stale_and_preserves_queued_packets() {
    let local_identity = Identity::generate();
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
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let transit_identity = Identity::generate();
    let transit_peer = PeerIdentity::from_pubkey(transit_identity.pubkey());
    let transit_addr = *transit_peer.node_addr();

    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.peers.push(peer_config.clone());
    let link_session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let endpoint_session = make_test_fmp_session(&local_identity, &peer_identity, [3; 8], [4; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");
    node.config.node.heartbeat_interval_secs = 2;
    node.config.node.link_dead_timeout_secs = 30;
    node.config.node.fast_link_dead_timeout_secs = 5;

    let mut active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        link_session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    active.mmp_mut().expect("mmp").receiver.record_recv(
        1,
        100,
        64,
        false,
        std::time::Instant::now() - std::time::Duration::from_secs(31),
    );
    node.peers.insert(peer_addr, active);
    node.peers.insert(
        transit_addr,
        ActivePeer::new(transit_peer, LinkId::new(9), 0),
    );
    node.learn_reverse_route(peer_addr, transit_addr);

    node.sessions.insert(
        peer_addr,
        crate::node::session::SessionEntry::new(
            peer_addr,
            peer_identity.pubkey_full(),
            crate::node::session::EndToEndState::Established(endpoint_session),
            1_000,
            true,
        ),
    );
    node.pending_session_traffic
        .push_tun_packet(peer_addr, vec![1, 2, 3], usize::MAX, usize::MAX);
    node.pending_session_traffic.push_endpoint_data(
        peer_addr,
        crate::node::EndpointDataPayload::new(vec![4, 5, 6]),
        usize::MAX,
        usize::MAX,
    );

    node.check_link_heartbeats().await;

    assert!(
        node.peers.contains_key(&peer_addr),
        "link-dead should keep the authenticated peer identity"
    );
    assert!(
        node.get_peer(&peer_addr).expect("peer").can_send(),
        "link-dead should keep the stale direct path sendable for probes and late recovery"
    );
    assert!(
        !node.get_peer(&peer_addr).expect("peer").is_healthy(),
        "link-dead should remove the dead direct path from healthy-direct routing"
    );
    assert!(
        node.sessions
            .get(&peer_addr)
            .is_some_and(|entry| entry.is_established()),
        "link-dead should preserve the established FSP session so fallback can carry traffic immediately"
    );
    assert_eq!(
        node.pending_session_traffic
            .tun_packets_for(&peer_addr)
            .map(|queue| queue.len()),
        Some(1),
        "queued TUN packets should survive direct link teardown"
    );
    assert_eq!(
        node.pending_session_traffic
            .endpoint_data_for(&peer_addr)
            .map(|queue| queue.len()),
        Some(1),
        "queued endpoint data should survive direct link teardown"
    );
    assert!(
        node.retry_pending.contains_key(&peer_addr),
        "direct reprobe should still be scheduled"
    );
    assert!(
        node.pending_lookups.contains_key(&peer_addr),
        "fallback lookup should start while queued packets are preserved"
    );
    assert!(
        node.session_direct_path_is_degraded(&peer_addr, Node::now_ms()),
        "link-dead should mark payload routing away from the suspect direct path"
    );
    let fallback = node.find_next_hop(&peer_addr).expect("fallback route");
    assert_eq!(
        fallback.node_addr(),
        &transit_addr,
        "fallback route should carry payload traffic while direct remains probeable"
    );

    let first_retry_after = node
        .retry_pending
        .get(&peer_addr)
        .expect("direct reprobe should stay scheduled")
        .retry_after_ms;

    node.check_link_heartbeats().await;

    assert!(
        node.get_peer(&peer_addr).expect("peer").can_send(),
        "a stale path should remain probeable instead of flapping to reconnecting"
    );
    assert_eq!(
        node.retry_pending
            .get(&peer_addr)
            .expect("direct reprobe should stay scheduled")
            .retry_after_ms,
        first_retry_after,
        "stale direct paths should not be repeatedly link-dead demoted every maintenance tick"
    );
}

#[test]
fn reconnecting_auto_connect_peer_is_eligible_for_graph_session_warmup() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config);
    let mut node = Node::new(config).expect("node");

    let mut active = ActivePeer::new(peer, LinkId::new(7), 0);
    active.mark_reconnecting();
    node.peers.insert(peer_addr, active);

    assert!(
        node.should_warm_auto_connect_session(&peer_addr),
        "a reconnecting direct peer should still warm an end-to-end fallback session"
    );
    assert!(
        node.find_next_hop(&peer_addr).is_none(),
        "a reconnecting direct peer must not be selected as a data next-hop"
    );
}

#[tokio::test]
async fn link_dead_after_recent_rx_loop_timeout_defers_peer_removal() {
    let local_identity = Identity::generate();
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "203.0.113.9:2121", 1)
                .with_seen_at_ms(10),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.peers.push(peer_config);
    let session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");
    node.config.node.heartbeat_interval_secs = 2;
    node.config.node.link_dead_timeout_secs = 30;
    node.config.node.fast_link_dead_timeout_secs = 5;

    let mut active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    active.mmp_mut().expect("mmp").receiver.record_recv(
        1,
        100,
        64,
        false,
        std::time::Instant::now() - std::time::Duration::from_secs(31),
    );
    node.peers.insert(peer_addr, active);
    node.mark_rx_loop_maintenance_timeout();

    node.check_link_heartbeats().await;

    assert!(
        node.peers.contains_key(&peer_addr),
        "a local rx-loop stall is inconclusive and must not flap a direct peer to fallback"
    );
    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "deferring a locally suspect link-dead timeout should not schedule a direct reconnect"
    );
}

#[tokio::test]
async fn failed_heartbeat_send_does_not_suppress_next_probe() {
    let local_identity = Identity::generate();
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
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.peers.push(peer_config);
    let session = make_test_fmp_session(&local_identity, &peer_identity, [1; 8], [2; 8]);
    let mut node = Node::with_identity(local_identity, config).expect("node");
    node.config.node.heartbeat_interval_secs = 2;
    node.config.node.link_dead_timeout_secs = 30;

    let active = ActivePeer::with_session(
        peer,
        LinkId::new(7),
        0,
        session,
        crate::utils::index::SessionIndex::new(11),
        crate::utils::index::SessionIndex::new(12),
        TransportId::new(1),
        crate::transport::TransportAddr::from_string("203.0.113.9:2121"),
        crate::transport::LinkStats::new(),
        true,
        &crate::mmp::MmpConfig::default(),
        None,
    );
    node.peers.insert(peer_addr, active);

    node.check_link_heartbeats().await;

    assert!(
        node.peers
            .get(&peer_addr)
            .expect("peer should remain active")
            .last_heartbeat_sent()
            .is_none(),
        "a failed heartbeat send must stay eligible for the next heartbeat tick"
    );
}

#[test]
fn queue_active_fallback_direct_retries_seeds_configured_relayed_peer() {
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
    node.queue_active_fallback_direct_retries(&bootstrap);

    let state = node
        .retry_pending
        .get(&peer_addr)
        .expect("active fallback peer should get direct retry state");
    assert_eq!(state.peer_config.npub, peer_config.npub);
    assert_eq!(state.retry_count, 0);
    assert!(state.reconnect);
}

#[test]
fn queue_active_fallback_direct_retries_skips_non_reconnect_transit_peer() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: false,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config);
    let mut node = Node::new(config).expect("node");
    node.peers
        .insert(peer_addr, ActivePeer::new(peer, LinkId::new(7), 0));

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    node.queue_active_fallback_direct_retries(&bootstrap);

    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "transit peers with auto_reconnect=false must not enter the fast active fallback retry loop"
    );
}

#[tokio::test]
async fn process_pending_retries_drops_non_reconnect_active_direct_refresh_state() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority("udp", "nat", 1)],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: false,
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

    let mut state = super::super::retry::RetryState::new(peer_config);
    state.retry_after_ms = 0;
    state.reconnect = true;
    node.retry_pending.insert(peer_addr, state);

    node.process_pending_retries(1_000).await;

    assert!(
        !node.retry_pending.contains_key(&peer_addr),
        "stale fast retry state for a non-reconnect active transit peer should be dropped instead of refiring every tick"
    );
}

#[test]
fn stale_udp_nostr_peer_without_static_addresses_keeps_direct_retry() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: Vec::new(),
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

    let transport_id = TransportId::new(1);
    let (packet_tx, _packet_rx) = packet_channel(64);
    let udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig::default(),
        packet_tx,
    );
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let mut active = ActivePeer::new(peer, LinkId::new(7), 0);
    active.set_current_addr(
        transport_id,
        &TransportAddr::from_string("203.0.113.24:51820"),
    );
    node.peers.insert(peer_addr, active);

    assert!(
        node.active_peer_should_keep_direct_retry(&peer_addr, &peer_config),
        "a stale UDP peer with only Nostr/NAT discovery must keep probing direct before link-dead"
    );
}

#[test]
fn stale_udp_peer_reuses_current_addr_after_traversal_transport_removed() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: Vec::new(),
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.node.discovery.nostr.enabled = true;
    config.peers.push(peer_config);
    let mut node = Node::new(config).expect("node");

    let live_udp_transport_id = TransportId::new(1);
    let old_traversal_transport_id = TransportId::new(99);
    let (packet_tx, _packet_rx) = packet_channel(64);
    let udp = UdpTransport::new(
        live_udp_transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig::default(),
        packet_tx,
    );
    node.transports
        .insert(live_udp_transport_id, TransportHandle::Udp(udp));

    let now_ms = Node::now_ms();
    let mut active = ActivePeer::new(peer, LinkId::new(7), now_ms);
    active.set_current_addr(
        old_traversal_transport_id,
        &TransportAddr::from_string("203.0.113.24:51820"),
    );
    active.mark_stale();
    node.peers.insert(peer_addr, active);

    let candidate = node
        .active_peer_current_udp_candidate(&peer_addr)
        .expect("stale UDP path should remain directly re-probeable");
    assert_eq!(candidate.transport, "udp");
    assert_eq!(candidate.addr, "203.0.113.24:51820");
    assert!(
        candidate.seen_at_ms.is_some(),
        "reused current endpoint should be treated as fresh"
    );
}

#[test]
fn fresh_udp_nostr_peer_without_static_addresses_skips_direct_retry() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: Vec::new(),
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

    let transport_id = TransportId::new(1);
    let (packet_tx, _packet_rx) = packet_channel(64);
    let udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig::default(),
        packet_tx,
    );
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let now_ms = Node::now_ms();
    let mut active = ActivePeer::new(peer, LinkId::new(7), now_ms);
    active.set_current_addr(
        transport_id,
        &TransportAddr::from_string("203.0.113.24:51820"),
    );
    node.peers.insert(peer_addr, active);

    assert!(
        !node.active_peer_should_keep_direct_retry(&peer_addr, &peer_config),
        "a fresh concrete UDP peer should not churn background traversal attempts"
    );
}

#[test]
fn reconnecting_static_udp_peer_keeps_direct_retry() {
    let peer_identity = Identity::generate();
    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::with_priority(
            "udp",
            "203.0.113.24:51820",
            1,
        )],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    };
    let peer = PeerIdentity::from_npub(&peer_config.npub).expect("peer identity");
    let peer_addr = *peer.node_addr();

    let mut config = Config::new();
    config.peers.push(peer_config.clone());
    let mut node = Node::new(config).expect("node");

    let transport_id = TransportId::new(1);
    let (packet_tx, _packet_rx) = packet_channel(64);
    let udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig::default(),
        packet_tx,
    );
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let now_ms = Node::now_ms();
    let mut active = ActivePeer::new(peer, LinkId::new(7), now_ms);
    active.set_current_addr(
        transport_id,
        &TransportAddr::from_string("203.0.113.24:51820"),
    );
    active.mark_reconnecting();
    node.peers.insert(peer_addr, active);

    assert!(
        node.active_peer_should_keep_direct_retry(&peer_addr, &peer_config),
        "a link-dead static UDP path is not fresh enough to suppress direct probing"
    );
}

#[test]
fn show_peers_reports_fallback_active_with_direct_probe_pending() {
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

    let bootstrap_transport = TransportId::new(77);
    node.bootstrap_transports.mark(bootstrap_transport);
    let mut active = ActivePeer::new(peer, LinkId::new(7), 0);
    active.set_current_addr(
        bootstrap_transport,
        &crate::transport::TransportAddr::from_string("fips"),
    );
    node.peers.insert(peer_addr, active);

    let mut retry = super::super::retry::RetryState::new(peer_config);
    retry.reconnect = true;
    retry.retry_after_ms = 42_000;
    node.retry_pending.insert(peer_addr, retry);

    let peers = crate::control::queries::show_peers(&node);
    let peer_json = peers["peers"]
        .as_array()
        .and_then(|peers| peers.first())
        .expect("one peer");
    assert_eq!(peer_json["transport_addr"], "fips");
    assert_eq!(peer_json["nostr_traversal"]["direct_probe_pending"], true);
    assert_eq!(
        peer_json["nostr_traversal"]["direct_probe_after_ms"],
        42_000
    );
}

#[tokio::test]
async fn process_pending_retries_allows_active_direct_refresh_at_peer_capacity() {
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
    node.set_max_peers(1);
    node.peers
        .insert(peer_addr, ActivePeer::new(peer, LinkId::new(7), 0));

    let mut state = super::super::retry::RetryState::new(peer_config);
    state.reconnect = true;
    state.retry_after_ms = 0;
    node.retry_pending.insert(peer_addr, state);

    node.process_pending_retries(1_000).await;

    let state = node
        .retry_pending
        .get(&peer_addr)
        .expect("active peer retry should remain scheduled after failed initiation");
    assert_eq!(
        state.retry_count, 0,
        "active direct refresh should stay on quick reprobe instead of peer backoff"
    );
    assert!(
        (3_000..=9_000).contains(&state.retry_after_ms),
        "active direct refresh should be quickly rescheduled, got {}",
        state.retry_after_ms
    );
}

#[test]
fn nostr_discovery_outbound_admission_atomic_roundtrip() {
    let bootstrap = NostrDiscovery::new_for_test();
    assert!(bootstrap.outbound_admission_allowed());
    bootstrap.set_outbound_admission(false);
    assert!(!bootstrap.outbound_admission_allowed());
    bootstrap.set_outbound_admission(true);
    assert!(bootstrap.outbound_admission_allowed());

    assert!(bootstrap.direct_refresh_admission_allowed());
    bootstrap.set_direct_refresh_admission(false);
    assert!(!bootstrap.direct_refresh_admission_allowed());
    bootstrap.set_direct_refresh_admission(true);
    assert!(bootstrap.direct_refresh_admission_allowed());
}

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
