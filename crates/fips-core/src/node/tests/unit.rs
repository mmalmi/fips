use super::*;
use crate::discovery::nostr::{BootstrapEvent, NostrDiscovery};
use crate::node::wire::{Msg1Header, build_msg2};
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
    let mut initiator =
        crate::noise::HandshakeState::new_initiator(local.keypair(), peer.pubkey_full());
    let mut responder = crate::noise::HandshakeState::new_responder(peer.keypair());
    initiator.set_local_epoch(local_epoch);
    responder.set_local_epoch(peer_epoch);
    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();
    initiator.into_session().unwrap()
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
        .connections
        .values()
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
        node.connections
            .values()
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
    node.bootstrap_transports.insert(bootstrap_id);

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

    node.bootstrap_transports.insert(bootstrap_id);

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

    // Test addr_to_link lookup
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

    // Verify peers_by_index is populated
    let our_index = peer.our_index().unwrap();
    assert_eq!(
        node.peers_by_index.get(&(transport_id, our_index.as_u32())),
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
        node.discovery_fallback_transit_blocked_peers
            .contains(&node_addr),
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
        node.discovery_fallback_transit_blocked_peers
            .contains(&node_addr),
        "nonconfigured peers accepted under open discovery should not be fallback transit"
    );
}

/// After `promote_connection`'s initial-promote branch the peer's
/// (transport_id, our_index) pair must be in
/// `decrypt_registered_sessions`. Unit tests construct `Node`
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
        node.decrypt_registered_sessions
            .contains(&(transport_id, our_index.as_u32())),
        "decrypt_registered_sessions must contain the new session after promote"
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
    node.peers_by_index
        .insert((transport_id, old_our_index.as_u32()), peer_node_addr);
    node.peers_by_index
        .insert((transport_id, pending_our_index.as_u32()), peer_node_addr);

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

/// `deregister_session_index` is used both for "peer is going away"
/// (where the connected UDP socket must be torn down) and for
/// "rekey drain completion — old session index retires while the
/// peer's NEW index keeps the connect()-ed 5-tuple". Pre-fix this
/// helper unconditionally cleared connected UDP, which would close
/// the per-peer kernel socket on every rekey on Linux. Validate
/// that when the peer still has another index in `peers_by_index`,
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
    // peers_by_index while the old index stays around until drain
    // completes).
    let index_new: u32 = 9999;
    node.peers_by_index
        .insert((transport_id, index_new), node_addr);

    // Deregister the OLD index. This is the rekey-drain pattern.
    // The peer is still present, the NEW index is still in
    // peers_by_index, so the per-peer connected UDP socket
    // (if any was installed) must NOT be torn down. The test
    // doesn't install a real ConnectedPeerSocket; instead it
    // checks the peer is still in `node.peers` and has a peer-
    // alive observable state.
    node.deregister_session_index((transport_id, index_old));

    assert!(
        !node.peers_by_index.contains_key(&(transport_id, index_old)),
        "old index must be evicted"
    );
    assert!(
        node.peers_by_index.contains_key(&(transport_id, index_new)),
        "new index must survive the deregister"
    );
    assert!(
        node.get_peer(&node_addr).is_some(),
        "peer must still be present after rekey-drain deregistration"
    );
    assert!(
        !node
            .decrypt_registered_sessions
            .contains(&(transport_id, index_old)),
        "old session must be evicted from decrypt_registered_sessions"
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

    // Verify first promotion populated peers_by_index
    let peer = node.get_peer(&node_addr).unwrap();
    let our_idx = peer.our_index().unwrap();
    assert_eq!(
        node.peers_by_index.get(&(transport_id, our_idx.as_u32())),
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
fn test_node_peers_by_index_tracking() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let node_addr = make_node_addr(42);

    // Allocate an index
    let index = node.index_allocator.allocate().unwrap();

    // Track in peers_by_index
    node.peers_by_index
        .insert((transport_id, index.as_u32()), node_addr);

    // Verify lookup
    let found = node.peers_by_index.get(&(transport_id, index.as_u32()));
    assert_eq!(found, Some(&node_addr));

    // Clean up
    node.peers_by_index.remove(&(transport_id, index.as_u32()));
    let _ = node.index_allocator.free(index);

    assert!(node.peers_by_index.is_empty());
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
    node.addr_to_link
        .insert((transport_id, pending_addr.clone()), pending_link_id);
    node.connections.insert(pending_link_id, pending_conn);
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
        "Auto-connect peers always get reconnect=true"
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

/// Test that auto-connect peers retry indefinitely (never exhaust).
#[test]
fn test_schedule_retry_auto_connect_never_exhausts() {
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

    // All attempts should keep the entry alive despite max_retries=2
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
    node.bootstrap_transports.insert(bootstrap_id);
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
    node.bootstrap_transports.insert(bootstrap_id);
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
    node.bootstrap_transports.insert(transport_id);
    node.bootstrap_transport_npubs
        .insert(transport_id, peer_npub.clone());

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
    node.bootstrap_transports.insert(bootstrap_id);

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
        node.connections
            .values()
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
        .connections
        .values()
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
    node.bootstrap_transports.insert(bootstrap_id);

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
    let conn = node.connections.values().next().unwrap();
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
    node.bootstrap_transports.insert(bootstrap_id);

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
        .connections
        .values()
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
    node.bootstrap_transports.insert(bootstrap_id);

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
    let conn = node.connections.values().next().unwrap();
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
    node.addr_to_link
        .insert((old_transport_id, old_addr.clone()), old_link_id);

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
    node.addr_to_link
        .insert((new_transport_id, new_addr.clone()), new_link_id);
    node.connections.insert(new_link_id, conn);
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
        node.addr_to_link.get(&(old_transport_id, old_addr.clone())),
        None
    );
    assert_eq!(
        node.addr_to_link
            .get(&(new_transport_id, new_addr.clone()))
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
        node.peers_by_index
            .get(&(new_transport_id, our_index.as_u32()))
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
    node.addr_to_link
        .insert((old_transport_id, old_addr.clone()), old_link_id);
    node.connections.insert(old_link_id, old_conn);
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
    node.addr_to_link
        .insert((new_transport_id, new_addr.clone()), new_link_id);
    node.connections.insert(new_link_id, new_conn);

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
    node.peers_by_index
        .insert((old_transport_id, old_our_index.as_u32()), peer_node_addr);

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
    node.connections.insert(new_link_id, new_conn);

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
    node.peers_by_index
        .insert((old_transport_id, old_our_index.as_u32()), peer_node_addr);

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
    node.connections.insert(new_link_id, new_conn);

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
    node.peers_by_index
        .insert((old_transport_id, old_our_index.as_u32()), peer_node_addr);
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
    node.addr_to_link
        .insert((old_transport_id, old_addr.clone()), old_link_id);

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
    node.addr_to_link
        .insert((new_transport_id, new_addr.clone()), new_link_id);
    node.connections.insert(new_link_id, new_conn);
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
        node.addr_to_link.get(&(old_transport_id, old_addr.clone())),
        None
    );
    assert_eq!(
        node.addr_to_link
            .get(&(new_transport_id, new_addr.clone()))
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
        node.peers_by_index
            .get(&(new_transport_id, our_index.as_u32()))
            .copied(),
        Some(peer_node_addr)
    );
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
    node.peers_by_index
        .insert((old_transport_id, old_our_index.as_u32()), peer_node_addr);
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
    node.addr_to_link
        .insert((old_transport_id, old_addr.clone()), old_link_id);

    let dial_transport_id = TransportId::new(2);
    let recv_transport_id = TransportId::new(3);
    let new_link_id = LinkId::new(11);
    let gateway_addr = TransportAddr::from_string("192.168.178.91:51830");
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
    node.addr_to_link
        .insert((dial_transport_id, gateway_addr.clone()), new_link_id);
    node.connections.insert(new_link_id, new_conn);
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
    node.addr_to_link
        .insert((transport_id, remote_addr.clone()), link_id);
    node.connections.insert(link_id, conn);
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
    node.connections.insert(link_id, conn);
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
    let now = std::time::Instant::now();
    let dead_timeout = std::time::Duration::from_secs(30);
    let fast_dead_timeout = std::time::Duration::from_secs(5);

    node.last_local_send_failure_at = Some(now);

    assert_eq!(
        node.local_send_failure_dead_timeout(now, dead_timeout, fast_dead_timeout),
        fast_dead_timeout
    );
    assert!(node.last_local_send_failure_at.is_some());

    assert_eq!(
        node.local_send_failure_dead_timeout(
            now + std::time::Duration::from_secs(4),
            dead_timeout,
            fast_dead_timeout,
        ),
        dead_timeout
    );
    assert!(
        node.last_local_send_failure_at.is_none(),
        "stale route failures must not keep compressing link-dead timeout"
    );
}

#[test]
fn fmp_bulk_classifier_detects_established_session_datagrams() {
    let src = make_node_addr(1);
    let dst = make_node_addr(2);
    let fsp_payload = crate::node::session_wire::build_fsp_header(7, 0, 0).to_vec();
    let datagram = crate::protocol::SessionDatagram::new(src, dst, fsp_payload);
    assert!(fmp_plaintext_is_bulk_session_datagram(&datagram.encode()));

    let coords_payload =
        crate::node::session_wire::build_fsp_header(8, crate::node::session_wire::FSP_FLAG_CP, 0)
            .to_vec();
    let coords_datagram = crate::protocol::SessionDatagram::new(src, dst, coords_payload);
    assert!(
        !fmp_plaintext_is_bulk_session_datagram(&coords_datagram.encode()),
        "coordinate-carrying session packets warm fallback routes and must not be discardable bulk"
    );

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
    node.pending_tun_packets
        .insert(peer_addr, std::collections::VecDeque::from([vec![1, 2, 3]]));
    node.pending_endpoint_data
        .insert(peer_addr, std::collections::VecDeque::from([vec![4, 5, 6]]));

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
        node.pending_tun_packets
            .get(&peer_addr)
            .map(std::collections::VecDeque::len),
        Some(1),
        "queued TUN packets should survive direct link teardown"
    );
    assert_eq!(
        node.pending_endpoint_data
            .get(&peer_addr)
            .map(std::collections::VecDeque::len),
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
    node.bootstrap_transports.insert(bootstrap_transport);
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
