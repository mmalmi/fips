use super::*;

async fn confirm_cross_connection_packets(
    a: &mut Node,
    a_rx: &mut PacketRx,
    b: &mut Node,
    b_rx: &mut PacketRx,
) {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            super::super::spanning_tree::process_node_packets(a, a_rx).await;
            super::super::spanning_tree::process_node_packets(b, b_rx).await;
            let a_peer = a.get_peer(b.node_addr()).unwrap();
            let b_peer = b.get_peer(a.node_addr()).unwrap();
            if a_peer.their_index() == b_peer.our_index()
                && b_peer.their_index() == a_peer.our_index()
                && a.pending_outbound.is_empty()
                && b.pending_outbound.is_empty()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("ordinary confirmation must align the established pair");
}

/// End-to-end test for the "restart with cached endpoint, no relay reachable"
/// flow that powers `RecentPeerEndpoints` in the nostr-vpn daemon.
///
/// Two nodes are wired up with Nostr discovery fully disabled — exactly the
/// state of a freshly-restarted daemon before it talks to any relay. Node A
/// is configured with B's exact UDP socket address as a static
/// `PeerConfig.addresses` entry (this is what nvpn feeds in from the
/// persisted recent-peers cache). `initiate_peer_connections` then drives
/// the handshake via `try_peer_addresses` → static dial — proving that the
/// relay-less reconnect path works end-to-end, not just on paper.
#[test]
fn test_static_address_handshake_without_nostr_discovery() {
    super::super::session::run_large_stack_async_test(
        "fips-static-address-handshake",
        static_address_handshake_without_nostr_discovery,
    );
}

async fn static_address_handshake_without_nostr_discovery() {
    use crate::Identity;
    use crate::config::{ConnectPolicy, PeerAddress, PeerConfig, UdpConfig};
    use crate::transport::udp::UdpTransport;
    use crate::transport::{TransportHandle, packet_channel};
    use tokio::time::Duration;

    let mut config_a = Config::new();
    config_a.node.discovery.nostr.enabled = false;
    config_a.node.discovery.lan.enabled = false;

    let mut config_b = Config::new();
    config_b.node.discovery.nostr.enabled = false;
    config_b.node.discovery.lan.enabled = false;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    // Wire up node B first so we know its UDP bind address.
    let transport_id = TransportId::new(1);
    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };
    let (packet_tx_b, packet_rx_b) = packet_channel(64);
    let mut transport_b = UdpTransport::new(transport_id, None, udp_config.clone(), packet_tx_b);
    transport_b.start_async().await.unwrap();
    let addr_b = transport_b.local_addr().unwrap();

    // Node A's static peer config: B's actual UDP address. This is
    // structurally identical to what the daemon hands FIPS at boot when
    // `recent_peers.json` is present and the relay path is cold.
    config_a.peers.push(PeerConfig {
        npub: identity_b.npub(),
        alias: None,
        addresses: vec![PeerAddress::new("udp", addr_b.to_string())],
        connect_policy: ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });

    let mut node_a = Node::with_identity(identity_a, config_a).unwrap();
    let mut node_b = Node::with_identity(identity_b, config_b).unwrap();

    let (packet_tx_a, packet_rx_a) = packet_channel(64);
    let mut transport_a = UdpTransport::new(transport_id, None, udp_config, packet_tx_a);
    transport_a.start_async().await.unwrap();

    node_a
        .transports
        .insert(transport_id, TransportHandle::Udp(transport_a));
    node_b
        .transports
        .insert(transport_id, TransportHandle::Udp(transport_b));
    node_a.packet_rx = Some(packet_rx_a);
    node_b.packet_rx = Some(packet_rx_b);
    node_a.state = NodeState::Running;
    node_b.state = NodeState::Running;

    // Kick off the static-address dial. This mirrors what
    // Node::start does at boot via initiate_peer_connections.
    node_a.initiate_peer_connections().await;

    // Run both rx loops just long enough for msg1 → msg2 → msg3 to settle.
    // 500ms is conservative for loopback; the existing handshake tests
    // use the same budget.
    let _ = tokio::time::timeout(Duration::from_millis(500), async {
        tokio::select! {
            _ = node_b.run_rx_loop() => {}
            _ = node_a.run_rx_loop() => {}
        }
    })
    .await;

    let peer_a_addr = *PeerIdentity::from_pubkey_full(node_a.identity.pubkey_full()).node_addr();
    let peer_b_addr = *PeerIdentity::from_pubkey_full(node_b.identity.pubkey_full()).node_addr();

    assert_eq!(
        node_a.peer_count(),
        1,
        "node A should reach node B using only the cached static UDP address"
    );
    assert_eq!(
        node_b.peer_count(),
        1,
        "node B should authenticate node A's static-only handshake"
    );
    assert!(node_a.get_peer(&peer_b_addr).is_some());
    assert!(node_b.get_peer(&peer_a_addr).is_some());

    for (_, t) in node_a.transports.iter_mut() {
        t.stop().await.ok();
    }
    for (_, t) in node_b.transports.iter_mut() {
        t.stop().await.ok();
    }
}

/// Integration test: simultaneous cross-connection (both nodes initiate).
///
/// Simulates the live scenario where both nodes have auto_connect to each other.
/// Both send msg1 simultaneously, creating a cross-connection that must be
/// resolved by the tie-breaker rule. Exercises the address-index fix that
/// allows inbound msg1 when an outbound link to the same address already exists.
#[tokio::test]
async fn test_cross_connection_both_initiate() {
    for queued_before_outbound in [false, true] {
        cross_connection_both_initiate(queued_before_outbound).await;
    }
}

async fn cross_connection_both_initiate(queued_before_outbound: bool) {
    use crate::config::UdpConfig;
    use crate::node::wire::{Msg1Header, Msg2Header, build_msg1};
    use crate::transport::udp::UdpTransport;
    use tokio::time::{Duration, timeout};

    // === Setup: Two nodes with UDP transports on localhost ===

    let mut node_a = make_node();
    let mut node_b = make_node();

    let transport_id_a = TransportId::new(1);
    let transport_id_b = TransportId::new(1);

    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };

    let (packet_tx_a, mut packet_rx_a) = packet_channel(64);
    let (packet_tx_b, mut packet_rx_b) = packet_channel(64);

    let mut transport_a = UdpTransport::new(transport_id_a, None, udp_config.clone(), packet_tx_a);
    let mut transport_b = UdpTransport::new(transport_id_b, None, udp_config, packet_tx_b);

    transport_a.start_async().await.unwrap();
    transport_b.start_async().await.unwrap();

    let addr_a = transport_a.local_addr().unwrap();
    let addr_b = transport_b.local_addr().unwrap();
    let remote_addr_b = TransportAddr::from_string(&addr_b.to_string());
    let remote_addr_a = TransportAddr::from_string(&addr_a.to_string());

    node_a
        .transports
        .insert(transport_id_a, TransportHandle::Udp(transport_a));
    node_b
        .transports
        .insert(transport_id_b, TransportHandle::Udp(transport_b));

    // Peer identities (must use full key for ECDH parity)
    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity.pubkey_full());
    let peer_b_node_addr = *peer_b_identity.node_addr();
    let peer_a_identity = PeerIdentity::from_pubkey_full(node_a.identity.pubkey_full());
    let peer_a_node_addr = *peer_a_identity.node_addr();

    // === Phase 1: Both nodes initiate handshakes (simulate auto_connect) ===

    let outbound_started_at = Node::now_ms();

    // Node A initiates to Node B
    let link_id_a_out = node_a.allocate_link_id();
    let mut conn_a = PeerConnection::outbound(link_id_a_out, peer_b_identity, outbound_started_at);
    let our_index_a = node_a.index_allocator.allocate().unwrap();
    let our_keypair_a = node_a.identity.keypair();
    let noise_msg1_a = conn_a
        .start_handshake(our_keypair_a, node_a.startup_epoch, outbound_started_at)
        .unwrap();
    conn_a.set_our_index(our_index_a);
    conn_a.set_transport_id(transport_id_a);
    conn_a.set_source_addr(remote_addr_b.clone());

    let wire_msg1_a = build_msg1(our_index_a, &noise_msg1_a);

    let link_a_out = Link::connectionless(
        link_id_a_out,
        transport_id_a,
        remote_addr_b.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node_a.links.insert(link_id_a_out, link_a_out);
    node_a
        .links
        .insert_addr((transport_id_a, remote_addr_b.clone()), link_id_a_out);
    node_a.peers.insert_connection(link_id_a_out, conn_a);
    node_a
        .pending_outbound
        .insert((transport_id_a, our_index_a.as_u32()), link_id_a_out);

    // Node B initiates to Node A
    let link_id_b_out = node_b.allocate_link_id();
    let mut conn_b = PeerConnection::outbound(link_id_b_out, peer_a_identity, outbound_started_at);
    let our_index_b = node_b.index_allocator.allocate().unwrap();
    let our_keypair_b = node_b.identity.keypair();
    let noise_msg1_b = conn_b
        .start_handshake(our_keypair_b, node_b.startup_epoch, outbound_started_at)
        .unwrap();
    conn_b.set_our_index(our_index_b);
    conn_b.set_transport_id(transport_id_b);
    conn_b.set_source_addr(remote_addr_a.clone());

    let wire_msg1_b = build_msg1(our_index_b, &noise_msg1_b);

    let link_b_out = Link::connectionless(
        link_id_b_out,
        transport_id_b,
        remote_addr_a.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node_b.links.insert(link_id_b_out, link_b_out);
    node_b
        .links
        .insert_addr((transport_id_b, remote_addr_a.clone()), link_id_b_out);
    node_b.peers.insert_connection(link_id_b_out, conn_b);
    node_b
        .pending_outbound
        .insert((transport_id_b, our_index_b.as_u32()), link_id_b_out);

    // Both send msg1 over UDP
    let transport = node_a.transports.get(&transport_id_a).unwrap();
    transport
        .send(&remote_addr_b, &wire_msg1_a)
        .await
        .expect("A send msg1");

    let transport = node_b.transports.get(&transport_id_b).unwrap();
    transport
        .send(&remote_addr_a, &wire_msg1_b)
        .await
        .expect("B send msg1");

    // === Phase 2: Both nodes receive the other's msg1 ===
    // Before the fix, address-index dispatch would reject these because
    // outbound links already exist for these addresses.

    // B receives A's msg1
    let mut packet_at_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("Timeout")
        .expect("Channel closed");
    // The transport can queue Msg1 before a control command starts our
    // outbound dial. Its reply is generated only when this handler runs.
    if queued_before_outbound {
        packet_at_b.timestamp_ms = outbound_started_at.saturating_sub(1);
    }
    node_b.handle_msg1(packet_at_b).await;

    // B should have promoted the inbound connection
    assert_eq!(
        node_b.peer_count(),
        1,
        "Node B should have 1 peer after processing A's msg1"
    );
    assert!(
        node_b.get_peer(&peer_a_node_addr).is_some(),
        "Node B should have peer A"
    );

    // A receives B's msg1
    let mut packet_at_a = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await
        .expect("Timeout")
        .expect("Channel closed");
    if queued_before_outbound {
        packet_at_a.timestamp_ms = outbound_started_at.saturating_sub(1);
    }
    node_a.handle_msg1(packet_at_a).await;

    // A should have promoted the inbound connection
    assert_eq!(
        node_a.peer_count(),
        1,
        "Node A should have 1 peer after processing B's msg1"
    );
    assert!(
        node_a.get_peer(&peer_b_node_addr).is_some(),
        "Node A should have peer B"
    );

    // A reconnect commonly races while the previous direct FSP carrier is
    // still marked degraded. That retained payload state must not make both
    // sides bypass deterministic cross-connection resolution for the freshly
    // authenticated inbound/outbound FMP handshake pair.
    if !queued_before_outbound {
        node_a.mark_session_direct_path_degraded(peer_b_node_addr, Node::now_ms());
        node_b.mark_session_direct_path_degraded(peer_a_node_addr, Node::now_ms());
    }
    assert!(
        node_a
            .get_peer(&peer_b_node_addr)
            .zip(node_a.get_connection(&link_id_a_out))
            .is_some_and(|(peer, conn)| {
                peer.handshake_msg2_generated_at()
                    .is_some_and(|generated_at| generated_at >= conn.started_at())
            }),
        "A retained inbound msg2 must causally follow its simultaneous outbound dial"
    );
    assert!(
        node_b
            .get_peer(&peer_a_node_addr)
            .zip(node_b.get_connection(&link_id_b_out))
            .is_some_and(|(peer, conn)| {
                peer.handshake_msg2_generated_at()
                    .is_some_and(|generated_at| generated_at >= conn.started_at())
            }),
        "B retained inbound msg2 must causally follow its simultaneous outbound dial"
    );

    // === Phase 3: Both nodes receive msg2 responses ===
    // The msg2 was sent during handle_msg1 processing. When handle_msg2
    // processes it, it will detect the cross-connection and resolve.

    // A receives B's msg2 (response to A's original msg1)
    let msg2_at_a = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await
        .expect("Timeout waiting for msg2 at A")
        .expect("Channel closed");
    node_a.handle_msg2(msg2_at_a).await;

    // B receives A's msg2 (response to B's original msg1)
    let msg2_at_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("Timeout waiting for msg2 at B")
        .expect("Channel closed");
    node_b.handle_msg2(msg2_at_b).await;

    // === Verification ===
    // Both nodes should have exactly 1 peer each after cross-connection resolution
    assert_eq!(
        node_a.peer_count(),
        1,
        "Node A should have exactly 1 peer after cross-connection"
    );
    assert_eq!(
        node_b.peer_count(),
        1,
        "Node B should have exactly 1 peer after cross-connection"
    );

    let peer_b_on_a = node_a
        .get_peer(&peer_b_node_addr)
        .expect("A should have peer B");
    let peer_a_on_b = node_b
        .get_peer(&peer_a_node_addr)
        .expect("B should have peer A");

    assert!(peer_b_on_a.has_session(), "Peer B on A should have session");
    assert!(peer_a_on_b.has_session(), "Peer A on B should have session");
    assert!(peer_b_on_a.can_send(), "Peer B on A should be sendable");
    assert!(peer_a_on_b.can_send(), "Peer A on B should be sendable");
    assert_eq!(
        peer_b_on_a.their_index(),
        peer_a_on_b.our_index(),
        "A must send to B's installed receiver index after degraded simultaneous reconnect"
    );
    assert_eq!(
        peer_a_on_b.their_index(),
        peer_b_on_a.our_index(),
        "B must send to A's installed receiver index after degraded simultaneous reconnect"
    );

    // Repeat the simultaneous dial with an already-established carrier that
    // liveness has marked link-dead. This is the roaming ordering: both sides
    // retain the stale peer/FSP session for fallback continuity, then race a
    // same-tuple direct refresh when the underlay returns.
    node_a.remove_link_dead_peer(&peer_b_node_addr);
    node_b.remove_link_dead_peer(&peer_a_node_addr);
    node_a
        .initiate_connection(transport_id_a, remote_addr_b.clone(), peer_b_identity)
        .await
        .expect("A starts same-path recovery");
    node_b
        .initiate_connection(transport_id_b, remote_addr_a.clone(), peer_a_identity)
        .await
        .expect("B starts same-path recovery");

    let recovery_msg1_at_b = timeout(Duration::from_secs(1), async {
        loop {
            let packet = packet_rx_b.recv().await.expect("B channel open");
            if Msg1Header::parse(packet.data.as_slice()).is_some() {
                break packet;
            }
        }
    })
    .await
    .expect("B should receive A's recovery msg1");
    node_b.handle_msg1(recovery_msg1_at_b).await;

    let recovery_msg1_at_a = timeout(Duration::from_secs(1), async {
        loop {
            let packet = packet_rx_a.recv().await.expect("A channel open");
            if Msg1Header::parse(packet.data.as_slice()).is_some() {
                break packet;
            }
        }
    })
    .await
    .expect("A should receive B's recovery msg1");
    node_a.handle_msg1(recovery_msg1_at_a).await;

    let recovery_msg2_at_a = timeout(Duration::from_secs(1), async {
        loop {
            let packet = packet_rx_a.recv().await.expect("A channel open");
            if Msg2Header::parse(packet.data.as_slice()).is_some() {
                break packet;
            }
        }
    })
    .await
    .expect("A should receive B's recovery msg2");
    node_a.handle_msg2(recovery_msg2_at_a).await;

    let recovery_msg2_at_b = timeout(Duration::from_secs(1), async {
        loop {
            let packet = packet_rx_b.recv().await.expect("B channel open");
            if Msg2Header::parse(packet.data.as_slice()).is_some() {
                break packet;
            }
        }
    })
    .await
    .expect("B should receive A's recovery msg2");
    node_b.handle_msg2(recovery_msg2_at_b).await;

    confirm_cross_connection_packets(&mut node_a, &mut packet_rx_a, &mut node_b, &mut packet_rx_b)
        .await;
    // The unused opposite inbound half has no confirming sender. Expire that
    // candidate without sleeping, preserving the established winning pair.
    for node in [&mut node_a, &mut node_b] {
        let unused = node
            .peers
            .connection_iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in unused {
            let conn = node.peers.get_connection_mut(&id).unwrap();
            assert!(!conn.is_outbound() && conn.has_session());
            conn.touch(1);
        }
        node.check_timeouts().await;
    }

    let recovered_b_on_a = node_a
        .get_peer(&peer_b_node_addr)
        .expect("A should retain recovered B");
    let recovered_a_on_b = node_b
        .get_peer(&peer_a_node_addr)
        .expect("B should retain recovered A");
    assert_eq!(
        recovered_b_on_a.their_index(),
        recovered_a_on_b.our_index(),
        "A recovery sender index must match B's installed receiver"
    );
    assert_eq!(
        recovered_a_on_b.their_index(),
        recovered_b_on_a.our_index(),
        "B recovery sender index must match A's installed receiver"
    );
    assert_eq!(node_a.connection_count(), 0);
    assert_eq!(node_b.connection_count(), 0);

    // Clean up transports
    for (_, t) in node_a.transports.iter_mut() {
        t.stop().await.ok();
    }
    for (_, t) in node_b.transports.iter_mut() {
        t.stop().await.ok();
    }
}

#[tokio::test]
async fn test_late_static_outbound_resend_completes_after_opposite_direction_promotion() {
    use crate::config::UdpConfig;
    use crate::node::wire::{Msg1Header, Msg2Header, build_msg1};
    use crate::transport::udp::UdpTransport;
    use tokio::time::{Duration, timeout};

    let (identity_a, identity_b) = loop {
        let a = Identity::generate();
        let b = Identity::generate();
        if a.node_addr() < b.node_addr() {
            break (a, b);
        }
    };

    let mut node_a = Node::with_identity(identity_a, Config::new()).unwrap();
    let mut node_b = Node::with_identity(identity_b, Config::new()).unwrap();

    let transport_id_a = TransportId::new(1);
    let transport_id_b = TransportId::new(1);
    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };

    let (packet_tx_a, mut packet_rx_a) = packet_channel(64);
    let (packet_tx_b, mut packet_rx_b) = packet_channel(64);

    let mut transport_a = UdpTransport::new(transport_id_a, None, udp_config.clone(), packet_tx_a);
    let mut transport_b = UdpTransport::new(transport_id_b, None, udp_config, packet_tx_b);

    transport_a.start_async().await.unwrap();
    transport_b.start_async().await.unwrap();

    let addr_a = transport_a.local_addr().unwrap();
    let addr_b = transport_b.local_addr().unwrap();
    let remote_addr_a = TransportAddr::from_string(&addr_a.to_string());
    let remote_addr_b = TransportAddr::from_string(&addr_b.to_string());

    node_a
        .transports
        .insert(transport_id_a, TransportHandle::Udp(transport_a));
    node_b
        .transports
        .insert(transport_id_b, TransportHandle::Udp(transport_b));

    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity.pubkey_full());
    let peer_b_node_addr = *peer_b_identity.node_addr();
    let peer_a_identity = PeerIdentity::from_pubkey_full(node_a.identity.pubkey_full());
    let peer_a_node_addr = *peer_a_identity.node_addr();

    let link_id_a_out = node_a.allocate_link_id();
    let mut conn_a = PeerConnection::outbound(link_id_a_out, peer_b_identity, 1_000);
    let our_index_a = node_a.index_allocator.allocate().unwrap();
    let noise_msg1_a = conn_a
        .start_handshake(node_a.identity.keypair(), node_a.startup_epoch, 1_000)
        .unwrap();
    conn_a.set_our_index(our_index_a);
    conn_a.set_transport_id(transport_id_a);
    conn_a.set_source_addr(remote_addr_b.clone());
    let wire_msg1_a = build_msg1(our_index_a, &noise_msg1_a);
    conn_a.set_handshake_msg1(wire_msg1_a, 2_000);

    let link_a_out = Link::connectionless(
        link_id_a_out,
        transport_id_a,
        remote_addr_b.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node_a.links.insert(link_id_a_out, link_a_out);
    node_a
        .links
        .insert_addr((transport_id_a, remote_addr_b.clone()), link_id_a_out);
    node_a.peers.insert_connection(link_id_a_out, conn_a);
    node_a
        .pending_outbound
        .insert((transport_id_a, our_index_a.as_u32()), link_id_a_out);

    let link_id_b_out = node_b.allocate_link_id();
    let mut conn_b = PeerConnection::outbound(link_id_b_out, peer_a_identity, 1_100);
    let our_index_b = node_b.index_allocator.allocate().unwrap();
    let noise_msg1_b = conn_b
        .start_handshake(node_b.identity.keypair(), node_b.startup_epoch, 1_100)
        .unwrap();
    conn_b.set_our_index(our_index_b);
    conn_b.set_transport_id(transport_id_b);
    conn_b.set_source_addr(remote_addr_a.clone());
    let wire_msg1_b = build_msg1(our_index_b, &noise_msg1_b);
    conn_b.set_handshake_msg1(wire_msg1_b.clone(), 2_100);

    let link_b_out = Link::connectionless(
        link_id_b_out,
        transport_id_b,
        remote_addr_a.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node_b.links.insert(link_id_b_out, link_b_out);
    node_b
        .links
        .insert_addr((transport_id_b, remote_addr_a.clone()), link_id_b_out);
    node_b.peers.insert_connection(link_id_b_out, conn_b);
    node_b
        .pending_outbound
        .insert((transport_id_b, our_index_b.as_u32()), link_id_b_out);

    node_b
        .transports
        .get(&transport_id_b)
        .unwrap()
        .send(&remote_addr_a, &wire_msg1_b)
        .await
        .expect("B send msg1");

    let packet_at_a = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await
        .expect("A should receive B msg1")
        .expect("A channel open");
    assert!(Msg1Header::parse(packet_at_a.data.as_slice()).is_some());
    node_a.handle_msg1(packet_at_a).await;

    let msg2_at_b = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("B should receive msg2 for its outbound")
        .expect("B channel open");
    assert!(Msg2Header::parse(msg2_at_b.data.as_slice()).is_some());
    node_b.handle_msg2(msg2_at_b).await;

    assert_eq!(node_a.peer_count(), 1);
    assert_eq!(node_b.peer_count(), 1);
    assert_eq!(
        node_a.connection_count(),
        1,
        "A's lost static outbound should still be waiting for msg2"
    );

    node_a.resend_pending_handshakes(2_000).await;

    let resent_msg1_at_b = timeout(Duration::from_secs(1), async {
        loop {
            let packet = packet_rx_b.recv().await.expect("B channel open");
            if Msg1Header::parse(packet.data.as_slice()).is_some() {
                break packet;
            }
        }
    })
    .await
    .expect("B should receive A's resent static msg1");
    node_b.handle_msg1(resent_msg1_at_b).await;

    let late_msg2_at_a = timeout(Duration::from_secs(1), async {
        loop {
            let packet = packet_rx_a.recv().await.expect("A channel open");
            if Msg2Header::parse(packet.data.as_slice()).is_some() {
                break packet;
            }
        }
    })
    .await
    .expect("A should receive msg2 for the resent static msg1");
    node_a.handle_msg2(late_msg2_at_a).await;

    confirm_cross_connection_packets(&mut node_a, &mut packet_rx_a, &mut node_b, &mut packet_rx_b)
        .await;

    assert_eq!(node_a.peer_count(), 1);
    assert_eq!(node_b.peer_count(), 1);
    assert_eq!(node_a.connection_count(), 0);
    assert_eq!(node_b.connection_count(), 0);
    assert!(node_a.pending_outbound.is_empty());
    assert!(node_b.pending_outbound.is_empty());

    let peer_b_on_a = node_a.get_peer(&peer_b_node_addr).unwrap();
    let peer_a_on_b = node_b.get_peer(&peer_a_node_addr).unwrap();
    assert!(
        peer_b_on_a.fmp_mmp_is_initiator(),
        "smaller node A should converge on its outbound session"
    );
    assert!(
        !peer_a_on_b.fmp_mmp_is_initiator(),
        "larger node B should keep the responder session"
    );
    assert_eq!(peer_b_on_a.current_addr(), Some(&remote_addr_b));
    assert_eq!(peer_a_on_b.current_addr(), Some(&remote_addr_a));

    for (_, t) in node_a.transports.iter_mut() {
        t.stop().await.ok();
    }
    for (_, t) in node_b.transports.iter_mut() {
        t.stop().await.ok();
    }
}

/// Two production dial sources (for example a configured static address and
/// LAN discovery) can race from the same UDP socket to the same peer. The
/// responder must keep the first authenticated inbound owner while the
/// initiator keeps the matching first outbound owner. Replacing the responder
/// with the second inbound handshake while the initiator discards its second
/// outbound handshake leaves complementary directions but mismatched Noise
/// sessions, so the direct FSP SessionAck can never return.
#[tokio::test]
async fn duplicate_same_tuple_outbound_dials_preserve_fmp_owner_and_session_ack() {
    use crate::node::tests::spanning_tree::{
        cleanup_nodes, initiate_handshake, make_test_node, process_available_packets,
    };
    use crate::node::wire::{Msg1Header, Msg2Header};
    use tokio::time::{Duration, timeout};

    let node_0 = make_test_node().await;
    let node_1 = make_test_node().await;
    let mut nodes = if node_0.node.node_addr() < node_1.node.node_addr() {
        vec![node_0, node_1]
    } else {
        vec![node_1, node_0]
    };

    let initiator_addr = *nodes[0].node.node_addr();
    let responder_addr = *nodes[1].node.node_addr();
    let responder_pubkey = nodes[1].node.identity().pubkey_full();

    // Model the static-address and LAN-discovery dials that production can
    // launch in the same event-loop turn.
    initiate_handshake(&mut nodes, 0, 1).await;
    initiate_handshake(&mut nodes, 0, 1).await;

    let first_msg1 = timeout(Duration::from_secs(1), async {
        loop {
            let packet = nodes[1]
                .packet_rx
                .recv()
                .await
                .expect("responder packet channel open");
            if Msg1Header::parse(packet.data.as_slice()).is_some() {
                break packet;
            }
        }
    })
    .await
    .expect("responder should receive first production-path Msg1");
    nodes[1].node.handle_msg1(first_msg1).await;
    let first_responder_link = nodes[1]
        .node
        .get_peer(&initiator_addr)
        .expect("first Msg1 should install an inbound owner")
        .link_id();

    let second_msg1 = timeout(Duration::from_secs(1), async {
        loop {
            let packet = nodes[1]
                .packet_rx
                .recv()
                .await
                .expect("responder packet channel open");
            if Msg1Header::parse(packet.data.as_slice()).is_some() {
                break packet;
            }
        }
    })
    .await
    .expect("responder should receive the racing duplicate Msg1");
    nodes[1].node.handle_msg1(second_msg1).await;

    // Process the canonical first Msg2. A losing duplicate responder index
    // must not be advertised; if old code did advertise one, the normal drain
    // below processes it and proves that it cannot split ownership.
    let msg2 = timeout(Duration::from_secs(1), async {
        loop {
            let packet = nodes[0]
                .packet_rx
                .recv()
                .await
                .expect("initiator packet channel open");
            if Msg2Header::parse(packet.data.as_slice()).is_some() {
                break packet;
            }
        }
    })
    .await
    .expect("initiator should receive the canonical Msg2 reply");
    nodes[0].node.handle_msg2(msg2).await;

    {
        let (a, b) = nodes.split_at_mut(1);
        confirm_cross_connection_packets(
            &mut a[0].node,
            &mut a[0].packet_rx,
            &mut b[0].node,
            &mut b[0].packet_rx,
        )
        .await;
    }
    populate_all_coord_caches(&mut nodes);

    // Exercise the actual encrypted production path. With split FMP owners,
    // the responder cannot decrypt SessionSetup and no SessionAck arrives.
    nodes[0]
        .node
        .initiate_session(responder_addr, responder_pubkey)
        .await
        .expect("direct FSP session initiation should start");
    timeout(Duration::from_secs(1), async {
        while !nodes[0]
            .node
            .get_session(&responder_addr)
            .is_some_and(|s| s.is_established())
            || !nodes[1]
                .node
                .get_session(&initiator_addr)
                .is_some_and(|s| s.is_established())
        {
            process_available_packets(&mut nodes).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("matching FMP owners must complete the direct FSP handshake");

    let initiator_peer = nodes[0]
        .node
        .get_peer(&responder_addr)
        .expect("initiator should retain responder");
    let responder_peer = nodes[1]
        .node
        .get_peer(&initiator_addr)
        .expect("responder should retain initiator");

    assert!(
        nodes[0]
            .node
            .get_session(&responder_addr)
            .is_some_and(|session| session.is_established()),
        "SessionAck must return over the canonical FMP owner"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&initiator_addr)
            .is_some_and(|session| session.is_established()),
        "responder must complete the same direct FSP session"
    );
    assert!(
        initiator_peer.fmp_mmp_is_initiator(),
        "smaller initiator should keep the canonical outbound owner"
    );
    assert!(
        !responder_peer.fmp_mmp_is_initiator(),
        "larger responder should keep the complementary inbound owner"
    );
    assert_eq!(
        responder_peer.link_id(),
        first_responder_link,
        "a same-direction duplicate must not replace an authenticated owner"
    );
    assert_eq!(initiator_peer.their_index(), responder_peer.our_index());
    assert_eq!(responder_peer.their_index(), initiator_peer.our_index());

    cleanup_nodes(&mut nodes).await;
}
