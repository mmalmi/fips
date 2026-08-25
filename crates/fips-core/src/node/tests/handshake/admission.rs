use super::*;
use crate::ReceivedPacket;

/// Test that duplicate msg2 is silently dropped when pending_outbound is already cleared.
#[tokio::test]
async fn test_duplicate_msg2_dropped() {
    use crate::node::wire::build_msg2;
    use crate::transport::ReceivedPacket;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // No pending_outbound entry — simulate post-promotion state
    let receiver_idx = SessionIndex::new(42);
    let sender_idx = SessionIndex::new(99);

    // Build a fake msg2 packet
    let fake_noise_msg2 = vec![0u8; 57]; // Noise IK msg2 is 57 bytes (33 ephem + 24 encrypted epoch)
    let wire_msg2 = build_msg2(sender_idx, receiver_idx, &fake_noise_msg2);

    let packet = ReceivedPacket {
        transport_id,
        remote_addr: TransportAddr::from_string("10.0.0.2:2121"),
        data: crate::transport::PacketBuffer::new(wire_msg2),
        timestamp_ms: 1000,
        trace_enqueued_at: None,
        trace_rx_loop_owned_at: None,
    };

    // Should silently drop — no pending_outbound for this index
    node.handle_msg2(packet).await;
    // No panic, no state change — that's the test
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.peer_count(), 0);
}

/// `should_admit_msg1` admits when no transport is registered for the id.
/// (No gate to apply — the caller's other checks decide the outcome.)
#[test]
fn test_should_admit_msg1_no_transport() {
    let node = make_node();
    let addr = TransportAddr::from_string("10.0.0.2:2121");
    assert!(node.should_admit_msg1(TransportId::new(1), &addr));
}

/// `should_admit_msg1` rejects a fresh msg1 (no address-index entry) when
/// the transport has accept_connections=false. Behavior unchanged from
/// before the carve-out.
#[tokio::test]
async fn test_should_admit_msg1_rejects_fresh_when_accept_off() {
    use crate::config::TcpConfig;
    use crate::transport::tcp::TcpTransport;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // bind_addr=None → accept_connections() == false
    let cfg = TcpConfig {
        bind_addr: None,
        ..Default::default()
    };
    let (tx, _rx) = packet_channel(64);
    let tcp = TcpTransport::new(transport_id, None, cfg, tx);
    node.transports
        .insert(transport_id, TransportHandle::Tcp(tcp));

    let addr = TransportAddr::from_string("10.0.0.2:2121");
    assert!(!node.should_admit_msg1(transport_id, &addr));
}

/// ISSUE-2026-0004 regression test: `should_admit_msg1` admits rekey/restart
/// msg1 from a peer with an existing link even when the transport has
/// accept_connections=false. Without this, the dual-init tie-breaker
/// deadlocks (the larger-NodeAddr side drops the winner's rekey msg1).
#[tokio::test]
async fn test_should_admit_msg1_admits_rekey_when_accept_off() {
    use crate::config::TcpConfig;
    use crate::transport::tcp::TcpTransport;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let cfg = TcpConfig {
        bind_addr: None,
        ..Default::default()
    };
    let (tx, _rx) = packet_channel(64);
    let tcp = TcpTransport::new(transport_id, None, cfg, tx);
    node.transports
        .insert(transport_id, TransportHandle::Tcp(tcp));

    let addr = TransportAddr::from_string("10.0.0.2:2121");

    // Pre-populate address dispatch as if a session were established for this
    // peer on this transport (rekey msg1 will arrive against this entry).
    let link_id = node.allocate_link_id();
    node.links
        .insert_addr((transport_id, addr.clone()), link_id);

    assert!(node.should_admit_msg1(transport_id, &addr));
}

/// Same regression coverage as the TCP test above, but exercising the
/// UDP transport's new `accept_connections` config field (introduced
/// alongside the `outbound_only` mode). Proves the Node-level gate's
/// address-index carve-out is transport-agnostic and that the new UDP
/// config knob is wired correctly through the Transport trait.
#[tokio::test]
async fn test_should_admit_msg1_admits_rekey_when_udp_accept_off() {
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let cfg = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        accept_connections: Some(false),
        ..Default::default()
    };
    let (tx, _rx) = packet_channel(64);
    let udp = UdpTransport::new(transport_id, None, cfg, tx);
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let addr = TransportAddr::from_string("10.0.0.2:2121");

    // Fresh msg1 (no address-index entry) is rejected by the gate when
    // the transport refuses inbound.
    assert!(!node.should_admit_msg1(transport_id, &addr));

    // Pre-populate address dispatch as if a session were established. The
    // rekey carve-out admits the msg1 even though the transport still
    // says accept_connections() == false.
    let link_id = node.allocate_link_id();
    node.links
        .insert_addr((transport_id, addr.clone()), link_id);

    assert!(node.should_admit_msg1(transport_id, &addr));
}

/// Regression test for the udp.outbound_only rekey loop observed in
/// production 2026-04-30 (parallel to ISSUE-2026-0004).
///
/// Production scenario: one peer runs `udp.outbound_only=true` with the other
/// peer configured by hostname (`peer.example.test:2121`).
/// `initiate_connection` populates address dispatch with the literal
/// hostname-form `TransportAddr`. The other peer's later rekey msg1 arrives
/// with a numeric source addr (the kernel always reports
/// `SocketAddr` in numeric form via `recvfrom`), so the address-index
/// lookup misses, the gate falls through to `accept_connections()`
/// (false in outbound_only mode), and rejects. Result: dual-init
/// tie-breaker stalls because the loser side never produces msg2.
///
/// The carve-out predicate must also consult peer state by source
/// address: `current_addr()` is updated from inbound encrypted-frame
/// source addrs (`handlers/encrypted.rs`), so an established peer can
/// be matched even when the address-index key is hostname-form and the
/// incoming addr is numeric.
#[tokio::test]
async fn test_should_admit_msg1_admits_rekey_when_addr_form_differs() {
    use crate::config::UdpConfig;
    use crate::peer::ActivePeer;
    use crate::transport::udp::UdpTransport;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // outbound_only mode forces accept_connections() to false.
    let cfg = UdpConfig {
        outbound_only: Some(true),
        ..Default::default()
    };
    let (tx, _rx) = packet_channel(64);
    let udp = UdpTransport::new(transport_id, None, cfg, tx);
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    // Simulate initiate_connection's effect when peer config carries a
    // hostname: address dispatch is populated with hostname-form, not
    // numeric-form.
    let hostname_addr = TransportAddr::from_string("peer.example.test:2121");
    let link_id = node.allocate_link_id();
    node.links
        .insert_addr((transport_id, hostname_addr.clone()), link_id);

    // Promote a peer at the hostname's resolved numeric form
    // (current_addr is set from the SocketAddr in udp_receive_loop).
    let peer_full = crate::Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey(peer_full.pubkey());
    let peer_node_addr = *peer_identity.node_addr();
    let mut peer = ActivePeer::new(peer_identity, link_id, 1000);
    let numeric_addr = TransportAddr::from_string("100.64.0.5:2121");
    peer.set_current_addr(transport_id, &numeric_addr);
    node.peers.insert(peer_node_addr, peer);

    // Sanity: legacy carve-out still works for the hostname-form lookup.
    assert!(node.should_admit_msg1(transport_id, &hostname_addr));

    // The bug: incoming rekey msg1 arrives with numeric source addr.
    // Without the additional carve-out, this is rejected (address-index
    // miss → accept_connections() false → drop).
    assert!(
        node.should_admit_msg1(transport_id, &numeric_addr),
        "rekey msg1 from established peer must be admitted even when \
         address dispatch is keyed by a different addr-form (hostname vs \
         numeric); the carve-out must consult peer current_addr"
    );

    // Negative: a stranger at a different numeric addr is still rejected
    // (no peer there, no address-index entry, falls to accept_connections).
    let stranger_addr = TransportAddr::from_string("198.51.100.1:2121");
    assert!(
        !node.should_admit_msg1(transport_id, &stranger_addr),
        "fresh msg1 from unknown source must still be rejected"
    );
}

async fn node_refusing_inbound(
    transport_id: TransportId,
    config: Config,
) -> (
    Node,
    TransportAddr,
    crate::transport::PacketRx,
    crate::transport::udp::UdpTransport,
) {
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;

    let mut node = Node::new(config).unwrap();
    let (node_tx, _node_rx) = packet_channel(64);
    let mut node_transport = UdpTransport::new(
        transport_id,
        None,
        UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            accept_connections: Some(false),
            ..Default::default()
        },
        node_tx,
    );
    node_transport.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(node_transport));

    let (far_tx, far_rx) = packet_channel(64);
    let mut far_end = UdpTransport::new(
        TransportId::new(200),
        None,
        UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        far_tx,
    );
    far_end.start_async().await.unwrap();
    let far_addr = TransportAddr::from_string(&far_end.local_addr().unwrap().to_string());

    (node, far_addr, far_rx, far_end)
}

fn genuine_msg1(
    initiator: &Node,
    responder: &Node,
    sender_index: u32,
) -> crate::transport::PacketBuffer {
    use crate::node::wire::build_msg1;

    let mut handshake = crate::noise::HandshakeState::new_initiator(
        initiator.identity.keypair(),
        responder.identity.pubkey_full(),
    );
    handshake.set_local_epoch(initiator.startup_epoch);
    crate::transport::PacketBuffer::new(build_msg1(
        SessionIndex::new(sender_index),
        &handshake.write_message_1().unwrap(),
    ))
}

async fn assert_no_packet(rx: &mut crate::transport::PacketRx, reason: &str) {
    assert!(
        tokio::time::timeout(Duration::from_millis(250), rx.recv())
            .await
            .is_err(),
        "{reason}"
    );
}

#[tokio::test]
async fn msg1_waiver_rejects_an_authenticated_identity_mismatch() {
    use crate::peer::ActivePeer;

    let transport_id = TransportId::new(1);
    let (mut node, source_addr, mut far_rx, _far_end) =
        node_refusing_inbound(transport_id, Config::new()).await;

    let victim = make_node();
    let victim_identity = PeerIdentity::from_pubkey_full(victim.identity.pubkey_full());
    let victim_addr = *victim_identity.node_addr();
    let victim_link = node.allocate_link_id();
    let mut victim_peer = ActivePeer::new(victim_identity, victim_link, 1_000);
    victim_peer.set_current_addr(transport_id, &source_addr);
    node.peers.insert(victim_addr, victim_peer);
    node.links.insert(
        victim_link,
        Link::connectionless(
            victim_link,
            transport_id,
            source_addr.clone(),
            LinkDirection::Inbound,
            Duration::from_millis(1),
        ),
    );

    let attacker = make_node();
    let attacker_addr = *attacker.node_addr();
    node.handle_msg1(ReceivedPacket::with_timestamp(
        transport_id,
        source_addr,
        genuine_msg1(&attacker, &node, 71),
        2_000,
    ))
    .await;

    assert!(node.get_peer(&attacker_addr).is_none());
    assert_eq!(node.get_peer(&victim_addr).unwrap().link_id(), victim_link);
    assert_eq!(node.peer_count(), 1);
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.link_count(), 1);
    assert_no_packet(
        &mut far_rx,
        "an identity that does not own the waived address must receive no msg2",
    )
    .await;
}

#[tokio::test]
async fn msg1_waiver_rejects_an_unattributed_address_entry() {
    let transport_id = TransportId::new(1);
    let (mut node, source_addr, mut far_rx, _far_end) =
        node_refusing_inbound(transport_id, Config::new()).await;

    let bare_link = node.allocate_link_id();
    node.links
        .insert_addr((transport_id, source_addr.clone()), bare_link);

    let initiator = make_node();
    let initiator_addr = *initiator.node_addr();
    node.handle_msg1(ReceivedPacket::with_timestamp(
        transport_id,
        source_addr,
        genuine_msg1(&initiator, &node, 72),
        2_000,
    ))
    .await;

    assert!(node.get_peer(&initiator_addr).is_none());
    assert_eq!(node.peer_count(), 0);
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.link_count(), 0);
    assert_no_packet(
        &mut far_rx,
        "an address entry with no attributable identity must receive no msg2",
    )
    .await;
}

#[tokio::test]
async fn established_identity_uses_reserved_msg1_capacity_after_stranger_exhaustion() {
    use crate::node::rate_limit::Msg1Class;
    use crate::node::wire::Msg2Header;

    let mut config = Config::new();
    config.node.rate_limit.handshake_burst = 1;
    config.node.rate_limit.handshake_rate = 0.0;
    let transport_id = TransportId::new(1);
    let (mut node, source_addr, mut far_rx, _far_end) =
        node_refusing_inbound(transport_id, config).await;

    drop(
        node.msg1_rate_limiter
            .start_handshake(Msg1Class::Stranger)
            .unwrap(),
    );
    assert!(
        node.msg1_rate_limiter
            .start_handshake(Msg1Class::Stranger)
            .is_err(),
        "fixture must exhaust stranger capacity"
    );

    let peer = make_node();
    let peer_identity = PeerIdentity::from_pubkey_full(peer.identity.pubkey_full());
    let peer_addr = *peer_identity.node_addr();
    let expected_link = node.allocate_link_id();
    node.peers.insert_connection(
        expected_link,
        PeerConnection::outbound(expected_link, peer_identity, 1_000),
    );
    node.links
        .insert_addr((transport_id, source_addr.clone()), expected_link);

    node.handle_msg1(ReceivedPacket::with_timestamp(
        transport_id,
        source_addr,
        genuine_msg1(&peer, &node, 73),
        2_000,
    ))
    .await;

    let answer = tokio::time::timeout(Duration::from_secs(1), far_rx.recv())
        .await
        .expect("reserved established-link capacity must produce msg2")
        .expect("far-end packet channel must remain open");
    assert!(
        Msg2Header::parse(answer.data.as_slice()).is_some(),
        "the response must be a msg2"
    );
    assert!(node.get_peer(&peer_addr).is_some());
    assert_eq!(node.msg1_rate_limiter.pending_count(), 0);
}

#[tokio::test]
async fn msg1_reject_path_does_not_release_another_pending_guard() {
    use crate::node::rate_limit::Msg1Class;

    let mut node = make_node();
    let held = node
        .msg1_rate_limiter
        .start_handshake(Msg1Class::Stranger)
        .unwrap();
    assert_eq!(node.msg1_rate_limiter.pending_count(), 1);

    node.handle_msg1(ReceivedPacket::with_timestamp(
        TransportId::new(99),
        TransportAddr::from_string("127.0.0.1:9"),
        crate::transport::PacketBuffer::new(vec![0u8; 4]),
        1_000,
    ))
    .await;

    assert_eq!(
        node.msg1_rate_limiter.pending_count(),
        1,
        "the rejected msg1 guard must release only its own slot"
    );
    drop(held);
    assert_eq!(node.msg1_rate_limiter.pending_count(), 0);
}
