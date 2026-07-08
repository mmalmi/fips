use super::*;

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
