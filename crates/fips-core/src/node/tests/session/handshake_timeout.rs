use super::*;

/// Test that SessionEntry handshake payload storage works correctly.
#[test]
fn test_session_entry_handshake_payload_storage() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    // Initially no handshake payload
    assert!(entry.handshake_payload().is_none());
    assert_eq!(entry.resend_count(), 0);
    assert_eq!(entry.next_resend_at_ms(), 0);

    // Store a handshake payload
    let payload = vec![0x01, 0x02, 0x03, 0x04];
    entry.set_handshake_payload(payload.clone(), 2000);

    assert_eq!(entry.handshake_payload().unwrap(), &payload);
    assert_eq!(entry.resend_count(), 0);
    assert_eq!(entry.next_resend_at_ms(), 2000);
}

/// Test that resend_count and next_resend_at_ms track correctly on SessionEntry.
#[test]
fn test_session_entry_resend_tracking() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    entry.set_handshake_payload(vec![0x01], 2000);

    // Record first resend
    entry.record_resend(4000);
    assert_eq!(entry.resend_count(), 1);
    assert_eq!(entry.next_resend_at_ms(), 4000);

    // Record second resend
    entry.record_resend(8000);
    assert_eq!(entry.resend_count(), 2);
    assert_eq!(entry.next_resend_at_ms(), 8000);
}

/// Test that clear_handshake_payload clears payload and resets timer.
#[test]
fn test_session_entry_clear_handshake_payload() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    entry.set_handshake_payload(vec![0x01, 0x02], 2000);
    entry.record_resend(4000);
    assert!(entry.handshake_payload().is_some());
    assert_eq!(entry.resend_count(), 1);

    // Clear on Established transition
    entry.clear_handshake_payload();
    assert!(entry.handshake_payload().is_none());
    assert_eq!(entry.next_resend_at_ms(), 0);
    // resend_count is NOT reset — it's a historical record
    assert_eq!(entry.resend_count(), 1);
}

/// Test that session handshake timeout removes stale Initiating sessions.
#[tokio::test]
async fn test_session_handshake_timeout() {
    use crate::noise::HandshakeState;

    let mut node = make_node();

    let identity_b = Identity::generate();
    let handshake =
        HandshakeState::new_initiator(node.identity.keypair(), identity_b.pubkey_full());

    let dest_addr = *identity_b.node_addr();

    // Create a session at time 1000
    let entry = crate::node::session::SessionEntry::new(
        dest_addr,
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );
    node.sessions.insert(dest_addr, entry);

    assert!(node.sessions.get(&dest_addr).is_some());

    // Before timeout: session should remain
    let timeout_secs = node.config.node.rate_limit.handshake_timeout_secs;
    let before_timeout = 1000 + timeout_secs * 1000 - 1;
    node.resend_pending_session_handshakes(before_timeout).await;
    assert!(
        node.sessions.get(&dest_addr).is_some(),
        "Session should survive before timeout"
    );

    // After timeout: session should be removed
    let after_timeout = 1000 + timeout_secs * 1000 + 1;
    node.resend_pending_session_handshakes(after_timeout).await;
    assert!(
        node.sessions.get(&dest_addr).is_none(),
        "Timed-out session should be removed"
    );
}

/// Test that session handshake timeout removes stale AwaitingMsg3 sessions.
#[tokio::test]
async fn test_session_awaiting_msg3_timeout() {
    use crate::noise::HandshakeState;

    let mut node = make_node();

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_xk_responder(identity_b.keypair());

    let src_addr = *identity_a.node_addr();

    // Create an AwaitingMsg3 session at time 1000
    let entry = crate::node::session::SessionEntry::new(
        src_addr,
        identity_a.pubkey_full(),
        EndToEndState::AwaitingMsg3(handshake),
        1000,
        false,
    );
    node.sessions.insert(src_addr, entry);

    assert!(node.sessions.get(&src_addr).is_some());

    // After timeout: session should be removed
    let timeout_secs = node.config.node.rate_limit.handshake_timeout_secs;
    let after_timeout = 1000 + timeout_secs * 1000 + 1;
    node.resend_pending_session_handshakes(after_timeout).await;
    assert!(
        node.sessions.get(&src_addr).is_none(),
        "Timed-out AwaitingMsg3 session should be removed"
    );
}

#[tokio::test]
async fn test_tun_outbound_path_mtu_generates_ptb() {
    // When a session's PathMtuState reports a lower MTU than the local
    // transport (simulating a bottleneck learned via MtuExceeded signals),
    // PM2 TUN outbound should generate ICMPv6 Packet Too Big for
    // oversized packets instead of forwarding them.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node1_addr);

    // Establish session (XK: 3 messages — Setup, Ack, Msg3)
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_established()
    );

    // Simulate receipt of MtuExceeded by reducing PathMtuState to a value
    // lower than the local transport MTU.
    let local_transport_mtu = nodes[0].node.transport_mtu();
    let reduced_mtu = local_transport_mtu - 200;
    nodes[0]
        .node
        .apply_packet_mover2_fsp_path_mtu_signal(
            &node1_addr,
            reduced_mtu,
            std::time::Instant::now(),
        )
        .expect("PM2 FSP owner should accept path MTU signal");
    assert_eq!(
        nodes[0]
            .node
            .session_mmp_snapshot(&node1_addr)
            .expect("session should have PM2 MMP state")
            .send_mtu,
        reduced_mtu
    );

    // Install TUN receiver on source node to capture ICMPv6 PTB
    let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
    nodes[0].node.tun_tx = Some(tun_tx);

    // Build an IPv6 packet that fits local MTU but exceeds path MTU
    let reduced_ipv6_mtu = crate::upper::icmp::effective_ipv6_mtu(reduced_mtu) as usize;
    let local_ipv6_mtu = nodes[0].node.effective_ipv6_mtu() as usize;
    let oversized_payload = vec![0u8; reduced_ipv6_mtu - 39]; // 40-byte hdr + payload > reduced MTU
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, &oversized_payload);
    assert!(
        ipv6_packet.len() > reduced_ipv6_mtu,
        "packet must exceed path MTU"
    );
    assert!(
        ipv6_packet.len() <= local_ipv6_mtu,
        "packet must fit local MTU"
    );

    send_tun_packet_via_pm2(&mut nodes, 0, ipv6_packet).await;

    // Verify ICMPv6 Packet Too Big was generated
    let ptb_messages: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(
        ptb_messages.len(),
        1,
        "Should generate exactly one ICMPv6 PTB"
    );

    let ptb = &ptb_messages[0];
    assert_eq!(ptb[0] >> 4, 6, "Should be IPv6");
    assert_eq!(ptb[6], 58, "Next header should be ICMPv6 (58)");
    assert_eq!(ptb[40], 2, "ICMPv6 type should be Packet Too Big (2)");
    assert_eq!(ptb[41], 0, "ICMPv6 code should be 0");

    // Verify PTB source is the *remote peer* (original packet's destination),
    // NOT the local node. Linux ignores PTBs whose source matches a local
    // address, causing a PMTUD blackhole.
    let ptb_src = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ptb[8..24]).unwrap());
    let ptb_dst = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ptb[24..40]).unwrap());
    assert_eq!(
        ptb_src,
        dst_fips.to_ipv6(),
        "PTB source must be remote peer (original dst), not local node"
    );
    assert_eq!(
        ptb_dst,
        src_fips.to_ipv6(),
        "PTB destination must be local node (original src)"
    );

    // Verify reported MTU (32-bit field at ICMPv6 header bytes 4-7)
    let reported_mtu = u32::from_be_bytes([ptb[44], ptb[45], ptb[46], ptb[47]]);
    assert_eq!(
        reported_mtu, reduced_ipv6_mtu as u32,
        "Reported MTU should match path IPv6 MTU"
    );

    // Verify a packet that fits within path MTU passes through (no PTB)
    let (tun_tx2, tun_rx2) = crate::upper::tun::write_channel();
    nodes[0].node.tun_tx = Some(tun_tx2);
    let fitting_payload = vec![0u8; reduced_ipv6_mtu - 41]; // fits within path MTU
    let fitting_packet = build_ipv6_packet(&src_fips, &dst_fips, &fitting_payload);
    assert!(fitting_packet.len() <= reduced_ipv6_mtu);

    send_tun_packet_via_pm2(&mut nodes, 0, fitting_packet).await;

    // No PTB should be generated for a fitting packet
    let ptb_messages2: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx2.try_recv().ok()).collect();
    assert_eq!(
        ptb_messages2.len(),
        0,
        "Should not generate PTB for fitting packet"
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration test: Multi-hop PMTUD with heterogeneous MTUs
// ============================================================================
