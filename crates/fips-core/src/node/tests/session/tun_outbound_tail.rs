use super::*;

#[tokio::test]
async fn test_tun_outbound_unknown_destination() {
    // Inject a packet for an unknown destination — should get ICMPv6 back
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);

    // Install TUN receiver on Node 0 (for ICMPv6 response)
    let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
    nodes[0].node.tun_tx = Some(tun_tx);

    let src_fips = crate::FipsAddress::from_node_addr(nodes[0].node.node_addr());

    // Build a packet to an unknown FIPS address (not in identity cache)
    let unknown_addr = NodeAddr::from_bytes([0xAA; 16]);
    let unknown_fips = crate::FipsAddress::from_node_addr(&unknown_addr);
    let ipv6_packet = build_ipv6_packet(&src_fips, &unknown_fips, b"unknown");

    send_tun_packet_via_dataplane(&mut nodes, 0, ipv6_packet).await;

    // Should receive ICMPv6 Destination Unreachable back on TUN
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(
        delivered.len(),
        1,
        "Should receive ICMPv6 Destination Unreachable"
    );
    // Verify it's an ICMPv6 Destination Unreachable (type 1, code 0)
    // ICMPv6 header starts at byte 40, type at byte 40, code at byte 41
    assert!(delivered[0].len() >= 48, "ICMPv6 response too short");
    assert_eq!(delivered[0][6], 58, "Next header should be ICMPv6 (58)");
    assert_eq!(
        delivered[0][40], 1,
        "ICMPv6 type should be Destination Unreachable (1)"
    );
    assert_eq!(delivered[0][41], 0, "ICMPv6 code should be No Route (0)");

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_tun_outbound_3node_forwarded() {
    // A—B—C: TUN packet from A destined for C, forwarded through B
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node2_addr);

    // Register Node 2's identity in Node 0's cache
    // (In production, this would come from the discovery protocol or DNS priming)
    let node2_pubkey = nodes[2].node.identity().pubkey_full();
    nodes[0].node.register_identity(node2_addr, node2_pubkey);

    // Install TUN receiver on Node 2
    let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
    nodes[2].node.tun_tx = Some(tun_tx);

    // Build and inject an IPv6 packet (triggers session initiation to Node 2)
    let test_payload = b"forwarded-data-plane";
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, test_payload);

    send_tun_packet_via_dataplane(&mut nodes, 0, ipv6_packet.clone()).await;

    // Drain packets: handshake + queued data delivery
    drain_to_quiescence(&mut nodes).await;

    // Session should be established
    assert!(
        nodes[0]
            .node
            .get_session(&node2_addr)
            .unwrap()
            .is_established()
    );

    // Verify packet delivered to Node 2
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(delivered.len(), 1, "Packet should be delivered to Node 2");
    assert_eq!(delivered[0], ipv6_packet);

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_tun_outbound_pending_queue_flush() {
    // Send multiple packets before session exists — all should be delivered
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node1_addr);

    // Install TUN receiver on Node 1
    let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
    nodes[1].node.tun_tx = Some(tun_tx);

    // Send 5 packets before any session exists
    let mut packets = Vec::new();
    for i in 0..5u8 {
        let payload = format!("queued-pkt-{}", i).into_bytes();
        let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, &payload);
        packets.push(ipv6_packet.clone());
        enqueue_tun_packet_via_dataplane(&mut nodes, 0, ipv6_packet);
    }
    process_available_packets(&mut nodes).await;

    // First packet triggers session initiation, rest are queued
    assert_eq!(nodes[0].node.session_count(), 1);
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_initiating()
    );

    // Drain until session established and queued packets flushed
    drain_to_quiescence(&mut nodes).await;

    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_established()
    );

    // All 5 packets should have been delivered
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(
        delivered.len(),
        5,
        "All 5 queued packets should be delivered"
    );
    for (i, pkt) in delivered.iter().enumerate() {
        assert_eq!(*pkt, packets[i], "Packet {} should match", i);
    }

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Unit tests: Session idle timeout
// ============================================================================
