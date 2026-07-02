use super::*;

#[test]
fn test_multihop_pmtud_heterogeneous_mtu() {
    run_large_stack_async_test("fips-multihop-pmtud-heterogeneous-mtu", || async {
        // Three-node chain: A(1400)—B(800)—C(800)
        //
        // Node B has a smaller transport MTU than A. When A sends an IPv6
        // packet that fits A's local MTU (1294) but whose wire size after
        // FIPS encapsulation exceeds B's transport MTU (800), B's forwarding
        // path fails with MtuExceeded and sends an MtuExceeded signal back
        // to A. A updates PathMtuState, and the next oversized packet
        // generates ICMPv6 Packet Too Big on TUN.
        //
        // This exercises the full PMTUD loop:
        //   1. Oversized packet forwarded A→B
        //   2. B→C forward fails (B's transport MTU 800 exceeded)
        //   3. B sends MtuExceeded signal back to A
        //   4. A receives signal, updates PathMtuState for C
        //   5. Next oversized packet → ICMPv6 PTB on TUN
        let mtus = [1400, 800, 800];
        let edges = vec![(0, 1), (1, 2)];
        let mut nodes = run_tree_test_with_mtus(&mtus, &edges).await;
        verify_tree_convergence(&nodes);
        populate_all_coord_caches(&mut nodes);

        let node0_addr = *nodes[0].node.node_addr();
        let node2_addr = *nodes[2].node.node_addr();

        let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
        let dst_fips = crate::FipsAddress::from_node_addr(&node2_addr);

        // Register Node 2's identity in Node 0's cache
        let node2_pubkey = nodes[2].node.identity().pubkey_full();
        nodes[0].node.register_identity(node2_addr, node2_pubkey);

        // Establish session A→C via B (triggers routing through tree)
        nodes[0]
            .node
            .initiate_session(node2_addr, node2_pubkey)
            .await
            .unwrap();
        drain_to_quiescence(&mut nodes).await;
        assert!(
            nodes[0]
                .node
                .get_session(&node2_addr)
                .unwrap()
                .is_established(),
            "Session A→C should be established"
        );

        let (dest_tun_tx, _dest_tun_rx) = crate::upper::tun::write_channel();
        nodes[2].node.tun_tx = Some(dest_tun_tx);

        // Exhaust coord warmup by sending small packets first.
        // Without piggybacked coords, the wire packet is ~106 + IPv6 bytes,
        // which fits B's receive buffer (mtu+100=900) for reasonable sizes.
        // With coords (~66 extra), the wire could exceed B's recv buffer.
        for _ in 0..5 {
            let small = build_ipv6_packet(&src_fips, &dst_fips, &[0u8; 10]);
            send_tun_packet_via_pm2(&mut nodes, 0, small).await;
        }
        drain_to_quiescence(&mut nodes).await;

        // Build an IPv6 packet that fits A's local MTU (1294) but whose wire
        // size (~750 + 106 = ~856 bytes) exceeds B's transport MTU (800).
        // effective_ipv6_mtu(1400) = 1294, effective_ipv6_mtu(800) = 694
        let oversized_payload = vec![0xABu8; 750 - 40]; // 710 bytes payload → 750-byte IPv6 packet
        let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, &oversized_payload);
        assert_eq!(ipv6_packet.len(), 750);
        let local_effective_mtu = crate::upper::icmp::effective_ipv6_mtu(1400) as usize;
        assert!(
            ipv6_packet.len() <= local_effective_mtu,
            "packet ({}) must fit A's local MTU ({})",
            ipv6_packet.len(),
            local_effective_mtu
        );

        // Send the oversized packet — B should fail to forward and send
        // MtuExceeded signal back.
        send_tun_packet_via_pm2(&mut nodes, 0, ipv6_packet.clone()).await;
        drain_to_quiescence(&mut nodes).await;

        // Verify PathMtuState was updated on A
        let path_mtu = nodes[0]
            .node
            .session_mmp_snapshot(&node2_addr)
            .expect("session should have PM2 MMP state")
            .send_mtu;
        assert!(
            path_mtu < 1400,
            "PathMtuState should have decreased from MtuExceeded signal, got {}",
            path_mtu
        );

        // Verify path_mtu_lookup (consulted by the TUN reader/writer at TCP MSS
        // clamp time) also reflects the tightened bottleneck. The reactive
        // MtuExceeded handler writes here so subsequent SYN clamps see the
        // forward-path budget rather than the discovery reverse-path value.
        let lookup_mtu = nodes[0]
            .node
            .path_mtu_lookup_get(&dst_fips)
            .expect("path_mtu_lookup should have entry for C after MtuExceeded");
        assert!(
            lookup_mtu < 1400,
            "path_mtu_lookup should have tightened from MtuExceeded signal, got {}",
            lookup_mtu
        );

        // Now send ANOTHER oversized packet — this time PM2 should
        // should check PathMtuState and generate ICMPv6 PTB on TUN instead
        // of forwarding.
        let (tun_tx2, tun_rx2) = crate::upper::tun::write_channel();
        nodes[0].node.tun_tx = Some(tun_tx2);

        send_tun_packet_via_pm2(&mut nodes, 0, ipv6_packet.clone()).await;

        let ptb_messages: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx2.try_recv().ok()).collect();
        assert_eq!(
            ptb_messages.len(),
            1,
            "Should generate ICMPv6 PTB for oversized packet after PathMtuState update"
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

        // Verify reported MTU is the path MTU (not local MTU)
        let reported_mtu = u32::from_be_bytes([ptb[44], ptb[45], ptb[46], ptb[47]]);
        let expected_ipv6_mtu = crate::upper::icmp::effective_ipv6_mtu(path_mtu) as u32;
        assert_eq!(
            reported_mtu, expected_ipv6_mtu,
            "ICMPv6 PTB MTU should match path IPv6 MTU (transport MTU {} - overhead)",
            path_mtu
        );

        // Verify a fitting packet still passes through without PTB
        let (tun_tx3, tun_rx3) = crate::upper::tun::write_channel();
        nodes[0].node.tun_tx = Some(tun_tx3);

        let fitting_payload = vec![0xCDu8; 600 - 40]; // 600-byte IPv6 packet, well within 694
        let fitting_packet = build_ipv6_packet(&src_fips, &dst_fips, &fitting_payload);
        assert!(fitting_packet.len() <= expected_ipv6_mtu as usize);

        send_tun_packet_via_pm2(&mut nodes, 0, fitting_packet).await;

        let ptb_messages3: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx3.try_recv().ok()).collect();
        assert_eq!(
            ptb_messages3.len(),
            0,
            "Should not generate PTB for packet fitting within path MTU"
        );

        cleanup_nodes(&mut nodes).await;
    });
}

// ============================================================================
// Reactive MtuExceeded → path_mtu_lookup focused unit tests
//
// These exercise the receive-side write path that mirrors the bottleneck
// MTU into `path_mtu_lookup` (consulted by the TUN reader/writer at
// SYN-clamp time). Discovery's reverse-path response and the FMP-promotion
// seed populate the same lookup; the reactive channel keeps it
// authoritative under forward-path-asymmetry conditions.
// ============================================================================
