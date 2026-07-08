use super::*;

#[test]
fn test_multihop_learned_path_mtu_generates_ptb_heterogeneous_mtu() {
    run_large_stack_async_test(
        "fips-multihop-learned-path-mtu-heterogeneous-mtu",
        || async {
            // Three-node chain: A(1400)-B(1200)-C(1200)
            //
            // Keep the transit hop smaller than the source, but above the
            // fixed-size v1 FilterAnnounce payload so the control plane can
            // establish the multihop session. Then feed the source the same
            // MtuExceeded body the reactive path uses and verify the TUN side
            // clamps oversized IPv6 packets while still forwarding fitting
            // packets over the graph route.
            let mtus = [1400, 1200, 1200];
            let edges = vec![(0, 1), (1, 2)];
            let mut nodes = run_tree_test_with_mtus(&mtus, &edges).await;
            verify_tree_convergence(&nodes);
            populate_all_coord_caches(&mut nodes);

            let node0_addr = *nodes[0].node.node_addr();
            let node1_addr = *nodes[1].node.node_addr();
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

            let bottleneck_mtu = mtus[1];
            let inner = build_mtu_exceeded_inner(&node2_addr, &node1_addr, bottleneck_mtu);
            nodes[0].node.handle_mtu_exceeded(&inner).await;

            let path_mtu = nodes[0]
                .node
                .session_mmp_snapshot(&node2_addr)
                .expect("session should have dataplane MMP state")
                .send_mtu;
            assert_eq!(
                path_mtu, bottleneck_mtu,
                "MtuExceeded should tighten the A->C dataplane path MTU"
            );
            assert_eq!(
                nodes[0].node.path_mtu_lookup_get(&dst_fips),
                Some(bottleneck_mtu),
                "MtuExceeded should mirror the bottleneck into path_mtu_lookup"
            );

            let reduced_ipv6_mtu = crate::upper::icmp::effective_ipv6_mtu(bottleneck_mtu) as usize;
            let local_effective_mtu = crate::upper::icmp::effective_ipv6_mtu(1400) as usize;
            let oversized_payload = vec![0xABu8; reduced_ipv6_mtu - 39];
            let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, &oversized_payload);
            assert!(
                ipv6_packet.len() > reduced_ipv6_mtu,
                "packet must exceed learned path IPv6 MTU"
            );
            assert!(
                ipv6_packet.len() <= local_effective_mtu,
                "packet must fit source local IPv6 MTU"
            );

            let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
            nodes[0].node.tun_tx = Some(tun_tx);
            send_tun_packet_via_dataplane(&mut nodes, 0, ipv6_packet).await;
            let ptb_messages: Vec<Vec<u8>> = std::iter::from_fn(|| {
                tun_rx
                    .try_recv_packet()
                    .ok()
                    .map(|packet| packet.as_slice().to_vec())
            })
            .collect();
            assert_eq!(
                ptb_messages.len(),
                1,
                "oversized packet should generate one ICMPv6 PTB"
            );
            let ptb = &ptb_messages[0];
            assert_eq!(ptb[0] >> 4, 6, "Should be IPv6");
            assert_eq!(ptb[6], 58, "Next header should be ICMPv6 (58)");
            assert_eq!(ptb[40], 2, "ICMPv6 type should be Packet Too Big (2)");
            assert_eq!(ptb[41], 0, "ICMPv6 code should be 0");
            let reported_mtu = u32::from_be_bytes([ptb[44], ptb[45], ptb[46], ptb[47]]);
            assert_eq!(reported_mtu, reduced_ipv6_mtu as u32);

            let (dest_tun_tx, dest_tun_rx) = crate::upper::tun::write_channel();
            nodes[2].node.tun_tx = Some(dest_tun_tx);
            let fitting_payload = vec![0xCDu8; 600 - 40];
            let fitting_packet = build_ipv6_packet(&src_fips, &dst_fips, &fitting_payload);
            assert!(fitting_packet.len() <= reduced_ipv6_mtu);

            send_tun_packet_via_dataplane(&mut nodes, 0, fitting_packet.clone()).await;
            let delivered = recv_tun_packet_while_draining(
                &mut nodes,
                &dest_tun_rx,
                Duration::from_secs(10),
                "fitting multihop packet after learned path MTU",
            )
            .await;
            assert_eq!(delivered, fitting_packet);

            cleanup_nodes(&mut nodes).await;
        },
    );
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
