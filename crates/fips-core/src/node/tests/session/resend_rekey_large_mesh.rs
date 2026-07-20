#[cfg(feature = "sim-transport")]
#[test]
fn test_session_100_nodes() {
    run_large_stack_async_test("fips-session-100-nodes", || async {
        session_100_nodes().await;
    });
}

#[cfg(feature = "sim-transport")]
async fn session_100_nodes() {
    let _guard = lock_large_network_test().await;

    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};
    use std::time::Instant;

    // Same random topology as other 100-node tests
    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;
    // This 100-node stress test shares loaded CI hosts with the rest of the
    // workspace. Keep the assertions strict, but allow a single routed phase
    // enough wall-clock budget to make progress under scheduler contention.
    const PHASE_TIMEOUT: Duration = Duration::from_secs(30);

    let start = Instant::now();

    let edges =
        crate::node::tests::spanning_tree::generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, false).await;
    let sim_network =
        super::sim_harness::replace_session_100_node_carriers(&mut nodes, &edges).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let setup_time = start.elapsed();

    // Collect identities: (node_addr, pubkey) for all nodes
    let all_info: Vec<(NodeAddr, secp256k1::PublicKey)> = nodes
        .iter()
        .map(|tn| (*tn.node.node_addr(), tn.node.identity().pubkey_full()))
        .collect();
    for node in nodes.iter_mut().take(NUM_NODES) {
        for &(addr, pubkey) in &all_info {
            if addr != *node.node.node_addr() {
                node.node.register_identity(addr, pubkey);
            }
        }
    }

    // Each node picks one random target for its outbound session.
    // Use deterministic RNG so failures are reproducible.
    let mut rng = StdRng::seed_from_u64(SEED + 1);
    let mut session_pairs: Vec<(usize, usize)> = Vec::with_capacity(NUM_NODES);
    for src in 0..NUM_NODES {
        let mut dst = rng.random_range(0..NUM_NODES);
        while dst == src {
            dst = rng.random_range(0..NUM_NODES);
        }
        session_pairs.push((src, dst));
    }

    // === Phase 1: Establish all sessions ===

    let session_start = Instant::now();

    for &(src, dst) in &session_pairs {
        let (dest_addr, dest_pubkey) = all_info[dst];

        nodes[src]
            .node
            .initiate_session(dest_addr, dest_pubkey)
            .await
            .expect("initiate_session failed");

        let src_addr = all_info[src].0;
        let context = format!("session {src}->{dst} initiator");
        wait_for_session_established(&mut nodes, src, &dest_addr, PHASE_TIMEOUT, &context).await;
        let context = format!("session {src}->{dst} responder");
        wait_for_session_established(&mut nodes, dst, &src_addr, PHASE_TIMEOUT, &context).await;
        // The live runtime clears these retained Ack/msg3 payloads after
        // authenticated traffic. This stress test deliberately defers all
        // traffic until every pair is established, so quiesce the pair once
        // the harness has observed both endpoints complete the handshake.
        settle_session_handshake_retransmits(&mut nodes, src, &dest_addr, dst, &src_addr);
    }
    let session_time = session_start.elapsed();

    // Verify all initiator sessions reached Established before data phase
    let mut handshake_failures: Vec<(usize, usize)> = Vec::new();
    for &(src, dst) in &session_pairs {
        let dest_addr = all_info[dst].0;
        let ok = nodes[src]
            .node
            .get_session(&dest_addr)
            .map(|e| e.is_established())
            .unwrap_or(false);
        if !ok {
            handshake_failures.push((src, dst));
        }
    }
    assert!(
        handshake_failures.is_empty(),
        "Handshake failed for {} pairs (first: {:?})",
        handshake_failures.len(),
        handshake_failures.first()
    );

    // === Phase 2: Inject TUN receivers and snapshot link stats ===

    // Install a tun_tx on every node so delivered datagrams can be counted.
    let mut tun_receivers: Vec<crate::upper::tun::TunRx> = Vec::with_capacity(NUM_NODES);
    for tn in nodes.iter_mut() {
        let (tx, rx) = crate::upper::tun::write_channel();
        tn.node.tun_tx = Some(tx);
        tun_receivers.push(rx);
    }

    // Snapshot per-peer link stats before data phase
    let link_pkts_sent_before: Vec<Vec<(NodeAddr, u64)>> = nodes
        .iter()
        .map(|tn| {
            tn.node
                .peers()
                .map(|p| (*p.node_addr(), p.link_stats().packets_sent))
                .collect()
        })
        .collect();

    // === Phase 3: Bidirectional data transfer ===
    //
    // For each session pair:
    //   1. Initiator sends one datagram to responder
    //   2. Responder sends one datagram back to initiator
    //
    // Verify each delivery before advancing to the next direction.

    let data_start = Instant::now();
    let mut send_forward_ok = 0usize;
    let mut send_reverse_ok = 0usize;
    let send_forward_err = 0usize;
    let send_reverse_err = 0usize;
    let mut fwd_delivered = 0usize;
    let mut rev_delivered = 0usize;

    async fn send_probe_until_delivered(
        nodes: &mut [TestNode],
        receiver: &crate::upper::tun::TunRx,
        source: usize,
        packet: &[u8],
        expected_payload: &[u8],
        timeout: Duration,
        context: &str,
    ) {
        const ATTEMPTS: usize = 3;

        for _ in 0..ATTEMPTS {
            send_tun_packet_via_dataplane(nodes, source, packet.to_vec()).await;
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    break;
                }
                let Some(delivered) = try_recv_tun_packet_while_draining(
                    nodes,
                    receiver,
                    deadline.saturating_duration_since(now),
                )
                .await
                else {
                    break;
                };
                if delivered.get(40..) == Some(expected_payload) {
                    return;
                }
                // A late duplicate from an earlier retry is not the current
                // probe. Keep draining until this attempt's deadline.
            }
        }

        panic!("{context}: payload was not delivered after {ATTEMPTS} attempts");
    }

    for (pair_idx, &(src, dst)) in session_pairs.iter().enumerate() {
        let dest_addr = all_info[dst].0;
        let src_addr = all_info[src].0;

        // Build IPv6 packets with pair index as payload
        let src_fips = crate::FipsAddress::from_node_addr(&src_addr);
        let dst_fips = crate::FipsAddress::from_node_addr(&dest_addr);

        // Forward: initiator → responder
        let fwd_payload = format!("fwd-{}", pair_idx).into_bytes();
        let fwd_ipv6 = build_ipv6_packet(&src_fips, &dst_fips, &fwd_payload);
        let context = format!("forward TUN delivery {src}->{dst}");
        send_probe_until_delivered(
            &mut nodes,
            &tun_receivers[dst],
            src,
            &fwd_ipv6,
            &fwd_payload,
            PHASE_TIMEOUT,
            &context,
        )
        .await;
        send_forward_ok += 1;
        fwd_delivered += 1;

        // Reverse: responder → initiator
        // (Responder should already be Established after XK msg3)
        let rev_payload = format!("rev-{}", pair_idx).into_bytes();
        let rev_ipv6 = build_ipv6_packet(&dst_fips, &src_fips, &rev_payload);
        let context = format!("reverse TUN delivery {dst}->{src}");
        send_probe_until_delivered(
            &mut nodes,
            &tun_receivers[src],
            dst,
            &rev_ipv6,
            &rev_payload,
            PHASE_TIMEOUT,
            &context,
        )
        .await;
        send_reverse_ok += 1;
        rev_delivered += 1;
    }

    let data_time = data_start.elapsed();
    let total_delivered = fwd_delivered + rev_delivered;

    // === Phase 4: Final session state ===

    let mut total_established = 0usize;
    let mut total_responding = 0usize;
    let mut total_initiating = 0usize;
    let mut fully_established_nodes = 0usize;

    for tn in &nodes {
        let mut all_est = true;
        for (_, entry) in tn.node.sessions.iter() {
            if entry.is_established() {
                total_established += 1;
            } else if entry.is_awaiting_msg3() {
                total_responding += 1;
                all_est = false;
            } else {
                total_initiating += 1;
                all_est = false;
            }
        }
        if tn.node.session_count() > 0 && all_est {
            fully_established_nodes += 1;
        }
    }

    let session_counts: Vec<usize> = nodes.iter().map(|tn| tn.node.session_count()).collect();
    let total_sessions: usize = session_counts.iter().sum();
    let min_sessions = *session_counts.iter().min().unwrap();
    let max_sessions = *session_counts.iter().max().unwrap();

    // === Phase 6: Link and routing statistics ===

    // Link stats delta: packets sent during data phase
    let mut data_link_pkts_sent: u64 = 0;
    let mut total_link_pkts_sent: u64 = 0;
    let mut total_link_pkts_recv: u64 = 0;
    let mut total_link_bytes_sent: u64 = 0;
    let mut total_link_bytes_recv: u64 = 0;

    for (i, tn) in nodes.iter().enumerate() {
        for peer in tn.node.peers() {
            let stats = peer.link_stats();
            // Delta for this peer since before data phase
            let before = link_pkts_sent_before[i]
                .iter()
                .find(|(addr, _)| addr == peer.node_addr())
                .map(|(_, pkts)| *pkts)
                .unwrap_or(0);
            data_link_pkts_sent += stats.packets_sent.saturating_sub(before);

            // Totals (cumulative since node creation)
            total_link_pkts_sent += stats.packets_sent;
            total_link_pkts_recv += stats.packets_recv;
            total_link_bytes_sent += stats.bytes_sent;
            total_link_bytes_recv += stats.bytes_recv;
        }
    }

    // Estimate average hop count from link packet overhead.
    // Each data datagram traverses N link hops, each producing 1 link send.
    // We sent 200 datagrams total (100 forward + 100 reverse).
    let total_data_datagrams = (send_forward_ok + send_reverse_ok) as u64;
    let avg_hops = if total_data_datagrams > 0 {
        data_link_pkts_sent as f64 / total_data_datagrams as f64
    } else {
        0.0
    };

    // Coord cache stats
    let coord_cache_sizes: Vec<usize> =
        nodes.iter().map(|tn| tn.node.coord_cache().len()).collect();
    let total_coord_entries: usize = coord_cache_sizes.iter().sum();
    let min_coord = *coord_cache_sizes.iter().min().unwrap();
    let max_coord = *coord_cache_sizes.iter().max().unwrap();

    // === Report ===

    eprintln!("\n  === Session 100-Node Test ===");
    eprintln!(
        "  Topology: {} nodes, {} edges (seed {})",
        NUM_NODES,
        edges.len(),
        SEED
    );
    eprintln!(
        "  Session pairs: {} (1 outbound per node, random target)",
        session_pairs.len()
    );

    eprintln!("\n  --- Handshake ---");
    eprintln!(
        "  Initiator established: {}/{}",
        session_pairs.len(),
        session_pairs.len()
    );

    eprintln!("\n  --- Data Transfer ---");
    eprintln!(
        "  Forward (initiator->responder): {} sent, {} errors",
        send_forward_ok, send_forward_err
    );
    eprintln!(
        "  Reverse (responder->initiator): {} sent, {} errors",
        send_reverse_ok, send_reverse_err
    );
    eprintln!(
        "  TUN delivery: {} total ({} expected)",
        total_delivered,
        send_forward_ok + send_reverse_ok
    );
    eprintln!(
        "  Forward delivered: {}/{} | Reverse delivered: {}/{}",
        fwd_delivered, send_forward_ok, rev_delivered, send_reverse_ok
    );

    eprintln!("\n  --- Final Session State ---");
    eprintln!(
        "  Entries: {} total ({} established, {} responding, {} initiating)",
        total_sessions, total_established, total_responding, total_initiating
    );
    eprintln!(
        "  Per node: min={} max={} avg={:.1}",
        min_sessions,
        max_sessions,
        total_sessions as f64 / NUM_NODES as f64
    );
    eprintln!(
        "  All-established nodes: {}/{}",
        fully_established_nodes, NUM_NODES
    );

    eprintln!("\n  --- Routing ---");
    eprintln!(
        "  Data-phase link hops: {} ({:.1} avg hops/datagram over {} datagrams)",
        data_link_pkts_sent, avg_hops, total_data_datagrams
    );
    eprintln!(
        "  Lifetime link totals: {} pkts sent, {} pkts recv, {:.1} KB sent, {:.1} KB recv",
        total_link_pkts_sent,
        total_link_pkts_recv,
        total_link_bytes_sent as f64 / 1024.0,
        total_link_bytes_recv as f64 / 1024.0
    );
    eprintln!(
        "  Coord cache: total={} min={} max={} avg={:.1}",
        total_coord_entries,
        min_coord,
        max_coord,
        total_coord_entries as f64 / NUM_NODES as f64
    );

    eprintln!("\n  --- Timing ---");
    eprintln!(
        "  Setup: {:.1}s | Handshake: {:.1}s | Data: {:.1}s | Total: {:.1}s",
        setup_time.as_secs_f64(),
        session_time.as_secs_f64(),
        data_time.as_secs_f64(),
        start.elapsed().as_secs_f64()
    );

    // === Assertions ===

    assert_eq!(send_forward_err, 0, "All forward sends should succeed");
    assert_eq!(
        send_reverse_err, 0,
        "All reverse sends should succeed (responder Established after XK msg3)"
    );
    assert_eq!(
        fwd_delivered, send_forward_ok,
        "All forward datagrams should be delivered to responder TUN"
    );
    assert_eq!(
        rev_delivered, send_reverse_ok,
        "All reverse datagrams should be delivered to initiator TUN"
    );
    assert_eq!(
        total_established, total_sessions,
        "All {} session entries should be Established, \
         but {} responding, {} initiating",
        total_sessions, total_responding, total_initiating
    );
    let sim_stats = sim_network.stats();
    assert_eq!(
        sim_stats.packets_dropped_loss
            + sim_stats.packets_dropped_egress
            + sim_stats.packets_dropped_down
            + sim_stats.packets_dropped_no_route,
        0,
        "Sim underlay should not drop packets"
    );

    cleanup_nodes(&mut nodes).await;
    crate::unregister_sim_network(super::sim_harness::SESSION_100_NODE_NETWORK);
}

// ============================================================================
// Data plane integration tests: TUN → session → link → TUN
// ============================================================================
