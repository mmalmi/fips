use super::*;

#[tokio::test]
async fn test_established_initiator_resends_final_msg3_until_responder_establishes() {
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    nodes[0]
        .node
        .config
        .node
        .rate_limit
        .handshake_resend_interval_ms = 5;
    nodes[0].node.config.node.rate_limit.handshake_max_resends = 3;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("session initiation should start");

    let count = wait_process_packets_for_node(&mut nodes, 1).await;
    assert!(count > 0, "SessionSetup should reach responder");
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .state()
            .is_awaiting_msg3()
    );

    let count = wait_process_packets_for_node(&mut nodes, 0).await;
    assert!(count > 0, "SessionAck should reach initiator");
    let initiator_entry = nodes[0].node.get_session(&node1_addr).unwrap();
    assert!(initiator_entry.state().is_established());
    assert!(
        initiator_entry.handshake_payload().is_some(),
        "initiator should retain final msg3 for loss recovery"
    );

    tokio::time::sleep(Duration::from_millis(10)).await;
    let mut dropped = 0;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        dropped += drop_queued_packets_for_node(&mut nodes[1]);
        if dropped > 0 {
            break;
        }
    }
    assert!(dropped > 0, "fixture should drop the first SessionMsg3");
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .state()
            .is_awaiting_msg3(),
        "responder should still be waiting after the dropped msg3"
    );

    tokio::time::sleep(Duration::from_millis(10)).await;
    let now_ms = Node::now_ms();
    nodes[0]
        .node
        .resend_pending_session_handshakes(now_ms)
        .await;

    let count = wait_process_packets_for_node(&mut nodes, 1).await;
    assert!(
        count > 0,
        "resender should deliver a replacement SessionMsg3"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .state()
            .is_established(),
        "responder should establish from the resent SessionMsg3"
    );

    nodes[1]
        .node
        .send_session_data(&node0_addr, 0, 0, b"responder-proof")
        .await
        .expect("responder should send data after establishment");
    let count = wait_process_packets_for_node(&mut nodes, 0).await;
    assert!(count > 0, "initiator should receive responder proof data");
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .handshake_payload()
            .is_none(),
        "authentic responder traffic should clear the retained final msg3"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_rekey_initiator_resends_final_msg3_until_responder_has_pending_session() {
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    nodes[0]
        .node
        .config
        .node
        .rate_limit
        .handshake_resend_interval_ms = 5;
    nodes[0].node.config.node.rate_limit.handshake_max_resends = 3;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initial session should start");
    drain_to_quiescence(&mut nodes).await;

    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .state()
            .is_established()
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .state()
            .is_established()
    );

    assert!(
        nodes[0].node.initiate_session_rekey(&node1_addr).await,
        "rekey should start"
    );

    let count = wait_process_packets_for_node(&mut nodes, 1).await;
    assert!(count > 0, "rekey msg1 should reach responder");

    let count = wait_process_packets_for_node(&mut nodes, 0).await;
    assert!(count > 0, "rekey msg2 should reach initiator");
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "initiator should have a pending new session"
    );
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .rekey_msg3_payload()
            .is_some(),
        "initiator must retain rekey msg3 for resend"
    );

    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if drop_queued_packets_for_node(&mut nodes[1]) > 0 {
            break;
        }
    }
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .pending_new_session()
            .is_none(),
        "responder should not have the new session before msg3 is resent"
    );

    nodes[1]
        .node
        .send_session_data(&node0_addr, 0, 0, b"old-session-proof")
        .await
        .expect("old session should remain usable while rekey msg3 is pending");
    let count = wait_process_packets_for_node(&mut nodes, 0).await;
    assert!(count > 0, "old-session proof should reach initiator");
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .rekey_msg3_payload()
            .is_some(),
        "old-session traffic must not clear retained rekey msg3"
    );
    let resend_count_before = nodes[0]
        .node
        .get_session(&node1_addr)
        .unwrap()
        .rekey_msg3_resend_count();

    tokio::time::sleep(Duration::from_millis(10)).await;
    let now_ms = Node::now_ms();
    nodes[0].node.resend_pending_session_msg3(now_ms).await;
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .rekey_msg3_resend_count()
            > resend_count_before,
        "rekey msg3 resend should be recorded"
    );

    let count = wait_process_packets_for_node(&mut nodes, 1).await;
    assert!(
        count > 0,
        "resender should deliver a replacement rekey msg3"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "responder should store the pending rekey session after resent msg3"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_rekey_initiator_resends_msg1_when_first_setup_lost() {
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    nodes[0]
        .node
        .config
        .node
        .rate_limit
        .handshake_resend_interval_ms = 5;
    nodes[0].node.config.node.rate_limit.handshake_max_resends = 3;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initial session should start");
    drain_to_quiescence(&mut nodes).await;

    assert!(
        nodes[0].node.initiate_session_rekey(&node1_addr).await,
        "rekey should start"
    );
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .handshake_payload()
            .is_some(),
        "initiator must retain rekey msg1 for resend"
    );

    let dropped = wait_drop_queued_packets_for_node(&mut nodes[1]).await;
    assert!(dropped > 0, "fixture should drop the first rekey msg1");

    tokio::time::sleep(Duration::from_millis(10)).await;
    nodes[0]
        .node
        .resend_pending_session_handshakes(Node::now_ms())
        .await;

    let count = wait_process_packets_for_node(&mut nodes, 1).await;
    assert!(count > 0, "resender should deliver replacement rekey msg1");
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .has_rekey_in_progress(),
        "responder should process the resent rekey msg1"
    );
    assert!(
        !nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .is_rekey_initiator(),
        "responder side should not become a competing initiator"
    );

    let count = wait_process_packets_for_node(&mut nodes, 0).await;
    assert!(count > 0, "rekey msg2 should reach initiator");
    let entry = nodes[0].node.get_session(&node1_addr).unwrap();
    assert!(
        entry.pending_new_session().is_some(),
        "initiator should complete XK after resent msg1"
    );
    assert!(
        entry.handshake_payload().is_none(),
        "rekey msg1 resend payload should clear once msg2 arrives"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_rekey_msg1_exhaustion_allows_peer_msg1_to_converge() {
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initial session should start");
    drain_to_quiescence(&mut nodes).await;

    let smaller = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        0
    } else {
        1
    };
    let larger = 1 - smaller;
    let smaller_addr = *nodes[smaller].node.node_addr();
    let larger_addr = *nodes[larger].node.node_addr();

    nodes[smaller]
        .node
        .config
        .node
        .rate_limit
        .handshake_max_resends = 0;
    assert!(
        nodes[smaller]
            .node
            .initiate_session_rekey(&larger_addr)
            .await,
        "smaller side should start local rekey"
    );
    assert!(
        nodes[smaller]
            .node
            .get_session(&larger_addr)
            .unwrap()
            .handshake_payload()
            .is_some(),
        "local rekey msg1 should be retained before exhaustion"
    );

    let dropped = wait_drop_queued_packets_for_node(&mut nodes[larger]).await;
    assert!(dropped > 0, "fixture should drop smaller side's rekey msg1");

    nodes[smaller]
        .node
        .resend_pending_session_handshakes(Node::now_ms())
        .await;
    let entry = nodes[smaller].node.get_session(&larger_addr).unwrap();
    assert!(
        !entry.has_rekey_in_progress(),
        "exhausted local rekey should be abandoned"
    );
    assert!(
        entry.handshake_payload().is_none(),
        "abandoning local rekey must clear stale msg1 payload"
    );

    assert!(
        nodes[larger]
            .node
            .initiate_session_rekey(&smaller_addr)
            .await,
        "larger side should be able to start its own fresh rekey"
    );
    let count = wait_process_packets_for_node(&mut nodes, smaller).await;
    assert!(
        count > 0,
        "smaller side should process peer msg1 after abandoning stale local rekey"
    );
    let entry = nodes[smaller].node.get_session(&larger_addr).unwrap();
    assert!(
        entry.has_rekey_in_progress(),
        "smaller side should now be the rekey responder"
    );
    assert!(
        !entry.is_rekey_initiator(),
        "stale tiebreak winner must not keep dropping peer msg1"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_session_100_nodes() {
    let _guard = lock_large_network_test().await;

    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};
    use std::sync::mpsc;
    use std::time::Instant;

    // Same random topology as other 100-node tests
    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;

    let start = Instant::now();

    let edges = generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let setup_time = start.elapsed();

    // Collect identities: (node_addr, pubkey) for all nodes
    let all_info: Vec<(NodeAddr, secp256k1::PublicKey)> = nodes
        .iter()
        .map(|tn| (*tn.node.node_addr(), tn.node.identity().pubkey_full()))
        .collect();

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

        drain_to_quiescence(&mut nodes).await;
    }

    drain_to_quiescence(&mut nodes).await;
    let session_time = session_start.elapsed();

    // Verify all initiator sessions reached Established before data phase
    let mut handshake_failures: Vec<(usize, usize)> = Vec::new();
    for &(src, dst) in &session_pairs {
        let dest_addr = all_info[dst].0;
        let ok = nodes[src]
            .node
            .get_session(&dest_addr)
            .map(|e| e.state().is_established())
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
    let mut tun_receivers: Vec<mpsc::Receiver<Vec<u8>>> = Vec::with_capacity(NUM_NODES);
    for tn in nodes.iter_mut() {
        let (tx, rx) = mpsc::channel();
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
    // Batched per pair with draining between each.

    let data_start = Instant::now();
    let mut send_forward_ok = 0usize;
    let mut send_forward_err = 0usize;
    let mut send_reverse_ok = 0usize;
    let mut send_reverse_err = 0usize;

    for (pair_idx, &(src, dst)) in session_pairs.iter().enumerate() {
        let dest_addr = all_info[dst].0;
        let src_addr = all_info[src].0;

        // Build IPv6 packets with pair index as payload
        let src_fips = crate::FipsAddress::from_node_addr(&src_addr);
        let dst_fips = crate::FipsAddress::from_node_addr(&dest_addr);

        // Forward: initiator → responder
        let fwd_payload = format!("fwd-{}", pair_idx).into_bytes();
        let fwd_ipv6 = build_ipv6_packet(&src_fips, &dst_fips, &fwd_payload);
        match nodes[src]
            .node
            .send_ipv6_packet(&dest_addr, &fwd_ipv6)
            .await
        {
            Ok(()) => send_forward_ok += 1,
            Err(_) => send_forward_err += 1,
        }

        drain_to_quiescence(&mut nodes).await;

        // Reverse: responder → initiator
        // (Responder should already be Established after XK msg3)
        let rev_payload = format!("rev-{}", pair_idx).into_bytes();
        let rev_ipv6 = build_ipv6_packet(&dst_fips, &src_fips, &rev_payload);
        match nodes[dst].node.send_ipv6_packet(&src_addr, &rev_ipv6).await {
            Ok(()) => send_reverse_ok += 1,
            Err(_) => send_reverse_err += 1,
        }

        drain_to_quiescence(&mut nodes).await;
    }

    let data_time = data_start.elapsed();

    // === Phase 4: Collect delivered datagrams from TUN receivers ===

    let mut delivered_per_node: Vec<Vec<Vec<u8>>> = Vec::with_capacity(NUM_NODES);
    for rx in tun_receivers.iter_mut() {
        let mut packets = Vec::new();
        while let Ok(pkt) = rx.try_recv() {
            packets.push(pkt);
        }
        delivered_per_node.push(packets);
    }

    let total_delivered: usize = delivered_per_node.iter().map(|v| v.len()).sum();

    // Verify each pair's forward and reverse datagrams arrived
    let mut fwd_delivered = 0usize;
    let mut rev_delivered = 0usize;
    let mut fwd_missing: Vec<(usize, usize)> = Vec::new();
    let mut rev_missing: Vec<(usize, usize)> = Vec::new();

    for (pair_idx, &(src, dst)) in session_pairs.iter().enumerate() {
        let fwd_payload = format!("fwd-{}", pair_idx).into_bytes();
        let rev_payload = format!("rev-{}", pair_idx).into_bytes();

        // After decompression, TUN receives full IPv6 packets.
        // Check that delivered packet's upper-layer payload matches.
        let fwd_found = delivered_per_node[dst]
            .iter()
            .any(|pkt| pkt.len() >= 40 && pkt[40..] == fwd_payload);
        if fwd_found {
            fwd_delivered += 1;
        } else if fwd_missing.len() < 20 {
            fwd_missing.push((src, dst));
        }

        let rev_found = delivered_per_node[src]
            .iter()
            .any(|pkt| pkt.len() >= 40 && pkt[40..] == rev_payload);
        if rev_found {
            rev_delivered += 1;
        } else if rev_missing.len() < 20 {
            rev_missing.push((src, dst));
        }
    }

    // === Phase 5: Final session state ===

    let mut total_established = 0usize;
    let mut total_responding = 0usize;
    let mut total_initiating = 0usize;
    let mut fully_established_nodes = 0usize;

    for tn in &nodes {
        let mut all_est = true;
        for (_, entry) in tn.node.sessions.iter() {
            if entry.state().is_established() {
                total_established += 1;
            } else if entry.state().is_awaiting_msg3() {
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

    if !fwd_missing.is_empty() {
        eprintln!(
            "\n  First {} undelivered forward datagrams:",
            fwd_missing.len()
        );
        for &(src, dst) in &fwd_missing {
            eprintln!("    node {} -> node {}", src, dst);
        }
    }
    if !rev_missing.is_empty() {
        eprintln!(
            "\n  First {} undelivered reverse datagrams:",
            rev_missing.len()
        );
        for &(src, dst) in &rev_missing {
            eprintln!("    node {} <- node {}", src, dst);
        }
    }

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

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Data plane integration tests: TUN → session → link → TUN
// ============================================================================
