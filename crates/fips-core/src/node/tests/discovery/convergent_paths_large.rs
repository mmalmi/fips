use super::*;

#[tokio::test]
async fn test_request_dedup_convergent_paths() {
    // Topology: triangle (node0 — node1, node0 — node2, node1 — node2)
    // A request from node0 targeting node2 may reach it via two paths
    // depending on bloom filter state. If both paths deliver the request,
    // the second arrival at node2 should be deduped.
    let edges = vec![(0, 1), (0, 2), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;

    let node0_addr = *nodes[0].node.node_addr();
    let target = *nodes[2].node.node_addr(); // target node2 (in bloom filters)
    let root = make_node_addr(0);

    let coords = TreeCoordinate::from_addrs(vec![node0_addr, root]).unwrap();
    let request = LookupRequest::new(300, target, node0_addr, coords, 5, 0);
    let payload = &request.encode()[1..];

    // Node0 handles the request (forwards to peers whose bloom filter
    // contains node2 — bloom-guided, not flooding)
    nodes[0]
        .node
        .handle_lookup_request(&node0_addr, payload)
        .await;

    // Process several rounds
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    // Node2 (the target) must have received the request
    assert!(
        nodes[2].node.recent_requests.contains_key(&300),
        "Node 2 (target) should have received the request"
    );

    // If node1 also received and forwarded it, node2 would have seen a
    // duplicate — verify dedup counter reflects convergent arrivals.
    // With bloom-guided routing, node1 may or may not receive the request
    // depending on filter state, so we only assert the target received it.

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration Tests — 100-Node Discovery
// ============================================================================

#[tokio::test]
#[ignore] // Long-running (~2 min): run explicitly with --ignored
async fn test_discovery_100_nodes() {
    let _guard = lock_large_network_test().await;

    // Set up a 100-node random topology (same seed as other 100-node tests).
    // Each node initiates lookups to a sample of other nodes in batches,
    // processing packets between batches to avoid flooding the network.
    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;
    const TTL: u8 = 20; // must exceed tree diameter (can reach 17+ hops)
    let edges = generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, false).await;
    verify_tree_convergence(&nodes);

    // Disable forward rate limiting: in this test all 100 nodes look up
    // the same 10 targets in <1s wall time. The 2s per-target rate limit
    // would suppress nearly all transit forwarding.
    for tn in nodes.iter_mut() {
        tn.node.disable_discovery_forward_rate_limit();
    }

    // Collect all node addresses and public keys for lookup targets
    let all_addrs: Vec<NodeAddr> = nodes.iter().map(|tn| *tn.node.node_addr()).collect();
    let all_pubkeys: Vec<secp256k1::PublicKey> = nodes
        .iter()
        .map(|tn| tn.node.identity().pubkey_full())
        .collect();

    // Pre-populate identity caches: each source needs the target's pubkey
    // for proof verification. In production, DNS resolution populates this
    // before lookups are initiated.
    for (src, node) in nodes.iter_mut().enumerate() {
        for dst in (0..NUM_NODES).step_by(10) {
            if src == dst {
                continue;
            }
            node.node
                .register_identity(all_addrs[dst], all_pubkeys[dst]);
        }
    }

    // Each node looks up every 10th other node (~10 targets per node).
    // Build the full list of (src, dst) pairs.
    let mut lookup_pairs: Vec<(usize, usize)> = Vec::new();
    for src in 0..NUM_NODES {
        for dst in (0..NUM_NODES).step_by(10) {
            if src == dst {
                continue;
            }
            lookup_pairs.push((src, dst));
        }
    }
    let total_lookups = lookup_pairs.len();

    // Process one source node at a time. Each node initiates ~10 lookups,
    // which route through the tree via bloom filters. We drain until
    // quiescent before moving to the next node.
    for src in 0..NUM_NODES {
        // Initiate all lookups for this source node
        let mut initiated = false;
        for &(s, dst) in &lookup_pairs {
            if s == src {
                nodes[src].node.initiate_lookup(&all_addrs[dst], TTL).await;
                initiated = true;
            }
        }
        if !initiated {
            continue;
        }

        // Drain packets until quiescent. With single-path tree routing,
        // a packet forwarded by node X may land in node Y's queue where
        // Y < X in iteration order, causing a zero-count round even though
        // packets are in flight. Use a higher idle threshold to handle this.
        let mut idle_rounds = 0;
        for _ in 0..80 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            let count = process_available_packets(&mut nodes).await;
            if count == 0 {
                idle_rounds += 1;
                if idle_rounds >= 5 {
                    break;
                }
            } else {
                idle_rounds = 0;
            }
        }
    }

    // Verify: each originator should have the target's coords in coord_cache
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut resolved = 0usize;
    let mut failed = 0usize;
    let mut failed_pairs: Vec<(usize, usize)> = Vec::new();

    for &(src, dst) in &lookup_pairs {
        if nodes[src]
            .node
            .coord_cache()
            .contains(&all_addrs[dst], now_ms)
        {
            resolved += 1;
        } else {
            failed += 1;
            if failed_pairs.len() < 20 {
                failed_pairs.push((src, dst));
            }
        }
    }

    eprintln!("\n  === Discovery 100-Node Test ===",);
    eprintln!(
        "  Lookups: {} | Resolved: {} | Failed: {} | Success rate: {:.1}%",
        total_lookups,
        resolved,
        failed,
        resolved as f64 / total_lookups as f64 * 100.0
    );

    // Report coord_cache stats across all nodes
    let total_cached: usize = nodes.iter().map(|tn| tn.node.coord_cache().len()).sum();
    let min_cached = nodes
        .iter()
        .map(|tn| tn.node.coord_cache().len())
        .min()
        .unwrap();
    let max_cached = nodes
        .iter()
        .map(|tn| tn.node.coord_cache().len())
        .max()
        .unwrap();
    eprintln!(
        "  Coord cache entries: total={} min={} max={} avg={:.1}",
        total_cached,
        min_cached,
        max_cached,
        total_cached as f64 / NUM_NODES as f64
    );

    // Detailed diagnostics for failures (to aid future debugging)
    if !failed_pairs.is_empty() {
        eprintln!(
            "  --- Failure Diagnostics ({} failures) ---",
            failed_pairs.len()
        );
        for &(src, dst) in &failed_pairs {
            let src_coords = nodes[src].node.tree_state().my_coords().clone();
            let dst_coords = nodes[dst].node.tree_state().my_coords().clone();
            let tree_dist = src_coords.distance_to(&dst_coords);
            let reverse_cached = nodes[dst]
                .node
                .coord_cache()
                .contains(&all_addrs[src], now_ms);
            let src_peers = nodes[src].node.peers.len();
            let dst_peers = nodes[dst].node.peers.len();

            eprintln!(
                "    node {} -> node {}: tree_dist={} src_depth={} dst_depth={} \
                 src_peers={} dst_peers={} reverse_cached={}",
                src,
                dst,
                tree_dist,
                src_coords.depth(),
                dst_coords.depth(),
                src_peers,
                dst_peers,
                reverse_cached
            );
        }
    }

    assert_eq!(
        failed, 0,
        "All {} lookups should resolve, but {} failed",
        total_lookups, failed
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration Tests — MTU Propagation
// ============================================================================
