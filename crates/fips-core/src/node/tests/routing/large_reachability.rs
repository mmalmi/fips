use super::*;

/// 100-node random graph: verify all-pairs routing reachability.
///
/// After tree and bloom filter convergence, simulates multi-hop packet
/// forwarding between every pair of nodes. Every packet must be delivered
/// without loops.
#[tokio::test]
async fn test_routing_reachability_100_nodes() {
    let _guard = lock_large_network_test().await;

    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;

    let edges = generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, false).await;
    verify_tree_convergence(&nodes);

    // Populate coord caches: every node learns every other node's coordinates.
    // In production this happens via SessionSetup/LookupResponse; here we
    // inject them directly. Bloom filter routing requires cached dest_coords
    // for loop-free forwarding — without coords, find_next_hop returns None.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Collect all (addr, coords) pairs first to avoid borrow issues
    let all_coords: Vec<(NodeAddr, TreeCoordinate)> = nodes
        .iter()
        .map(|tn| {
            (
                *tn.node.node_addr(),
                tn.node.tree_state().my_coords().clone(),
            )
        })
        .collect();

    for node in &mut nodes {
        for (addr, coords) in &all_coords {
            if addr != node.node.node_addr() {
                node.node
                    .coord_cache_mut()
                    .insert(*addr, coords.clone(), now_ms);
            }
        }
    }

    let addr_index = build_addr_index(&nodes);

    let mut total_pairs = 0;
    let mut total_hops = 0usize;
    let mut max_hops = 0usize;
    let mut failures = Vec::new();
    let mut loops = Vec::new();

    // Test all pairs
    for src in 0..NUM_NODES {
        for dst in 0..NUM_NODES {
            if src == dst {
                continue;
            }

            total_pairs += 1;

            match simulate_forwarding(&mut nodes, &addr_index, src, dst) {
                ForwardResult::Delivered(hops) => {
                    total_hops += hops;
                    if hops > max_hops {
                        max_hops = hops;
                    }
                }
                ForwardResult::NoRoute { at_node, hops } => {
                    failures.push((src, dst, at_node, hops));
                }
                ForwardResult::Loop { at_node, hops } => {
                    loops.push((src, dst, at_node, hops));
                }
            }
        }
    }

    let delivered = total_pairs - failures.len() - loops.len();
    let avg_hops = if delivered > 0 {
        total_hops as f64 / delivered as f64
    } else {
        0.0
    };

    eprintln!("\n  === Routing Reachability ({} nodes) ===", NUM_NODES);
    eprintln!(
        "  Pairs tested: {} | Delivered: {} | Failed: {} | Loops: {}",
        total_pairs,
        delivered,
        failures.len(),
        loops.len()
    );
    eprintln!("  Hops: avg={:.1} max={}", avg_hops, max_hops);

    if !failures.is_empty() {
        let show = failures.len().min(10);
        eprintln!("  First {} failures:", show);
        for &(src, dst, at_node, hops) in &failures[..show] {
            eprintln!(
                "    {} -> {}: stuck at node {} after {} hops",
                src, dst, at_node, hops
            );
        }
    }

    if !loops.is_empty() {
        let show = loops.len().min(10);
        eprintln!("  First {} loops:", show);
        for &(src, dst, at_node, hops) in &loops[..show] {
            eprintln!(
                "    {} -> {}: loop at node {} after {} hops",
                src, dst, at_node, hops
            );
        }
    }

    assert!(
        loops.is_empty(),
        "Detected {} routing loops out of {} pairs",
        loops.len(),
        total_pairs
    );
    assert!(
        failures.is_empty(),
        "Detected {} routing failures out of {} pairs",
        failures.len(),
        total_pairs
    );

    cleanup_nodes(&mut nodes).await;
}
