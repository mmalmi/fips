use super::*;

/// Generate a connected random graph with deterministic topology.
///
/// First builds a random spanning tree to ensure connectivity,
/// then adds extra edges up to the target count.
pub(in crate::node::tests) fn generate_random_edges(
    n: usize,
    target_edges: usize,
    seed: u64,
) -> Vec<(usize, usize)> {
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    let mut rng = StdRng::seed_from_u64(seed);
    let mut edges = Vec::new();
    let mut adj = vec![vec![false; n]; n];

    // Build a random spanning tree (ensures connectivity)
    let mut connected = vec![false; n];
    connected[0] = true;
    let mut connected_count = 1;

    while connected_count < n {
        let from = rng.random_range(0..n);
        if !connected[from] {
            continue;
        }
        let to = rng.random_range(0..n);
        if connected[to] || from == to {
            continue;
        }

        edges.push((from, to));
        adj[from][to] = true;
        adj[to][from] = true;
        connected[to] = true;
        connected_count += 1;
    }

    // Add random extra edges up to target
    let mut attempts = 0;
    while edges.len() < target_edges && attempts < target_edges * 10 {
        let a = rng.random_range(0..n);
        let b = rng.random_range(0..n);
        attempts += 1;
        if a == b || adj[a][b] {
            continue;
        }
        edges.push((a, b));
        adj[a][b] = true;
        adj[b][a] = true;
    }

    edges
}

/// Verify that all nodes in a connected component have converged to a
/// consistent spanning tree.
pub(in crate::node::tests) fn verify_tree_convergence(nodes: &[TestNode]) {
    let n = nodes.len();
    assert!(n > 0);

    // Find the expected root (smallest NodeAddr across all nodes)
    let expected_root = nodes.iter().map(|tn| *tn.node.node_addr()).min().unwrap();

    // All nodes should agree on the root
    for (i, tn) in nodes.iter().enumerate() {
        let ts = tn.node.tree_state();
        assert_eq!(
            *ts.root(),
            expected_root,
            "Node {} (addr={}) has root {} but expected {}",
            i,
            tn.node.node_addr(),
            ts.root(),
            expected_root
        );
    }

    // Root node should have is_root() == true and depth 0
    let root_node = nodes
        .iter()
        .find(|tn| *tn.node.node_addr() == expected_root)
        .unwrap();
    assert!(
        root_node.node.tree_state().is_root(),
        "Expected root node should have is_root = true"
    );
    assert_eq!(
        root_node.node.tree_state().my_coords().depth(),
        0,
        "Root node should have depth 0"
    );

    // Non-root nodes should have depth > 0
    for (i, tn) in nodes.iter().enumerate() {
        let ts = tn.node.tree_state();
        if *tn.node.node_addr() != expected_root {
            assert!(
                ts.my_coords().depth() > 0,
                "Non-root node {} should have depth > 0, got {}",
                i,
                ts.my_coords().depth()
            );
        }
    }

    // Each non-root node's parent should be one of its peers
    for (i, tn) in nodes.iter().enumerate() {
        let ts = tn.node.tree_state();
        if ts.is_root() {
            continue;
        }

        let parent_id = ts.my_declaration().parent_id();
        assert!(
            tn.node.get_peer(parent_id).is_some(),
            "Node {}'s parent {} should be in its peer list",
            i,
            parent_id
        );
    }

    // Each node's coordinate root should match expected root
    for (i, tn) in nodes.iter().enumerate() {
        let coords = tn.node.tree_state().my_coords();
        assert_eq!(
            *coords.root_id(),
            expected_root,
            "Node {}'s coordinate root {} should match expected root {}",
            i,
            coords.root_id(),
            expected_root
        );
    }

    // Depth consistency: child's depth = parent's depth + 1
    for (i, tn) in nodes.iter().enumerate() {
        let ts = tn.node.tree_state();
        if ts.is_root() {
            continue;
        }

        let my_depth = ts.my_coords().depth();
        let parent_id = ts.my_declaration().parent_id();

        // Find the parent node in our array
        if let Some(parent_node) = nodes.iter().find(|pn| pn.node.node_addr() == parent_id) {
            let parent_depth = parent_node.node.tree_state().my_coords().depth();
            assert_eq!(
                my_depth,
                parent_depth + 1,
                "Node {}'s depth ({}) should be parent's depth ({}) + 1",
                i,
                my_depth,
                parent_depth
            );
        }
    }
}

/// Verify tree convergence for disconnected components.
///
/// Each connected component should converge to its own root (smallest
/// NodeAddr in that component).
pub(in crate::node::tests) fn verify_tree_convergence_components(
    nodes: &[TestNode],
    components: &[Vec<usize>],
) {
    for component in components {
        let component_nodes: Vec<&TestNode> = component.iter().map(|&i| &nodes[i]).collect();

        let expected_root = component_nodes
            .iter()
            .map(|tn| *tn.node.node_addr())
            .min()
            .unwrap();

        for &idx in component {
            let ts = nodes[idx].node.tree_state();
            assert_eq!(
                *ts.root(),
                expected_root,
                "Node {} in component should have root {}",
                idx,
                expected_root
            );
        }
    }
}

/// Run a spanning tree test for a given set of edges.
///
/// Creates nodes, initiates handshakes, drains packets, and verifies convergence.
/// If `verbose` is true, prints topology and convergence progress.
pub(in crate::node::tests) async fn run_tree_test(
    num_nodes: usize,
    edges: &[(usize, usize)],
    verbose: bool,
) -> Vec<TestNode> {
    // Create nodes
    let mut nodes = Vec::new();
    for _ in 0..num_nodes {
        nodes.push(make_test_node().await);
    }

    if verbose {
        eprintln!(
            "\n  === Spanning Tree Convergence ({} nodes, {} edges) ===",
            num_nodes,
            edges.len()
        );
        let expected_root = nodes.iter().map(|tn| *tn.node.node_addr()).min().unwrap();
        let root_idx = nodes
            .iter()
            .position(|tn| *tn.node.node_addr() == expected_root)
            .unwrap();
        eprintln!("  Expected root: node[{}] = {}", root_idx, expected_root);

        // Compute average degree
        let mut degree = vec![0usize; num_nodes];
        for &(i, j) in edges {
            degree[i] += 1;
            degree[j] += 1;
        }
        let avg_degree = degree.iter().sum::<usize>() as f64 / num_nodes as f64;
        let max_degree = degree.iter().max().copied().unwrap_or(0);
        let min_degree = degree.iter().min().copied().unwrap_or(0);
        eprintln!(
            "  Degree: min={} max={} avg={:.1}",
            min_degree, max_degree, avg_degree
        );

        // Per-node/edge detail only for small networks
        if num_nodes <= 20 {
            let mut sorted: Vec<(usize, NodeAddr)> = nodes
                .iter()
                .enumerate()
                .map(|(i, tn)| (i, *tn.node.node_addr()))
                .collect();
            sorted.sort_by_key(|(_, addr)| *addr);
            eprintln!("  Node addresses (sorted, smallest = expected root):");
            for (i, addr) in &sorted {
                let marker = if *i == sorted[0].0 { " <-- root" } else { "" };
                eprintln!("    node[{}] = {}{}", i, addr, marker);
            }
            eprintln!("  Edges:");
            for (idx, &(i, j)) in edges.iter().enumerate() {
                eprintln!("    edge[{}]: node[{}] -- node[{}]", idx, i, j);
            }
        }
    }

    // Initiate handshakes in batches so synthetic one-shot UDP sends do not
    // overwhelm the localhost receive queues on slower CI runners.
    let mut initial_total = 0;
    for chunk in edges.chunks(16) {
        for &(i, j) in chunk {
            complete_direct_handshake(&mut nodes, i, j).await;
        }
        initial_total += drain_initial_handshake_burst(&mut nodes).await;
    }

    // Drain packets until convergence (handles rate-limited announces)
    let total = initial_total + drain_all_packets(&mut nodes, verbose).await;
    assert!(total > 0, "Should have processed at least some packets");
    let repaired = repair_missing_edge_handshakes(&mut nodes, edges, verbose).await;
    let refreshed = refresh_synthetic_filter_announces(&mut nodes, edges, verbose).await;

    if verbose {
        eprintln!("\n  Total packets processed: {}", total);
        if refreshed > 0 {
            eprintln!("  Synthetic filter refresh packets: {}", refreshed);
        }
        if repaired > 0 {
            eprintln!("  Synthetic handshake retries: {}", repaired);
            print_tree_snapshot("After synthetic handshake repair", &nodes);
        }
    }

    // Verify all edges established bidirectional peers
    for &(i, j) in edges {
        let j_addr = *nodes[j].node.node_addr();
        let i_addr = *nodes[i].node.node_addr();

        assert!(
            nodes[i].node.get_peer(&j_addr).is_some(),
            "Node {} should have peer {} (node {})",
            i,
            j_addr,
            j
        );
        assert!(
            nodes[j].node.get_peer(&i_addr).is_some(),
            "Node {} should have peer {} (node {})",
            j,
            i_addr,
            i
        );
    }

    nodes
}

/// Like `run_tree_test` but with per-node transport MTUs.
///
/// `mtus` must have one entry per node. Used for heterogeneous-MTU tests
/// where different hops have different link-layer capacities.
pub(in crate::node::tests) async fn run_tree_test_with_mtus(
    mtus: &[u16],
    edges: &[(usize, usize)],
) -> Vec<TestNode> {
    let mut nodes = Vec::new();
    for &mtu in mtus {
        nodes.push(make_test_node_with_mtu(mtu).await);
    }

    let mut initial_total = 0;
    for chunk in edges.chunks(16) {
        for &(i, j) in chunk {
            complete_direct_handshake(&mut nodes, i, j).await;
        }
        initial_total += drain_initial_handshake_burst(&mut nodes).await;
    }

    let total = initial_total + drain_all_packets(&mut nodes, false).await;
    assert!(total > 0, "Should have processed at least some packets");
    let _ = repair_missing_edge_handshakes(&mut nodes, edges, false).await;
    let _ = refresh_synthetic_filter_announces(&mut nodes, edges, false).await;

    for &(i, j) in edges {
        let j_addr = *nodes[j].node.node_addr();
        let i_addr = *nodes[i].node.node_addr();
        assert!(
            nodes[i].node.get_peer(&j_addr).is_some(),
            "Node {} should have peer {} (node {})",
            i,
            j_addr,
            j
        );
        assert!(
            nodes[j].node.get_peer(&i_addr).is_some(),
            "Node {} should have peer {} (node {})",
            j,
            i_addr,
            i
        );
    }

    nodes
}

/// Clean up transports for all test nodes.
pub(in crate::node::tests) async fn cleanup_nodes(nodes: &mut [TestNode]) {
    for tn in nodes.iter_mut() {
        for (_, t) in tn.node.transports.iter_mut() {
            t.stop().await.ok();
        }
    }
}
