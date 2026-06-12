use super::*;

/// Print a snapshot of each node's tree state.
///
/// For small networks (≤20 nodes) prints per-node detail.
/// For larger networks prints a compact summary with depth histogram.
pub(in crate::node::tests) fn print_tree_snapshot(label: &str, nodes: &[TestNode]) {
    eprintln!("\n  --- {} ---", label);

    // Find expected root for reference
    let expected_root = nodes.iter().map(|tn| *tn.node.node_addr()).min().unwrap();
    let expected_root_idx = nodes
        .iter()
        .position(|tn| *tn.node.node_addr() == expected_root)
        .unwrap();

    // Count how many nodes agree on the correct root
    let correct_root_count = nodes
        .iter()
        .filter(|tn| *tn.node.tree_state().root() == expected_root)
        .count();
    let total_pending: usize = nodes
        .iter()
        .map(|tn| {
            tn.node
                .peers
                .values()
                .filter(|p| p.has_pending_tree_announce())
                .count()
        })
        .sum();

    // Build depth histogram
    let mut depth_counts = std::collections::BTreeMap::new();
    for tn in nodes {
        *depth_counts
            .entry(tn.node.tree_state().my_coords().depth())
            .or_insert(0usize) += 1;
    }
    let depth_str: Vec<String> = depth_counts
        .iter()
        .map(|(d, c)| format!("d{}={}", d, c))
        .collect();

    // Count distinct roots
    let mut roots = std::collections::BTreeSet::new();
    for tn in nodes {
        roots.insert(*tn.node.tree_state().root());
    }

    eprintln!(
        "  converged={}/{} roots={} depths=[{}] pending={}",
        correct_root_count,
        nodes.len(),
        roots.len(),
        depth_str.join(" "),
        total_pending,
    );

    // Per-node detail for small networks
    if nodes.len() <= 20 {
        for (i, tn) in nodes.iter().enumerate() {
            let ts = tn.node.tree_state();
            let parent_idx = if ts.is_root() {
                "self".to_string()
            } else {
                nodes
                    .iter()
                    .position(|n| n.node.node_addr() == ts.my_declaration().parent_id())
                    .map(|p| format!("{}", p))
                    .unwrap_or_else(|| format!("?{}", ts.my_declaration().parent_id()))
            };
            let root_idx = nodes
                .iter()
                .position(|n| n.node.node_addr() == ts.root())
                .map(|r| format!("{}", r))
                .unwrap_or_else(|| format!("?{}", ts.root()));
            let pending = tn
                .node
                .peers
                .values()
                .filter(|p| p.has_pending_tree_announce())
                .count();
            eprintln!(
                "  node[{}] root=node[{}] depth={} parent=node[{}] peers={} pending={}",
                i,
                root_idx,
                ts.my_coords().depth(),
                parent_idx,
                tn.node.peer_count(),
                pending,
            );
        }
    } else if correct_root_count < nodes.len() {
        // For large networks that haven't converged, show which nodes are wrong
        let wrong: Vec<usize> = nodes
            .iter()
            .enumerate()
            .filter(|(_, tn)| *tn.node.tree_state().root() != expected_root)
            .map(|(i, _)| i)
            .collect();
        if wrong.len() <= 20 {
            eprintln!("  unconverged nodes: {:?}", wrong);
        } else {
            eprintln!("  unconverged nodes: {} remaining", wrong.len());
        }
    }

    let _ = expected_root_idx; // suppress unused
}
