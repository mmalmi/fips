use super::*;

fn synthetic_component_roots(nodes: &[TestNode], edges: &[(usize, usize)]) -> Vec<NodeAddr> {
    let mut adjacency = vec![Vec::new(); nodes.len()];
    for &(left, right) in edges {
        adjacency[left].push(right);
        adjacency[right].push(left);
    }

    let mut roots = nodes
        .iter()
        .map(|node| *node.node.node_addr())
        .collect::<Vec<_>>();
    let mut visited = vec![false; nodes.len()];
    for start in 0..nodes.len() {
        if visited[start] {
            continue;
        }
        let mut stack = vec![start];
        let mut component = Vec::new();
        visited[start] = true;
        while let Some(index) = stack.pop() {
            component.push(index);
            for &neighbor in &adjacency[index] {
                if !visited[neighbor] {
                    visited[neighbor] = true;
                    stack.push(neighbor);
                }
            }
        }
        let root = component
            .iter()
            .map(|&index| *nodes[index].node.node_addr())
            .min()
            .expect("synthetic component contains its start node");
        for index in component {
            roots[index] = root;
        }
    }
    roots
}

fn synthetic_tree_converged(nodes: &[TestNode], expected_roots: &[NodeAddr]) -> bool {
    if nodes.len() != expected_roots.len() {
        return false;
    }

    nodes.iter().enumerate().all(|(index, node)| {
        let expected_root = expected_roots[index];
        let tree = node.node.tree_state();
        *tree.root() == expected_root
            && *tree.my_coords().root_id() == expected_root
            && if *node.node.node_addr() == expected_root {
                tree.is_root() && tree.my_coords().depth() == 0
            } else {
                let parent_addr = tree.my_declaration().parent_id();
                nodes
                    .iter()
                    .find(|candidate| candidate.node.node_addr() == parent_addr)
                    .is_some_and(|parent| {
                        let parent_tree = parent.node.tree_state();
                        !tree.is_root()
                            && tree.my_coords().depth() > 0
                            && node.node.get_peer(parent_addr).is_some()
                            && parent_tree
                                .peer_declaration(node.node.node_addr())
                                .is_some_and(|declaration| {
                                    declaration.parent_id() == parent_addr
                                        && declaration.sequence()
                                            == tree.my_declaration().sequence()
                                })
                            && parent_tree.peer_coords(node.node.node_addr())
                                == Some(tree.my_coords())
                    })
            }
    })
}

pub(in crate::node::tests) async fn repair_synthetic_tree_announces(
    nodes: &mut [TestNode],
    edges: &[(usize, usize)],
    verbose: bool,
) {
    let expected_roots = synthetic_component_roots(nodes, edges);
    for round in 0..nodes.len().saturating_mul(2).max(8) {
        if synthetic_tree_converged(nodes, &expected_roots) {
            return;
        }
        if verbose {
            eprintln!("  Direct synthetic TreeAnnounce repair round {}", round + 1);
        }

        for &(left, right) in edges {
            for (sender, receiver) in [(left, right), (right, left)] {
                let sender_addr = *nodes[sender].node.node_addr();
                let encoded = nodes[sender]
                    .node
                    .build_tree_announce()
                    .expect("synthetic TreeAnnounce should build")
                    .encode()
                    .expect("synthetic TreeAnnounce should encode");
                nodes[receiver]
                    .node
                    .handle_tree_announce(&sender_addr, &encoded[1..])
                    .await;
            }
        }
    }

    assert!(
        synthetic_tree_converged(nodes, &expected_roots),
        "synthetic topology did not converge after direct TreeAnnounce repair"
    );
}

pub(in crate::node::tests) async fn run_synthetic_node_work(nodes: &mut [TestNode]) {
    let now_ms = Node::now_ms();
    for tn in nodes.iter_mut() {
        tn.node.resend_pending_handshakes(now_ms).await;
        tn.node.send_pending_tree_announces().await;
        tn.node.send_pending_filter_announces().await;
    }
}

pub(in crate::node::tests) fn has_synthetic_pending_work(nodes: &[TestNode]) -> bool {
    nodes.iter().any(|tn| {
        !tn.node.peers.connection_is_empty()
            || tn.node.peers.iter().any(|(addr, peer)| {
                peer.has_pending_tree_announce() || tn.node.bloom_state.needs_update(addr)
            })
    })
}

pub(in crate::node::tests) async fn drain_synthetic_packets_until_idle(
    nodes: &mut [TestNode],
    max_rounds: usize,
    sleep_ms: u64,
) -> usize {
    let mut total = 0;
    let mut idle_rounds = 0;

    for _ in 0..max_rounds {
        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
        run_synthetic_node_work(nodes).await;

        let count = process_available_packets(nodes).await;
        total += count;
        if count == 0 {
            idle_rounds += 1;
            if idle_rounds >= 3 && !has_synthetic_pending_work(nodes) {
                break;
            }
        } else {
            idle_rounds = 0;
        }
    }

    total
}

fn has_current_edge_filter_from(nodes: &[TestNode], receiver: usize, sender: usize) -> bool {
    let sender_addr = *nodes[sender].node.node_addr();
    let receiver_addr = *nodes[receiver].node.node_addr();
    let expected = nodes[sender]
        .node
        .bloom_state
        .compute_outgoing_filter(&receiver_addr, &nodes[sender].node.peer_inbound_filters());
    nodes[receiver]
        .node
        .get_peer(&sender_addr)
        .and_then(|peer| peer.inbound_filter())
        == Some(&expected)
}

fn missing_edge_filters(nodes: &[TestNode], edges: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut missing = Vec::new();
    for &(i, j) in edges {
        if !has_current_edge_filter_from(nodes, i, j) {
            missing.push((j, i));
        }
        if !has_current_edge_filter_from(nodes, j, i) {
            missing.push((i, j));
        }
    }
    missing
}

async fn repair_missing_edge_filters(
    nodes: &mut [TestNode],
    edges: &[(usize, usize)],
    verbose: bool,
) -> usize {
    let mut injected = 0;
    for round in 0..nodes.len().max(1) {
        let missing = missing_edge_filters(nodes, edges);
        if missing.is_empty() {
            return injected;
        }
        if verbose {
            eprintln!(
                "  Direct synthetic filter repair round {}: {} direction(s)",
                round + 1,
                missing.len(),
            );
        }
        for (sender, receiver) in missing {
            let sender_addr = *nodes[sender].node.node_addr();
            let receiver_addr = *nodes[receiver].node.node_addr();
            let encoded = nodes[sender]
                .node
                .build_filter_announce(&receiver_addr)
                .encode()
                .expect("synthetic FilterAnnounce should encode");
            nodes[receiver]
                .node
                .handle_filter_announce(&sender_addr, &encoded[1..])
                .await;
            injected += 1;
        }
    }

    let remaining = missing_edge_filters(nodes, edges);
    assert!(
        remaining.is_empty(),
        "synthetic topology filters did not converge: {}",
        remaining
            .iter()
            .map(|(sender, receiver)| format!("{}->{}", sender, receiver))
            .collect::<Vec<_>>()
            .join(", ")
    );
    injected
}

pub(in crate::node::tests) async fn refresh_synthetic_filter_announces(
    nodes: &mut [TestNode],
    edges: &[(usize, usize)],
    verbose: bool,
) -> usize {
    let mut total = 0;

    for _ in 0..4 {
        for tn in nodes.iter_mut() {
            tn.node.send_tree_announce_to_all().await;
        }
        total += drain_synthetic_packets_until_idle(nodes, 80, 10).await;
    }

    for _ in 0..4 {
        for tn in nodes.iter_mut() {
            let peers: Vec<NodeAddr> = tn.node.peers.keys().copied().collect();
            tn.node.bloom_state.mark_all_updates_needed(peers);
        }
        total += drain_synthetic_packets_until_idle(nodes, 80, 10).await;
    }

    total += repair_missing_edge_filters(nodes, edges, verbose).await;

    total
}
