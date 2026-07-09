use super::*;

#[test]
fn test_effective_depth_selects_lower_cost_deeper_peer() {
    // Peer A at depth 1 with high cost (LoRa), peer B at depth 2 with low cost (fiber).
    // effective_depth(A) = 1 + 6.0 = 7.0
    // effective_depth(B) = 2 + 1.01 = 3.01
    // Should select B despite being deeper.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    // Peer A: depth 1
    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    // Peer B: depth 2
    state.update_peer(
        ParentDeclaration::new(peer_b, make_node_addr(3), 1, 1000),
        make_coords(&[2, 3, 0]),
    );

    let costs = make_costs(&[(1, 6.0), (2, 1.01)]);
    let result = state.evaluate_parent(&costs);
    assert_eq!(result, Some(peer_b));
}

#[test]
fn test_effective_depth_equal_cost_degenerates_to_depth() {
    // Both peers at cost 1.0 (default). Should pick shallowest, same as v1.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);
    let root = make_node_addr(0);

    // Peer 1: depth 1
    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    // Peer 2: depth 3
    state.update_peer(
        ParentDeclaration::new(peer2, make_node_addr(3), 1, 1000),
        make_coords(&[2, 3, 4, 0]),
    );

    let costs = make_costs(&[(1, 1.0), (2, 1.0)]);
    let result = state.evaluate_parent(&costs);
    assert_eq!(result, Some(peer1));
}

#[test]
fn test_effective_depth_tiebreak_by_node_addr() {
    // Two peers with identical effective_depth. Smaller NodeAddr wins.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);
    let root = make_node_addr(0);

    // Both at depth 1, cost 1.0 → effective_depth 2.0
    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer2, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    let costs = make_costs(&[(1, 1.0), (2, 1.0)]);
    let result = state.evaluate_parent(&costs);
    assert_eq!(result, Some(peer1)); // smaller NodeAddr
}

#[test]
fn test_hysteresis_prevents_marginal_switch() {
    // Current parent eff_depth 3.5, candidate 3.2.
    // With 20% hysteresis, threshold = 3.5 * 0.8 = 2.8.
    // 3.2 > 2.8, so no switch.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);
    state.set_parent_hysteresis(0.2);

    let peer_a = make_node_addr(1); // current parent
    let peer_b = make_node_addr(2); // candidate
    let root = make_node_addr(0);

    // Peer A: depth 1, cost 2.5 → eff 3.5
    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    // Peer B: depth 1, cost 2.2 → eff 3.2
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Set peer_a as current parent
    state.set_parent(peer_a, 1, 1000);
    state.recompute_coords();

    let costs = make_costs(&[(1, 2.5), (2, 2.2)]);
    let result = state.evaluate_parent(&costs);
    assert_eq!(result, None); // marginal improvement blocked by hysteresis
}

#[test]
fn test_hysteresis_allows_significant_switch() {
    // Current parent eff_depth 7.0, candidate 3.01.
    // With 20% hysteresis, threshold = 7.0 * 0.8 = 5.6.
    // 3.01 < 5.6, so switch occurs.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);
    state.set_parent_hysteresis(0.2);

    let peer_a = make_node_addr(1); // current parent (LoRa)
    let peer_b = make_node_addr(2); // candidate (fiber)
    let root = make_node_addr(0);

    // Peer A: depth 1, cost 6.0 → eff 7.0
    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    // Peer B: depth 2, cost 1.01 → eff 3.01
    state.update_peer(
        ParentDeclaration::new(peer_b, make_node_addr(3), 1, 1000),
        make_coords(&[2, 3, 0]),
    );

    // Set peer_a as current parent
    state.set_parent(peer_a, 1, 1000);
    state.recompute_coords();

    let costs = make_costs(&[(1, 6.0), (2, 1.01)]);
    let result = state.evaluate_parent(&costs);
    assert_eq!(result, Some(peer_b));
}

#[test]
fn test_cold_start_default_cost() {
    // Peer with no cost entry in map gets default 1.0.
    // This degenerates to depth-only selection.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);
    let root = make_node_addr(0);

    // Peer 1: depth 1, peer 2: depth 3
    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer2, make_node_addr(3), 1, 1000),
        make_coords(&[2, 3, 4, 0]),
    );

    // Empty cost map — all peers get default 1.0
    let result = state.evaluate_parent(&HashMap::new());
    assert_eq!(result, Some(peer1)); // shallowest wins
}
