use super::*;

#[test]
fn test_hold_down_suppresses_reeval() {
    // After a parent switch, re-evaluation returns None during hold-down.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);
    state.set_hold_down(60); // 60s hold-down

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Switch to peer_a (sets last_parent_switch)
    state.set_parent(peer_a, 1, 1000);
    state.recompute_coords();

    // Peer_b now offers better cost, but hold-down suppresses
    let costs = make_costs(&[(1, 5.0), (2, 1.0)]);
    state.set_parent_hysteresis(0.0); // no hysteresis, only hold-down
    let result = state.evaluate_parent(&costs);
    assert_eq!(result, None); // suppressed by hold-down
}

#[test]
fn test_mandatory_switch_bypasses_hold_down() {
    // Parent loss during hold-down still triggers switch.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);
    state.set_hold_down(60); // 60s hold-down

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Switch to peer_a
    state.set_parent(peer_a, 1, 1000);
    state.recompute_coords();

    // Remove peer_a (parent lost) — should bypass hold-down
    state.remove_peer(&peer_a);
    let result = state.evaluate_parent(&HashMap::new());
    assert_eq!(result, Some(peer_b)); // mandatory switch
}

#[test]
fn test_heterogeneous_7node_avoids_bottleneck() {
    // 7-node topology simulating a mixed fiber/LoRa network:
    //
    //   0 (root)
    //   ├── 1 (fiber, cost 1.01) — depth 1
    //   │   ├── 3 (fiber, cost 1.01) — depth 2
    //   │   └── 4 (fiber, cost 1.01) — depth 2
    //   ├── 2 (LoRa, cost 6.0)  — depth 1
    //   │   └── 5 (fiber, cost 1.01) — depth 2 (inherits LoRa bottleneck!)
    //   └── 6 (wifi, cost 1.07) — depth 1
    //
    // Node 5 is connected to both node 2 (LoRa parent, depth 1) and
    // node 1 (fiber, depth 1). Without cost-awareness, node 5 could
    // pick node 2 as parent (both at depth 1, tiebreak by addr).
    // With cost-awareness, node 5 should pick node 1 (eff 2.01) over
    // node 2 (eff 7.0).

    let root = make_node_addr(0);

    // Test from node 5's perspective
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1); // fiber peer at depth 1
    let peer2 = make_node_addr(2); // LoRa peer at depth 1

    // Both peers reach root 0 at depth 1
    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer2, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Without costs (all 1.0): picks peer 1 (smaller addr) — correct by luck
    let result_no_cost = state.evaluate_parent(&HashMap::new());
    assert_eq!(result_no_cost, Some(peer1));

    // With costs: fiber (1.01) vs LoRa (6.0) — fiber wins definitively
    let costs = make_costs(&[(1, 1.01), (2, 6.0)]);
    let result_with_cost = state.evaluate_parent(&costs);
    assert_eq!(result_with_cost, Some(peer1));

    // Now test the critical case: node 5 currently has LoRa parent (peer 2).
    // Even without hysteresis, it should want to switch to fiber (peer 1).
    state.set_parent(peer2, 1, 1000);
    state.recompute_coords();
    assert_eq!(state.my_coords().depth(), 2); // depth 2 through LoRa peer

    let result_switch = state.evaluate_parent(&costs);
    assert_eq!(result_switch, Some(peer1)); // switches away from LoRa bottleneck

    // With hysteresis enabled, still switches because the cost difference is large
    state.set_parent_hysteresis(0.2);
    // current_parent_eff = 1 + 6.0 = 7.0, best_eff = 1 + 1.01 = 2.01
    // threshold = 7.0 * 0.8 = 5.6, 2.01 < 5.6 → switch
    let result_hyst = state.evaluate_parent(&costs);
    assert_eq!(result_hyst, Some(peer1));
}

// =====================================================================
// Cost degradation tests (periodic re-evaluation scenarios)
// =====================================================================
//
// These test evaluate_parent() with changing cost maps, validating the
// scenarios that periodic re-evaluation is designed to catch: link
// quality changes after the tree has stabilized.

#[test]
fn test_cost_degradation_triggers_switch() {
    // Node 5 has two peers at depth 1. Initially both have similar costs
    // (both fiber). After stabilization, peer A's link degrades (becomes
    // LoRa-like). Re-evaluation with updated costs should trigger a switch.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);
    state.set_parent_hysteresis(0.2);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Initial: both fiber-like costs. Node picks peer_a (smaller addr).
    let initial_costs = make_costs(&[(1, 1.05), (2, 1.08)]);
    let result = state.evaluate_parent(&initial_costs);
    assert_eq!(result, Some(peer_a));

    state.set_parent(peer_a, 1, 1000);
    state.recompute_coords();

    // Verify stable: no switch with same costs
    let result = state.evaluate_parent(&initial_costs);
    assert_eq!(result, None);

    // Peer A's link degrades significantly (LoRa-like latency + loss)
    // current_parent_eff = 1 + 6.0 = 7.0
    // best_eff = 1 + 1.08 = 2.08
    // threshold = 7.0 * 0.8 = 5.6, 2.08 < 5.6 → switch
    let degraded_costs = make_costs(&[(1, 6.0), (2, 1.08)]);
    let result = state.evaluate_parent(&degraded_costs);
    assert_eq!(result, Some(peer_b));
}

#[test]
fn test_cost_improvement_within_hysteresis_no_switch() {
    // Node 5 has parent peer_a. Peer_b's cost improves slightly but
    // stays within the hysteresis band. Re-evaluation should not switch.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);
    state.set_parent_hysteresis(0.2);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    state.set_parent(peer_a, 1, 1000);
    state.recompute_coords();

    // Peer B slightly better: cost 1.5 vs peer A cost 2.0
    // current_parent_eff = 1 + 2.0 = 3.0
    // best_eff = 1 + 1.5 = 2.5
    // threshold = 3.0 * 0.8 = 2.4, 2.5 > 2.4 → no switch
    let costs = make_costs(&[(1, 2.0), (2, 1.5)]);
    let result = state.evaluate_parent(&costs);
    assert_eq!(result, None);
}

#[test]
fn test_single_peer_no_reeval_benefit() {
    // With only one peer, evaluate_parent should select it initially,
    // but once it's our parent, re-evaluation returns None regardless
    // of cost changes (no alternative exists).
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer_a = make_node_addr(1);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );

    // Initial selection: picks the only peer
    let costs = make_costs(&[(1, 1.05)]);
    let result = state.evaluate_parent(&costs);
    assert_eq!(result, Some(peer_a));

    state.set_parent(peer_a, 1, 1000);
    state.recompute_coords();

    // Even with terrible cost, no switch (no alternative)
    let bad_costs = make_costs(&[(1, 50.0)]);
    let result = state.evaluate_parent(&bad_costs);
    assert_eq!(result, None);
}

// =====================================================================
// Flap dampening tests
// =====================================================================

#[test]
fn test_flap_dampening_engages_after_threshold() {
    // Create TreeState with flap_threshold=3, window=60s, dampening=3600s (long)
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);
    state.set_flap_dampening(3, 60, 3600);
    state.set_hold_down(0); // disable hold-down for this test

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Switch 1: initial parent selection (root -> peer_a)
    assert!(!state.is_flap_dampened());
    state.set_parent(peer_a, 1, 1000);
    state.recompute_coords();
    assert!(!state.is_flap_dampened());

    // Switch 2: peer_a -> peer_b
    state.set_parent(peer_b, 2, 2000);
    state.recompute_coords();
    assert!(!state.is_flap_dampened());

    // Switch 3: peer_b -> peer_a — threshold reached, dampening engages
    let dampened = state.set_parent(peer_a, 3, 3000);
    state.recompute_coords();
    assert!(dampened);
    assert!(state.is_flap_dampened());

    // evaluate_parent should return None for non-mandatory switches
    // Make peer_b much better than peer_a
    let costs = make_costs(&[(1, 10.0), (2, 1.0)]);
    let result = state.evaluate_parent(&costs);
    assert_eq!(result, None); // suppressed by flap dampening
}

#[test]
fn test_flap_dampening_allows_mandatory_switches() {
    // Engage dampening, then verify mandatory switches still work
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);
    state.set_flap_dampening(3, 60, 3600);
    state.set_hold_down(0);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Trigger dampening with 3 switches
    state.set_parent(peer_a, 1, 1000);
    state.recompute_coords();
    state.set_parent(peer_b, 2, 2000);
    state.recompute_coords();
    state.set_parent(peer_a, 3, 3000);
    state.recompute_coords();
    assert!(state.is_flap_dampened());

    // Remove current parent (peer_a) — this is a mandatory switch
    state.remove_peer(&peer_a);
    let result = state.evaluate_parent(&HashMap::new());
    assert_eq!(result, Some(peer_b)); // mandatory switch bypasses dampening
}

#[test]
fn test_flap_dampening_expires() {
    // Test with 0-second dampening duration to verify expiry logic
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);
    state.set_flap_dampening(3, 60, 0); // 0-second dampening
    state.set_hold_down(0);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Trigger dampening
    state.set_parent(peer_a, 1, 1000);
    state.recompute_coords();
    state.set_parent(peer_b, 2, 2000);
    state.recompute_coords();
    let dampened = state.set_parent(peer_a, 3, 3000);
    state.recompute_coords();
    assert!(dampened); // dampening was engaged

    // With 0-second duration, dampening should have already expired
    assert!(!state.is_flap_dampened());

    // evaluate_parent should work normally now
    let costs = make_costs(&[(1, 10.0), (2, 1.0)]);
    let result = state.evaluate_parent(&costs);
    assert_eq!(result, Some(peer_b)); // not suppressed
}

#[test]
fn test_flap_dampening_below_threshold() {
    // Fewer switches than threshold should NOT engage dampening
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);
    state.set_flap_dampening(4, 60, 3600); // threshold=4
    state.set_hold_down(0);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Only 3 switches (below threshold of 4)
    state.set_parent(peer_a, 1, 1000);
    state.recompute_coords();
    state.set_parent(peer_b, 2, 2000);
    state.recompute_coords();
    state.set_parent(peer_a, 3, 3000);
    state.recompute_coords();

    assert!(!state.is_flap_dampened());

    // evaluate_parent should still work normally
    let costs = make_costs(&[(1, 10.0), (2, 1.0)]);
    let result = state.evaluate_parent(&costs);
    assert_eq!(result, Some(peer_b)); // not suppressed
}

#[test]
fn test_flap_dampening_window_reset() {
    // Test that the flap window resets after expiry.
    // Use a 0-second window so it immediately expires between switch groups.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);
    // threshold=3, window=0s (expires immediately), dampening=3600s
    state.set_flap_dampening(3, 0, 3600);
    state.set_hold_down(0);

    let peer_a = make_node_addr(1);
    let peer_b = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer_b, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Each switch resets the window (0s window means every switch starts fresh).
    // So we never accumulate enough to reach threshold=3.
    state.set_parent(peer_a, 1, 1000);
    state.recompute_coords();
    // Window expired, counter resets on next switch
    state.set_parent(peer_b, 2, 2000);
    state.recompute_coords();
    // Window expired, counter resets on next switch
    state.set_parent(peer_a, 3, 3000);
    state.recompute_coords();

    // Dampening should NOT have engaged because each switch reset the window
    assert!(!state.is_flap_dampened());
}

#[test]
fn test_flap_dampening_same_parent_no_count() {
    // Re-declaring the same parent should not count as a flap
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);
    state.set_flap_dampening(3, 60, 3600);
    state.set_hold_down(0);

    let peer_a = make_node_addr(1);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer_a, root, 1, 1000),
        make_coords(&[1, 0]),
    );

    // Initial parent selection
    state.set_parent(peer_a, 1, 1000);
    state.recompute_coords();

    // Re-declare same parent multiple times (e.g., parent ancestry changed)
    state.set_parent(peer_a, 2, 2000);
    state.recompute_coords();
    state.set_parent(peer_a, 3, 3000);
    state.recompute_coords();
    state.set_parent(peer_a, 4, 4000);
    state.recompute_coords();
    state.set_parent(peer_a, 5, 5000);
    state.recompute_coords();

    // Should NOT be dampened since only the first was a real switch
    assert!(!state.is_flap_dampened());
}
