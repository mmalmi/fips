use super::*;

#[test]
fn test_evaluate_parent_picks_smallest_root() {
    // Node 5 starts as root. Peers 3 and 7 each claim different roots.
    // Peer 3's path: [3, 1] (root=1)
    // Peer 7's path: [7, 2] (root=2)
    // Should pick peer 3 because root 1 < root 2.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer3 = make_node_addr(3);
    let peer7 = make_node_addr(7);

    state.update_peer(
        ParentDeclaration::new(peer3, make_node_addr(1), 1, 1000),
        make_coords(&[3, 1]),
    );
    state.update_peer(
        ParentDeclaration::new(peer7, make_node_addr(2), 1, 1000),
        make_coords(&[7, 2]),
    );

    let result = state.evaluate_parent(&HashMap::new());
    assert_eq!(result, Some(peer3));
}

#[test]
fn test_evaluate_parent_prefers_shallowest_depth() {
    // Node 5, root=0 (shared). Peer 1 at depth 1, peer 2 at depth 3.
    // Both reach root 0. Should pick peer 1 (shallowest).
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);
    let root = make_node_addr(0);

    // Peer 1: depth 1 (path = [1, 0])
    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    // Peer 2: depth 3 (path = [2, 3, 4, 0])
    state.update_peer(
        ParentDeclaration::new(peer2, make_node_addr(3), 1, 1000),
        make_coords(&[2, 3, 4, 0]),
    );

    let result = state.evaluate_parent(&HashMap::new());
    assert_eq!(result, Some(peer1));
}

#[test]
fn test_evaluate_parent_stays_root_when_smallest() {
    // Node 0 (smallest possible) should stay root even if peers exist.
    let my_node = make_node_addr(0);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1);
    // Peer 1 has root 0 (us) — shouldn't trigger switch
    state.update_peer(
        ParentDeclaration::new(peer1, my_node, 1, 1000),
        make_coords(&[1, 0]),
    );

    assert_eq!(state.evaluate_parent(&HashMap::new()), None);
}

#[test]
fn test_evaluate_parent_no_switch_when_already_best() {
    // Node 5, already using peer 1 as parent. No better option.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );

    // Switch to peer1 as parent first
    state.set_parent(peer1, 1, 1000);
    state.recompute_coords();

    // Now evaluate — should return None since peer1 is already our parent
    assert_eq!(state.evaluate_parent(&HashMap::new()), None);
}

#[test]
fn test_evaluate_parent_no_peers() {
    let my_node = make_node_addr(5);
    let state = TreeState::new(my_node);

    assert_eq!(state.evaluate_parent(&HashMap::new()), None);
}

#[test]
fn test_evaluate_parent_depth_threshold() {
    // Node 5, currently at depth 4 through peer 2.
    // Peer 1 offers depth 3 (improvement of 1, which equals threshold).
    // Peer 3 offers depth 1 (improvement of 3, exceeds threshold).
    // Should switch to peer 3.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer2 = make_node_addr(2);
    let peer3 = make_node_addr(3);
    let root = make_node_addr(0);

    // Peer 2: depth 3 (we'd be depth 4 through them)
    state.update_peer(
        ParentDeclaration::new(peer2, make_node_addr(6), 1, 1000),
        make_coords(&[2, 6, 7, 0]),
    );

    // Set peer2 as our parent, making us depth 4
    state.set_parent(peer2, 1, 1000);
    state.recompute_coords();
    assert_eq!(state.my_coords().depth(), 4);

    // Peer 3: depth 1 (we'd be depth 2 through them) — improvement of 2
    state.update_peer(
        ParentDeclaration::new(peer3, root, 1, 1000),
        make_coords(&[3, 0]),
    );

    let result = state.evaluate_parent(&HashMap::new());
    assert_eq!(result, Some(peer3));
}

#[test]
fn test_evaluate_parent_rejects_loop_candidate() {
    // Node 5 with peer 1 whose ancestry contains node 5 — selecting
    // peer 1 would create a coordinate loop. evaluate_parent must skip it.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1);
    let _root = make_node_addr(0);

    // Peer 1's ancestry: [1, 5, 0] — contains us (node 5)
    state.update_peer(
        ParentDeclaration::new(peer1, my_node, 1, 1000),
        make_coords(&[1, 5, 0]),
    );

    // Should return None — the only candidate creates a loop
    assert_eq!(state.evaluate_parent(&HashMap::new()), None);
}

#[test]
fn test_evaluate_parent_picks_loop_free_over_loopy() {
    // Two peers reach the same root. Peer 1's ancestry contains us (loop),
    // peer 2's does not. Should pick peer 2 even though peer 1 is shallower.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);
    let _root = make_node_addr(0);

    // Peer 1: depth 2, but ancestry contains us — loop
    state.update_peer(
        ParentDeclaration::new(peer1, my_node, 1, 1000),
        make_coords(&[1, 5, 0]),
    );
    // Peer 2: depth 3, loop-free
    state.update_peer(
        ParentDeclaration::new(peer2, make_node_addr(3), 1, 1000),
        make_coords(&[2, 3, 4, 0]),
    );

    let result = state.evaluate_parent(&HashMap::new());
    assert_eq!(result, Some(peer2));
}

#[test]
fn test_handle_parent_lost_finds_alternative() {
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );
    state.update_peer(
        ParentDeclaration::new(peer2, root, 1, 1000),
        make_coords(&[2, 0]),
    );

    // Set peer1 as parent
    state.set_parent(peer1, 1, 1000);
    state.recompute_coords();

    // Remove peer1 (parent lost)
    state.remove_peer(&peer1);
    let changed = state.handle_parent_lost(&HashMap::new());

    assert!(changed);
    // Should have switched to peer2
    assert_eq!(state.my_declaration().parent_id(), &peer2);
    assert!(!state.is_root());
}

#[test]
fn test_handle_parent_lost_becomes_root_when_self_smaller_than_remaining() {
    // Regression: self (NodeAddr 1) had peer 0 as parent. Peer 0 disappears,
    // leaving only peers with bigger NodeAddrs (and bigger roots). The old
    // evaluate_parent() picked one of them — recompute_coords() then
    // produced [self, peer, ..., peer_root] where last (peer_root) > min
    // (self), an ancestry that recipients reject as
    // "advertised root X is not the minimum path entry Y". This is the
    // bug seen in production where ubuntu-dev (3847a4..) advertised itself
    // as root while its path still contained mac (312c79..).
    let my_node = make_node_addr(1); // our addr is the smallest
    let mut state = TreeState::new(my_node);

    let smaller = make_node_addr(0);
    let bigger1 = make_node_addr(2);
    let bigger2 = make_node_addr(3);

    // Initially: peer 0 (smaller) is our parent.
    state.update_peer(
        ParentDeclaration::self_root(smaller, 1, 1000),
        make_coords(&[0]),
    );
    // Bigger peers exist, both rooted at themselves (no smaller node visible
    // through them).
    state.update_peer(
        ParentDeclaration::self_root(bigger1, 1, 1000),
        make_coords(&[2]),
    );
    state.update_peer(
        ParentDeclaration::self_root(bigger2, 1, 1000),
        make_coords(&[3]),
    );

    state.set_parent(smaller, 2, 2000);
    state.recompute_coords();
    assert_eq!(state.my_coords().entries().len(), 2);
    assert_eq!(state.root(), &smaller);

    // Smaller peer disconnects.
    state.remove_peer(&smaller);
    let changed = state.handle_parent_lost(&HashMap::new());
    assert!(changed);

    // Must become root (we're the smallest visible), NOT pick bigger1/bigger2.
    assert!(
        state.is_root(),
        "must self-root when no smaller peer remains"
    );
    assert_eq!(state.root(), &my_node);
    assert_eq!(state.my_coords().entries().len(), 1);

    // The resulting ancestry must be valid: last == min.
    let entries = state.my_coords().entries();
    let min = entries.iter().map(|e| e.node_addr).min().unwrap();
    assert_eq!(*state.my_coords().root_id(), min);
}

#[test]
fn test_recompute_coords_demotes_when_self_smaller_than_parent_root() {
    // Defensive: even if set_parent is called with a parent whose root is
    // bigger than us (e.g., a stale evaluate_parent decision in some legacy
    // path), recompute_coords must produce a valid ancestry by demoting to
    // self-root rather than emit [self, peer, peer_root] with last > min.
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let bigger_peer = make_node_addr(7);
    state.update_peer(
        ParentDeclaration::self_root(bigger_peer, 1, 1000),
        make_coords(&[7]),
    );

    state.set_parent(bigger_peer, 2, 2000);
    state.recompute_coords();

    assert!(state.is_root(), "recompute_coords demoted to self-root");
    assert_eq!(state.root(), &my_node);
    assert_eq!(state.my_coords().entries().len(), 1);
    let entries = state.my_coords().entries();
    let min = entries.iter().map(|e| e.node_addr).min().unwrap();
    assert_eq!(*state.my_coords().root_id(), min);
}

#[test]
fn test_handle_parent_lost_becomes_root() {
    let my_node = make_node_addr(5);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1);
    let root = make_node_addr(0);

    state.update_peer(
        ParentDeclaration::new(peer1, root, 1, 1000),
        make_coords(&[1, 0]),
    );

    // Set peer1 as parent
    state.set_parent(peer1, 1, 1000);
    state.recompute_coords();
    let seq_before = state.my_declaration().sequence();

    // Remove peer1 (only parent)
    state.remove_peer(&peer1);
    let changed = state.handle_parent_lost(&HashMap::new());

    assert!(changed);
    assert!(state.is_root());
    assert!(state.my_declaration().sequence() > seq_before);
    assert_eq!(state.root(), &my_node);
}

// === find_next_hop tests ===
