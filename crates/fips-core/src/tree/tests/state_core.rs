use super::*;

#[test]
fn test_tree_state_new() {
    let node = make_node_addr(1);
    let state = TreeState::new(node);

    assert_eq!(state.my_node_addr(), &node);
    assert!(state.is_root());
    assert_eq!(state.root(), &node);
    assert_eq!(state.my_coords().depth(), 0);
    assert_eq!(state.peer_count(), 0);
}

#[test]
fn test_tree_state_update_peer() {
    let my_node = make_node_addr(0);
    let mut state = TreeState::new(my_node);

    let peer = make_node_addr(1);
    let root = make_node_addr(2);

    let decl = ParentDeclaration::new(peer, root, 1, 1000);
    let coords = make_coords(&[1, 2]);

    assert!(state.update_peer(decl.clone(), coords.clone()));
    assert_eq!(state.peer_count(), 1);
    assert!(state.peer_coords(&peer).is_some());
    assert!(state.peer_declaration(&peer).is_some());

    // Same sequence should not update
    let decl2 = ParentDeclaration::new(peer, root, 1, 1000);
    assert!(!state.update_peer(decl2, coords.clone()));

    // Higher sequence should update
    let decl3 = ParentDeclaration::new(peer, root, 2, 2000);
    assert!(state.update_peer(decl3, coords));
}

#[test]
fn test_tree_state_remove_peer() {
    let my_node = make_node_addr(0);
    let mut state = TreeState::new(my_node);

    let peer = make_node_addr(1);
    let root = make_node_addr(2);

    let decl = ParentDeclaration::new(peer, root, 1, 1000);
    let coords = make_coords(&[1, 2]);

    state.update_peer(decl, coords);
    assert_eq!(state.peer_count(), 1);

    state.remove_peer(&peer);
    assert_eq!(state.peer_count(), 0);
    assert!(state.peer_coords(&peer).is_none());
}

#[test]
fn test_tree_state_distance_to_peer() {
    let my_node = make_node_addr(0);
    let mut state = TreeState::new(my_node);

    let peer = make_node_addr(1);

    // Both are roots in their own trees initially - different roots
    let peer_coords = TreeCoordinate::root(peer);
    let decl = ParentDeclaration::self_root(peer, 1, 1000);
    state.update_peer(decl, peer_coords);

    // Different roots = MAX distance
    assert_eq!(state.distance_to_peer(&peer), Some(usize::MAX));

    // If they share a root, distance should be finite
    let shared_root = make_node_addr(99);

    // Update my state to have shared root
    state.set_parent(shared_root, 1, 1000);
    let my_new_coords = make_coords(&[0, 99]);
    // Manually set coords for test (normally done by recompute_coords)
    state.my_coords = my_new_coords;
    state.root = shared_root;

    // Update peer to have same root
    let peer_coords = make_coords(&[1, 99]);
    let decl = ParentDeclaration::new(peer, shared_root, 2, 2000);
    state.update_peer(decl, peer_coords);

    // Now distance should be 2 (me -> root -> peer)
    assert_eq!(state.distance_to_peer(&peer), Some(2));
}

#[test]
fn test_tree_state_peer_ids() {
    let my_node = make_node_addr(0);
    let mut state = TreeState::new(my_node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);

    state.update_peer(
        ParentDeclaration::self_root(peer1, 1, 1000),
        TreeCoordinate::root(peer1),
    );
    state.update_peer(
        ParentDeclaration::self_root(peer2, 1, 1000),
        TreeCoordinate::root(peer2),
    );

    let ids: Vec<_> = state.peer_ids().collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&&peer1));
    assert!(ids.contains(&&peer2));
}

// ===== Parent Selection Tests =====
