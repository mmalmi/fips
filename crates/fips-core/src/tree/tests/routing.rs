use super::*;

fn make_tree_state(my_addr: u8, coord_path: &[u8]) -> TreeState {
    let my_node = make_node_addr(my_addr);
    let mut state = TreeState::new(my_node);
    let coords = make_coords(coord_path);
    state.root = *coords.root_id();
    state.my_coords = coords;
    state
}

/// Add a peer with given coordinates to the tree state.
fn add_peer(state: &mut TreeState, peer_addr: u8, coord_path: &[u8]) {
    let peer = make_node_addr(peer_addr);
    let parent = make_node_addr(coord_path[1]);
    state.update_peer(
        ParentDeclaration::new(peer, parent, 1, 1000),
        make_coords(coord_path),
    );
}

#[test]
fn test_find_next_hop_chain() {
    // Chain: 0 (root) <- 5 (us) <- 1 <- 2
    // Both peers 1 and 2 are in our peer_ancestry. Peer 2 IS the
    // destination (distance 0), so it's the best next hop.
    let mut state = make_tree_state(5, &[5, 0]);
    add_peer(&mut state, 1, &[1, 5, 0]);
    add_peer(&mut state, 2, &[2, 1, 5, 0]);

    let dest = make_coords(&[2, 1, 5, 0]);
    assert_eq!(state.find_next_hop(&dest), Some(make_node_addr(2)));
}

#[test]
fn test_find_next_hop_chain_indirect() {
    // Chain: 0 (root) <- 5 (us) <- 1
    // Dest is node 2 at [2, 1, 5, 0] but peer 2 is NOT in our peer
    // list — only peer 1 is. So we route via peer 1 (distance 1).
    let mut state = make_tree_state(5, &[5, 0]);
    add_peer(&mut state, 1, &[1, 5, 0]);

    let dest = make_coords(&[2, 1, 5, 0]);
    assert_eq!(state.find_next_hop(&dest), Some(make_node_addr(1)));
}

#[test]
fn test_find_next_hop_toward_root() {
    // Tree: 0 (root) <- 1 <- 5 (us)
    // Routing toward root should pick node 1 (our parent).
    let mut state = make_tree_state(5, &[5, 1, 0]);
    add_peer(&mut state, 1, &[1, 0]);

    let dest = make_coords(&[0]);
    assert_eq!(state.find_next_hop(&dest), Some(make_node_addr(1)));
}

#[test]
fn test_find_next_hop_sibling() {
    // Tree: 0 (root) <- 5 (us), 0 <- 3
    // Routing to sibling 3: should go through parent 0... but 0 is
    // the root and not in our peer list. Our only peer is 3 itself.
    // But 3 is not a "closer" peer in tree distance — distance from
    // us to 3 is 2 (up to root, down to 3), and distance from 3 to
    // 3 is 0, so 3 IS closer. Should pick 3.
    let mut state = make_tree_state(5, &[5, 0]);
    add_peer(&mut state, 3, &[3, 0]);

    let dest = make_coords(&[3, 0]);
    assert_eq!(state.find_next_hop(&dest), Some(make_node_addr(3)));
}

#[test]
fn test_find_next_hop_tie_breaking() {
    // Tree: 0 (root) <- 5 (us), 0 <- 3, 0 <- 2
    // Both peers are siblings at depth 1, equidistant to a dest
    // at [4, 0]. Should pick node 2 (smaller node_addr).
    let mut state = make_tree_state(5, &[5, 0]);
    add_peer(&mut state, 3, &[3, 0]);
    add_peer(&mut state, 2, &[2, 0]);

    let dest = make_coords(&[4, 0]);
    // Our distance: 2 (up to root, down to 4)
    // Peer 3 distance: 2 (up to root, down to 4)
    // Peer 2 distance: 2 (up to root, down to 4)
    // All equal to our distance — no peer is strictly closer.
    assert_eq!(state.find_next_hop(&dest), None);
}

#[test]
fn test_find_next_hop_different_root() {
    let mut state = make_tree_state(5, &[5, 0]);
    add_peer(&mut state, 1, &[1, 0]);

    // Destination in a different tree (root = 9)
    let dest = make_coords(&[3, 9]);
    assert_eq!(state.find_next_hop(&dest), None);
}

#[test]
fn test_find_next_hop_no_peers() {
    let state = make_tree_state(5, &[5, 0]);
    let dest = make_coords(&[3, 0]);
    assert_eq!(state.find_next_hop(&dest), None);
}

#[test]
fn test_find_next_hop_local_minimum() {
    // Tree: 0 (root) <- 5 (us), 5 <- 8
    // Routing to node 3 at [3, 0]. Our distance = 2.
    // Peer 8's distance = 4 (8→5→0→3 but via coords: [8,5,0] to [3,0] = 3).
    // Actually: lca of [8,5,0] and [3,0] is root 0 at depth 0.
    // dist = (2-0) + (1-0) = 3. Our dist = (1-0) + (1-0) = 2.
    // Peer is farther, so no hop.
    let mut state = make_tree_state(5, &[5, 0]);
    add_peer(&mut state, 8, &[8, 5, 0]);

    let dest = make_coords(&[3, 0]);
    assert_eq!(state.find_next_hop(&dest), None);
}

#[test]
fn test_find_next_hop_best_of_multiple() {
    // Tree: 0 (root) <- 1 <- 5 (us), 1 <- 3 <- 7
    // Dest is node 7 at [7, 3, 1, 0].
    // Peer 1 coords [1, 0]: dist to dest = 0 + 2 = 2
    // Peer 3 coords [3, 1, 0]: dist to dest = 0 + 1 = 1
    // Our coords [5, 1, 0]: dist to dest = 1 + 2 = 3
    // Peer 3 is closest. Should pick 3.
    let mut state = make_tree_state(5, &[5, 1, 0]);
    add_peer(&mut state, 1, &[1, 0]);
    add_peer(&mut state, 3, &[3, 1, 0]);

    let dest = make_coords(&[7, 3, 1, 0]);
    assert_eq!(state.find_next_hop(&dest), Some(make_node_addr(3)));
}

// === Cost-based parent selection tests ===
