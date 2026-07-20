use super::*;
use crate::node::route_impl::TransitNextHopPlan;

#[test]
fn test_routing_tree_fallback() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let my_addr = *node.node_addr();

    // Create a peer
    let link_id = LinkId::new(1);
    let (conn, id) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_addr = *id.node_addr();
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, id, 2000).unwrap();

    // Set up tree state through the public API.
    // We're root, peer is our child. The peer has a subtree below it.
    // TreeState::new() already makes us the root with coords [my_addr].
    // Add peer as child of us.
    let peer_coords = TreeCoordinate::from_addrs(vec![peer_addr, my_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(peer_addr, my_addr, 1, 1000),
        peer_coords,
    );

    // Destination: a node under our peer in the tree
    let dest = make_node_addr(99);
    let dest_coords = TreeCoordinate::from_addrs(vec![dest, peer_addr, my_addr]).unwrap();

    // Put dest coords in the cache
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    node.coord_cache_mut().insert(dest, dest_coords, now_ms);

    // No bloom filter hit — should fall back to tree routing.
    // Our distance to dest: 2 (root → peer → dest)
    // Peer's distance to dest: 1 (peer → dest)
    // Peer is closer, so it's the next hop.
    let result = node.find_next_hop(&dest);
    assert!(result.is_some());
    assert_eq!(result.unwrap().node_addr(), &peer_addr);
}

/// Regression: bloom hit on a peer that is NOT strictly closer to dest
/// than we are must fall through to greedy tree routing rather than
/// returning None. Pinned by commit a859da7.
///
/// Pre-fix behavior: bloom candidates exist but `select_best_candidate`
/// rejects them all under the self-distance check (peer dist >= my dist),
/// and `find_next_hop` returned None — a NoRoute failure even though the
/// tree had a valid greedy next hop.
///
/// Post-fix behavior: same scenario falls through to greedy tree routing
/// and returns the tree-routing-selected next hop.
#[test]
fn test_routing_bloom_hit_not_closer_falls_through_to_tree() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let my_addr = *node.node_addr();

    // tree_peer: child of self, on the path to dest (greedy tree pick).
    let tree_link = LinkId::new(1);
    let (tree_conn, tree_id) = make_completed_connection(&mut node, tree_link, transport_id, 1000);
    let tree_peer_addr = *tree_id.node_addr();
    node.add_connection(tree_conn).unwrap();
    node.promote_connection(tree_link, tree_id, 2000).unwrap();

    // bloom_peer: also a child of self, but with a stale/false-positive
    // bloom hit for dest. Its tree distance to dest is NOT closer than
    // ours, so the self-distance check in select_best_candidate excludes
    // it — leaving zero viable bloom candidates.
    let bloom_link = LinkId::new(2);
    let (bloom_conn, bloom_id) =
        make_completed_connection(&mut node, bloom_link, transport_id, 1000);
    let bloom_peer_addr = *bloom_id.node_addr();
    node.add_connection(bloom_conn).unwrap();
    node.promote_connection(bloom_link, bloom_id, 2000).unwrap();

    // Tree topology (we are root):
    //   self ── tree_peer ── dest
    //     └──── bloom_peer
    //
    // Distances to dest:
    //   self        : 2 (root → tree_peer → dest)
    //   tree_peer   : 1 (tree_peer → dest)            ← greedy winner
    //   bloom_peer  : 3 (bloom_peer → root → tree_peer → dest)  ← NOT closer than self
    let tree_peer_coords = TreeCoordinate::from_addrs(vec![tree_peer_addr, my_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(tree_peer_addr, my_addr, 1, 1000),
        tree_peer_coords,
    );
    let bloom_peer_coords = TreeCoordinate::from_addrs(vec![bloom_peer_addr, my_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(bloom_peer_addr, my_addr, 1, 1000),
        bloom_peer_coords,
    );

    // Destination is a child of tree_peer in the tree.
    let dest = make_node_addr(99);
    let dest_coords = TreeCoordinate::from_addrs(vec![dest, tree_peer_addr, my_addr]).unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    node.coord_cache_mut().insert(dest, dest_coords, now_ms);

    // dest is in bloom_peer's filter only (the "bloom hit" candidate),
    // but bloom_peer's tree distance (3) is NOT strictly less than our
    // distance (2), so select_best_candidate yields no winner.
    // tree_peer has NO bloom entry for dest.
    let bloom_peer = node.get_peer_mut(&bloom_peer_addr).unwrap();
    let mut filter = BloomFilter::new();
    filter.insert(&dest);
    bloom_peer.update_filter(filter, 1, 3000);

    // Pre-fix this returned None. Post-fix it falls through to greedy
    // tree routing and picks tree_peer (distance 1 < self distance 2).
    let result = node.find_next_hop(&dest);
    assert!(
        result.is_some(),
        "find_next_hop must fall through to tree routing when bloom \
         candidates exist but none are strictly closer than self"
    );
    let next_hop = result.unwrap().node_addr();
    assert_eq!(
        next_hop, &tree_peer_addr,
        "tree-routing winner expected (tree_peer), got {:?}",
        next_hop,
    );
    assert_ne!(
        next_hop, &bloom_peer_addr,
        "bloom_peer must be excluded by the self-distance check",
    );
}

#[test]
fn test_routing_tree_no_coords_in_cache() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Create a peer
    let link_id = LinkId::new(1);
    let (conn, id) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, id, 2000).unwrap();

    // Destination not in bloom filters and not in coord cache
    let dest = make_node_addr(99);
    assert!(node.find_next_hop(&dest).is_none());
}

#[test]
fn test_reply_learned_mode_uses_observed_route_without_coords() {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    let mut node = Node::new(config).unwrap();
    let transport_id = TransportId::new(1);

    let link_id1 = LinkId::new(1);
    let (conn1, id1) = make_completed_connection(&mut node, link_id1, transport_id, 1000);
    let peer1_addr = *id1.node_addr();
    node.add_connection(conn1).unwrap();
    node.promote_connection(link_id1, id1, 2000).unwrap();

    let link_id2 = LinkId::new(2);
    let (conn2, id2) = make_completed_connection(&mut node, link_id2, transport_id, 1000);
    let peer2_addr = *id2.node_addr();
    node.add_connection(conn2).unwrap();
    node.promote_connection(link_id2, id2, 2000).unwrap();

    let dest = make_node_addr(99);
    node.learn_reverse_route(dest, peer2_addr);

    let result = node.find_next_hop(&dest);
    assert!(result.is_some(), "learned route should not require coords");
    assert_eq!(result.unwrap().node_addr(), &peer2_addr);
    assert_ne!(peer1_addr, peer2_addr);
}

#[test]
fn test_transit_keeps_response_proven_route_instead_of_exploring_tree_branch() {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.node.routing.learned_fallback_explore_interval = 1;
    let mut node = Node::new(config).unwrap();
    let transport_id = TransportId::new(1);
    let my_addr = *node.node_addr();

    let tree_link = LinkId::new(1);
    let (tree_connection, tree_identity) =
        make_completed_connection(&mut node, tree_link, transport_id, 1_000);
    let tree_hop = *tree_identity.node_addr();
    node.add_connection(tree_connection).unwrap();
    node.promote_connection(tree_link, tree_identity, 2_000)
        .unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(tree_hop, my_addr, 1, 2_000),
        TreeCoordinate::from_addrs(vec![tree_hop, my_addr]).unwrap(),
    );

    let learned_link = LinkId::new(2);
    let (learned_connection, learned_identity) =
        make_completed_connection(&mut node, learned_link, transport_id, 1_000);
    let learned_hop = *learned_identity.node_addr();
    node.add_connection(learned_connection).unwrap();
    node.promote_connection(learned_link, learned_identity, 2_000)
        .unwrap();

    let ingress_link = LinkId::new(3);
    let (ingress_connection, ingress_identity) =
        make_completed_connection(&mut node, ingress_link, transport_id, 1_000);
    let ingress_hop = *ingress_identity.node_addr();
    node.add_connection(ingress_connection).unwrap();
    node.promote_connection(ingress_link, ingress_identity, 2_000)
        .unwrap();

    let destination = make_node_addr(99);
    node.coord_cache_mut().insert(
        destination,
        TreeCoordinate::from_addrs(vec![destination, tree_hop, my_addr]).unwrap(),
        Node::now_ms(),
    );
    node.learn_reverse_route(destination, learned_hop);

    for _ in 0..4 {
        assert!(matches!(
            node.plan_transit_next_hop(&destination, &ingress_hop),
            TransitNextHopPlan::Route(next_hop) if next_hop == learned_hop
        ));
    }
    assert_ne!(tree_hop, learned_hop);
}

#[test]
fn test_reply_learned_mode_multipaths_observed_routes() {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    let mut node = Node::new(config).unwrap();
    let transport_id = TransportId::new(1);

    let link_id1 = LinkId::new(1);
    let (conn1, id1) = make_completed_connection(&mut node, link_id1, transport_id, 1000);
    let peer1_addr = *id1.node_addr();
    node.add_connection(conn1).unwrap();
    node.promote_connection(link_id1, id1, 2000).unwrap();

    let link_id2 = LinkId::new(2);
    let (conn2, id2) = make_completed_connection(&mut node, link_id2, transport_id, 1000);
    let peer2_addr = *id2.node_addr();
    node.add_connection(conn2).unwrap();
    node.promote_connection(link_id2, id2, 2000).unwrap();

    let dest = make_node_addr(99);
    node.learn_reverse_route(dest, peer1_addr);
    for _ in 0..4 {
        node.learn_reverse_route(dest, peer2_addr);
    }

    let mut selected = Vec::new();
    for _ in 0..20 {
        selected.push(
            *node
                .find_next_hop(&dest)
                .expect("learned route")
                .node_addr(),
        );
    }

    let peer1_count = selected.iter().filter(|addr| **addr == peer1_addr).count();
    let peer2_count = selected.iter().filter(|addr| **addr == peer2_addr).count();

    assert!(
        peer1_count > 0,
        "lower-score learned route should remain in exploratory rotation"
    );
    assert!(
        peer2_count > peer1_count,
        "higher-score learned route should carry most packets"
    );
}

#[test]
fn test_reply_learned_mode_periodically_explores_coordinate_route() {
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::ReplyLearned;
    config.node.routing.learned_fallback_explore_interval = 2;
    let mut node = Node::new(config).unwrap();
    let transport_id = TransportId::new(1);
    let my_addr = *node.node_addr();

    let tree_link = LinkId::new(1);
    let (tree_conn, tree_id) = make_completed_connection(&mut node, tree_link, transport_id, 1000);
    let tree_peer_addr = *tree_id.node_addr();
    node.add_connection(tree_conn).unwrap();
    node.promote_connection(tree_link, tree_id, 2000).unwrap();

    let learned_link = LinkId::new(2);
    let (learned_conn, learned_id) =
        make_completed_connection(&mut node, learned_link, transport_id, 1000);
    let learned_peer_addr = *learned_id.node_addr();
    node.add_connection(learned_conn).unwrap();
    node.promote_connection(learned_link, learned_id, 2000)
        .unwrap();

    let tree_peer_coords = TreeCoordinate::from_addrs(vec![tree_peer_addr, my_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(tree_peer_addr, my_addr, 1, 1000),
        tree_peer_coords,
    );
    let learned_peer_coords = TreeCoordinate::from_addrs(vec![learned_peer_addr, my_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(learned_peer_addr, my_addr, 1, 1000),
        learned_peer_coords,
    );

    let dest = make_node_addr(99);
    let dest_coords = TreeCoordinate::from_addrs(vec![dest, tree_peer_addr, my_addr]).unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    node.coord_cache_mut().insert(dest, dest_coords, now_ms);
    node.learn_reverse_route(dest, learned_peer_addr);

    let first = *node
        .find_next_hop(&dest)
        .expect("learned route")
        .node_addr();
    let second = *node
        .find_next_hop(&dest)
        .expect("learned route")
        .node_addr();
    let third = *node
        .find_next_hop(&dest)
        .expect("coordinate exploration route")
        .node_addr();

    assert_eq!(first, learned_peer_addr);
    assert_eq!(second, learned_peer_addr);
    assert_eq!(
        third, tree_peer_addr,
        "fallback exploration should periodically try the coordinate route"
    );
}

#[test]
fn test_tree_mode_ignores_learned_route_without_coords() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let link_id = LinkId::new(1);
    let (conn, id) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_addr = *id.node_addr();
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, id, 2000).unwrap();

    let dest = make_node_addr(99);
    node.learn_reverse_route(dest, peer_addr);

    assert!(
        node.find_next_hop(&dest).is_none(),
        "default tree mode must preserve current no-coords behavior"
    );
}

// === Active routing refreshes coord_cache TTL ===

#[test]
fn test_routing_refreshes_coord_cache_ttl() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let my_addr = *node.node_addr();

    // Create a peer
    let link_id = LinkId::new(1);
    let (conn, id) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_addr = *id.node_addr();
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, id, 2000).unwrap();

    // Set up tree coordinates
    let dest = make_node_addr(99);
    let dest_coords = TreeCoordinate::from_addrs(vec![dest, peer_addr, my_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(peer_addr, my_addr, 1, 1000),
        TreeCoordinate::from_addrs(vec![peer_addr, my_addr]).unwrap(),
    );

    // Insert with a short TTL (10s) — enough to survive until find_next_hop runs
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let short_ttl = 10_000; // 10 seconds
    node.coord_cache_mut()
        .insert_with_ttl(dest, dest_coords, now_ms, short_ttl);
    let original_expiry = node.coord_cache().get_entry(&dest).unwrap().expires_at();

    // find_next_hop should succeed and refresh TTL to now + default_ttl (300s)
    assert!(node.find_next_hop(&dest).is_some());

    // The refresh should have extended expires_at beyond the original
    let new_expiry = node.coord_cache().get_entry(&dest).unwrap().expires_at();
    assert!(
        new_expiry > original_expiry,
        "find_next_hop should refresh the coord_cache TTL: original={}, new={}",
        original_expiry,
        new_expiry,
    );
}

// === Bloom filter without coords → no route (loop prevention) ===

#[test]
fn test_routing_bloom_hit_without_coords_returns_none() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Create two peers
    let link_id1 = LinkId::new(1);
    let (conn1, id1) = make_completed_connection(&mut node, link_id1, transport_id, 1000);
    let peer1_addr = *id1.node_addr();
    node.add_connection(conn1).unwrap();
    node.promote_connection(link_id1, id1, 2000).unwrap();

    let link_id2 = LinkId::new(2);
    let (conn2, id2) = make_completed_connection(&mut node, link_id2, transport_id, 1000);
    let peer2_addr = *id2.node_addr();
    node.add_connection(conn2).unwrap();
    node.promote_connection(link_id2, id2, 2000).unwrap();

    let dest = make_node_addr(99);

    // Add dest to BOTH peers' bloom filters
    for &addr in &[peer1_addr, peer2_addr] {
        let peer = node.get_peer_mut(&addr).unwrap();
        let mut filter = BloomFilter::new();
        filter.insert(&dest);
        peer.update_filter(filter, 1, 3000);
    }

    // Bloom filter candidates exist, but dest coords are NOT cached.
    // find_next_hop must return None to prevent routing loops.
    // The caller should signal CoordsRequired back to the source.
    assert!(node.find_next_hop(&dest).is_none());
}

// === Discovery-populated coord_cache ===

#[test]
fn test_routing_discovery_coord_cache() {
    // Verify that find_next_hop() uses coord_cache entries populated by
    // discovery. initiate_lookup() populates coord_cache, and
    // find_next_hop() consults it.
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let my_addr = *node.node_addr();

    // Create a peer
    let link_id = LinkId::new(1);
    let (conn, id) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_addr = *id.node_addr();
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, id, 2000).unwrap();

    // Set up tree: we are root, peer is our child
    let peer_coords = TreeCoordinate::from_addrs(vec![peer_addr, my_addr]).unwrap();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(peer_addr, my_addr, 1, 1000),
        peer_coords,
    );

    // Create a destination "behind" the peer in the tree
    let dest = make_node_addr(99);
    let dest_coords = TreeCoordinate::from_addrs(vec![dest, peer_addr, my_addr]).unwrap();

    // Put dest in peer's bloom filter so there's a candidate
    let peer = node.get_peer_mut(&peer_addr).unwrap();
    let mut filter = BloomFilter::new();
    filter.insert(&dest);
    peer.update_filter(filter, 1, 3000);

    // Verify: coord_cache has nothing for dest
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    assert!(node.coord_cache().get(&dest, now_ms).is_none());

    // Without coord_cache entry, should return None
    assert!(node.find_next_hop(&dest).is_none());

    // Now populate coord_cache (as discovery would do)
    node.coord_cache_mut().insert(dest, dest_coords, now_ms);

    // find_next_hop should succeed via coord_cache
    let result = node.find_next_hop(&dest);
    assert!(result.is_some(), "Should route via coord_cache");
    assert_eq!(
        result.unwrap().node_addr(),
        &peer_addr,
        "Should pick peer with bloom filter hit"
    );
}

// === Integration: converged network ===
