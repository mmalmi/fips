//! State-driven planner boundaries; native merge/delivery coverage lives separately.
use super::*;
use crate::node::route_impl::TransitNextHopPlan;
use crate::tree::CoordEntry;

fn add_peer(node: &mut Node, index: u64, identity: &Identity) -> PeerIdentity {
    let link = LinkId::new(index);
    let (connection, peer) =
        make_completed_connection_for_identity(node, link, TransportId::new(1), 1_000, identity);
    node.add_connection(connection).unwrap();
    node.promote_connection(link, peer, 2_000).unwrap();
    peer
}

fn set_root(node: &mut Node, parent: PeerIdentity, root: PeerIdentity, sequence: u64) {
    let parent_addr = *parent.node_addr();
    let root_addr = *root.node_addr();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(parent_addr, root_addr, sequence, 1_000),
        TreeCoordinate::new(vec![
            CoordEntry::new(parent_addr, sequence, 1_000),
            CoordEntry::new(root_addr, sequence + 20, 990),
        ])
        .unwrap(),
    );
    node.tree_state_mut()
        .set_parent(parent_addr, sequence, 1_000);
    node.tree_state_mut().recompute_coords();
    node.invalidate_tree_coordinates();
    assert_eq!(node.tree_state().root(), &root_addr);
}

struct Fixture {
    node: Node,
    parent: PeerIdentity,
    root: PeerIdentity,
    replacement: PeerIdentity,
    alternate: PeerIdentity,
}

fn fixture() -> Fixture {
    // Keep every declared ancestry consistent with minimum-address root rules.
    let mut identities = (0..5).map(|_| Identity::generate()).collect::<Vec<_>>();
    identities.sort_by_key(|identity| *identity.node_addr());
    let alternate_identity = identities.pop().unwrap();
    let local = identities.pop().unwrap();
    let parent_identity = identities.pop().unwrap();
    let root = PeerIdentity::from_pubkey_full(identities.pop().unwrap().pubkey_full());
    let replacement = PeerIdentity::from_pubkey_full(identities.pop().unwrap().pubkey_full());
    let mut config = Config::new();
    config.node.routing.mode = RoutingMode::Tree;
    let mut node = Node::with_identity(local, config).unwrap();
    let parent = add_peer(&mut node, 1, &parent_identity);
    let alternate = add_peer(&mut node, 2, &alternate_identity);
    set_root(&mut node, parent, root, 7);
    Fixture {
        node,
        parent,
        root,
        replacement,
        alternate,
    }
}

#[test]
fn uncached_current_root_routes_without_creating_lookup_evidence() {
    let Fixture {
        mut node,
        parent,
        root,
        ..
    } = fixture();
    let destination = *root.node_addr();
    let expected = TreeCoordinate::root_with_meta(destination, 27, 990);
    assert_eq!(
        node.current_tree_root_coords(&destination),
        Some(expected.clone())
    );
    assert_eq!(node.get_dest_coords(&destination), expected);
    assert!(node.application_route_has_coordinates(&destination, *parent.node_addr()));
    assert_eq!(
        node.find_next_hop(&destination)
            .map(|peer| *peer.node_addr()),
        Some(*parent.node_addr())
    );
    assert!(
        matches!(node.plan_transit_next_hop(&destination, &make_node_addr(251)), TransitNextHopPlan::Route(next) if next == *parent.node_addr())
    );
    assert!(
        !node.coord_cache().contains(&destination, Node::now_ms()),
        "local routing must not insert proof or hint cache evidence"
    );
    assert!(!node.pending_lookups.contains_key(&destination));

    let other = *make_peer_identity().node_addr();
    assert!(node.current_tree_root_coords(&other).is_none());
    assert!(!node.application_route_has_coordinates(&other, *parent.node_addr()));
    assert!(node.find_next_hop(&other).is_none());
    assert_eq!(node.get_dest_coords(&other), TreeCoordinate::root(other));

    node.config.node.routing.mode = RoutingMode::ReplyLearned;
    assert!(node.current_tree_root_coords(&destination).is_none());
    assert!(
        node.find_next_hop(&destination).is_none(),
        "the new ancestry fallback belongs only to Tree mode"
    );
    assert_eq!(
        node.get_dest_coords(&destination),
        TreeCoordinate::root(destination)
    );
}

#[test]
fn present_coordinate_cache_entry_precedes_current_root_fallback() {
    let Fixture {
        mut node,
        parent,
        root,
        replacement,
        ..
    } = fixture();
    let destination = *root.node_addr();
    let foreign_root = *replacement.node_addr();
    let cached = TreeCoordinate::from_addrs(vec![destination, foreign_root]).unwrap();
    node.coord_cache_mut()
        .insert(destination, cached.clone(), Node::now_ms());
    assert_eq!(node.get_dest_coords(&destination), cached);
    assert!(!node.application_route_has_coordinates(&destination, *parent.node_addr()));
    assert!(
        node.find_next_hop(&destination).is_none(),
        "a present wrong-root record must not be masked by the local fallback"
    );
    assert!(matches!(
        node.plan_transit_next_hop(&destination, &make_node_addr(251)),
        TransitNextHopPlan::NoRoute
    ));
    assert_eq!(
        node.coord_cache().get(&destination, Node::now_ms()),
        Some(&cached)
    );

    node.coord_cache_mut().clear();
    assert_eq!(
        node.find_next_hop(&destination)
            .map(|peer| *peer.node_addr()),
        Some(*parent.node_addr())
    );
    let cached = TreeCoordinate::root_with_meta(destination, 71, 1_001);
    node.coord_cache_mut()
        .insert(destination, cached.clone(), Node::now_ms());
    assert_eq!(
        node.get_dest_coords(&destination),
        cached,
        "valid cached metadata also retains precedence"
    );
    assert!(node.application_route_has_coordinates(&destination, *parent.node_addr()));
}

#[test]
fn root_replacement_and_parent_loss_remove_old_root_fallback() {
    let Fixture {
        mut node,
        parent,
        root: old_root,
        replacement: new_root,
        ..
    } = fixture();
    let old_destination = *old_root.node_addr();
    node.coord_cache_mut().insert(
        old_destination,
        TreeCoordinate::root(old_destination),
        Node::now_ms(),
    );
    set_root(&mut node, parent, new_root, 8);
    let destination = *new_root.node_addr();
    assert!(node.current_tree_root_coords(&old_destination).is_none());
    assert!(
        !node
            .coord_cache()
            .contains(&old_destination, Node::now_ms())
    );
    assert!(node.find_next_hop(&old_destination).is_none());
    assert!(!node.application_route_has_coordinates(&old_destination, *parent.node_addr()));
    assert_eq!(
        node.find_next_hop(&destination)
            .map(|peer| *peer.node_addr()),
        Some(*parent.node_addr())
    );
    assert_eq!(
        node.get_dest_coords(&destination),
        TreeCoordinate::root_with_meta(destination, 28, 990)
    );

    assert!(node.handle_peer_removal_tree_cleanup(parent.node_addr()));
    assert!(node.tree_state().is_root());
    assert!(node.current_tree_root_coords(&destination).is_none());
    assert!(!node.application_route_has_coordinates(&destination, *parent.node_addr()));
    assert!(
        node.find_next_hop(&destination).is_none(),
        "a split must not retain the departed root's implicit route"
    );
}

#[test]
fn root_transit_excludes_previous_hop_and_nonprogressing_peer() {
    let Fixture {
        mut node,
        parent,
        root,
        alternate: child,
        ..
    } = fixture();
    let child_addr = *child.node_addr();
    let local = *node.node_addr();
    let destination = *root.node_addr();
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(child_addr, local, 1, 1_000),
        TreeCoordinate::from_addrs(vec![child_addr, local, *parent.node_addr(), destination])
            .unwrap(),
    );
    assert!(
        matches!(node.plan_transit_next_hop(&destination, &child_addr), TransitNextHopPlan::Route(next) if next == *parent.node_addr())
    );
    assert!(
        matches!(node.plan_transit_next_hop(&destination, parent.node_addr()), TransitNextHopPlan::Loop(next) if next == *parent.node_addr()),
        "root routing must not bounce back or escape through a nonprogressing child"
    );
    node.peers
        .get_mut(parent.node_addr())
        .unwrap()
        .mark_disconnected();
    assert!(
        node.find_next_hop(&destination).is_none(),
        "root evidence alone cannot authorize an unusable carrier"
    );
}

#[test]
fn current_root_hint_does_not_override_unavailable_source_binding() {
    let Fixture {
        mut node,
        parent,
        root,
        alternate: selected,
        ..
    } = fixture();
    let destination = *root.node_addr();
    node.set_endpoint_source_route(root, Some(selected))
        .unwrap();
    assert_eq!(
        node.find_next_hop(&destination)
            .map(|peer| *peer.node_addr()),
        Some(*selected.node_addr())
    );
    node.peers
        .get_mut(selected.node_addr())
        .unwrap()
        .mark_disconnected();
    assert!(
        node.find_next_hop(&destination).is_none(),
        "local traffic must fail closed on the selected carrier"
    );
    assert_eq!(
        node.source_routes.get(&destination),
        Some(selected.node_addr())
    );
    assert!(
        matches!(node.plan_transit_next_hop(&destination, &make_node_addr(251)), TransitNextHopPlan::Route(next) if next == *parent.node_addr()),
        "transit still uses native progress, independently of local source binding"
    );
}
