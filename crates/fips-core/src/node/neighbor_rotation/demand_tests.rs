//! Attribution controls; real route departure and recovery use SimNetwork.
use super::*;
use crate::Config;
use crate::dataplane::{DataplaneFspWrapRoute, DataplaneLiveOwnerRoutes, OwnerConfig, OwnerId};

fn addr(value: u8) -> NodeAddr {
    NodeAddr::from_bytes([value; 16])
}

fn queue(node: &mut Node, destination: NodeAddr) {
    let admission = node
        .pending_session_traffic
        .push_tun_packet(destination, vec![1], 8, 8, None);
    assert!(!admission.destination_dropped());
}

fn preferred(node: &Node, candidate: NodeAddr) -> bool {
    !node.neighbor_rotation_discovery_order(candidate, 100).1
}

fn installed(node: &mut Node, destination: NodeAddr, carrier: NodeAddr) {
    let owner = OwnerId::fsp_node(destination);
    node.dataplane.register_owner(owner, OwnerConfig::new(1, 8));
    node.dataplane
        .replace_owner_fsp_routes(
            owner,
            DataplaneLiveOwnerRoutes::default(),
            Some(DataplaneFspWrapRoute::new(
                OwnerId::fmp_node(carrier),
                1,
                2,
                *node.node_addr(),
                destination,
            )),
            None,
        )
        .unwrap();
    assert_eq!(
        node.dataplane.fsp_owner_next_hop(&destination),
        Some(carrier)
    );
}

#[test]
fn queued_binding_redirects_preference_and_drain_removes_it() {
    let mut node = Node::new(Config::new()).unwrap();
    let (destination, first, second) = (addr(1), addr(2), addr(3));
    node.source_routes.insert(destination, first);
    assert!(
        !preferred(&node, first),
        "binding without traffic is not demand"
    );
    queue(&mut node, destination);
    assert!(preferred(&node, first));
    assert!(
        !preferred(&node, destination),
        "respect the explicit carrier"
    );
    node.source_routes.insert(destination, second);
    assert!(!preferred(&node, first), "no cached old binding");
    assert!(preferred(&node, second));
    node.source_routes.remove(&destination);
    assert!(!preferred(&node, second));
    assert!(
        preferred(&node, destination),
        "unbound direct discovery still works"
    );
    node.pending_session_traffic
        .remove_destination(&destination);
    assert!(!preferred(&node, destination));
}

#[test]
fn installed_carrier_is_used_only_until_cleared_or_overridden() {
    let mut node = Node::new(Config::new()).unwrap();
    let (destination, current, explicit) = (addr(1), addr(2), addr(3));
    installed(&mut node, destination, current);
    queue(&mut node, destination);
    assert!(preferred(&node, current));
    assert!(
        !preferred(&node, destination),
        "direct fast path honors installed carrier"
    );
    node.source_routes.insert(destination, explicit);
    assert!(!preferred(&node, current));
    assert!(preferred(&node, explicit));
    node.source_routes.remove(&destination);
    assert!(node.dataplane.clear_fsp_output_route(destination));
    assert_eq!(node.dataplane.fsp_owner_next_hop(&destination), None);
    assert!(
        !preferred(&node, current),
        "do not revive historical carrier state"
    );
    assert!(preferred(&node, destination));
}

#[test]
fn shared_carrier_retains_demand_until_all_original_destinations_drain() {
    let mut node = Node::new(Config::new()).unwrap();
    let carrier = addr(3);
    for destination in [addr(1), addr(2)] {
        queue(&mut node, destination);
        node.source_routes.insert(destination, carrier);
    }
    node.pending_session_traffic.remove_destination(&addr(1));
    assert!(preferred(&node, carrier));
    node.pending_session_traffic.remove_destination(&addr(2));
    assert!(!preferred(&node, carrier));
}

#[test]
fn carrier_demand_keeps_ordinary_exploration_and_interrupted_retry_precedence() {
    let mut node = Node::new(Config::new()).unwrap();
    let (destination, carrier, ordinary) = (addr(1), addr(2), addr(3));
    queue(&mut node, destination);
    node.source_routes.insert(destination, carrier);
    assert!(preferred(&node, carrier));
    node.neighbor_rotation.exploration_due = true;
    assert!(!preferred(&node, carrier));
    assert!(!preferred(&node, destination));
    node.neighbor_rotation.exploration_due = false;
    node.neighbor_rotation.interrupted_outgoing = Some(InterruptedOutgoing {
        peer: ordinary,
        started_ms: 1,
        deadline_ms: 200,
    });
    assert!(
        node.neighbor_rotation_discovery_order(ordinary, 100)
            < node.neighbor_rotation_discovery_order(carrier, 100)
    );
    assert!(
        node.neighbor_rotation_discovery_order(carrier, 200)
            < node.neighbor_rotation_discovery_order(ordinary, 200)
    );
}
