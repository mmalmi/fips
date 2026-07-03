//! Routing integration tests.
//!
//! Tests the full Node::find_next_hop() routing logic including bloom
//! filter priority, greedy tree routing, and tie-breaking.

use super::*;
use crate::bloom::BloomFilter;
use crate::config::RoutingMode;
use crate::mmp::ReceiverReport;
use crate::tree::{ParentDeclaration, TreeCoordinate};
use spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, generate_random_edges, initiate_handshake,
    lock_large_network_test, make_test_node, run_tree_test, verify_tree_convergence,
};
use std::collections::HashSet;

mod chain_topology;
mod direct_paths;
mod large_reachability;
mod partition_and_source_coords;
mod stale_metrics;
mod tree_and_bloom;

// === Multi-hop forwarding simulation ===

/// Result of simulating multi-hop packet forwarding.
#[derive(Debug)]
enum ForwardResult {
    /// Packet reached the destination in the given number of hops.
    Delivered(usize),
    /// Routing returned None at the given node index (no route).
    NoRoute { at_node: usize, hops: usize },
    /// Routing loop detected (visited the same node twice).
    Loop { at_node: usize, hops: usize },
}

/// Build a NodeAddr → node index lookup table.
fn build_addr_index(nodes: &[TestNode]) -> std::collections::HashMap<NodeAddr, usize> {
    nodes
        .iter()
        .enumerate()
        .map(|(i, tn)| (*tn.node.node_addr(), i))
        .collect()
}

/// Simulate multi-hop forwarding from source to destination.
///
/// At each hop, calls `find_next_hop` on the current node and follows
/// the result to the next node. Terminates on delivery, routing failure,
/// or loop detection.
fn simulate_forwarding(
    nodes: &mut [TestNode],
    addr_index: &std::collections::HashMap<NodeAddr, usize>,
    src: usize,
    dst: usize,
) -> ForwardResult {
    let dest_addr = *nodes[dst].node.node_addr();
    let max_hops = nodes.len(); // can't take more hops than nodes

    let mut current = src;
    let mut visited = HashSet::new();
    visited.insert(current);

    for hop in 0..max_hops {
        let next = nodes[current].node.find_next_hop(&dest_addr);

        match next {
            None => {
                // find_next_hop returns None for local delivery (dest == self)
                if *nodes[current].node.node_addr() == dest_addr {
                    return ForwardResult::Delivered(hop);
                }
                return ForwardResult::NoRoute {
                    at_node: current,
                    hops: hop,
                };
            }
            Some(peer) => {
                let next_addr = *peer.node_addr();

                // Is next hop the destination?
                if next_addr == dest_addr {
                    return ForwardResult::Delivered(hop + 1);
                }

                // Find the node index for the next hop
                let next_idx = match addr_index.get(&next_addr) {
                    Some(&idx) => idx,
                    None => {
                        return ForwardResult::NoRoute {
                            at_node: current,
                            hops: hop,
                        };
                    }
                };

                // Loop detection
                if visited.contains(&next_idx) {
                    return ForwardResult::Loop {
                        at_node: next_idx,
                        hops: hop + 1,
                    };
                }

                visited.insert(next_idx);
                current = next_idx;
            }
        }
    }

    ForwardResult::NoRoute {
        at_node: current,
        hops: max_hops,
    }
}

#[test]
fn test_parent_loss_reparent_invalidates_coord_cache() {
    let mut node = make_node();
    let my_addr = *node.node_addr();

    let root = make_node_addr(0);
    let parent = make_node_addr(1);
    let alt = make_node_addr(2);

    node.tree_state_mut().update_peer(
        ParentDeclaration::new(parent, root, 1, 1000),
        TreeCoordinate::from_addrs(vec![parent, root]).unwrap(),
    );
    node.tree_state_mut().update_peer(
        ParentDeclaration::new(alt, root, 1, 1000),
        TreeCoordinate::from_addrs(vec![alt, root]).unwrap(),
    );
    node.tree_state_mut().set_parent(parent, 1, 1000);
    node.tree_state_mut().recompute_coords();
    assert!(!node.tree_state().is_root());
    assert_eq!(node.tree_state().root(), &root);

    let now_ms = Node::now_ms();

    let downstream = make_node_addr(10);
    node.coord_cache_mut().insert(
        downstream,
        TreeCoordinate::from_addrs(vec![downstream, my_addr, root]).unwrap(),
        now_ms,
    );
    let sibling_dest = make_node_addr(11);
    node.coord_cache_mut().insert(
        sibling_dest,
        TreeCoordinate::from_addrs(vec![sibling_dest, alt, root]).unwrap(),
        now_ms,
    );

    let changed = node.handle_peer_removal_tree_cleanup(&parent);
    assert!(changed);
    assert_eq!(node.tree_state().my_declaration().parent_id(), &alt);
    assert_eq!(node.tree_state().root(), &root);

    assert!(
        !node.coord_cache().contains(&downstream, now_ms),
        "entry routing through our old coordinate prefix must be invalidated"
    );
    assert!(
        node.coord_cache().contains(&sibling_dest, now_ms),
        "same-root entry not routing through us should survive"
    );
}

#[test]
fn test_parent_loss_selfroot_invalidates_coord_cache() {
    let mut node = make_node();
    let my_addr = *node.node_addr();

    let old_root = make_node_addr(0);
    let parent = make_node_addr(1);

    node.tree_state_mut().update_peer(
        ParentDeclaration::new(parent, old_root, 1, 1000),
        TreeCoordinate::from_addrs(vec![parent, old_root]).unwrap(),
    );
    node.tree_state_mut().set_parent(parent, 1, 1000);
    node.tree_state_mut().recompute_coords();
    assert!(!node.tree_state().is_root());

    let now_ms = Node::now_ms();

    let downstream = make_node_addr(10);
    node.coord_cache_mut().insert(
        downstream,
        TreeCoordinate::from_addrs(vec![downstream, my_addr, old_root]).unwrap(),
        now_ms,
    );
    let foreign = make_node_addr(11);
    node.coord_cache_mut().insert(
        foreign,
        TreeCoordinate::from_addrs(vec![foreign, parent, old_root]).unwrap(),
        now_ms,
    );

    let changed = node.handle_peer_removal_tree_cleanup(&parent);
    assert!(changed);
    assert!(node.tree_state().is_root());
    assert_eq!(node.tree_state().root(), &my_addr);

    assert!(
        !node.coord_cache().contains(&downstream, now_ms),
        "via-node entry must be invalidated after self-root"
    );
    assert!(
        !node.coord_cache().contains(&foreign, now_ms),
        "old-root entry must be invalidated after self-root"
    );
}
