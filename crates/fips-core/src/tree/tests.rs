use std::collections::HashMap;

use super::*;

fn make_node_addr(val: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = val;
    NodeAddr::from_bytes(bytes)
}

fn make_coords(ids: &[u8]) -> TreeCoordinate {
    TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
}

fn make_costs(entries: &[(u8, f64)]) -> HashMap<NodeAddr, f64> {
    entries
        .iter()
        .map(|&(addr, cost)| (make_node_addr(addr), cost))
        .collect()
}

// ===== TreeCoordinate Tests =====

mod coordinate;
mod cost_selection;
mod dampening;
mod declaration;
mod parent_eval;
mod routing;
mod state_core;
