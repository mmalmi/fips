//! Discovery protocol tests: LookupRequest and LookupResponse.
//!
//! Unit tests for handler logic (dedup, TTL, response caching) and
//! integration tests for multi-node forwarding and reverse-path
//! response routing.

use super::*;
use crate::config::RoutingMode;
use crate::node::recent_requests::RecentRequest;
use crate::protocol::{LookupRequest, LookupResponse};
use crate::tree::TreeCoordinate;
use spanning_tree::{
    cleanup_nodes, generate_random_edges, lock_large_network_test, process_available_packets,
    run_tree_test, verify_tree_convergence,
};

mod convergent_paths_large;
mod forwarding_basic;
mod open_sweep;
mod path_mtu;
mod pending_lookups;
mod recent_requests;
mod reply_learned_forward;
mod reply_learned_origin;
mod reply_learned_policy;
mod request;
mod response;
