//! Spanning tree convergence integration tests.
//!
//! Tests that multi-node networks converge to a consistent spanning tree
//! with the correct root (smallest NodeAddr). Includes helper infrastructure
//! reused by bloom filter tests.

use super::*;
use crate::mmp::ReceiverReport;
use crate::protocol::TreeAnnounce;
use crate::transport::ReceivedPacket;
use crate::tree::{CoordEntry, ParentDeclaration, TreeCoordinate};

static LARGE_NETWORK_TEST_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

pub(super) async fn lock_large_network_test() -> tokio::sync::MutexGuard<'static, ()> {
    LARGE_NETWORK_TEST_LOCK.lock().await
}

mod cases;
mod drain;
mod fixture;
mod repair;
mod snapshot;
mod synthetic;
mod topology;

pub(super) use drain::{drain_all_packets, process_available_packets};
pub(super) use fixture::{TestNode, initiate_handshake, make_test_node, make_test_node_with_mtu};
pub(super) use topology::{
    cleanup_nodes, generate_random_edges, run_tree_test, run_tree_test_with_mtus,
    verify_tree_convergence, verify_tree_convergence_components,
};

use drain::drain_initial_handshake_burst;
use fixture::complete_direct_handshake;
use repair::repair_missing_edge_handshakes;
use snapshot::print_tree_snapshot;
use synthetic::{
    drain_synthetic_packets_until_idle, has_synthetic_pending_work,
    refresh_synthetic_filter_announces, run_synthetic_node_work,
};
