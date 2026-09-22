use super::*;
use crate::{Config, Identity, PeerIdentity, config::NeighborRotationConfig, peer::ActivePeer};

fn node(cap: usize) -> Node {
    let mut config = Config::new();
    config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: 1,
        interval_secs: 1,
    });
    config.node.rate_limit.handshake_timeout_secs = 6;
    let mut node = Node::new(config).unwrap();
    node.set_max_peers(cap);
    node
}

fn add(node: &mut Node, byte: u8, demand: Option<u64>) -> NodeAddr {
    let key = Identity::from_secret_bytes(&[byte; 32]).unwrap();
    let identity = PeerIdentity::from_pubkey_full(key.pubkey_full());
    let addr = *identity.node_addr();
    let mut active = ActivePeer::new(identity, LinkId::new(u64::from(byte)), 1);
    active.touch(100);
    if let Some(at) = demand {
        active.record_transit_demand(at);
    }
    node.peers.insert(addr, active);
    addr
}

fn lose(node: &mut Node, peer: NodeAddr, at: u64) {
    node.remove_link_dead_discovered_peer(&peer, at, Duration::from_secs(3));
    assert!(!node.peers.contains_key(&peer));
}

fn preferred(node: &Node, peer: NodeAddr, at: u64) -> bool {
    !node.neighbor_rotation_discovery_order(peer, at).1
}

#[test]
fn unused_transit_history_survives_waiting_without_route_or_retry_authority() {
    let mut node = node(2);
    let peer = add(&mut node, 1, Some(100));
    lose(&mut node, peer, 4_100);
    // Time waiting behind other admissions must not spend the earned preference.
    assert!(preferred(&node, peer, 10_100));
    node.config.node.rate_limit.handshake_timeout_secs = 60;
    assert!(preferred(&node, peer, 700_000));
    assert!(!node.retry_pending.contains_key(&peer));
    assert!(!node.source_routes.contains_key(&peer));
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.link_count(), 0);
}

#[test]
fn old_transit_link_maintenance_and_unadmitted_queues_do_not_earn_history() {
    let mut node = node(3);
    let stale = add(&mut node, 1, Some(100));
    let heartbeat = add(&mut node, 2, None);
    let queued = add(&mut node, 3, None);
    node.pending_session_traffic
        .push_tun_packet(queued, vec![1], 8, 8, None);
    for peer in [stale, heartbeat, queued] {
        lose(&mut node, peer, 4_101);
        assert!(!preferred(&node, peer, 4_101));
    }
    assert!(node.neighbor_rotation.lost_neighbors.is_empty());
}

#[test]
fn configured_peers_disabled_rotation_and_unlimited_rosters_do_not_add_history() {
    let mut node = node(1);
    let configured = add(&mut node, 1, Some(100));
    node.config.peers.push(crate::config::PeerConfig::new(
        node.peers.get(&configured).unwrap().identity().npub(),
        "udp",
        "127.0.0.1:9999",
    ));
    node.configured_peers = crate::node::ConfiguredPeerLookup::from_config(&node.config);
    lose(&mut node, configured, 100);
    let disabled = add(&mut node, 2, Some(100));
    node.config.node.neighbor_rotation = None;
    lose(&mut node, disabled, 100);
    node.config.node.neighbor_rotation = Some(NeighborRotationConfig {
        idle_secs: 1,
        interval_secs: 1,
    });
    node.set_max_peers(0);
    let unlimited = add(&mut node, 3, Some(100));
    lose(&mut node, unlimited, 100);
    assert!(node.neighbor_rotation.lost_neighbors.is_empty());
}

#[test]
fn history_is_capped_pruned_and_requires_new_transit_after_reconnection() {
    let mut node = node(2);
    let mut peers = Vec::new();
    for byte in 1..=3 {
        let peer = add(&mut node, byte, Some(100));
        lose(&mut node, peer, 100 + u64::from(byte));
        peers.push(peer);
        assert!(node.neighbor_rotation.lost_neighbors.len() <= 2);
    }
    assert!(!preferred(&node, peers[0], 104));
    assert!(preferred(&node, peers[1], 104));
    // A new authenticated owner starts without transit demand. Its later loss
    // cannot inherit the first owner's activity or its unused preference.
    assert_eq!(add(&mut node, 2, None), peers[1]);
    lose(&mut node, peers[1], 104);
    assert!(!preferred(&node, peers[1], 104));
    let fresh = add(&mut node, 4, Some(7_000));
    lose(&mut node, fresh, 7_000);
    assert_eq!(node.neighbor_rotation.lost_neighbors.len(), 2);
    assert!(preferred(&node, peers[2], 7_000));
    assert!(preferred(&node, fresh, 7_000));
    let newest = add(&mut node, 5, Some(7_001));
    lose(&mut node, newest, 7_001);
    assert_eq!(node.neighbor_rotation.lost_neighbors.len(), 2);
    assert!(!preferred(&node, peers[2], 7_001));
    assert!(preferred(&node, fresh, 7_001));
    assert!(preferred(&node, newest, 7_001));
}

#[test]
fn a_started_preference_is_consumed_and_ordinary_exploration_remains_owed() {
    let mut node = node(1);
    let returning = add(&mut node, 1, Some(100));
    lose(&mut node, returning, 100);
    add(&mut node, 2, None);
    assert!(preferred(&node, returning, 20_000));
    let cursor = node.neighbor_rotation.cursor;
    assert!(node.begin_neighbor_rotation(returning, true, 20_000));
    assert_eq!(node.neighbor_rotation_deadline(&returning), Some(26_000));
    node.config.node.rate_limit.handshake_timeout_secs = 60;
    assert_eq!(node.neighbor_rotation_deadline(&returning), Some(26_000));
    assert!(node.neighbor_rotation.exploration_due);
    assert_eq!(node.neighbor_rotation.cursor, cursor);
    assert!(
        !node
            .neighbor_rotation
            .lost_neighbors
            .contains_key(&returning)
    );
    // Clearing a completed/failed attempt does not restore spent history.
    node.neighbor_rotation.attempt = None;
    node.neighbor_rotation.exploration_due = false;
    assert!(!preferred(&node, returning, 27_000));
}

#[test]
fn direct_removal_without_committed_rotation_never_creates_a_preference() {
    let mut node = node(2);
    let administrative = add(&mut node, 1, Some(100));
    let elective = add(&mut node, 2, Some(100));
    node.remove_active_peer(&administrative);
    node.remove_neighbor_for_rotation(&elective);
    assert!(node.neighbor_rotation.lost_neighbors.is_empty());
}

#[test]
fn reducing_the_live_cap_retires_oldest_history_and_zero_clears_it() {
    let mut node = node(3);
    let now = Node::now_ms();
    let mut peers = Vec::new();
    for byte in 1..=3 {
        let peer = add(&mut node, byte, Some(now));
        lose(&mut node, peer, now + u64::from(byte));
        peers.push(peer);
    }
    node.set_max_peers(1);
    assert_eq!(node.neighbor_rotation.lost_neighbors.len(), 1);
    assert!(preferred(&node, peers[2], now + 3));
    node.set_max_peers(0);
    assert!(node.neighbor_rotation.lost_neighbors.is_empty());
}
