use super::*;

use crate::Identity;

fn make_peer_identity() -> PeerIdentity {
    let identity = Identity::generate();
    PeerIdentity::from_pubkey(identity.pubkey())
}

fn make_node_addr(val: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = val;
    NodeAddr::from_bytes(bytes)
}

fn make_coords(ids: &[u8]) -> TreeCoordinate {
    TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
}

#[test]
fn test_connectivity_state_properties() {
    assert!(ConnectivityState::Connected.can_send());
    assert!(ConnectivityState::Stale.can_send());
    assert!(!ConnectivityState::Reconnecting.can_send());
    assert!(!ConnectivityState::Disconnected.can_send());

    assert!(ConnectivityState::Connected.is_healthy());
    assert!(!ConnectivityState::Stale.is_healthy());

    assert!(ConnectivityState::Disconnected.is_terminal());
    assert!(!ConnectivityState::Connected.is_terminal());
}

#[test]
fn test_active_peer_creation() {
    let identity = make_peer_identity();
    let peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    assert_eq!(peer.identity().node_addr(), identity.node_addr());
    assert_eq!(peer.link_id(), LinkId::new(1));
    assert!(peer.is_healthy());
    assert!(peer.can_send());
    assert_eq!(peer.authenticated_at(), 1000);
    assert!(peer.needs_filter_update()); // New peers need filter
}

#[test]
fn test_connectivity_transitions() {
    let identity = make_peer_identity();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    assert!(peer.is_healthy());

    peer.mark_stale();
    assert_eq!(peer.connectivity(), ConnectivityState::Stale);
    assert!(peer.can_send()); // Stale can still send

    // Traffic received brings back to connected
    peer.touch(2000);
    assert!(peer.is_healthy());

    peer.mark_reconnecting();
    assert!(!peer.can_send());
    peer.touch(2500);
    assert_eq!(peer.connectivity(), ConnectivityState::Reconnecting);
    assert!(!peer.can_send());

    peer.mark_connected(3000);
    assert!(peer.is_healthy());

    peer.mark_disconnected();
    assert!(peer.is_disconnected());
    assert!(!peer.can_send());
}

#[test]
fn test_tree_position() {
    let identity = make_peer_identity();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    assert!(!peer.has_tree_position());
    assert!(peer.coords().is_none());

    let node = make_node_addr(1);
    let parent = make_node_addr(2);
    let decl = ParentDeclaration::new(node, parent, 1, 1000);
    let coords = make_coords(&[1, 2, 0]);

    peer.update_tree_position(decl, coords);

    assert!(peer.has_tree_position());
    assert!(peer.coords().is_some());
    assert_eq!(
        peer.last_seen(),
        1000,
        "tree metadata updates must not refresh path liveness"
    );
}

#[test]
fn test_bloom_filter() {
    let identity = make_peer_identity();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);
    let target = make_node_addr(42);

    assert!(!peer.may_reach(&target));
    assert!(peer.filter_is_stale(2000, 500));

    let mut filter = BloomFilter::new();
    filter.insert(&target);
    peer.update_filter(filter, 1, 1500);

    assert!(peer.may_reach(&target));
    assert!(!peer.filter_is_stale(1800, 500));
    assert!(peer.filter_is_stale(2500, 500));
}

#[test]
fn test_timing() {
    let identity = make_peer_identity();
    let peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    assert_eq!(peer.connection_duration(2000), 1000);
    assert_eq!(peer.idle_time(2000), 1000);
}

#[test]
fn test_filter_update_flag() {
    let identity = make_peer_identity();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    assert!(peer.needs_filter_update()); // New peer

    peer.clear_filter_update_needed();
    assert!(!peer.needs_filter_update());

    peer.mark_filter_update_needed();
    assert!(peer.needs_filter_update());
}

#[test]
fn test_with_stats() {
    let identity = make_peer_identity();
    let mut stats = LinkStats::new();
    stats.record_sent(100);
    stats.record_recv(200, 500);

    let peer = ActivePeer::with_stats(identity, LinkId::new(1), 1000, stats);

    assert_eq!(peer.link_stats().packets_sent, 1);
    assert_eq!(peer.link_stats().packets_recv, 1);
}

#[test]
fn test_replay_suppression_counter() {
    let identity = make_peer_identity();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    // Initial count is zero
    assert_eq!(peer.replay_suppressed_count(), 0);

    // Increment returns new count
    assert_eq!(peer.increment_replay_suppressed(), 1);
    assert_eq!(peer.increment_replay_suppressed(), 2);
    assert_eq!(peer.increment_replay_suppressed(), 3);
    assert_eq!(peer.replay_suppressed_count(), 3);

    // Reset returns previous count and zeroes it
    assert_eq!(peer.reset_replay_suppressed(), 3);
    assert_eq!(peer.replay_suppressed_count(), 0);

    // Can increment again after reset
    assert_eq!(peer.increment_replay_suppressed(), 1);
    assert_eq!(peer.replay_suppressed_count(), 1);

    // Reset when zero returns zero
    peer.reset_replay_suppressed();
    assert_eq!(peer.reset_replay_suppressed(), 0);
}

#[test]
fn test_increment_decrypt_failures_monotonic() {
    let identity = make_peer_identity();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    // Initial count is zero
    assert_eq!(peer.consecutive_decrypt_failures(), 0);

    // Each call returns a strictly increasing count
    let mut prev = 0u32;
    for expected in 1..=25u32 {
        let count = peer.increment_decrypt_failures();
        assert_eq!(count, expected, "increment must return monotonic count");
        assert!(count > prev, "count must strictly increase");
        assert_eq!(peer.consecutive_decrypt_failures(), count);
        prev = count;
    }
}

#[test]
fn test_reset_decrypt_failures_zeroes_counter() {
    let identity = make_peer_identity();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    // Drive counter up
    for _ in 0..7 {
        peer.increment_decrypt_failures();
    }
    assert_eq!(peer.consecutive_decrypt_failures(), 7);

    // Reset zeroes it
    peer.reset_decrypt_failures();
    assert_eq!(peer.consecutive_decrypt_failures(), 0);

    // Reset on zero is a no-op (still zero, no panic)
    peer.reset_decrypt_failures();
    assert_eq!(peer.consecutive_decrypt_failures(), 0);

    // Counter resumes at 1 after reset
    assert_eq!(peer.increment_decrypt_failures(), 1);
    assert_eq!(peer.consecutive_decrypt_failures(), 1);
}

#[test]
fn test_rekey_jitter_in_range() {
    for _ in 0..100 {
        let identity = make_peer_identity();
        let peer = ActivePeer::new(identity, LinkId::new(1), 1000);
        let jitter = peer.rekey_jitter_secs();
        assert!(
            (-REKEY_JITTER_SECS..=REKEY_JITTER_SECS).contains(&jitter),
            "jitter {} outside [-{}, +{}]",
            jitter,
            REKEY_JITTER_SECS,
            REKEY_JITTER_SECS
        );
    }
}

#[test]
fn test_rekey_jitter_mean_near_zero() {
    let mut sum = 0i64;
    let n = 200i64;

    for _ in 0..n {
        let identity = make_peer_identity();
        let peer = ActivePeer::new(identity, LinkId::new(1), 1000);
        sum += peer.rekey_jitter_secs();
    }

    let mean = sum / n;
    assert!(
        mean.abs() < 5,
        "empirical mean {} not within 5 of 0 over {} samples",
        mean,
        n
    );
}
