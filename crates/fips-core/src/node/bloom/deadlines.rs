//! Component controls for cached deadlines and failed-send ownership. Synthetic
//! timestamps below exercise bookkeeping; native RX timing has separate tests.

use super::*;
use crate::config::Config;
use crate::transport::LinkId;
use crate::{ActivePeer, BloomState, Identity, PeerIdentity};

fn addr(value: u8) -> NodeAddr {
    let mut bytes = [0; 16];
    bytes[0] = value;
    NodeAddr::from_bytes(bytes)
}

#[test]
fn pending_deadline_tracks_removal_completion_and_readmission() {
    let mut state = BloomState::new(addr(0));
    let first = addr(1);
    let second = addr(2);
    state.record_update_sent(first, 1_000);
    state.record_update_sent(second, 1_200);
    state.mark_all_updates_needed([first, second]);
    assert_eq!(state.pending_update_deadline_ms(), Some(1_500));
    assert!(state.pending_peers_due(1_499).is_empty());
    assert_eq!(state.pending_peers_due(1_500), vec![first]);

    state.remove_peer_state(&first);
    assert_eq!(state.pending_peer_deadline_ms(&first), None);
    assert_eq!(state.pending_update_deadline_ms(), Some(1_700));
    assert_eq!(state.pending_peers_due(1_700), vec![second]);

    // Successful completion retires the retry floor as well as pending work.
    state.defer_update_retry(&second, 2_000);
    state.record_update_sent(second, 2_000);
    assert_eq!(state.pending_update_deadline_ms(), None);
    assert!(!state.needs_update(&second));
    state.mark_update_needed(second);
    assert_eq!(state.pending_peer_deadline_ms(&second), Some(2_500));

    // Removal also retires prior successful-send history for a later owner.
    state.mark_update_needed(first);
    assert_eq!(state.pending_peer_deadline_ms(&first), Some(0));
    assert_eq!(state.pending_update_deadline_ms(), Some(0));
    state.clear_pending_updates();
    assert_eq!(state.pending_update_deadline_ms(), None);
    assert!(state.pending_peers_due(u64::MAX).is_empty());
    state.mark_update_needed(second);
    assert_eq!(state.pending_update_deadline_ms(), Some(2_500));
}

#[test]
fn repeated_and_changed_marks_preserve_failed_send_floors() {
    let mut state = BloomState::new(addr(0));
    let first = addr(1);
    let second = addr(2);
    let absent = addr(3);
    for peer in [first, second] {
        state.record_update_sent(peer, 1_000);
        state.record_sent_filter(peer, state.base_filter());
    }
    state.mark_update_needed(first);
    state.defer_update_retry(&first, 2_200);
    state.defer_update_retry(&first, 2_000);
    state.mark_update_needed(first);
    state.mark_all_updates_needed([first, second]);
    assert_eq!(state.pending_peer_deadline_ms(&first), Some(2_200));
    assert_eq!(state.pending_update_deadline_ms(), Some(1_500));

    // A real outgoing-content change must preserve existing send ownership.
    state.add_leaf_dependent(addr(4));
    state.mark_changed_peers(&absent, &[first, second], &HashMap::new());
    assert_eq!(state.pending_peer_deadline_ms(&first), Some(2_200));
    assert_eq!(state.pending_peer_deadline_ms(&second), Some(1_500));
    assert_eq!(state.pending_peers_due(1_500), vec![second]);

    state.defer_pending_retries(2_300);
    state.defer_pending_retries(2_100);
    state.mark_all_updates_needed([first, second]);
    state.mark_changed_peers(&absent, &[first, second], &HashMap::new());
    assert_eq!(state.pending_peer_deadline_ms(&first), Some(2_300));
    assert_eq!(state.pending_peer_deadline_ms(&second), Some(2_300));
    assert_eq!(state.pending_update_deadline_ms(), Some(2_300));
    assert!(state.pending_peers_due(2_299).is_empty());
    assert_eq!(state.pending_peers_due(2_300).len(), 2);

    state.defer_update_retry(&absent, 9_000);
    assert!(!state.needs_update(&absent));
    assert_eq!(state.pending_peer_deadline_ms(&absent), None);
    assert_eq!(state.pending_update_deadline_ms(), Some(2_300));
    assert!(
        state.should_send_update(&first, 1_500),
        "the independent ordinary tick still observes only successful-send debounce"
    );
    assert!(!state.should_send_update(&first, 1_499));
}

#[test]
fn pending_deadline_recomputes_debounce_without_clock_wrap_or_floor_rewind() {
    let mut state = BloomState::new(addr(0));
    let peer = addr(1);
    state.record_update_sent(peer, 1_000);
    state.mark_update_needed(peer);
    assert_eq!(state.pending_update_deadline_ms(), Some(1_500));
    assert!(state.pending_peers_due(999).is_empty());
    assert!(!state.should_send_update(&peer, 999));

    state.set_update_debounce_ms(2_000);
    assert_eq!(state.pending_update_deadline_ms(), Some(3_000));
    state.defer_update_retry(&peer, 2_500);
    state.set_update_debounce_ms(100);
    assert_eq!(state.pending_update_deadline_ms(), Some(2_500));
    assert!(state.pending_peers_due(2_499).is_empty());
    assert_eq!(state.pending_peers_due(2_500), vec![peer]);
    assert!(state.should_send_update(&peer, 1_100));

    state.record_update_sent(peer, u64::MAX - 10);
    state.mark_update_needed(peer);
    assert_eq!(state.pending_update_deadline_ms(), Some(u64::MAX));
    assert!(state.pending_peers_due(u64::MAX - 1).is_empty());
    assert!(!state.should_send_update(&peer, u64::MAX - 1));
    assert_eq!(state.pending_peers_due(u64::MAX), vec![peer]);
    assert!(state.should_send_update(&peer, u64::MAX));
    state.defer_update_retry(&peer, u64::MAX);
    state.set_update_debounce_ms(0);
    assert_eq!(state.pending_update_deadline_ms(), Some(u64::MAX));
}

#[tokio::test]
async fn failed_fast_send_is_paced_without_disabling_periodic_retry() {
    let mut node = Node::new(Config::new()).unwrap();
    node.config.node.bloom.announce_refresh_interval_secs = 0;
    let identity = Identity::generate();
    let peer = PeerIdentity::from_pubkey(identity.pubkey());
    let peer_addr = *peer.node_addr();
    let admitted_at = Node::now_ms();
    node.peers.insert(
        peer_addr,
        ActivePeer::new(peer, LinkId::new(1), admitted_at),
    );
    // As in the existing Bloom failure fixture, no carrier exists. The real
    // production send returns an error; there is no transport error injection.
    node.bloom_state.record_update_sent(peer_addr, 0);
    node.bloom_state.mark_update_needed(peer_addr);
    let tick_ms = node.config.node.tick_interval_secs * 1_000;
    assert!(tick_ms > 0);
    let before = Node::now_ms();
    node.send_due_filter_announces().await;
    let after = Node::now_ms();
    let due = node
        .bloom_state
        .pending_peer_deadline_ms(&peer_addr)
        .unwrap();
    assert!(due >= before.saturating_add(tick_ms));
    assert!(due <= after.saturating_add(tick_ms));
    assert_eq!(node.pending_routing_announce_deadline_ms(), Some(due));
    assert_eq!(node.stats().bloom.send_failed, 1);
    assert_eq!(node.stats().bloom.sent, 0);
    assert!(node.bloom_state.needs_update(&peer_addr));
    node.send_due_filter_announces().await;
    assert_eq!(node.stats().bloom.send_failed, 1, "no hot retry loop");

    // The timeout hook uses a fresh clock without consuming pending updates.
    let before_defer = Node::now_ms();
    node.defer_filter_announce_retry();
    let after_defer = Node::now_ms();
    let deferred = node
        .bloom_state
        .pending_peer_deadline_ms(&peer_addr)
        .unwrap();
    assert!(deferred >= due.max(before_defer.saturating_add(tick_ms)));
    assert!(deferred <= due.max(after_defer.saturating_add(tick_ms)));

    node.check_bloom_state().await;
    assert_eq!(
        node.stats().bloom.send_failed,
        2,
        "ordinary maintenance is not gated by the extra fast retry floor"
    );
    assert_eq!(node.stats().bloom.sent, 0);
    assert!(node.bloom_state.needs_update(&peer_addr));
    assert_eq!(
        node.peers.get(&peer_addr).unwrap().authenticated_at(),
        admitted_at
    );

    node.peers.remove(&peer_addr);
    node.bloom_state.remove_peer_state(&peer_addr);
    assert_eq!(node.pending_routing_announce_deadline_ms(), None);
    node.send_due_filter_announces().await;
    node.check_bloom_state().await;
    assert_eq!(node.stats().bloom.send_failed, 2);
    assert!(!node.bloom_state.needs_update(&peer_addr));
}
