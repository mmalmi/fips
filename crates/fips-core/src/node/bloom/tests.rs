use super::*;
use crate::config::Config;
use crate::transport::LinkId;
use crate::{ActivePeer, Identity, PeerIdentity};

fn unsendable_peer() -> (Node, NodeAddr) {
    let mut node = Node::new(Config::new()).unwrap();
    let identity = Identity::generate();
    let peer = PeerIdentity::from_pubkey(identity.pubkey());
    let addr = *peer.node_addr();
    node.peers
        .insert(addr, ActivePeer::new(peer, LinkId::new(1), Node::now_ms()));
    // Component fixture: a previous successful filter exists, but its carrier
    // is unavailable. Exercise the production send failure, not a mock result.
    node.bloom_state.record_update_sent(addr, 0);
    (node, addr)
}

#[tokio::test]
async fn disabled_refresh_preserves_explicit_updates_and_failed_send_ownership() {
    let (mut node, peer) = unsendable_peer();
    node.config.node.bloom.announce_refresh_interval_secs = 0;
    node.check_bloom_state().await;
    assert_eq!(node.stats().bloom.send_failed, 0);
    assert!(!node.bloom_state.needs_update(&peer));

    node.bloom_state.mark_update_needed(peer);
    node.check_bloom_state().await;
    assert_eq!(node.stats().bloom.send_failed, 1);
    assert_eq!(node.stats().bloom.sent, 0);
    assert!(node.bloom_state.needs_update(&peer));
    assert!(node.bloom_state.refresh_due(&peer, Node::now_ms(), 5_000));
    node.check_bloom_state().await;
    assert_eq!(
        node.stats().bloom.send_failed,
        2,
        "failed update retains retry ownership"
    );
}

#[tokio::test]
async fn periodic_refresh_failure_remains_pending_and_removed_peer_is_not_polled() {
    let (mut node, peer) = unsendable_peer();
    node.check_bloom_state().await;
    assert_eq!(node.stats().bloom.send_failed, 1);
    assert!(node.bloom_state.needs_update(&peer));
    assert!(node.bloom_state.refresh_due(&peer, Node::now_ms(), 5_000));

    node.peers.remove(&peer);
    node.bloom_state.remove_peer_state(&peer);
    node.check_bloom_state().await;
    assert_eq!(node.stats().bloom.send_failed, 1);
    assert!(!node.bloom_state.needs_update(&peer));
    assert!(!node.bloom_state.refresh_due(&peer, Node::now_ms(), 5_000));
}
