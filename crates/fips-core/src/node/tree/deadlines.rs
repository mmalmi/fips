use super::*;
use crate::config::Config;
use crate::transport::LinkId;
use crate::{ActivePeer, Identity, PeerIdentity};

fn fixture(last_sent: u64) -> (Node, NodeAddr) {
    let mut node = Node::new(Config::new()).unwrap();
    let identity = Identity::generate();
    let peer = PeerIdentity::from_pubkey(identity.pubkey());
    let addr = *peer.node_addr();
    let mut active = ActivePeer::new(peer, LinkId::new(1), Node::now_ms());
    active.set_tree_announce_min_interval_ms(500);
    active.set_last_tree_announce_sent_ms(last_sent);
    node.peers.insert(addr, active);
    (node, addr)
}

#[tokio::test]
async fn rate_limited_send_arms_only_pending_deadline() {
    let last = Node::now_ms() + 60_000;
    let (mut node, addr) = fixture(last);
    assert_eq!(node.pending_tree_announce_deadline_ms(), None);
    node.send_tree_announce_to_peer(&addr).await.unwrap();
    assert_eq!(node.pending_tree_announce_deadline_ms(), Some(last + 500));
    assert!(node.peers.get(&addr).unwrap().has_pending_tree_announce());
    assert_eq!(node.stats().tree.sent, 0);
    assert_eq!(node.stats().tree.rate_limited, 1);
    node.send_pending_tree_announces().await;
    assert_eq!(node.pending_tree_announce_deadline_ms(), Some(last + 500));
    assert_eq!(
        node.stats().tree.send_failed,
        0,
        "clock rollback cannot send early"
    );
    assert_eq!(node.last_parent_reeval, None);
}

#[tokio::test]
async fn pending_deadline_rechecks_cleared_removed_and_replaced_peers() {
    for change in 0..3 {
        let (mut node, addr) = fixture(0);
        node.mark_tree_announce_pending(&addr);
        assert!(node.pending_tree_announce_deadline_ms().is_some());
        let future = Node::now_ms() + 60_000;
        match change {
            0 => node
                .peers
                .get_mut(&addr)
                .unwrap()
                .record_tree_announce_sent(future),
            1 => {
                node.peers.remove(&addr);
            }
            _ => {
                let old = node.peers.get(&addr).unwrap();
                let mut replacement = ActivePeer::new(*old.identity(), LinkId::new(2), future);
                replacement.set_tree_announce_min_interval_ms(500);
                replacement.set_last_tree_announce_sent_ms(future);
                node.peers.insert(addr, replacement);
                node.mark_tree_announce_pending(&addr);
            }
        }
        node.send_pending_tree_announces().await;
        assert_eq!(
            node.pending_tree_announce_deadline_ms(),
            (change == 2).then_some(future + 500)
        );
        assert_eq!(node.stats().tree.sent, 0);
        assert_eq!(node.stats().tree.send_failed, 0);
    }
}

#[tokio::test]
async fn pending_dispatch_leaves_periodic_refresh_on_maintenance() {
    let (mut node, _) = fixture(0);
    assert_eq!(node.config.node.tree.announce_refresh_interval_secs, 5);
    assert_eq!(node.config.node.tree.reeval_interval_secs, 60);
    node.send_pending_tree_announces().await;
    assert_eq!(node.stats().tree.send_failed, 0);
    assert_eq!(node.pending_tree_announce_deadline_ms(), None);
    assert_eq!(node.last_parent_reeval, None);

    // With no carrier installed, a real periodic attempt fails locally. The
    // fast path above must not make this attempt just because refresh is due.
    node.send_due_tree_announces().await;
    assert_eq!(node.stats().tree.send_failed, 1);
    assert_eq!(node.pending_tree_announce_deadline_ms(), None);
}

#[tokio::test]
async fn failed_pending_send_retains_authority_and_existing_retry_floor() {
    let (mut node, addr) = fixture(0);
    node.mark_all_tree_announces_pending();
    let before = Node::now_ms();
    node.send_pending_tree_announces().await;
    assert_eq!(node.stats().tree.send_failed, 1);
    assert!(node.peers.get(&addr).unwrap().has_pending_tree_announce());
    let due = node.pending_tree_announce_deadline_ms().unwrap();
    assert!(due >= before + node.config.node.tick_interval_secs * 1_000);

    // An update during failure backoff cannot rearm an immediate send loop.
    node.mark_tree_announce_pending(&addr);
    assert_eq!(node.pending_tree_announce_deadline_ms(), Some(due));
    node.send_pending_tree_announces().await;
    assert_eq!(node.stats().tree.send_failed, 1);
    assert_eq!(
        node.peers.get(&addr).unwrap().last_tree_announce_sent_ms(),
        0
    );

    // This floor only bounds the added fast path; the original maintenance
    // retry remains eligible when its independently scheduled tick arrives.
    node.send_due_tree_announces().await;
    assert_eq!(node.stats().tree.send_failed, 2);
}

#[test]
fn authenticated_restart_arms_pending_deadline_without_resetting_rate_limit() {
    let last = Node::now_ms();
    let (mut node, addr) = fixture(last);
    node.reset_peer_routing_after_restart(&addr);
    assert_eq!(node.pending_tree_announce_deadline_ms(), Some(last + 500));
    assert_eq!(
        node.peers.get(&addr).unwrap().last_tree_announce_sent_ms(),
        last
    );
}

#[test]
fn both_parent_removal_paths_arm_remaining_peer_deadlines() {
    for degrade in [false, true] {
        let last = Node::now_ms();
        let mut nodes = vec![
            Node::new(Config::new()).unwrap(),
            Node::new(Config::new()).unwrap(),
        ];
        nodes.sort_by_key(|node| *node.node_addr());
        let mut node = nodes.pop().unwrap();
        let root = nodes.pop().unwrap();
        let parent = *root.node_addr();
        let mut active = ActivePeer::new(
            PeerIdentity::from_pubkey(root.identity.pubkey()),
            LinkId::new(1),
            last,
        );
        active.set_last_tree_announce_sent_ms(last);
        node.peers.insert(parent, active);
        node.tree_state.update_peer(
            crate::tree::ParentDeclaration::self_root(parent, 1, 1),
            crate::tree::TreeCoordinate::from_addrs(vec![parent]).unwrap(),
        );
        let identity = Identity::generate();
        let peer = PeerIdentity::from_pubkey(identity.pubkey());
        let retained = *peer.node_addr();
        let mut active = ActivePeer::new(peer, LinkId::new(2), last);
        active.set_last_tree_announce_sent_ms(last);
        node.peers.insert(retained, active);
        node.tree_state.set_parent(parent, 1, 1);
        node.tree_state.recompute_coords();
        assert!(!node.tree_state.is_root());
        assert_eq!(node.pending_tree_announce_deadline_ms(), None);
        if degrade {
            node.remove_link_dead_peer(&parent);
        } else {
            node.remove_active_peer(&parent);
        }
        assert!(node.tree_state.is_root());
        assert_eq!(node.pending_tree_announce_deadline_ms(), Some(last + 500));
        assert!(
            node.peers
                .get(&retained)
                .unwrap()
                .has_pending_tree_announce()
        );
        assert_eq!(node.peers.get(&parent).is_some(), degrade);
    }
}
