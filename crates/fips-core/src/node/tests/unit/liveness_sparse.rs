use super::*;
use crate::mmp::MmpMode;

fn fixture(mode: MmpMode, with_fallback: bool) -> (Node, NodeAddr, Option<NodeAddr>) {
    let remote = Identity::generate();
    let dest = *remote.node_addr();
    let mut config = Config::new();
    config.node.routing.mode = crate::config::RoutingMode::ReplyLearned;
    config.node.session_mmp.mode = mode;
    config
        .peers
        .push(auto_connect_peer(remote.npub(), "203.0.113.9:2121"));
    let mut node = Node::new(config).unwrap();
    let active = make_active_test_peer(
        &node,
        &remote,
        TransportId::new(1),
        LinkId::new(7),
        TransportAddr::from_string("203.0.113.9:2121"),
        SessionIndex::new(11),
        SessionIndex::new(12),
    );
    node.peers.insert(dest, active);
    seed_dataplane_fmp_rx_for_test(&mut node, dest, Duration::ZERO);
    let session = make_test_fmp_session(node.identity(), &remote, [3; 8], [4; 8]);
    node.sessions.insert(
        dest,
        crate::node::session::SessionEntry::new(
            dest,
            remote.pubkey_full(),
            crate::node::session::EndToEndState::Established(session),
            1_000,
            true,
        ),
    );
    ensure_dataplane_fsp_owner_for_test(&mut node, dest);
    let fallback = with_fallback.then(|| {
        let peer = make_peer_identity();
        let addr = *peer.node_addr();
        node.peers
            .insert(addr, ActivePeer::new(peer, LinkId::new(9), Node::now_ms()));
        node.learn_reverse_route(dest, addr);
        addr
    });
    (node, dest, fallback)
}

#[tokio::test]
async fn one_unanswered_request_uses_fallback_despite_fresh_control() {
    let (mut node, dest, fallback) = fixture(MmpMode::Full, true);
    let now = Node::now_ms();
    let sent = now - node.session_direct_path_exclusive_trust_timeout_ms() - 1_000;
    seed_dataplane_fsp_data_sent_for_test(&mut node, dest, dest, sent);
    seed_dataplane_fsp_control_rx_for_test(&mut node, dest, dest, now);

    node.check_link_heartbeats().await;

    assert!(node.get_peer(&dest).unwrap().is_healthy());
    assert!(node.sessions.get(&dest).unwrap().is_established());
    assert!(node.session_direct_path_degradation_active(&dest, Node::now_ms()));
    assert!(node.retry_pending.contains_key(&dest));
    assert_eq!(
        node.find_next_hop(&dest).map(|peer| *peer.node_addr()),
        fallback,
        "a quiet sender must be able to use a known alternate after its one request times out"
    );
    assert_eq!(
        node.dataplane
            .fsp_owner_activity(&dest)
            .unwrap()
            .traffic_counters()
            .0,
        1,
        "fallback must not require a second application send"
    );
}

#[test]
fn sparse_direct_feedback_preserves_deadline_mode_and_carrier_guards() {
    for mode in [MmpMode::Full, MmpMode::Minimal] {
        let (mut node, dest, fallback) = fixture(mode, true);
        let sent = Node::now_ms();
        let deadline = sent + node.session_direct_path_exclusive_trust_timeout_ms();
        assert!(!node.session_direct_path_exclusive_trust_expired(&dest, deadline + 1));
        seed_dataplane_fsp_data_sent_for_test(&mut node, dest, dest, sent);
        if mode == MmpMode::Full {
            assert!(!node.session_direct_path_exclusive_trust_expired(&dest, deadline));
        }
        assert_eq!(
            node.session_direct_path_exclusive_trust_expired(&dest, deadline + 1),
            mode == MmpMode::Full,
            "only report-enabled sessions can treat an aged unanswered request as failed"
        );
        seed_dataplane_fsp_data_sent_for_test(&mut node, dest, fallback.unwrap(), sent);
        assert!(
            !node.session_direct_path_exclusive_trust_expired(&dest, deadline + 1),
            "an unanswered alternate-path request must not be attributed to the direct carrier"
        );
    }
}

#[tokio::test]
async fn sparse_direct_failure_without_an_alternate_keeps_the_peer_usable() {
    let (mut node, dest, _) = fixture(MmpMode::Full, false);
    let now = Node::now_ms();
    let sent = now - node.session_direct_path_exclusive_trust_timeout_ms() - 1_000;
    seed_dataplane_fsp_data_sent_for_test(&mut node, dest, dest, sent);
    seed_dataplane_fsp_control_rx_for_test(&mut node, dest, dest, now);

    node.check_link_heartbeats().await;

    assert!(node.get_peer(&dest).unwrap().is_healthy());
    assert!(!node.session_direct_path_degradation_active(&dest, Node::now_ms()));
    assert!(!node.pending_lookups.contains_key(&dest));
    assert_eq!(
        node.find_next_hop(&dest).map(|peer| *peer.node_addr()),
        Some(dest)
    );
}
