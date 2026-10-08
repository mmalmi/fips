use super::*;

#[test]
fn idle_retry_sweeps_preserve_pending_state_and_queue_only_active_candidates() {
    let configs = (0..128)
        .map(|_| crate::config::PeerConfig {
            npub: Identity::generate().npub(),
            alias: None,
            addresses: (0..16)
                .map(|priority| crate::config::PeerAddress::with_priority("udp", "nat", priority))
                .collect(),
            connect_policy: crate::config::ConnectPolicy::AutoConnect,
            auto_reconnect: true,
            discovery_fallback_transit: true,
        })
        .collect::<Vec<_>>();
    let mut config = Config::new();
    config.peers = configs.clone();
    let mut node = Node::new(config).unwrap();
    let active = configs[..3]
        .iter()
        .map(|config| PeerIdentity::from_npub(&config.npub).unwrap())
        .collect::<Vec<_>>();
    for (index, peer) in active.iter().enumerate() {
        let mut entry = ActivePeer::new(*peer, LinkId::new(index as u64 + 1), 0);
        entry.mark_stale();
        node.peers.insert(*peer.node_addr(), entry);
    }
    let pending_addr = *active[0].node_addr();
    let mut pending = crate::node::retry::RetryState::new(configs[0].clone());
    pending.retry_count = 4;
    pending.retry_after_ms = u64::MAX;
    node.retry_pending.insert(pending_addr, pending);

    for _ in 0..16 {
        node.queue_active_fallback_direct_retries();
        assert_eq!(node.retry_pending.len(), 3);
        let preserved = node.retry_pending.get(&pending_addr).unwrap();
        assert_eq!(preserved.retry_count, 4);
        assert_eq!(preserved.retry_after_ms, u64::MAX);
        for (peer, config) in active[1..].iter().zip(&configs[1..3]) {
            let state = node.retry_pending.get(peer.node_addr()).unwrap();
            assert!(state.reconnect);
            assert_eq!(state.retry_count, 0);
            assert_eq!(state.peer_config.addresses, config.addresses);
        }
    }
}
