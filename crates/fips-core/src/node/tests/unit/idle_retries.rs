use super::*;

#[tokio::test]
async fn outbound_handshake_local_send_failure_keeps_retry_budget_and_backoff() {
    let mut node = make_node();
    node.config.node.rate_limit.handshake_resend_interval_ms = 1_000;
    node.config.node.rate_limit.handshake_resend_backoff = 2.0;
    node.config.node.rate_limit.handshake_max_resends = 2;
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote = TransportAddr::from_string(&receiver.local_addr().unwrap().to_string());
    let transport_id = TransportId::new(1);
    let transport = make_udp_transport_with_mtu(1, 1_400).await;
    let TransportHandle::Udp(udp) = &transport else {
        unreachable!()
    };
    let stats = udp.stats().clone();
    node.transports.insert(transport_id, transport);
    let peer = Identity::generate();
    node.initiate_connection(
        transport_id,
        remote,
        PeerIdentity::from_pubkey_full(peer.pubkey_full()),
    )
    .await
    .unwrap();
    let link = *node.peers.connection_keys().next().unwrap();
    let initial = node.peers.get_connection(&link).unwrap();
    let sender_index = initial.our_index();
    let first_due = initial.next_resend_at_ms();
    assert_eq!(stats.snapshot().packets_sent, 1);

    // A local carrier failure must not turn the maintenance loop into a send loop.
    node.transports
        .get_mut(&transport_id)
        .unwrap()
        .stop()
        .await
        .unwrap();
    node.resend_pending_handshakes(first_due).await;
    let failed = node.peers.get_connection(&link).unwrap();
    assert_eq!(failed.resend_count(), 1);
    assert_eq!(failed.next_resend_at_ms(), first_due + 2_000);
    assert_eq!(failed.our_index(), sender_index);

    // Restore the same carrier and exercise recovery at the original deadline.
    let TransportHandle::Udp(udp) = node.transports.get_mut(&transport_id).unwrap() else {
        unreachable!()
    };
    udp.start_async().await.unwrap();
    node.resend_pending_handshakes(first_due + 1_999).await;
    assert_eq!(stats.snapshot().packets_sent, 1);
    node.resend_pending_handshakes(first_due + 2_000).await;
    assert_eq!(stats.snapshot().packets_sent, 2);
    let recovered = node.peers.get_connection(&link).unwrap();
    assert_eq!(recovered.resend_count(), 2);
    assert_eq!(recovered.our_index(), sender_index);
    node.resend_pending_handshakes(first_due + 100_000).await;
    assert_eq!(
        stats.snapshot().packets_sent,
        2,
        "exhausted retries stay bounded"
    );
    node.transports
        .get_mut(&transport_id)
        .unwrap()
        .stop()
        .await
        .unwrap();
}

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
