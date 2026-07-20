async fn process_dataplane_control_packet_for_test(node: &mut Node, packet: ReceivedPacket) {
    let (packet_tx, mut packet_rx) = packet_channel(1);
    packet_tx.send(packet).expect("packet should enqueue");
    let (_endpoint_tx, mut endpoint_rx) = crate::node::endpoint_data_batch_channel(1);
    let (_tun_outbound_tx, mut tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
    let (_fast_tx, mut fast_ingress_rx) = tokio::sync::mpsc::channel(1);
    let (endpoint_tx, _endpoint_rx) = crate::node::EndpointEventSender::channel(1);

    let mut turn = {
        let mut dataplane_io = crate::node::handlers::rx_loop_dataplane_io(
            &mut packet_rx,
            &mut fast_ingress_rx,
            &mut endpoint_rx,
            &mut tun_outbound_rx,
            &endpoint_tx,
        );
        node.drain_dataplane_turn_with_firsts(
            &mut dataplane_io,
            crate::dataplane::DataplaneLiveTurnFirsts::default(),
            crate::node::handlers::RxLoopDataplaneTurnLimits::new(1, 0, 0, 1),
        )
        .await
    };
    node.process_dataplane_control_ingress(&mut turn).await;
}

#[tokio::test]
async fn test_process_pending_retries_drops_expired_entries() {
    let mut node = make_node();
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut state = super::super::retry::RetryState::new(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "127.0.0.1:9",
    ));
    state.retry_after_ms = 0;
    state.expires_at_ms = Some(1_000);
    state.reconnect = true;
    node.retry_pending.insert(peer_node_addr, state);

    node.process_pending_retries(1_000).await;

    assert!(
        !node.retry_pending.contains_key(&peer_node_addr),
        "expired retry entries should be dropped before retry processing"
    );
}

/// Test that schedule_reconnect preserves accumulated backoff across link-dead cycles.
///
/// Regression test for issue #5: previously `schedule_reconnect` always created a
/// fresh `RetryState` with `retry_count=0`, discarding any backoff accumulated by
/// prior failed handshake attempts. On repeated link-dead evictions the node would
/// restart exponential backoff from the base interval every time instead of
/// continuing to back off.
#[test]
fn test_schedule_reconnect_preserves_backoff() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    // Simulate two stale handshake timeouts incrementing the retry count.
    node.schedule_retry(peer_node_addr, 1_000); // count=1, delay=10s
    node.schedule_retry(peer_node_addr, 11_000); // count=2, delay=20s
    {
        let state = node.retry_pending.get(&peer_node_addr).unwrap();
        assert_eq!(state.retry_count, 2, "Two failures should yield count=2");
    }

    // Now simulate a link-dead removal triggering schedule_reconnect.
    // The existing retry entry (count=2) should be preserved and bumped to 3,
    // NOT reset to 0 as it was before the fix.
    node.schedule_reconnect(peer_node_addr, 31_000);

    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert!(state.reconnect, "Entry should be marked as reconnect");
    assert_eq!(
        state.retry_count, 3,
        "schedule_reconnect should increment existing count (was 2), not reset to 0 (regression: issue #5)"
    );

    // With count=3, backoff should be 5s * 2^3 = 40s.
    let base_ms = node.config.node.retry.base_interval_secs * 1000;
    let max_ms = node.config.node.retry.max_backoff_secs * 1000;
    let expected_delay = state.backoff_ms(base_ms, max_ms);
    assert_eq!(
        state.retry_after_ms,
        31_000 + expected_delay,
        "retry_after_ms should reflect count=3 backoff"
    );
}

/// Test that schedule_reconnect on a fresh peer (no prior retry entry) starts at count=0.
#[test]
fn test_schedule_reconnect_fresh_state() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    // No prior retry entry — first reconnect should use base delay.
    node.schedule_reconnect(peer_node_addr, 1_000);

    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert!(state.reconnect, "Entry should be marked as reconnect");
    assert_eq!(
        state.retry_count, 0,
        "Fresh reconnect should start at count=0"
    );
    // Base delay: 5s * 2^0 = 5s
    let base_ms = node.config.node.retry.base_interval_secs * 1000;
    let max_ms = node.config.node.retry.max_backoff_secs * 1000;
    let expected_delay = state.backoff_ms(base_ms, max_ms);
    assert_eq!(state.retry_after_ms, 1_000 + expected_delay);
}

#[test]
fn test_schedule_link_dead_reprobe_resets_backoff() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();
    node.schedule_retry(peer_node_addr, 1_000);
    node.schedule_retry(peer_node_addr, 11_000);
    assert_eq!(
        node.retry_pending.get(&peer_node_addr).unwrap().retry_count,
        2
    );

    node.schedule_link_dead_reprobe(peer_node_addr, 31_000);

    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert!(state.reconnect);
    assert_eq!(
        state.retry_count, 0,
        "link-dead direct paths should not preserve peer-level exponential backoff"
    );
    assert!(
        (31_500..=32_500).contains(&state.retry_after_ms),
        "link-dead should schedule a quick jittered direct re-probe, got {}",
        state.retry_after_ms
    );
}
