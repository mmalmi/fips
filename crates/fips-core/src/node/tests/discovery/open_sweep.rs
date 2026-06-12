// ============================================================================
// Open-Discovery Sweep — cache-injection unit test
// ============================================================================

/// Pin the iterate-filter-queue contract of `run_open_discovery_sweep`.
///
/// Builds a `Node` with `nostr.policy = Open` and an empty peer list,
/// then injects three cached adverts into a test `NostrDiscovery` and
/// asserts the sweep:
///   - queues a retry for an eligible (unknown, not-self) advert,
///   - skips the advert whose author is our own node identity, and
///   - skips the advert whose author is an already-connected peer.
///
/// Uses `NostrDiscovery::new_for_test()` and `insert_advert_for_test()`
/// (both `#[cfg(test)]`-gated test escape hatches in
/// `src/discovery/nostr/runtime.rs`) to populate the cache without
/// requiring live relay subscriptions.
#[tokio::test]
async fn test_open_discovery_sweep_queues_eligible_skips_filtered() {
    use crate::config::NostrDiscoveryPolicy;
    use crate::discovery::nostr::{NostrDiscovery, OverlayEndpointAdvert, OverlayTransportKind};
    use crate::peer::ActivePeer;
    use crate::transport::LinkId;
    use std::sync::Arc;

    // Build node with open-discovery enabled.
    let mut config = crate::Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::Open;
    let mut node = crate::Node::new(config).unwrap();

    // Identity of an already-connected peer; insert into node.peers
    // so the sweep's `self.peers.contains_key(&node_addr)` filter fires.
    let connected_identity = crate::Identity::generate();
    let connected_npub = crate::encode_npub(&connected_identity.pubkey());
    let connected_node_addr = *connected_identity.node_addr();
    let connected_peer_identity = crate::PeerIdentity::from_pubkey(connected_identity.pubkey());
    node.peers.insert(
        connected_node_addr,
        ActivePeer::new(connected_peer_identity, LinkId::new(1), 1_000),
    );

    // Eligible peer: fresh identity not in node.peers / retry_pending.
    let eligible_identity = crate::Identity::generate();
    let eligible_npub = crate::encode_npub(&eligible_identity.pubkey());
    let eligible_node_addr = *eligible_identity.node_addr();

    // Self filter: advert authored by node's own identity.
    let self_npub = crate::encode_npub(&node.identity().pubkey());
    let self_node_addr = *node.identity().node_addr();

    // Build a NostrDiscovery test instance and inject the three adverts.
    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let endpoint = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: "203.0.113.7:2121".to_string(),
    };
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for npub in [&eligible_npub, &connected_npub, &self_npub] {
        let advert =
            NostrDiscovery::cached_advert_for_test(npub.clone(), endpoint.clone(), now_secs);
        bootstrap.insert_advert_for_test(npub.clone(), advert).await;
    }

    // Run the sweep.
    node.run_open_discovery_sweep(&bootstrap, Some(3_600), "test")
        .await;

    // Eligible peer was queued.
    assert!(
        node.retry_pending.contains_key(&eligible_node_addr),
        "eligible advert should be queued for retry"
    );
    let queued = node.retry_pending.get(&eligible_node_addr).unwrap();
    assert_eq!(queued.peer_config.npub, eligible_npub);

    // Connected-peer skip filter held.
    assert!(
        !node.retry_pending.contains_key(&connected_node_addr),
        "advert for already-connected peer must not be queued"
    );

    // Self skip filter held.
    assert!(
        !node.retry_pending.contains_key(&self_node_addr),
        "advert authored by own node must not be queued"
    );

    // Exactly one queued entry from the three injected adverts.
    assert_eq!(node.retry_pending.len(), 1);
}

/// Pin the cold-start expedite path: when an open-discovery sweep sees a
/// fresh advert for a CONFIGURED peer whose retry is sitting on a future
/// exponential-backoff slot, the sweep must pull the retry forward to "now"
/// so the next `process_pending_retries` tick fires it immediately.
///
/// Without this expedite, a daemon restart with NAT'd peers wedges at the
/// 80s backoff slot — the initial `initiate_peer_connection` failed before
/// any overlay data arrived, the retry was scheduled at 5/10/20/40/80s, and
/// by the time the Nostr advert is cached we still wait for the backoff to
/// elapse instead of acting on the fresh data.
#[tokio::test]
async fn test_open_discovery_sweep_expedites_configured_peer_retry() {
    use crate::config::{ConnectPolicy, NostrDiscoveryPolicy, PeerAddress, PeerConfig};
    use crate::discovery::nostr::{NostrDiscovery, OverlayEndpointAdvert, OverlayTransportKind};
    use std::sync::Arc;

    // A configured peer whose advert will arrive after retry was scheduled.
    let configured_identity = crate::Identity::generate();
    let configured_npub = crate::encode_npub(&configured_identity.pubkey());
    let configured_node_addr = *configured_identity.node_addr();

    let mut config = crate::Config::new();
    config.node.discovery.nostr.enabled = true;
    config.node.discovery.nostr.policy = NostrDiscoveryPolicy::Open;
    config.peers.push(PeerConfig {
        npub: configured_npub.clone(),
        alias: Some("test-peer".to_string()),
        addresses: vec![PeerAddress::new("udp", "203.0.113.99:51820")],
        connect_policy: ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        discovery_fallback_transit: true,
    });
    let mut node = crate::Node::new(config).unwrap();

    // Simulate the "initial connection failed, retry scheduled 60s out"
    // state the cold-start path produces. We synthesize the retry entry
    // directly so the test doesn't depend on the failure path firing.
    let pc = node
        .config
        .peers()
        .iter()
        .find(|pc| pc.npub == configured_npub)
        .cloned()
        .unwrap();
    let now_ms = crate::Node::now_ms();
    let scheduled_at_ms = now_ms + 60_000;
    let mut state = crate::node::retry::RetryState::new(pc);
    state.retry_count = 3;
    state.retry_after_ms = scheduled_at_ms;
    node.retry_pending.insert(configured_node_addr, state);

    // Inject the fresh overlay advert into the bootstrap cache.
    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let endpoint = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: "203.0.113.7:2121".to_string(),
    };
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let advert =
        NostrDiscovery::cached_advert_for_test(configured_npub.clone(), endpoint, now_secs);
    bootstrap
        .insert_advert_for_test(configured_npub.clone(), advert)
        .await;

    // Run the sweep.
    node.run_open_discovery_sweep(&bootstrap, Some(3_600), "test")
        .await;

    // Retry was expedited: retry_after_ms pulled back from +60s to ≤ now.
    let state = node
        .retry_pending
        .get(&configured_node_addr)
        .expect("retry entry must still exist; sweep should expedite, not remove");
    assert!(
        state.retry_after_ms <= crate::Node::now_ms(),
        "expected retry_after_ms ≤ now (expedited); got {} (now ≈ {})",
        state.retry_after_ms,
        crate::Node::now_ms()
    );
    assert!(
        state.retry_after_ms < scheduled_at_ms,
        "expected retry_after_ms < original scheduled_at_ms; got {} >= {}",
        state.retry_after_ms,
        scheduled_at_ms
    );

    // The peer_config must still match — expedite is purely a timing change,
    // it must not mutate the configured peer's address list or alias.
    assert_eq!(state.peer_config.npub, configured_npub);
    assert_eq!(state.peer_config.alias.as_deref(), Some("test-peer"));
}

// ============================================================================
// Per-Attempt Timeout State Machine — IF-3-A
// ============================================================================
