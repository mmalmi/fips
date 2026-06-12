//! Tests for the consecutive-decrypt-failure recovery path.
//!
//! Covers `Node::handle_decrypt_failure` (in `node/handlers/encrypted.rs`),
//! which increments `ActivePeer::increment_decrypt_failures` on each AEAD
//! verification failure and starts a link-session recovery rekey once
//! `DECRYPT_FAILURE_THRESHOLD` consecutive failures are observed. Peer
//! eviction is reserved for cases where recovery cannot be started.

use super::*;
use crate::node::decrypt_worker::DecryptFailureReport;
use std::time::{Duration, Instant};

async fn make_started_udp_transport(id: u32) -> TransportHandle {
    let (packet_tx, _packet_rx) = packet_channel(64);
    let transport_id = TransportId::new(id);
    let mut udp = UdpTransport::new(
        transport_id,
        Some(format!("udp{}", id)),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    TransportHandle::Udp(udp)
}

/// Drive a fully-promoted peer to the decrypt-failure threshold with no usable
/// transport and verify the old force-removal fallback still cleans up both
/// active peer storage and session-index dispatch.
///
/// Setup uses the `make_completed_connection` harness so the peer has a
/// real `our_index`/`transport_id`, ensuring `remove_active_peer` exercises
/// the full active peer registry cleanup path.
#[tokio::test]
async fn test_decrypt_failure_threshold_removes_peer_when_recovery_unavailable() {
    // Threshold constant in node/handlers/encrypted.rs (kept in sync with
    // production code; see DECRYPT_FAILURE_THRESHOLD).
    const THRESHOLD: u32 = 4;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    // Build a fully-promoted active peer with our_index/transport_id set
    // so session-index dispatch is populated by promote_connection.
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2_000).unwrap();

    // Sanity: peer is registered and indexed.
    assert_eq!(node.peer_count(), 1, "peer should be present after promote");
    let our_index = node
        .get_peer(&node_addr)
        .and_then(|p| p.our_index())
        .expect("promoted peer must have our_index");
    assert_eq!(
        node.peers
            .get_session_index(&(transport_id, our_index.as_u32())),
        Some(&node_addr),
        "active peer registry session-index dispatch must be populated after promote"
    );
    assert_eq!(
        node.get_peer(&node_addr)
            .unwrap()
            .consecutive_decrypt_failures(),
        0,
        "fresh peer's failure counter must start at zero"
    );

    // Drive failures up to (but not including) the threshold; peer must
    // remain present and the counter must increase monotonically.
    for expected in 1..THRESHOLD {
        node.handle_decrypt_failure(&node_addr).await;
        let count = node
            .get_peer(&node_addr)
            .expect("peer must still be present below threshold")
            .consecutive_decrypt_failures();
        assert_eq!(
            count, expected,
            "counter should track failures pre-threshold"
        );
    }
    assert_eq!(
        node.peer_count(),
        1,
        "peer must remain registered until threshold is reached"
    );

    // The Nth failure crosses the threshold. Recovery cannot start because
    // the peer's transport handle is absent, so we fall back to eviction.
    node.handle_decrypt_failure(&node_addr).await;

    assert!(
        node.get_peer(&node_addr).is_none(),
        "peer must be removed from peers table at threshold"
    );
    assert_eq!(
        node.peer_count(),
        0,
        "peer_count must be zero after eviction"
    );
    assert!(
        !node
            .peers
            .contains_session_index(&(transport_id, our_index.as_u32())),
        "active peer registry session-index entry must be cleaned up at threshold"
    );
}

/// With a usable transport, the threshold should start an in-place FMP rekey
/// and keep the existing peer/session alive instead of dropping the link.
#[tokio::test]
async fn test_decrypt_failure_threshold_starts_recovery_rekey_when_transport_available() {
    const THRESHOLD: u32 = 4;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    node.transports
        .insert(transport_id, make_started_udp_transport(1).await);

    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2_000).unwrap();

    for expected in 1..THRESHOLD {
        node.handle_decrypt_failure(&node_addr).await;
        let count = node
            .get_peer(&node_addr)
            .expect("peer must still be present below threshold")
            .consecutive_decrypt_failures();
        assert_eq!(count, expected);
    }

    node.handle_decrypt_failure(&node_addr).await;

    let peer = node
        .get_peer(&node_addr)
        .expect("recovery rekey should keep peer alive");
    assert!(
        peer.rekey_in_progress(),
        "threshold should start an in-place recovery rekey"
    );
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        0,
        "starting recovery should reset the local failure streak"
    );
    let rekey_index = peer
        .rekey_our_index()
        .expect("recovery rekey must allocate a new local index");
    assert!(
        node.pending_outbound
            .contains_key(&(transport_id, rekey_index.as_u32())),
        "rekey msg2 dispatch must be registered"
    );
    assert!(
        node.retry_pending.is_empty(),
        "recovery rekey should not schedule a reconnect retry"
    );

    let mut transport = node.transports.remove(&transport_id).unwrap();
    transport.stop().await.unwrap();
}

#[tokio::test]
async fn test_worker_decrypt_failures_suppressed_during_fresh_session_drain() {
    const THRESHOLD: u32 = 4;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    node.transports
        .insert(transport_id, make_started_udp_transport(1).await);

    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2_000).unwrap();

    for counter in 1..=THRESHOLD + 5 {
        node.handle_decrypt_failure_report(&DecryptFailureReport {
            source_peer: identity,
            fmp_counter: counter as u64,
            fmp_replay_highest: 0,
            trace_enqueued_at: None,
        })
        .await;
    }

    let peer = node
        .get_peer(&node_addr)
        .expect("fresh-session stale packet drain must not remove peer");
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        0,
        "fresh worker failures before any authenticated counter should be ignored"
    );
    assert!(
        !peer.rekey_in_progress(),
        "fresh stale packet drain must not start another recovery rekey"
    );

    let mut transport = node.transports.remove(&transport_id).unwrap();
    transport.stop().await.unwrap();
}

#[tokio::test]
async fn test_worker_decrypt_failures_suppressed_during_post_auth_fresh_session_drain() {
    const THRESHOLD: u32 = 4;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2_000).unwrap();

    for counter in 1..=THRESHOLD {
        node.handle_decrypt_failure_report(&DecryptFailureReport {
            source_peer: identity,
            fmp_counter: counter as u64,
            fmp_replay_highest: 1,
            trace_enqueued_at: None,
        })
        .await;
    }

    let peer = node
        .get_peer(&node_addr)
        .expect("post-auth stale packet drain must not remove peer");
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        0,
        "fresh worker failures after an authenticated counter should still be ignored briefly"
    );
}

#[tokio::test]
async fn test_worker_decrypt_failures_count_after_post_auth_grace() {
    const THRESHOLD: u32 = 4;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2_000).unwrap();
    node.get_peer_mut(&node_addr)
        .expect("promoted peer")
        .set_session_established_at_for_test(Instant::now() - Duration::from_secs(11));

    for counter in 1..=THRESHOLD {
        node.handle_decrypt_failure_report(&DecryptFailureReport {
            source_peer: identity,
            fmp_counter: counter as u64,
            fmp_replay_highest: 1,
            trace_enqueued_at: None,
        })
        .await;
    }

    assert!(
        node.get_peer(&node_addr).is_none(),
        "worker failures must trigger recovery/removal after the post-auth stale drain grace"
    );
}

#[tokio::test]
async fn test_worker_decrypt_failures_count_after_fresh_session_grace() {
    const THRESHOLD: u32 = 4;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2_000).unwrap();
    node.get_peer_mut(&node_addr)
        .expect("promoted peer")
        .set_session_established_at_for_test(Instant::now() - Duration::from_secs(31));

    for counter in 1..=THRESHOLD {
        node.handle_decrypt_failure_report(&DecryptFailureReport {
            source_peer: identity,
            fmp_counter: counter as u64,
            fmp_replay_highest: 0,
            trace_enqueued_at: None,
        })
        .await;
    }

    assert!(
        node.get_peer(&node_addr).is_none(),
        "fresh-session grace must be bounded so true key mismatch still recovers"
    );
}
