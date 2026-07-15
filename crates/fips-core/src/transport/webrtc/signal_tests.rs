use super::*;
use crate::packet_channel;

pub(super) fn incoming_offer(identity: &crate::Identity, session_id: &str) -> IncomingSignal {
    let sender_full = identity.pubkey_full();
    let (sender_xonly, _) = sender_full.x_only_public_key();
    let now = now_ms();
    IncomingSignal {
        signal: WebRtcSignal {
            version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
            negotiation_id: session_id.into(),
            link_type: "webrtc".into(),
            kind: LinkNegotiationKind::Offer,
            created_at_ms: now,
            expires_at_ms: now + SIGNAL_TTL_MS,
            payload: WebRtcSignalPayload {
                sdp: Some("invalid but bounded SDP".into()),
                candidates: None,
            },
        },
        sender: PublicKey::from_slice(&sender_xonly.serialize()).expect("Nostr public key"),
        sender_full_hex: hex::encode(sender_full.serialize()),
    }
}

#[test]
fn inverted_signal_lifetime_is_rejected() {
    let identity = crate::Identity::generate();
    let remote = crate::Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(85),
        None,
        WebRtcConfig::default(),
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let mut incoming = incoming_offer(&remote, "inverted-lifetime");
    let now = now_ms();
    incoming.signal.created_at_ms = now + 1_000;
    incoming.signal.expires_at_ms = now + 500;

    assert!(matches!(
        transport.runtime().validate_signal(&incoming.signal),
        Err(TransportError::Timeout)
    ));
}

#[tokio::test]
async fn answer_without_a_pending_or_pooled_session_is_explicitly_rejected() {
    let identity = crate::Identity::generate();
    let remote = crate::Identity::generate();
    let remote_full = hex::encode(remote.pubkey_full().serialize());
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(86),
        None,
        WebRtcConfig::default(),
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let now = now_ms();
    let answer = WebRtcSignal {
        version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
        negotiation_id: "late-answer".into(),
        link_type: "webrtc".into(),
        kind: LinkNegotiationKind::Answer,
        created_at_ms: now,
        expires_at_ms: now + SIGNAL_TTL_MS,
        payload: WebRtcSignalPayload {
            sdp: Some("v=0\r\na=candidate:1 1 UDP 1 127.0.0.1 5000 typ host\r\n".into()),
            candidates: None,
        },
    };

    assert!(
        transport
            .runtime()
            .handle_answer(answer, &remote_full)
            .await
            .is_err(),
        "a late or unknown answer must not be silently accepted"
    );
    assert_eq!(
        transport.negotiation.snapshot().answers_without_session,
        1
    );
}

#[tokio::test]
async fn mismatched_answer_does_not_remove_the_newer_pending_session() {
    let identity = crate::Identity::generate();
    let remote = crate::Identity::generate();
    let remote_full = hex::encode(remote.pubkey_full().serialize());
    let addr = TransportAddr::from_string(&remote_full);
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(89),
        None,
        WebRtcConfig::default(),
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let pc = transport
        .physical
        .reserve(&addr)
        .expect("physical permit")
        .activate(
            transport
                .api
                .new_peer_connection(RTCConfiguration::default())
                .await
                .expect("peer connection"),
        );
    transport.pending.lock().await.insert(
        addr.clone(),
        PendingDial {
            session_id: "new-session".into(),
            phase_owner_id: "new-session".into(),
            pc,
            created_at_ms: now_ms(),
            origin: PendingDialOrigin::Local,
            deadline: tokio::time::Instant::now() + Duration::from_secs(2),
        },
    );
    let now = now_ms();
    let stale = WebRtcSignal {
        version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
        negotiation_id: "old-session".into(),
        link_type: "webrtc".into(),
        kind: LinkNegotiationKind::Answer,
        created_at_ms: now,
        expires_at_ms: now + SIGNAL_TTL_MS,
        payload: WebRtcSignalPayload {
            sdp: Some("v=0\r\na=candidate:1 1 UDP 1 127.0.0.1 5000 typ host\r\n".into()),
            candidates: None,
        },
    };

    assert!(
        transport
            .runtime()
            .handle_answer(stale, &remote_full)
            .await
            .is_err()
    );
    assert_eq!(
        transport
            .pending
            .lock()
            .await
            .get(&addr)
            .map(|pending| pending.session_id.as_str()),
        Some("new-session")
    );
    transport.close_connection_async(&addr).await;
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
}

#[tokio::test]
async fn duplicate_answer_for_the_pooled_session_is_a_benign_replay() {
    let identity = crate::Identity::generate();
    let remote = crate::Identity::generate();
    let remote_full = hex::encode(remote.pubkey_full().serialize());
    let addr = TransportAddr::from_string(&remote_full);
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(90),
        None,
        WebRtcConfig::default(),
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let pc = transport
        .physical
        .reserve(&addr)
        .expect("physical permit")
        .activate(
            transport
                .api
                .new_peer_connection(RTCConfiguration::default())
                .await
                .expect("peer connection"),
        );
    let data_channel = pc
        .create_data_channel("pooled-replay", None)
        .await
        .expect("data channel");
    transport.pool.lock().await.insert(
        addr.clone(),
        WebRtcConnection {
            session_id: "pooled-session".into(),
            pc,
            data_channel,
        },
    );
    let now = now_ms();
    let replay = WebRtcSignal {
        version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
        negotiation_id: "pooled-session".into(),
        link_type: "webrtc".into(),
        kind: LinkNegotiationKind::Answer,
        created_at_ms: now,
        expires_at_ms: now + SIGNAL_TTL_MS,
        payload: WebRtcSignalPayload {
            sdp: Some("v=0\r\na=candidate:1 1 UDP 1 127.0.0.1 5000 typ host\r\n".into()),
            candidates: None,
        },
    };

    transport
        .runtime()
        .handle_answer(replay, &remote_full)
        .await
        .expect("pooled Answer replay");
    assert!(transport.pool.lock().await.contains_key(&addr));
    transport.close_connection_async(&addr).await;
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
}

#[tokio::test]
async fn expired_handler_cleanup_cannot_remove_a_newer_pending_generation() {
    let identity = crate::Identity::generate();
    let remote = crate::Identity::generate();
    let remote_full = hex::encode(remote.pubkey_full().serialize());
    let addr = TransportAddr::from_string(&remote_full);
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(94),
        None,
        WebRtcConfig::default(),
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let pc = transport
        .physical
        .reserve(&addr)
        .expect("physical permit")
        .activate(
            transport
                .api
                .new_peer_connection(RTCConfiguration::default())
                .await
                .expect("peer connection"),
        );
    let deadline = tokio::time::Instant::now() - Duration::from_millis(1);
    transport.pending.lock().await.insert(
        addr.clone(),
        PendingDial {
            session_id: "new-session".into(),
            phase_owner_id: "new-owner".into(),
            pc,
            created_at_ms: now_ms(),
            origin: PendingDialOrigin::Remote,
            deadline,
        },
    );
    let runtime = transport.runtime();

    runtime
        .mark_expired_pending_failed(
            addr.clone(),
            "old-owner",
            deadline,
            "old handler timed out".into(),
        )
        .await;
    assert_eq!(
        transport
            .pending
            .lock()
            .await
            .get(&addr)
            .map(|pending| pending.phase_owner_id.as_str()),
        Some("new-owner")
    );

    runtime
        .mark_expired_pending_failed(
            addr.clone(),
            "new-owner",
            deadline,
            "owning handler timed out".into(),
        )
        .await;
    assert!(!transport.pending.lock().await.contains_key(&addr));
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
}

#[tokio::test]
async fn cleanup_winning_during_gather_prevents_a_stale_signal_queue() {
    let identity = crate::Identity::generate();
    let remote = crate::Identity::generate();
    let remote_full = remote.pubkey_full();
    let remote_addr = TransportAddr::from_string(&hex::encode(remote_full.serialize()));
    let (remote_xonly, _) = remote_full.x_only_public_key();
    let recipient = PublicKey::from_slice(&remote_xonly.serialize()).expect("Nostr key");
    let (packet_tx, _packet_rx) = packet_channel(1);
    let mut transport = WebRtcTransport::new(
        TransportId::new(95),
        None,
        WebRtcConfig::default(),
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let pc = transport
        .physical
        .reserve(&remote_addr)
        .expect("physical permit")
        .activate(
            transport
                .api
                .new_peer_connection(RTCConfiguration::default())
                .await
                .expect("peer connection"),
        );
    transport.pending.lock().await.insert(
        remote_addr.clone(),
        PendingDial {
            session_id: "stale-session".into(),
            phase_owner_id: "stale-session".into(),
            pc: Arc::clone(&pc),
            created_at_ms: now_ms(),
            origin: PendingDialOrigin::Local,
            deadline: tokio::time::Instant::now() + Duration::from_secs(2),
        },
    );
    let owners = WebRtcSessionOwners::from_refs(
        &transport.pool,
        &transport.pending,
        &transport.failed,
        &transport.ready,
    );
    let expected_owner = WebRtcSessionOwner::new("stale-session", &pc);
    assert!(
        cleanup_webrtc_session(
            &owners,
            &remote_addr,
            Some(&expected_owner),
            None,
            CleanupWait::Started,
        )
        .await
    );
    let now = now_ms();
    let stale = WebRtcSignal {
        version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
        negotiation_id: "stale-session".into(),
        link_type: "webrtc".into(),
        kind: LinkNegotiationKind::Offer,
        created_at_ms: now,
        expires_at_ms: now + 1_000,
        payload: WebRtcSignalPayload {
            sdp: Some("v=0\r\na=candidate:1 1 UDP 1 127.0.0.1 5000 typ host\r\n".into()),
            candidates: None,
        },
    };
    assert!(
        transport
            .runtime()
            .queue_signal_for_pending(
                &remote_addr,
                "stale-session",
                &pc,
                recipient,
                &stale,
            )
            .await
            .is_err()
    );
    assert!(transport.drain_link_negotiations(1).is_empty());
    drop(pc);
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
}

#[tokio::test]
async fn pending_lock_contention_cannot_queue_a_signal_after_its_deadline() {
    let identity = crate::Identity::generate();
    let remote = crate::Identity::generate();
    let remote_full = remote.pubkey_full();
    let remote_addr = TransportAddr::from_string(&hex::encode(remote_full.serialize()));
    let (remote_xonly, _) = remote_full.x_only_public_key();
    let recipient = PublicKey::from_slice(&remote_xonly.serialize()).expect("Nostr key");
    let (packet_tx, _packet_rx) = packet_channel(1);
    let mut transport = WebRtcTransport::new(
        TransportId::new(99),
        None,
        WebRtcConfig::default(),
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let pc = transport
        .physical
        .reserve(&remote_addr)
        .expect("physical permit")
        .activate(
            transport
                .api
                .new_peer_connection(RTCConfiguration::default())
                .await
                .expect("peer connection"),
        );
    let deadline = tokio::time::Instant::now() + Duration::from_millis(30);
    transport.pending.lock().await.insert(
        remote_addr.clone(),
        PendingDial {
            session_id: "lock-deadline".into(),
            phase_owner_id: "lock-deadline".into(),
            pc: Arc::clone(&pc),
            created_at_ms: now_ms(),
            origin: PendingDialOrigin::Local,
            deadline,
        },
    );
    let wall_now = now_ms();
    let signal = WebRtcSignal {
        version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
        negotiation_id: "lock-deadline".into(),
        link_type: "webrtc".into(),
        kind: LinkNegotiationKind::Offer,
        created_at_ms: wall_now,
        expires_at_ms: wall_now + 1_000,
        payload: WebRtcSignalPayload {
            sdp: Some("v=0\r\na=candidate:1 1 UDP 1 127.0.0.1 5000 typ host\r\n".into()),
            candidates: None,
        },
    };
    let pending_guard = transport.pending.lock().await;
    let queue = {
        let runtime = transport.runtime();
        let addr = remote_addr.clone();
        let pc = Arc::clone(&pc);
        tokio::spawn(async move {
            runtime
                .queue_signal_for_pending(&addr, "lock-deadline", &pc, recipient, &signal)
                .await
        })
    };
    tokio::time::sleep_until(deadline + Duration::from_millis(10)).await;
    drop(pending_guard);
    assert!(matches!(
        queue.await.expect("queue task"),
        Err(TransportError::Timeout)
    ));
    assert!(transport.drain_link_negotiations(1).is_empty());
    transport.close_connection_async(&remote_addr).await;
    drop(pc);
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
}

#[tokio::test]
async fn handler_capacity_backpressures_without_dropping_the_next_offer() {
    let identity = crate::Identity::generate();
    let remote_a = crate::Identity::generate();
    let remote_b = crate::Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let mut transport = WebRtcTransport::new(
        TransportId::new(81),
        None,
        WebRtcConfig {
            accept_connections: Some(true),
            max_connections: Some(1),
            resolve_mdns_candidates: Some(false),
            stun_servers: Some(Vec::new()),
            ..WebRtcConfig::default()
        },
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    transport.start_async().await.expect("start transport");

    let seen_sessions = Arc::clone(&transport.seen_sessions);
    let seen_guard = seen_sessions.lock().await;
    transport
        .signal_tx
        .send(incoming_offer(&remote_a, "first-offer"))
        .expect("queue first offer");
    // Give the dispatcher a turn to consume the first offer. Its handler then
    // blocks deterministically on the held seen-session lock.
    tokio::time::sleep(Duration::from_millis(25)).await;
    transport
        .signal_tx
        .send(incoming_offer(&remote_b, "second-offer"))
        .expect("queue second offer");
    tokio::task::yield_now().await;
    drop(seen_guard);

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if seen_sessions.lock().await.len() == 2 {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both queued offers reach the bounded handler");
    transport.stop_async().await.expect("stop transport");
}
