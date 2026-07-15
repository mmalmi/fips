use super::*;
use crate::packet_channel;

#[tokio::test]
async fn incomplete_ice_gathering_is_not_treated_as_success() {
    let (sender, mut gathering) = mpsc::channel(1);
    let error = wait_for_ice_gathering(Duration::from_millis(5), &mut gathering)
        .await
        .expect_err("a held non-trickle gather must fail at its deadline");
    assert!(matches!(error, TransportError::StartFailed(_)));
    drop(sender);
}

#[test]
fn completed_non_trickle_sdp_requires_at_least_one_candidate() {
    assert!(require_non_trickle_ice_candidates("v=0\r\n").is_err());
    assert_eq!(
        require_non_trickle_ice_candidates(
            "v=0\r\na=candidate:1 1 UDP 1 127.0.0.1 5000 typ host\r\n"
        )
        .expect("candidate-bearing SDP"),
        1
    );
}

#[test]
fn stun_override_distinguishes_unset_from_explicit_empty() {
    let fallback = vec!["stun:fallback.invalid:3478".to_string()];
    assert_eq!(WebRtcConfig::default().stun_servers(&fallback), fallback);

    let disabled = WebRtcConfig {
        stun_servers: Some(Vec::new()),
        ..WebRtcConfig::default()
    };
    assert!(disabled.stun_servers(&fallback).is_empty());

    let explicit = WebRtcConfig {
        stun_servers: Some(vec!["stun:override.invalid:3478".to_string()]),
        ..WebRtcConfig::default()
    };
    assert_eq!(
        explicit.stun_servers(&fallback),
        vec!["stun:override.invalid:3478".to_string()]
    );
}

#[test]
fn offer_expiry_and_responder_deadline_preserve_the_original_phase_budget() {
    let monotonic_now = tokio::time::Instant::now();
    let expires_at_ms = signal_expiry_for_deadline(
        monotonic_now + Duration::from_millis(1_500),
        monotonic_now,
        10_000,
    );
    assert_eq!(expires_at_ms, 11_500);

    let signal = WebRtcSignal {
        version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
        negotiation_id: "bounded-phase".into(),
        link_type: "webrtc".into(),
        kind: LinkNegotiationKind::Offer,
        created_at_ms: 10_000,
        expires_at_ms,
        payload: WebRtcSignalPayload {
            sdp: Some("v=0\r\na=candidate:1 1 UDP 1 127.0.0.1 5000 typ host\r\n".into()),
            candidates: None,
        },
    };
    assert_eq!(
        deadline_from_signal(&signal, Duration::from_secs(30), monotonic_now, 10_300),
        monotonic_now + Duration::from_millis(1_200),
        "responder work uses the initiator's remaining absolute budget"
    );
    assert_eq!(
        deadline_from_signal(
            &signal,
            Duration::from_millis(500),
            monotonic_now,
            10_300,
        ),
        monotonic_now + Duration::from_millis(500),
        "the local configured timeout may only tighten the signal deadline"
    );
}

#[tokio::test]
async fn inherited_outbound_deadline_is_never_restarted() {
    let local = crate::Identity::generate();
    let remote = crate::Identity::generate();
    let remote_addr = TransportAddr::from_string(&hex::encode(remote.pubkey_full().serialize()));
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(89),
        None,
        WebRtcConfig {
            accept_connections: Some(true),
            connect_timeout_ms: Some(30_000),
            ice_gather_timeout_ms: Some(30_000),
            resolve_mdns_candidates: Some(false),
            stun_servers: Some(Vec::new()),
            ..WebRtcConfig::default()
        },
        packet_tx,
        &local,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let reservation = transport
        .physical
        .reserve(&remote_addr)
        .expect("physical permit");
    let inherited_deadline = tokio::time::Instant::now();
    let started = tokio::time::Instant::now();

    let result = transport
        .runtime()
        .start_outbound(
            remote_addr.clone(),
            reservation,
            inherited_deadline,
            None,
        )
        .await;

    assert!(result.is_err(), "an expired inherited deadline must fail");
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "the configured 30s timeout must not replace the inherited deadline"
    );
    assert!(!transport.pending.lock().await.contains_key(&remote_addr));
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
    let snapshot = transport.resource_snapshot();
    assert_eq!(snapshot.created_total, snapshot.closed_total);
    assert_eq!(snapshot.creating + snapshot.active + snapshot.closing, 0);
}

#[tokio::test]
async fn old_connect_timeout_cannot_remove_same_id_successor() {
    let local = crate::Identity::generate();
    let remote = crate::Identity::generate();
    let remote_addr = TransportAddr::from_string(&hex::encode(remote.pubkey_full().serialize()));
    let successor_slot = TransportAddr::from_string("timeout-successor-physical-slot");
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(104),
        None,
        WebRtcConfig {
            max_connections: Some(2),
            ..WebRtcConfig::default()
        },
        packet_tx,
        &local,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let old_pc = transport
        .physical
        .reserve(&remote_addr)
        .expect("old physical permit")
        .activate(
            transport
                .api
                .new_peer_connection(RTCConfiguration::default())
                .await
                .expect("old peer connection"),
        );
    let successor_pc = transport
        .physical
        .reserve(&successor_slot)
        .expect("successor physical permit")
        .activate(
            transport
                .api
                .new_peer_connection(RTCConfiguration::default())
                .await
                .expect("successor peer connection"),
        );
    let old_deadline = tokio::time::Instant::now() + Duration::from_millis(30);
    transport.pending.lock().await.insert(
        remote_addr.clone(),
        PendingDial {
            session_id: "reused-session".into(),
            phase_owner_id: "old-owner".into(),
            pc: Arc::clone(&old_pc),
            created_at_ms: now_ms(),
            origin: PendingDialOrigin::Remote,
            deadline: old_deadline,
        },
    );
    transport.runtime().spawn_connect_timeout(
        remote_addr.clone(),
        "reused-session".into(),
        old_deadline,
        &old_pc,
    );

    let successor_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let replaced_old = transport
        .pending
        .lock()
        .await
        .insert(
            remote_addr.clone(),
            PendingDial {
                session_id: "reused-session".into(),
                phase_owner_id: "successor-owner".into(),
                pc: Arc::clone(&successor_pc),
                created_at_ms: now_ms(),
                origin: PendingDialOrigin::Remote,
                deadline: successor_deadline,
            },
        )
        .expect("replace old pending owner");
    drop(replaced_old);
    tokio::time::sleep_until(old_deadline + Duration::from_millis(30)).await;

    let successor = transport.pending.lock().await.remove(&remote_addr).expect(
        "old timeout must leave the same-ID successor pending",
    );
    assert!(Arc::ptr_eq(&successor.pc, &successor_pc));
    assert_eq!(successor.deadline, successor_deadline);
    assert!(!transport.failed.lock().await.contains_key(&remote_addr));
    assert_eq!(transport.negotiation.snapshot().timeouts_fired, 0);

    drop(start_peer_connection_cleanup(old_pc));
    drop(start_peer_connection_cleanup(successor.pc));
    drop(successor_pc);
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
    let snapshot = transport.resource_snapshot();
    assert_eq!(snapshot.created_total, snapshot.closed_total);
    assert_eq!(snapshot.abandoned, 0);
}

#[tokio::test]
async fn expired_answer_after_connect_timer_counts_one_phase_timeout() {
    let local = crate::Identity::generate();
    let remote = crate::Identity::generate();
    let remote_full_key = remote.pubkey_full();
    let remote_addr = TransportAddr::from_string(&hex::encode(remote_full_key.serialize()));
    let (remote_xonly, _) = remote_full_key.x_only_public_key();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(107),
        None,
        WebRtcConfig::default(),
        packet_tx,
        &local,
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
    let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
    transport.pending.lock().await.insert(
        remote_addr.clone(),
        PendingDial {
            session_id: "one-timeout".into(),
            phase_owner_id: "one-timeout".into(),
            pc: Arc::clone(&pc),
            created_at_ms: now_ms(),
            origin: PendingDialOrigin::Local,
            deadline,
        },
    );
    transport.runtime().spawn_connect_timeout(
        remote_addr.clone(),
        "one-timeout".into(),
        deadline,
        &pc,
    );
    tokio::time::sleep_until(deadline + Duration::from_millis(20)).await;
    assert!(!transport.pending.lock().await.contains_key(&remote_addr));
    assert_eq!(transport.negotiation.snapshot().timeouts_fired, 1);

    let now = now_ms();
    let result = transport
        .runtime()
        .handle_incoming_signal(IncomingSignal {
            signal: WebRtcSignal {
                version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
                negotiation_id: "one-timeout".into(),
                link_type: "webrtc".into(),
                kind: LinkNegotiationKind::Answer,
                created_at_ms: now.saturating_sub(10),
                expires_at_ms: now.saturating_sub(1),
                payload: WebRtcSignalPayload {
                    sdp: Some(
                        "v=0\r\na=candidate:1 1 UDP 1 127.0.0.1 5000 typ host\r\n".into(),
                    ),
                    candidates: None,
                },
            },
            sender: PublicKey::from_slice(&remote_xonly.serialize()).expect("Nostr key"),
            sender_full_hex: hex::encode(remote_full_key.serialize()),
        })
        .await;
    assert!(matches!(result, Err(TransportError::Timeout)));
    let counters = transport.negotiation.snapshot();
    assert_eq!(counters.timeouts_fired, 1);
    assert_eq!(counters.late_answers_rejected, 1);

    drop(pc);
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
}

#[tokio::test(flavor = "current_thread")]
async fn locked_answer_queue_deadline_records_exactly_one_timeout() {
    let local = crate::Identity::generate();
    let remote = crate::Identity::generate();
    let remote_full_key = remote.pubkey_full();
    let remote_addr = TransportAddr::from_string(&hex::encode(remote_full_key.serialize()));
    let (remote_xonly, _) = remote_full_key.x_only_public_key();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let mut transport = WebRtcTransport::new(
        TransportId::new(105),
        None,
        WebRtcConfig {
            accept_connections: Some(true),
            max_connections: Some(1),
            ice_gather_timeout_ms: Some(250),
            resolve_mdns_candidates: Some(false),
            stun_servers: Some(Vec::new()),
            ..WebRtcConfig::default()
        },
        packet_tx,
        &local,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");

    let offer_pc = build_webrtc_api()
        .expect("offer API")
        .new_peer_connection(RTCConfiguration::default())
        .await
        .expect("offer peer connection");
    offer_pc
        .create_data_channel("locked-answer", None)
        .await
        .expect("offer data channel");
    let offer = offer_pc.create_offer(None).await.expect("offer");
    let mut gathering = offer_pc.gathering_complete_promise().await;
    offer_pc
        .set_local_description(offer)
        .await
        .expect("offer local description");
    wait_for_ice_gathering(Duration::from_secs(1), &mut gathering)
        .await
        .expect("complete offer gathering");
    let offer_sdp = offer_pc
        .local_description()
        .await
        .expect("complete local offer")
        .sdp;
    require_non_trickle_ice_candidates(&offer_sdp).expect("candidate-bearing offer");

    let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
    let wall_now = now_ms();
    let signal = WebRtcSignal {
        version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
        negotiation_id: "locked-answer-deadline".into(),
        link_type: "webrtc".into(),
        kind: LinkNegotiationKind::Offer,
        created_at_ms: wall_now,
        expires_at_ms: wall_now + 200,
        payload: WebRtcSignalPayload {
            sdp: Some(offer_sdp),
            candidates: None,
        },
    };
    let runtime = transport.runtime();
    let handler = tokio::spawn(async move {
        runtime
            .handle_offer(
                signal,
                PublicKey::from_slice(&remote_xonly.serialize()).expect("Nostr key"),
                hex::encode(remote_full_key.serialize()),
                deadline,
            )
            .await
    });
    let pending_guard = tokio::time::timeout(Duration::from_millis(150), async {
        loop {
            let pending = transport.pending.lock().await;
            if pending
                .get(&remote_addr)
                .is_some_and(|dial| dial.session_id == "locked-answer-deadline")
            {
                return pending;
            }
            drop(pending);
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("handler inserts pending before gathering answer");
    tokio::time::sleep_until(deadline + Duration::from_millis(10)).await;
    drop(pending_guard);

    assert!(matches!(
        handler.await.expect("offer handler task"),
        Err(TransportError::Timeout)
    ));
    assert!(transport.drain_link_negotiations(1).is_empty());
    let snapshot = transport.negotiation.snapshot();
    assert_eq!(snapshot.answers_queued, 0);
    assert_eq!(snapshot.timeouts_fired, 1);
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
    offer_pc.close().await.expect("close offer peer");
}

#[tokio::test]
async fn replacement_deadline_queues_no_late_answer_or_successor() {
    let local = crate::Identity::generate();
    let remote = crate::Identity::generate();
    let remote_full_key = remote.pubkey_full();
    let remote_addr = TransportAddr::from_string(&hex::encode(remote_full_key.serialize()));
    let (remote_xonly, _) = remote_full_key.x_only_public_key();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let mut transport = WebRtcTransport::new(
        TransportId::new(88),
        None,
        WebRtcConfig {
            accept_connections: Some(true),
            max_connections: Some(1),
            connect_timeout_ms: Some(30),
            ice_gather_timeout_ms: Some(250),
            resolve_mdns_candidates: Some(false),
            stun_servers: Some(Vec::new()),
            ..WebRtcConfig::default()
        },
        packet_tx,
        &local,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");

    let old_pc = transport
        .physical
        .reserve(&remote_addr)
        .expect("old physical permit")
        .activate(
            transport
                .api
                .new_peer_connection(RTCConfiguration::default())
                .await
                .expect("old peer connection"),
        );
    let escaped_old_pc = old_pc.raw();
    let old_dc = old_pc
        .create_data_channel("old-session", None)
        .await
        .expect("old data channel");
    transport.pool.lock().await.insert(
        remote_addr.clone(),
        WebRtcConnection {
            session_id: "old-session".into(),
            pc: old_pc,
            data_channel: old_dc,
        },
    );

    let offer_pc = build_webrtc_api()
        .expect("offer API")
        .new_peer_connection(RTCConfiguration::default())
        .await
        .expect("offer peer connection");
    offer_pc
        .create_data_channel("replacement", None)
        .await
        .expect("offer data channel");
    let offer = offer_pc.create_offer(None).await.expect("offer");
    let mut gathering = offer_pc.gathering_complete_promise().await;
    offer_pc
        .set_local_description(offer)
        .await
        .expect("offer local description");
    wait_for_ice_gathering(Duration::from_secs(1), &mut gathering)
        .await
        .expect("complete offer gathering");
    let offer_sdp = offer_pc
        .local_description()
        .await
        .expect("complete local offer")
        .sdp;
    require_non_trickle_ice_candidates(&offer_sdp).expect("candidate-bearing offer");
    let now = now_ms();
    let incoming = IncomingSignal {
        signal: WebRtcSignal {
            version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
            negotiation_id: "replacement-session".into(),
            link_type: "webrtc".into(),
            kind: LinkNegotiationKind::Offer,
            created_at_ms: now,
            expires_at_ms: now + SIGNAL_TTL_MS,
            payload: WebRtcSignalPayload {
                sdp: Some(offer_sdp),
                candidates: None,
            },
        },
        sender: PublicKey::from_slice(&remote_xonly.serialize()).expect("Nostr key"),
        sender_full_hex: hex::encode(remote_full_key.serialize()),
    };

    let started = tokio::time::Instant::now();
    let result = transport.runtime().handle_incoming_signal(incoming).await;
    assert!(
        matches!(
            result,
            Err(TransportError::Timeout | TransportError::ConnectionRefused)
        ),
        "replacement phase result: {result:?}"
    );
    assert!(started.elapsed() < Duration::from_millis(150));
    assert!(
        transport
            .drain_link_negotiations(8)
            .into_iter()
            .map(|outbound| LinkNegotiationMessage::decode(&outbound.payload).unwrap())
            .all(|message| message.kind != LinkNegotiationKind::Answer),
        "an expired replacement phase must queue no late Answer"
    );
    assert_eq!(transport.resource_snapshot().created_total, 1);
    assert_eq!(
        transport.physical.phase(&remote_addr),
        Some(PhysicalPhase::Closing)
    );

    drop(escaped_old_pc);
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
    offer_pc.close().await.expect("close offer peer");
}

#[tokio::test]
async fn one_same_peer_offer_is_admitted_before_expensive_mdns_work() {
    let local = crate::Identity::generate();
    let remote = crate::Identity::generate();
    let remote_full_key = remote.pubkey_full();
    let remote_addr = TransportAddr::from_string(&hex::encode(remote_full_key.serialize()));
    let (remote_xonly, _) = remote_full_key.x_only_public_key();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(96),
        None,
        WebRtcConfig {
            accept_connections: Some(true),
            max_connections: Some(1),
            connect_timeout_ms: Some(2_000),
            resolve_mdns_candidates: Some(true),
            stun_servers: Some(Vec::new()),
            ..WebRtcConfig::default()
        },
        packet_tx,
        &local,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let old_pc = transport
        .physical
        .reserve(&remote_addr)
        .expect("old physical permit")
        .activate(
            transport
                .api
                .new_peer_connection(RTCConfiguration::default())
                .await
                .expect("old peer connection"),
        );
    let escaped_old_pc = old_pc.raw();
    let cleanup = start_peer_connection_cleanup(old_pc);
    assert_eq!(
        transport.physical.phase(&remote_addr),
        Some(PhysicalPhase::Closing)
    );

    let unresolved_offer = |session_id: &str| {
        let now = now_ms();
        IncomingSignal {
            signal: WebRtcSignal {
                version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
                negotiation_id: session_id.into(),
                link_type: "webrtc".into(),
                kind: LinkNegotiationKind::Offer,
                created_at_ms: now,
                expires_at_ms: now + 2_000,
                payload: WebRtcSignalPayload {
                    sdp: Some(
                        "v=0\r\na=candidate:1 1 UDP 1 never-resolves-fips.local 5000 typ host\r\n"
                            .into(),
                    ),
                    candidates: None,
                },
            },
            sender: PublicKey::from_slice(&remote_xonly.serialize()).expect("Nostr key"),
            sender_full_hex: hex::encode(remote_full_key.serialize()),
        }
    };
    let first_offer = unresolved_offer("first-offer");
    let second_offer = unresolved_offer("second-offer");
    let first_runtime = transport.runtime();
    let first = tokio::spawn(async move {
        first_runtime
            .handle_incoming_signal(first_offer)
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while !transport.physical.has_offer_handler(&remote_addr) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first offer claims per-peer admission");
    assert!(
        !transport.physical.has_peer_release_waiter(&remote_addr),
        "offer admission must precede mDNS and physical-release waiting"
    );

    let second = tokio::time::timeout(
        Duration::from_millis(100),
        transport
            .runtime()
            .handle_incoming_signal(second_offer),
    )
    .await
    .expect("second same-peer offer rejects promptly");
    assert!(matches!(second, Err(TransportError::ConnectionRefused)));

    first.abort();
    assert!(first.await.expect_err("first handler cancellation").is_cancelled());
    assert!(!transport.physical.has_offer_handler(&remote_addr));
    drop(escaped_old_pc);
    cleanup.wait().await;
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
}
