use super::*;

#[tokio::test]
async fn fresh_offer_replaces_an_existing_webrtc_session() {
    let identity = crate::Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(1),
        None,
        WebRtcConfig::default(),
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let addr = TransportAddr::from_string(
        "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let reservation = transport.physical.reserve(&addr).expect("physical permit");
    let pc = reservation.activate(
        transport
            .api
            .new_peer_connection(RTCConfiguration::default())
            .await
            .expect("peer connection"),
    );
    let raw_pc = pc.raw();
    let weak_raw_pc = Arc::downgrade(&raw_pc);
    drop(raw_pc);
    let data_channel = pc
        .create_data_channel("replacement-test", None)
        .await
        .expect("data channel");
    transport.pool.lock().await.insert(
        addr.clone(),
        WebRtcConnection {
            session_id: "old-session".to_string(),
            pc: Arc::clone(&pc),
            data_channel,
        },
    );
    transport.ready.lock().await.insert(addr.clone());

    assert_eq!(
        prepare_pooled_webrtc_session_for_offer(
            &transport.pool,
            &transport.pending,
            &transport.failed,
            &transport.ready,
            &addr,
            "old-session",
            "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .await,
        PooledOfferDisposition::IgnoreReplay,
        "a replay of the active session must be ignored"
    );
    assert!(transport.pool.lock().await.contains_key(&addr));
    drop(pc);

    assert_eq!(
        prepare_pooled_webrtc_session_for_offer(
            &transport.pool,
            &transport.pending,
            &transport.failed,
            &transport.ready,
            &addr,
            "new-session",
            "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .await,
        PooledOfferDisposition::Accept,
        "a fresh offer must continue after retiring the old session"
    );
    assert!(!transport.pool.lock().await.contains_key(&addr));
    assert!(!transport.ready.lock().await.contains(&addr));
    assert_eq!(
        transport.physical.phase(&addr),
        Some(PhysicalPhase::Closing),
        "logical eviction starts physical cleanup synchronously"
    );
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
    assert!(weak_raw_pc.upgrade().is_none());
    let snapshot = transport.resource_snapshot();
    assert_eq!(snapshot.created_total, snapshot.closed_total);
    assert_eq!(snapshot.creating + snapshot.active + snapshot.closing, 0);
}

#[tokio::test]
async fn session_failure_bookkeeping_precedes_physical_permit_release() {
    let identity = crate::Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(83),
        None,
        WebRtcConfig::default(),
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let addr = TransportAddr::from_string(
        "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
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
    let raw_pc = pc.raw();
    transport.pending.lock().await.insert(
        addr.clone(),
        PendingDial {
            session_id: "old-session".into(),
            phase_owner_id: "old-session".into(),
            pc: Arc::clone(&pc),
            created_at_ms: now_ms(),
            origin: PendingDialOrigin::Local,
            deadline: tokio::time::Instant::now() + Duration::from_secs(2),
        },
    );
    transport.ready.lock().await.insert(addr.clone());
    let expected_owner = WebRtcSessionOwner::new("old-session", &pc);
    drop(pc);

    let runtime = transport.runtime();
    let failed_addr = addr.clone();
    let failure = tokio::spawn(async move {
        runtime
            .mark_session_failed(failed_addr, &expected_owner, "old session failed".into())
            .await;
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        while transport.resource_snapshot().closing == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("old physical session enters Closing");
    assert!(!transport.ready.lock().await.contains(&addr));
    assert_eq!(
        transport.failed.lock().await.get(&addr).map(String::as_str),
        Some("old session failed")
    );

    drop(raw_pc);
    failure.await.expect("failure cleanup task");
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
}
