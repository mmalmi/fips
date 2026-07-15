use super::*;
use crate::packet_channel;

#[tokio::test]
async fn one_mapless_closing_offer_waits_for_release_and_later_offers_are_refused() {
    let identity = crate::Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(84),
        None,
        WebRtcConfig {
            max_connections: Some(1),
            resolve_mdns_candidates: Some(false),
            ..WebRtcConfig::default()
        },
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let addr = TransportAddr::from_string("mapless-closing-peer");
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
    let completion = start_peer_connection_cleanup(pc);
    assert_eq!(
        transport.physical.phase(&addr),
        Some(PhysicalPhase::Closing)
    );

    let waiting_resources = transport.physical.clone();
    let waiting_addr = addr.clone();
    let first = tokio::spawn(async move {
        reserve_physical_for_incoming_offer(
            &waiting_resources,
            &waiting_addr,
            now_ms() + 2_000,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while !transport.physical.has_peer_release_waiter(&addr) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first replacement owns the per-peer waiter");

    let second = tokio::time::timeout(
        Duration::from_millis(100),
        reserve_physical_for_incoming_offer(
            &transport.physical,
            &addr,
            now_ms() + 2_000,
            tokio::time::Instant::now() + Duration::from_secs(2),
        ),
    )
    .await
    .expect("later same-peer offer is rejected without waiting");
    assert!(matches!(
        second,
        Err(PhysicalReserveError::PeerBusy(PhysicalPhase::Closing))
    ));

    first.abort();
    match first.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(_) => panic!("first replacement waiter was not cancelled"),
    }
    assert!(!transport.physical.has_peer_release_waiter(&addr));
    let waiting_resources = transport.physical.clone();
    let waiting_addr = addr.clone();
    let successor = tokio::spawn(async move {
        reserve_physical_for_incoming_offer(
            &waiting_resources,
            &waiting_addr,
            now_ms() + 2_000,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while !transport.physical.has_peer_release_waiter(&addr) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled waiter releases the per-peer slot");

    drop(raw_pc);
    completion.wait().await;
    let replacement = successor
        .await
        .expect("replacement waiter task")
        .expect("first replacement reserves after real cleanup");
    drop(replacement);
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
async fn pooled_replacement_starts_cleanup_without_awaiting_escaped_raw_owners() {
    let identity = crate::Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(87),
        None,
        WebRtcConfig {
            max_connections: Some(1),
            resolve_mdns_candidates: Some(false),
            ..WebRtcConfig::default()
        },
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
    let escaped_raw = pc.raw();
    let data_channel = pc
        .create_data_channel("replacement-deadline", None)
        .await
        .expect("data channel");
    transport.pool.lock().await.insert(
        addr.clone(),
        WebRtcConnection {
            session_id: "old-session".into(),
            pc,
            data_channel,
        },
    );

    let disposition = tokio::time::timeout(
        Duration::from_millis(100),
        prepare_pooled_webrtc_session_for_offer(
            &transport.pool,
            &transport.pending,
            &transport.failed,
            &transport.ready,
            &addr,
            "new-session",
            "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
    )
    .await
    .expect("logical replacement must not await an escaped raw PC owner");
    assert_eq!(disposition, PooledOfferDisposition::Accept);
    assert_eq!(
        transport.physical.phase(&addr),
        Some(PhysicalPhase::Closing)
    );

    drop(escaped_raw);
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
}

#[tokio::test]
async fn stopping_transport_cancels_the_generation_bound_replacement_waiter() {
    let resources = PhysicalResources::new(1);
    let addr = TransportAddr::from_string("stopped-replacement-peer");
    let api = build_webrtc_api().expect("WebRTC API");
    let pc = resources.reserve(&addr).expect("physical permit").activate(
        api.new_peer_connection(RTCConfiguration::default())
            .await
            .expect("peer connection"),
    );
    let escaped_raw = pc.raw();
    let completion = start_peer_connection_cleanup(pc);
    let waiting_resources = resources.clone();
    let waiting_addr = addr.clone();
    let waiter = tokio::spawn(async move {
        reserve_physical_for_incoming_offer(
            &waiting_resources,
            &waiting_addr,
            now_ms() + 2_000,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while !resources.has_peer_release_waiter(&addr) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("replacement waiter registered");

    resources.stop_accepting();
    let result = tokio::time::timeout(Duration::from_millis(100), waiter)
        .await
        .expect("stop wakes replacement waiter")
        .expect("waiter task");
    assert!(matches!(
        result,
        Err(PhysicalReserveError::PeerBusy(PhysicalPhase::Closing))
    ));
    assert!(!resources.has_peer_release_waiter(&addr));

    drop(escaped_raw);
    completion.wait().await;
    assert!(
        resources
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
}

#[tokio::test]
async fn successful_full_close_and_owned_ice_fallback_both_conserve_the_permit() {
    async fn managed_peer(resources: &PhysicalResources, addr: &str) -> ManagedPeer {
        let api = build_webrtc_api().expect("WebRTC API");
        resources
            .reserve(&TransportAddr::from_string(addr))
            .expect("physical permit")
            .activate(
                api.new_peer_connection(RTCConfiguration::default())
                    .await
                    .expect("peer connection"),
            )
    }

    let normal_resources = PhysicalResources::new(1);
    let normal = managed_peer(&normal_resources, "normal-close-peer").await;
    let (normal_raw, normal_guard, normal_completion) =
        normal.begin_cleanup().expect("normal cleanup owner");
    drop(normal);
    assert!(
        !run_physical_peer_cleanup(
            Duration::from_secs(1),
            normal_raw,
            normal_resources.clone(),
        )
        .await,
        "a successful RTCPeerConnection close must not run duplicate ICE stop"
    );
    normal_guard.complete();
    normal_completion.finish();
    let normal_snapshot = normal_resources.snapshot();
    assert_eq!(normal_snapshot.created_total, normal_snapshot.closed_total);
    assert_eq!(normal_snapshot.closing, 0);
    assert_eq!(normal_snapshot.abandoned, 0);

    let fallback_resources = PhysicalResources::new(1);
    let fallback = managed_peer(&fallback_resources, "fallback-close-peer").await;
    let (fallback_raw, fallback_guard, fallback_completion) =
        fallback.begin_cleanup().expect("fallback cleanup owner");
    drop(fallback);
    assert!(
        run_physical_peer_cleanup_with_close(
            Duration::from_millis(10),
            fallback_raw,
            fallback_resources.clone(),
            std::future::pending::<Result<(), ()>>(),
        )
        .await,
        "timed-out full close must abort/join and run the owned ICE fallback"
    );
    assert_eq!(fallback_resources.snapshot().closing, 1);
    fallback_guard.complete();
    fallback_completion.finish();
    let fallback_snapshot = fallback_resources.snapshot();
    assert_eq!(
        fallback_snapshot.created_total,
        fallback_snapshot.closed_total
    );
    assert_eq!(fallback_snapshot.closing, 0);
    assert_eq!(fallback_snapshot.abandoned, 0);
    assert_eq!(fallback_snapshot.ice_stop_failures_total, 0);
}
