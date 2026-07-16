use super::*;
use crate::packet_channel;

#[tokio::test]
async fn transport_drop_breaks_callback_cycles_and_completes_physical_cleanup() {
    let identity = crate::Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(78),
        None,
        WebRtcConfig {
            resolve_mdns_candidates: Some(false),
            ..WebRtcConfig::default()
        },
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let addr = TransportAddr::from_string("drop-cycle-peer");
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
        .create_data_channel("drop-cycle", None)
        .await
        .expect("data channel");
    let runtime = transport.runtime();
    wire_peer_connection_state(&runtime, addr.clone(), "drop-cycle".into(), Arc::clone(&pc));
    wire_data_channel(
        runtime.data_channel_context(),
        addr.clone(),
        "drop-cycle".into(),
        Arc::clone(&pc),
        Arc::clone(&data_channel),
    );
    transport.pool.lock().await.insert(
        addr,
        WebRtcConnection {
            session_id: "drop-cycle".into(),
            pc: Arc::clone(&pc),
            data_channel,
        },
    );
    let weak_pool = Arc::downgrade(&transport.pool);
    let resources = transport.physical.clone();
    drop(runtime);
    drop(pc);
    drop(transport);

    assert!(
        weak_pool.upgrade().is_none(),
        "callback maps must not form an ownership cycle"
    );
    assert!(
        resources
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
    let snapshot = resources.snapshot();
    assert_eq!(snapshot.created_total, snapshot.closed_total);
    assert_eq!(snapshot.abandoned, 0);
}

#[tokio::test]
async fn pending_timeout_does_not_retain_transport_after_drop() {
    let identity = crate::Identity::generate();
    let remote = crate::Identity::generate();
    let remote_addr = test_webrtc_addr(&remote);
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(79),
        None,
        WebRtcConfig {
            connect_timeout_ms: Some(30_000),
            ice_gather_timeout_ms: Some(500),
            resolve_mdns_candidates: Some(false),
            stun_servers: Some(Vec::new()),
            ..WebRtcConfig::default()
        },
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");

    transport
        .connect_async(&remote_addr)
        .await
        .expect("start pending dial");
    let dial_tasks = {
        let mut tasks = transport.dial_tasks.lock().expect("WebRTC dial tasks");
        std::mem::take(&mut *tasks)
    };
    for task in dial_tasks {
        task.await
            .expect("outbound dial task")
            .expect("outbound setup");
    }
    assert_eq!(transport.pending.lock().await.len(), 1);

    let weak_pending = Arc::downgrade(&transport.pending);
    let resources = transport.physical.clone();
    drop(transport);
    tokio::task::yield_now().await;

    assert!(
        weak_pending.upgrade().is_none(),
        "detached timeout must not retain the pending map"
    );
    assert!(
        resources
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
    let snapshot = resources.snapshot();
    assert_eq!(snapshot.created_total, snapshot.closed_total);
    assert_eq!(snapshot.abandoned, 0);
}

#[tokio::test]
async fn ready_fallback_does_not_retain_connection_maps_after_drop() {
    let pool = Arc::new(Mutex::new(HashMap::new()));
    let ready = Arc::new(Mutex::new(HashSet::new()));
    let weak_pool = Arc::downgrade(&pool);
    let weak_ready = Arc::downgrade(&ready);

    spawn_webrtc_ready_fallback(
        TransportId::new(80),
        TransportAddr::from_string("ready-fallback-peer"),
        WebRtcSessionOwner {
            session_id: Some("ready-fallback-session".into()),
            pc: Some(std::sync::Weak::new()),
            generation: None,
        },
        PhysicalResources::new(1).downgrade(),
        pool,
        ready,
    );
    tokio::task::yield_now().await;

    assert!(
        weak_pool.upgrade().is_none(),
        "ready fallback must not retain the connection pool"
    );
    assert!(
        weak_ready.upgrade().is_none(),
        "ready fallback must not retain the ready set"
    );
}

#[tokio::test]
async fn direct_drop_aborts_live_signal_and_dial_owners() {
    let identity = crate::Identity::generate();
    let inbound = crate::Identity::generate();
    let outbound = crate::Identity::generate();
    let outbound_addr = test_webrtc_addr(&outbound);
    let (packet_tx, _packet_rx) = packet_channel(1);
    let mut transport = WebRtcTransport::new(
        TransportId::new(82),
        None,
        WebRtcConfig {
            accept_connections: Some(true),
            max_connections: Some(2),
            ice_gather_timeout_ms: Some(30_000),
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
        .send(super::signal_tests::incoming_offer(
            &inbound,
            "blocked-inbound-offer",
        ))
        .expect("queue blocked signal handler");
    tokio::time::sleep(Duration::from_millis(25)).await;
    transport
        .connect_async(&outbound_addr)
        .await
        .expect("queue live outbound dial");
    assert!(transport.signal_task.is_some());
    assert!(!transport.dial_tasks.lock().expect("dial tasks").is_empty());

    let weak_pool = Arc::downgrade(&transport.pool);
    let weak_pending = Arc::downgrade(&transport.pending);
    let weak_failed = Arc::downgrade(&transport.failed);
    let weak_ready = Arc::downgrade(&transport.ready);
    let resources = transport.physical.clone();
    // Keep the receiver open after dropping the transport. Without explicit
    // task abortion, the signal owner would otherwise exit merely because the
    // transport dropped the last sender, masking the ownership regression.
    let retained_signal_tx = transport.signal_tx.clone();
    drop(transport);
    drop(seen_guard);
    drop(seen_sessions);

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if weak_pool.upgrade().is_none()
                && weak_pending.upgrade().is_none()
                && weak_failed.upgrade().is_none()
                && weak_ready.upgrade().is_none()
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("direct Drop releases non-cleanup runtime owners");
    drop(retained_signal_tx);
    assert!(
        resources
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
    let snapshot = resources.snapshot();
    assert_eq!(snapshot.created_total, snapshot.closed_total);
    assert_eq!(snapshot.abandoned, 0);
}

async fn pending_handoff_transport(
    transport_id: u32,
    session_id: &str,
) -> (
    WebRtcTransport,
    TransportAddr,
    ManagedPeer,
    Arc<RTCDataChannel>,
) {
    let identity = crate::Identity::generate();
    let remote = crate::Identity::generate();
    let addr = test_webrtc_addr(&remote);
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(transport_id),
        None,
        WebRtcConfig {
            max_connections: Some(2),
            ..WebRtcConfig::default()
        },
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
        .create_data_channel(session_id, None)
        .await
        .expect("data channel");
    transport.pending.lock().await.insert(
        addr.clone(),
        PendingDial {
            session_id: session_id.into(),
            phase_owner_id: session_id.into(),
            pc: Arc::clone(&pc),
            created_at_ms: now_ms(),
            origin: PendingDialOrigin::Local,
            deadline: tokio::time::Instant::now() + Duration::from_secs(2),
        },
    );
    (transport, addr, pc, data_channel)
}

async fn pooled_handoff_transport(
    transport_id: u32,
    session_id: &str,
) -> (
    WebRtcTransport,
    TransportAddr,
    ManagedPeer,
    Arc<RTCDataChannel>,
) {
    let (transport, addr, pc, data_channel) =
        pending_handoff_transport(transport_id, session_id).await;
    assert!(matches!(
        promote_pending_webrtc_session(
            &transport.physical,
            &transport.pool,
            &transport.pending,
            &transport.failed,
            &addr,
            WebRtcConnection {
                session_id: session_id.into(),
                pc: Arc::clone(&pc),
                data_channel: Arc::clone(&data_channel),
            },
        )
        .await,
        Ok(None)
    ));
    (transport, addr, pc, data_channel)
}

#[tokio::test]
async fn close_cannot_miss_the_atomic_pending_to_pool_handoff() {
    let (transport, addr, pc, data_channel) =
        pending_handoff_transport(97, "close-handoff").await;
    let pending_guard = transport.pending.lock().await;
    let promote = {
        let physical = transport.physical.clone();
        let pool = Arc::clone(&transport.pool);
        let pending = Arc::clone(&transport.pending);
        let failed = Arc::clone(&transport.failed);
        let addr = addr.clone();
        let candidate = WebRtcConnection {
            session_id: "close-handoff".into(),
            pc: Arc::clone(&pc),
            data_channel: Arc::clone(&data_channel),
        };
        tokio::spawn(async move {
            promote_pending_webrtc_session(
                &physical,
                &pool,
                &pending,
                &failed,
                &addr,
                candidate,
            )
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        while transport.pool.try_lock().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("promotion holds pool while awaiting pending");
    let close = {
        let owners = WebRtcSessionOwners::from_refs(
            &transport.pool,
            &transport.pending,
            &transport.failed,
            &transport.ready,
        );
        let addr = addr.clone();
        let expected_owner = WebRtcSessionOwner::new("close-handoff", &pc);
        tokio::spawn(async move {
            cleanup_webrtc_session(
                &owners,
                &addr,
                Some(&expected_owner),
                Some("terminal cleanup won".into()),
                CleanupWait::Started,
            )
            .await
        })
    };
    drop(pending_guard);
    assert!(matches!(promote.await.expect("promotion task"), Ok(None)));
    assert!(close.await.expect("close task"));
    assert!(!transport.pool.lock().await.contains_key(&addr));
    assert!(!transport.pending.lock().await.contains_key(&addr));
    assert_eq!(
        transport.failed.lock().await.get(&addr).map(String::as_str),
        Some("terminal cleanup won")
    );
    drop(data_channel);
    drop(pc);
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
}

#[tokio::test]
async fn stop_during_pending_to_pool_handoff_cannot_resurrect_a_session() {
    let (transport, addr, pc, data_channel) =
        pending_handoff_transport(98, "stop-handoff").await;
    let pending_guard = transport.pending.lock().await;
    let promote = {
        let physical = transport.physical.clone();
        let pool = Arc::clone(&transport.pool);
        let pending = Arc::clone(&transport.pending);
        let failed = Arc::clone(&transport.failed);
        let addr = addr.clone();
        let candidate = WebRtcConnection {
            session_id: "stop-handoff".into(),
            pc: Arc::clone(&pc),
            data_channel: Arc::clone(&data_channel),
        };
        tokio::spawn(async move {
            promote_pending_webrtc_session(
                &physical,
                &pool,
                &pending,
                &failed,
                &addr,
                candidate,
            )
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        while transport.pool.try_lock().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("promotion holds pool while awaiting pending");
    transport.physical.stop_accepting();
    drop(pending_guard);
    let rejected = match promote.await.expect("promotion task") {
        Err(rejected) => rejected,
        Ok(_) => panic!("stopped transport accepted the handoff"),
    };
    assert!(!transport.pool.lock().await.contains_key(&addr));
    assert!(transport.pending.lock().await.contains_key(&addr));
    drop(rejected.data_channel);
    drop(rejected.pc);
    let owners = WebRtcSessionOwners::from_refs(
        &transport.pool,
        &transport.pending,
        &transport.failed,
        &transport.ready,
    );
    let expected_owner = WebRtcSessionOwner::new("stop-handoff", &pc);
    assert!(
        cleanup_webrtc_session(
            &owners,
            &addr,
            Some(&expected_owner),
            None,
            CleanupWait::Started,
        )
        .await
    );
    drop(data_channel);
    drop(pc);
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
}

#[tokio::test]
async fn ready_send_is_linearized_with_pooled_session_cleanup() {
    let (transport, addr, pc, data_channel) =
        pooled_handoff_transport(99, "ready-linearization").await;

    let (operation_entered_tx, operation_entered_rx) = tokio::sync::oneshot::channel();
    let (release_operation_tx, release_operation_rx) = tokio::sync::oneshot::channel();
    let ready_operation = {
        let physical = transport.physical.clone();
        let pool = Arc::clone(&transport.pool);
        let addr = addr.clone();
        let pc = Arc::clone(&pc);
        tokio::spawn(async move {
            while_pooled_webrtc_session_is_active(
                &physical,
                &pool,
                &addr,
                "ready-linearization",
                &pc,
                async move {
                    operation_entered_tx
                        .send(())
                        .expect("report ready operation entry");
                    release_operation_rx
                        .await
                        .expect("release ready operation");
                },
            )
            .await
        })
    };
    operation_entered_rx
        .await
        .expect("ready operation holds exact pooled owner");

    let (cleanup_started_tx, cleanup_started_rx) = tokio::sync::oneshot::channel();
    let cleanup = {
        let owners = WebRtcSessionOwners::from_refs(
            &transport.pool,
            &transport.pending,
            &transport.failed,
            &transport.ready,
        );
        let addr = addr.clone();
        let pc = Arc::clone(&pc);
        tokio::spawn(async move {
            cleanup_started_tx
                .send(())
                .expect("report cleanup attempt");
            cleanup_terminal_webrtc_session(
                &owners,
                &addr,
                "ready-linearization",
                None,
                pc,
            )
            .await
        })
    };
    cleanup_started_rx.await.expect("cleanup reaches pool lock");
    assert!(
        !cleanup.is_finished(),
        "cleanup cannot linearize between the active check and READY send"
    );
    assert_eq!(
        transport.physical.phase(&addr),
        Some(PhysicalPhase::Active),
        "terminal callback cannot start physical close before removing the pool owner"
    );

    release_operation_tx
        .send(())
        .expect("finish ready operation");
    assert_eq!(
        ready_operation.await.expect("ready operation task"),
        Some(())
    );
    assert!(cleanup.await.expect("cleanup task"));
    assert!(!transport.pool.lock().await.contains_key(&addr));
    assert!(!transport.pending.lock().await.contains_key(&addr));

    drop(data_channel);
    drop(pc);
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
    let snapshot = transport.physical.snapshot();
    assert_eq!(snapshot.created_total, snapshot.closed_total);
    assert_eq!(snapshot.abandoned, 0);
}

#[tokio::test]
async fn cleanup_linearized_first_suppresses_ready_send() {
    let (transport, addr, pc, data_channel) =
        pooled_handoff_transport(100, "cleanup-before-ready").await;

    // Hold pending so cleanup can prove it owns pool before the READY task is
    // queued. This makes cleanup-first ordering independent of task polling.
    let pending_guard = transport.pending.lock().await;
    let cleanup = {
        let owners = WebRtcSessionOwners::from_refs(
            &transport.pool,
            &transport.pending,
            &transport.failed,
            &transport.ready,
        );
        let addr = addr.clone();
        let expected_owner = WebRtcSessionOwner::new("cleanup-before-ready", &pc);
        tokio::spawn(async move {
            cleanup_webrtc_session(
                &owners,
                &addr,
                Some(&expected_owner),
                None,
                CleanupWait::Started,
            )
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        while transport.pool.try_lock().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cleanup owns pool while awaiting pending");

    let ready_sent = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ready_operation = {
        let physical = transport.physical.clone();
        let pool = Arc::clone(&transport.pool);
        let addr = addr.clone();
        let pc = Arc::clone(&pc);
        let ready_sent = Arc::clone(&ready_sent);
        tokio::spawn(async move {
            while_pooled_webrtc_session_is_active(
                &physical,
                &pool,
                &addr,
                "cleanup-before-ready",
                &pc,
                async move {
                    ready_sent.store(true, std::sync::atomic::Ordering::SeqCst);
                },
            )
            .await
        })
    };
    drop(pending_guard);

    assert!(cleanup.await.expect("cleanup task"));
    assert_eq!(
        ready_operation.await.expect("ready operation task"),
        None
    );
    assert!(
        !ready_sent.load(std::sync::atomic::Ordering::SeqCst),
        "cleanup that owns the pool epoch must suppress READY"
    );
    assert!(!transport.pool.lock().await.contains_key(&addr));
    assert!(!transport.pending.lock().await.contains_key(&addr));
    assert!(!transport.ready.lock().await.contains(&addr));

    drop(data_channel);
    drop(pc);
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
    let snapshot = transport.physical.snapshot();
    assert_eq!(snapshot.created_total, snapshot.closed_total);
    assert_eq!(snapshot.abandoned, 0);
}

#[tokio::test]
async fn received_ready_marker_and_cleanup_share_one_owner_epoch() {
    let (transport, addr, pc, data_channel) =
        pooled_handoff_transport(101, "received-ready-cleanup").await;
    let ready_guard = transport.ready.lock().await;
    let (marker_started_tx, marker_started_rx) = tokio::sync::oneshot::channel();
    let marker = {
        let physical = transport.physical.clone();
        let pool = Arc::clone(&transport.pool);
        let ready = Arc::clone(&transport.ready);
        let addr = addr.clone();
        let expected_owner = WebRtcSessionOwner::new("received-ready-cleanup", &pc);
        tokio::spawn(async move {
            marker_started_tx
                .send(())
                .expect("report received READY attempt");
            mark_webrtc_ready_if_pooled(
                TransportId::new(101),
                &addr,
                &expected_owner,
                &physical,
                &pool,
                &ready,
            )
            .await
        })
    };
    marker_started_rx
        .await
        .expect("received READY holds pool while awaiting ready set");
    tokio::time::timeout(Duration::from_secs(1), async {
        while transport.pool.try_lock().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("received READY owns pool before cleanup starts");

    let (cleanup_started_tx, cleanup_started_rx) = tokio::sync::oneshot::channel();
    let cleanup = {
        let owners = WebRtcSessionOwners::from_refs(
            &transport.pool,
            &transport.pending,
            &transport.failed,
            &transport.ready,
        );
        let addr = addr.clone();
        let expected_owner = WebRtcSessionOwner::new("received-ready-cleanup", &pc);
        tokio::spawn(async move {
            cleanup_started_tx
                .send(())
                .expect("report cleanup attempt");
            cleanup_webrtc_session(
                &owners,
                &addr,
                Some(&expected_owner),
                None,
                CleanupWait::Started,
            )
            .await
        })
    };
    cleanup_started_rx.await.expect("cleanup awaits pool owner");
    assert!(!cleanup.is_finished());
    drop(ready_guard);

    assert!(marker.await.expect("received READY task"));
    assert!(cleanup.await.expect("cleanup task"));
    assert!(!transport.pool.lock().await.contains_key(&addr));
    assert!(!transport.pending.lock().await.contains_key(&addr));
    assert!(!transport.ready.lock().await.contains(&addr));

    drop(data_channel);
    drop(pc);
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
    let snapshot = transport.physical.snapshot();
    assert_eq!(snapshot.created_total, snapshot.closed_total);
    assert_eq!(snapshot.abandoned, 0);
}

#[tokio::test]
async fn ready_fallback_and_cleanup_share_one_owner_epoch() {
    let (transport, addr, pc, data_channel) =
        pooled_handoff_transport(102, "fallback-ready-cleanup").await;
    let ready_guard = transport.ready.lock().await;
    spawn_webrtc_ready_fallback(
        TransportId::new(102),
        addr.clone(),
        WebRtcSessionOwner::new("fallback-ready-cleanup", &pc),
        transport.physical.downgrade(),
        Arc::clone(&transport.pool),
        Arc::clone(&transport.ready),
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while transport.pool.try_lock().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("fallback holds pool while awaiting ready set");

    let (cleanup_started_tx, cleanup_started_rx) = tokio::sync::oneshot::channel();
    let cleanup = {
        let owners = WebRtcSessionOwners::from_refs(
            &transport.pool,
            &transport.pending,
            &transport.failed,
            &transport.ready,
        );
        let addr = addr.clone();
        let expected_owner = WebRtcSessionOwner::new("fallback-ready-cleanup", &pc);
        tokio::spawn(async move {
            cleanup_started_tx
                .send(())
                .expect("report fallback cleanup attempt");
            cleanup_webrtc_session(
                &owners,
                &addr,
                Some(&expected_owner),
                None,
                CleanupWait::Started,
            )
            .await
        })
    };
    cleanup_started_rx
        .await
        .expect("cleanup awaits fallback pool owner");
    assert!(!cleanup.is_finished());
    drop(ready_guard);

    assert!(cleanup.await.expect("cleanup task"));
    assert!(!transport.pool.lock().await.contains_key(&addr));
    assert!(!transport.pending.lock().await.contains_key(&addr));
    assert!(!transport.ready.lock().await.contains(&addr));

    drop(data_channel);
    drop(pc);
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
    let snapshot = transport.physical.snapshot();
    assert_eq!(snapshot.created_total, snapshot.closed_total);
    assert_eq!(snapshot.abandoned, 0);
}

#[tokio::test]
async fn stop_cannot_leave_ready_state_after_draining_its_pool_owner() {
    let (mut transport, addr, pc, data_channel) =
        pooled_handoff_transport(103, "stop-ready-cleanup").await;
    transport.start_async().await.expect("start transport");
    let physical = transport.physical.clone();
    let pool = Arc::clone(&transport.pool);
    let pending = Arc::clone(&transport.pending);
    let ready = Arc::clone(&transport.ready);
    let ready_guard = ready.lock().await;
    let marker = {
        let physical = physical.clone();
        let pool = Arc::clone(&pool);
        let ready = Arc::clone(&ready);
        let addr = addr.clone();
        let expected_owner = WebRtcSessionOwner::new("stop-ready-cleanup", &pc);
        tokio::spawn(async move {
            mark_webrtc_ready_if_pooled(
                TransportId::new(103),
                &addr,
                &expected_owner,
                &physical,
                &pool,
                &ready,
            )
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        while pool.try_lock().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("READY marker owns pool while awaiting ready set");

    drop(data_channel);
    drop(pc);
    let stop = tokio::spawn(async move { transport.stop_async().await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while physical.is_accepting() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("stop closes readiness admission");
    drop(ready_guard);

    assert!(!marker.await.expect("READY marker task"));
    stop.await
        .expect("stop task")
        .expect("bounded transport stop");
    assert!(!pool.lock().await.contains_key(&addr));
    assert!(!pending.lock().await.contains_key(&addr));
    assert!(!ready.lock().await.contains(&addr));
    assert!(physical.wait_for_quiescence(Duration::from_secs(3)).await);
    let snapshot = physical.snapshot();
    assert_eq!(snapshot.created_total, snapshot.closed_total);
    assert_eq!(snapshot.abandoned, 0);
}

#[tokio::test]
async fn detached_cleanup_cannot_remove_same_id_successor() {
    let (transport, addr, old_pc, old_data_channel) =
        pooled_handoff_transport(106, "detached-owner-reuse").await;
    let successor_resources = transport.physical.clone();
    let successor_slot = TransportAddr::from_string("detached-successor-physical-slot");
    let successor_pc = successor_resources
        .reserve(&successor_slot)
        .expect("successor physical permit")
        .activate(
            transport
                .api
                .new_peer_connection(RTCConfiguration::default())
                .await
                .expect("successor peer connection"),
        );
    let successor_data_channel = successor_pc
        .create_data_channel("detached-owner-reuse", None)
        .await
        .expect("successor data channel");
    let old_connection = transport
        .pool
        .lock()
        .await
        .insert(
            addr.clone(),
            WebRtcConnection {
                session_id: "detached-owner-reuse".into(),
                pc: Arc::clone(&successor_pc),
                data_channel: Arc::clone(&successor_data_channel),
            },
        )
        .expect("replace old logical owner");

    transport
        .close_connection_detached_task(&addr)
        .expect("capture old physical generation")
        .await
    .expect("detached cleanup task");

    let pool = transport.pool.lock().await;
    let successor = pool
        .get(&addr)
        .expect("same-ID successor remains logically owned");
    assert!(Arc::ptr_eq(&successor.pc, &successor_pc));
    drop(pool);
    assert!(!transport.failed.lock().await.contains_key(&addr));
    assert!(!transport.ready.lock().await.contains(&addr));

    let successor = transport
        .pool
        .lock()
        .await
        .remove(&addr)
        .expect("remove successor for cleanup");
    drop(old_connection.data_channel);
    drop(start_peer_connection_cleanup(old_connection.pc));
    drop(old_data_channel);
    drop(old_pc);
    drop(successor.data_channel);
    drop(start_peer_connection_cleanup(successor.pc));
    drop(successor_data_channel);
    drop(successor_pc);
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
    assert_eq!(
        successor_resources.snapshot().created_total,
        successor_resources.snapshot().closed_total
    );
}
