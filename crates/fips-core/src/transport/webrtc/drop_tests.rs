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
        runtime.transport_id,
        runtime.packet_tx.clone(),
        WebRtcSessionOwners::from_refs(
            &runtime.pool,
            &runtime.pending,
            &runtime.failed,
            &runtime.ready,
        ),
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
    let remote_addr = TransportAddr::from_string(&hex::encode(remote.pubkey_full().serialize()));
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(79),
        None,
        WebRtcConfig {
            connect_timeout_ms: Some(30_000),
            ice_gather_timeout_ms: Some(50),
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
        "ready-fallback-session".into(),
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
    let outbound_addr =
        TransportAddr::from_string(&hex::encode(outbound.pubkey_full().serialize()));
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
