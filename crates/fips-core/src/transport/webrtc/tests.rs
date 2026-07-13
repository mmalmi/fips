use super::*;
use crate::packet_channel;
use std::sync::atomic::{AtomicBool, Ordering};

#[test]
fn validates_compressed_pubkey_addresses() {
    let good = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert!(validate_compressed_pubkey_hex(good).is_ok());
    assert!(validate_compressed_pubkey_hex(&good[2..]).is_err());
    assert!(
        validate_compressed_pubkey_hex(
            "04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        .is_err()
    );
}

#[test]
fn webrtc_signal_serializes_like_ts_transport() {
    let signal = WebRtcSignal {
        protocol: WEBRTC_PROTOCOL.to_string(),
        version: WEBRTC_SIGNAL_VERSION,
        session_id: "abc".to_string(),
        kind: WebRtcSignalKind::Offer,
        sender: "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        recipient: "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        sdp: Some("v=0".to_string()),
        candidates: None,
        created_at_ms: 1,
        expires_at_ms: 2,
    };
    let json = serde_json::to_string(&signal).unwrap();
    assert!(json.contains(r#""sessionId":"abc""#));
    assert!(json.contains(r#""createdAtMs":1"#));
    assert!(json.contains(r#""expiresAtMs":2"#));
}

#[tokio::test]
async fn accepted_webrtc_offer_cannot_be_replayed_before_expiry() {
    let seen_sessions = SeenSessionPool::default();
    let remote_addr = TransportAddr::from_string(
        "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );

    assert!(
        accept_webrtc_offer_once(&seen_sessions, &remote_addr, "session-a", 200, 100).await
    );
    assert!(
        !accept_webrtc_offer_once(&seen_sessions, &remote_addr, "session-a", 200, 150).await,
        "a delayed copy of an accepted offer must not recreate its ICE peer"
    );
    assert!(
        accept_webrtc_offer_once(&seen_sessions, &remote_addr, "session-a", 300, 201).await,
        "expired replay entries must not block a later offer"
    );
}

#[test]
fn disconnected_webrtc_sessions_are_terminal_for_fips() {
    for state in [
        RTCPeerConnectionState::Disconnected,
        RTCPeerConnectionState::Failed,
        RTCPeerConnectionState::Closed,
    ] {
        assert!(webrtc_peer_state_is_terminal(state));
    }
    for state in [
        RTCPeerConnectionState::New,
        RTCPeerConnectionState::Connecting,
        RTCPeerConnectionState::Connected,
    ] {
        assert!(!webrtc_peer_state_is_terminal(state));
    }
}

#[test]
fn pending_offer_conflicts_choose_the_newest_offer_or_stable_initiator() {
    let lower = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let higher = "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    assert!(incoming_offer_replaces_pending(
        higher,
        lower,
        PendingDialOrigin::Remote,
        100,
        101,
    ));
    assert!(!incoming_offer_replaces_pending(
        higher,
        lower,
        PendingDialOrigin::Remote,
        101,
        100,
    ));
    assert!(incoming_offer_replaces_pending(
        higher,
        lower,
        PendingDialOrigin::Local,
        100,
        100,
    ));
    assert!(!incoming_offer_replaces_pending(
        lower,
        higher,
        PendingDialOrigin::Local,
        100,
        100,
    ));
}

#[test]
fn default_ice_gather_timeout_keeps_signaling_interactive() {
    assert_eq!(WebRtcConfig::default().ice_gather_timeout_ms(), 2_000);
}

#[test]
fn webrtc_listens_for_signaling_on_every_advert_relay() {
    let identity = crate::Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let config = WebRtcConfig {
        signal_relays: Some(vec!["wss://signals.example".to_string()]),
        ..WebRtcConfig::default()
    };
    let discovery = NostrDiscoveryConfig {
        advert_relays: vec![
            "wss://adverts.example".to_string(),
            "wss://signals.example".to_string(),
        ],
        ..NostrDiscoveryConfig::default()
    };
    let transport = WebRtcTransport::new(
        TransportId::new(1),
        None,
        config,
        packet_tx,
        &identity,
        &discovery,
    )
    .expect("WebRTC transport");

    assert_eq!(
        transport.signal_relays,
        vec![
            "wss://signals.example".to_string(),
            "wss://adverts.example".to_string(),
        ]
    );
}

#[tokio::test]
async fn connection_state_does_not_report_none_during_pool_contention() {
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
    let _pool_guard = transport.pool.lock().await;
    let addr = TransportAddr::from_string(
        "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );

    assert_eq!(
        transport.connection_state_sync(&addr),
        ConnectionState::Connecting
    );
}

#[tokio::test]
async fn stalled_webrtc_send_times_out_and_starts_cleanup() {
    let cleanup_started = Arc::new(AtomicBool::new(false));
    let cleanup_flag = Arc::clone(&cleanup_started);
    let started = tokio::time::Instant::now();

    let result = bounded_webrtc_send(
        Duration::from_millis(10),
        std::future::pending::<Result<usize, std::io::Error>>(),
        move || async move {
            cleanup_flag.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await;
        },
    )
    .await;

    assert!(matches!(result, Err(TransportError::Timeout)));
    assert!(cleanup_started.load(Ordering::SeqCst));
    assert!(started.elapsed() < Duration::from_millis(100));
}

#[tokio::test]
async fn physical_cleanup_finishes_within_bounded_wait() {
    let cleanup_finished = Arc::new(AtomicBool::new(false));
    let cleanup_flag = Arc::clone(&cleanup_finished);
    let started = tokio::time::Instant::now();

    finish_webrtc_cleanup_bounded(Duration::from_millis(50), async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        cleanup_flag.store(true, Ordering::SeqCst);
    })
    .await;

    assert!(started.elapsed() < Duration::from_millis(100));
    assert!(cleanup_finished.load(Ordering::SeqCst));
}

#[tokio::test]
async fn timed_out_physical_cleanup_still_closes_gathered_ice_peer() {
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
    let pc = Arc::new(
        transport
            .api
            .new_peer_connection(RTCConfiguration::default())
            .await
            .expect("peer connection"),
    );
    pc.create_data_channel("cleanup-test", None)
        .await
        .expect("data channel");
    let offer = pc.create_offer(None).await.expect("offer");
    let mut gathering = pc.gathering_complete_promise().await;
    pc.set_local_description(offer)
        .await
        .expect("local description");
    tokio::time::timeout(Duration::from_secs(1), gathering.recv())
        .await
        .expect("ICE gathering timeout");

    let pc_for_cleanup = Arc::clone(&pc);
    finish_webrtc_cleanup_bounded(Duration::from_millis(10), async move {
        // Model the production close path reaching an awaited library stage
        // after the caller's bounded wait has elapsed.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = pc_for_cleanup.close().await;
    })
    .await;

    tokio::time::timeout(Duration::from_millis(500), async {
        while pc.connection_state() != RTCPeerConnectionState::Closed {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timed-out cleanup must finish closing the ICE peer");
}

#[tokio::test]
async fn stalled_full_close_still_stops_gathered_ice_transport() {
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
    let pc = Arc::new(
        transport
            .api
            .new_peer_connection(RTCConfiguration::default())
            .await
            .expect("peer connection"),
    );
    pc.create_data_channel("cleanup-test", None)
        .await
        .expect("data channel");
    let offer = pc.create_offer(None).await.expect("offer");
    let mut gathering = pc.gathering_complete_promise().await;
    pc.set_local_description(offer)
        .await
        .expect("local description");
    tokio::time::timeout(Duration::from_secs(1), gathering.recv())
        .await
        .expect("ICE gathering timeout");

    close_peer_connection_with_bounded_full_close(
        Duration::from_millis(10),
        Arc::clone(&pc),
        std::future::pending::<()>(),
    )
    .await;

    assert_eq!(
        pc.dtls_transport().ice_transport().state(),
        ::webrtc::ice_transport::ice_transport_state::RTCIceTransportState::Closed,
        "ICE teardown must not wait behind a stalled SCTP/DTLS/full close"
    );
}

#[tokio::test]
async fn graceful_full_close_runs_before_ice_fallback() {
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
    let pc = Arc::new(
        transport
            .api
            .new_peer_connection(RTCConfiguration::default())
            .await
            .expect("peer connection"),
    );
    pc.create_data_channel("cleanup-test", None)
        .await
        .expect("data channel");
    let offer = pc.create_offer(None).await.expect("offer");
    let mut gathering = pc.gathering_complete_promise().await;
    pc.set_local_description(offer)
        .await
        .expect("local description");
    tokio::time::timeout(Duration::from_secs(1), gathering.recv())
        .await
        .expect("ICE gathering timeout");

    let graceful_started_while_ice_open = Arc::new(AtomicBool::new(false));
    let graceful_flag = Arc::clone(&graceful_started_while_ice_open);
    let pc_for_close = Arc::clone(&pc);
    close_peer_connection_with_bounded_full_close(
        Duration::from_millis(100),
        Arc::clone(&pc),
        async move {
            graceful_flag.store(
                pc_for_close.dtls_transport().ice_transport().state()
                    != ::webrtc::ice_transport::ice_transport_state::RTCIceTransportState::Closed,
                Ordering::SeqCst,
            );
            let _ = pc_for_close.close().await;
        },
    )
    .await;

    assert!(
        graceful_started_while_ice_open.load(Ordering::SeqCst),
        "graceful SCTP/DTLS close must run before the terminal ICE fallback"
    );
}

#[tokio::test]
async fn terminal_session_cleanup_closes_the_peer_connection() {
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
    let pc = Arc::new(
        transport
            .api
            .new_peer_connection(RTCConfiguration::default())
            .await
            .expect("peer connection"),
    );
    let data_channel = pc
        .create_data_channel("cleanup-test", None)
        .await
        .expect("data channel");
    let addr = TransportAddr::from_string(
        "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    transport.pool.lock().await.insert(
        addr.clone(),
        WebRtcConnection {
            session_id: "cleanup-session".to_string(),
            pc: Arc::clone(&pc),
            data_channel,
        },
    );
    transport.ready.lock().await.insert(addr.clone());

    let removed = cleanup_webrtc_session(
        &transport.pool,
        &transport.pending,
        &transport.failed,
        &transport.ready,
        &addr,
        Some("cleanup-session"),
        Some("peer disconnected".to_string()),
    )
    .await;

    assert!(removed);
    assert!(!transport.pool.lock().await.contains_key(&addr));
    assert!(!transport.ready.lock().await.contains(&addr));
    assert_eq!(
        transport.failed.lock().await.get(&addr).map(String::as_str),
        Some("peer disconnected")
    );
    assert_eq!(pc.connection_state(), RTCPeerConnectionState::Closed);
}

#[tokio::test]
async fn fresh_offer_evicts_an_established_session_immediately() {
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
    let pc = Arc::new(
        transport
            .api
            .new_peer_connection(RTCConfiguration::default())
            .await
            .expect("peer connection"),
    );
    let data_channel = pc
        .create_data_channel("replacement-test", None)
        .await
        .expect("data channel");
    let addr = TransportAddr::from_string(
        "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    transport.pool.lock().await.insert(
        addr.clone(),
        WebRtcConnection {
            session_id: "stale-session".to_string(),
            pc,
            data_channel,
        },
    );
    transport.ready.lock().await.insert(addr.clone());

    assert!(
        evict_established_webrtc_session_for_offer(
            &transport.pool,
            &transport.failed,
            &transport.ready,
            &addr,
        )
        .await
    );
    assert!(!transport.pool.lock().await.contains_key(&addr));
    assert!(!transport.ready.lock().await.contains(&addr));
}
