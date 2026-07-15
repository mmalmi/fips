use super::*;
use crate::packet_channel;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(unix)]
const DISABLED_MDNS_ISOLATION_CHILD: &str = "FIPS_DISABLED_MDNS_ISOLATION_CHILD";
#[cfg(unix)]
const SHARED_MDNS_ISOLATION_CHILD: &str = "FIPS_SHARED_MDNS_ISOLATION_CHILD";

#[cfg(unix)]
fn run_mdns_isolation_child(test_name: &str, environment: &str) {
    let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .arg(test_name)
        .arg("--exact")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(environment, "1")
        .output()
        .expect("isolated mDNS descriptor child");
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        "isolated mDNS descriptor child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn bound_mdns_socket_count() -> usize {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit initializes `limit` on success.
    let limit = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } == 0 {
        // SAFETY: the successful call initialized `limit`.
        unsafe { limit.assume_init() }.rlim_cur.min(4_096) as i32
    } else {
        1_024
    };
    (0..limit)
        .filter(|fd| {
            let mut address = std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed();
            let mut length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            // SAFETY: address and length are valid writable getsockname outputs.
            if unsafe {
                libc::getsockname(
                    *fd,
                    address.as_mut_ptr().cast::<libc::sockaddr>(),
                    &mut length,
                )
            } != 0
            {
                return false;
            }
            // SAFETY: getsockname initialized a sockaddr of the reported family.
            let address = unsafe { address.assume_init() };
            match address.ss_family as i32 {
                libc::AF_INET => {
                    // SAFETY: AF_INET identifies sockaddr_in.
                    let address = unsafe {
                        &*((&address as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>())
                    };
                    u16::from_be(address.sin_port) == 5_353
                }
                libc::AF_INET6 => {
                    // SAFETY: AF_INET6 identifies sockaddr_in6.
                    let address = unsafe {
                        &*((&address as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>())
                    };
                    u16::from_be(address.sin6_port) == 5_353
                }
                _ => false,
            }
        })
        .count()
}

#[cfg(unix)]
async fn gathered_test_peer(transport: &WebRtcTransport, name: &str) -> ManagedPeer {
    let addr = TransportAddr::from_string(name);
    let pc = transport
        .physical
        .reserve(&addr)
        .expect("physical test permit")
        .activate(
            transport
                .api
                .new_peer_connection(RTCConfiguration::default())
                .await
                .expect("test peer connection"),
        );
    pc.create_data_channel("mDNS-isolation", None)
        .await
        .expect("test data channel");
    let offer = pc.create_offer(None).await.expect("test offer");
    let mut gathering = pc.gathering_complete_promise().await;
    pc.set_local_description(offer)
        .await
        .expect("test local description");
    let _ = tokio::time::timeout(Duration::from_secs(1), gathering.recv()).await;
    pc
}

#[tokio::test]
async fn shared_resolver_bounds_waiters_and_cleans_up_cancellation() {
    let resolver = SharedMdnsResolver::new(true, 3).expect("shared mDNS resolver");
    let sdp = (0..9)
        .map(|index| {
            format!(
                "a=candidate:{index} 1 UDP 1 browser-{index}.local 5000 typ host\r\n"
            )
        })
        .collect::<String>();
    let task_resolver = resolver.clone();
    let task = tokio::spawn(async move { task_resolver.resolve_sdp(&sdp).await });

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let snapshot = resolver.snapshot();
            if snapshot.active_waiters == 3 {
                assert_eq!(snapshot.owner_count, 1);
                assert_eq!(snapshot.max_waiters, 3);
                assert_eq!(snapshot.peak_waiters, 3);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("bounded mDNS waiters start");

    task.abort();
    let _ = task.await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while resolver.snapshot().active_waiters != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled mDNS waiters are removed");
    assert_eq!(resolver.snapshot().owner_count, 1);
}

#[tokio::test]
async fn disabled_resolver_strips_mdns_candidates_without_starting_an_owner() {
    let resolver = SharedMdnsResolver::new(false, 32).expect("disabled mDNS resolver");
    let native_sdp = "v=0\r\na=candidate:1 1 UDP 1 192.0.2.1 5000 typ host\r\n";
    assert_eq!(resolver.resolve_sdp(native_sdp).await.unwrap(), native_sdp);
    assert_eq!(resolver.snapshot().owner_count, 0);

    let browser_sdp =
        "v=0\r\na=candidate:1 1 UDP 1 browser-host.local 5000 typ host\r\na=candidate:2 1 UDP 1 198.51.100.2 5001 typ srflx\r\n";
    let resolved = resolver.resolve_sdp(browser_sdp).await.unwrap();
    assert!(!resolved.contains("browser-host.local"));
    assert!(resolved.contains("198.51.100.2"));
    assert_eq!(resolver.snapshot().owner_count, 0);
}

#[cfg(unix)]
#[test]
fn fully_disabled_peer_connections_open_no_mdns_descriptors() {
    if std::env::var_os(DISABLED_MDNS_ISOLATION_CHILD).is_none() {
        return run_mdns_isolation_child(
            "transport::webrtc::tests::fully_disabled_peer_connections_open_no_mdns_descriptors",
            DISABLED_MDNS_ISOLATION_CHILD,
        );
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("mDNS isolation runtime")
        .block_on(fully_disabled_peer_connections_open_no_mdns_descriptors_inner());
}

#[cfg(unix)]
async fn fully_disabled_peer_connections_open_no_mdns_descriptors_inner() {
    let baseline = bound_mdns_socket_count();
    let identity = crate::Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(76),
        None,
        WebRtcConfig {
            max_connections: Some(4),
            stun_servers: Some(Vec::new()),
            resolve_mdns_candidates: Some(false),
            ..WebRtcConfig::default()
        },
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("fully disabled WebRTC transport");
    assert_eq!(transport.mdns_resolver.snapshot().owner_count, 0);

    let mut peers = Vec::new();
    for index in 0..4 {
        peers.push(gathered_test_peer(&transport, &format!("disabled-peer-{index}")).await);
    }
    assert_eq!(bound_mdns_socket_count(), baseline);
    for peer in peers {
        start_peer_connection_cleanup(peer);
    }
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
    assert_eq!(transport.resource_snapshot().abandoned, 0);
    assert_eq!(transport.mdns_resolver.snapshot().owner_count, 0);
    assert_eq!(bound_mdns_socket_count(), baseline);
}

#[cfg(unix)]
#[test]
fn shared_resolver_plateau_is_constant_across_queries_and_peer_connections() {
    if std::env::var_os(SHARED_MDNS_ISOLATION_CHILD).is_none() {
        return run_mdns_isolation_child(
            "transport::webrtc::tests::shared_resolver_plateau_is_constant_across_queries_and_peer_connections",
            SHARED_MDNS_ISOLATION_CHILD,
        );
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("mDNS isolation runtime")
        .block_on(shared_resolver_plateau_is_constant_across_queries_and_peer_connections_inner());
}

#[cfg(unix)]
async fn shared_resolver_plateau_is_constant_across_queries_and_peer_connections_inner() {
    let cold_mdns = bound_mdns_socket_count();
    let identity = crate::Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(77),
        None,
        WebRtcConfig {
            max_connections: Some(4),
            stun_servers: Some(Vec::new()),
            ..WebRtcConfig::default()
        },
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("shared-resolver WebRTC transport");

    for query in 0..2 {
        let resolver = transport.mdns_resolver.clone();
        let task = tokio::spawn(async move {
            resolver
                .resolve_sdp(&format!(
                    "a=candidate:{query} 1 UDP 1 plateau-{query}.local 5000 typ host\r\n"
                ))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while transport.mdns_resolver.snapshot().active_waiters != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shared resolver query starts");
        task.abort();
        let _ = task.await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while transport.mdns_resolver.snapshot().active_waiters != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shared resolver cancellation clears");
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let warm_mdns = bound_mdns_socket_count();
    assert!(warm_mdns > cold_mdns, "shared owner must open its fixed mDNS sockets");
    assert_eq!(transport.mdns_resolver.snapshot().owner_count, 1);

    let mut peers = Vec::new();
    for index in 0..4 {
        peers.push(gathered_test_peer(&transport, &format!("shared-peer-{index}")).await);
    }
    assert_eq!(
        bound_mdns_socket_count(),
        warm_mdns,
        "per-PC mDNS must remain disabled after the shared owner starts"
    );
    for peer in peers {
        start_peer_connection_cleanup(peer);
    }
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(3))
            .await
    );
    transport
        .mdns_resolver
        .stop()
        .await
        .expect("stop shared resolver");
    tokio::time::timeout(Duration::from_secs(1), async {
        while bound_mdns_socket_count() > cold_mdns {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("shared resolver descriptors return to cold baseline");
    assert_eq!(transport.mdns_resolver.snapshot().owner_count, 0);
}

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
        version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
        negotiation_id: "abc".to_string(),
        link_type: "webrtc".to_string(),
        kind: LinkNegotiationKind::Offer,
        created_at_ms: 1,
        expires_at_ms: 2,
        payload: WebRtcSignalPayload {
            sdp: Some("v=0".to_string()),
            candidates: None,
        },
    };
    let json = serde_json::to_string(&signal).unwrap();
    assert!(json.contains(r#""negotiationId":"abc""#));
    assert!(json.contains(r#""linkType":"webrtc""#));
    assert!(json.contains(r#""createdAtMs":1"#));
    assert!(json.contains(r#""expiresAtMs":2"#));
}

#[test]
fn simultaneous_webrtc_offers_have_one_deterministic_winner() {
    let smaller = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let larger = "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    assert!(incoming_offer_wins_glare(larger, smaller));
    assert!(!incoming_offer_wins_glare(smaller, larger));
    assert_eq!(
        pooled_replacement_disposition(larger, smaller),
        PooledOfferDisposition::Accept
    );
    assert_eq!(
        pooled_replacement_disposition(smaller, larger),
        PooledOfferDisposition::Redial
    );
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

#[tokio::test]
async fn webrtc_queues_negotiation_for_fips_session_without_relay_client() {
    let identity = crate::Identity::generate();
    let remote = crate::Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let discovery = NostrDiscoveryConfig {
        advert_relays: vec!["wss://adverts.example".to_string()],
        ..NostrDiscoveryConfig::default()
    };
    let mut transport = WebRtcTransport::new(
        TransportId::new(1),
        None,
        WebRtcConfig::default(),
        packet_tx,
        &identity,
        &discovery,
    )
    .expect("WebRTC transport");

    let remote_nostr = nostr::PublicKey::from_slice(&remote.pubkey().serialize())
        .expect("remote Nostr pubkey");
    let now = now_ms();
    let signal = WebRtcSignal {
        version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
        negotiation_id: "test-session".to_string(),
        link_type: "webrtc".to_string(),
        kind: LinkNegotiationKind::Offer,
        created_at_ms: now,
        expires_at_ms: now + SIGNAL_TTL_MS,
        payload: WebRtcSignalPayload {
            sdp: Some("v=0".to_string()),
            candidates: None,
        },
    };
    transport
        .signaling
        .send_signal(remote_nostr, &signal)
        .await
        .expect("queue FIPS session signal");
    let queued = transport.drain_link_negotiations(1);
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].recipient, *remote.node_addr());
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
async fn physical_cleanup_stops_gathered_ice_and_releases_capacity() {
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

    close_peer_connection_bounded(pc).await;

    assert_eq!(
        raw_pc.dtls_transport().ice_transport().state(),
        ::webrtc::ice_transport::ice_transport_state::RTCIceTransportState::Closed,
        "physical cleanup must force terminal ICE teardown"
    );
    drop(raw_pc);
    transport
        .physical
        .wait_for_quiescence(Duration::from_secs(3))
        .await
        .then_some(())
        .expect("physical cleanup quiesces");
    assert_eq!(transport.resource_snapshot().active, 0);
    assert_eq!(transport.resource_snapshot().closing, 0);
    assert_eq!(transport.resource_snapshot().created_total, 1);
    assert_eq!(transport.resource_snapshot().closed_total, 1);
}

#[tokio::test]
async fn straggler_peer_reference_keeps_cleanup_owned_and_replacement_blocked() {
    let identity = crate::Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(73),
        None,
        WebRtcConfig {
            max_connections: Some(1),
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
    let reservation = transport.physical.reserve(&addr).expect("physical permit");
    let pc = reservation.activate(
        transport
            .api
            .new_peer_connection(RTCConfiguration::default())
            .await
            .expect("peer connection"),
    );
    let straggler = pc.raw();
    let data_channel = straggler
        .create_data_channel("straggler-test", None)
        .await
        .expect("data channel");
    let offer = straggler.create_offer(None).await.expect("offer");
    let mut gathering = straggler.gathering_complete_promise().await;
    straggler
        .set_local_description(offer)
        .await
        .expect("local description");
    tokio::time::timeout(Duration::from_secs(1), gathering.recv())
        .await
        .expect("ICE gathering timeout");
    drop(data_channel);

    let cleanup = tokio::spawn(close_peer_connection_bounded(pc));
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = transport.resource_snapshot();
            if snapshot.closing == 1 && snapshot.cleanup_inflight == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("physical cleanup retains ownership");
    assert!(matches!(
        transport.physical.reserve(&addr),
        Err(PhysicalReserveError::PeerBusy(PhysicalPhase::Closing))
    ));

    drop(straggler);
    cleanup.await.expect("bounded cleanup caller");
    transport
        .physical
        .wait_for_quiescence(Duration::from_secs(3))
        .await
        .then_some(())
        .expect("physical cleanup quiesces");
    let snapshot = transport.resource_snapshot();
    assert_eq!(snapshot.active + snapshot.closing, 0);
    assert_eq!(snapshot.cleanup_inflight, 0);
    assert_eq!(snapshot.created_total, snapshot.closed_total);
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
    let data_channel = pc
        .create_data_channel("cleanup-test", None)
        .await
        .expect("data channel");
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
    assert_eq!(raw_pc.connection_state(), RTCPeerConnectionState::Closed);
}

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
        Arc::clone(&runtime.pool),
        Arc::clone(&runtime.pending),
        Arc::clone(&runtime.failed),
        Arc::clone(&runtime.ready),
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

    assert!(weak_pool.upgrade().is_none(), "callback maps must not form an ownership cycle");
    assert!(resources.wait_for_quiescence(Duration::from_secs(3)).await);
    let snapshot = resources.snapshot();
    assert_eq!(snapshot.created_total, snapshot.closed_total);
    assert_eq!(snapshot.abandoned, 0);
}

#[tokio::test]
async fn invalid_answer_immediately_removes_and_closes_its_pending_session() {
    let identity = crate::Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(74),
        None,
        WebRtcConfig::default(),
        packet_tx,
        &identity,
        &NostrDiscoveryConfig::default(),
    )
    .expect("WebRTC transport");
    let remote_key =
        "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let addr = TransportAddr::from_string(remote_key);
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
            session_id: "invalid-answer".into(),
            pc: Arc::clone(&pc),
            created_at_ms: now_ms(),
            origin: PendingDialOrigin::Local,
        },
    );
    drop(pc);

    let now = now_ms();
    let signal = WebRtcSignal {
        version: crate::transport::link_negotiation::LINK_NEGOTIATION_VERSION,
        negotiation_id: "invalid-answer".into(),
        link_type: "webrtc".into(),
        kind: LinkNegotiationKind::Answer,
        created_at_ms: now,
        expires_at_ms: now + SIGNAL_TTL_MS,
        payload: WebRtcSignalPayload {
            sdp: Some("not valid SDP".into()),
            candidates: None,
        },
    };
    assert!(
        transport
            .runtime()
            .handle_answer(signal, remote_key)
            .await
            .is_err()
    );
    assert!(!transport.pending.lock().await.contains_key(&addr));
    assert!(transport.failed.lock().await.contains_key(&addr));
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
async fn outbound_post_attach_error_immediately_closes_its_pending_session() {
    let identity = crate::Identity::generate();
    let (packet_tx, _packet_rx) = packet_channel(1);
    let transport = WebRtcTransport::new(
        TransportId::new(75),
        None,
        WebRtcConfig {
            ice_gather_timeout_ms: Some(50),
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
    let reservation = transport.physical.reserve(&addr).expect("physical permit");
    let mut runtime = transport.runtime();
    let (closed_tx, closed_rx) = mpsc::unbounded_channel();
    drop(closed_rx);
    runtime.signaling = FipsSignalSender::new(closed_tx);

    assert!(
        runtime
            .start_outbound(addr.clone(), reservation)
            .await
            .is_err()
    );
    assert!(!transport.pending.lock().await.contains_key(&addr));
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
    assert_eq!(raw_pc.connection_state(), RTCPeerConnectionState::Closed);
}
