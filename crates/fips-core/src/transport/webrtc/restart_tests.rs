use super::*;
use crate::packet_channel;

async fn transport() -> WebRtcTransport {
    let (packet_tx, _packet_rx) = packet_channel(8);
    let mut transport = WebRtcTransport::new(
        TransportId::new(121),
        None,
        WebRtcConfig {
            stun_servers: Some(Vec::new()),
            resolve_mdns_candidates: Some(false),
            ..Default::default()
        },
        packet_tx,
        &crate::Identity::generate(),
        &NostrDiscoveryConfig::default(),
    )
    .unwrap();
    transport
        .use_canonical_loopback_candidate_profile()
        .unwrap();
    transport.start_async().await.unwrap();
    transport
}

async fn next_offer(transport: &mut WebRtcTransport) -> WebRtcSignal {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(signal) = transport.drain_link_negotiations(1).pop() {
                return LinkNegotiationMessage::decode(&signal.payload)
                    .unwrap()
                    .typed_payload()
                    .unwrap();
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn outbound_creation_reports_connecting_before_the_setup_task_runs() {
    let mut transport = transport().await;
    let peer = crate::Identity::generate();
    let addr = test_webrtc_addr(&peer);
    transport.connect_async(&addr).await.unwrap();

    // The single-threaded executor has not polled the spawned setup task yet.
    // Node polls this public state to decide whether to keep its preparation.
    let resources = transport.resource_snapshot();
    assert_eq!(resources.creating, 1);
    assert_eq!(resources.created_total, 0);
    let state = transport.connection_state_sync(&addr);
    transport.stop_async().await.unwrap();
    assert!(
        matches!(state, ConnectionState::Connecting),
        "An owned setup must not look like a missing connection attempt: {state:?}"
    );
}

#[tokio::test]
async fn outbound_creation_state_covers_active_setup_but_not_failed_or_stopped() {
    let mut transport = transport().await;
    let addr = test_webrtc_addr(&crate::Identity::generate());
    let reservation = transport.physical.reserve(&addr).unwrap();
    let pc = reservation.activate(transport.runtime().new_peer_connection().await.unwrap());
    // This is the production boundary after creation and before publication
    // into pending, while data-channel setup may still be awaiting progress.
    assert_eq!(transport.resource_snapshot().active, 1);
    assert!(transport.pending.lock().await.is_empty());
    let active_state = transport.connection_state_sync(&addr);
    transport
        .failed
        .lock()
        .await
        .insert(addr.clone(), "setup failed".into());
    let failed_state = transport.connection_state_sync(&addr);
    transport.failed.lock().await.remove(&addr);
    transport.physical.stop_accepting();
    let stopped_state = transport.connection_state_sync(&addr);
    close_peer_connection_bounded(pc).await;
    transport.stop_async().await.unwrap();
    assert_eq!(active_state, ConnectionState::Connecting);
    assert_eq!(failed_state, ConnectionState::Failed("setup failed".into()));
    assert_eq!(stopped_state, ConnectionState::None);
    assert_eq!(
        transport.connection_state_sync(&addr),
        ConnectionState::None
    );
}

#[tokio::test(flavor = "current_thread")]
async fn outbound_creation_cleanup_does_not_report_connecting() {
    let mut transport = transport().await;
    let addr = test_webrtc_addr(&crate::Identity::generate());
    let reservation = transport.physical.reserve(&addr).unwrap();
    let pc = reservation.activate(transport.runtime().new_peer_connection().await.unwrap());
    let cleanup = start_peer_connection_cleanup(pc);
    assert_eq!(
        transport.physical.phase(&addr),
        Some(PhysicalPhase::Closing)
    );
    let closing_state = transport.connection_state_sync(&addr);
    tokio::time::timeout(Duration::from_secs(3), cleanup.wait())
        .await
        .expect("physical cleanup completes");
    let resources = transport.resource_snapshot();
    assert_eq!(resources.created_total, resources.closed_total);
    assert_eq!(closing_state, ConnectionState::None);
    assert_eq!(
        transport.connection_state_sync(&addr),
        ConnectionState::None
    );
    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn close_and_stop_cancel_recovery_after_new_peer_creation() {
    for stop in [false, true] {
        let mut transport = transport().await;
        let peer = crate::Identity::generate();
        let addr = test_webrtc_addr(&peer);
        transport
            .recovering
            .lock()
            .unwrap()
            .insert(addr.clone(), "old-offer".into());
        let guard = WebRtcRecoveryGuard {
            recovering: Arc::clone(&transport.recovering),
            addr: addr.clone(),
            session_id: "old-offer".into(),
        };
        let reservation = transport.physical.reserve(&addr).unwrap();
        let runtime = transport.runtime();
        let remote = addr.clone();
        // Block publication into pending after creation, beyond the recovery
        // task's initial guard check. This is a real RTCPeerConnection.
        let pool = Arc::clone(&transport.pool);
        let held = pool.lock().await;
        let task = tokio::spawn(async move {
            assert!(guard.is_current());
            runtime
                .start_outbound(
                    remote,
                    reservation,
                    tokio::time::Instant::now() + Duration::from_secs(5),
                    None,
                    Some(guard),
                )
                .await
        });
        transport.dial_tasks.lock().unwrap().push(task);
        tokio::time::timeout(Duration::from_secs(2), async {
            while transport.resource_snapshot().created_total != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("replacement PC created before cancellation");
        let recovering = Arc::clone(&transport.recovering);
        let physical = transport.physical.clone();
        let release = async move {
            while if stop {
                physical.is_accepting()
            } else {
                recovering.lock().unwrap().contains_key(&addr)
            } {
                tokio::task::yield_now().await;
            }
            drop(held);
        };
        if stop {
            let (result, ()) = tokio::join!(transport.stop_async(), release);
            result.unwrap();
        } else {
            let close_addr = test_webrtc_addr(&peer);
            tokio::join!(transport.close_connection_async(&close_addr), release);
            assert!(
                transport
                    .physical
                    .wait_for_quiescence(Duration::from_secs(3))
                    .await
            );
            transport.stop_async().await.unwrap();
        }
        let resources = transport.resource_snapshot();
        assert_eq!(resources.created_total, resources.closed_total);
        assert_eq!(
            resources.creating + resources.active + resources.closing + resources.abandoned,
            0
        );
        assert!(transport.recovering.lock().unwrap().is_empty());
        assert!(transport.pending.lock().await.is_empty());
        assert!(transport.drain_link_negotiations(8).is_empty());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_close_before_outbound_setup_does_not_leave_an_offer_or_peer() {
    let mut transport = transport().await;
    let addr = test_webrtc_addr(&crate::Identity::generate());
    transport.connect_async(&addr).await.unwrap();
    // No executor turn has run the outbound task yet. Closing must retire
    // its existing physical reservation, even though pending is still empty.
    transport.close_connection_async(&addr).await;
    let quiescent = transport
        .physical
        .wait_for_quiescence(Duration::from_secs(2))
        .await;
    let pending = transport.pending.lock().await.len();
    let offers = transport.drain_link_negotiations(8).len();
    let resources = transport.resource_snapshot();
    transport.stop_async().await.unwrap();

    assert!(
        quiescent,
        "Closed setup left a live physical owner: {resources:?}"
    );
    assert_eq!(pending, 0, "Closed setup published a pending dial");
    assert_eq!(offers, 0, "Closed setup sent an offer after explicit close");
    assert_eq!(resources.created_total, 0, "Cancelled setup created a PC");
}

#[tokio::test]
async fn explicit_close_rejects_outbound_publication_after_peer_activation() {
    assert_close_rejects_outbound_publication(false).await;
}

#[tokio::test]
async fn explicit_close_detached_rejects_publication_after_peer_activation() {
    assert_close_rejects_outbound_publication(true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_close_cancellation_allows_a_fresh_dial_to_the_same_peer() {
    let mut transport = transport().await;
    let addr = test_webrtc_addr(&crate::Identity::generate());
    transport.connect_async(&addr).await.unwrap();
    transport.close_connection_async(&addr).await;
    assert_eq!(
        transport.connection_state_sync(&addr),
        ConnectionState::None
    );
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(2))
            .await
    );

    transport.connect_async(&addr).await.unwrap();
    let offer = next_offer(&mut transport).await;
    assert_eq!(offer.kind, LinkNegotiationKind::Offer);
    assert_eq!(transport.pending.lock().await.len(), 1);
    transport.close_connection_async(&addr).await;
    assert!(
        transport
            .physical
            .wait_for_quiescence(Duration::from_secs(2))
            .await
    );
    assert_eq!(
        transport.connection_state_sync(&addr),
        ConnectionState::None
    );
    let resources = transport.resource_snapshot();
    transport.stop_async().await.unwrap();
    assert_eq!(resources.created_total, 1);
    assert_eq!(resources.closed_total, 1);
    assert_eq!(resources.peak_physical, 1);
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_close_cancellation_is_rechecked_after_publication_lock_wait() {
    let mut transport = transport().await;
    let addr = test_webrtc_addr(&crate::Identity::generate());
    let runtime = transport.runtime();
    let pc = transport
        .physical
        .reserve(&addr)
        .unwrap()
        .activate(runtime.new_peer_connection().await.unwrap());
    let pool = Arc::clone(&transport.pool);
    let held = pool.lock().await;
    let publish_pc = Arc::clone(&pc);
    let publish_addr = addr.clone();
    let publishing = tokio::spawn(async move {
        runtime
            .try_reserve_pending(
                &publish_addr,
                PendingDial {
                    session_id: "waiting-setup".into(),
                    phase_owner_id: "waiting-setup".into(),
                    pc: publish_pc,
                    created_at_ms: now_ms(),
                    origin: PendingDialOrigin::Local,
                    awaiting_answer: false,
                    deadline: tokio::time::Instant::now() + Duration::from_secs(5),
                },
                None,
            )
            .await
    });
    tokio::task::yield_now().await;
    // Close claims cancellation before waiting behind the same pool lock.
    tokio::join!(transport.close_connection_async(&addr), async {
        drop(held)
    });
    let admitted = publishing.await.unwrap();
    close_peer_connection_bounded(pc).await;
    transport.stop_async().await.unwrap();
    assert!(
        !admitted,
        "Publication used a pre-lock cancellation snapshot"
    );
}

async fn assert_close_rejects_outbound_publication(detached: bool) {
    let mut transport = transport().await;
    let addr = test_webrtc_addr(&crate::Identity::generate());
    let runtime = transport.runtime();
    let reservation = transport.physical.reserve(&addr).unwrap();
    let pc = reservation.activate(runtime.new_peer_connection().await.unwrap());
    assert_eq!(transport.resource_snapshot().active, 1);
    assert!(transport.pending.lock().await.is_empty());
    if detached {
        transport
            .close_connection_detached_task(&addr)
            .unwrap()
            .await
            .unwrap();
    } else {
        transport.close_connection_async(&addr).await;
    }
    // Exercise the real publication boundary with a real activated PC,
    // resuming setup after close has already observed no logical owner.
    let admitted = runtime
        .try_reserve_pending(
            &addr,
            PendingDial {
                session_id: "closed-setup".into(),
                phase_owner_id: "closed-setup".into(),
                pc: Arc::clone(&pc),
                created_at_ms: now_ms(),
                origin: PendingDialOrigin::Local,
                awaiting_answer: false,
                deadline: tokio::time::Instant::now() + Duration::from_secs(5),
            },
            None,
        )
        .await;
    transport.close_connection_async(&addr).await;
    close_peer_connection_bounded(pc).await;
    transport.stop_async().await.unwrap();
    let resources = transport.resource_snapshot();
    assert!(
        !admitted,
        "Retired setup was republished (detached={detached})"
    );
    assert_eq!(resources.created_total, resources.closed_total);
    assert_eq!(resources.creating + resources.active + resources.closing, 0);
}

#[tokio::test]
async fn stale_answer_cannot_claim_the_replacement_offer() {
    let mut transport = transport().await;
    let peer = crate::Identity::generate();
    let addr = test_webrtc_addr(&peer);
    transport.connect_async(&addr).await.unwrap();
    let old = next_offer(&mut transport).await;
    transport
        .authenticated_session_restarted(peer.pubkey_full())
        .await;
    let replacement = next_offer(&mut transport).await;
    assert_ne!(replacement.negotiation_id, old.negotiation_id);
    let stale = WebRtcSignal {
        kind: LinkNegotiationKind::Answer,
        ..old
    };
    assert!(
        transport
            .runtime()
            .handle_answer(stale, &addr.to_string())
            .await
            .is_err()
    );
    assert!(
        transport
            .pending
            .lock()
            .await
            .get(&addr)
            .unwrap()
            .awaiting_answer
    );
    assert_eq!(
        transport
            .pending
            .lock()
            .await
            .get(&addr)
            .unwrap()
            .session_id,
        replacement.negotiation_id
    );
    transport.stop_async().await.unwrap();
}

#[tokio::test]
async fn restart_preserves_answered_inbound_and_expired_negotiations() {
    for state in ["answered", "inbound", "expired"] {
        let mut transport = transport().await;
        let peer = crate::Identity::generate();
        let addr = test_webrtc_addr(&peer);
        transport.connect_async(&addr).await.unwrap();
        let offer = next_offer(&mut transport).await;
        {
            let mut pending = transport.pending.lock().await;
            let dial = pending.get_mut(&addr).unwrap();
            match state {
                "answered" => dial.awaiting_answer = false,
                "inbound" => dial.origin = PendingDialOrigin::Remote,
                "expired" => dial.deadline = tokio::time::Instant::now(),
                _ => unreachable!(),
            }
        }
        transport
            .authenticated_session_restarted(peer.pubkey_full())
            .await;
        assert_eq!(
            transport
                .pending
                .lock()
                .await
                .get(&addr)
                .unwrap()
                .session_id,
            offer.negotiation_id
        );
        assert!(transport.recovering.lock().unwrap().is_empty());
        assert!(transport.drain_link_negotiations(8).is_empty());
        assert_eq!(transport.resource_snapshot().created_total, 1);
        transport.stop_async().await.unwrap();
    }
}
