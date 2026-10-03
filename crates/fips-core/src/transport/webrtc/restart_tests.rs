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
