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
