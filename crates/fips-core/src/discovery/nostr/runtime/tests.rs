use super::*;
use crate::discovery::nostr::{OverlayTransportKind, TraversalAddress};

#[test]
fn event_channel_capacity_tracks_open_and_inbound_limits() {
    let mut config = NostrDiscoveryConfig {
        open_discovery_max_pending: 8,
        max_concurrent_incoming_offers: 16,
        ..Default::default()
    };
    assert_eq!(event_channel_capacity(&config), 64);

    config.open_discovery_max_pending = 32;
    config.max_concurrent_incoming_offers = 4;
    assert_eq!(event_channel_capacity(&config), 128);

    config.open_discovery_max_pending = 0;
    config.max_concurrent_incoming_offers = 0;
    assert_eq!(event_channel_capacity(&config), 64);

    config.open_discovery_max_pending = 5000;
    config.max_concurrent_incoming_offers = 1;
    assert_eq!(event_channel_capacity(&config), 4096);
}

#[test]
fn advert_publish_retry_delay_backs_off_to_short_cap() {
    assert_eq!(
        next_advert_publish_retry_delay(ADVERT_PUBLISH_RETRY_INITIAL),
        Duration::from_secs(4)
    );
    assert_eq!(
        next_advert_publish_retry_delay(Duration::from_secs(16)),
        Duration::from_secs(30)
    );
    assert_eq!(
        next_advert_publish_retry_delay(Duration::from_secs(30)),
        ADVERT_PUBLISH_RETRY_MAX
    );
}

#[test]
fn signal_answer_wait_is_bounded_by_attempt_timeout() {
    let config = NostrDiscoveryConfig {
        signal_ttl_secs: 120,
        attempt_timeout_secs: 10,
        ..Default::default()
    };
    assert_eq!(signal_answer_timeout(&config), Duration::from_secs(10));

    let config = NostrDiscoveryConfig {
        signal_ttl_secs: 5,
        attempt_timeout_secs: 10,
        ..Default::default()
    };
    assert_eq!(signal_answer_timeout(&config), Duration::from_secs(5));
}

#[test]
fn mesh_signaled_initiators_use_direct_refresh_admission() {
    let discovery = NostrDiscovery::new_for_test();

    discovery.set_outbound_admission(false);
    discovery.set_direct_refresh_admission(true);

    assert!(
        !discovery.traversal_initiator_admission_allowed(false),
        "ordinary Nostr traversal should still obey peer-slot capacity"
    );
    assert!(
        discovery.traversal_initiator_admission_allowed(true),
        "mesh-signaled direct refresh should bypass only the peer-slot cap"
    );

    discovery.set_direct_refresh_admission(false);
    assert!(
        !discovery.traversal_initiator_admission_allowed(true),
        "mesh-signaled direct refresh should still obey connection/link capacity"
    );
}

#[test]
fn ambient_advert_subscription_is_open_policy_only() {
    let discovery = NostrDiscovery::new_for_test();
    assert!(!discovery.should_subscribe_ambient_adverts());

    let open = NostrDiscovery::new_for_test_with_config(NostrDiscoveryConfig {
        policy: crate::config::NostrDiscoveryPolicy::Open,
        ..Default::default()
    });
    assert!(open.should_subscribe_ambient_adverts());

    let disabled = NostrDiscovery::new_for_test_with_config(NostrDiscoveryConfig {
        policy: crate::config::NostrDiscoveryPolicy::Disabled,
        ..Default::default()
    });
    assert!(!disabled.should_subscribe_ambient_adverts());
}

#[tokio::test]
async fn duplicate_connect_request_reports_already_active() {
    let discovery = Arc::new(NostrDiscovery::new_for_test());
    let peer_npub = nostr::Keys::generate()
        .public_key()
        .to_bech32()
        .expect("peer npub");
    let peer_config = PeerConfig::new(peer_npub, "udp", "nat");

    assert!(
        discovery
            .request_connect_with_mesh_signaling(peer_config.clone(), true)
            .await,
        "first request should spawn an initiator"
    );
    assert!(
        !discovery
            .request_connect_with_mesh_signaling(peer_config, true)
            .await,
        "second request for the same peer should be deduped"
    );
    assert_eq!(discovery.active_initiator_count_for_test().await, 1);
}

#[tokio::test]
async fn duplicate_connect_request_canonicalizes_hex_and_npub() {
    let discovery = Arc::new(NostrDiscovery::new_for_test());
    let peer_pubkey = nostr::Keys::generate().public_key();
    let peer_npub = peer_pubkey.to_bech32().expect("peer npub");
    let peer_hex = peer_pubkey.to_hex();

    assert!(
        discovery
            .request_connect_with_mesh_signaling(PeerConfig::new(peer_npub, "udp", "nat"), true)
            .await,
        "first request should spawn an initiator"
    );
    assert!(
        !discovery
            .request_connect_with_mesh_signaling(PeerConfig::new(peer_hex, "udp", "nat"), true)
            .await,
        "same pubkey with a different edge spelling should be deduped"
    );
    assert_eq!(discovery.active_initiator_count_for_test().await, 1);
}

#[tokio::test]
async fn advert_cache_lookup_canonicalizes_hex_and_npub() {
    let discovery = NostrDiscovery::new_for_test();
    let peer_pubkey = nostr::Keys::generate().public_key();
    let peer_npub = peer_pubkey.to_bech32().expect("peer npub");
    let peer_hex = peer_pubkey.to_hex();
    let endpoint = OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: "nat".to_string(),
    };
    let advert = NostrDiscovery::cached_advert_for_test(peer_npub.clone(), endpoint.clone(), 42);

    discovery.insert_advert_for_test(peer_npub, advert).await;

    assert_eq!(
        discovery.cached_advert_endpoints_for_peer(&peer_hex).await,
        Some(vec![endpoint])
    );
}

#[tokio::test]
async fn mesh_signal_channel_roundtrips_offer() {
    let discovery = NostrDiscovery::new_for_test();
    let offer = TraversalOffer {
        message_type: "offer".to_string(),
        session_id: "session".to_string(),
        issued_at: 1,
        expires_at: 2,
        nonce: "nonce".to_string(),
        sender_npub: discovery.npub.clone(),
        recipient_npub: "npub1peer".to_string(),
        reflexive_address: None,
        local_addresses: Vec::new(),
        stun_server: None,
    };

    assert!(
        discovery
            .emit_mesh_signal(MeshTraversalSignal::Offer {
                peer_npub: "npub1peer".to_string(),
                offer: offer.clone(),
            })
            .await
    );

    let signals = discovery.drain_mesh_signals().await;
    assert_eq!(signals.len(), 1);
    match &signals[0] {
        MeshTraversalSignal::Offer {
            peer_npub,
            offer: got,
        } => {
            assert_eq!(peer_npub, "npub1peer");
            assert_eq!(got, &offer);
        }
        MeshTraversalSignal::Answer { .. } => panic!("expected mesh offer"),
    }
}

#[tokio::test]
async fn mesh_answer_resolves_pending_offer_without_nostr_event() {
    let discovery = NostrDiscovery::new_for_test();
    let (tx, rx) = oneshot::channel();
    discovery
        .pending_answers
        .lock()
        .await
        .insert("offer-nonce".to_string(), tx);
    let answer = TraversalAnswer {
        message_type: "answer".to_string(),
        session_id: "session".to_string(),
        issued_at: 1,
        expires_at: 2,
        nonce: "answer-nonce".to_string(),
        sender_npub: "npub1peer".to_string(),
        recipient_npub: discovery.npub.clone(),
        in_reply_to: "offer-nonce".to_string(),
        accepted: true,
        reflexive_address: None,
        local_addresses: vec![TraversalAddress {
            protocol: "udp".to_string(),
            ip: "127.0.0.1".to_string(),
            port: 51820,
        }],
        stun_server: None,
        punch: None,
        reason: None,
        offer_received_at: None,
    };

    discovery
        .receive_mesh_traversal_answer(answer.clone(), "npub1peer".to_string())
        .await;

    let envelope = rx.await.expect("pending answer should resolve");
    assert_eq!(envelope.payload, answer);
    assert!(envelope.event_id.is_none());
    assert_eq!(envelope.sender_npub, "npub1peer");
}
