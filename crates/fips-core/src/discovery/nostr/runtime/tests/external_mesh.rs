use super::*;

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

#[test]
fn ambient_advert_filter_targets_normal_nostr_adverts_for_app() {
    let discovery = NostrDiscovery::new_for_test_with_config(NostrDiscoveryConfig {
        app: "fips-test".to_string(),
        ..Default::default()
    });

    let filter = serde_json::to_value(discovery.ambient_advert_filter()).unwrap();

    assert_eq!(filter["kinds"], serde_json::json!([ADVERT_KIND]));
    assert_eq!(filter["#d"], serde_json::json!(["fips-test"]));
}

#[tokio::test]
async fn external_peerfinding_signs_local_advert_without_relay_selection() {
    let discovery = Arc::new(NostrDiscovery::new_for_test_with_config(
        NostrDiscoveryConfig {
            advertise: true,
            peerfinding_source: NostrPeerfindingSource::External,
            app: "fips-test".to_string(),
            advert_relays: vec!["wss://must-not-be-used.example".to_string()],
            ..Default::default()
        },
    ));
    let advert = OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![OverlayEndpointAdvert {
            transport: OverlayTransportKind::Tcp,
            addr: "8.8.8.8:443".to_string(),
        }],
        stun_servers: None,
    };
    discovery
        .update_local_advert(Some(advert))
        .await
        .expect("cache local advert");

    let event = discovery
        .local_advert_event()
        .await
        .expect("sign local advert")
        .expect("local advert event");

    assert!(event.verify().is_ok());
    assert!(NostrDiscovery::advert_event_targets_app(
        &event,
        "fips-test"
    ));
    assert!(discovery.current_advert_event_id.read().await.is_none());
}

#[tokio::test]
async fn external_peerfinding_never_queries_configured_advert_relays() {
    let peer = nostr::Keys::generate();
    let peer_npub = peer.public_key().to_bech32().expect("peer npub");
    let discovery = NostrDiscovery::new_for_test_with_config(NostrDiscoveryConfig {
        peerfinding_source: NostrPeerfindingSource::External,
        advert_relays: vec!["wss://must-not-be-used.example".to_string()],
        ..Default::default()
    });

    let error = discovery
        .advert_endpoints_for_peer(&peer_npub)
        .await
        .expect_err("external provider has not supplied this peer");

    assert!(matches!(error, BootstrapError::MissingAdvert(_)));
    assert_eq!(
        discovery.refetch_advert_for_stale_check(&peer_npub).await,
        NostrRefetchOutcome::Skipped
    );
}

#[tokio::test]
async fn externally_ingested_cache_resolves_without_internal_relay_client() {
    let peer = nostr::Keys::generate();
    let peer_npub = peer.public_key().to_bech32().expect("peer npub");
    let discovery = NostrDiscovery::new_for_test_with_config(NostrDiscoveryConfig {
        app: "fips-test".to_string(),
        advert_relays: Vec::new(),
        ..Default::default()
    });
    let event = signed_runtime_overlay_advert_event(
        &peer,
        "fips-test",
        OverlayTransportKind::Tcp,
        "8.8.4.4:443",
        Timestamp::now().as_secs(),
    );
    assert!(discovery.ingest_advert_event(&event).await.cached());

    let endpoints = discovery
        .advert_endpoints_for_peer(&peer_npub)
        .await
        .expect("external cache should resolve without an internal relay client");

    assert_eq!(
        endpoints,
        vec![OverlayEndpointAdvert {
            transport: OverlayTransportKind::Tcp,
            addr: "8.8.4.4:443".to_string(),
        }]
    );
}

#[tokio::test]
async fn stale_external_advert_does_not_replace_newer_cache_entry() {
    let peer = nostr::Keys::generate();
    let peer_npub = peer.public_key().to_bech32().expect("peer npub");
    let discovery = NostrDiscovery::new_for_test_with_config(NostrDiscoveryConfig {
        app: "fips-test".to_string(),
        ..Default::default()
    });
    let now_secs = Timestamp::now().as_secs();
    let newer = signed_runtime_overlay_advert_event(
        &peer,
        "fips-test",
        OverlayTransportKind::Tcp,
        "8.8.8.8:443",
        now_secs,
    );
    let older = signed_runtime_overlay_advert_event(
        &peer,
        "fips-test",
        OverlayTransportKind::Tcp,
        "8.8.4.4:443",
        now_secs.saturating_sub(1),
    );

    assert_eq!(
        discovery.ingest_advert_event(&newer).await,
        NostrAdvertIngestOutcome::Cached
    );
    assert_eq!(
        discovery.ingest_advert_event(&older).await,
        NostrAdvertIngestOutcome::Stale
    );

    let endpoints = discovery
        .cached_advert_endpoints_for_peer(&peer_npub)
        .await
        .expect("newer advert should remain cached");
    assert_eq!(endpoints[0].addr, "8.8.8.8:443");
}

fn signed_runtime_overlay_advert_event(
    keys: &nostr::Keys,
    app: &str,
    transport: OverlayTransportKind,
    addr: &str,
    created_at_secs: u64,
) -> Event {
    let advert = OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints: vec![OverlayEndpointAdvert {
            transport,
            addr: addr.to_string(),
        }],
        stun_servers: None,
    };
    EventBuilder::new(
        Kind::Custom(ADVERT_KIND),
        serde_json::to_string(&advert).unwrap(),
    )
    .tags([
        Tag::identifier(app),
        Tag::custom(TagKind::custom("protocol"), [app.to_string()]),
        Tag::custom(TagKind::custom("version"), [PROTOCOL_VERSION.to_string()]),
        Tag::expiration(Timestamp::from(created_at_secs.saturating_add(3_600))),
    ])
    .custom_created_at(Timestamp::from(created_at_secs))
    .sign_with_keys(keys)
    .unwrap()
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
    assert_eq!(envelope.sender_npub, "npub1peer");
}

#[tokio::test]
async fn stale_initiator_does_not_suppress_fresh_mesh_offer_after_roam() {
    let discovery = NostrDiscovery::new_for_test();
    let ours = PeerIdentity::from_npub(&discovery.npub).expect("local identity");
    let peer_npub = loop {
        let candidate = nostr::Keys::generate()
            .public_key()
            .to_bech32()
            .expect("peer npub");
        let theirs = PeerIdentity::from_npub(&candidate).expect("peer identity");
        if suppress_responder_for_own_initiator(ours.node_addr(), theirs.node_addr(), true) {
            break candidate;
        }
    };
    let peer_key = NostrPeerKey::parse(&peer_npub).expect("peer key");
    let started_at_ms = now_ms();
    discovery
        .active_initiators
        .lock()
        .await
        .insert(peer_key, started_at_ms);

    assert!(
        discovery
            .should_suppress_responder_for_active_initiator(
                &peer_npub,
                started_at_ms + MESH_SIGNAL_RETRY_INTERVAL.as_millis() as u64 - 1,
            )
            .await,
        "the deterministic winner should suppress true simultaneous traversal glare"
    );
    assert!(
        !discovery
            .should_suppress_responder_for_active_initiator(
                &peer_npub,
                started_at_ms + MESH_SIGNAL_RETRY_INTERVAL.as_millis() as u64,
            )
            .await,
        "an older initiator owns obsolete endpoints and must not suppress a post-roam offer"
    );
}

#[tokio::test]
async fn suppressed_mesh_offer_retry_is_admitted_after_glare_window() {
    let discovery = NostrDiscovery::new_for_test();
    let ours = PeerIdentity::from_npub(&discovery.npub).expect("local identity");
    let peer_npub = loop {
        let candidate = nostr::Keys::generate()
            .public_key()
            .to_bech32()
            .expect("peer npub");
        let theirs = PeerIdentity::from_npub(&candidate).expect("peer identity");
        if suppress_responder_for_own_initiator(ours.node_addr(), theirs.node_addr(), true) {
            break candidate;
        }
    };
    let peer_key = NostrPeerKey::parse(&peer_npub).expect("peer key");
    let started_at_ms = now_ms();
    discovery
        .active_initiators
        .lock()
        .await
        .insert(peer_key, started_at_ms);
    let retry_interval_ms = MESH_SIGNAL_RETRY_INTERVAL.as_millis() as u64;

    assert_eq!(
        discovery
            .admit_incoming_mesh_offer(
                &peer_npub,
                "post-roam-offer",
                started_at_ms + retry_interval_ms - 1,
            )
            .await,
        IncomingMeshOfferAdmission::SuppressedByActiveInitiator
    );
    assert_eq!(
        discovery
            .admit_incoming_mesh_offer(
                &peer_npub,
                "post-roam-offer",
                started_at_ms + retry_interval_ms,
            )
            .await,
        IncomingMeshOfferAdmission::Accepted,
        "suppression must not consume replay admission for the offer retry"
    );
    assert_eq!(
        discovery
            .admit_incoming_mesh_offer(
                &peer_npub,
                "post-roam-offer",
                started_at_ms + retry_interval_ms + 1,
            )
            .await,
        IncomingMeshOfferAdmission::Duplicate
    );
}

#[tokio::test(start_paused = true)]
async fn mesh_offer_retries_until_answer_arrives() {
    let discovery = Arc::new(NostrDiscovery::new_for_test());
    let peer_npub = nostr::Keys::generate()
        .public_key()
        .to_bech32()
        .expect("peer npub");
    let offer = TraversalOffer {
        message_type: "offer".to_string(),
        session_id: "retry-session".to_string(),
        issued_at: 1,
        expires_at: u64::MAX,
        nonce: "retry-nonce".to_string(),
        sender_npub: discovery.npub.clone(),
        recipient_npub: peer_npub.clone(),
        reflexive_address: None,
        local_addresses: Vec::new(),
        stun_server: None,
    };
    let answer = TraversalAnswer {
        message_type: "answer".to_string(),
        session_id: offer.session_id.clone(),
        issued_at: 1,
        expires_at: u64::MAX,
        nonce: "answer-nonce".to_string(),
        sender_npub: peer_npub.clone(),
        recipient_npub: discovery.npub.clone(),
        in_reply_to: offer.nonce.clone(),
        accepted: true,
        reflexive_address: None,
        local_addresses: Vec::new(),
        stun_server: None,
        punch: None,
        reason: None,
        offer_received_at: None,
    };
    let (tx, rx) = oneshot::channel();
    let runtime = Arc::clone(&discovery);
    let waiting_offer = offer.clone();
    let waiting_peer = peer_npub.clone();
    let wait = tokio::spawn(async move {
        runtime
            .wait_for_mesh_traversal_answer(&waiting_peer, &waiting_offer, rx)
            .await
    });

    tokio::task::yield_now().await;
    tokio::time::advance(MESH_SIGNAL_RETRY_INTERVAL).await;
    tokio::task::yield_now().await;

    let signals = discovery.drain_mesh_signals().await;
    assert_eq!(signals.len(), 1);
    match &signals[0] {
        MeshTraversalSignal::Offer {
            peer_npub: repeated_peer,
            offer: repeated_offer,
        } => {
            assert_eq!(repeated_peer, &peer_npub);
            assert_eq!(repeated_offer, &offer);
        }
        MeshTraversalSignal::Answer { .. } => panic!("expected repeated offer"),
    }

    assert!(
        tx.send(SignalEnvelope {
            payload: answer.clone(),
            sender_npub: peer_npub,
        })
        .is_ok()
    );
    let received = wait.await.expect("wait task").expect("mesh answer");
    assert_eq!(received.payload, answer);
}

#[tokio::test]
async fn duplicate_mesh_offer_replays_cached_answer() {
    let discovery = Arc::new(NostrDiscovery::new_for_test());
    let sender_npub = nostr::Keys::generate()
        .public_key()
        .to_bech32()
        .expect("peer npub");
    let offer = TraversalOffer {
        message_type: "offer".to_string(),
        session_id: "cached-session".to_string(),
        issued_at: now_ms(),
        expires_at: now_ms() + 60_000,
        nonce: "cached-offer-nonce".to_string(),
        sender_npub: sender_npub.clone(),
        recipient_npub: discovery.npub.clone(),
        reflexive_address: None,
        local_addresses: Vec::new(),
        stun_server: None,
    };
    let answer = TraversalAnswer {
        message_type: "answer".to_string(),
        session_id: offer.session_id.clone(),
        issued_at: now_ms(),
        expires_at: now_ms() + 60_000,
        nonce: "cached-answer-nonce".to_string(),
        sender_npub: discovery.npub.clone(),
        recipient_npub: sender_npub.clone(),
        in_reply_to: offer.nonce.clone(),
        accepted: false,
        reflexive_address: None,
        local_addresses: Vec::new(),
        stun_server: None,
        punch: None,
        reason: Some("test".to_string()),
        offer_received_at: Some(now_ms()),
    };
    discovery
        .cache_mesh_traversal_answer(&offer, &sender_npub, &answer)
        .await;

    discovery
        .receive_mesh_traversal_offer(offer, sender_npub.clone())
        .await;

    let signals = discovery.drain_mesh_signals().await;
    assert_eq!(signals.len(), 1);
    match &signals[0] {
        MeshTraversalSignal::Answer {
            peer_npub,
            answer: replayed,
        } => {
            assert_eq!(peer_npub, &sender_npub);
            assert_eq!(replayed, &answer);
        }
        MeshTraversalSignal::Offer { .. } => panic!("expected cached answer"),
    }
}
