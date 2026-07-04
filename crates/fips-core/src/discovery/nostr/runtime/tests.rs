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

#[tokio::test]
async fn traversal_replay_cache_is_scoped_by_signal_path() {
    let discovery = NostrDiscovery::new_for_test();

    discovery
        .mark_session_seen("session", TraversalSignalPath::Mesh)
        .await
        .expect("first mesh copy should be accepted");
    discovery
        .mark_session_seen("session", TraversalSignalPath::Nostr)
        .await
        .expect("Nostr fallback copy of the same offer should still be accepted");

    let duplicate_mesh = discovery
        .mark_session_seen("session", TraversalSignalPath::Mesh)
        .await
        .expect_err("duplicate mesh copy should still be rejected");
    assert!(matches!(duplicate_mesh, BootstrapError::Replay(_)));

    let duplicate_nostr = discovery
        .mark_session_seen("session", TraversalSignalPath::Nostr)
        .await
        .expect_err("duplicate Nostr copy should still be rejected");
    assert!(matches!(duplicate_nostr, BootstrapError::Replay(_)));
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

#[test]
fn rating_fact_subscription_is_enabled_by_trust_config() {
    let discovery = NostrDiscovery::new_for_test();
    assert!(!discovery.should_subscribe_rating_facts());

    let discovery = NostrDiscovery::new_for_test_with_config(NostrDiscoveryConfig {
        open_discovery_trust_ratings_enabled: true,
        ..Default::default()
    });
    assert!(discovery.should_subscribe_rating_facts());

    let filter = serde_json::to_value(discovery.rating_fact_filter()).unwrap();
    assert_eq!(
        filter["kinds"],
        serde_json::json!([ratings::RATING_FACT_KIND])
    );
    assert_eq!(filter["#i"], serde_json::json!(["fips.peer"]));
    assert_eq!(filter["limit"], 500);
    assert!(filter["since"].as_u64().is_some());
}

#[tokio::test]
async fn trusted_rating_fact_updates_peer_trust_score() {
    let author = nostr::Keys::generate();
    let author_npub = author.public_key().to_bech32().expect("author npub");
    let subject = nostr::Keys::generate();
    let subject_npub = subject.public_key().to_bech32().expect("subject npub");
    let discovery = NostrDiscovery::new_for_test_with_config(NostrDiscoveryConfig {
        open_discovery_trust_ratings_enabled: true,
        open_discovery_trusted_rating_authors: vec![author_npub],
        ..Default::default()
    });
    let event = signed_rating_fact_event(&author, &subject_npub, "fips.peer", 80, 42);

    assert!(discovery.process_rating_fact_event(&event).await);

    let scores = discovery
        .trust_scores_for_npubs(std::slice::from_ref(&subject_npub))
        .await;
    assert_eq!(scores.get(&subject_npub), Some(&60));
}

#[tokio::test]
async fn peer_trust_snapshot_uses_newest_rating_per_peer() {
    let author = nostr::Keys::generate();
    let author_npub = author.public_key().to_bech32().expect("author npub");
    let subject = nostr::Keys::generate();
    let subject_npub = subject.public_key().to_bech32().expect("subject npub");
    let discovery = NostrDiscovery::new_for_test_with_config(NostrDiscoveryConfig {
        open_discovery_trust_ratings_enabled: true,
        open_discovery_trusted_rating_authors: vec![author_npub],
        ..Default::default()
    });

    assert!(
        discovery
            .process_rating_fact_event(&signed_rating_fact_event(
                &author,
                &subject_npub,
                "fips.peer",
                80,
                42,
            ))
            .await
    );
    assert!(
        discovery
            .process_rating_fact_event(&signed_rating_fact_event(
                &author,
                &subject_npub,
                "fips.peer",
                0,
                41,
            ))
            .await
    );
    assert!(
        discovery
            .process_rating_fact_event(&signed_rating_fact_event(
                &author,
                &subject_npub,
                "fips.peer",
                100,
                43,
            ))
            .await
    );

    let snapshot = discovery
        .peer_trust_score_snapshot()
        .expect("trust cache snapshot");
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].npub, subject_npub);
    assert_eq!(snapshot[0].score, 100);
    assert_eq!(snapshot[0].updated_at_secs, 43);
}

#[tokio::test]
async fn configured_rating_fact_file_updates_peer_trust_score() {
    let author = nostr::Keys::generate();
    let author_npub = author.public_key().to_bech32().expect("author npub");
    let subject = nostr::Keys::generate();
    let subject_npub = subject.public_key().to_bech32().expect("subject npub");
    let event = signed_rating_fact_event(&author, &subject_npub, "fips.peer", 90, 43);
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("ratings.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&serde_json::json!({ "events": [event] }))
            .expect("encode rating events"),
    )
    .expect("write rating event file");

    let discovery = NostrDiscovery::new_for_test_with_config(NostrDiscoveryConfig {
        open_discovery_trust_ratings_enabled: true,
        open_discovery_trusted_rating_authors: vec![author_npub],
        open_discovery_rating_event_files: vec![path],
        ..Default::default()
    });

    let report = discovery.load_rating_fact_events_from_files().await;

    assert_eq!(report.files, 1);
    assert_eq!(report.events, 1);
    assert_eq!(report.accepted, 1);
    let scores = discovery
        .trust_scores_for_npubs(std::slice::from_ref(&subject_npub))
        .await;
    assert_eq!(scores.get(&subject_npub), Some(&80));
}

#[tokio::test]
async fn hashtree_query_output_rating_file_updates_peer_trust_score() {
    let author = nostr::Keys::generate();
    let author_npub = author.public_key().to_bech32().expect("author npub");
    let subject = nostr::Keys::generate();
    let subject_npub = subject.public_key().to_bech32().expect("subject npub");
    let event = signed_rating_fact_event(&author, &subject_npub, "fips.peer", 95, 44);
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("hashtree-query.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "root": "nhash1testfixture",
            "count": 1,
            "events": [event],
        }))
        .expect("encode hashtree query output"),
    )
    .expect("write rating event file");

    let discovery = NostrDiscovery::new_for_test_with_config(NostrDiscoveryConfig {
        open_discovery_trust_ratings_enabled: true,
        open_discovery_trusted_rating_authors: vec![author_npub],
        open_discovery_rating_event_files: vec![path],
        ..Default::default()
    });

    let report = discovery.load_rating_fact_events_from_files().await;

    assert_eq!(report.files, 1);
    assert_eq!(report.events, 1);
    assert_eq!(report.accepted, 1);
    let scores = discovery
        .trust_scores_for_npubs(std::slice::from_ref(&subject_npub))
        .await;
    assert_eq!(scores.get(&subject_npub), Some(&90));
}

#[tokio::test]
async fn untrusted_rating_fact_is_ignored() {
    let author = nostr::Keys::generate();
    let subject = nostr::Keys::generate();
    let subject_npub = subject.public_key().to_bech32().expect("subject npub");
    let discovery = NostrDiscovery::new_for_test_with_config(NostrDiscoveryConfig {
        open_discovery_trust_ratings_enabled: true,
        ..Default::default()
    });
    let event = signed_rating_fact_event(&author, &subject_npub, "fips.peer", 80, 42);

    assert!(!discovery.process_rating_fact_event(&event).await);

    let scores = discovery
        .trust_scores_for_npubs(std::slice::from_ref(&subject_npub))
        .await;
    assert!(!scores.contains_key(&subject_npub));
}

#[tokio::test]
async fn rating_fact_scope_must_match_configured_scope() {
    let author = nostr::Keys::generate();
    let author_npub = author.public_key().to_bech32().expect("author npub");
    let subject = nostr::Keys::generate();
    let subject_npub = subject.public_key().to_bech32().expect("subject npub");
    let discovery = NostrDiscovery::new_for_test_with_config(NostrDiscoveryConfig {
        open_discovery_trust_ratings_enabled: true,
        open_discovery_trusted_rating_authors: vec![author_npub],
        ..Default::default()
    });
    let event = signed_rating_fact_event(&author, &subject_npub, "other.scope", 80, 42);

    assert!(!discovery.process_rating_fact_event(&event).await);

    let scores = discovery
        .trust_scores_for_npubs(std::slice::from_ref(&subject_npub))
        .await;
    assert!(!scores.contains_key(&subject_npub));
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

fn signed_rating_fact_event(
    keys: &nostr::Keys,
    subject_npub: &str,
    scope: &str,
    rating: i64,
    created_at: u64,
) -> Event {
    let created_at_string = created_at.to_string();
    let rating_string = rating.to_string();
    let rater_npub = keys.public_key().to_bech32().expect("rater npub");
    let rater_index = rater_npub.to_lowercase();
    let subject_index = subject_npub.to_lowercase();
    let scope_index = scope.to_lowercase();
    let tags = vec![
        rating_fact_tag(["i", "550e8400-e29b-41d4-a716-446655440000", "subject"]),
        rating_fact_tag(["i", &rater_index]),
        rating_fact_tag(["i", &subject_index]),
        rating_fact_tag(["i", &scope_index]),
        rating_fact_tag(["type", "rating"]),
        rating_fact_tag(["schema", "1"]),
        rating_fact_tag(["created_at", &created_at_string]),
        rating_fact_tag(["rater", &rater_npub]),
        rating_fact_tag(["subject", subject_npub]),
        rating_fact_tag(["scope", scope]),
        rating_fact_tag(["rating", &rating_string]),
        rating_fact_tag(["min_rating", "0"]),
        rating_fact_tag(["max_rating", "100"]),
    ];
    EventBuilder::new(Kind::Custom(ratings::RATING_FACT_KIND), "")
        .tags(tags)
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(keys)
        .unwrap()
}

fn rating_fact_tag<const N: usize>(parts: [&str; N]) -> Tag {
    Tag::parse(parts).unwrap()
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
