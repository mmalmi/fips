use super::*;
use crate::Identity;
use crate::config::NostrPeerfindingSource;
use crate::discovery::nostr::{
    NostrAdvertIngestOutcome, OverlayTransportKind, TraversalAddress, TraversalOffer,
};

mod external_mesh;

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

#[tokio::test]
async fn queued_bootstrap_event_wakes_the_node_immediately() {
    let discovery = NostrDiscovery::new_for_test();
    discovery
        .emit_event(BootstrapEvent::Failed {
            peer_config: crate::config::PeerConfig::new(
                Identity::generate().npub(),
                "udp",
                "127.0.0.1:9",
            ),
            reason: "notification test".to_string(),
        })
        .await;

    tokio::time::timeout(
        std::time::Duration::from_millis(50),
        discovery.node_event_notify().notified(),
    )
    .await
    .expect("completed traversal events must wake the node instead of waiting for its next one-second maintenance tick");
}

#[test]
fn external_peerfinding_does_not_open_direct_relay_connections() {
    let relays = AdvertRelayConfig {
        advert_relays: vec!["wss://peerfinding.example".to_string()],
    };

    assert!(relays.active_relays(false).is_empty());
    assert_eq!(
        relays.active_relays(true),
        HashSet::from(["wss://peerfinding.example".to_string()])
    );
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
fn webrtc_only_advert_needs_no_relay_signaling_metadata() {
    let advert = OverlayAdvert {
        identifier: crate::discovery::nostr::ADVERT_IDENTIFIER.to_string(),
        version: crate::discovery::nostr::ADVERT_VERSION,
        endpoints: vec![OverlayEndpointAdvert {
            transport: OverlayTransportKind::WebRtc,
            addr: format!("02{}", "11".repeat(32)),
        }],
        stun_servers: Some(vec!["stun:stun.example.org:3478".to_string()]),
    };

    let published = super::advert::sanitize_advert_for_publish(advert)
        .expect("WebRTC-only adverts must remain publishable");
    assert_eq!(published.stun_servers, None);
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

#[tokio::test]
async fn shutdown_awaits_tasks_and_clears_pending_answers() {
    let discovery = Arc::new(NostrDiscovery::new_for_test());
    let top_task_hold = Arc::new(());
    let top_task_capture = Arc::clone(&top_task_hold);
    *discovery.notify_task.lock().await = Some(tokio::spawn(async move {
        std::future::pending::<()>().await;
        drop(top_task_capture);
    }));

    let child_task_hold = Arc::new(());
    let child_task_capture = Arc::clone(&child_task_hold);
    assert!(
        discovery
            .spawn_child_task(async move {
                std::future::pending::<()>().await;
                drop(child_task_capture);
            })
            .await
    );

    let (answer_tx, answer_rx) = oneshot::channel::<SignalEnvelope<TraversalAnswer>>();
    discovery
        .pending_answers
        .lock()
        .await
        .insert("pending".to_string(), answer_tx);

    discovery.shutdown().await.expect("shutdown");

    assert_eq!(Arc::strong_count(&top_task_hold), 1);
    assert_eq!(Arc::strong_count(&child_task_hold), 1);
    assert!(answer_rx.await.is_err());
    assert!(discovery.child_tasks.lock().await.is_empty());
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
async fn rejected_traversal_admission_does_not_spawn_background_work() {
    let discovery = Arc::new(NostrDiscovery::new_for_test());
    discovery.set_direct_refresh_admission(false);
    let peer = nostr::Keys::generate()
        .public_key()
        .to_bech32()
        .expect("peer npub");

    assert!(
        !discovery
            .request_connect_with_mesh_signaling(PeerConfig::new(peer, "udp", "nat"), true)
            .await,
        "capacity rejection should be synchronous"
    );
    assert_eq!(
        discovery.active_initiator_count_for_test().await,
        0,
        "a rejected traversal must not allocate an initiator task"
    );
}

#[tokio::test]
async fn traversal_replay_cache_rejects_duplicate_session_signal() {
    let discovery = NostrDiscovery::new_for_test();

    discovery
        .mark_session_seen("session", TraversalSignalPath::Mesh)
        .await
        .expect("first mesh copy should be accepted");
    let duplicate_mesh = discovery
        .mark_session_seen("session", TraversalSignalPath::Mesh)
        .await
        .expect_err("duplicate mesh copy should still be rejected");
    assert!(matches!(duplicate_mesh, BootstrapError::Replay(_)));
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
async fn trusted_rating_fact_signer_can_differ_from_rater() {
    let crawler = nostr::Keys::generate();
    let crawler_npub = crawler.public_key().to_bech32().expect("crawler npub");
    let rater = nostr::Keys::generate();
    let rater_npub = rater.public_key().to_bech32().expect("rater npub");
    let subject = nostr::Keys::generate();
    let subject_npub = subject.public_key().to_bech32().expect("subject npub");
    let discovery = NostrDiscovery::new_for_test_with_config(NostrDiscoveryConfig {
        open_discovery_trust_ratings_enabled: true,
        open_discovery_trusted_rating_authors: vec![crawler_npub],
        ..Default::default()
    });
    let event = signed_rating_fact_event_with_rater(
        &crawler,
        &rater_npub,
        &subject_npub,
        "fips.peer",
        75,
        43,
    );

    assert_ne!(event.pubkey, rater.public_key());
    assert!(discovery.process_rating_fact_event(&event).await);

    let scores = discovery
        .trust_scores_for_npubs(std::slice::from_ref(&subject_npub))
        .await;
    assert_eq!(scores.get(&subject_npub), Some(&50));
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

#[tokio::test]
async fn authenticated_mesh_traversal_does_not_require_nostr_advert() {
    let discovery = Arc::new(NostrDiscovery::new_for_test_with_config(
        NostrDiscoveryConfig {
            stun_servers: Vec::new(),
            share_local_candidates: true,
            attempt_timeout_secs: 5,
            ..Default::default()
        },
    ));
    let peer_npub = nostr::Keys::generate()
        .public_key()
        .to_bech32()
        .expect("peer npub");

    assert!(
        discovery
            .request_connect_with_mesh_signaling(
                PeerConfig::new(peer_npub.clone(), "udp", "nat"),
                true,
            )
            .await,
        "authenticated traversal request should start"
    );

    let signal = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(signal) = discovery.drain_mesh_signals().await.into_iter().next() {
                break signal;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("mesh traversal must not wait for a Nostr advert");
    assert!(
        matches!(
            signal,
            MeshTraversalSignal::Offer {
                peer_npub: ref signal_peer_npub,
                ..
            } if signal_peer_npub == &peer_npub
        ),
        "authenticated session should carry the traversal offer"
    );

    discovery.shutdown().await.expect("shutdown discovery");
}

#[tokio::test]
async fn distinct_incoming_offer_attempts_are_not_peer_rate_limited() {
    let discovery = NostrDiscovery::new_for_test();

    assert!(discovery.accept_incoming_offer_for_test("attempt-1").await);
    assert!(discovery.accept_incoming_offer_for_test("attempt-2").await);
    assert!(!discovery.accept_incoming_offer_for_test("attempt-1").await);
}

#[tokio::test]
async fn incoming_mesh_offer_breaks_mutual_traversal_cooldown() {
    let discovery = Arc::new(NostrDiscovery::new_for_test_with_config(
        NostrDiscoveryConfig {
            stun_servers: Vec::new(),
            share_local_candidates: true,
            attempt_timeout_secs: 1,
            ..Default::default()
        },
    ));
    let expected_peer_npub = nostr::Keys::generate()
        .public_key()
        .to_bech32()
        .expect("peer npub");
    let received_at = now_ms();
    for offset in 0..5 {
        discovery.record_traversal_failure(&expected_peer_npub, received_at + offset);
    }
    assert!(
        discovery
            .cooldown_until(&expected_peer_npub, received_at + 5)
            .is_some(),
        "fixture must put the peer in traversal cooldown"
    );

    discovery
        .receive_mesh_traversal_offer(
            TraversalOffer {
                message_type: "offer".to_string(),
                session_id: "roam-recovery".to_string(),
                issued_at: received_at,
                expires_at: received_at + 30_000,
                nonce: "roam-recovery-nonce".to_string(),
                sender_npub: expected_peer_npub.clone(),
                recipient_npub: discovery.npub.clone(),
                reflexive_address: None,
                local_addresses: vec![TraversalAddress {
                    protocol: "udp".to_string(),
                    ip: "127.0.0.1".to_string(),
                    port: 51_820,
                }],
                stun_server: None,
            },
            expected_peer_npub.clone(),
        )
        .await;

    let answer = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(signal) = discovery.drain_mesh_signals().await.into_iter().next() {
                break signal;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a configured peer's recovery offer must not be stranded by cooldown");
    assert!(
        matches!(
            answer,
            MeshTraversalSignal::Answer {
                ref peer_npub,
                ..
            } if peer_npub == &expected_peer_npub
        ),
        "the cooldown peer must receive a traversal answer"
    );

    discovery.shutdown().await.expect("shutdown discovery");
}

fn signed_rating_fact_event(
    keys: &nostr::Keys,
    subject_npub: &str,
    scope: &str,
    rating: i64,
    created_at: u64,
) -> Event {
    let rater_npub = keys.public_key().to_bech32().expect("rater npub");
    signed_rating_fact_event_with_rater(keys, &rater_npub, subject_npub, scope, rating, created_at)
}

fn signed_rating_fact_event_with_rater(
    keys: &nostr::Keys,
    rater_npub: &str,
    subject_npub: &str,
    scope: &str,
    rating: i64,
    created_at: u64,
) -> Event {
    let created_at_string = created_at.to_string();
    let rating_string = rating.to_string();
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
        rating_fact_tag(["rater", rater_npub]),
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
