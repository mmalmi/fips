use super::*;

#[tokio::test]
async fn future_rating_cannot_pin_peer_trust_above_later_health_updates() {
    let author = nostr::Keys::generate();
    let subject = nostr::Keys::generate().public_key().to_hex();
    let discovery = NostrDiscovery::new_for_test_with_config(NostrDiscoveryConfig {
        open_discovery_trust_ratings_enabled: true,
        open_discovery_trusted_rating_authors: vec![author.public_key().to_hex()],
        ..Default::default()
    });
    let now = Timestamp::now().as_secs();
    let future = now + FRESHNESS_SKEW_TOLERANCE_MS / 1000 + 60;

    // Crawlers may wrap an observation in a newly signed event. Validate the
    // observation timestamp independently of the envelope's timestamp.
    for (observation_time, publication_time) in [(future, now), (now, future)] {
        let original =
            signed_rating_fact_event(&author, &subject, "fips.peer", 100, observation_time);
        let event = EventBuilder::new(original.kind, original.content)
            .tags(original.tags)
            .custom_created_at(Timestamp::from(publication_time))
            .sign_with_keys(&author)
            .unwrap();
        assert!(
            !discovery.process_rating_fact_event(&event).await,
            "reject future observation={observation_time} publication={publication_time}"
        );
    }

    let fresh = signed_rating_fact_event(&author, &subject, "fips.peer", 0, now);
    assert!(discovery.process_rating_fact_event(&fresh).await);
    assert_eq!(
        discovery
            .trust_scores_for_npubs(std::slice::from_ref(&subject))
            .await[&subject],
        -100,
        "current bad-health evidence must replace the bogus future good rating"
    );
}

#[tokio::test]
async fn rating_tolerates_small_clock_skew_and_historical_observations() {
    let author = nostr::Keys::generate();
    let subject = nostr::Keys::generate().public_key().to_hex();
    let discovery = NostrDiscovery::new_for_test_with_config(NostrDiscoveryConfig {
        open_discovery_trust_ratings_enabled: true,
        open_discovery_trusted_rating_authors: vec![author.public_key().to_hex()],
        ..Default::default()
    });
    for created_at in [
        42,
        Timestamp::now().as_secs() + FRESHNESS_SKEW_TOLERANCE_MS / 1000,
    ] {
        let event = signed_rating_fact_event(&author, &subject, "fips.peer", 80, created_at);
        assert!(discovery.process_rating_fact_event(&event).await);
    }
}
