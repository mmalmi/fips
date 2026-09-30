use super::*;

#[test]
fn established_handshake_bucket_rejects_zero_or_non_finite_overrides() {
    let mut zero_burst = Config::default();
    zero_burst.node.rate_limit.established_handshake_burst = Some(0);
    assert!(
        zero_burst
            .validate()
            .unwrap_err()
            .to_string()
            .contains("established_handshake_burst")
    );

    for bad_rate in [0.0, -1.0, f64::NAN, f64::INFINITY] {
        let mut config = Config::default();
        config.node.rate_limit.established_handshake_rate = Some(bad_rate);
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("established_handshake_rate"),
            "bad rate {bad_rate} must be rejected"
        );
    }
}

#[test]
fn established_handshake_bucket_accepts_derived_and_positive_settings() {
    Config::default()
        .validate()
        .expect("omitted settings derive from existing limits");

    let mut config = Config::default();
    config.node.rate_limit.established_handshake_burst = Some(7);
    config.node.rate_limit.established_handshake_rate = Some(0.5);
    config
        .validate()
        .expect("positive explicit settings must validate");
}

#[test]
fn traversal_freshness_window_must_be_strictly_inside_replay_window() {
    let mut boundary = Config::default();
    boundary.node.discovery.nostr.signal_ttl_secs = 180;
    let err = boundary
        .validate()
        .expect_err("180 + 2 * 60 must not fit in the 300s replay window");
    assert!(err.to_string().contains("signal_ttl_secs"));
    assert!(err.to_string().contains("replay_window_secs"));

    let mut inside = Config::default();
    inside.node.discovery.nostr.signal_ttl_secs = 179;
    inside
        .validate()
        .expect("179 + 2 * 60 remains strictly inside the 300s replay window");
}

#[test]
fn traversal_per_sender_offer_limit_must_fit_a_semaphore() {
    let mut zero = Config::default();
    zero.node.discovery.nostr.max_concurrent_offers_per_npub = 0;
    assert!(
        zero.validate()
            .unwrap_err()
            .to_string()
            .contains("max_concurrent_offers_per_npub")
    );

    let mut oversized = Config::default();
    oversized
        .node
        .discovery
        .nostr
        .max_concurrent_offers_per_npub = tokio::sync::Semaphore::MAX_PERMITS.saturating_add(1);
    assert!(
        oversized
            .validate()
            .unwrap_err()
            .to_string()
            .contains("max_concurrent_offers_per_npub")
    );
}
