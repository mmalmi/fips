/// B4: strict-fresh path returns Fresh; the offer is well within TTL and
/// not expired.
#[test]
fn freshness_strict_returns_fresh_outcome() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        TraversalSignalTiming::new(1_700_000_000_000, 60_000),
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        observed(
            Some(addr("203.0.113.10", 62000)),
            vec![addr("192.168.1.10", 62000)],
            Some("stun:example.org:3478"),
        ),
    );

    let result = validate_offer_freshness(
        &offer,
        1_700_000_000_500,
        60_000,
        "npub1client",
        "npub1server",
    )
    .expect("strict-fresh offer should validate");
    assert_eq!(result, FreshnessOutcome::Fresh);
}

/// B4: an offer whose `expires_at` has already passed by < SKEW_TOL is
/// accepted but flagged FreshWithinSkewTolerance — emulates the case where
/// the responder's clock is ahead of the initiator's.
#[test]
fn freshness_responder_clock_ahead_within_tolerance_is_tolerated() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        TraversalSignalTiming::new(1_700_000_000_000, 60_000), // expires_at = 1_700_000_060_000
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        observed(
            Some(addr("203.0.113.10", 62000)),
            vec![addr("192.168.1.10", 62000)],
            None,
        ),
    );

    // now 90s past issued_at — 30s past strict expiry, but inside the 60s
    // SKEW_TOL grace.
    let result = validate_offer_freshness(
        &offer,
        1_700_000_090_000,
        60_000,
        "npub1client",
        "npub1server",
    )
    .expect("offer just past strict expiry should be tolerated");
    assert_eq!(result, FreshnessOutcome::FreshWithinSkewTolerance);
}

/// B4: an offer beyond TTL + SKEW_TOL is rejected as expired.
#[test]
fn freshness_responder_clock_far_ahead_is_rejected() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        TraversalSignalTiming::new(1_700_000_000_000, 60_000),
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        observed(
            Some(addr("203.0.113.10", 62000)),
            vec![addr("192.168.1.10", 62000)],
            None,
        ),
    );

    // 130s past issued_at: 70s past strict expiry, 10s past tolerated expiry.
    let err = validate_offer_freshness(
        &offer,
        1_700_000_130_000,
        60_000,
        "npub1client",
        "npub1server",
    )
    .expect_err("offer past tolerated expiry should be rejected");
    assert!(err.to_string().contains("expired-offer"), "{}", err);
}

#[test]
fn freshness_future_dated_offer_is_bounded_by_skew_tolerance() {
    let now = 1_700_000_000_000;
    let within = create_traversal_offer(
        "within".to_string(),
        TraversalSignalTiming::new(now + FRESHNESS_SKEW_TOLERANCE_MS, 60_000),
        "nonce".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        observed(None, vec![addr("192.168.1.10", 62000)], None),
    );
    assert_eq!(
        validate_offer_freshness(&within, now, 60_000, "npub1client", "npub1server").unwrap(),
        FreshnessOutcome::FreshWithinSkewTolerance
    );

    let mut beyond = within;
    beyond.issued_at = now + FRESHNESS_SKEW_TOLERANCE_MS + 1;
    beyond.expires_at = beyond.issued_at + 60_000;
    let error =
        validate_offer_freshness(&beyond, now, 60_000, "npub1client", "npub1server").unwrap_err();
    assert!(error.to_string().contains("future-dated-offer"));
}

#[test]
fn freshness_sender_cannot_extend_declared_expiry_past_ttl() {
    let issued_at = 1_700_000_000_000;
    let mut offer = create_traversal_offer(
        "extended".to_string(),
        TraversalSignalTiming::new(issued_at, 60_000),
        "nonce".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        observed(None, vec![addr("192.168.1.10", 62000)], None),
    );
    offer.expires_at = u64::MAX;

    let error = validate_offer_freshness(
        &offer,
        issued_at + 120_001,
        60_000,
        "npub1client",
        "npub1server",
    )
    .unwrap_err();
    assert!(error.to_string().contains("expired-offer"));
}

/// B5a: the NTP-style skew estimator returns the responder's apparent
/// clock offset relative to the initiator. Symmetric one-way delays of
/// 50ms each plus a +500ms responder skew should yield ≈+500ms.
#[test]
fn estimate_clock_skew_matches_responder_offset() {
    // T1 (initiator sent)
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        TraversalSignalTiming::new(1_700_000_000_000, 60_000),
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        observed(None, vec![addr("192.168.1.10", 62000)], None),
    );
    // Wire takes 50ms, responder clock is +500ms ahead, so:
    //   T2 = 1_700_000_000_000 + 50 + 500 = 1_700_000_000_550
    //   T3 = 1_700_000_000_550 (no processing time for this synthetic case)
    //   T4 = T1 + 50 + (T3 - T2 + 500_skew_corrected) + 50 wire return
    //      For simplicity: T4 = T1 + 100ms wire + 0 responder processing
    //                       = 1_700_000_000_100 (initiator wall clock)
    let answer = create_traversal_answer(
        &offer,
        TraversalSignalTiming::new(1_700_000_000_550, 60_000), // T3
        "answer-1".to_string(),
        "npub1server".to_string(),
        observed(Some(addr("198.51.100.20", 63000)), vec![], None),
        None,
        Some(1_700_000_000_550), // T2
    );
    let answer_received_at = 1_700_000_000_100; // T4

    let skew = estimate_clock_skew(&offer, &answer, answer_received_at)
        .expect("offer_received_at populated -> Some");
    // ((550 - 0) + (550 - 100)) / 2 = (550 + 450) / 2 = 500
    assert_eq!(skew, 500);
}

/// B5a: backward-compat — when the responder did not populate
/// `offer_received_at` (older daemon), skew estimation returns None
/// and callers should silently skip logging it.
#[test]
fn estimate_clock_skew_returns_none_without_responder_timestamp() {
    let offer = create_traversal_offer(
        "sess-1".to_string(),
        TraversalSignalTiming::new(1_700_000_000_000, 60_000),
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        observed(None, vec![], None),
    );
    let answer = create_traversal_answer(
        &offer,
        TraversalSignalTiming::new(1_700_000_000_500, 60_000),
        "answer-1".to_string(),
        "npub1server".to_string(),
        observed(Some(addr("198.51.100.20", 63000)), vec![], None),
        None,
        None, // older responder
    );
    assert!(estimate_clock_skew(&offer, &answer, 1_700_000_000_900).is_none());
}
