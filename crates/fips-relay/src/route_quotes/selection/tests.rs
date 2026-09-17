use super::*;

pub(super) fn offer(provider: u8, rate: u64) -> RouteOffer {
    let peer = |n| {
        PeerIdentity::from_pubkey_full(Identity::from_secret_bytes(&[n; 32]).unwrap().pubkey_full())
    };
    let destination = peer(4);
    let provider = *peer(provider).node_addr();
    RouteOffer {
        trial: false,
        billing: BillingBasis::ForwardingData,
        id: provider.to_string(),
        buyer: *peer(1).node_addr(),
        provider,
        destination,
        next_hop: *destination.node_addr(),
        path: vec![provider, *destination.node_addr()],
        price: BytePrice {
            msat: rate,
            per_bytes: PRICE_BYTES,
        },
        expires_unix: 100,
        max_units: 1_000_000,
        mint_url: "http://test.invalid".into(),
        receiver_pubkey_hex: "02".to_owned() + &"11".repeat(32),
        capacity_sat: 64,
        grace_msat: 8_000,
    }
}

pub(super) fn working(offer: &RouteOffer, loss: f64) -> SourceRouteQuality {
    SourceRouteQuality {
        next_hop: Some(offer.provider),
        receiver_reports_enabled: true,
        has_recent_delivery_feedback: true,
        loss_rate: Some(loss),
        rtt_ms: Some(50.0),
        ..Default::default()
    }
}

#[test]
fn selection_ranks_estimated_delivered_cost_and_enforces_quality_limits() {
    let cheap = offer(2, 1_000);
    let premium = offer(3, 1_500);
    let mut state = Destination {
        active: Some(cheap.clone()),
        ..Default::default()
    };
    let policy = PriceSelectionPolicy {
        max_loss_percent: 75,
        ..Default::default()
    };
    let now = Instant::now();
    assert_eq!(
        state
            .choose(vec![premium.clone(), cheap.clone()], &policy, now)
            .unwrap()
            .provider,
        cheap.provider
    );
    state.observe(&working(&cheap, 0.5), &policy, now).unwrap();
    // 1,000 / 50% = 2,000 vs an optimistic 1,500 for a bounded trial.
    assert_eq!(
        state
            .choose(vec![cheap.clone(), premium.clone()], &policy, now)
            .unwrap()
            .provider,
        premium.provider
    );
    state.observe(&working(&cheap, 0.0), &policy, now).unwrap();
    assert_eq!(
        state
            .choose(vec![cheap.clone(), premium.clone()], &policy, now)
            .unwrap()
            .provider,
        cheap.provider
    );
    let mut slow = working(&cheap, 0.0);
    slow.rtt_ms = Some(policy.max_rtt_ms as f64 + 1.0);
    state.observe(&slow, &policy, now).unwrap();
    assert_eq!(
        state
            .choose(vec![cheap, premium.clone()], &policy, now)
            .unwrap()
            .provider,
        premium.provider
    );
}

#[test]
fn failed_provider_cannot_evade_cooldown_with_a_new_quote_or_path() {
    let cheap = offer(2, 1_000);
    let premium = offer(3, 2_000);
    let mut state = Destination {
        active: Some(cheap.clone()),
        ..Default::default()
    };
    let policy = PriceSelectionPolicy::default();
    let now = Instant::now();
    let failure = SourceRouteQuality {
        next_hop: Some(cheap.provider),
        delivery_feedback_timed_out: true,
        ..Default::default()
    };
    state.observe(&failure, &policy, now).unwrap();
    let deadline = state.failed[&cheap.provider];
    state
        .observe(&failure, &policy, now + Duration::from_secs(1))
        .unwrap();
    assert_eq!(
        state.failed[&cheap.provider], deadline,
        "polling cannot extend the retry delay"
    );
    let mut advertised = cheap.clone();
    advertised.id = "new-quote".into();
    advertised.path.insert(1, premium.provider);
    assert_eq!(
        state
            .choose(vec![advertised, premium.clone()], &policy, now)
            .unwrap()
            .provider,
        premium.provider
    );
    assert!(state.choose(vec![cheap.clone()], &policy, now).is_err());
    // A failed active path remains eligible for a new bounded attempt after
    // cooldown; repeated timeout observations cannot lock it out forever.
    state
        .observe(&failure, &policy, deadline + Duration::from_millis(1))
        .unwrap();
    assert_eq!(state.failed[&cheap.provider], deadline);
    assert_eq!(
        state
            .choose(vec![cheap.clone()], &policy, deadline)
            .unwrap()
            .provider,
        cheap.provider
    );
}

#[test]
fn stale_unknown_or_wrong_carrier_feedback_cannot_create_a_measurement() {
    let cheap = offer(2, 1_000);
    let policy = PriceSelectionPolicy::default();
    let now = Instant::now();
    let mut state = Destination {
        active: Some(cheap.clone()),
        ..Default::default()
    };
    state
        .observe(&SourceRouteQuality::default(), &policy, now)
        .unwrap();
    assert_eq!(state.working_loss(&cheap, &policy, now), None);
    assert!(state.failed.is_empty(), "idle unknown is not failure");
    state.observe(&working(&cheap, 0.2), &policy, now).unwrap();
    assert_eq!(state.working_loss(&cheap, &policy, now), Some(200_000));
    assert_eq!(
        state.working_loss(&cheap, &policy, now + Duration::from_secs(16)),
        None
    );
    let other = offer(3, 1_500);
    state.observe(&working(&other, 0.0), &policy, now).unwrap();
    assert_eq!(state.working_loss(&cheap, &policy, now), None);
    let mut nonfinite = working(&cheap, f64::NAN);
    nonfinite.rtt_ms = Some(f64::INFINITY);
    state.observe(&nonfinite, &policy, now).unwrap();
    assert_eq!(
        state.working_loss(&cheap, &policy, now),
        None,
        "unknown loss and RTT cannot validate an unrestricted allowance"
    );
}

#[test]
fn small_savings_do_not_oscillate_and_policy_state_is_bounded() {
    let active = offer(2, 1_000);
    let slightly_cheaper = offer(3, 950);
    let policy = PriceSelectionPolicy::default();
    let now = Instant::now();
    let mut state = Destination {
        active: Some(active.clone()),
        ..Default::default()
    };
    assert_eq!(
        state
            .choose(vec![slightly_cheaper, active.clone()], &policy, now)
            .unwrap()
            .provider,
        active.provider
    );
    for n in 5..5 + MAX_FAILED_PROVIDERS as u8 {
        state
            .failed
            .insert(offer(n, 1).provider, now + Duration::from_secs(60));
    }
    let failed = SourceRouteQuality {
        next_hop: Some(active.provider),
        delivery_feedback_timed_out: true,
        ..Default::default()
    };
    assert!(state.observe(&failed, &policy, now).is_err());
    assert_eq!(state.failed.len(), MAX_FAILED_PROVIDERS);
    state
        .observe(&failed, &policy, now + Duration::from_secs(61))
        .unwrap();
    assert_eq!(state.failed.len(), MAX_FAILED_PROVIDERS);
}

#[test]
fn invalid_selection_policies_are_rejected() {
    PriceSelectionPolicy::default().validate().unwrap();
    let mutations: [fn(&mut PriceSelectionPolicy); 6] = [
        |p| p.feedback_timeout_ms = 0,
        |p| p.retry_after_ms = 1,
        |p| p.trial_max_units = u64::MAX,
        |p| p.max_loss_percent = 100,
        |p| p.min_improvement_percent = 100,
        |p| p.max_rtt_ms = 0,
    ];
    for mutate in mutations {
        let mut p = PriceSelectionPolicy::default();
        mutate(&mut p);
        assert!(p.validate().is_err());
    }
}

#[test]
fn delivered_cost_choice_matches_independent_reference() {
    let now = Instant::now();
    let policy = PriceSelectionPolicy {
        max_loss_percent: 90,
        min_improvement_percent: 0,
        ..Default::default()
    };
    for active_price in [0, 1, 97, 1_024, 8_192] {
        for other_price in [0, 1, 97, 1_024, 8_192] {
            for loss_percent in [0, 10, 25, 50, 90] {
                let active = offer(2, active_price);
                let other = offer(3, other_price);
                let mut state = Destination {
                    active: Some(active.clone()),
                    ..Default::default()
                };
                state
                    .observe(&working(&active, loss_percent as f64 / 100.0), &policy, now)
                    .unwrap();
                // Compare cross-products directly: no production score or
                // rounding is reused. Equal cost retains the current carrier.
                let expect = if other_price * (100 - loss_percent) < active_price * 100 {
                    other.provider
                } else {
                    active.provider
                };
                assert_eq!(
                    state
                        .choose(vec![other, active], &policy, now)
                        .unwrap()
                        .provider,
                    expect
                );
            }
        }
    }
}

#[test]
fn switching_keeps_recent_alternative_cost_without_qualifying_a_new_trial() {
    let cheap = offer(2, 1_000);
    let reliable = offer(3, 1_120);
    let policy = PriceSelectionPolicy::default();
    let now = Instant::now();
    let mut state = Destination {
        active: Some(cheap.clone()),
        ..Default::default()
    };
    state.observe(&working(&cheap, 0.24), &policy, now).unwrap();
    let choices = vec![cheap.clone(), reliable.clone()];
    assert_eq!(
        state
            .choose(choices.clone(), &policy, now)
            .unwrap()
            .provider,
        reliable.provider
    );
    state.active = Some(reliable.clone());
    state
        .observe(&working(&reliable, 0.0), &policy, now)
        .unwrap();
    assert_eq!(
        state.choose(choices, &policy, now).unwrap().provider,
        reliable.provider,
        "switching cannot instantly turn measured loss into zero-loss optimism"
    );
    assert_eq!(
        state.working_loss(&cheap, &policy, now),
        None,
        "a remembered alternative still requires a fresh limited trial"
    );
    assert_eq!(
        state.measured_loss(&cheap, &policy, now + Duration::from_secs(16)),
        None
    );
    for n in 5..25 {
        let next = offer(n, 1000);
        state.active = Some(next.clone());
        state
            .observe(
                &working(&next, 0.1),
                &policy,
                now + Duration::from_millis(u64::from(n)),
            )
            .unwrap();
    }
    assert_eq!(state.observations.len(), MAX_OBSERVATIONS);
    assert_eq!(
        state.measured_loss(&cheap, &policy, now),
        None,
        "oldest sample evicted"
    );
}
