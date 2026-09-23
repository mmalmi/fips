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
fn healthy_recovered_trial_never_reuses_an_obsolete_full_offer() {
    let policy = PriceSelectionPolicy::default();
    for price in [0, 1_024] {
        let full = offer(2, price);
        let mut trial = full.clone();
        trial.id = "recovered-trial".into();
        trial.trial = true;
        trial.max_units = policy.trial_max_units;
        trial.expires_unix = unix_now().unwrap() + 60;
        let mut state = Destination {
            active: Some(trial.clone()),
            ..Default::default()
        };
        state
            .observe(&working(&trial, 0.0), &policy, Instant::now())
            .unwrap();
        // The quote cache can still contain a full offer from before the
        // provider failed. Its agreement may already have been retired.
        for selected in [&full, &trial] {
            assert!(matches!(
                state
                    .selection_step(selected, &policy, true, |_| Some(100))
                    .unwrap(),
                SelectionStep::Request {
                    max_units: None,
                    reuse_unchanged: false
                }
            ));
        }
        // An active full agreement remains reusable on subsequent healthy polls.
        state.active = Some(full.clone());
        assert!(matches!(
            state
                .selection_step(&full, &policy, true, |_| Some(100))
                .unwrap(),
            SelectionStep::Accept
        ));
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
    let mut offers = [offer(2, 0), offer(3, 0), offer(5, 0)];
    let permutations = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let prices = [
        [0, 0, 0],
        [0, 1, 97],
        [1, 9, 10],
        [9, 10, 11],
        [899, 900, 1_000],
        [900, 901, 1_000],
        [1_000, 1_024, 1_500],
        [1_000, 1_500, 2_000],
        [u64::MAX / 2, u64::MAX - 1, u64::MAX],
    ];
    for rates in prices {
        for (offer, rate) in offers.iter_mut().zip(rates) {
            offer.price.msat = rate;
        }
        for losses in [
            [0_u32, 0, 0],
            [30, 30, 30],
            [0, 10, 25],
            [90, 50, 0],
            [25, 0, 50],
            [50, 90, 10],
            [50, 25, 0],
        ] {
            for margin in [0, PriceSelectionPolicy::default().min_improvement_percent] {
                let policy = PriceSelectionPolicy {
                    max_loss_percent: 90,
                    min_improvement_percent: margin,
                    ..Default::default()
                };
                let mut state = Destination::default();
                for (offer, loss) in offers.iter().zip(losses) {
                    state.active = Some(offer.clone());
                    state
                        .observe(&working(offer, f64::from(loss) / 100.0), &policy, now)
                        .unwrap();
                }
                for active in 0..3 {
                    state.active = Some(offers[active].clone());
                    let mut expected = active;
                    // Independent percentage cross-products: admit only strict
                    // savings over the active route, then find the cheapest.
                    // Do not reuse the production score or its rounding.
                    let cost_pair = |a: usize, b: usize| {
                        (
                            u128::from(rates[a]) * u128::from(100 - losses[b]),
                            u128::from(rates[b]) * u128::from(100 - losses[a]),
                        )
                    };
                    for candidate in 0..3 {
                        let (next, current) = cost_pair(candidate, active);
                        if next * 100 >= current * u128::from(100 - margin) {
                            continue;
                        }
                        let (next, best) = cost_pair(candidate, expected);
                        if (next, offers[candidate].provider) < (best, offers[expected].provider) {
                            expected = candidate;
                        }
                    }
                    for order in permutations {
                        assert_eq!(
                            state
                                .choose(order.map(|i| offers[i].clone()).to_vec(), &policy, now)
                                .unwrap()
                                .provider,
                            offers[expected].provider,
                            "rates={rates:?} losses={losses:?} margin={margin} active={active} order={order:?}"
                        );
                    }
                }
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
