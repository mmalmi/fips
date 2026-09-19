use super::{
    tests::{offer, working},
    *,
};

fn offers() -> Vec<RouteOffer> {
    let mut offers: Vec<_> = [2, 3, 5, 6, 7, 8]
        .into_iter()
        .map(|n| offer(n, 1_000))
        .collect();
    offers.sort_by_key(|offer| offer.provider);
    offers[0].price.msat = 1;
    offers
}

fn candidates(state: &mut Destination, offers: &[RouteOffer], now: Instant) -> Vec<usize> {
    state.candidate_indices(
        &offers
            .iter()
            .map(|offer| offer.provider)
            .collect::<Vec<_>>(),
        now,
    )
}

#[test]
fn excluded_active_and_alternative_providers_do_not_consume_candidate_slots() {
    let offers = offers();
    let policy = PriceSelectionPolicy::default();
    let now = Instant::now();
    let mut state = Destination {
        active: Some(offers[0].clone()),
        ..Default::default()
    };
    state
        .observe(
            &SourceRouteQuality {
                next_hop: Some(offers[0].provider),
                delivery_feedback_timed_out: true,
                ..Default::default()
            },
            &policy,
            now,
        )
        .unwrap();
    state.fail(offers[2].provider, &policy, now).unwrap();
    let exclusions = state.failed.clone();
    let indices = candidates(&mut state, &offers, now);
    assert_eq!(indices, vec![1, 3, 4, 5]);
    assert_eq!(
        state.cursor, 3,
        "rotation remains over the original peer list"
    );
    assert_eq!(state.failed, exclusions);
    let quoted = indices.into_iter().map(|i| offers[i].clone()).collect();
    assert_eq!(state.choose(quoted, &policy, now).unwrap(), offers[1]);
    assert_eq!(
        state.choose(offers.clone(), &policy, now).unwrap(),
        offers[1],
        "final selection independently rejects excluded quotes"
    );
}

#[test]
fn healthy_active_and_idle_unknown_candidates_keep_existing_rotation() {
    let offers = offers();
    let policy = PriceSelectionPolicy::default();
    let now = Instant::now();
    let mut state = Destination {
        active: Some(offers[2].clone()),
        cursor: 4,
        ..Default::default()
    };
    state
        .observe(
            &SourceRouteQuality {
                next_hop: Some(offers[2].provider),
                ..Default::default()
            },
            &policy,
            now,
        )
        .unwrap();
    assert_eq!(candidates(&mut state, &offers, now), vec![2, 4, 5, 0]);
    assert_eq!(state.cursor, 1);
    state
        .observe(&working(&offers[2], 0.0), &policy, now)
        .unwrap();
    assert_eq!(candidates(&mut state, &offers, now), vec![2, 1, 3, 4]);
    assert_eq!(state.cursor, 4);
    state.active = None;
    assert_eq!(candidates(&mut state, &offers, now), vec![4, 5, 0, 1]);
    let cursor = state.cursor;
    assert!(state.candidate_indices(&[], now).is_empty());
    assert_eq!(state.cursor, cursor);
}

#[test]
fn cooldown_expiry_restores_discovery_but_keeps_bounded_retry_state() {
    let offers = offers();
    let policy = PriceSelectionPolicy::default();
    let now = Instant::now();
    let mut state = Destination {
        active: Some(offers[0].clone()),
        ..Default::default()
    };
    state.fail(offers[0].provider, &policy, now).unwrap();
    let retry_at = state.failed[&offers[0].provider];
    let just_before = retry_at - Duration::from_millis(1);
    assert!(!candidates(&mut state, &offers, just_before).contains(&0));
    state
        .fail(offers[0].provider, &policy, just_before)
        .unwrap();
    assert_eq!(state.failed[&offers[0].provider], retry_at);
    assert_eq!(candidates(&mut state, &offers, retry_at)[0], 0);
    assert_eq!(
        state.failed[&offers[0].provider], retry_at,
        "discovery must retain expired failure state for a fresh bounded retry"
    );
    let selected = state.choose(offers.clone(), &policy, retry_at).unwrap();
    assert_eq!(selected, offers[0]);
    assert!(matches!(
        state
            .selection_step(&selected, &policy, true, |_| None)
            .unwrap(),
        SelectionStep::Request {
            max_units: Some(32_768),
            reuse_unchanged: false
        }
    ));
}

#[test]
fn exhausted_unknown_trial_stays_excluded_after_cooldown_until_qualified() {
    let mut offers = offers();
    offers[0].trial = true;
    offers[0].max_units = 32_768;
    offers[0].expires_unix = unix_now().unwrap() + 600;
    let policy = PriceSelectionPolicy::default();
    let now = Instant::now();
    let mut state = Destination {
        active: Some(offers[0].clone()),
        ..Default::default()
    };
    state.observe_admission(true, &policy, now).unwrap();
    let retry_at = state.failed[&offers[0].provider];
    for at in [now, retry_at + Duration::from_secs(1)] {
        state.observe_admission(false, &policy, at).unwrap();
        assert!(!candidates(&mut state, &offers, at).contains(&0));
        assert!(
            state
                .candidate_indices(&[offers[0].provider], at)
                .is_empty()
        );
        assert!(state.choose(vec![offers[0].clone()], &policy, at).is_err());
        assert_eq!(state.failed[&offers[0].provider], retry_at);
        assert_eq!(state.blocked_trial.as_deref(), Some(offers[0].id.as_str()));
    }
    let qualified_at = retry_at + Duration::from_secs(2);
    state
        .observe(&working(&offers[0], 0.0), &policy, qualified_at)
        .unwrap();
    state
        .observe_admission(false, &policy, qualified_at)
        .unwrap();
    assert_eq!(candidates(&mut state, &offers, qualified_at)[0], 0);
    assert!(state.failed.is_empty());
    assert!(state.blocked_trial.is_none());
    let selected = state.choose(offers, &policy, qualified_at).unwrap();
    assert!(matches!(
        state
            .selection_step(&selected, &policy, true, |_| None)
            .unwrap(),
        SelectionStep::Request {
            max_units: None,
            reuse_unchanged: false
        }
    ));
}
