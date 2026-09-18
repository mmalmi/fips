use super::{
    tests::{offer, working},
    *,
};

fn trial() -> Destination {
    Destination {
        active: Some(RouteOffer {
            trial: true,
            max_units: 32_768,
            expires_unix: unix_now().unwrap() + 600,
            ..offer(2, 1_000)
        }),
        ..Default::default()
    }
}

#[test]
fn quota_blocked_unknown_trial_uses_alternative_without_refilling_after_cooldown() {
    let policy = PriceSelectionPolicy::default();
    let mut state = trial();
    let active = state.active.as_ref().unwrap().clone();
    let alternative = offer(3, 2_000);
    let now = Instant::now();
    let unknown = SourceRouteQuality {
        next_hop: Some(active.provider),
        ..Default::default()
    };
    state.observe(&unknown, &policy, now).unwrap();
    state.observe_admission(true, &policy, now).unwrap();
    let retry_at = state.failed[&active.provider];
    for at in [now, retry_at + Duration::from_secs(1)] {
        state.observe(&unknown, &policy, at).unwrap();
        // A later missing reader result (for example after channel expiry)
        // cannot erase the earlier exact trial denial.
        state.observe_admission(false, &policy, at).unwrap();
        assert_eq!(state.failed[&active.provider], retry_at);
        assert_eq!(state.active.as_ref(), Some(&active));
        assert!(state.choose(vec![active.clone()], &policy, at).is_err());
        assert_eq!(
            state
                .choose(vec![active.clone(), alternative.clone()], &policy, at)
                .unwrap(),
            alternative
        );
    }
    // Actual later selection of another carrier ends the active-trial exclusion;
    // the original provider still has the ordinary finite retry policy.
    state.active = Some(alternative);
    state.observe_admission(false, &policy, now).unwrap();
    assert!(state.choose(vec![active.clone()], &policy, now).is_err());
    assert_eq!(
        state
            .choose(vec![active.clone()], &policy, retry_at)
            .unwrap(),
        active
    );
}

#[test]
fn qualified_exhausted_trial_promotes_but_idle_and_full_routes_are_not_failed() {
    let policy = PriceSelectionPolicy::default();
    let now = Instant::now();
    let mut state = trial();
    let active = state.active.as_ref().unwrap().clone();
    state
        .observe(&SourceRouteQuality::default(), &policy, now)
        .unwrap();
    state.observe_admission(false, &policy, now).unwrap();
    assert!(state.failed.is_empty());
    assert!(matches!(
        state
            .selection_step(&active, &policy, true, |_| None)
            .unwrap(),
        SelectionStep::Retain(_)
    ));
    state.observe_admission(true, &policy, now).unwrap();
    state.observe(&working(&active, 0.0), &policy, now).unwrap();
    state.observe_admission(true, &policy, now).unwrap();
    assert!(state.failed.is_empty());
    assert!(state.blocked_trial.is_none());
    assert!(matches!(
        state
            .selection_step(&active, &policy, true, |_| None)
            .unwrap(),
        SelectionStep::Request {
            max_units: None,
            reuse_unchanged: false
        }
    ));
    state.active.as_mut().unwrap().trial = false;
    state
        .observe(&SourceRouteQuality::default(), &policy, now)
        .unwrap();
    state.observe_admission(true, &policy, now).unwrap();
    assert!(state.failed.is_empty());
    assert!(state.blocked_trial.is_none());
}
