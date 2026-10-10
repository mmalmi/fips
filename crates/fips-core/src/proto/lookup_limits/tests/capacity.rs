use super::*;

#[test]
fn quiet_ingress_reuses_expired_slots_without_evicting_active_cooldowns() {
    let mut limiter = DiscoveryForwardRateLimiter::new();
    let now = instant_now();
    for target in 0..FORWARD_MAX_TARGETS as u32 {
        let ingress = numbered_addr(10_000 + target / DEFAULT_FORWARD_BURST as u32);
        assert_eq!(
            limiter.decision_at(&ingress, &numbered_addr(target), now),
            DiscoveryForwardDecision::Forward
        );
    }
    let quiet = numbered_addr(20_000);
    let target = numbered_addr(30_000);
    let due = now + DEFAULT_FORWARD_MIN_INTERVAL;
    assert_eq!(
        limiter.decision_at(&quiet, &target, due - Duration::from_nanos(1)),
        DiscoveryForwardDecision::TargetCapacity
    );
    assert_eq!(
        limiter.decision_at(&quiet, &target, due),
        DiscoveryForwardDecision::Forward,
        "idle retention must not extend expired cooldowns"
    );
    assert_eq!(limiter.len(), FORWARD_MAX_TARGETS);
    assert_eq!(
        limiter.decision_at(&quiet, &target, due),
        DiscoveryForwardDecision::TargetInterval
    );
}

fn small_limiter(now: Instant) -> DiscoveryForwardRateLimiter {
    DiscoveryForwardRateLimiter::with_test_params(
        now,
        DiscoveryForwardTestParams {
            min_interval: Duration::from_secs(2),
            max_age: Duration::from_secs(60),
            max_targets: 2,
            max_ingress_peers: 4,
            ingress_burst: 2.0,
            ingress_rate: 0.0,
            ingress_max_age: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(5),
        },
    )
}

#[test]
fn rejected_ingress_cannot_evict_even_expired_scope_state() {
    let now = instant_now();
    let mut limiter = small_limiter(now);
    for target in [1, 2] {
        assert_eq!(
            limiter.decision_at(&addr(90), &addr(target), now),
            DiscoveryForwardDecision::Forward
        );
    }
    let before = limiter.last_forwarded.clone();
    let index = limiter.forwarded_by_time.clone();
    let due = now + Duration::from_secs(2);
    assert_eq!(
        limiter.decision_for_origin_at(&addr(90), &addr(91), &addr(3), due),
        DiscoveryForwardDecision::IngressBudget,
        "changing claimed origin must not bypass the authenticated budget"
    );
    limiter.max_ingress_peers = 1;
    assert_eq!(
        limiter.decision_at(&addr(91), &addr(3), due),
        DiscoveryForwardDecision::IngressCapacity
    );
    assert_eq!(limiter.last_forwarded, before);
    assert_eq!(limiter.forwarded_by_time, index);
}

#[test]
fn refreshing_a_scope_preserves_its_new_cooldown_under_churn() {
    let now = instant_now();
    let mut limiter = small_limiter(now);
    limiter.ingress_burst = 4.0;
    for origin in [1, 2] {
        assert_eq!(
            limiter.decision_for_origin_at(&addr(90), &addr(origin), &addr(99), now),
            DiscoveryForwardDecision::Forward
        );
    }
    let due = now + Duration::from_secs(2);
    for origin in [1, 3] {
        assert_eq!(
            limiter.decision_for_origin_at(&addr(90), &addr(origin), &addr(99), due),
            DiscoveryForwardDecision::Forward
        );
    }
    assert!(
        limiter
            .last_forwarded
            .contains_key(&(addr(90), addr(1), addr(99)))
    );
    assert!(
        !limiter
            .last_forwarded
            .contains_key(&(addr(90), addr(2), addr(99)))
    );
    assert_eq!(
        limiter.decision_for_origin_at(&addr(90), &addr(1), &addr(99), due),
        DiscoveryForwardDecision::TargetInterval
    );
    assert_eq!(
        limiter.decision_for_origin_at(&addr(91), &addr(1), &addr(99), due),
        DiscoveryForwardDecision::TargetCapacity,
        "new ingress cannot evict another ingress's active cooldown"
    );
    assert_eq!(limiter.len(), 2);
}

#[test]
fn full_scope_table_can_defer_new_ingress_without_spending_or_reserving() {
    let mut limiter = DiscoveryForwardRateLimiter::new();
    limiter.max_targets = 1;
    assert!(limiter.should_forward(&addr(1), &addr(99)));
    let before = limiter.last_forwarded.clone();
    let due = before[&(addr(1), addr(1), addr(99))] + DEFAULT_FORWARD_MIN_INTERVAL;
    for _ in 0..100 {
        assert_eq!(
            limiter.deferred_deadline(&addr(2), &addr(3), &addr(99)),
            Some(due)
        );
        assert_eq!(
            limiter.ingress_buckets[&addr(2)].tokens,
            DEFAULT_FORWARD_BURST
        );
        assert_eq!(limiter.last_forwarded, before);
    }
    assert_eq!(limiter.forwarded_by_time.len(), 1);
    limiter.ingress_buckets.get_mut(&addr(2)).unwrap().tokens = 0.0;
    limiter.ingress_rate = 0.0;
    assert_eq!(
        limiter.deferred_deadline(&addr(2), &addr(3), &addr(99)),
        None
    );
}

#[test]
fn zero_target_capacity_never_allocates() {
    let mut limiter = DiscoveryForwardRateLimiter::new();
    limiter.max_targets = 0;
    assert!(!limiter.should_forward(&addr(1), &addr(2)));
    assert!(
        limiter
            .deferred_deadline(&addr(1), &addr(1), &addr(2))
            .is_none()
    );
    assert!(limiter.last_forwarded.is_empty());
    assert!(limiter.forwarded_by_time.is_empty());
    assert!(limiter.ingress_buckets.is_empty());
}

#[test]
fn expiry_index_stays_bounded_through_scope_refresh_churn_and_cleanup() {
    let mut limiter = DiscoveryForwardRateLimiter::with_interval(Duration::ZERO);
    limiter.max_targets = 8;
    let now = instant_now();
    for i in 0..10_000 {
        let ingress = numbered_addr(20_000 + i / DEFAULT_FORWARD_BURST as u32);
        let origin = numbered_addr(i / 4);
        let target = numbered_addr(i / 2);
        assert_eq!(
            limiter.decision_for_origin_at(&ingress, &origin, &target, now),
            DiscoveryForwardDecision::Forward
        );
        assert_eq!(limiter.forwarded_by_time.len(), limiter.len());
        assert!(limiter.len() <= 8);
        assert!(
            limiter
                .forwarded_by_time
                .iter()
                .all(|(last, key)| limiter.last_forwarded.get(key) == Some(last))
        );
    }
    limiter.cleanup(now + FORWARD_MAX_AGE);
    assert!(limiter.last_forwarded.is_empty());
    assert!(limiter.forwarded_by_time.is_empty());
}
