use super::*;

#[test]
fn distinct_origins_share_ingress_without_sharing_the_retry_delay() {
    let mut limiter = DiscoveryForwardRateLimiter::new();
    let now = instant_now();
    for origin in 1..=16 {
        assert_eq!(
            limiter.decision_for_origin_at(&addr(50), &addr(origin), &addr(99), now),
            DiscoveryForwardDecision::Forward
        );
        // Fresh request IDs cannot reset this authenticated origin's slot.
        for _ in 0..2 {
            assert_eq!(
                limiter.decision_for_origin_at(&addr(50), &addr(origin), &addr(99), now),
                DiscoveryForwardDecision::TargetInterval
            );
        }
    }
    assert_eq!(limiter.len(), 16);
    assert_eq!(
        limiter.ingress_buckets[&addr(50)].tokens,
        DEFAULT_FORWARD_BURST - 16.0
    );
}

#[test]
fn claimed_origin_churn_spends_the_authenticated_ingress_budget_before_allocation() {
    let mut limiter = DiscoveryForwardRateLimiter::new();
    let now = instant_now();
    for origin in 0..DEFAULT_FORWARD_BURST as u32 {
        assert_eq!(
            limiter.decision_for_origin_at(&addr(50), &numbered_addr(origin), &addr(99), now),
            DiscoveryForwardDecision::Forward
        );
    }
    for origin in 256..1024 {
        assert_eq!(
            limiter.decision_for_origin_at(&addr(50), &numbered_addr(origin), &addr(99), now),
            DiscoveryForwardDecision::IngressBudget
        );
    }
    assert_eq!(limiter.len(), 256);
    assert_eq!(limiter.ingress_len(), 1);
    assert_eq!(
        limiter.decision_for_origin_at(&addr(51), &numbered_addr(1024), &addr(99), now),
        DiscoveryForwardDecision::Forward
    );
}

#[test]
fn origin_target_pairs_share_the_existing_hard_cap_and_expiry() {
    let mut limiter = DiscoveryForwardRateLimiter::new();
    limiter.max_targets = 8;
    let now = instant_now();
    for origin in 0..8 {
        assert_eq!(
            limiter.decision_for_origin_at(&addr(50), &addr(origin), &addr(99), now),
            DiscoveryForwardDecision::Forward
        );
    }
    let tokens = limiter.ingress_buckets[&addr(50)].tokens;
    assert_eq!(
        limiter.decision_for_origin_at(&addr(50), &addr(9), &addr(99), now),
        DiscoveryForwardDecision::TargetCapacity
    );
    assert_eq!(limiter.len(), 8);
    assert_eq!(limiter.ingress_buckets[&addr(50)].tokens, tokens);
    assert_eq!(
        limiter.decision_for_origin_at(&addr(50), &addr(9), &addr(99), now + FORWARD_MAX_AGE),
        DiscoveryForwardDecision::Forward
    );
    assert_eq!(limiter.len(), 1);
}

#[test]
fn forged_origin_cannot_take_another_authenticated_ingress_slot() {
    let mut limiter = DiscoveryForwardRateLimiter::new();
    let now = instant_now();
    let target = addr(99);
    let honest = addr(2);
    for ingress in [addr(1), honest] {
        assert_eq!(
            limiter.decision_for_origin_at(&ingress, &honest, &target, now),
            DiscoveryForwardDecision::Forward
        );
        assert_eq!(
            limiter.decision_for_origin_at(&ingress, &honest, &target, now),
            DiscoveryForwardDecision::TargetInterval
        );
        assert!(
            limiter
                .deferred_deadline(&ingress, &honest, &target)
                .is_some()
        );
    }
    assert_eq!(limiter.len(), 2);
}
