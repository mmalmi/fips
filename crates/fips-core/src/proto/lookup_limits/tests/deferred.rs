use super::*;

#[test]
fn waiting_requires_ingress_budget_without_allocating_another_scope() {
    let mut limiter = DiscoveryForwardRateLimiter::new();
    limiter.ingress_burst = 1.0;
    limiter.ingress_rate = 0.0;
    assert!(limiter.should_forward(&addr(1), &addr(10)));
    let key = (addr(1), addr(1), addr(10));
    let last = limiter.last_forwarded[&key];
    assert_eq!(
        limiter.deferred_deadline(&addr(1), &addr(1), &addr(10)),
        None
    );
    assert_eq!(
        limiter.deferred_deadline(&addr(2), &addr(1), &addr(10)),
        None
    );
    assert_eq!(limiter.len(), 1);
    assert_eq!(limiter.ingress_len(), 1);
    assert_eq!(limiter.last_forwarded[&key], last);
}

#[test]
fn waiting_cannot_expand_the_existing_ingress_bucket_bound() {
    let mut limiter = DiscoveryForwardRateLimiter::new();
    limiter.max_ingress_peers = 1;
    assert!(limiter.should_forward(&addr(1), &addr(10)));
    assert!(!limiter.should_forward_for_origin(&addr(2), &addr(1), &addr(10)));
    assert_eq!(
        limiter.deferred_deadline(&addr(2), &addr(1), &addr(10)),
        None
    );
    assert_eq!(limiter.ingress_len(), 1);
    assert_eq!(limiter.len(), 1);
}

#[test]
fn shared_ingress_can_wait_without_advancing_the_slot_or_spending_tokens() {
    let mut limiter = DiscoveryForwardRateLimiter::new();
    limiter.ingress_burst = 2.0;
    limiter.ingress_rate = 0.0;
    assert!(limiter.should_forward(&addr(1), &addr(10)));
    let key = (addr(1), addr(1), addr(10));
    let last = limiter.last_forwarded[&key];
    let due = last + Duration::from_secs(2);
    for _ in 0..100 {
        assert_eq!(
            limiter.deferred_deadline(&addr(1), &addr(1), &addr(10)),
            Some(due)
        );
        assert_eq!(limiter.last_forwarded[&key], last);
        assert_eq!(limiter.ingress_buckets[&addr(1)].tokens, 1.0);
    }
    assert_eq!(
        limiter.decision_at(&addr(1), &addr(10), due - Duration::from_nanos(1)),
        DiscoveryForwardDecision::TargetInterval
    );
    assert_eq!(
        limiter.decision_at(&addr(1), &addr(10), due),
        DiscoveryForwardDecision::Forward
    );
    assert_eq!(limiter.ingress_buckets[&addr(1)].tokens, 0.0);
    assert_eq!(
        limiter.deferred_deadline(&addr(1), &addr(1), &addr(10)),
        None
    );
    assert_eq!(
        limiter.decision_at(&addr(1), &addr(11), due),
        DiscoveryForwardDecision::IngressBudget
    );
}
