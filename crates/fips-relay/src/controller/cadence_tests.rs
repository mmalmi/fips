use super::*;

#[test]
fn confirmed_idle_channels_do_not_poll_and_new_usage_has_a_deadline() {
    let policy = PaymentCadence::default();
    let start = tokio::time::Instant::now();
    let mut channel = ChannelSchedule::default();
    assert!(channel.due(start, 0, 0, 8_000, &policy));
    channel.acknowledge(start, 0, 0);
    assert!(!channel.due(start + Duration::from_secs(100), 0, 0, 8_000, &policy));
    assert!(!channel.due(start, 250, 0, 8_000, &policy));
    assert!(!channel.due(start + Duration::from_millis(499), 250, 0, 8_000, &policy));
    assert!(channel.due(start + Duration::from_millis(500), 250, 0, 8_000, &policy));
    channel.acknowledge(start + Duration::from_millis(500), 250, 1_000);
    assert!(!channel.due(start + Duration::from_secs(1), 900, 1, 8_000, &policy));
}

#[test]
fn priced_usage_triggers_before_the_timer_and_acknowledged_credit_is_subtracted() {
    let policy = PaymentCadence {
        max_delay_ms: 2_000,
        unpaid_percent: 50,
    };
    let start = tokio::time::Instant::now();
    let mut channel = ChannelSchedule::default();
    channel.acknowledge(start, 10_000, 10_000);
    assert!(!channel.due(start, 13_999, 10, 8_000, &policy));
    assert!(channel.due(start, 14_000, 10, 8_000, &policy));
    channel.acknowledge(start, 14_000, 14_000);
    assert!(!channel.due(start, 14_000, 14, 8_000, &policy));
}

#[test]
fn failed_exchanges_retry_without_fresh_traffic_or_resetting_liability() {
    let policy = PaymentCadence::default();
    let start = tokio::time::Instant::now();
    let mut channel = ChannelSchedule::default();
    channel.failed(start);
    assert!(!channel.due(start, 0, 5, 8_000, &policy));
    assert!(channel.due(start + RETRY_DELAY, 0, 5, 8_000, &policy));
    channel.acknowledge(start, 0, 0);
    // A durable signed obligation survives even if the crash lost local sends.
    assert!(channel.due(start + RETRY_DELAY, 0, 5, 8_000, &policy));
}

#[test]
fn schedules_are_independent_and_payment_quantization_does_not_create_traffic() {
    let policy = PaymentCadence::default();
    let now = tokio::time::Instant::now();
    let mut busy = ChannelSchedule::default();
    let mut idle = ChannelSchedule::default();
    busy.acknowledge(now, 0, 0);
    idle.acknowledge(now, 999, 1_000);
    assert!(busy.due(now, 1, 0, 0, &policy));
    assert!(!idle.due(now, 999, 1, 8_000, &policy));
}

#[test]
fn policy_bounds_and_default_json_are_explicit() {
    let p: PaymentCadence = serde_json::from_str("{}").unwrap();
    assert_eq!(p, PaymentCadence::default());
    for delay in [250, 500, 1_000, 2_000] {
        assert!(
            PaymentCadence {
                max_delay_ms: delay,
                unpaid_percent: 50
            }
            .validate()
            .is_ok()
        );
    }
    for p in [
        PaymentCadence {
            max_delay_ms: 0,
            unpaid_percent: 50,
        },
        PaymentCadence {
            max_delay_ms: 500,
            unpaid_percent: 0,
        },
        PaymentCadence {
            max_delay_ms: 500,
            unpaid_percent: 100,
        },
    ] {
        assert!(p.validate().is_err());
    }
}

#[test]
fn unchanged_unclaimed_usage_backs_off_but_late_claims_remain_reconcilable() {
    let policy = PaymentCadence::default();
    let mut now = tokio::time::Instant::now();
    let mut channel = ChannelSchedule::default();
    channel.acknowledge(now, 9_584, 8_000);
    for millis in [500, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000] {
        let deadline = now + Duration::from_millis(millis);
        assert!(!channel.due(
            deadline - Duration::from_millis(1),
            9_584,
            8,
            8_000,
            &policy
        ));
        assert!(channel.due(deadline, 9_584, 8, 8_000, &policy));
        now = deadline;
        channel.acknowledge(now, 9_584, 8_000);
        assert_eq!(
            channel.acknowledged_msat,
            Some(8_000),
            "unclaimed sends are not payment"
        );
    }
    // Progress on a late claim restores the short recheck; paying it in full
    // then suppresses polling without needing another packet or settlement.
    channel.acknowledge(now, 9_584, 9_000);
    assert!(channel.due(now + RETRY_DELAY, 9_584, 9, 8_000, &policy));
    channel.acknowledge(now + RETRY_DELAY, 9_584, 10_000);
    assert!(!channel.due(now + Duration::from_secs(100), 9_584, 10, 8_000, &policy));
}

#[test]
fn new_sends_signed_liability_and_errors_wake_a_stalled_claim() {
    let policy = PaymentCadence::default();
    let now = tokio::time::Instant::now();
    for (evidence, authorized, delay) in [(9_585, 8, 500), (12_000, 8, 0), (9_584, 12, 0)] {
        let mut channel = ChannelSchedule::default();
        channel.acknowledge(now, 9_584, 8_000);
        channel.acknowledge(now, 9_584, 8_000);
        assert!(!channel.due(now, 9_584, 8, 8_000, &policy));
        assert_eq!(
            channel.due(now, evidence, authorized, 8_000, &policy),
            delay == 0
        );
        assert!(channel.due(
            now + Duration::from_millis(delay),
            evidence,
            authorized,
            8_000,
            &policy
        ));
    }
    let mut channel = ChannelSchedule::default();
    channel.acknowledge(now, 9_584, 8_000);
    channel.acknowledge(now, 9_584, 8_000);
    channel.failed(now);
    assert!(!channel.due(
        now + RETRY_DELAY - Duration::from_millis(1),
        9_584,
        8,
        8_000,
        &policy
    ));
    assert!(channel.due(now + RETRY_DELAY, 9_584, 8, 8_000, &policy));
}
