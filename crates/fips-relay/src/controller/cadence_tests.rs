use super::*;

#[test]
fn confirmed_idle_channels_do_not_poll_and_new_usage_has_a_deadline() {
    let policy = PaymentCadence::default();
    let start = tokio::time::Instant::now();
    let mut channel = ChannelSchedule::default();
    assert!(channel.due(start, 0, 0, 8_000, &policy));
    channel.acknowledge(0);
    assert!(!channel.due(start + Duration::from_secs(100), 0, 0, 8_000, &policy));
    assert!(!channel.due(start, 250, 0, 8_000, &policy));
    assert!(!channel.due(start + Duration::from_millis(499), 250, 0, 8_000, &policy));
    assert!(channel.due(start + Duration::from_millis(500), 250, 0, 8_000, &policy));
    channel.acknowledge(1_000);
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
    channel.acknowledge(10_000);
    assert!(!channel.due(start, 13_999, 10, 8_000, &policy));
    assert!(channel.due(start, 14_000, 10, 8_000, &policy));
    channel.acknowledge(14_000);
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
    channel.acknowledge(0);
    // A durable signed obligation survives even if the crash lost local sends.
    assert!(channel.due(start + RETRY_DELAY, 0, 5, 8_000, &policy));
}

#[test]
fn schedules_are_independent_and_payment_quantization_does_not_create_traffic() {
    let policy = PaymentCadence::default();
    let now = tokio::time::Instant::now();
    let mut busy = ChannelSchedule::default();
    let mut idle = ChannelSchedule::default();
    busy.acknowledge(0);
    idle.acknowledge(1_000);
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
