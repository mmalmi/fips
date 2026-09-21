use super::*;

fn pending() -> SenderState {
    let mut state = SenderState::new();
    state.record_sent(0, 3, 37);
    state
}

#[test]
fn pending_sender_adopts_fresh_interval_once() {
    let mut state = SenderState::new();
    assert!(state.absorb_pending_sender(pending()).is_ok());
    let refused = state.absorb_pending_sender(pending()).err().unwrap();
    assert_eq!(refused.cumulative_packets_sent(), 1);
    assert_eq!(refused.cumulative_bytes_sent(), 37);
    let report = state.build_report(Instant::now()).unwrap();
    assert_eq!(report.cumulative_packets_sent, 1);
    assert_eq!(report.cumulative_bytes_sent, 37);
    assert_eq!(report.interval_start_counter, 0);
    assert_eq!(report.interval_end_counter, 0);
    assert_eq!(report.interval_start_timestamp, 3);
    assert_eq!(report.interval_end_timestamp, 3);
    assert_eq!(report.interval_bytes_sent, 37);
}

#[test]
fn pending_sender_preserves_lifetime_and_cadence_across_rekey() {
    let mut state = SenderState::new_with_cold_start(731);
    let now = Instant::now();
    state.record_sent(10, 9, 80);
    state.build_report(now).unwrap();
    state.record_send_failure();
    state.record_send_failure();
    state.record_sent(11, 10, 81);
    state.reset_for_rekey();
    let cadence = (
        state.last_report_time,
        state.report_interval,
        state.consecutive_send_failures,
        state.srtt_sample_count,
    );
    assert!(state.absorb_pending_sender(pending()).is_ok());
    assert_eq!(
        (
            state.last_report_time,
            state.report_interval,
            state.consecutive_send_failures,
            state.srtt_sample_count
        ),
        cadence
    );
    assert_eq!(
        state.next_report_at(now),
        Some(now + Duration::from_millis(731 * 4))
    );
    let report = state.build_report(now).unwrap();
    assert_eq!(report.cumulative_packets_sent, 3);
    assert_eq!(report.cumulative_bytes_sent, 198);
    assert_eq!(report.interval_start_counter, 0);
    assert_eq!(report.interval_end_counter, 0);
    assert_eq!(report.interval_bytes_sent, 37);
}

#[test]
fn pending_sender_refuses_nonempty_interval_without_mutation() {
    let mut state = SenderState::new();
    state.record_sent(5, 7, 90);
    let refused = state.absorb_pending_sender(pending()).err().unwrap();
    assert_eq!(refused.cumulative_bytes_sent(), 37);
    let report = state.build_report(Instant::now()).unwrap();
    assert_eq!(report.interval_start_counter, 5);
    assert_eq!(report.interval_end_counter, 5);
    assert_eq!(report.interval_start_timestamp, 7);
    assert_eq!(report.interval_bytes_sent, 90);
    assert_eq!(report.cumulative_packets_sent, 1);
    assert_eq!(report.cumulative_bytes_sent, 90);
}

#[test]
fn pending_sender_refuses_overflow_before_any_mutation() {
    for overflow_packets in [false, true] {
        let mut state = SenderState::new();
        // Storage-free arithmetic boundary fixture, not observed network traffic.
        state.cumulative_packets_sent = if overflow_packets { u64::MAX } else { 9 };
        state.cumulative_bytes_sent = if overflow_packets { 100 } else { u64::MAX - 36 };
        let before = (state.cumulative_packets_sent, state.cumulative_bytes_sent);
        let refused = state.absorb_pending_sender(pending()).err().unwrap();
        assert_eq!(refused.cumulative_packets_sent(), 1);
        assert_eq!(refused.cumulative_bytes_sent(), 37);
        assert_eq!(
            (state.cumulative_packets_sent, state.cumulative_bytes_sent),
            before
        );
        assert!(state.build_report(Instant::now()).is_none());
    }
}

#[test]
fn pending_sender_rejects_previously_reported_or_multi_nonce_state() {
    let mut state = SenderState::new();
    let mut reported = pending();
    reported.build_report(Instant::now()).unwrap();
    assert!(state.absorb_pending_sender(reported).is_err());
    let mut multiple = pending();
    multiple.record_sent(1, 4, 37);
    assert!(state.absorb_pending_sender(multiple).is_err());
    assert!(state.absorb_pending_sender(SenderState::new()).is_ok());
    assert_eq!(state.cumulative_packets_sent(), 0);
    assert_eq!(state.cumulative_bytes_sent(), 0);
    assert!(state.build_report(Instant::now()).is_none());
}
