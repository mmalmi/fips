use super::*;

#[test]
fn pending_boundary_cannot_omit_a_committed_event_waiting_for_insertion() {
    let mut trace = Trace::new();
    trace.begin(Some(10));
    // Persistence may already have returned; insertion has not acquired the lock.
    let before = trace.snapshot(Some(30));
    assert_eq!(before.pending, 1);
    assert_eq!(before.completed_sequence, 0);
    assert!(before.events.is_empty());
    trace.committed("original", 3, 5, Some(10), Some(20));
    let after = trace.snapshot(Some(40));
    assert_eq!(after.pending, 0);
    assert_eq!(after.measured_at_ns, Some(40));
    let event = &after.events[0];
    assert_eq!((event.sequence, event.old_sat, event.new_sat), (1, 3, 5));
    assert_eq!((event.started_ns, event.finished_ns), (10, 20));
}

#[test]
fn rollover_exposes_the_exact_retained_sequence_range() {
    let mut trace = Trace::new();
    for n in 0..CAPACITY as u64 + 3 {
        trace.begin(Some(n * 10));
        trace.committed("original", n, n + 1, Some(n * 10), Some(n * 10 + 1));
    }
    let sample = trace.snapshot(Some((CAPACITY as u64 + 4) * 10));
    assert_eq!(sample.events.len(), CAPACITY);
    assert_eq!(sample.completed_sequence, CAPACITY as u64 + 3);
    assert_eq!(sample.overwritten, 3);
    assert_eq!(sample.events[0].sequence, 4);
    assert!(
        sample
            .events
            .windows(2)
            .all(|w| w[1].sequence == w[0].sequence + 1)
    );
    assert_eq!(
        sample.events.last().unwrap().sequence,
        sample.completed_sequence
    );
}

#[test]
fn missing_or_backwards_clocks_and_invalid_ids_leave_visible_sequence_gaps() {
    let mut trace = Trace::new();
    let oversized = "x".repeat(MAX_CHANNEL_ID_BYTES + 1);
    for (id, start, end) in [
        ("original", None, Some(20)),
        ("original", Some(30), None),
        ("original", Some(50), Some(40)),
        ("", Some(60), Some(70)),
        (oversized.as_str(), Some(80), Some(90)),
    ] {
        trace.begin(start);
        trace.committed(id, 1, 2, start, end);
    }
    trace.begin(Some(100));
    trace.committed("original", 2, 3, Some(100), Some(110));
    let sample = trace.snapshot(None);
    assert_eq!(sample.pending, 0);
    assert_eq!(sample.completed_sequence, 6);
    assert_eq!(sample.missing_intervals, 5);
    assert_eq!(sample.clock_failures, 4);
    assert_eq!(sample.measured_at_ns, None);
    assert_eq!(sample.events.len(), 1);
    assert_eq!(sample.events[0].sequence, 6);
}

#[test]
fn sequence_exhaustion_does_not_wrap_into_plausible_coverage() {
    let mut trace = Trace::new();
    trace.completed_sequence = u64::MAX;
    trace.begin(Some(1));
    trace.committed("original", 1, 2, Some(1), Some(2));
    let sample = trace.snapshot(Some(3));
    assert!(sample.sequence_exhausted);
    assert_eq!(sample.completed_sequence, u64::MAX);
    assert_eq!(sample.missing_intervals, 1);
    assert_eq!(sample.pending, 0);
    assert!(sample.events.is_empty());
}
