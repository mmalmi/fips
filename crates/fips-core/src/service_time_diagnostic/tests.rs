use super::*;

fn plan() -> Plan {
    let start = Instant::now() + Duration::from_secs(1);
    Plan {
        epoch_ms: 10_000,
        start,
        end: start + Duration::from_millis(WINDOW_MS),
    }
}

#[test]
fn activation_requires_bounded_future_epoch() {
    let now = Instant::now();
    for raw in ["", "x", "999", "1000", "5999", "121001"] {
        assert!(Plan::parse(raw, 1_000, now).is_err(), "{raw}");
    }
    for raw in ["6000", "121000"] {
        let plan = Plan::parse(raw, 1_000, now).unwrap();
        assert_eq!(plan.end.duration_since(plan.start), Duration::from_secs(15));
        assert_eq!(
            plan.start.duration_since(now).as_millis(),
            raw.parse::<u128>().unwrap() - 1_000
        );
    }
}

#[test]
fn warmup_is_excluded_but_spanning_work_is_carried_in() {
    let p = plan();
    let mut state = State::new();
    let before = state
        .begin(
            &p,
            Stage::SerialControl,
            p.start - Duration::from_millis(500),
        )
        .unwrap();
    state.finish(&p, before, p.start);
    assert_eq!(state.aggregates[0].ended, 0);
    let spanning = state
        .begin(
            &p,
            Stage::SerialControl,
            p.start - Duration::from_millis(100),
        )
        .unwrap();
    state.finish(&p, spanning, p.start + Duration::from_millis(25));
    let aggregate = state.aggregates[0];
    assert_eq!(
        (aggregate.ended, aggregate.cutoff, aggregate.carried_in),
        (1, 0, 1)
    );
    assert_eq!(aggregate.inclusive_wall_ns, 25_000_000);
    assert_eq!(aggregate.duration_histogram.iter().sum::<u64>(), 1);
}

#[test]
fn terminal_charges_in_flight_work_once_and_freezes_counters() {
    let p = plan();
    let mut state = State::new();
    let slot = state
        .begin(&p, Stage::SerialControl, p.start - Duration::from_secs(1))
        .unwrap();
    assert!(state.close(&p));
    assert!(!state.close(&p));
    state.finish(&p, slot, p.end + Duration::from_secs(10));
    let aggregate = state.aggregates[0];
    assert_eq!(
        (aggregate.ended, aggregate.cutoff, aggregate.carried_in),
        (0, 1, 1)
    );
    assert_eq!(aggregate.inclusive_wall_ns, 15_000_000_000);
    assert_eq!(aggregate.duration_histogram[7], 1);
    assert!(state.begin(&p, Stage::SerialControl, p.end).is_none());
    assert!(state.active.iter().all(Option::is_none));
}

#[test]
fn late_timer_does_not_extend_window_or_double_charge_finished_cutoffs() {
    let p = plan();
    let mut state = State::new();
    let slot = state
        .begin(&p, Stage::Msg1Stranger, p.end - Duration::from_millis(5))
        .unwrap();
    state.finish(&p, slot, p.end + Duration::from_secs(30));
    assert!(state.begin(&p, Stage::SerialControl, p.end).is_none());
    state.close(&p);
    let aggregate = state.aggregates[Stage::Msg1Stranger as usize];
    assert_eq!(aggregate.inclusive_wall_ns, 5_000_000);
    assert_eq!((aggregate.ended, aggregate.cutoff), (0, 1));
}

#[test]
fn nested_stages_are_inclusive_and_classification_preserves_prefix_time() {
    let p = plan();
    let mut state = State::new();
    let outer = state.begin(&p, Stage::SerialControl, p.start).unwrap();
    let msg1 = state
        .begin(
            &p,
            Stage::Msg1Unclassified,
            p.start + Duration::from_millis(1),
        )
        .unwrap();
    state.classify_msg1(&p, msg1, p.start + Duration::from_millis(3), true);
    let sync = state
        .begin(&p, Stage::FmpOwnerSync, p.start + Duration::from_millis(4))
        .unwrap();
    state.finish(&p, sync, p.start + Duration::from_millis(6));
    state.finish(&p, msg1, p.start + Duration::from_millis(8));
    state.finish(&p, outer, p.start + Duration::from_millis(10));
    assert_eq!(
        state.aggregates[Stage::SerialControl as usize].inclusive_wall_ns,
        10_000_000
    );
    assert_eq!(
        state.aggregates[Stage::Msg1Established as usize].inclusive_wall_ns,
        7_000_000
    );
    assert_eq!(
        state.aggregates[Stage::FmpOwnerSync as usize].inclusive_wall_ns,
        2_000_000
    );
    assert_eq!(state.aggregates[Stage::Msg1Unclassified as usize].ended, 0);
    let late = state
        .begin(
            &p,
            Stage::Msg1Unclassified,
            p.end - Duration::from_millis(1),
        )
        .unwrap();
    state.classify_msg1(&p, late, p.end, false);
    state.close(&p);
    assert_eq!(state.aggregates[Stage::Msg1Unclassified as usize].cutoff, 1);
    assert_eq!(state.aggregates[Stage::Msg1Stranger as usize].cutoff, 0);
}

#[test]
fn bounded_slots_report_overflow_and_reuse_finished_slots() {
    let p = plan();
    let mut state = State::new();
    for slot in 0..SLOTS {
        assert_eq!(state.begin(&p, Stage::SerialControl, p.start), Some(slot));
    }
    assert!(state.begin(&p, Stage::SerialControl, p.start).is_none());
    assert_eq!(state.slot_overflow, 1);
    state.finish(&p, 3, p.start + Duration::from_millis(1));
    assert_eq!(
        state.begin(&p, Stage::FmpOwnerSync, p.start + Duration::from_millis(2)),
        Some(3)
    );
    state.close(&p);
    let counts: u64 = state.aggregates.iter().map(|a| a.ended + a.cutoff).sum();
    assert_eq!(counts, SLOTS as u64 + 1);
}

#[test]
fn fanout_counts_only_refreshes_ended_within_window() {
    let p = plan();
    let mut state = State::new();
    let done = state.begin(&p, Stage::FspRouteRefresh, p.start).unwrap();
    state.active[done].as_mut().unwrap().fanout = Some((128, 17));
    state.finish(&p, done, p.start + Duration::from_millis(3));
    let cutoff = state
        .begin(
            &p,
            Stage::FspRouteRefresh,
            p.start + Duration::from_millis(4),
        )
        .unwrap();
    state.active[cutoff].as_mut().unwrap().fanout = Some((1_024, 500));
    state.close(&p);
    assert_eq!(state.fanout.ended_refreshes, 1);
    assert_eq!(state.fanout.destinations_scanned, 128);
    assert_eq!(state.fanout.destinations_refreshed, 17);
    assert_eq!(state.fanout.refreshed_histogram[4], 1);
    assert_eq!(state.aggregates[Stage::FspRouteRefresh as usize].cutoff, 1);
}

#[test]
fn histogram_edges_and_stage_names_have_fixed_schema() {
    for (index, bound) in DURATION_UPPER_US.iter().enumerate() {
        assert_eq!(bucket(*bound, &DURATION_UPPER_US), index);
        assert_eq!(bucket(*bound + 1, &DURATION_UPPER_US), index + 1);
    }
    assert_eq!(bucket(0, &FANOUT_UPPER), 0);
    assert_eq!(bucket(u64::MAX, &FANOUT_UPPER), 7);
    assert_eq!(
        serde_json::to_string(&ALL_STAGES).unwrap(),
        "[\"serial_control\",\"msg1_unclassified\",\"msg1_stranger\",\"msg1_established\",\"fmp_owner_sync\",\"fsp_route_refresh\",\"msg1_rekey_owner_sync\"]"
    );
}

#[test]
fn timer_closes_without_traffic_and_live_guard_drop_cannot_double_count() {
    // Only the test uses a short clock; production Plan::parse fixes 15 seconds.
    let start = Instant::now() + Duration::from_millis(2);
    let recorder = Arc::new(Recorder::new(Plan {
        epoch_ms: 10_000,
        start,
        end: start + Duration::from_millis(2),
    }));
    let slot = recorder
        .lock()
        .begin(
            &recorder.plan,
            Stage::SerialControl,
            start - Duration::from_millis(1),
        )
        .unwrap();
    let guard = Span {
        recorder: Some(Arc::clone(&recorder)),
        slot,
    };
    recorder.run_timer();
    assert!(recorder.closed.load(Ordering::Relaxed));
    drop(guard);
    let state = recorder.lock();
    assert_eq!(state.aggregates[0].cutoff, 1);
    assert_eq!(state.aggregates[0].inclusive_wall_ns, 2_000_000);
}

#[test]
fn guards_release_slots_on_drop_and_mark_early_loop_exit() {
    fn require_send<T: Send>() {}
    require_send::<Span>();
    require_send::<RxLoopGuard>();
    let start = Instant::now() - Duration::from_millis(1);
    let recorder = Arc::new(Recorder::new(Plan {
        epoch_ms: 10_000,
        start,
        end: start + Duration::from_secs(15),
    }));
    let slot = recorder
        .lock()
        .begin(&recorder.plan, Stage::Msg1Unclassified, start)
        .unwrap();
    let mut guard = Span {
        recorder: Some(Arc::clone(&recorder)),
        slot,
    };
    guard.classify_msg1(false);
    drop(guard);
    drop(RxLoopGuard(Some(Arc::clone(&recorder))));
    let state = recorder.lock();
    assert!(state.active.iter().all(Option::is_none));
    assert_eq!(state.aggregates[Stage::Msg1Stranger as usize].ended, 1);
    assert!(state.rx_loop_exited_early);
}
