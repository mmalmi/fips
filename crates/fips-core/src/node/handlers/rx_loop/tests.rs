use super::budget::{
    FALLBACK_INTERLEAVE_BUDGET, FALLBACK_INTERLEAVE_EVERY, FALLBACK_PRESSURE_HIGH_WATER,
    FALLBACK_PRESSURE_INTERLEAVE_BUDGET, FALLBACK_PRESSURE_INTERLEAVE_EVERY,
    FALLBACK_PRESSURE_TRAILING_BUDGET, FallbackDrainPlan, NON_PACKET_DRAIN_BUDGET,
    PACKET_DRAIN_BUDGET, authenticated_bulk_preempts_packet_rx, fallback_drain_plan,
    non_packet_drain_budget,
};
use super::drain::{
    DecryptReturnDrainCursor, PacketDrainAction, PacketDrainCursor, PriorityBulkDrainCursor,
    RxLoopDataDrainStats, RxLoopMaintenancePlan, RxLoopMaintenanceState, SingleLaneDrainCursor,
};
use std::time::{Duration, Instant};

#[test]
fn non_packet_drain_budget_caps_large_packet_turns() {
    assert_eq!(non_packet_drain_budget(0), 0);
    assert_eq!(non_packet_drain_budget(8), 8);
    assert_eq!(
        non_packet_drain_budget(PACKET_DRAIN_BUDGET),
        NON_PACKET_DRAIN_BUDGET
    );
}

#[test]
fn fallback_drain_plan_expands_bulk_turns_only_without_transport_priority() {
    assert_eq!(
        FALLBACK_PRESSURE_HIGH_WATER,
        PACKET_DRAIN_BUDGET / 2,
        "bulk fallback pressure should start before already-decrypted backlog spans a full raw receive turn"
    );

    let normal = fallback_drain_plan(0, FALLBACK_PRESSURE_HIGH_WATER - 1);
    let pressured = fallback_drain_plan(0, FALLBACK_PRESSURE_HIGH_WATER);

    assert_eq!(
        pressured,
        FallbackDrainPlan {
            interleave_every: FALLBACK_PRESSURE_INTERLEAVE_EVERY,
            interleave_budget: FALLBACK_PRESSURE_INTERLEAVE_BUDGET,
            trailing_budget: FALLBACK_PRESSURE_TRAILING_BUDGET,
        }
    );
    assert_eq!(
        normal,
        FallbackDrainPlan {
            interleave_every: FALLBACK_INTERLEAVE_EVERY,
            interleave_budget: FALLBACK_INTERLEAVE_BUDGET,
            trailing_budget: NON_PACKET_DRAIN_BUDGET,
        }
    );
    assert!(
        pressured.interleave_budget > normal.interleave_budget,
        "pressure mode should drain already-decrypted bulk faster than the normal cadence"
    );
    assert!(
        pressured.trailing_budget <= PACKET_DRAIN_BUDGET / 2,
        "pressure mode stays bounded so endpoint/timer progress returns within a packet turn"
    );
    assert_eq!(
        fallback_drain_plan(1, FALLBACK_PRESSURE_HIGH_WATER),
        FallbackDrainPlan {
            interleave_every: FALLBACK_INTERLEAVE_EVERY,
            interleave_budget: FALLBACK_INTERLEAVE_BUDGET,
            trailing_budget: NON_PACKET_DRAIN_BUDGET,
        },
        "fresh transport priority packets must keep the normal bulk-fallback cadence"
    );
}

#[test]
fn authenticated_bulk_yields_to_ready_transport_priority() {
    assert!(authenticated_bulk_preempts_packet_rx(0));
    assert!(
        !authenticated_bulk_preempts_packet_rx(1),
        "bulk endpoint delivery should not preempt a ready control-sized transport packet"
    );
}

#[test]
fn packet_drain_cursor_can_retime_fallback_interleave_under_pressure() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    for packet in 0..64 {
        tx.send(packet).unwrap();
    }

    let mut drain = PacketDrainCursor::new(None, 64, FALLBACK_INTERLEAVE_EVERY, 0);
    for _ in 0..FALLBACK_INTERLEAVE_EVERY {
        assert!(matches!(
            drain.next(&mut rx),
            Some(PacketDrainAction::Packet(_))
        ));
    }
    assert_eq!(
        drain.next(&mut rx),
        Some(PacketDrainAction::InterleaveFallback)
    );

    drain.reset_fallback_interleave_every(FALLBACK_PRESSURE_INTERLEAVE_EVERY);
    for _ in 0..FALLBACK_PRESSURE_INTERLEAVE_EVERY {
        assert!(matches!(
            drain.next(&mut rx),
            Some(PacketDrainAction::Packet(_))
        ));
    }
    assert_eq!(
        drain.next(&mut rx),
        Some(PacketDrainAction::InterleaveFallback),
        "new fallback pressure should shorten the next raw-packet interval"
    );
}

#[test]
fn packet_drain_cursor_restores_normal_fallback_interleave_after_pressure() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    for packet in 0..80 {
        tx.send(packet).unwrap();
    }

    let mut drain = PacketDrainCursor::new(None, 80, FALLBACK_PRESSURE_INTERLEAVE_EVERY, 0);
    for _ in 0..FALLBACK_PRESSURE_INTERLEAVE_EVERY {
        assert!(matches!(
            drain.next(&mut rx),
            Some(PacketDrainAction::Packet(_))
        ));
    }
    assert_eq!(
        drain.next(&mut rx),
        Some(PacketDrainAction::InterleaveFallback)
    );

    drain.reset_fallback_interleave_every(FALLBACK_INTERLEAVE_EVERY);
    for _ in 0..(FALLBACK_INTERLEAVE_EVERY - 1) {
        assert!(matches!(
            drain.next(&mut rx),
            Some(PacketDrainAction::Packet(_))
        ));
    }
    assert!(matches!(
        drain.next(&mut rx),
        Some(PacketDrainAction::Packet(_)),
    ));
    assert_eq!(
        drain.next(&mut rx),
        Some(PacketDrainAction::InterleaveFallback),
        "priority pressure relief should restore the normal fallback cadence"
    );
}

#[test]
fn rx_loop_data_drain_stats_owns_counts_total_and_pressure() {
    let empty = RxLoopDataDrainStats::default();
    assert_eq!(empty.total(), 0);
    assert!(!empty.has_drained());
    assert!(!empty.data_pressure(false));
    assert!(empty.data_pressure(true));

    let drained = RxLoopDataDrainStats::new(2, 3, 5);
    assert_eq!(drained.total(), 10);
    assert!(drained.has_drained());
    assert!(drained.data_pressure(false));
    assert!(drained.data_pressure(true));
}

#[test]
fn rx_loop_maintenance_state_owns_activity_window_and_timeout_skip() {
    let start = Instant::now();
    let window = Duration::from_secs(2);
    let empty = RxLoopDataDrainStats::default();
    let drained = RxLoopDataDrainStats::new(1, 0, 0);
    let mut state = RxLoopMaintenanceState::default();

    assert!(!state.data_pressure(empty, start, window));
    assert!(!state.skip_slow_maintenance(false));

    state.record_data_activity(start);
    assert!(state.data_pressure(empty, start + Duration::from_secs(1), window));
    assert!(!state.data_pressure(empty, start + Duration::from_secs(3), window));
    assert!(state.data_pressure(drained, start + Duration::from_secs(3), window));

    state.record_maintenance_result(true, true);
    assert!(state.skip_slow_maintenance(true));
    assert!(!state.skip_slow_maintenance(false));

    state.record_maintenance_result(true, false);
    assert!(state.skip_slow_maintenance(true));

    state.record_maintenance_result(false, true);
    assert!(!state.skip_slow_maintenance(true));
}

#[test]
fn rx_loop_maintenance_plan_owns_pressure_skip_and_timeout_budget() {
    let start = Instant::now();
    let window = Duration::from_secs(2);
    let idle_timeout = Duration::from_millis(100);
    let busy_timeout = Duration::from_millis(10);
    let empty = RxLoopDataDrainStats::default();
    let drained = RxLoopDataDrainStats::new(1, 0, 0);
    let mut state = RxLoopMaintenanceState::default();

    let idle = state.plan_maintenance(empty, start, window, idle_timeout, busy_timeout);
    assert_eq!(
        idle,
        RxLoopMaintenancePlan::new(false, false, idle_timeout, busy_timeout)
    );
    assert_eq!(
        RxLoopMaintenancePlan::new(false, true, idle_timeout, busy_timeout).slow_timeout(),
        Some(idle_timeout)
    );
    assert!(!idle.data_pressure());
    assert_eq!(idle.slow_timeout(), Some(idle_timeout));

    state.record_data_activity(start);
    let recent_busy = state.plan_maintenance(
        empty,
        start + Duration::from_secs(1),
        window,
        idle_timeout,
        busy_timeout,
    );
    assert!(recent_busy.data_pressure());
    assert_eq!(recent_busy.slow_timeout(), Some(busy_timeout));

    state.record_maintenance_result(true, true);
    let skipped_busy = state.plan_maintenance(
        drained,
        start + Duration::from_secs(1),
        window,
        idle_timeout,
        busy_timeout,
    );
    assert!(skipped_busy.data_pressure());
    assert_eq!(skipped_busy.slow_timeout(), None);

    let expired_idle = state.plan_maintenance(
        empty,
        start + Duration::from_secs(3),
        window,
        idle_timeout,
        busy_timeout,
    );
    assert!(!expired_idle.data_pressure());
    assert_eq!(expired_idle.slow_timeout(), Some(idle_timeout));
}

#[tokio::test]
async fn endpoint_command_drain_prefers_ready_priority_over_selected_bulk() {
    let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
    let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

    priority_tx.send("priority").await.unwrap();
    bulk_tx.send("bulk-queued").await.unwrap();
    let mut drain = PriorityBulkDrainCursor::new(None, Some("bulk-selected"), 4);

    assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), Some("priority"));
    assert_eq!(
        drain.next(&mut priority_rx, &mut bulk_rx),
        Some("bulk-selected")
    );
    assert_eq!(
        drain.next(&mut priority_rx, &mut bulk_rx),
        Some("bulk-queued")
    );
    assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), None);
    assert_eq!(drain.drained(), 3);
}

#[tokio::test]
async fn fallback_drain_prefers_ready_priority_over_selected_bulk() {
    let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
    let (_authenticated_bulk_tx, mut authenticated_bulk_rx) = tokio::sync::mpsc::channel(4);
    let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

    priority_tx.send("priority-fallback").await.unwrap();
    bulk_tx.send("queued-bulk-fallback").await.unwrap();
    let mut drain = DecryptReturnDrainCursor::new(None, None, Some("selected-bulk-fallback"), 4);

    assert_eq!(
        drain.next(&mut priority_rx, &mut authenticated_bulk_rx, &mut bulk_rx),
        Some("priority-fallback")
    );
    assert_eq!(
        drain.next(&mut priority_rx, &mut authenticated_bulk_rx, &mut bulk_rx),
        Some("selected-bulk-fallback")
    );
    assert_eq!(
        drain.next(&mut priority_rx, &mut authenticated_bulk_rx, &mut bulk_rx),
        Some("queued-bulk-fallback")
    );
    assert_eq!(
        drain.next(&mut priority_rx, &mut authenticated_bulk_rx, &mut bulk_rx),
        None
    );
    assert_eq!(drain.drained(), 3);
}

#[tokio::test]
async fn decrypt_return_drain_prefers_authenticated_bulk_over_selected_fallback_bulk() {
    let (_priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
    let (authenticated_bulk_tx, mut authenticated_bulk_rx) = tokio::sync::mpsc::channel(4);
    let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

    authenticated_bulk_tx
        .send("queued-authenticated-bulk")
        .await
        .unwrap();
    bulk_tx.send("queued-fallback-bulk").await.unwrap();
    let mut drain = DecryptReturnDrainCursor::new(None, None, Some("selected-fallback-bulk"), 4);

    assert_eq!(
        drain.next(&mut priority_rx, &mut authenticated_bulk_rx, &mut bulk_rx),
        Some("queued-authenticated-bulk")
    );
    assert_eq!(
        drain.next(&mut priority_rx, &mut authenticated_bulk_rx, &mut bulk_rx),
        Some("selected-fallback-bulk")
    );
    assert_eq!(
        drain.next(&mut priority_rx, &mut authenticated_bulk_rx, &mut bulk_rx),
        Some("queued-fallback-bulk")
    );
    assert_eq!(
        drain.next(&mut priority_rx, &mut authenticated_bulk_rx, &mut bulk_rx),
        None
    );
    assert_eq!(drain.drained(), 3);
}

#[tokio::test]
async fn decrypt_return_drain_prefers_priority_over_selected_authenticated_bulk() {
    let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
    let (authenticated_bulk_tx, mut authenticated_bulk_rx) = tokio::sync::mpsc::channel(4);
    let (_bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

    priority_tx.send("queued-priority").await.unwrap();
    authenticated_bulk_tx
        .send("queued-authenticated-bulk")
        .await
        .unwrap();
    let mut drain =
        DecryptReturnDrainCursor::new(None, Some("selected-authenticated-bulk"), None, 4);

    assert_eq!(
        drain.next(&mut priority_rx, &mut authenticated_bulk_rx, &mut bulk_rx),
        Some("queued-priority")
    );
    assert_eq!(
        drain.next(&mut priority_rx, &mut authenticated_bulk_rx, &mut bulk_rx),
        Some("selected-authenticated-bulk")
    );
    assert_eq!(
        drain.next(&mut priority_rx, &mut authenticated_bulk_rx, &mut bulk_rx),
        Some("queued-authenticated-bulk")
    );
    assert_eq!(
        drain.next(&mut priority_rx, &mut authenticated_bulk_rx, &mut bulk_rx),
        None
    );
    assert_eq!(drain.drained(), 3);
}

#[tokio::test]
async fn priority_fallback_drain_leaves_bulk_for_lower_priority_turn() {
    let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
    let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

    priority_tx.send("queued-priority").await.unwrap();
    bulk_tx.send("queued-bulk").await.unwrap();
    let mut drain = SingleLaneDrainCursor::new(Some("selected-priority"), 4);

    assert_eq!(drain.next(&mut priority_rx), Some("selected-priority"));
    assert_eq!(drain.next(&mut priority_rx), Some("queued-priority"));
    assert_eq!(drain.next(&mut priority_rx), None);
    assert_eq!(bulk_rx.try_recv().ok(), Some("queued-bulk"));
    assert_eq!(drain.drained(), 2);
}

#[tokio::test]
async fn priority_bulk_drain_cursor_owns_selected_head_and_budget() {
    let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
    let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

    priority_tx.send("queued-priority").await.unwrap();
    bulk_tx.send("queued-bulk").await.unwrap();
    let mut drain =
        PriorityBulkDrainCursor::new(Some("selected-priority"), Some("selected-bulk"), 3);

    assert_eq!(
        drain.next(&mut priority_rx, &mut bulk_rx),
        Some("selected-priority")
    );
    assert_eq!(
        drain.next(&mut priority_rx, &mut bulk_rx),
        Some("queued-priority")
    );
    assert_eq!(
        drain.next(&mut priority_rx, &mut bulk_rx),
        Some("selected-bulk")
    );
    assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), None);
    assert_eq!(bulk_rx.try_recv().ok(), Some("queued-bulk"));
    assert_eq!(drain.drained(), 3);
}

#[tokio::test]
async fn priority_bulk_drain_cursor_charges_batch_extra_against_budget() {
    let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
    let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

    priority_tx.send("queued-priority").await.unwrap();
    bulk_tx.send("queued-bulk").await.unwrap();
    let mut drain = PriorityBulkDrainCursor::new(None, Some("selected-bulk"), 4);

    assert_eq!(
        drain.next(&mut priority_rx, &mut bulk_rx),
        Some("queued-priority")
    );
    drain.charge_extra(3);
    assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), None);
    assert_eq!(bulk_rx.try_recv().ok(), Some("queued-bulk"));
    assert_eq!(drain.drained(), 4);
}

#[tokio::test]
async fn packet_drain_cursor_owns_first_packet_budget_and_interleave() {
    let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();

    packet_tx.send("queued-1").unwrap();
    packet_tx.send("queued-2").unwrap();
    let mut drain = PacketDrainCursor::new(Some("selected"), 3, 2, 0);

    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::Packet("selected"))
    );
    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::Packet("queued-1"))
    );
    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::InterleaveFallback)
    );
    assert_eq!(drain.next(&mut packet_rx), None);
    assert_eq!(packet_rx.try_recv().ok(), Some("queued-2"));
    assert_eq!(drain.drained(), 2);
}

#[tokio::test]
async fn packet_drain_cursor_charges_interleaves_against_budget() {
    let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();

    packet_tx.send("queued-1").unwrap();
    packet_tx.send("queued-2").unwrap();
    let mut drain = PacketDrainCursor::new(Some("selected"), 4, 2, 0);

    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::Packet("selected"))
    );
    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::Packet("queued-1"))
    );
    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::InterleaveFallback)
    );
    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::Packet("queued-2"))
    );
    assert_eq!(drain.next(&mut packet_rx), None);
    assert_eq!(drain.drained(), 3);
}

#[tokio::test]
async fn packet_drain_cursor_refunds_empty_interleave_turns() {
    let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();

    packet_tx.send("queued-1").unwrap();
    packet_tx.send("queued-2").unwrap();
    packet_tx.send("queued-3").unwrap();
    let mut drain = PacketDrainCursor::new(None, 3, 1, 0);

    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::Packet("queued-1"))
    );
    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::InterleaveFallback)
    );
    drain.refund_empty_interleave_turn();
    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::Packet("queued-2"))
    );
    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::InterleaveFallback)
    );
    drain.refund_empty_interleave_turn();
    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::Packet("queued-3"))
    );
    assert_eq!(drain.next(&mut packet_rx), None);
    assert_eq!(drain.drained(), 3);
}

#[tokio::test]
async fn packet_drain_cursor_interleaves_side_queues_after_fallback() {
    let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();

    packet_tx.send("queued-1").unwrap();
    packet_tx.send("queued-2").unwrap();
    packet_tx.send("queued-3").unwrap();
    let mut drain = PacketDrainCursor::new(None, 5, 2, 2);

    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::Packet("queued-1"))
    );
    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::Packet("queued-2"))
    );
    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::InterleaveFallback)
    );
    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::InterleaveSideQueues)
    );
    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::Packet("queued-3"))
    );
    assert_eq!(drain.next(&mut packet_rx), None);
    assert_eq!(drain.drained(), 3);
}

#[tokio::test]
async fn packet_drain_cursor_can_disable_side_queue_interleaves() {
    let (packet_tx, mut packet_rx) = tokio::sync::mpsc::unbounded_channel();

    packet_tx.send("queued-1").unwrap();
    packet_tx.send("queued-2").unwrap();
    packet_tx.send("queued-3").unwrap();
    let mut drain = PacketDrainCursor::new(None, 3, 0, 0);

    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::Packet("queued-1"))
    );
    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::Packet("queued-2"))
    );
    assert_eq!(
        drain.next(&mut packet_rx),
        Some(PacketDrainAction::Packet("queued-3"))
    );
    assert_eq!(drain.next(&mut packet_rx), None);
    assert_eq!(drain.drained(), 3);
}

#[tokio::test]
async fn single_lane_drain_cursor_owns_first_item_and_budget() {
    let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel(4);

    tun_tx.send("queued-1").await.unwrap();
    tun_tx.send("queued-2").await.unwrap();
    tun_tx.send("queued-3").await.unwrap();
    let mut drain = SingleLaneDrainCursor::new(Some("selected"), 3);

    assert_eq!(drain.next(&mut tun_rx), Some("selected"));
    assert_eq!(drain.next(&mut tun_rx), Some("queued-1"));
    assert_eq!(drain.next(&mut tun_rx), Some("queued-2"));
    assert_eq!(drain.next(&mut tun_rx), None);
    assert_eq!(tun_rx.try_recv().ok(), Some("queued-3"));
    assert_eq!(drain.drained(), 3);
}
