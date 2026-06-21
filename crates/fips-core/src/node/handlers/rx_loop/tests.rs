use super::budget::{
    CONTROL_QUERY_INTERLEAVE_BUDGET, ENDPOINT_COMMAND_COALESCE_MAX_PACKETS,
    FALLBACK_INTERLEAVE_BUDGET, FALLBACK_INTERLEAVE_EVERY, FallbackDrainPlan,
    NON_PACKET_DRAIN_BUDGET, PACKET_DRAIN_BUDGET, authenticated_bulk_preempts_packet_rx,
    fallback_drain_plan, non_packet_drain_budget,
};
use super::drain::{
    DecryptReturnDrainCursor, PacketDrainAction, PacketDrainCursor, PriorityBulkDrainCursor,
    RxLoopDataDrainStats, RxLoopMaintenancePlan, RxLoopMaintenanceState, RxLoopSideQueues,
    SingleLaneDrainCursor, rx_loop_side_queues_have_ready,
};
use crate::control::protocol::Request;
use crate::node::decrypt_worker::DecryptWorkerEvent;
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
fn fallback_drain_plan_stays_bounded_under_return_pressure() {
    let plan = fallback_drain_plan();
    assert_eq!(
        plan,
        FallbackDrainPlan {
            interleave_every: FALLBACK_INTERLEAVE_EVERY,
            interleave_budget: FALLBACK_INTERLEAVE_BUDGET,
            trailing_budget: NON_PACKET_DRAIN_BUDGET,
        }
    );
    assert!(
        plan.interleave_budget <= NON_PACKET_DRAIN_BUDGET,
        "fallback returns should keep a bounded normal turn even when bulk is backlogged"
    );
    assert!(
        plan.trailing_budget <= NON_PACKET_DRAIN_BUDGET,
        "trailing fallback returns should not grow into a pressure side path"
    );
    assert!(
        NON_PACKET_DRAIN_BUDGET <= 16
            && plan.interleave_budget <= 16
            && super::budget::SIDE_QUEUE_INTERLEAVE_BUDGET <= 16,
        "non-packet turns must stay short so fresh transport priority is not held behind bulk work"
    );
}

#[test]
fn authenticated_bulk_yields_to_transport_pressure() {
    assert!(authenticated_bulk_preempts_packet_rx(0, 0));
    assert!(
        authenticated_bulk_preempts_packet_rx(0, super::budget::FALLBACK_INTERLEAVE_EVERY - 1),
        "small transport bulk backlog should not strand authenticated delivery until the next packet turn"
    );
    assert!(
        !authenticated_bulk_preempts_packet_rx(1, 0),
        "bulk endpoint delivery should not preempt a ready control-sized transport packet"
    );
    assert!(
        !authenticated_bulk_preempts_packet_rx(0, super::budget::FALLBACK_INTERLEAVE_EVERY),
        "a full interleave interval of transport bulk should cut ahead; packet drains interleave authenticated delivery"
    );
}

#[test]
fn endpoint_priority_pre_packet_turn_stays_bounded() {
    assert!(
        NON_PACKET_DRAIN_BUDGET <= 16,
        "endpoint-priority commands run before raw packet receive, so the turn must stay short"
    );
}

#[test]
fn rx_loop_data_drain_stats_owns_counts_total_and_pressure() {
    let empty = RxLoopDataDrainStats::default();
    assert_eq!(empty.total(), 0);
    assert_eq!(empty.data_total(), 0);
    assert!(!empty.has_drained());
    assert!(!empty.has_data_drained());
    assert!(!empty.data_pressure(false));
    assert!(empty.data_pressure(true));

    let drained = RxLoopDataDrainStats::new(2, 3, 5);
    assert_eq!(drained.data_total(), 10);
    assert_eq!(drained.total(), 10);
    assert!(drained.has_drained());
    assert!(drained.has_data_drained());
    assert!(drained.data_pressure(false));
    assert!(drained.data_pressure(true));

    let control_only = RxLoopDataDrainStats::with_control(0, 0, 0, 2);
    assert_eq!(control_only.data_total(), 0);
    assert_eq!(control_only.total(), 2);
    assert!(control_only.has_drained());
    assert!(!control_only.has_data_drained());
    assert!(
        !control_only.data_pressure(false),
        "read-only control progress must not look like dataplane pressure"
    );

    let decrypt_only = RxLoopDataDrainStats::with_decrypt(0, 1, 0, 0);
    assert_eq!(decrypt_only.data_total(), 1);
    assert!(decrypt_only.has_data_drained());
    assert!(
        decrypt_only.data_pressure(false),
        "decrypt-worker receive bookkeeping must count as dataplane progress"
    );
}

#[tokio::test]
async fn rx_loop_side_queue_readiness_includes_control_queries() {
    assert!(
        CONTROL_QUERY_INTERLEAVE_BUDGET < super::budget::SIDE_QUEUE_INTERLEAVE_BUDGET,
        "control query reserve should stay a small slice of the side-queue budget"
    );

    let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(1);
    let (_tun_tx, mut tun_rx) = tokio::sync::mpsc::channel(1);
    let (_endpoint_priority_tx, mut endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
    let (_endpoint_tx, mut endpoint_rx) = tokio::sync::mpsc::channel(1);
    let (response_tx, _response_rx) = tokio::sync::oneshot::channel();

    control_tx
        .send((
            Request {
                command: "show_status".to_string(),
                params: None,
            },
            response_tx,
        ))
        .await
        .unwrap();

    let side_queues = RxLoopSideQueues {
        control_query_rx: &mut control_rx,
        tun_outbound_rx: &mut tun_rx,
        endpoint_priority_command_rx: &mut endpoint_priority_rx,
        endpoint_command_rx: &mut endpoint_rx,
    };

    assert!(
        rx_loop_side_queues_have_ready(&side_queues),
        "hot packet drains should notice queued read-only control queries"
    );
}

#[tokio::test]
async fn drain_control_queries_answers_show_requests() {
    let mut node =
        crate::node::Node::new(crate::config::Config::new()).expect("node should construct");
    let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(2);
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();

    control_tx
        .send((
            Request {
                command: "show_stats_list".to_string(),
                params: None,
            },
            response_tx,
        ))
        .await
        .unwrap();

    let drained = node.drain_control_queries(&mut control_rx, None, 1).await;
    assert_eq!(drained, 1);

    let response = response_rx.await.expect("query response");
    assert_eq!(response.status, "ok");
    assert!(response.data.is_some());
    assert!(control_rx.try_recv().is_err());
}

#[tokio::test]
async fn pre_maintenance_drain_consumes_worker_fallback_without_raw_packets() {
    let mut node =
        crate::node::Node::new(crate::config::Config::new()).expect("node should construct");
    let (_packet_tx, mut packet_rx) = crate::transport::packet_channel(1);
    let (fallback_tx, mut fallback_rx) =
        crate::node::decrypt_worker::decrypt_worker_fallback_channels();
    let (_tun_tx, mut tun_rx) = tokio::sync::mpsc::channel(1);
    let (_endpoint_priority_tx, mut endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
    let (_endpoint_tx, mut endpoint_rx) = tokio::sync::mpsc::channel(1);

    assert!(fallback_tx.send_for_test(DecryptWorkerEvent::AuthenticatedSessionBatch(Vec::new())));
    assert_eq!(fallback_rx.authenticated_bulk_queued_packets(), 0);
    assert!(!fallback_rx.authenticated_bulk.is_empty());

    let drained = node
        .drain_rx_loop_data_queues(
            &mut packet_rx,
            &mut fallback_rx,
            &mut tun_rx,
            &mut endpoint_priority_rx,
            &mut endpoint_rx,
            NON_PACKET_DRAIN_BUDGET,
        )
        .await;

    assert_eq!(drained.packets, 0);
    assert_eq!(drained.decrypt, 1);
    assert!(fallback_rx.authenticated_bulk.is_empty());
    assert!(
        drained.has_data_drained(),
        "queued authenticated receive bookkeeping must be applied before link-dead maintenance"
    );
}

#[test]
fn rx_loop_maintenance_state_owns_activity_window_and_timeout_skip() {
    let start = Instant::now();
    let window = Duration::from_secs(2);
    let empty = RxLoopDataDrainStats::default();
    let drained = RxLoopDataDrainStats::new(1, 0, 0);
    let mut state = RxLoopMaintenanceState::default();

    assert!(!state.data_pressure(empty, start, window));
    assert!(!state.skip_slow_maintenance(empty, false));
    assert!(
        state.skip_slow_maintenance(drained, true),
        "queued dataplane work should reserve the tick for fast maintenance only"
    );

    state.record_data_activity(start);
    assert!(state.data_pressure(empty, start + Duration::from_secs(1), window));
    assert!(!state.data_pressure(empty, start + Duration::from_secs(3), window));
    assert!(state.data_pressure(drained, start + Duration::from_secs(3), window));

    state.record_maintenance_result(true, true);
    assert!(state.skip_slow_maintenance(empty, true));
    assert!(!state.skip_slow_maintenance(empty, false));

    state.record_maintenance_result(true, false);
    assert!(state.skip_slow_maintenance(empty, true));

    state.record_maintenance_result(false, true);
    assert!(!state.skip_slow_maintenance(empty, true));
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
    let skipped_busy_after_timeout = state.plan_maintenance(
        empty,
        start + Duration::from_secs(1),
        window,
        idle_timeout,
        busy_timeout,
    );
    assert!(skipped_busy_after_timeout.data_pressure());
    assert_eq!(skipped_busy_after_timeout.slow_timeout(), None);

    let skipped_busy_with_queued_data = RxLoopMaintenanceState::default().plan_maintenance(
        drained,
        start + Duration::from_secs(1),
        window,
        idle_timeout,
        busy_timeout,
    );
    assert!(skipped_busy_with_queued_data.data_pressure());
    assert_eq!(skipped_busy_with_queued_data.slow_timeout(), None);

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
async fn priority_bulk_drain_cursor_bulk_only_stops_for_priority() {
    let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
    let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);

    priority_tx.send("priority").await.unwrap();
    bulk_tx.send("bulk").await.unwrap();
    let mut drain = PriorityBulkDrainCursor::new(None, Some("selected-bulk"), 4);

    assert_eq!(
        drain.next_bulk_if_no_priority(&mut priority_rx, &mut bulk_rx),
        None,
        "bulk coalescing must stop when priority work is ready"
    );
    assert_eq!(drain.next(&mut priority_rx, &mut bulk_rx), Some("priority"));
    assert_eq!(
        drain.next_bulk_if_no_priority(&mut priority_rx, &mut bulk_rx),
        Some("selected-bulk")
    );
    assert_eq!(
        drain.next_bulk_if_no_priority(&mut priority_rx, &mut bulk_rx),
        Some("bulk")
    );
}

#[tokio::test]
async fn priority_bulk_drain_cursor_deferred_bulk_yields_to_later_priority() {
    let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
    let (_bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);
    let mut drain = PriorityBulkDrainCursor::new(None, None, 4);

    drain.defer_bulk("deferred-bulk");
    priority_tx.send("priority").await.unwrap();

    assert_eq!(
        drain.next(&mut priority_rx, &mut bulk_rx),
        Some("priority"),
        "a non-coalesced bulk command should be put back behind new priority work"
    );
    assert_eq!(
        drain.next(&mut priority_rx, &mut bulk_rx),
        Some("deferred-bulk")
    );
}

#[test]
fn endpoint_command_coalesce_cap_is_small_bounded_packet_groups() {
    assert_eq!(ENDPOINT_COMMAND_COALESCE_MAX_PACKETS, 256);
    assert!(
        ENDPOINT_COMMAND_COALESCE_MAX_PACKETS <= PACKET_DRAIN_BUDGET,
        "endpoint coalescing should remain below one raw packet drain turn"
    );
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
