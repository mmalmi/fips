use super::budget::{
    ENDPOINT_DRAIN_BUDGET, LATENCY_PACKET_DRAIN_BUDGET, PACKET_DRAIN_BUDGET, TUN_DRAIN_BUDGET,
    endpoint_drain_budget, mixed_dataplane_crypto_budget, tun_drain_budget,
};
use super::drain::{
    RxLoopDataDrainStats, RxLoopMaintenancePlan, RxLoopMaintenanceState, SingleLaneDrainCursor,
};
use crate::control::protocol::Request;
use std::time::{Duration, Instant};

#[test]
fn endpoint_drain_budget_caps_large_packet_turns() {
    assert_eq!(endpoint_drain_budget(0), 0);
    assert_eq!(endpoint_drain_budget(8), 8);
    assert_eq!(
        endpoint_drain_budget(PACKET_DRAIN_BUDGET),
        ENDPOINT_DRAIN_BUDGET
    );
}

#[test]
fn tun_outbound_gets_dataplane_sized_turns() {
    assert_eq!(
        endpoint_drain_budget(PACKET_DRAIN_BUDGET),
        ENDPOINT_DRAIN_BUDGET
    );
    assert_eq!(tun_drain_budget(PACKET_DRAIN_BUDGET), TUN_DRAIN_BUDGET);
    assert_eq!(TUN_DRAIN_BUDGET, LATENCY_PACKET_DRAIN_BUDGET);
    assert!(
        TUN_DRAIN_BUDGET > ENDPOINT_DRAIN_BUDGET,
        "canonical TUN packet ingress must not inherit the endpoint/control slice"
    );
}

#[test]
fn mixed_packet_and_tun_turn_crypto_budget_covers_admitted_sources() {
    let crypto_budget = mixed_dataplane_crypto_budget(
        LATENCY_PACKET_DRAIN_BUDGET,
        ENDPOINT_DRAIN_BUDGET,
        TUN_DRAIN_BUDGET,
    );

    assert_eq!(
        crypto_budget,
        LATENCY_PACKET_DRAIN_BUDGET + ENDPOINT_DRAIN_BUDGET + TUN_DRAIN_BUDGET
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

    let drained = RxLoopDataDrainStats::new(2, 3, 5, 0);
    assert_eq!(drained.data_total(), 10);
    assert_eq!(drained.total(), 10);
    assert!(drained.has_drained());
    assert!(drained.has_data_drained());
    assert!(drained.data_pressure(false));
    assert!(drained.data_pressure(true));

    let control_only = RxLoopDataDrainStats::new(0, 0, 0, 2);
    assert_eq!(control_only.data_total(), 0);
    assert_eq!(control_only.total(), 2);
    assert!(control_only.has_drained());
    assert!(!control_only.has_data_drained());
    assert!(
        !control_only.data_pressure(false),
        "read-only control progress must not look like dataplane pressure"
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
async fn dataplane_turn_uses_rx_loop_owned_channels() {
    let mut node =
        crate::node::Node::new(crate::config::Config::new()).expect("node should construct");
    let (_packet_tx, mut packet_rx) = crate::transport::packet_channel(1);
    let (_endpoint_tx, mut endpoint_rx) = crate::node::endpoint_data_batch_channel(1);
    let (_tun_outbound_tx, mut tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
    let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
    let mut endpoint_io = node
        .attach_endpoint_data_io(1)
        .expect("endpoint io should attach before start");

    let turn = node
        .drain_dataplane_turn_with_firsts(
            &mut packet_rx,
            crate::dataplane::DataplaneLiveTurnFirsts::default(),
            4,
            &mut endpoint_rx,
            4,
            &mut tun_outbound_rx,
            4,
            &tun_tx,
            &endpoint_io.event_tx,
            4,
        )
        .await;

    assert_eq!(
        turn.summary(),
        crate::dataplane::DataplaneRuntimeSummary::default()
    );
    assert!(!turn.has_activity());
    assert!(!turn.has_failures());
    assert!(turn.raw_ingress_drops().is_empty());
    assert!(turn.output_drops().is_empty());
    assert!(turn.drops().is_empty());
    assert!(turn.endpoint_data_drops().is_empty());
    assert!(turn.tun_outbound_drops().is_empty());
    assert!(tun_rx.try_recv().is_err());
    assert!(endpoint_io.event_rx.try_recv().is_err());
}

#[tokio::test]
async fn dataplane_turn_reports_raw_ingress_failures() {
    let mut node =
        crate::node::Node::new(crate::config::Config::new()).expect("node should construct");
    let (packet_tx, mut packet_rx) = crate::transport::packet_channel(1);
    let (_endpoint_tx, mut endpoint_rx) = crate::node::endpoint_data_batch_channel(1);
    let (_tun_outbound_tx, mut tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
    let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
    let mut endpoint_io = node
        .attach_endpoint_data_io(1)
        .expect("endpoint io should attach before start");

    packet_tx
        .send(crate::transport::ReceivedPacket::with_timestamp(
            crate::transport::TransportId::new(7),
            crate::transport::TransportAddr::from_string("198.51.100.7:9000"),
            vec![0],
            123_456,
        ))
        .expect("malformed packet queued");

    let turn = node
        .drain_dataplane_turn_with_firsts(
            &mut packet_rx,
            crate::dataplane::DataplaneLiveTurnFirsts::default(),
            4,
            &mut endpoint_rx,
            4,
            &mut tun_outbound_rx,
            4,
            &tun_tx,
            &endpoint_io.event_tx,
            4,
        )
        .await;

    assert!(turn.has_activity());
    assert!(turn.has_failures());
    assert_eq!(turn.summary().raw_ingress_dropped(), 1);
    assert_eq!(turn.raw_ingress_drops().len(), 1);
    assert_eq!(
        turn.raw_ingress_drops()[0].reason(),
        crate::dataplane::DataplaneRawIngressDropReason::Wire(
            crate::dataplane::WirePreflightError::TooShort
        )
    );
    assert_eq!(
        turn.raw_ingress_drops()[0].transport_id(),
        crate::transport::TransportId::new(7)
    );
    assert!(turn.output_drops().is_empty());
    assert!(turn.drops().is_empty());
    assert!(turn.endpoint_data_drops().is_empty());
    assert!(turn.tun_outbound_drops().is_empty());
    assert!(packet_rx.try_recv().is_err());
    assert!(tun_rx.try_recv().is_err());
    assert!(endpoint_io.event_rx.try_recv().is_err());
}

#[test]
fn rx_loop_maintenance_state_owns_activity_window_and_timeout_skip() {
    let start = Instant::now();
    let window = Duration::from_secs(2);
    let empty = RxLoopDataDrainStats::default();
    let drained = RxLoopDataDrainStats::new(1, 0, 0, 0);
    let mut state = RxLoopMaintenanceState::default();

    assert!(!state.data_pressure(empty, start, window));
    assert!(!state.skip_slow_maintenance(empty, false));
    assert!(
        !state.skip_slow_maintenance(drained, true),
        "queued dataplane work should timebox slow maintenance instead of starving it"
    );

    state.record_data_activity(start);
    assert!(state.data_pressure(empty, start + Duration::from_secs(1), window));
    assert!(!state.data_pressure(empty, start + Duration::from_secs(3), window));
    assert!(state.data_pressure(drained, start + Duration::from_secs(3), window));

    state.record_maintenance_result(true, true);
    assert!(state.skip_slow_maintenance(empty, true));
    assert!(!state.skip_slow_maintenance(empty, false));

    state.record_maintenance_result(true, false);
    assert!(
        !state.skip_slow_maintenance(empty, true),
        "one skipped or successful busy tick should clear the timeout latch"
    );

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
    let drained = RxLoopDataDrainStats::new(1, 0, 0, 0);
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

    state.record_maintenance_result(true, false);
    let retried_busy_after_skip = state.plan_maintenance(
        empty,
        start + Duration::from_secs(1),
        window,
        idle_timeout,
        busy_timeout,
    );
    assert!(retried_busy_after_skip.data_pressure());
    assert_eq!(
        retried_busy_after_skip.slow_timeout(),
        Some(busy_timeout),
        "slow maintenance should retry under sustained data pressure after one skip"
    );

    let busy_with_queued_data = RxLoopMaintenanceState::default().plan_maintenance(
        drained,
        start + Duration::from_secs(1),
        window,
        idle_timeout,
        busy_timeout,
    );
    assert!(busy_with_queued_data.data_pressure());
    assert_eq!(busy_with_queued_data.slow_timeout(), Some(busy_timeout));

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
async fn single_lane_drain_leaves_other_lanes_for_later_turns() {
    let (selected_tx, mut selected_rx) = tokio::sync::mpsc::channel(4);
    let (other_tx, mut other_rx) = tokio::sync::mpsc::channel(4);

    selected_tx.send("queued-selected").await.unwrap();
    other_tx.send("queued-other").await.unwrap();
    let mut drain = SingleLaneDrainCursor::new(Some("selected-first"), 4);

    assert_eq!(drain.next(&mut selected_rx), Some("selected-first"));
    assert_eq!(drain.next(&mut selected_rx), Some("queued-selected"));
    assert_eq!(drain.next(&mut selected_rx), None);
    assert_eq!(other_rx.try_recv().ok(), Some("queued-other"));
    assert_eq!(drain.drained(), 2);
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
