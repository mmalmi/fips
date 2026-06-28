use super::budget::{NON_PACKET_DRAIN_BUDGET, PACKET_DRAIN_BUDGET, non_packet_drain_budget};
use super::drain::{
    RxLoopDataDrainStats, RxLoopMaintenancePlan, RxLoopMaintenanceState, SingleLaneDrainCursor,
};
use crate::control::protocol::Request;
use std::time::{Duration, Instant};

fn closed_scratch_sinks() -> (crate::upper::tun::TunTx, crate::node::EndpointEventSender) {
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    drop(tun_rx);
    let (endpoint_tx, endpoint_rx) = crate::node::EndpointEventSender::channel(1);
    drop(endpoint_rx);
    (tun_tx, endpoint_tx)
}

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
async fn side_queue_drain_preserves_tun_slice_after_endpoint_batch_overrun() {
    let mut node =
        crate::node::Node::new(crate::config::Config::new()).expect("node should construct");
    let (scratch_tun_tx, scratch_endpoint_tx) = closed_scratch_sinks();
    let (_packet_tx, mut packet_rx) = crate::transport::packet_channel(1);
    let (_control_tx, mut control_rx) = tokio::sync::mpsc::channel(1);
    let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel(1);
    let (_endpoint_priority_tx, mut endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
    let (endpoint_tx, mut endpoint_rx) = tokio::sync::mpsc::channel(1);
    let remote = crate::PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
    let payloads = (0..9)
        .map(|idx| crate::node::EndpointDataPayload::new(format!("endpoint-{idx}").into_bytes()))
        .collect::<Vec<_>>();

    endpoint_tx
        .send(
            crate::node::NodeEndpointCommand::send_batch_oneway(
                remote,
                payloads,
                None,
                crate::node::EndpointCommandLane::Bulk,
            )
            .expect("endpoint batch command"),
        )
        .await
        .expect("endpoint batch queued");
    tun_tx
        .send(vec![0])
        .await
        .expect("invalid TUN packet still exercises TUN drain accounting");

    let drained = node
        .drain_rx_loop_side_queues(
            &mut packet_rx,
            &mut control_rx,
            &mut tun_rx,
            &mut endpoint_priority_rx,
            &mut endpoint_rx,
            &scratch_tun_tx,
            &scratch_endpoint_tx,
            2,
        )
        .await;

    assert_eq!(
        drained.endpoint, 2,
        "nine endpoint payloads cost two endpoint drain credits"
    );
    assert_eq!(
        drained.tun, 1,
        "endpoint batch overrun must not consume the TUN reserved slice"
    );
    assert_eq!(drained.control, 0);
    assert!(endpoint_rx.try_recv().is_err());
    assert!(tun_rx.try_recv().is_err());
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
async fn packet_mover2_scratch_turn_uses_rx_loop_owned_channels() {
    let mut node =
        crate::node::Node::new(crate::config::Config::new()).expect("node should construct");
    let (_packet_tx, mut packet_rx) = crate::transport::packet_channel(1);
    let (_endpoint_priority_tx, mut endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
    let (_endpoint_tx, mut endpoint_rx) = tokio::sync::mpsc::channel(1);
    let (_tun_outbound_tx, mut tun_outbound_rx) = tokio::sync::mpsc::channel(1);
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    let mut endpoint_io = node
        .attach_endpoint_data_io(1)
        .expect("endpoint io should attach before start");

    let turn = node
        .drain_packet_mover2_scratch_turn(
            &mut packet_rx,
            4,
            &mut endpoint_priority_rx,
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
        crate::packet_mover2::PacketMover2RuntimeSummary::default()
    );
    assert!(!turn.has_activity());
    assert!(!turn.has_failures());
    assert!(turn.raw_ingress_drops().is_empty());
    assert!(turn.output_drops().is_empty());
    assert!(turn.drops().is_empty());
    assert!(turn.endpoint_command_drops().is_empty());
    assert!(turn.tun_outbound_drops().is_empty());
    assert!(tun_rx.try_recv().is_err());
    assert!(endpoint_io.event_rx.try_recv().is_err());
}

#[tokio::test]
async fn packet_mover2_scratch_replays_deferred_endpoint_commands() {
    let mut node =
        crate::node::Node::new(crate::config::Config::new()).expect("node should construct");
    let (_packet_tx, mut packet_rx) = crate::transport::packet_channel(1);
    let (endpoint_priority_tx, mut endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
    let (_endpoint_tx, mut endpoint_rx) = tokio::sync::mpsc::channel(1);
    let (_tun_outbound_tx, mut tun_outbound_rx) = tokio::sync::mpsc::channel(1);
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    let mut endpoint_io = node
        .attach_endpoint_data_io(1)
        .expect("endpoint io should attach before start");
    let (response_tx, mut response_rx) = tokio::sync::oneshot::channel();

    endpoint_priority_tx
        .send(crate::node::NodeEndpointCommand::PeerSnapshot { response_tx })
        .await
        .expect("peer snapshot command queued");

    let mut turn = node
        .drain_packet_mover2_scratch_turn(
            &mut packet_rx,
            4,
            &mut endpoint_priority_rx,
            &mut endpoint_rx,
            4,
            &mut tun_outbound_rx,
            4,
            &tun_tx,
            &endpoint_io.event_tx,
            4,
        )
        .await;

    assert_eq!(turn.endpoint_deferred_commands(), 1);
    assert!(matches!(
        response_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));

    let processed = node
        .process_packet_mover2_scratch_control_ingress(&mut turn)
        .await;

    assert_eq!(processed, 1);
    let peers = tokio::time::timeout(Duration::from_secs(1), response_rx)
        .await
        .expect("deferred endpoint command should complete")
        .expect("peer snapshot sender should stay alive");
    assert!(peers.is_empty());
    assert!(tun_rx.try_recv().is_err());
    assert!(endpoint_io.event_rx.try_recv().is_err());
}

#[tokio::test]
async fn packet_mover2_scratch_turn_reports_raw_ingress_failures() {
    let mut node =
        crate::node::Node::new(crate::config::Config::new()).expect("node should construct");
    let (packet_tx, mut packet_rx) = crate::transport::packet_channel(1);
    let (_endpoint_priority_tx, mut endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
    let (_endpoint_tx, mut endpoint_rx) = tokio::sync::mpsc::channel(1);
    let (_tun_outbound_tx, mut tun_outbound_rx) = tokio::sync::mpsc::channel(1);
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
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
        .drain_packet_mover2_scratch_turn(
            &mut packet_rx,
            4,
            &mut endpoint_priority_rx,
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
        crate::packet_mover2::PacketMover2RawIngressDropReason::Wire(
            crate::packet_mover2::WirePreflightError::TooShort
        )
    );
    assert_eq!(
        turn.raw_ingress_drops()[0].transport_id(),
        crate::transport::TransportId::new(7)
    );
    assert!(turn.output_drops().is_empty());
    assert!(turn.drops().is_empty());
    assert!(turn.endpoint_command_drops().is_empty());
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
    let drained = RxLoopDataDrainStats::new(1, 0, 0);
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
