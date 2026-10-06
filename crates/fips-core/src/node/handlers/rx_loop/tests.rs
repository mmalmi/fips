#[cfg(feature = "sim-transport")]
mod bloom_cancellation;
mod cooperative_progress;

use super::budget::{
    ENDPOINT_DRAIN_BUDGET, LATENCY_PACKET_DRAIN_BUDGET, PACKET_DRAIN_BUDGET,
    RX_LOOP_FAST_MAINTENANCE_TIMEOUT, TUN_DRAIN_BUDGET, endpoint_drain_budget,
    mixed_dataplane_crypto_budget, tun_drain_budget,
};
use super::drain::{
    RxLoopDataDrainStats, RxLoopMaintenancePlan, RxLoopMaintenanceState, SingleLaneDrainCursor,
};
use super::{
    rx_loop_fast_maintenance_within_budget, wait_for_optional_deadline,
    wait_for_optional_epoch_deadline,
};
use crate::control::protocol::Request;
use std::time::{Duration, Instant};

#[tokio::test]
async fn endpoint_snapshot_interleave_preserves_fifo_mutation_barriers() {
    use crate::node::NodeEndpointControlCommand as Command;
    use tokio::sync::oneshot;
    let mut node = crate::node::Node::new(crate::config::Config::new()).unwrap();
    let endpoint = node.attach_endpoint_data_io(16).unwrap();
    let identity = crate::PeerIdentity::from_pubkey(crate::Identity::generate().pubkey());
    let (first_tx, mut first) = oneshot::channel();
    let (mutation_tx, mutation) = oneshot::channel();
    let (second_tx, mut second) = oneshot::channel();
    let (last_tx, mut last) = oneshot::channel();
    endpoint
        .control_tx
        .send(Command::PeerSnapshot {
            response_tx: first_tx,
        })
        .await
        .unwrap();
    endpoint
        .control_tx
        .send(Command::RegisterIdentity {
            identity,
            response_tx: mutation_tx,
        })
        .await
        .unwrap();
    endpoint
        .control_tx
        .send(Command::TransportStatsSnapshot {
            response_tx: second_tx,
        })
        .await
        .unwrap();
    endpoint
        .control_tx
        .send(Command::PeerSnapshot {
            response_tx: last_tx,
        })
        .await
        .unwrap();
    // Even a cancelled mutation response must remain a FIFO barrier.
    drop(mutation);
    node.drain_endpoint_snapshots().await;
    assert!(first.try_recv().is_ok());
    assert!(second.try_recv().is_err());
    assert!(last.try_recv().is_err());
    assert!(matches!(
        node.pending_endpoint_control,
        Some(Command::RegisterIdentity { .. })
    ));
    node.drain_endpoint_snapshots().await;
    assert!(
        second.try_recv().is_err(),
        "never read beyond a stashed mutation"
    );
    let command = super::next_endpoint_control(
        &mut node.pending_endpoint_control,
        &mut node.endpoint_control_rx,
    )
    .await
    .unwrap();
    assert!(matches!(command, Command::RegisterIdentity { .. }));
    node.handle_endpoint_control(command).await;
    node.drain_endpoint_snapshots().await;
    assert!(second.try_recv().is_ok());
    assert!(last.try_recv().is_ok());
}

#[tokio::test]
async fn endpoint_snapshot_interleave_is_bounded_and_keeps_adjacent_mutations() {
    use crate::node::NodeEndpointControlCommand as Command;
    use tokio::sync::oneshot;
    let mut node = crate::node::Node::new(crate::config::Config::new()).unwrap();
    let endpoint = node.attach_endpoint_data_io(16).unwrap();
    let mut replies = Vec::new();
    for _ in 0..5 {
        let (response_tx, response_rx) = oneshot::channel();
        endpoint
            .control_tx
            .send(Command::PeerSnapshot { response_tx })
            .await
            .unwrap();
        replies.push(response_rx);
    }
    node.drain_endpoint_snapshots().await;
    for reply in &mut replies[..4] {
        assert!(reply.try_recv().is_ok());
    }
    assert!(replies[4].try_recv().is_err());
    node.drain_endpoint_snapshots().await;
    assert!(replies[4].try_recv().is_ok());
    let mut mutations = Vec::new();
    for _ in 0..2 {
        let (response_tx, response_rx) = oneshot::channel();
        let identity = crate::PeerIdentity::from_pubkey(crate::Identity::generate().pubkey());
        endpoint
            .control_tx
            .send(Command::RegisterIdentity {
                identity,
                response_tx,
            })
            .await
            .unwrap();
        mutations.push(response_rx);
    }
    for mut response in mutations {
        node.drain_endpoint_snapshots().await;
        assert!(response.try_recv().is_err());
        // A higher-priority ready select branch must leave the stash untouched.
        tokio::select! { biased;
            _ = std::future::ready(()) => {},
            _ = super::next_endpoint_control(&mut node.pending_endpoint_control, &mut node.endpoint_control_rx) => panic!("unexpected selection"),
        }
        assert!(node.pending_endpoint_control.is_some());
        let command = super::next_endpoint_control(
            &mut node.pending_endpoint_control,
            &mut node.endpoint_control_rx,
        )
        .await
        .unwrap();
        assert!(matches!(command, Command::RegisterIdentity { .. }));
        node.handle_endpoint_control(command).await;
        assert!(response.try_recv().is_ok());
    }
}

#[tokio::test]
async fn endpoint_control_receiver_closes_on_rx_loop_return_or_cancellation() {
    use crate::node::NodeEndpointControlCommand as Command;
    for cancel in [false, true] {
        let mut config = crate::config::Config::new();
        config.node.control.enabled = false;
        let mut node = crate::node::Node::new(config).unwrap();
        let endpoint = node.attach_endpoint_data_io(16).unwrap();
        assert!(node.run_rx_loop().await.is_err(), "not started");
        assert!(
            !endpoint.control_tx.is_closed(),
            "NotStarted does not consume control"
        );
        let (response_tx, mut response_rx) = tokio::sync::oneshot::channel();
        node.pending_endpoint_control = Some(Command::PeerSnapshot { response_tx });
        let (packet_tx, packet_rx) = crate::transport::packet_channel(16);
        node.packet_rx = Some(packet_rx);
        if cancel {
            let mut running = Box::pin(node.run_rx_loop());
            assert!(futures::poll!(&mut running).is_pending());
            drop(running);
        } else {
            drop(packet_tx);
            node.run_rx_loop().await.unwrap();
        }
        assert!(endpoint.control_tx.is_closed());
        assert!(node.endpoint_control_rx.is_none());
        assert!(node.pending_endpoint_control.is_none());
        assert!(!matches!(
            response_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
    }
}

#[tokio::test(start_paused = true)]
async fn fast_maintenance_loses_no_more_than_its_total_budget() {
    let started = tokio::time::Instant::now();
    let completed = rx_loop_fast_maintenance_within_budget(std::future::pending::<()>()).await;

    assert!(!completed);
    assert_eq!(started.elapsed(), RX_LOOP_FAST_MAINTENANCE_TIMEOUT);
}

#[tokio::test(start_paused = true)]
async fn absent_report_deadline_never_creates_an_idle_wakeup() {
    assert!(
        tokio::time::timeout(
            Duration::from_secs(3_600),
            wait_for_optional_deadline(None, Instant::now()),
        )
        .await
        .is_err()
    );
}

#[tokio::test(start_paused = true)]
async fn pending_tree_wait_is_idle_without_work_and_immediate_when_due() {
    let absent = wait_for_optional_epoch_deadline(None);
    tokio::pin!(absent);
    assert!(futures::poll!(&mut absent).is_pending());
    let due = wait_for_optional_epoch_deadline(Some(crate::time::now_ms()));
    tokio::pin!(due);
    assert!(futures::poll!(&mut due).is_ready());
    let later = wait_for_optional_epoch_deadline(Some(crate::time::now_ms() + 60_000));
    tokio::pin!(later);
    assert!(futures::poll!(&mut later).is_pending());
    tokio::time::advance(Duration::from_secs(61)).await;
    later.await;
    assert!(futures::poll!(&mut absent).is_pending());
}

#[tokio::test]
async fn failed_pending_tree_turn_still_drains_bounded_data() {
    use crate::transport::{LinkId, PacketBuffer, ReceivedPacket, TransportAddr, TransportId};
    use crate::{ActivePeer, Identity, PeerIdentity};
    let mut node = crate::node::Node::new(crate::config::Config::new()).unwrap();
    let identity = Identity::generate();
    let peer = PeerIdentity::from_pubkey(identity.pubkey());
    let addr = *peer.node_addr();
    node.peers
        .insert(addr, ActivePeer::new(peer, LinkId::new(1), 0));
    node.mark_tree_announce_pending(&addr);
    let (packet_tx, mut packet_rx) = crate::transport::packet_channel(PACKET_DRAIN_BUDGET + 1);
    for _ in 0..=PACKET_DRAIN_BUDGET {
        packet_tx
            .send(ReceivedPacket::with_timestamp(
                TransportId::new(7),
                TransportAddr::from_string("127.0.0.1:9000"),
                PacketBuffer::new(vec![0]),
                123_456,
            ))
            .unwrap();
    }
    let (_endpoint_tx, mut endpoint_rx) = crate::node::endpoint_data_batch_channel(1);
    let (_tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
    let (_fast_tx, mut fast_rx) = tokio::sync::mpsc::channel(1);
    let endpoint_io = node.attach_endpoint_data_io(1).unwrap();
    let mut io = super::rx_loop_dataplane_io(
        &mut packet_rx,
        &mut fast_rx,
        &mut endpoint_rx,
        &mut tun_rx,
        &endpoint_io.event_tx,
    );
    let (completed, drained) = node.run_rx_loop_routing_announce_turn(&mut io).await;
    assert!(
        completed,
        "local carrier rejection completes without timeout"
    );
    assert_eq!(node.stats().tree.send_failed, 1);
    assert!(node.peers.get(&addr).unwrap().has_pending_tree_announce());
    assert!(node.pending_tree_announce_deadline_ms().unwrap() > crate::time::now_ms());
    assert_eq!(drained.packets, PACKET_DRAIN_BUDGET);
    assert!(drained.has_data_drained());
    assert!(packet_rx.try_recv().is_ok());
    assert!(packet_rx.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn report_deadline_honors_due_time_and_slow_batch_retry_floor() {
    for delayed_floor in [false, true] {
        let now = tokio::time::Instant::now().into_std();
        let later = now + Duration::from_secs(3_600);
        let (due, floor) = if delayed_floor {
            (now, later)
        } else {
            (later, now)
        };
        let wait = wait_for_optional_deadline(Some(due), floor);
        tokio::pin!(wait);
        // Only the sleep helper uses this virtual clock, not MMP's std clock.
        tokio::select! {
            biased;
            _ = &mut wait => panic!("future report deadline completed immediately"),
            _ = tokio::task::yield_now() => {}
        }
        tokio::time::advance(Duration::from_secs(1_800)).await;
        tokio::select! {
            biased;
            _ = &mut wait => panic!("report woke before its deadline/retry floor"),
            _ = tokio::task::yield_now() => {}
        }
        tokio::time::advance(Duration::from_secs(1_801)).await;
        wait.await;
    }
    let expired = tokio::time::Instant::now().into_std() - Duration::from_secs(1);
    let wait = wait_for_optional_deadline(Some(expired), expired);
    tokio::pin!(wait);
    assert!(
        futures::poll!(&mut wait).is_ready(),
        "expired work must be runnable on its first poll"
    );
}

#[tokio::test]
async fn report_turn_drains_bounded_queued_work_without_a_timeout() {
    use crate::dataplane::{OwnerConfig, OwnerId};
    use crate::transport::{PacketBuffer, ReceivedPacket, TransportAddr, TransportId};

    let mut node = crate::node::Node::new(crate::config::Config::new()).unwrap();
    let owner = OwnerId::fmp_node(crate::NodeAddr::from_bytes([17; 16]));
    node.dataplane.register_owner(
        owner,
        OwnerConfig::new(1, 8).with_fmp_mmp(Default::default(), false),
    );
    node.dataplane
        .record_fmp_mmp_send_result(&owner.node_addr(), 1, 1, 80, true);
    let earlier = Instant::now() - Duration::from_millis(400);
    assert_eq!(
        node.dataplane
            .collect_fmp_mmp_reports(earlier)
            .reports
            .len(),
        1
    );
    node.dataplane
        .record_fmp_mmp_send_result(&owner.node_addr(), 2, 2, 80, true);
    assert!(
        node.dataplane
            .fmp_report_deadline()
            .is_some_and(|due| due < Instant::now())
    );

    let (packet_tx, mut packet_rx) = crate::transport::packet_channel(PACKET_DRAIN_BUDGET + 1);
    for _ in 0..=PACKET_DRAIN_BUDGET {
        packet_tx
            .send(ReceivedPacket::with_timestamp(
                TransportId::new(7),
                TransportAddr::from_string("127.0.0.1:9000"),
                PacketBuffer::new(vec![0]),
                123_456,
            ))
            .unwrap();
    }
    let (_endpoint_tx, mut endpoint_rx) = crate::node::endpoint_data_batch_channel(1);
    let (_tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
    let (_fast_tx, mut fast_rx) = tokio::sync::mpsc::channel(1);
    let endpoint_io = node.attach_endpoint_data_io(1).unwrap();
    let mut io = super::rx_loop_dataplane_io(
        &mut packet_rx,
        &mut fast_rx,
        &mut endpoint_rx,
        &mut tun_rx,
        &endpoint_io.event_tx,
    );
    // There is no active carrier for this owner; the real report dispatch
    // completes without timeout. This checks post-dispatch queue progress,
    // not successful delivery or a simulated slow transport.
    let (completed, drained) = node.run_rx_loop_link_report_turn(&mut io).await;
    assert!(completed);
    assert!(drained.has_data_drained());
    assert_eq!(drained.packets, PACKET_DRAIN_BUDGET);
    assert!(
        packet_rx.try_recv().is_ok(),
        "excess backlog remains bounded"
    );
    assert!(packet_rx.try_recv().is_err());
}

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
    const {
        assert!(
            TUN_DRAIN_BUDGET > ENDPOINT_DRAIN_BUDGET,
            "canonical TUN packet ingress must not inherit the endpoint/control slice"
        );
    }
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
fn admission_pressure_relief_runs_only_for_bulk_capacity_pressure() {
    for (admission_dropped, runnable_work, turns, elapsed, priority_ready, expected) in [
        (true, true, 1, Duration::from_micros(100), 0, true),
        (false, true, 1, Duration::from_micros(100), 0, false),
        (true, false, 1, Duration::from_micros(100), 0, false),
        (
            true,
            true,
            super::budget::RX_LOOP_BULK_SERVICE_MAX_TURNS,
            Duration::from_micros(100),
            0,
            false,
        ),
        (
            true,
            true,
            1,
            super::budget::RX_LOOP_BULK_SERVICE_MAX_ELAPSED,
            0,
            false,
        ),
        (true, true, 1, Duration::from_micros(100), 1, false),
    ] {
        assert_eq!(
            super::bulk_admission_pressure_relief_due(
                admission_dropped,
                runnable_work,
                turns,
                elapsed,
                priority_ready,
            ),
            expected
        );
    }
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
    let (_fast_tx, mut fast_ingress_rx) = tokio::sync::mpsc::channel(1);
    let (_tun_tx, tun_rx) = crate::upper::tun::write_channel();
    let mut endpoint_io = node
        .attach_endpoint_data_io(1)
        .expect("endpoint io should attach before start");

    let turn = {
        let mut dataplane_io = super::rx_loop_dataplane_io(
            &mut packet_rx,
            &mut fast_ingress_rx,
            &mut endpoint_rx,
            &mut tun_outbound_rx,
            &endpoint_io.event_tx,
        );
        node.drain_dataplane_turn_with_firsts(
            &mut dataplane_io,
            crate::dataplane::DataplaneLiveTurnFirsts::default(),
            super::RxLoopDataplaneTurnLimits::new(4, 4, 4, 4),
        )
        .await
    };

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
    assert!(tun_rx.try_recv_packet().is_err());
    assert!(endpoint_io.event_rx.try_recv().is_err());
}

#[tokio::test]
async fn dataplane_turn_reports_raw_ingress_failures() {
    let mut node =
        crate::node::Node::new(crate::config::Config::new()).expect("node should construct");
    let (packet_tx, mut packet_rx) = crate::transport::packet_channel(1);
    let (_endpoint_tx, mut endpoint_rx) = crate::node::endpoint_data_batch_channel(1);
    let (_tun_outbound_tx, mut tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
    let (_fast_tx, mut fast_ingress_rx) = tokio::sync::mpsc::channel(1);
    let (_tun_tx, tun_rx) = crate::upper::tun::write_channel();
    let mut endpoint_io = node
        .attach_endpoint_data_io(1)
        .expect("endpoint io should attach before start");

    packet_tx
        .send(crate::transport::ReceivedPacket::with_timestamp(
            crate::transport::TransportId::new(7),
            crate::transport::TransportAddr::from_string("198.51.100.7:9000"),
            crate::transport::PacketBuffer::new(vec![0]),
            123_456,
        ))
        .expect("malformed packet queued");

    let turn = {
        let mut dataplane_io = super::rx_loop_dataplane_io(
            &mut packet_rx,
            &mut fast_ingress_rx,
            &mut endpoint_rx,
            &mut tun_outbound_rx,
            &endpoint_io.event_tx,
        );
        node.drain_dataplane_turn_with_firsts(
            &mut dataplane_io,
            crate::dataplane::DataplaneLiveTurnFirsts::default(),
            super::RxLoopDataplaneTurnLimits::new(4, 4, 4, 4),
        )
        .await
    };

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
    assert!(tun_rx.try_recv_packet().is_err());
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
    assert!(!state.skip_slow_maintenance(false));
    assert!(
        !state.skip_slow_maintenance(true),
        "queued dataplane work should timebox slow maintenance instead of starving it"
    );

    state.record_data_activity(start);
    assert!(state.data_pressure(empty, start + Duration::from_secs(1), window));
    assert!(!state.data_pressure(empty, start + Duration::from_secs(3), window));
    assert!(state.data_pressure(drained, start + Duration::from_secs(3), window));

    state.record_maintenance_result(true, true);
    assert!(state.skip_slow_maintenance(true));
    assert!(!state.skip_slow_maintenance(false));

    state.record_maintenance_result(true, false);
    assert!(
        !state.skip_slow_maintenance(true),
        "one skipped or successful busy tick should clear the timeout latch"
    );

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
