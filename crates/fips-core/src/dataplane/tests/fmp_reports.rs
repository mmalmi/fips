use super::*;
use crate::mmp::{MmpConfig, MmpMode, receiver::ReceiverState};
use std::time::{Duration, Instant};

fn live_link(mode: MmpMode) -> (DataplaneLiveNode, OwnerId) {
    let mut live = DataplaneLiveNode::new(AdmissionConfig::new(4, 8));
    let owner = fmp_owner(910);
    live.register_owner(
        owner,
        OwnerConfig::new(1, 8)
            .with_fmp_session_start_ms(1_000)
            .with_fmp_mmp(
                MmpConfig {
                    mode,
                    ..Default::default()
                },
                false,
            ),
    );
    (live, owner)
}

fn receive(live: &mut DataplaneLiveNode, owner: OwnerId, counter: u64, now: Instant) {
    live.record_authenticated_fmp_mmp_receive(DataplaneAuthenticatedFmpMmpReceive::new(
        owner.node_addr(),
        counter,
        100,
        80,
        false,
        false,
        now,
    ))
    .unwrap();
}

#[tokio::test]
async fn fmp_report_traffic_is_counted_without_eliciting_more_reports() {
    let (mut live, owner) = live_link(MmpMode::Full);
    let now = Instant::now();
    live.record_fmp_mmp_send_result(&owner.node_addr(), 1, 100, 80, true);
    receive(&mut live, owner, 1, now);
    assert_eq!(live.collect_fmp_mmp_reports(now).reports.len(), 2);

    for (counter, bytes) in [(2, 48), (3, 68)] {
        live.record_fmp_mmp_send_result(&owner.node_addr(), counter, 100, bytes, false);
        let mut packet = DataplaneAuthenticatedFmpMmpReceive::new(
            owner.node_addr(),
            counter,
            100,
            bytes,
            false,
            false,
            now,
        );
        packet.elicits_report = false;
        live.record_authenticated_fmp_mmp_receive(packet).unwrap();
    }
    let later = now + Duration::from_secs(10);
    assert_eq!(live.fmp_report_deadline(), None);
    assert!(live.collect_fmp_mmp_reports(later).reports.is_empty());

    // New data must resume reporting, including every intervening report in
    // cumulative accounting so its counter is not mistaken for packet loss.
    live.record_fmp_mmp_send_result(&owner.node_addr(), 4, 100, 80, true);
    receive(&mut live, owner, 4, later);
    let reports = live.collect_fmp_mmp_reports(later).reports;
    assert_eq!(reports.len(), 2);
    for report in reports {
        match report.kind {
            DataplaneFmpMmpReportKind::Sender => {
                let report =
                    crate::mmp::report::SenderReport::decode(&report.encoded[1..]).unwrap();
                assert_eq!(report.cumulative_packets_sent, 4);
                assert_eq!(report.cumulative_bytes_sent, 276);
            }
            DataplaneFmpMmpReportKind::Receiver => {
                let report =
                    crate::mmp::report::ReceiverReport::decode(&report.encoded[1..]).unwrap();
                assert_eq!(report.cumulative_packets_recv, 4);
                assert_eq!(report.cumulative_bytes_recv, 276);
            }
        }
    }
}

#[tokio::test]
async fn fmp_report_deadlines_require_pending_traffic_and_respect_modes() {
    for mode in [MmpMode::Full, MmpMode::Lightweight, MmpMode::Minimal] {
        let (mut live, owner) = live_link(mode);
        assert_eq!(live.fmp_report_deadline(), None, "registration is idle");
        live.record_fmp_mmp_send_result(&owner.node_addr(), 1, 100, 80, true);
        assert_eq!(live.fmp_report_deadline().is_some(), mode == MmpMode::Full);
        receive(&mut live, owner, 1, Instant::now());
        assert_eq!(
            live.fmp_report_deadline().is_some(),
            mode != MmpMode::Minimal
        );

        let now = Instant::now();
        let reports = live.collect_fmp_mmp_reports(now).reports;
        let expected = match mode {
            MmpMode::Full => 2,
            MmpMode::Lightweight => 1,
            MmpMode::Minimal => 0,
        };
        assert_eq!(reports.len(), expected);
        assert_eq!(
            live.fmp_report_deadline(),
            None,
            "a drained link stays idle"
        );

        receive(&mut live, owner, 2, now + Duration::from_millis(10));
        if mode == MmpMode::Minimal {
            assert_eq!(live.fmp_report_deadline(), None);
        } else {
            let due = now + Duration::from_millis(200);
            assert_eq!(live.fmp_report_deadline(), Some(due));
            assert!(
                live.collect_fmp_mmp_reports(due - Duration::from_nanos(1))
                    .reports
                    .is_empty()
            );
            assert_eq!(live.fmp_report_deadline(), Some(due));
            assert_eq!(live.collect_fmp_mmp_reports(due).reports.len(), 1);
            assert_eq!(live.fmp_report_deadline(), None);
        }
    }
}

#[tokio::test]
async fn fmp_report_deadline_clears_after_owner_removal_or_rekey() {
    for remove in [false, true] {
        let (mut live, owner) = live_link(MmpMode::Full);
        let now = Instant::now();
        live.record_fmp_mmp_send_result(&owner.node_addr(), 100, 100, 80, true);
        receive(&mut live, owner, 100, now);
        assert!(live.fmp_report_deadline().is_some());
        if remove {
            live.unregister_owner(owner);
        } else {
            live.driver.owner_mut(owner).unwrap().rekey(2);
        }
        assert!(live.collect_fmp_mmp_reports(now).reports.is_empty());
        assert_eq!(
            live.fmp_report_deadline(),
            None,
            "stale hint is consumed once"
        );
        if remove {
            live.record_fmp_mmp_send_result(&owner.node_addr(), 101, 100, 80, true);
            assert_eq!(live.fmp_report_deadline(), None);
        } else {
            receive(&mut live, owner, 0, now);
            assert_eq!(live.fmp_report_deadline(), Some(now));
            let reports = live.collect_fmp_mmp_reports(now).reports;
            assert_eq!(reports.len(), 1);
            assert_eq!(reports[0].kind, DataplaneFmpMmpReportKind::Receiver);
            let rr = crate::mmp::report::ReceiverReport::decode(&reports[0].encoded[1..]).unwrap();
            assert_eq!(rr.highest_counter, 0);
            assert_eq!(rr.interval_packets_recv, 1);
            assert_eq!(live.fmp_report_deadline(), None);
        }
    }
}

#[tokio::test]
async fn fmp_receiver_feedback_moves_deadline_later_and_earlier() {
    let (mut live, owner) = live_link(MmpMode::Full);
    let now = Instant::now();
    receive(&mut live, owner, 1, now);
    assert_eq!(live.collect_fmp_mmp_reports(now).reports.len(), 1);
    receive(&mut live, owner, 2, now + Duration::from_millis(1));
    let cold_due = now + Duration::from_millis(200);
    assert_eq!(live.fmp_report_deadline(), Some(cold_due));

    // Real echoed timestamps establish 500ms RTT, increasing the RR interval.
    let mut remote = ReceiverState::new(32);
    remote.record_recv(1, 100, 80, false, now);
    let first = remote.build_report(now).unwrap();
    let result = live
        .process_fmp_mmp_receiver_report(&owner.node_addr(), &first, 1_600, now)
        .unwrap();
    assert!(result.first_rtt);
    assert_eq!(result.srtt_ms, Some(500.0));
    assert_eq!(
        live.fmp_report_deadline(),
        Some(cold_due),
        "hint may wake early"
    );
    assert!(live.collect_fmp_mmp_reports(cold_due).reports.is_empty());
    let later = now + Duration::from_millis(500);
    assert_eq!(live.fmp_report_deadline(), Some(later));

    // A subsequent 20ms sample shortens the interval; the touched owner must
    // advance the cached wake rather than waiting for the old 500ms deadline.
    remote.record_recv(2, 600, 80, false, now);
    let next = remote.build_report(now).unwrap();
    live.process_fmp_mmp_receiver_report(&owner.node_addr(), &next, 1_620, now)
        .unwrap();
    let interval = live
        .driver
        .owner_mut(owner)
        .unwrap()
        .fmp_mmp
        .as_ref()
        .unwrap()
        .receiver
        .report_interval();
    let earlier = now + interval;
    assert!(earlier < later && earlier > cold_due);
    assert_eq!(live.fmp_report_deadline(), Some(earlier));
    assert!(
        live.collect_fmp_mmp_reports(earlier - Duration::from_nanos(1))
            .reports
            .is_empty()
    );
    assert_eq!(live.collect_fmp_mmp_reports(earlier).reports.len(), 1);
    assert_eq!(live.fmp_report_deadline(), None);
}

#[tokio::test]
async fn fmp_report_deadline_uses_earliest_remaining_link() {
    let (mut live, owner) = live_link(MmpMode::Full);
    let second = fmp_owner(911);
    live.register_owner(
        second,
        OwnerConfig::new(1, 8).with_fmp_mmp(MmpConfig::default(), false),
    );
    let now = Instant::now();
    receive(&mut live, owner, 1, now);
    live.collect_fmp_mmp_reports(now);
    receive(&mut live, owner, 2, now);
    let later = now + Duration::from_millis(200);
    receive(&mut live, second, 1, now);
    assert_eq!(live.fmp_report_deadline(), Some(now));
    let reports = live.collect_fmp_mmp_reports(now).reports;
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].node_addr, second.node_addr());
    assert_eq!(live.fmp_report_deadline(), Some(later));
    assert_eq!(live.collect_fmp_mmp_reports(later).reports.len(), 1);
    assert_eq!(live.fmp_report_deadline(), None);
}
