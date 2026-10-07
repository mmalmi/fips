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

fn establish_rtt(live: &mut DataplaneLiveNode, owner: OwnerId, now: Instant) {
    let mut remote = ReceiverState::new(100);
    remote.record_recv(1, 100, 80, false, now);
    let rr = remote.build_report(now).unwrap();
    let measured = live
        .process_fmp_mmp_receiver_report(&owner.node_addr(), &rr, 1_120, now)
        .unwrap();
    assert!(measured.srtt_ms.is_some());
}

#[tokio::test]
async fn lost_initial_report_retries_until_first_valid_rtt_then_quiets() {
    let (mut live, owner) = live_link(MmpMode::Full);
    let now = Instant::now();
    live.record_fmp_mmp_send_result(&owner.node_addr(), 1, 100, 80, true);
    let reports = live.collect_fmp_mmp_reports(now).reports;
    assert_eq!(reports.len(), 1);
    // The report is successfully sent but lost before the peer receives it.
    // Accounting it must preserve a new measurement attempt during startup.
    live.record_fmp_mmp_send_result(&owner.node_addr(), 2, 101, 48, false);
    let due = now + Duration::from_millis(200);
    assert_eq!(live.fmp_report_deadline(), Some(due));
    assert!(live
        .collect_fmp_mmp_reports(due - Duration::from_nanos(1))
        .reports
        .is_empty());
    let retry = live.collect_fmp_mmp_reports(due).reports;
    assert_eq!(retry.len(), 1);
    assert_eq!(retry[0].kind, DataplaneFmpMmpReportKind::Sender);
    live.record_fmp_mmp_send_result(&owner.node_addr(), 3, 300, 48, false);
    establish_rtt(&mut live, owner, due + Duration::from_millis(20));
    assert!(live
        .collect_fmp_mmp_reports(due + Duration::from_secs(1))
        .reports
        .is_empty());
    assert_eq!(live.fmp_report_deadline(), None);
}

#[tokio::test]
async fn fmp_report_traffic_is_counted_without_eliciting_more_reports() {
    let (mut live, owner) = live_link(MmpMode::Full);
    let now = Instant::now();
    establish_rtt(&mut live, owner, now);
    live.record_fmp_mmp_send_result(&owner.node_addr(), 1, 100, 80, true);
    receive(&mut live, owner, 1, now);
    assert_eq!(live.collect_fmp_mmp_reports(now).reports.len(), 2);

    use crate::mmp::{link_message_elicits_receiver_report, link_message_elicits_sender_report};
    use crate::proto::protocol::LinkMessageType;
    for (counter, bytes, kind) in [
        (2, 48, LinkMessageType::SenderReport),
        (3, 68, LinkMessageType::ReceiverReport),
    ] {
        live.record_fmp_mmp_send_result(
            &owner.node_addr(),
            counter,
            100,
            bytes,
            link_message_elicits_sender_report(Some(kind.to_byte())),
        );
        let mut packet = DataplaneAuthenticatedFmpMmpReceive::new(
            owner.node_addr(),
            counter,
            100,
            bytes,
            false,
            false,
            now,
        );
        packet.elicits_report = link_message_elicits_receiver_report(Some(kind.to_byte()));
        live.record_authenticated_fmp_mmp_receive(packet).unwrap();
    }
    let later = now + Duration::from_secs(10);
    let replies = live.collect_fmp_mmp_reports(later).reports;
    assert_eq!(
        replies.len(),
        1,
        "sender report receives one bounded response"
    );
    assert_eq!(replies[0].kind, DataplaneFmpMmpReportKind::Receiver);
    // Actually sending that response must not create a sender-report deadline.
    assert!(!link_message_elicits_sender_report(
        replies[0].encoded.first().copied()
    ));
    assert_eq!(live.fmp_report_deadline(), None);
    assert!(
        live.collect_fmp_mmp_reports(later + Duration::from_secs(10))
            .reports
            .is_empty()
    );

    // New data must resume reporting, including every intervening report in
    // cumulative accounting so its counter is not mistaken for packet loss.
    let resumed = later + Duration::from_secs(11);
    live.record_fmp_mmp_send_result(&owner.node_addr(), 4, 100, 80, true);
    receive(&mut live, owner, 4, resumed);
    let reports = live.collect_fmp_mmp_reports(resumed).reports;
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
async fn legacy_sender_reports_receive_feedback_and_leave_cold_start() {
    use crate::mmp::{MmpPeerState, link_message_elicits_receiver_report};
    use crate::proto::protocol::LinkMessageType;

    let (mut live, owner) = live_link(MmpMode::Full);
    let mut legacy = MmpPeerState::new(&MmpConfig::default(), true);
    let start = Instant::now();
    // The published sender counts its own reports as traffic. Keep that
    // behavior here so the mixed-version feedback path cannot go untested.
    legacy.sender.record_sent(0, 100, 80);
    let mut now = start;
    for counter in 1..=8 {
        if counter > 1 {
            now += legacy.sender.report_interval();
        }
        assert!(legacy.sender.should_send_report(now));
        let sr = legacy.sender.build_report(now).unwrap();
        let timestamp = 100 + now.duration_since(start).as_millis() as u32;
        let bytes = sr.encode().len() + 1;
        legacy.sender.record_sent(counter, timestamp, bytes);
        let mut packet = DataplaneAuthenticatedFmpMmpReceive::new(
            owner.node_addr(),
            counter,
            timestamp,
            bytes,
            false,
            false,
            now + Duration::from_millis(10),
        );
        packet.elicits_report =
            link_message_elicits_receiver_report(Some(LinkMessageType::SenderReport.to_byte()));
        live.record_authenticated_fmp_mmp_receive(packet).unwrap();
        let due = live
            .fmp_report_deadline()
            .expect("sender report needs feedback");
        let reply_time = due.max(now + Duration::from_millis(10));
        let reports = live.collect_fmp_mmp_reports(reply_time).reports;
        assert_eq!(reports.len(), 1, "one bounded receiver response");
        assert_eq!(reports[0].kind, DataplaneFmpMmpReportKind::Receiver);
        let rr = crate::mmp::report::ReceiverReport::decode(&reports[0].encoded[1..]).unwrap();
        assert_eq!(rr.cumulative_packets_recv, counter);
        legacy.metrics.process_receiver_report(
            &rr,
            100 + reply_time.duration_since(start).as_millis() as u32 + 10,
            reply_time + Duration::from_millis(10),
        );
        let srtt = legacy.metrics.srtt_ms().expect("legacy RTT feedback");
        assert!((srtt - 20.0).abs() < 0.1);
        assert_eq!(
            legacy.metrics.loss_rate(),
            0.0,
            "reports are not false loss"
        );
        legacy
            .sender
            .update_report_interval_from_srtt((srtt * 1000.0) as i64);
        assert_eq!(
            live.fmp_report_deadline(),
            None,
            "response does not sustain traffic"
        );
    }
    assert_eq!(legacy.sender.report_interval(), Duration::from_secs(1));

    // A lost report must still count as a real gap in the counter sequence.
    now += Duration::from_secs(1);
    let timestamp = 100 + now.duration_since(start).as_millis() as u32;
    let mut packet = DataplaneAuthenticatedFmpMmpReceive::new(
        owner.node_addr(),
        10,
        timestamp,
        48,
        false,
        false,
        now,
    );
    packet.elicits_report =
        link_message_elicits_receiver_report(Some(LinkMessageType::SenderReport.to_byte()));
    live.record_authenticated_fmp_mmp_receive(packet).unwrap();
    let reports = live.collect_fmp_mmp_reports(now).reports;
    let rr = crate::mmp::report::ReceiverReport::decode(&reports[0].encoded[1..]).unwrap();
    legacy
        .metrics
        .process_receiver_report(&rr, timestamp + 20, now + Duration::from_millis(20));
    assert!(
        legacy.metrics.loss_rate() > 0.0,
        "a missing report remains measurable loss"
    );
}

#[tokio::test]
async fn fmp_report_deadlines_require_pending_traffic_and_respect_modes() {
    for mode in [MmpMode::Full, MmpMode::Lightweight, MmpMode::Minimal] {
        let (mut live, owner) = live_link(mode);
        assert_eq!(live.fmp_report_deadline(), None, "registration is idle");
        establish_rtt(&mut live, owner, Instant::now());
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
