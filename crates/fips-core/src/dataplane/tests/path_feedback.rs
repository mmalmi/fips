#[test]
fn new_carrier_does_not_inherit_the_previous_carriers_smoothed_rtt() {
    let owner = fsp_owner(94);
    let mut mover = mover();
    mover.register_owner(
        owner,
        OwnerConfig::new(1, 8)
            .with_fsp_session_start_ms(1_000)
            .with_fsp_send_headers(0, 0)
            .with_fsp_mmp(crate::config::SessionMmpConfig::default(), true),
    );
    let report = crate::mmp::report::ReceiverReport {
        highest_counter: 100,
        cumulative_packets_recv: 100,
        cumulative_bytes_recv: 10_000,
        timestamp_echo: 100,
        dwell_time: 0,
        max_burst_loss: 0,
        mean_burst_loss: 0,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
        interval_packets_recv: 0,
        interval_bytes_recv: 0,
    };
    let old = fmp_owner(90).node_addr();
    let new = fmp_owner(91).node_addr();
    for (carrier, sent_at, received_at, echo, expected) in [
        (old, 1_100, 1_800, 100, 700.0),
        (new, 2_000, 2_020, 1_000, 20.0),
    ] {
        mover.owner_mut(owner).unwrap().record_fsp_data_sent(
            carrier,
            100,
            ActivityTick::new(sent_at),
        );
        if carrier == new {
            assert!(
                mover
                    .process_fsp_mmp_receiver_report(
                        owner,
                        &report,
                        Some(carrier),
                        received_at,
                        std::time::Instant::now(),
                        128,
                    )
                    .is_err(),
                "a delayed report echoing the old path cannot qualify the new one"
            );
            assert!(
                !mover
                    .owner_fsp_activity(owner)
                    .unwrap()
                    .has_recent_delivery_feedback_from(&new, received_at, 2_000)
            );
        }
        let result = mover
            .process_fsp_mmp_receiver_report(
                owner,
                &crate::mmp::report::ReceiverReport {
                    timestamp_echo: echo,
                    ..report.clone()
                },
                Some(carrier),
                received_at,
                std::time::Instant::now(),
                128,
            )
            .unwrap();
        assert_eq!(result.srtt_ms, Some(expected));
    }
    assert_eq!(
        mover
            .owner_fsp_activity(owner)
            .unwrap()
            .traffic_counters()
            .0,
        2
    );
}

#[test]
fn delivery_feedback_waits_one_report_window_before_degrading_a_new_burst() {
    let owner = fsp_owner(95);
    let mut mover = mover();
    mover.register_owner(
        owner,
        OwnerConfig::new(1, 8)
            .with_fsp_session_start_ms(1_000)
            .with_fsp_send_headers(0, 0)
            .with_fsp_mmp(crate::config::SessionMmpConfig::default(), true),
    );
    let send = |mover: &mut Dataplane, now| {
        assert!(mover.owner_mut(owner).unwrap().record_fsp_data_sent(
            owner.node_addr(),
            100,
            ActivityTick::new(now),
        ));
    };
    let feedback = |mover: &Dataplane, now| {
        mover
            .owner_fsp_activity(owner)
            .unwrap()
            .has_recent_delivery_feedback_from(&owner.node_addr(), now, 2_500)
    };
    let expired = |mover: &Dataplane, now| {
        mover
            .owner_fsp_activity(owner)
            .unwrap()
            .has_recent_outbound_without_delivery_feedback_from(&owner.node_addr(), now, 2_500)
    };
    send(&mut mover, 1_050);
    assert!(
        !expired(&mover, 1_100),
        "initial data must wait for its first report"
    );
    let mut report = crate::mmp::report::ReceiverReport {
        highest_counter: 100,
        cumulative_packets_recv: 100,
        cumulative_bytes_recv: 10_000,
        timestamp_echo: 50,
        dwell_time: 0,
        max_burst_loss: 0,
        mean_burst_loss: 0,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
        interval_packets_recv: 0,
        interval_bytes_recv: 0,
    };
    mover
        .process_fsp_mmp_receiver_report(
            owner,
            &report,
            Some(owner.node_addr()),
            1_200,
            std::time::Instant::now(),
            128,
        )
        .unwrap();
    send(&mut mover, 5_000);
    assert!(
        !expired(&mover, 5_100),
        "a send after idle must get its own report window"
    );
    send(&mut mover, 7_400);
    mover
        .process_fsp_mmp_receiver_report(
            owner,
            &report,
            Some(owner.node_addr()),
            7_450,
            std::time::Instant::now(),
            128,
        )
        .unwrap();
    assert!(
        !expired(&mover, 7_500),
        "the report window includes its boundary"
    );
    assert!(
        expired(&mover, 7_501),
        "new sends and frozen reports must not extend a blackhole's grace"
    );
    assert!(
        !feedback(&mover, 7_501),
        "frozen reports must not validate a recovery probe"
    );
    report.cumulative_packets_recv += 1;
    mover
        .process_fsp_mmp_receiver_report(
            owner,
            &report,
            Some(owner.node_addr()),
            7_510,
            std::time::Instant::now(),
            128,
        )
        .unwrap();
    assert!(
        !expired(&mover, 7_520),
        "advancing authenticated feedback must restore trust"
    );
    assert!(feedback(&mover, 7_520));
    assert!(mover.owner_mut(owner).unwrap().record_fsp_data_sent(
        fmp_owner(96).node_addr(),
        100,
        ActivityTick::new(7_530),
    ));
    assert!(
        !feedback(&mover, 7_540),
        "path changes must discard old direct proof"
    );
}
