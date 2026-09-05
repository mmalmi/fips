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
}
