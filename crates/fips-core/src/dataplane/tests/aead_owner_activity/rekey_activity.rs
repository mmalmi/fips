#[test]
fn staged_fsp_rekey_preserves_established_path_delivery_activity() {
    let owner = fsp_owner(93);
    let mut mover = mover();
    mover.register_owner(
        owner,
        OwnerConfig::new(1, 8)
            .with_fsp_session_start_ms(1_000)
            .with_fsp_send_headers(0, 0)
            .with_fsp_epoch(false, None)
            .with_fsp_mmp(crate::config::SessionMmpConfig::default(), true),
    );

    assert!(
        mover.owner_mut(owner).unwrap().record_fsp_data_sent(
            owner.node_addr(),
            1_200,
            ActivityTick::new(1_050),
        )
    );
    let rr = crate::mmp::report::ReceiverReport {
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
            &rr,
            Some(owner.node_addr()),
            1_100,
            std::time::Instant::now(),
            128,
        )
        .expect("owner should process pre-rekey delivery feedback");
    assert!(
        mover.owner_mut(owner).unwrap().install_fsp_pending_receive_epoch(
            true,
            test_key(94),
        )
    );

    assert!(mover.owner_mut(owner).unwrap().install_fsp_session(
        OwnerConfig::new(2, 8)
            .with_fsp_session_start_ms(1_000)
            .with_fsp_send_headers(crate::node::session_wire::FSP_FLAG_K, 0)
            .with_fsp_epoch(true, Some(false))
            .with_fsp_mmp(crate::config::SessionMmpConfig::default(), true),
        OwnerCryptoKeys::new(test_key(94), test_key(94)),
    ));
    assert!(
        mover.owner_mut(owner).unwrap().record_fsp_data_sent(
            owner.node_addr(),
            1_200,
            ActivityTick::new(1_200),
        )
    );

    assert!(
        !mover
            .owner_fsp_activity(owner)
            .unwrap()
            .has_recent_outbound_without_delivery_feedback_from(
                &owner.node_addr(),
                1_300,
                2_500,
            ),
        "a staged key cutover must retain recent delivery proof for the unchanged direct path"
    );
}
