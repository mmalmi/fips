#[test]
fn owner_tracks_outbound_activity_only_for_reserved_packets() {
    let owner = fmp_owner(76);
    let mut mover = mover();
    mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(7));

    mover
        .submit_outbound_packet(
            outbound_packet(owner, 1, PacketClass::Bulk, b"newer")
                .with_activity_tick(ActivityTick::new(50)),
        )
        .unwrap();
    let work = dispatch_outbound_available(&mut mover, 8);
    assert_eq!(work.len(), 1);
    assert_eq!(work[0].reservation.counter, 7);
    assert_eq!(
        mover.owner_mut(owner).unwrap().last_tx_activity(),
        Some(ActivityTick::new(50))
    );

    mover
        .submit_outbound_packet(
            outbound_packet(owner, 1, PacketClass::Liveness, b"older")
                .with_activity_tick(ActivityTick::new(40)),
        )
        .unwrap();
    assert_eq!(dispatch_outbound_available(&mut mover, 8).len(), 1);
    assert_eq!(
        mover.owner_mut(owner).unwrap().last_tx_activity(),
        Some(ActivityTick::new(50))
    );

    mover
        .submit_outbound_packet(
            outbound_packet(owner, 0, PacketClass::Liveness, b"stale")
                .with_activity_tick(ActivityTick::new(60)),
        )
        .unwrap();
    assert!(dispatch_outbound_available(&mut mover, 8).is_empty());
    assert_eq!(
        mover.owner_mut(owner).unwrap().last_tx_activity(),
        Some(ActivityTick::new(50))
    );

    let drops = mover.drain_drops();
    assert!(
        drops
            .iter()
            .any(|drop| drop.reason == PacketDropReason::StaleGeneration && drop.counter.is_none())
    );
}

#[test]
fn fsp_owner_tracks_data_return_without_registry_side_channel() {
    let owner = fsp_owner(77);
    let next_hop = fmp_owner(78);
    let wrap = DataplaneFspWrapRoute::new(next_hop, 1, 7878, test_node_addr(1), owner.node_addr());
    let mut mover = mover();
    mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(10));
    mover
        .owner_mut(owner)
        .unwrap()
        .set_fsp_wrap_route(Some(wrap));

    let outbound = OutboundPacket::fsp(
        owner,
        1,
        PacketClass::Bulk,
        0,
        PacketBuffer::new(b"payload".to_vec()),
    )
    .with_fsp_inner_header(
        crate::protocol::SessionMessageType::EndpointData.to_byte(),
        0,
    )
    .with_activity_tick(ActivityTick::new(100));
    mover.submit_outbound_packet(outbound).unwrap();
    assert_eq!(dispatch_outbound_available(&mut mover, 8).len(), 1);

    let activity = mover.owner_fsp_activity(owner).unwrap();
    assert_eq!(
        activity.last_outbound_next_hop(),
        Some(next_hop.node_addr())
    );
    assert!(activity.has_recent_outbound_activity(105, 10));
    assert!(activity.has_recent_outbound_without_inbound(105, 10));
    assert_eq!(mover.record_fsp_decrypt_failure(owner), Some(1));
    assert_eq!(mover.record_fsp_decrypt_failure(owner), Some(2));
    let sync = |counter, body_len| FspReceiveSync {
        counter,
        received_k_bit: false,
        timestamp: 0,
        plaintext_len: FSP_INNER_HEADER_SIZE + body_len,
        ce_flag: false,
        path_mtu: u16::MAX,
        spin_bit: false,
    };

    assert!(
        mover
            .record_authenticated_fsp_session(DataplaneAuthenticatedFspSession::new(
                owner.node_addr(),
                owner.node_addr(),
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                11,
                sync(1, 11),
                Some(ActivityTick::new(110)),
                std::time::Instant::now(),
            ),)
            .is_some()
    );
    let activity = mover.owner_fsp_activity(owner).unwrap();
    assert_eq!(
        activity.last_rx_data_age_ms(115),
        Some(5),
        "authenticated application data should still count as general session activity"
    );
    assert!(
        activity.has_recent_outbound_without_data_return_from(
            &next_hop.node_addr(),
            115,
            20,
        ),
        "direct inbound data must not masquerade as return traffic for a routed fallback send"
    );
    assert!(!activity.has_recent_outbound_without_inbound(115, 20));
    assert_eq!(mover.record_fsp_decrypt_failure(owner), Some(1));

    assert!(
        mover
            .record_authenticated_fsp_session(DataplaneAuthenticatedFspSession::new(
                owner.node_addr(),
                next_hop.node_addr(),
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                13,
                sync(2, 13),
                Some(ActivityTick::new(120)),
                std::time::Instant::now(),
            ),)
            .is_some()
    );
    let activity = mover.owner_fsp_activity(owner).unwrap();
    assert_eq!(activity.last_rx_age_ms(125), Some(5));
    assert_eq!(activity.last_rx_data_age_ms(125), Some(5));
    assert_eq!(
        mover.min_fsp_rx_age_for_next_hop(&next_hop.node_addr(), 125),
        Some(5),
        "authenticated FSP via the previous hop must refresh that hop's link liveness"
    );
    assert_eq!(
        mover.min_fsp_data_rx_age_for_next_hop(&next_hop.node_addr(), 125),
        Some(5),
        "endpoint data via the previous hop keeps payload trust fresh"
    );

    let other_previous_hop = test_node_addr(179);
    assert!(
        mover
            .record_authenticated_fsp_session(DataplaneAuthenticatedFspSession::new(
                owner.node_addr(),
                other_previous_hop,
                crate::protocol::SessionMessageType::SenderReport.to_byte(),
                17,
                sync(3, 17),
                Some(ActivityTick::new(130)),
                std::time::Instant::now(),
            ),)
            .is_some()
    );
    let activity = mover.owner_fsp_activity(owner).unwrap();
    assert_eq!(activity.last_rx_age_ms(135), Some(5));
    assert_eq!(activity.last_rx_data_age_ms(135), Some(15));
    assert_eq!(
        mover.min_fsp_rx_age_for_next_hop(&other_previous_hop, 135),
        Some(5),
        "control/session FSP activity should still prove previous-hop liveness"
    );
    assert_eq!(
        mover.min_fsp_data_rx_age_for_next_hop(&other_previous_hop, 135),
        None,
        "control/session FSP activity must not masquerade as endpoint-data freshness"
    );
}

#[test]
fn fsp_owner_uses_session_age_when_no_packet_has_authenticated() {
    let owner = fsp_owner(180);
    let mut mover = mover();
    mover.register_owner(
        owner,
        OwnerConfig::new(1, 8).with_fsp_session_start_ms(1_000),
    );

    let activity = mover.owner_fsp_activity(owner).unwrap();
    assert_eq!(activity.authenticated_inbound_or_session_age_ms(16_000), Some(15_000));
}

#[test]
fn fsp_owner_records_direct_transport_as_the_destination_next_hop() {
    let owner = fsp_owner(79);
    let mut mover = mover();
    mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(10));

    let outbound = OutboundPacket::fsp(
        owner,
        1,
        PacketClass::Bulk,
        0,
        PacketBuffer::new(b"direct payload".to_vec()),
    )
    .with_fsp_inner_header(
        crate::protocol::SessionMessageType::EndpointData.to_byte(),
        0,
    )
    .with_activity_tick(ActivityTick::new(100));
    mover.submit_outbound_packet(outbound).unwrap();
    assert_eq!(dispatch_outbound_available(&mut mover, 8).len(), 1);

    assert_eq!(
        mover
            .owner_fsp_activity(owner)
            .unwrap()
            .last_outbound_next_hop(),
        Some(owner.node_addr()),
        "direct FSP transport must replace any previously recorded fallback next hop"
    );
}

#[test]
fn fsp_owner_owns_session_mmp_reports() {
    let owner = fsp_owner(80);
    let mut mover = mover();
    mover.register_owner(
        owner,
        OwnerConfig::new(1, 8)
            .with_fsp_session_start_ms(1_000)
            .with_fsp_send_headers(0, 0)
            .with_fsp_mmp(crate::config::SessionMmpConfig::default(), true)
            .with_next_send_counter(20),
    );
    mover
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(80), test_key(81)));

    let outbound = OutboundPacket::fsp(
        owner,
        1,
        PacketClass::Mmp,
        0,
        PacketBuffer::new(b"sender".to_vec()),
    )
    .with_fsp_inner_header(
        crate::protocol::SessionMessageType::SenderReport.to_byte(),
        0,
    )
    .with_activity_tick(ActivityTick::new(1_020));
    mover.submit_outbound_packet(outbound).unwrap();
    assert_eq!(dispatch_outbound_available(&mut mover, 8).len(), 1);

    let sync = FspReceiveSync {
        counter: 9,
        received_k_bit: false,
        timestamp: 7,
        plaintext_len: FSP_INNER_HEADER_SIZE + 5,
        ce_flag: false,
        path_mtu: 1234,
        spin_bit: false,
    };
    assert_eq!(
        mover.record_authenticated_fsp_session(DataplaneAuthenticatedFspSession::new(
            owner.node_addr(),
            owner.node_addr(),
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            5,
            sync,
            Some(ActivityTick::new(1_030)),
            std::time::Instant::now(),
        ),),
        Some(true)
    );

    let batch = mover.collect_fsp_mmp_reports(std::time::Instant::now());
    assert!(
        batch.reports.iter().any(|report| {
            report.dest_addr == owner.node_addr()
                && report.msg_type == crate::protocol::SessionMessageType::SenderReport.to_byte()
        }),
        "owner should emit session SenderReport from reserved FSP sends"
    );
    assert!(
        batch.reports.iter().any(|report| {
            report.dest_addr == owner.node_addr()
                && report.msg_type == crate::protocol::SessionMessageType::ReceiverReport.to_byte()
        }),
        "owner should emit session ReceiverReport from authenticated FSP receives"
    );
    assert!(
        batch.reports.iter().any(|report| {
            report.dest_addr == owner.node_addr()
                && report.msg_type
                    == crate::protocol::SessionMessageType::PathMtuNotification.to_byte()
        }),
        "owner should emit path-MTU notifications from authenticated FSP receives"
    );
    assert_eq!(batch.metric_logs.len(), 1);
    assert_eq!(batch.metric_logs[0].dest_addr, owner.node_addr());
    assert_eq!(batch.metric_logs[0].send_mtu, u16::MAX);
    assert_eq!(batch.metric_logs[0].observed_mtu, 1234);
    assert_eq!(batch.metric_logs[0].tx_packets, 1);
    assert_eq!(batch.metric_logs[0].rx_packets, 1);
}

#[test]
fn fsp_owner_current_epoch_confirmation_is_one_shot_per_generation() {
    let owner = fsp_owner(84);
    let mut mover = mover();
    mover.register_owner(
        owner,
        OwnerConfig::new(1, 8)
            .with_fsp_session_start_ms(1_000)
            .with_fsp_send_headers(0, 0),
    );
    let sync = FspReceiveSync {
        counter: 1,
        received_k_bit: false,
        timestamp: 10,
        plaintext_len: FSP_INNER_HEADER_SIZE,
        ce_flag: false,
        path_mtu: u16::MAX,
        spin_bit: false,
    };

    assert_eq!(
        mover.record_authenticated_fsp_session(DataplaneAuthenticatedFspSession::new(
            owner.node_addr(),
            owner.node_addr(),
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0,
            sync,
            Some(ActivityTick::new(1_010)),
            std::time::Instant::now(),
        ),),
        Some(true)
    );
    assert_eq!(
        mover.record_authenticated_fsp_session(DataplaneAuthenticatedFspSession::new(
            owner.node_addr(),
            owner.node_addr(),
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0,
            FspReceiveSync { counter: 2, ..sync },
            Some(ActivityTick::new(1_020)),
            std::time::Instant::now(),
        ),),
        Some(false)
    );

    mover.owner_mut(owner).unwrap().rekey(2);
    assert_eq!(
        mover.record_authenticated_fsp_session(DataplaneAuthenticatedFspSession::new(
            owner.node_addr(),
            owner.node_addr(),
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0,
            FspReceiveSync { counter: 3, ..sync },
            Some(ActivityTick::new(1_030)),
            std::time::Instant::now(),
        ),),
        Some(true)
    );
}

#[test]
fn fsp_owner_keeps_previous_receive_epoch_during_rekey_drain() {
    let owner = fsp_owner(85);
    let old_key = 85;
    let new_key = 86;
    let mut mover = mover();
    mover.register_owner(
        owner,
        OwnerConfig::new(1, 8)
            .with_fsp_session_start_ms(1_000)
            .with_fsp_send_headers(0, 0)
            .with_fsp_epoch(false, None),
    );
    mover
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(old_key), test_key(old_key)));

    mover
        .submit_socket_packet(SocketPacket::new(
            owner,
            1,
            10,
            FSP_HEADER_SIZE as u16,
            PacketClass::Bulk,
            OutputTarget::Transport,
            PacketBuffer::new(fsp_encrypted_wire(10, 0, b"old-before", old_key)),
        ))
        .unwrap();
    let turn = run_aead_available(&mut mover, 8);
    assert!(turn.drops().is_empty());
    assert_eq!(
        &turn.outputs()[0].payload.as_slice()[FSP_HEADER_SIZE..],
        b"old-before"
    );

    assert!(
        mover.owner_mut(owner).unwrap().install_fsp_session(
            OwnerConfig::new(2, 8)
                .with_fsp_session_start_ms(2_000)
                .with_fsp_send_headers(crate::node::session_wire::FSP_FLAG_K, 0)
                .with_fsp_epoch(true, Some(false)),
            OwnerCryptoKeys::new(test_key(new_key), test_key(new_key)),
        )
    );

    mover
        .submit_socket_packet(SocketPacket::new(
            owner,
            2,
            11,
            FSP_HEADER_SIZE as u16,
            PacketClass::Bulk,
            OutputTarget::Transport,
            PacketBuffer::new(fsp_encrypted_wire(11, 0, b"old-after", old_key)),
        ))
        .unwrap();
    let current_epoch_packet = SocketPacket::new(
        owner,
        2,
        1,
        FSP_HEADER_SIZE as u16,
        PacketClass::Bulk,
        OutputTarget::Transport,
        PacketBuffer::new(fsp_encrypted_wire(
            1,
            crate::node::session_wire::FSP_FLAG_K,
            b"new-after",
            new_key,
        )),
    )
    .with_wire_flags(crate::node::session_wire::FSP_FLAG_K);
    mover.submit_socket_packet(current_epoch_packet).unwrap();

    let turn = run_aead_available(&mut mover, 8);
    assert!(turn.drops().is_empty(), "{:?}", turn.drops());
    let outputs = turn.outputs();
    assert_eq!(outputs.len(), 2);
    assert_eq!(
        &outputs[0].payload.as_slice()[FSP_HEADER_SIZE..],
        b"old-after"
    );
    assert_eq!(
        &outputs[1].payload.as_slice()[FSP_HEADER_SIZE..],
        b"new-after"
    );
}

#[test]
fn fsp_owner_authenticates_pending_receive_epoch_before_cutover() {
    let owner = fsp_owner(86);
    let old_key = 86;
    let new_key = 87;
    let mut mover = mover();
    mover.register_owner(
        owner,
        OwnerConfig::new(1, 8)
            .with_fsp_session_start_ms(1_000)
            .with_fsp_send_headers(0, 0)
            .with_fsp_epoch(false, None),
    );
    mover
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(old_key), test_key(old_key)));
    assert!(
        mover
            .owner_mut(owner)
            .unwrap()
            .install_fsp_pending_receive_epoch(true, test_key(new_key))
    );

    mover
        .submit_socket_packet(
            SocketPacket::new(
                owner,
                1,
                1,
                FSP_HEADER_SIZE as u16,
                PacketClass::Bulk,
                OutputTarget::Transport,
                PacketBuffer::new(fsp_encrypted_wire(
                    1,
                    crate::node::session_wire::FSP_FLAG_K,
                    b"pending-new",
                    new_key,
                )),
            )
            .with_wire_flags(crate::node::session_wire::FSP_FLAG_K),
        )
        .unwrap();
    let turn = run_aead_available(&mut mover, 8);
    assert!(turn.drops().is_empty(), "{:?}", turn.drops());
    assert_eq!(
        &turn.outputs()[0].payload.as_slice()[FSP_HEADER_SIZE..],
        b"pending-new"
    );

    assert!(
        mover.owner_mut(owner).unwrap().install_fsp_session(
            OwnerConfig::new(2, 8)
                .with_fsp_session_start_ms(2_000)
                .with_fsp_send_headers(crate::node::session_wire::FSP_FLAG_K, 0)
                .with_fsp_epoch(true, Some(false)),
            OwnerCryptoKeys::new(test_key(new_key), test_key(new_key)),
        )
    );
    mover
        .submit_socket_packet(
            SocketPacket::new(
                owner,
                2,
                1,
                FSP_HEADER_SIZE as u16,
                PacketClass::Bulk,
                OutputTarget::Transport,
                PacketBuffer::new(fsp_encrypted_wire(
                    1,
                    crate::node::session_wire::FSP_FLAG_K,
                    b"replay",
                    new_key,
                )),
            )
            .with_wire_flags(crate::node::session_wire::FSP_FLAG_K),
        )
        .unwrap();
    let turn = run_aead_available(&mut mover, 8);
    assert!(
        turn.drops()
            .iter()
            .any(|drop| drop.reason == PacketDropReason::Replay && drop.counter == Some(1))
    );
}

#[test]
fn fmp_owner_authenticates_pending_receive_epoch_before_cutover() {
    let owner = fmp_owner(96);
    let old_key = 96;
    let new_key = 97;
    let receiver_idx = 0x96;
    let mut mover = mover();
    mover.register_owner(
        owner,
        OwnerConfig::new(1, 8)
            .with_fmp_session_start_ms(1_000)
            .with_fmp_send_headers(receiver_idx, 0)
            .with_fmp_epoch(false, None),
    );
    mover
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(old_key), test_key(old_key)));
    assert!(
        mover
            .owner_mut(owner)
            .unwrap()
            .install_fmp_pending_receive_epoch(true, test_key(new_key))
    );

    let pending_flags = crate::node::wire::FLAG_KEY_EPOCH;
    mover
        .submit_socket_packet(
            fmp_socket_packet(
                owner,
                1,
                OutputTarget::Transport,
                fmp_encrypted_wire(receiver_idx, 1, pending_flags, b"pending-new", new_key),
            )
            .unwrap(),
        )
        .unwrap();
    let turn = run_aead_available(&mut mover, 8);
    assert!(turn.drops().is_empty(), "{:?}", turn.drops());
    assert_eq!(
        &turn.outputs()[0].payload.as_slice()[FMP_ESTABLISHED_HEADER_SIZE..],
        b"pending-new"
    );

    assert!(
        mover.owner_mut(owner).unwrap().install_fmp_session(
            OwnerConfig::new(2, 8)
                .with_fmp_session_start_ms(2_000)
                .with_fmp_send_headers(receiver_idx, pending_flags)
                .with_fmp_epoch(true, Some(false)),
            OwnerCryptoKeys::new(test_key(new_key), test_key(new_key)),
        )
    );
    mover
        .submit_socket_packet(
            fmp_socket_packet(
                owner,
                2,
                OutputTarget::Transport,
                fmp_encrypted_wire(receiver_idx, 1, pending_flags, b"replay", new_key),
            )
            .unwrap(),
        )
        .unwrap();
    let turn = run_aead_available(&mut mover, 8);
    assert!(
        turn.drops()
            .iter()
            .any(|drop| drop.reason == PacketDropReason::Replay && drop.counter == Some(1))
    );
}

#[test]
fn fsp_owner_owns_session_receiver_reports_and_path_mtu_signals() {
    let owner = fsp_owner(81);
    let mut mover = mover();
    mover.register_owner(
        owner,
        OwnerConfig::new(1, 8)
            .with_fsp_session_start_ms(1_000)
            .with_fsp_send_headers(0, 0)
            .with_fsp_mmp(crate::config::SessionMmpConfig::default(), true),
    );

    let sync = FspReceiveSync {
        counter: 40,
        received_k_bit: false,
        timestamp: 10,
        plaintext_len: FSP_INNER_HEADER_SIZE + 1200,
        ce_flag: false,
        path_mtu: u16::MAX,
        spin_bit: false,
    };
    assert_eq!(
        mover.record_authenticated_fsp_session(DataplaneAuthenticatedFspSession::new(
            owner.node_addr(),
            owner.node_addr(),
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            1200,
            sync,
            Some(ActivityTick::new(1_040)),
            std::time::Instant::now(),
        ),),
        Some(true)
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
    let report = mover
        .process_fsp_mmp_receiver_report(
            owner,
            &rr,
            Some(owner.node_addr()),
            1_100,
            std::time::Instant::now(),
            128,
        )
        .expect("owner should process session receiver report");
    assert!(report.used_direct_next_hop);
    assert_eq!(report.mode, crate::mmp::MmpMode::Full);

    assert_eq!(mover.seed_fsp_path_mtu(owner, 1400), Ok(()));
    assert_eq!(
        mover.owner_fsp_activity(owner).unwrap().current_path_mtu(),
        Some(1400)
    );
    assert_eq!(
        mover.apply_fsp_path_mtu_signal(owner, 1280, std::time::Instant::now()),
        Ok(DataplaneFspPathMtuApplyResult::Changed(
            DataplaneFspPathMtuChange {
                old_mtu: 1400,
                new_mtu: 1280
            }
        ))
    );
    assert_eq!(
        mover.owner_fsp_activity(owner).unwrap().current_path_mtu(),
        Some(1280)
    );
    assert_eq!(
        mover.apply_fsp_path_mtu_signal(owner, 1400, std::time::Instant::now()),
        Ok(DataplaneFspPathMtuApplyResult::Unchanged)
    );
}

#[test]
fn runtime_turn_driver_runs_classified_inbound_and_outbound_once() {
    let owner = fmp_owner(78);
    let open_key = 31;
    let seal_key = 32;
    let path = live_path(7800);
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(300));
    driver
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));

    let inbound = fmp_socket_packet(
        owner,
        1,
        OutputTarget::Transport,
        fmp_encrypted_wire(78, 100, 0, b"inbound", open_key),
    )
    .unwrap()
    .with_source_path(path.clone())
    .with_activity_tick(ActivityTick::new(10));
    let outbound = OutboundPacket::fmp(
        owner,
        1,
        PacketClass::Liveness,
        780,
        0,
        PacketBuffer::new(b"outbound".to_vec()),
    )
    .with_activity_tick(ActivityTick::new(11));

    let turn = run_aead_classified_turn(&mut driver, [inbound], [outbound], 8);
    let summary = turn.summary();
    assert!(
        summary.completions <= summary.dispatched,
        "native completion timing cannot retire more work than was dispatched"
    );
    assert_eq!(
        summary,
        DataplaneRuntimeSummary {
            raw_ingress_dropped: 0,
            inbound_admitted: 1,
            inbound_dropped: 0,
            outbound_admitted: 1,
            outbound_dropped: 0,
            completions: summary.completions,
            dispatched: 2,
            outputs: 2,
            outputs_sent: 0,
            outputs_dropped: 0,
            drops: 0,
        }
    );
    assert!(turn.drops().is_empty());

    let outputs = turn.outputs();
    assert_eq!(outputs[0].target, OutputTarget::Transport);
    assert_eq!(outputs[0].counter, 100);
    assert_eq!(
        &outputs[0].payload.as_slice()[FMP_ESTABLISHED_HEADER_SIZE..],
        b"inbound"
    );
    assert_eq!(outputs[0].path.clone(), None);

    assert_eq!(outputs[1].target, OutputTarget::Transport);
    assert_eq!(outputs[1].counter, 300);
    assert_eq!(outputs[1].path.clone(), Some(path.clone()));
    assert_eq!(open_sealed_output(&outputs[1], seal_key), b"outbound");

    let owner_state = driver.owner_mut(owner).unwrap();
    assert_eq!(owner_state.active_path(), Some(path));
    assert_eq!(owner_state.last_rx_activity(), Some(ActivityTick::new(10)));
    assert_eq!(owner_state.last_tx_activity(), Some(ActivityTick::new(11)));
}

#[test]
fn completion_only_turn_retires_worker_completion_without_new_dispatch() {
    let owner = fmp_owner(80);
    let open_key = 80;
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(owner, OwnerConfig::new(1, 8));

    driver
        .mover
        .submit_socket_packet(
            fmp_socket_packet(
                owner,
                1,
                OutputTarget::Transport,
                fmp_encrypted_wire(80, 100, 0, b"completion-only", open_key),
            )
            .unwrap(),
        )
        .unwrap();

    let mut work = dispatch_available(&mut driver.mover, 8);
    assert_eq!(work.len(), 1);
    assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 1);

    let completion = complete_test_open_work(work.pop().unwrap(), open_key);

    {
        let turn = run_aead_completion_turn(&mut driver, [completion], 8);
        assert_eq!(
            turn.summary(),
            DataplaneRuntimeSummary {
                raw_ingress_dropped: 0,
                inbound_admitted: 0,
                inbound_dropped: 0,
                outbound_admitted: 0,
                outbound_dropped: 0,
                completions: 1,
                dispatched: 0,
                outputs: 1,
                outputs_sent: 0,
                outputs_dropped: 0,
                drops: 0,
            }
        );
        assert!(turn.drops().is_empty());
        assert_eq!(turn.outputs().len(), 1);
        assert_eq!(turn.outputs()[0].owner(), owner);
        assert_eq!(turn.outputs()[0].counter(), 100);
        assert_eq!(turn.outputs()[0].target(), OutputTarget::Transport);
        assert_eq!(
            &turn.outputs()[0].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
            b"completion-only"
        );
    }

    assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 0);
}

#[test]
fn completion_source_pump_reports_completion_activity_before_output_is_ready() {
    let owner = fmp_owner(84);
    let open_key = 84;
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(owner, OwnerConfig::new(1, 8));

    let packets: [(u64, &[u8]); 3] = [(100, b"first"), (101, b"second"), (102, b"third")];
    for (counter, payload) in packets {
        driver
            .mover
            .submit_socket_packet(
                fmp_socket_packet(
                    owner,
                    1,
                    OutputTarget::Transport,
                    fmp_encrypted_wire(84, counter, 0, payload, open_key),
                )
                .unwrap(),
            )
            .unwrap();
    }

    let mut work = dispatch_available(&mut driver.mover, 8);
    assert_eq!(work.len(), 3);

    let mut completions = work
        .drain(..)
        .map(|work| complete_test_open_work(work, open_key))
        .collect::<VecDeque<_>>();
    let third = completions.pop_back().unwrap();
    let first = completions.pop_front().unwrap();
    let second = completions.pop_front().unwrap();

    let mut raw_ingress = VecDeque::new();
    let mut outbound = VecDeque::new();
    let mut sink = BatchRecordingOutputSink::default();
    let mut completion_source = VecDeque::from([third]);

    {
        let turn = pump_aead_output_completion_turn(
            &mut driver,
            AeadOutputCompletionTurn {
                completions: &mut completion_source,
                completion_limit: 8,
                raw_ingress: &mut raw_ingress,
                router: &mut NullIngressRouter,
                raw_ingress_limit: 0,
                outbound: &mut outbound,
                outbound_limit: 0,
                sink: &mut sink,
                crypto_limit: 8,
            },
        );
        assert_eq!(turn.summary().completions(), 1);
        assert_eq!(turn.summary().dispatched(), 0);
        assert_eq!(turn.summary().outputs(), 0);
        assert!(turn.summary().has_activity());
        assert!(turn.outputs().is_empty());
        assert!(turn.drops().is_empty());
    }
    assert!(completion_source.is_empty());
    assert!(sink.outputs.is_empty());
    assert_eq!(sink.batch_calls, 0);

    completion_source.extend([first, second]);
    {
        let turn = pump_aead_output_completion_turn(
            &mut driver,
            AeadOutputCompletionTurn {
                completions: &mut completion_source,
                completion_limit: 8,
                raw_ingress: &mut raw_ingress,
                router: &mut NullIngressRouter,
                raw_ingress_limit: 0,
                outbound: &mut outbound,
                outbound_limit: 0,
                sink: &mut sink,
                crypto_limit: 8,
            },
        );
        assert_eq!(turn.summary().completions(), 2);
        assert_eq!(turn.summary().outputs(), 3);
        assert_eq!(turn.summary().outputs_sent(), 3);
        assert!(turn.outputs().is_empty());
        assert!(turn.drops().is_empty());
    }

    assert!(completion_source.is_empty());
    assert_eq!(sink.batch_calls, 1);
    assert_eq!(sink.outputs.len(), 3);
    assert_eq!(sink.outputs[0].counter(), 100);
    assert_eq!(sink.outputs[1].counter(), 101);
    assert_eq!(sink.outputs[2].counter(), 102);
    assert_eq!(
        &sink.outputs[0].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
        b"first"
    );
    assert_eq!(
        &sink.outputs[1].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
        b"second"
    );
    assert_eq!(
        &sink.outputs[2].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
        b"third"
    );
    assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 0);
}
