#[test]
fn staged_fsp_rekey_preserves_established_path_delivery_activity() {
    let owner = fsp_owner(93);
    let mut mover = mover();
    let pending_authority = crate::noise::SendCounterAuthority::for_test();
    mover.register_owner(
        owner,
        OwnerConfig::new(1, 8)
            .with_fsp_session_start_ms(1_000)
            .with_fsp_send_headers(0, 0)
            .with_fsp_epoch(false, None)
            .with_fsp_mmp(crate::config::SessionMmpConfig::default(), true),
    );

    assert!(mover.owner_mut(owner).unwrap().record_fsp_data_sent(
        owner.node_addr(),
        1_200,
        ActivityTick::new(1_050),
    ));
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
    assert!(mover.owner_mut(owner).unwrap().install_fsp_pending_epoch(
        true,
        test_key(94),
        test_key(94),
        pending_authority.clone(),
    ));

    assert!(
        mover.owner_mut(owner).unwrap().install_fsp_session(
            OwnerConfig::new(2, 8)
                .with_send_counter_authority(pending_authority)
                .with_fsp_session_start_ms(1_000)
                .with_fsp_send_headers(crate::node::session_wire::FSP_FLAG_K, 0)
                .with_fsp_epoch(true, Some(false))
                .with_fsp_mmp(crate::config::SessionMmpConfig::default(), true),
            OwnerCryptoKeys::new(test_key(94), test_key(94)),
        )
    );
    assert!(mover.owner_mut(owner).unwrap().record_fsp_data_sent(
        owner.node_addr(),
        1_200,
        ActivityTick::new(1_200),
    ));

    assert!(
        !mover
            .owner_fsp_activity(owner)
            .unwrap()
            .has_recent_outbound_without_delivery_feedback_from(&owner.node_addr(), 1_300, 2_500,),
        "a staged key cutover must retain recent delivery proof for the unchanged direct path"
    );
}

#[test]
fn rekey_delivers_authenticated_work_completed_after_cutover() {
    for protocol in [PacketProtocol::Fmp, PacketProtocol::Fsp] {
        for (pending, queued, expired) in [
            (false, false, false), (true, false, false), (false, true, false), (true, true, false),
            (false, false, true), (true, false, true), (false, true, true), (true, true, true),
        ] {
            let owner = match protocol { PacketProtocol::Fmp => fmp_owner(95), PacketProtocol::Fsp => fsp_owner(95) };
            let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
            let next_authority = crate::noise::SendCounterAuthority::for_test();
            let config = |generation, previous| match protocol {
                PacketProtocol::Fmp => OwnerConfig::new(generation, 8).with_fmp_epoch(generation == 2, previous),
                PacketProtocol::Fsp => OwnerConfig::new(generation, 8).with_fsp_epoch(generation == 2, previous),
            };
            driver.mover.register_owner(owner, config(1, None));
            let state = driver.mover.owner_mut(owner).unwrap();
            state.set_crypto_keys(OwnerCryptoKeys::new(test_key(95), test_key(95)));
            assert!(match protocol {
                PacketProtocol::Fmp => state.install_fmp_pending_receive_epoch(true, test_key(96), next_authority.clone()),
                PacketProtocol::Fsp => state.install_fsp_pending_epoch(true, test_key(96), test_key(96), next_authority.clone()),
            });
            let payload = b"reply crossing cutover";
            let packet_for = |generation, new_key, receive_epoch| {
                let flags = if new_key { match protocol {
                    PacketProtocol::Fmp => crate::node::wire::FLAG_KEY_EPOCH,
                    PacketProtocol::Fsp => crate::node::session_wire::FSP_FLAG_K,
                }} else { 0 };
                let key = if new_key { 96 } else { 95 };
                match protocol {
                    PacketProtocol::Fmp => fmp_socket_packet(owner, generation, OutputTarget::Transport,
                        fmp_encrypted_wire(95, 7, flags, payload, key)).unwrap().with_receive_epoch(receive_epoch),
                    PacketProtocol::Fsp => SocketPacket::new(owner, generation, 7, FSP_HEADER_SIZE as u16,
                        PacketClass::Bulk, OutputTarget::Transport,
                        PacketBuffer::new(fsp_encrypted_wire(7, flags, payload, key))).with_wire_flags(flags),
                }
            };
            let packet = packet_for(1, pending, if pending { DataplaneReceiveEpoch::Pending } else { DataplaneReceiveEpoch::Current });
            driver.mover.submit_socket_packet(packet).unwrap();
            let mut prepared = if queued { Vec::new() } else { capture_prepared_work(&mut driver.mover, 8) };
            let state = driver.mover.owner_mut(owner).unwrap();
            let config = config(2, Some(false)).with_send_counter_authority(next_authority);
            let keys = OwnerCryptoKeys::new(test_key(96), test_key(96));
            assert!(match protocol {
                PacketProtocol::Fmp => state.install_fmp_session(config, keys),
                PacketProtocol::Fsp => state.install_fsp_session(config, keys),
            });
            if expired {
                match protocol {
                    PacketProtocol::Fmp => { state.set_fmp_epoch(true, None); }
                    PacketProtocol::Fsp => { state.set_fsp_epoch(true, None); }
                }
                if queued {
                    let turn = run_aead_available(&mut driver.mover, 8);
                    assert!(turn.outputs().is_empty());
                    assert_eq!(turn.drops[0].reason, PacketDropReason::StaleGeneration);
                } else {
                    let completions = prepared.into_iter().map(execute_test_prepared_crypto_work).collect::<Vec<_>>();
                    let turn = run_aead_completion_turn(&mut driver, completions, 8);
                    assert!(turn.outputs.is_empty());
                    assert_eq!(turn.drops[0].reason, PacketDropReason::StaleCompletionGeneration);
                }
                continue;
            }
            if queued { prepared = capture_prepared_work(&mut driver.mover, 8); }
            assert_eq!(prepared.len(), 1, "{protocol:?} pending={pending} queued={queued}: admission survives cutover");
            let completions = prepared.into_iter().map(execute_test_prepared_crypto_work).collect::<Vec<_>>();
            let turn = run_aead_completion_turn(&mut driver, completions, 8);
            assert!(turn.drops.is_empty(), "{protocol:?} pending={pending}: {:?}", turn.drops);
            assert_eq!(turn.outputs.len(), 1, "{protocol:?} pending={pending}: authenticated reply retained");
            assert!(turn.outputs[0].payload.as_slice().ends_with(payload));
            let epoch = if pending { DataplaneReceiveEpoch::Current } else { DataplaneReceiveEpoch::Previous };
            driver.mover.submit_socket_packet(packet_for(2, pending, epoch)).unwrap();
            let duplicate = run_aead_available(&mut driver.mover, 8);
            assert_eq!(duplicate.drops.len(), 1);
            assert_eq!(duplicate.drops[0].reason, PacketDropReason::Replay);
            if !pending {
                driver.mover.submit_socket_packet(packet_for(2, true, DataplaneReceiveEpoch::Current)).unwrap();
                let current = run_aead_available(&mut driver.mover, 8);
                assert!(current.drops.is_empty(), "old work cannot consume a new key's counter");
                assert_eq!(current.outputs().len(), 1);
            }
        }
    }
}

#[test]
fn rekey_delivers_outbound_work_queued_before_cutover() {
    for protocol in [PacketProtocol::Fmp, PacketProtocol::Fsp] {
        let owner = match protocol { PacketProtocol::Fmp => fmp_owner(98), PacketProtocol::Fsp => fsp_owner(98) };
        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        let next_authority = crate::noise::SendCounterAuthority::for_test();
        let config = |generation, previous| match protocol {
            PacketProtocol::Fmp => OwnerConfig::new(generation, 8)
                .with_fmp_epoch(generation == 2, previous)
                .with_fmp_send_headers(98, if generation == 2 { crate::node::wire::FLAG_KEY_EPOCH } else { 0 }),
            PacketProtocol::Fsp => OwnerConfig::new(generation, 8).with_fsp_epoch(generation == 2, previous),
        };
        driver.mover.register_owner(owner, config(1, None));
        let state = driver.mover.owner_mut(owner).unwrap();
        state.set_crypto_keys(OwnerCryptoKeys::new(test_key(98), test_key(98)));
        assert!(match protocol {
            PacketProtocol::Fmp => state.install_fmp_pending_receive_epoch(true, test_key(99), next_authority.clone()),
            PacketProtocol::Fsp => state.install_fsp_pending_epoch(true, test_key(99), test_key(99), next_authority.clone()),
        });
        driver.mover.submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Bulk, b"queued reply")).unwrap();
        let state = driver.mover.owner_mut(owner).unwrap();
        let config = config(2, Some(false)).with_send_counter_authority(next_authority);
        let keys = OwnerCryptoKeys::new(test_key(99), test_key(99));
        assert!(match protocol {
            PacketProtocol::Fmp => state.install_fmp_session(config, keys),
            PacketProtocol::Fsp => state.install_fsp_session(config, keys),
        });
        let turn = run_aead_available(&mut driver.mover, 8);
        assert!(turn.drops.is_empty(), "{protocol:?}: {:?}", turn.drops);
        assert_eq!(turn.outputs().len(), 1, "{protocol:?}: queued plaintext uses current keys");
        let output = turn.outputs()[0];
        let plaintext = match protocol {
            PacketProtocol::Fmp => open_fmp_wire_payload(output.payload.as_slice(), 99),
            PacketProtocol::Fsp => open_fsp_wire_payload(output.payload.as_slice(), 99),
        };
        assert_eq!(plaintext, b"queued reply", "current key and matching wire headers");
    }
}
