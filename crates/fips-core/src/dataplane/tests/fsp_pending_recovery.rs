fn fsp_recovery_driver() -> (
    DataplaneTurnDriver,
    OwnerId,
    crate::noise::SendCounterAuthority,
) {
    let owner = fsp_owner(141);
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(owner, OwnerConfig::new(1, 8).with_fsp_epoch(false, None));
    let state = driver.owner_mut(owner).unwrap();
    state.set_crypto_keys(OwnerCryptoKeys::new(test_key(141), test_key(141)));
    let authority = crate::noise::SendCounterAuthority::for_test();
    assert!(state.install_fsp_pending_epoch(true, test_key(142), test_key(142), authority.clone()));
    (driver, owner, authority)
}

#[test]
fn fsp_pending_recovery_late_same_flag_packets_preserve_current_path_and_counter() {
    for target in [
        OutputTarget::Transport,
        OutputTarget::SessionPayload {
            local_addr: test_node_addr(144),
        },
    ] {
        let (mut driver, owner, authority) = fsp_recovery_driver();
        assert!(
            driver.owner_mut(owner).unwrap().install_fsp_session(
                OwnerConfig::new(2, 8)
                    .with_fsp_epoch(false, Some(false))
                    .with_send_counter_authority(authority),
                OwnerCryptoKeys::new(test_key(142), test_key(142)),
            )
        );
        let current_path = live_path(200);
        let old_path = live_path(100);
        let moved_path = live_path(300);
        let body = crate::node::session_wire::fsp_prepend_inner_header(
            0,
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0,
            b"late data",
        );
        for (key, counter, path, expected_path, expected_highest) in [
            (142, 7, &current_path, &current_path, 7),
            (141, 1_000, &old_path, &current_path, 7),
            (142, 8, &moved_path, &moved_path, 8),
        ] {
            let packet = fsp_socket_packet(
                owner,
                2,
                target,
                fsp_encrypted_wire(
                    counter,
                    crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
                    &body,
                    key,
                ),
            )
            .unwrap()
            .with_previous_hop(owner.node_addr())
            .with_source_path(path.clone());
            driver.mover.submit_socket_packet(packet).unwrap();
            let turn = run_aead_available(&mut driver.mover, 8);
            assert!(turn.drops().is_empty(), "{:?}", turn.drops());
            assert_eq!(
                turn.outputs().len(),
                1,
                "late application data remains deliverable"
            );
            let state = driver.owner_mut(owner).unwrap();
            assert_eq!(
                state.active_path(),
                Some(expected_path.clone()),
                "target {target:?}, key {key}"
            );
            assert_eq!(
                state.authenticated_counter_highest, expected_highest,
                "target {target:?}, key {key}"
            );
        }
    }
}

#[test]
fn fsp_pending_recovery_authenticates_before_alignment_and_keeps_replay_per_key() {
    let (mut driver, owner, authority) = fsp_recovery_driver();
    assert!(
        !driver
            .owner_mut(owner)
            .unwrap()
            .confirm_fsp_pending_receive_epoch(false)
    );
    // Neither an unrelated key nor altered ciphertext proves an epoch.
    let mut altered = pending_instance_packet(owner, 1, 142, false, 1);
    let last = altered.payload.len() - 1;
    altered.payload.as_mut_slice()[last] ^= 1;
    for packet in [pending_instance_packet(owner, 1, 143, false, 1), altered] {
        driver.mover.submit_socket_packet(packet).unwrap();
        assert_eq!(run_aead_available(&mut driver.mover, 8).drops().len(), 1);
        assert!(
            !driver
                .owner_mut(owner)
                .unwrap()
                .confirm_fsp_pending_receive_epoch(false)
        );
    }
    // Same flag/counter under two different authenticated keys is valid. A
    // duplicate pending packet queued beside them must still be rejected.
    for key in [141, 142, 142] {
        driver
            .mover
            .submit_socket_packet(pending_instance_packet(owner, 1, key, false, 1))
            .unwrap();
    }
    let turn = run_aead_available(&mut driver.mover, 8);
    assert_eq!(turn.outputs().len(), 2);
    assert_eq!(turn.drops().len(), 1);
    assert_eq!(turn.drops()[0].reason(), PacketDropReason::Replay);
    assert!(
        driver
            .owner_mut(owner)
            .unwrap()
            .confirm_fsp_pending_receive_epoch(false)
    );
    assert!(
        driver.owner_mut(owner).unwrap().install_fsp_session(
            OwnerConfig::new(2, 8)
                .with_fsp_epoch(false, Some(false))
                .with_send_counter_authority(authority),
            OwnerCryptoKeys::new(test_key(142), test_key(142)),
        )
    );
    for key in [141, 142] {
        driver
            .mover
            .submit_socket_packet(pending_instance_packet(owner, 2, key, false, 1))
            .unwrap();
    }
    let turn = run_aead_available(&mut driver.mover, 8);
    assert!(turn.outputs().is_empty());
    assert_eq!(turn.drops().len(), 2);
    assert!(
        turn.drops()
            .iter()
            .all(|drop| drop.reason() == PacketDropReason::Replay)
    );
    for key in [141, 142] {
        driver
            .mover
            .submit_socket_packet(pending_instance_packet(owner, 2, key, false, 2))
            .unwrap();
    }
    let turn = run_aead_available(&mut driver.mover, 8);
    assert!(turn.drops().is_empty(), "{:?}", turn.drops());
    assert_eq!(turn.outputs().len(), 2);
    assert_eq!(
        turn.outputs()[0].authenticated_receive_epoch,
        Some((DataplaneReceiveEpoch::Previous, 0))
    );
    assert_eq!(
        turn.outputs()[1].authenticated_receive_epoch,
        Some((DataplaneReceiveEpoch::Current, 0))
    );
}

#[test]
fn fsp_pending_recovery_rejects_replaced_cancelled_and_stale_generation_completions() {
    for replacement in [false, true] {
        let (mut driver, owner, _) = fsp_recovery_driver();
        driver
            .mover
            .submit_socket_packet(pending_instance_packet(owner, 1, 142, false, 1))
            .unwrap();
        let work = capture_prepared_work(&mut driver.mover, 8);
        assert_eq!(work.len(), 1);
        assert!(
            driver
                .owner_mut(owner)
                .unwrap()
                .clear_fsp_pending_receive_epoch()
        );
        if replacement {
            assert!(install_test_pending_epoch(
                driver.owner_mut(owner).unwrap(),
                true,
                143
            ));
        }
        let turn = run_aead_completion_turn(
            &mut driver,
            work.into_iter().map(execute_test_prepared_crypto_work),
            8,
        );
        assert!(turn.outputs().is_empty());
        assert_eq!(turn.drops().len(), 1);
        assert!(
            !driver
                .owner_mut(owner)
                .unwrap()
                .confirm_fsp_pending_receive_epoch(false)
        );
    }
    let (mut driver, owner, _) = fsp_recovery_driver();
    driver
        .mover
        .submit_socket_packet(pending_instance_packet(owner, 1, 142, false, 1))
        .unwrap();
    let work = capture_prepared_work(&mut driver.mover, 8);
    assert_eq!(work.len(), 1);
    assert!(driver.owner_mut(owner).unwrap().install_fsp_session(
        OwnerConfig::new(2, 8).with_fsp_epoch(false, None),
        OwnerCryptoKeys::new(test_key(143), test_key(143)),
    ));
    let turn = run_aead_completion_turn(
        &mut driver,
        work.into_iter().map(execute_test_prepared_crypto_work),
        8,
    );
    assert!(turn.outputs().is_empty());
    assert_eq!(turn.drops().len(), 1);
    assert_eq!(
        turn.drops()[0].reason(),
        PacketDropReason::StaleCompletionGeneration
    );
}

#[test]
fn fsp_pending_recovery_remaps_inflight_keys_and_expires_same_flag_drain() {
    let (mut driver, owner, authority) = fsp_recovery_driver();
    for key in [141, 142] {
        driver
            .mover
            .submit_socket_packet(pending_instance_packet(owner, 1, key, false, 1))
            .unwrap();
    }
    let work = capture_prepared_work(&mut driver.mover, 8);
    assert_eq!(work.len(), 2);
    assert!(
        driver.owner_mut(owner).unwrap().install_fsp_session(
            OwnerConfig::new(2, 8)
                .with_fsp_epoch(false, Some(false))
                .with_send_counter_authority(authority),
            OwnerCryptoKeys::new(test_key(142), test_key(142)),
        )
    );
    let turn = run_aead_completion_turn(
        &mut driver,
        work.into_iter().map(execute_test_prepared_crypto_work),
        8,
    );
    assert!(turn.drops().is_empty(), "{:?}", turn.drops());
    assert_eq!(turn.outputs().len(), 2);
    assert_eq!(
        turn.outputs()[0].authenticated_receive_epoch,
        Some((DataplaneReceiveEpoch::Previous, 0))
    );
    assert_eq!(
        turn.outputs()[1].authenticated_receive_epoch,
        Some((DataplaneReceiveEpoch::Current, 0))
    );
    driver
        .mover
        .submit_socket_packet(pending_instance_packet(owner, 2, 141, false, 2))
        .unwrap();
    let work = capture_prepared_work(&mut driver.mover, 8);
    assert_eq!(work.len(), 1);
    assert!(driver.owner_mut(owner).unwrap().set_fsp_epoch(false, None));
    let turn = run_aead_completion_turn(
        &mut driver,
        work.into_iter().map(execute_test_prepared_crypto_work),
        8,
    );
    assert!(turn.outputs().is_empty());
    assert_eq!(turn.drops().len(), 1);
    driver
        .mover
        .submit_socket_packet(pending_instance_packet(owner, 2, 141, false, 3))
        .unwrap();
    let turn = run_aead_available(&mut driver.mover, 8);
    assert!(turn.outputs().is_empty());
    assert_eq!(turn.drops().len(), 1);
}
