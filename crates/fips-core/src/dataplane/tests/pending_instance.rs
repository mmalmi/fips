#[test]
fn replacing_pending_epoch_rejects_only_its_obsolete_completions() {
    for owner in [fmp_owner(110), fsp_owner(110)] {
        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(110), test_key(110)));
        assert!(install_test_pending_epoch(
            driver.owner_mut(owner).unwrap(),
            true,
            111
        ));
        driver
            .mover
            .submit_socket_packet(pending_instance_packet(owner, 1, 110, false, 7))
            .unwrap();
        driver
            .mover
            .submit_socket_packet(
                pending_instance_packet(owner, 1, 111, true, 7)
                    .with_receive_epoch(DataplaneReceiveEpoch::Pending),
            )
            .unwrap();
        let old_work = capture_prepared_work(&mut driver.mover, 8);
        assert_eq!(old_work.len(), 2);
        match owner.protocol() {
            PacketProtocol::Fmp => assert!(
                driver
                    .owner_mut(owner)
                    .unwrap()
                    .clear_fmp_pending_receive_epoch()
            ),
            PacketProtocol::Fsp => assert!(
                driver
                    .owner_mut(owner)
                    .unwrap()
                    .clear_fsp_pending_receive_epoch()
            ),
        }
        assert!(install_test_pending_epoch(
            driver.owner_mut(owner).unwrap(),
            true,
            112
        ));

        // A new pending reservation must survive retirement of the old one,
        // even when both sessions start with the same counter.
        driver
            .mover
            .submit_socket_packet(
                pending_instance_packet(owner, 1, 112, true, 7)
                    .with_receive_epoch(DataplaneReceiveEpoch::Pending),
            )
            .unwrap();
        let new_work = capture_prepared_work(&mut driver.mover, 8);
        assert_eq!(new_work.len(), 1, "replacement owns a fresh replay window");
        let turn = run_aead_completion_turn(
            &mut driver,
            old_work.into_iter().map(execute_test_prepared_crypto_work),
            8,
        );
        assert_eq!(
            turn.outputs().len(),
            1,
            "only the current epoch completion remains valid"
        );
        assert_eq!(turn.drops().len(), 1);
        if owner.protocol() == PacketProtocol::Fmp {
            assert!(
                !driver
                    .owner_mut(owner)
                    .unwrap()
                    .confirm_fmp_pending_receive_epoch(true)
            );
        }
        let turn = run_aead_completion_turn(
            &mut driver,
            new_work.into_iter().map(execute_test_prepared_crypto_work),
            8,
        );
        assert!(turn.drops().is_empty(), "{:?}", turn.drops());
        assert_eq!(turn.outputs().len(), 1);
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 0);
    }
}

#[test]
fn full_session_replacement_keeps_its_own_replay_history() {
    for owner in [fmp_owner(113), fsp_owner(113)] {
        let mut mover = mover();
        mover.register_owner(
            owner,
            OwnerConfig::new(1, 8)
                .with_fmp_epoch(true, None)
                .with_fsp_epoch(true, None),
        );
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(113), test_key(113)));
        assert!(install_test_pending_epoch(
            mover.owner_mut(owner).unwrap(),
            false,
            114
        ));
        mover
            .submit_socket_packet(
                pending_instance_packet(owner, 1, 114, false, 7)
                    .with_receive_epoch(DataplaneReceiveEpoch::Pending),
            )
            .unwrap();
        assert!(run_aead_available(&mut mover, 8).drops().is_empty());

        let config = OwnerConfig::new(2, 8)
            .with_fmp_epoch(false, Some(true))
            .with_fsp_epoch(false, Some(true))
            .with_send_counter_authority(crate::noise::SendCounterAuthority::for_test());
        let keys = OwnerCryptoKeys::new(test_key(115), test_key(115));
        let state = mover.owner_mut(owner).unwrap();
        assert!(match owner.protocol() {
            PacketProtocol::Fmp => state.install_fmp_session(config, keys),
            PacketProtocol::Fsp => state.install_fsp_session(config, keys),
        });
        mover
            .submit_socket_packet(pending_instance_packet(owner, 2, 115, false, 7))
            .unwrap();
        let turn = run_aead_available(&mut mover, 8);
        assert!(
            turn.drops().is_empty(),
            "full connection must not inherit another session's counters: {:?}",
            turn.drops()
        );
        assert_eq!(turn.outputs().len(), 1);
    }
}

fn install_test_pending_epoch(state: &mut OwnerState, k_bit: bool, key: u8) -> bool {
    let authority = crate::noise::SendCounterAuthority::for_test();
    match state.owner.protocol() {
        PacketProtocol::Fmp => {
            state.install_fmp_pending_receive_epoch(k_bit, test_key(key), authority)
        }
        PacketProtocol::Fsp => {
            state.install_fsp_pending_epoch(k_bit, test_key(key), test_key(key), authority)
        }
    }
}

fn pending_instance_packet(
    owner: OwnerId,
    generation: u64,
    key: u8,
    k_bit: bool,
    counter: u64,
) -> SocketPacket {
    match owner.protocol() {
        PacketProtocol::Fmp => fmp_socket_packet(
            owner,
            generation,
            OutputTarget::Transport,
            fmp_encrypted_wire(
                110,
                counter,
                if k_bit {
                    crate::node::wire::FLAG_KEY_EPOCH
                } else {
                    0
                },
                b"pending-instance",
                key,
            ),
        )
        .unwrap(),
        PacketProtocol::Fsp => fsp_socket_packet(
            owner,
            generation,
            OutputTarget::Transport,
            fsp_encrypted_wire(
                counter,
                if k_bit {
                    crate::node::session_wire::FSP_FLAG_K
                } else {
                    0
                },
                b"pending-instance",
                key,
            ),
        )
        .unwrap(),
    }
}
