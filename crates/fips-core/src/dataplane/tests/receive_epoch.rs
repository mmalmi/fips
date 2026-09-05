#[test]
fn fmp_receive_epoch_owns_replay_reservations_when_flags_match() {
    let owner = fmp_owner(98);
    let mut mover = mover();
    let pending_authority = crate::noise::SendCounterAuthority::for_test();
    mover.register_owner(owner, OwnerConfig::new(1, 8).with_fmp_epoch(false, None));
    mover
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(98), test_key(98)));
    assert!(
        mover
            .owner_mut(owner)
            .unwrap()
            .install_fmp_pending_receive_epoch(true, test_key(99), pending_authority.clone())
    );
    assert!(
        !mover
            .owner_mut(owner)
            .unwrap()
            .confirm_fmp_pending_receive_epoch(false)
    );
    mover
        .submit_socket_packet(
            fmp_socket_packet(
                owner,
                1,
                OutputTarget::Transport,
                fmp_encrypted_wire(98, 0, 0, b"wrong-key", 100),
            )
            .unwrap()
            .with_receive_epoch(DataplaneReceiveEpoch::Pending),
        )
        .unwrap();
    assert_eq!(run_aead_available(&mut mover, 8).drops().len(), 1);
    assert!(
        !mover
            .owner_mut(owner)
            .unwrap()
            .confirm_fmp_pending_receive_epoch(false)
    );

    for counter in [1, 2] {
        for (epoch, key) in [
            (DataplaneReceiveEpoch::Current, 98),
            (DataplaneReceiveEpoch::Pending, 99),
        ] {
            mover
                .submit_socket_packet(
                    fmp_socket_packet(
                        owner,
                        1,
                        OutputTarget::Transport,
                        fmp_encrypted_wire(98, counter, 0, b"epoch-owned", key),
                    )
                    .unwrap()
                    .with_receive_epoch(epoch),
                )
                .unwrap();
            // Check completion after the current counter has retired as well
            // as simultaneous reservations with the same counter and K-bit.
            if counter == 1 {
                let turn = run_aead_available(&mut mover, 8);
                assert!(turn.drops().is_empty(), "{:?}", turn.drops());
                assert_eq!(turn.outputs().len(), 1);
            }
        }
        if counter == 2 {
            let turn = run_aead_available(&mut mover, 8);
            assert!(turn.drops().is_empty(), "{:?}", turn.drops());
            assert_eq!(turn.outputs().len(), 2);
        }
    }

    assert!(
        !mover
            .owner_mut(owner)
            .unwrap()
            .confirm_fmp_pending_receive_epoch(true)
    );
    assert!(
        mover
            .owner_mut(owner)
            .unwrap()
            .confirm_fmp_pending_receive_epoch(false)
    );
    assert!(
        mover.owner_mut(owner).unwrap().install_fmp_session(
            OwnerConfig::new(2, 8)
                .with_fmp_epoch(false, Some(false))
                .with_send_counter_authority(pending_authority),
            OwnerCryptoKeys::new(test_key(99), test_key(99)),
        )
    );
    // Both replay windows survive a promotion that retains the same flag.
    for (epoch, key) in [
        (DataplaneReceiveEpoch::Previous, 98),
        (DataplaneReceiveEpoch::Current, 99),
    ] {
        mover
            .submit_socket_packet(
                fmp_socket_packet(
                    owner,
                    2,
                    OutputTarget::Transport,
                    fmp_encrypted_wire(98, 1, 0, b"already-received", key),
                )
                .unwrap()
                .with_receive_epoch(epoch),
            )
            .unwrap();
    }
    let turn = run_aead_available(&mut mover, 8);
    assert_eq!(turn.drops().len(), 2);
    assert!(
        turn.drops()
            .iter()
            .all(|drop| drop.reason == PacketDropReason::Replay)
    );

    assert!(
        mover
            .owner_mut(owner)
            .unwrap()
            .install_fmp_pending_receive_epoch(
                true,
                test_key(100),
                crate::noise::SendCounterAuthority::for_test()
            )
    );
    for (epoch, key) in [
        (DataplaneReceiveEpoch::Previous, 98),
        (DataplaneReceiveEpoch::Current, 99),
        (DataplaneReceiveEpoch::Pending, 100),
    ] {
        mover
            .submit_socket_packet(
                fmp_socket_packet(
                    owner,
                    2,
                    OutputTarget::Transport,
                    fmp_encrypted_wire(98, 3, 0, b"three-epochs", key),
                )
                .unwrap()
                .with_receive_epoch(epoch),
            )
            .unwrap();
    }
    let turn = run_aead_available(&mut mover, 8);
    assert!(turn.drops().is_empty(), "{:?}", turn.drops());
    assert_eq!(turn.outputs().len(), 3);
}

#[test]
fn fmp_receiver_index_wins_over_epoch_flag() {
    let owner = fmp_owner(101);
    let mut mover = mover();
    mover.register_owner(owner, OwnerConfig::new(1, 8).with_fmp_epoch(false, None));
    mover
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(101), test_key(101)));
    assert!(mover.owner_mut(owner).unwrap().install_fmp_session(
        OwnerConfig::new(2, 8).with_fmp_epoch(true, Some(false)),
        OwnerCryptoKeys::new(test_key(102), test_key(102)),
    ));
    assert!(
        mover
            .owner_mut(owner)
            .unwrap()
            .install_fmp_pending_receive_epoch(
                false,
                test_key(103),
                crate::noise::SendCounterAuthority::for_test()
            )
    );
    for (counter, flags) in [(1, 0), (2, crate::node::wire::FLAG_KEY_EPOCH)] {
        for (epoch, key) in [
            (DataplaneReceiveEpoch::Previous, 101),
            (DataplaneReceiveEpoch::Current, 102),
            (DataplaneReceiveEpoch::Pending, 103),
        ] {
            mover
                .submit_socket_packet(
                    fmp_socket_packet(
                        owner,
                        2,
                        OutputTarget::Transport,
                        fmp_encrypted_wire(101, counter, flags, b"retained-epoch", key),
                    )
                    .unwrap()
                    .with_receive_epoch(epoch),
                )
                .unwrap();
        }
        let turn = run_aead_available(&mut mover, 8);
        assert!(turn.drops().is_empty(), "{:?}", turn.drops());
        assert_eq!(turn.outputs().len(), 3);
    }
}
