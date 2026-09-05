#[test]
fn fsp_owner_authenticates_pending_receive_epoch_before_cutover() {
    let owner = fsp_owner(86);
    let old_key = 86;
    let new_key = 87;
    let mut mover = mover();
    let pending_authority = crate::noise::SendCounterAuthority::for_test();
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
    assert!(mover.owner_mut(owner).unwrap().install_fsp_pending_epoch(
        true,
        test_key(new_key),
        test_key(new_key),
        pending_authority.clone()
    ));
    assert!(
        mover
            .owner_mut(owner)
            .unwrap()
            .has_fsp_pending_receive_epoch(true)
    );
    assert!(
        mover
            .owner_mut(owner)
            .unwrap()
            .clear_fsp_pending_receive_epoch()
    );
    assert!(
        !mover
            .owner_mut(owner)
            .unwrap()
            .has_fsp_pending_receive_epoch(true)
    );
    assert!(mover.owner_mut(owner).unwrap().install_fsp_pending_epoch(
        true,
        test_key(new_key),
        test_key(new_key),
        pending_authority.clone()
    ));

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
                .with_send_counter_authority(pending_authority)
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
    let pending_authority = crate::noise::SendCounterAuthority::for_test();
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
            .install_fmp_pending_receive_epoch(true, test_key(new_key), pending_authority.clone())
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
            .unwrap()
            .with_receive_epoch(DataplaneReceiveEpoch::Pending),
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
                .with_send_counter_authority(pending_authority)
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
