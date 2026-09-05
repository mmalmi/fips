#[test]
fn owner_tracks_inbound_path_drift_and_uses_latest_path_for_outbound_transport() {
    let owner = fmp_owner(73);
    let open_key = 21;
    let seal_key = 22;
    let path_a = live_path(100);
    let path_b = live_path(200);
    let mut mover = mover();
    mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(500));
    mover
        .owner_mut(owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));

    let inbound_a = fmp_socket_packet(
        owner,
        1,
        OutputTarget::Transport,
        fmp_encrypted_wire(73, 1000, 0, b"in-a", open_key),
    )
    .unwrap()
    .with_source_path(path_a.clone());
    mover.submit_socket_packet(inbound_a).unwrap();
    let turn = run_aead_available(&mut mover, 8);
    assert!(turn.drops().is_empty());
    assert_eq!(turn.outputs()[0].path.clone(), None);
    assert_eq!(
        mover.owner_mut(owner).unwrap().active_path(),
        Some(path_a.clone())
    );

    let forged = fmp_socket_packet(
        owner,
        1,
        OutputTarget::Transport,
        fmp_encrypted_wire(73, 1001, 0, b"forged", open_key + 1),
    )
    .unwrap()
    .with_source_path(path_b.clone());
    mover.submit_socket_packet(forged).unwrap();
    let turn = run_aead_available(&mut mover, 8);
    assert!(turn.outputs().is_empty());
    assert_eq!(turn.drops()[0].reason, PacketDropReason::CryptoFailed);

    mover
        .submit_outbound_packet(OutboundPacket::fmp(
            owner,
            1,
            PacketClass::Bulk,
            730,
            0,
            PacketBuffer::new(b"out-a".to_vec()),
        ))
        .unwrap();
    let turn = run_aead_available(&mut mover, 8);
    let output = turn.outputs()[0];
    assert_eq!(output.counter, 500);
    assert_eq!(output.target, OutputTarget::Transport);
    assert_eq!(output.path.clone(), Some(path_a));
    assert_eq!(open_sealed_output(output, seal_key), b"out-a");

    let inbound_b = fmp_socket_packet(
        owner,
        1,
        OutputTarget::Transport,
        fmp_encrypted_wire(73, 1001, 0, b"in-b", open_key),
    )
    .unwrap()
    .with_source_path(path_b.clone());
    mover.submit_socket_packet(inbound_b).unwrap();
    let turn = run_aead_available(&mut mover, 8);
    assert!(turn.drops().is_empty());
    assert_eq!(turn.outputs()[0].path.clone(), None);
    assert_eq!(
        mover.owner_mut(owner).unwrap().active_path(),
        Some(path_b.clone())
    );

    mover
        .submit_outbound_packet(OutboundPacket::fmp(
            owner,
            1,
            PacketClass::Bulk,
            730,
            0,
            PacketBuffer::new(b"out-b".to_vec()),
        ))
        .unwrap();
    let turn = run_aead_available(&mut mover, 8);
    let output = turn.outputs()[0];
    assert_eq!(output.counter, 501);
    assert_eq!(output.path.clone(), Some(path_b));
    assert_eq!(open_sealed_output(output, seal_key), b"out-b");
}

#[test]
fn authenticated_fsp_ingress_only_moves_direct_output_to_the_session_peer() {
    let owner = fsp_owner(731);
    let relay = test_node_addr(732);
    let direct_flag = crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT;
    let direct_path = live_path(100);
    let relay_path = live_path(200);
    let moved_direct_path = live_path(300);
    let open_key = 21;
    let seal_key = 22;

    for target in [
        OutputTarget::Transport,
        OutputTarget::SessionPayload {
            local_addr: test_node_addr(733),
        },
    ] {
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        let state = mover.owner_mut(owner).unwrap();
        state.set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));
        state.set_active_path(direct_path.clone());

        let inbound_body = crate::node::session_wire::fsp_prepend_inner_header(
            0,
            crate::protocol::SessionMessageType::CoordsWarmup.to_byte(),
            0,
            &[],
        );
        for (counter, flags, previous_hop, source_path, key, expected_path) in [
            (0, 0, relay, &relay_path, open_key, &direct_path),
            (1, direct_flag, relay, &relay_path, open_key, &direct_path),
            (
                2,
                direct_flag,
                owner.node_addr(),
                &moved_direct_path,
                open_key + 1,
                &direct_path,
            ),
            (
                3,
                direct_flag,
                owner.node_addr(),
                &moved_direct_path,
                open_key,
                &moved_direct_path,
            ),
        ] {
            let inbound = fsp_socket_packet(
                owner,
                1,
                target,
                fsp_encrypted_wire(counter, flags, &inbound_body, key),
            )
            .unwrap()
            .with_source_path(source_path.clone())
            .with_previous_hop(previous_hop);
            mover.submit_socket_packet(inbound).unwrap();
            let turn = run_aead_available(&mut mover, 8);
            assert_eq!(turn.outputs().len(), usize::from(key == open_key));
            assert_eq!(turn.drops().len(), usize::from(key != open_key));

            mover
                .submit_outbound_packet(OutboundPacket::fsp(
                    owner,
                    1,
                    PacketClass::Bulk,
                    0,
                    PacketBuffer::new(b"reply".to_vec()),
                ))
                .unwrap();
            let turn = run_aead_available(&mut mover, 8);
            assert!(turn.drops().is_empty());
            let output = turn.outputs()[0];
            assert_eq!(output.target(), OutputTarget::Transport);
            assert_eq!(
                output.path.clone(),
                Some(expected_path.clone()),
                "ingress counter {counter}"
            );
            assert_eq!(open_sealed_output(output, seal_key), b"reply");
            assert_ne!(
                FspWireHeader::parse(output.payload()).unwrap().flags() & direct_flag,
                0
            );
        }
    }
}
