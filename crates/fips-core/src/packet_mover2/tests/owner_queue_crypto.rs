    #[test]
    fn happy_path_dispatches_fmp_and_fsp_packets() {
        let fmp = fmp_owner(7);
        let fsp = fsp_owner(7);
        let key = 7;
        let mut mover = mover();
        mover.register_owner(fmp, OwnerConfig::new(1, 8));
        mover.register_owner(fsp, OwnerConfig::new(1, 8));

        mover
            .submit_socket_packet(encrypted_fsp_packet(
                fsp,
                1,
                10,
                PacketClass::Bulk,
                OutputTarget::Tun,
                key,
            ))
            .unwrap();
        mover
            .submit_socket_packet(encrypted_fmp_packet(
                fmp,
                1,
                20,
                PacketClass::Control,
                OutputTarget::Transport,
                key,
            ))
            .unwrap();

        let work = dispatch_available(&mut mover, 8);
        assert_eq!(work.len(), 2);
        assert_eq!(work[0].packet.owner, fmp);
        assert_eq!(work[1].packet.owner, fsp);

        let mut retired = Vec::new();
        for item in work {
            retired.extend(retire_open_aead(&mut mover, item, key));
        }
        let outputs = outputs(retired);
        assert_eq!(outputs[0].target, OutputTarget::Transport);
        assert_eq!(outputs[1].target, OutputTarget::Tun);
        assert_eq!(&outputs[0].payload[FMP_ESTABLISHED_HEADER_SIZE..], &[20]);
        assert_eq!(&outputs[1].payload[FSP_HEADER_SIZE..], &[10]);
    }

    #[test]
    fn wire_preflight_parses_fmp_and_fsp_established_headers() {
        let fmp = FmpWireHeader::parse(&fmp_wire(77, 900, 0x03)).unwrap();
        assert_eq!(fmp.receiver_idx(), 77);
        assert_eq!(fmp.counter(), 900);
        assert_eq!(fmp.flags(), 0x03);
        assert_eq!(fmp.ciphertext_offset(), FMP_ESTABLISHED_HEADER_SIZE);

        let fsp = FspWireHeader::parse(&fsp_wire(901, 0x02)).unwrap();
        assert_eq!(fsp.counter(), 901);
        assert_eq!(fsp.flags(), 0x02);
        assert_eq!(fsp.ciphertext_offset(), FSP_HEADER_SIZE);

        let cp_fsp = FspWireHeader::parse(&fsp_wire(
            901,
            crate::node::session_wire::FSP_FLAG_CP,
        ))
        .unwrap();
        assert_eq!(
            cp_fsp.ciphertext_offset(),
            FSP_HEADER_SIZE + 2 * std::mem::size_of::<u16>()
        );

        let owner = fmp_owner(77);
        let packet = SocketPacket::from_fmp_established_wire(
            owner,
            5,
            OutputTarget::Transport,
            fmp_wire(77, 902, 0),
        )
        .unwrap();
        assert_eq!(packet.owner, owner);
        assert_eq!(packet.generation, 5);
        assert_eq!(packet.counter, 902);
        assert_eq!(packet.class, PacketClass::Bulk);

        let mut wrong_phase = fmp_wire(77, 903, 0);
        wrong_phase[0] = (FMP_VERSION << 4) | crate::node::wire::PHASE_MSG1;
        assert_eq!(
            FmpWireHeader::parse(&wrong_phase).unwrap_err(),
            WirePreflightError::WrongPhase
        );

        let plaintext_fsp = fsp_wire(904, FSP_FLAG_U);
        assert_eq!(
            FspWireHeader::parse(&plaintext_fsp).unwrap_err(),
            WirePreflightError::PlaintextFsp
        );

        let mut missing_coords = fsp_wire(905, crate::node::session_wire::FSP_FLAG_CP);
        missing_coords.truncate(FSP_HEADER_SIZE);
        assert_eq!(
            FspWireHeader::parse(&missing_coords).unwrap_err(),
            WirePreflightError::BadFspCoords
        );
    }

    #[test]
    fn session_handoff_routes_opened_fmp_datagram_to_sourced_fsp_ingress() {
        let local_addr = NodeAddr::from_bytes([0x41; 16]);
        let source_addr = NodeAddr::from_bytes([0x42; 16]);
        let next_hop = NodeAddr::from_bytes([0x43; 16]);
        let transport_id = TransportId::new(4100);
        let remote_addr = TransportAddr::from_string("198.51.100.41:4100");
        let source_path = TransportPath::live(transport_id, remote_addr.clone());
        let activity_tick = ActivityTick::new(41_000);
        let fsp_wire = fsp_wire(410, 0x03);
        let datagram =
            crate::protocol::SessionDatagram::new(source_addr, local_addr, fsp_wire.clone())
                .with_ttl(42)
                .with_path_mtu(1280)
                .encode();
        let mut payload = fmp_wire(4100, 41, 0);
        payload.truncate(FMP_ESTABLISHED_HEADER_SIZE);
        payload.extend_from_slice(&41_000_u32.to_le_bytes());
        payload.extend_from_slice(&datagram);
        let output = PacketOutput {
            owner: OwnerId::fmp_node(next_hop),
            counter: 41,
            ingress_seq: 410,
            lane: Lane::Bulk,
            target: OutputTarget::SessionIngress { local_addr },
            source_path: Some(source_path.clone()),
            previous_hop: None,
            ce_flag: false,
            path_mtu: u16::MAX,
            path: None,
            activity_tick: Some(activity_tick),
            source_wire_len: Some(payload.len()),
            fmp_timestamp_ms: None,
            fsp_send_receipt: None,
            payload: payload.into(),
        };

        let handoff = packet_mover2_session_ingress_from_output(output, local_addr)
            .expect("session datagram should route to sourced FSP ingress");
        let PacketMover2SessionIngressHandoff::Raw { raw, coord_warmup } = handoff else {
            panic!("established encrypted FSP should use raw fast path");
        };

        assert!(coord_warmup.is_empty());
        assert_eq!(raw.protocol, PacketProtocol::Fsp);
        assert_eq!(raw.transport_id, transport_id);
        assert_eq!(raw.remote_addr, remote_addr);
        assert_eq!(raw.path, source_path);
        assert_eq!(raw.fsp_source, Some(source_addr));
        assert_eq!(raw.path_mtu, 1280);
        assert_eq!(raw.activity_tick, Some(activity_tick));
        assert_eq!(raw.payload.as_ref(), fsp_wire.as_slice());
    }

    #[test]
    fn session_handoff_routes_fsp_handshake_datagram_to_local_session_ingress() {
        let local_addr = NodeAddr::from_bytes([0x51; 16]);
        let source_addr = NodeAddr::from_bytes([0x52; 16]);
        let next_hop = NodeAddr::from_bytes([0x53; 16]);
        let transport_id = TransportId::new(5100);
        let remote_addr = TransportAddr::from_string("198.51.100.51:5100");
        let source_path = TransportPath::live(transport_id, remote_addr);
        let path_mtu = 1330;
        let mut fsp_handshake =
            crate::node::session_wire::build_fsp_handshake_prefix(
                crate::node::session_wire::FSP_PHASE_MSG1,
                4,
            )
            .to_vec();
        fsp_handshake.extend_from_slice(b"msg1");
        let datagram =
            crate::protocol::SessionDatagram::new(source_addr, local_addr, fsp_handshake.clone())
                .with_ttl(42)
                .with_path_mtu(path_mtu)
                .encode();
        let mut payload = fmp_wire(5100, 51, crate::node::wire::FLAG_CE);
        payload.truncate(FMP_ESTABLISHED_HEADER_SIZE);
        payload.extend_from_slice(&51_000_u32.to_le_bytes());
        payload.extend_from_slice(&datagram);
        let output = PacketOutput {
            owner: OwnerId::fmp_node(next_hop),
            counter: 51,
            ingress_seq: 510,
            lane: Lane::Bulk,
            target: OutputTarget::SessionIngress { local_addr },
            source_path: Some(source_path),
            previous_hop: None,
            ce_flag: false,
            path_mtu: u16::MAX,
            path: None,
            activity_tick: None,
            source_wire_len: Some(payload.len()),
            fmp_timestamp_ms: None,
            fsp_send_receipt: None,
            payload: payload.into(),
        };

        let handoff = packet_mover2_session_ingress_from_output(output, local_addr)
            .expect("session datagram should route to local session ingress");
        let PacketMover2SessionIngressHandoff::Local(local) = handoff else {
            panic!("FSP handshake should stay on local session path");
        };

        assert_eq!(local.source_addr(), source_addr);
        assert_eq!(local.previous_hop_addr(), next_hop);
        assert!(local.ce_flag());
        assert_eq!(local.path_mtu(), path_mtu);
        assert_eq!(local.payload(), fsp_handshake.as_slice());
    }

    #[test]
    fn priority_admission_keeps_reserved_progress_when_bulk_is_full() {
        let owner = fsp_owner(1);
        let mut mover = PacketMover2::new(AdmissionConfig::new(2, 1));
        mover.register_owner(owner, OwnerConfig::new(1, 8));

        mover
            .submit_socket_packet(packet(owner, 1, 1, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap();
        let bulk_drop = mover
            .submit_socket_packet(packet(owner, 1, 2, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap_err();
        mover
            .submit_socket_packet(packet(
                owner,
                1,
                3,
                PacketClass::Liveness,
                OutputTarget::Endpoint,
            ))
            .unwrap();

        assert_eq!(bulk_drop.owner(), owner);
        assert_eq!(bulk_drop.counter(), 2);
        assert_eq!(bulk_drop.class(), PacketClass::Bulk);
        assert_eq!(bulk_drop.lane(), Lane::Bulk);
        assert_eq!(bulk_drop.payload_len(), 1);
        assert_eq!(bulk_drop.reason(), AdmissionDropReason::BulkFull);
        assert_eq!(queue_lens(&mover), (1, 1));
        let work = dispatch_available(&mut mover, 1);
        assert_eq!(work[0].packet.counter, 3);

        let drops = mover.drain_drops();
        assert_eq!(
            drops[0].reason(),
            PacketDropReason::Admission(AdmissionDropReason::BulkFull)
        );
        assert_eq!(drops[0].owner(), owner);
        assert_eq!(drops[0].counter(), Some(2));
        assert_eq!(drops[0].ingress_seq(), None);
        assert_eq!(drops[0].lane(), Lane::Bulk);
    }

    #[test]
    fn blocked_owner_ingress_does_not_stop_runnable_owner() {
        let blocked = fsp_owner(21);
        let runnable = fsp_owner(22);
        let mut mover = PacketMover2::new(AdmissionConfig::new(2, 8));
        mover.register_owner(blocked, OwnerConfig::new(1, 1));
        mover.register_owner(runnable, OwnerConfig::new(1, 1));

        mover
            .submit_socket_packet(packet(blocked, 1, 1, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap();
        let first = dispatch_available(&mut mover, 8);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].packet.owner, blocked);

        mover
            .submit_socket_packet(packet(blocked, 1, 2, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap();
        mover
            .submit_socket_packet(packet(blocked, 1, 3, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap();
        mover
            .submit_socket_packet(packet(runnable, 1, 1, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap();

        let work = dispatch_available(&mut mover, 8);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].packet.owner, runnable);
        assert_eq!(work[0].packet.counter, 1);
        assert_eq!(queue_lens(&mover), (0, 2));

        let first_reservation = first[0].reservation.clone();
        mover.retire_completion(CryptoCompletion {
            reservation: first_reservation,
            result: CryptoResult::Failed(CryptoFailureKind::Open),
        });
        let work = dispatch_available(&mut mover, 1);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].packet.owner, blocked);
        assert_eq!(work[0].packet.counter, 2);
    }

    #[test]
    fn ingress_dispatch_feeds_contiguous_owner_run() {
        let first_owner = fsp_owner(23);
        let second_owner = fsp_owner(24);
        let mut mover = PacketMover2::new(AdmissionConfig::new(2, 8));
        mover.register_owner(first_owner, OwnerConfig::new(1, 8));
        mover.register_owner(second_owner, OwnerConfig::new(1, 8));

        mover
            .submit_socket_packet(packet(first_owner, 1, 1, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap();
        mover
            .submit_socket_packet(packet(second_owner, 1, 1, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap();
        mover
            .submit_socket_packet(packet(first_owner, 1, 2, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap();

        let work = dispatch_available(&mut mover, 8);
        assert_eq!(
            work.iter()
                .map(|work| (work.packet.owner, work.packet.counter))
                .collect::<Vec<_>>(),
            vec![(first_owner, 1), (first_owner, 2), (second_owner, 1)]
        );
    }

    #[test]
    fn turn_runner_batches_admission_and_reuses_work_buffer() {
        let owner = fsp_owner(11);
        let key = 11;
        let mut mover = PacketMover2::new(AdmissionConfig::new(2, 4));
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));
        for packet in [
            encrypted_fsp_packet(owner, 1, 1, PacketClass::Bulk, OutputTarget::Tun, key),
            encrypted_fsp_packet(
                owner,
                1,
                2,
                PacketClass::Liveness,
                OutputTarget::Endpoint,
                key,
            ),
            encrypted_fsp_packet(owner, 1, 3, PacketClass::Bulk, OutputTarget::Transport, key),
        ] {
            assert!(mover.submit_socket_packet(packet).is_ok());
        }

        let mut open_work = Vec::with_capacity(8);
        let mut seal_work = Vec::with_capacity(8);
        let turn = run_aead_available_with_work_buffers(&mut mover, 2, &mut open_work, &mut seal_work);
        assert!(open_work.is_empty());
        assert!(seal_work.is_empty());
        assert_eq!(turn.dispatched(), 2);
        assert!(turn.drops().is_empty());
        assert_eq!(
            turn.outputs()
                .iter()
                .map(|output| output.counter)
                .collect::<Vec<_>>(),
            vec![2, 1]
        );
        assert_eq!(
            turn.retired()
                .iter()
                .filter(|item| matches!(item, RetiredPacket::Output(_)))
                .count(),
            2
        );

        let turn = run_aead_available_with_work_buffers(&mut mover, 2, &mut open_work, &mut seal_work);
        assert_eq!(turn.dispatched(), 1);
        assert_eq!(turn.outputs()[0].counter, 3);
        assert_eq!(open_work.capacity(), 8);
        assert_eq!(seal_work.capacity(), 8);
    }

    #[test]
    fn owner_retires_worker_completions_in_owner_order() {
        let owner = fsp_owner(9);
        let key = 9;
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        for counter in 1..=3 {
            mover
                .submit_socket_packet(encrypted_fsp_packet(
                    owner,
                    1,
                    counter,
                    PacketClass::Bulk,
                    OutputTarget::Tun,
                    key,
                ))
                .unwrap();
        }

        let work = dispatch_available(&mut mover, 8);
        assert_eq!(
            work.iter().map(crypto_work_order).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );

        let completion_2 = open_aead_completion(work[2].clone(), key);
        assert!(mover.retire_completion(completion_2).is_empty());

        let completion_0 = open_aead_completion(work[0].clone(), key);
        let retired = outputs(mover.retire_completion(completion_0));
        assert_eq!(
            retired
                .iter()
                .map(|output| output.counter)
                .collect::<Vec<_>>(),
            vec![1]
        );

        let completion_1 = open_aead_completion(work[1].clone(), key);
        let retired = outputs(mover.retire_completion(completion_1));
        assert_eq!(
            retired
                .iter()
                .map(|output| output.counter)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
    }

    #[test]
    fn owner_defers_in_flight_overflow_and_still_rejects_replay() {
        let owner = fsp_owner(3);
        let key = 3;
        let mut mover = PacketMover2::new(AdmissionConfig::new(4, 4));
        mover.register_owner(owner, OwnerConfig::new(1, 1));

        mover
            .submit_socket_packet(encrypted_fsp_packet(
                owner,
                1,
                8,
                PacketClass::Bulk,
                OutputTarget::Tun,
                key,
            ))
            .unwrap();
        mover
            .submit_socket_packet(encrypted_fsp_packet(
                owner,
                1,
                9,
                PacketClass::Bulk,
                OutputTarget::Tun,
                key,
            ))
            .unwrap();
        mover
            .submit_socket_packet(encrypted_fsp_packet(
                owner,
                1,
                8,
                PacketClass::Bulk,
                OutputTarget::Tun,
                key,
            ))
            .unwrap();

        let work = dispatch_available(&mut mover, 8);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].packet.counter, 8);
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 1);

        let drops = mover.drain_drops();
        assert!(drops.is_empty());

        assert_eq!(
            outputs(retire_open_aead(&mut mover, work[0].clone(), key)).len(),
            1
        );
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 0);

        let work = dispatch_available(&mut mover, 8);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].packet.counter, 9);
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 1);

        let drops = mover.drain_drops();
        assert!(drops.is_empty());

        assert_eq!(
            outputs(retire_open_aead(&mut mover, work[0].clone(), key)).len(),
            1
        );
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 0);

        let work = dispatch_available(&mut mover, 8);
        assert!(work.is_empty());

        let drops = mover.drain_drops();
        assert_eq!(drops.len(), 1);
        assert_eq!(drops[0].owner(), owner);
        assert_eq!(drops[0].reason(), PacketDropReason::Replay);
        assert_eq!(drops[0].counter(), Some(8));
        assert_eq!(drops[0].ingress_seq(), Some(2));
        assert_eq!(drops[0].lane(), Lane::Bulk);
    }

    #[test]
    fn owner_bulk_in_flight_cap_preserves_priority_reservations() {
        let owner = fsp_owner(33);
        let mut inbound =
            OwnerState::new(owner, OwnerConfig::new(1, 4).with_bulk_in_flight_limit(2));

        inbound
            .reserve(
                &packet(owner, 1, 10, PacketClass::Bulk, OutputTarget::Tun),
                0,
            )
            .unwrap();
        inbound
            .reserve(
                &packet(owner, 1, 11, PacketClass::Bulk, OutputTarget::Tun),
                1,
            )
            .unwrap();
        assert_eq!(
            inbound.reserve(
                &packet(owner, 1, 12, PacketClass::Bulk, OutputTarget::Tun),
                2,
            ),
            Err(OwnerReserveError::InFlightFull)
        );

        let liveness = inbound
            .reserve(
                &packet(owner, 1, 13, PacketClass::Liveness, OutputTarget::Tun),
                3,
            )
            .unwrap();
        assert_eq!(liveness.lane, Lane::Priority);
        assert_eq!(liveness.counter, 13);
        assert_eq!(inbound.in_flight, 3);

        let mut outbound =
            OwnerState::new(owner, OwnerConfig::new(1, 4).with_bulk_in_flight_limit(2));
        outbound
            .reserve_outbound(
                outbound_packet(owner, 1, PacketClass::Bulk, b"bulk-1"),
                0,
            )
            .unwrap();
        outbound
            .reserve_outbound(
                outbound_packet(owner, 1, PacketClass::Bulk, b"bulk-2"),
                1,
            )
            .unwrap();
        assert!(matches!(
            outbound.reserve_outbound(
                outbound_packet(owner, 1, PacketClass::Bulk, b"bulk-3"),
                2,
            ),
            Err(OwnerReserveError::InFlightFull)
        ));

        let (mmp, _) = outbound
            .reserve_outbound(outbound_packet(owner, 1, PacketClass::Mmp, b"mmp"), 3)
            .unwrap();
        assert_eq!(mmp.lane, Lane::Priority);
        assert_eq!(mmp.counter, 2);
        assert_eq!(outbound.in_flight, 3);
    }

    #[test]
    fn owner_reliable_bulk_window_feeds_deeper_without_widening_discardable_bulk() {
        let owner = fsp_owner(34);
        let mut state = OwnerState::new(
            owner,
            OwnerConfig::new(1, 8)
                .with_bulk_in_flight_limit(2)
                .with_reliable_bulk_in_flight_limit(4),
        );

        for counter in 10..12 {
            state
                .reserve(
                    &packet(owner, 1, counter, PacketClass::Bulk, OutputTarget::Tun),
                    counter,
                )
                .unwrap();
        }
        assert_eq!(
            state.reserve(
                &packet(owner, 1, 12, PacketClass::Bulk, OutputTarget::Tun),
                12,
            ),
            Err(OwnerReserveError::InFlightFull)
        );

        for counter in 20..24 {
            state
                .reserve(
                    &packet(
                        owner,
                        1,
                        counter,
                        PacketClass::ReliableBulk,
                        OutputTarget::Tun,
                    ),
                    counter,
                )
                .unwrap();
        }
        assert_eq!(
            state.reserve(
                &packet(
                    owner,
                    1,
                    24,
                    PacketClass::ReliableBulk,
                    OutputTarget::Tun,
                ),
                24,
            ),
            Err(OwnerReserveError::InFlightFull)
        );

        let liveness = state
            .reserve(
                &packet(owner, 1, 30, PacketClass::Liveness, OutputTarget::Tun),
                30,
            )
            .unwrap();
        assert_eq!(liveness.lane, Lane::Priority);
        assert_eq!(state.in_flight, 7);
    }

    #[test]
    fn owner_total_bulk_window_keeps_priority_reserve_across_bulk_classes() {
        let owner = fsp_owner(35);
        let mut state = OwnerState::new(
            owner,
            OwnerConfig::new(1, 4)
                .with_bulk_in_flight_limit(3)
                .with_reliable_bulk_in_flight_limit(3),
        );

        for counter in 10..13 {
            state
                .reserve(
                    &packet(
                        owner,
                        1,
                        counter,
                        PacketClass::ReliableBulk,
                        OutputTarget::Tun,
                    ),
                    counter,
                )
                .unwrap();
        }
        assert_eq!(
            state.reserve(
                &packet(
                    owner,
                    1,
                    13,
                    PacketClass::ReliableBulk,
                    OutputTarget::Tun,
                ),
                13,
            ),
            Err(OwnerReserveError::InFlightFull)
        );

        let control = state
            .reserve(
                &packet(owner, 1, 20, PacketClass::Control, OutputTarget::Tun),
                20,
            )
            .unwrap();
        assert_eq!(control.lane, Lane::Priority);
        assert_eq!(state.in_flight, 4);
    }

    #[test]
    fn outbound_dispatch_preserves_priority_when_bulk_in_flight_cap_is_full() {
        let owner = fsp_owner(36);
        let mut mover = PacketMover2::new(AdmissionConfig::new(8, 8));
        mover.register_owner(
            owner,
            OwnerConfig::new(1, 4)
                .with_next_send_counter(10)
                .with_bulk_in_flight_limit(2),
        );

        mover
            .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Bulk, b"bulk-1"))
            .unwrap();
        mover
            .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Bulk, b"bulk-2"))
            .unwrap();
        let work = dispatch_outbound_available(&mut mover, 8);
        assert_eq!(work.len(), 2);
        assert_eq!(work[0].reservation.counter, 10);
        assert_eq!(work[1].reservation.counter, 11);
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 2);

        mover
            .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Bulk, b"bulk-3"))
            .unwrap();
        mover
            .submit_outbound_packet(outbound_packet(
                owner,
                1,
                PacketClass::Liveness,
                b"priority",
            ))
            .unwrap();

        let work = dispatch_outbound_available(&mut mover, 8);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].packet.class, PacketClass::Liveness);
        assert_eq!(work[0].reservation.counter, 12);
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 3);
        assert_eq!(outbound_queue_lens(&mover), (0, 1));
        assert!(mover.drain_drops().is_empty());
    }

    #[test]
    fn blocked_owner_outbound_does_not_stop_runnable_owner() {
        let blocked = fsp_owner(37);
        let runnable = fsp_owner(38);
        let mut mover = PacketMover2::new(AdmissionConfig::new(2, 8));
        mover.register_owner(blocked, OwnerConfig::new(1, 1).with_next_send_counter(370));
        mover.register_owner(runnable, OwnerConfig::new(1, 1).with_next_send_counter(380));

        mover
            .submit_outbound_packet(outbound_packet(blocked, 1, PacketClass::Bulk, b"blocked-1"))
            .unwrap();
        let first = dispatch_outbound_available(&mut mover, 8);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].reservation.owner, blocked);

        mover
            .submit_outbound_packet(outbound_packet(blocked, 1, PacketClass::Bulk, b"blocked-2"))
            .unwrap();
        mover
            .submit_outbound_packet(outbound_packet(blocked, 1, PacketClass::Bulk, b"blocked-3"))
            .unwrap();
        mover
            .submit_outbound_packet(outbound_packet(runnable, 1, PacketClass::Bulk, b"runnable"))
            .unwrap();

        let work = dispatch_outbound_available(&mut mover, 8);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].reservation.owner, runnable);
        assert_eq!(work[0].reservation.counter, 380);
        assert_eq!(outbound_queue_lens(&mover), (0, 2));

        let first_reservation = first[0].reservation.clone();
        mover.retire_completion(CryptoCompletion {
            reservation: first_reservation,
            result: CryptoResult::Failed(CryptoFailureKind::Seal),
        });
        let work = dispatch_outbound_available(&mut mover, 1);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].reservation.owner, blocked);
        assert_eq!(work[0].packet.payload.as_ref(), b"blocked-2");
    }

    #[test]
    fn outbound_dispatch_feeds_contiguous_owner_run() {
        let first_owner = fsp_owner(39);
        let second_owner = fsp_owner(40);
        let mut mover = PacketMover2::new(AdmissionConfig::new(2, 8));
        mover.register_owner(first_owner, OwnerConfig::new(1, 8).with_next_send_counter(390));
        mover.register_owner(second_owner, OwnerConfig::new(1, 8).with_next_send_counter(400));

        mover
            .submit_outbound_packet(outbound_packet(first_owner, 1, PacketClass::Bulk, b"first-1"))
            .unwrap();
        mover
            .submit_outbound_packet(outbound_packet(second_owner, 1, PacketClass::Bulk, b"second"))
            .unwrap();
        mover
            .submit_outbound_packet(outbound_packet(first_owner, 1, PacketClass::Bulk, b"first-2"))
            .unwrap();

        let work = dispatch_outbound_available(&mut mover, 8);
        assert_eq!(
            work.iter()
                .map(|work| (work.reservation.owner, work.reservation.counter))
                .collect::<Vec<_>>(),
            vec![(first_owner, 390), (first_owner, 391), (second_owner, 400)]
        );
    }

    #[test]
    fn stale_generation_is_dropped_before_dispatch_and_at_retire() {
        let owner = fmp_owner(4);
        let key = 4;
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        mover
            .submit_socket_packet(encrypted_fmp_packet(
                owner,
                1,
                1,
                PacketClass::Control,
                OutputTarget::Transport,
                key,
            ))
            .unwrap();

        let mut work = dispatch_available(&mut mover, 8);
        assert_eq!(work.len(), 1);
        mover.owner_mut(owner).unwrap().rekey(2);
        let stale_retire = retire_open_aead(&mut mover, work.pop().unwrap(), key);
        let stale_retire_drops = drops(stale_retire);
        assert_eq!(
            stale_retire_drops[0].reason,
            PacketDropReason::StaleCompletionGeneration
        );

        mover
            .submit_socket_packet(encrypted_fmp_packet(
                owner,
                1,
                2,
                PacketClass::Control,
                OutputTarget::Transport,
                key,
            ))
            .unwrap();
        mover
            .submit_socket_packet(encrypted_fmp_packet(
                owner,
                2,
                3,
                PacketClass::Control,
                OutputTarget::Transport,
                key,
            ))
            .unwrap();
        let work = dispatch_available(&mut mover, 8);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].packet.counter, 3);

        let drops = mover.drain_drops();
        assert!(drops.iter().any(
            |drop| drop.reason == PacketDropReason::StaleGeneration && drop.counter == Some(2)
        ));
    }

    #[test]
    fn tun_endpoint_and_transport_outputs_keep_owner_order() {
        let owner = fsp_owner(42);
        let key = 42;
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        let targets = [
            OutputTarget::Tun,
            OutputTarget::Endpoint,
            OutputTarget::Transport,
        ];
        for (idx, target) in targets.into_iter().enumerate() {
            mover
                .submit_socket_packet(encrypted_fsp_packet(
                    owner,
                    1,
                    idx as u64 + 1,
                    PacketClass::Bulk,
                    target,
                    key,
                ))
                .unwrap();
        }

        let work = dispatch_available(&mut mover, 8);
        let mut retired = Vec::new();
        for work in work.into_iter().rev() {
            retired.extend(retire_open_aead(&mut mover, work, key));
        }
        let outputs = outputs(retired);
        assert_eq!(
            outputs
                .iter()
                .map(|output| output.target)
                .collect::<Vec<_>>(),
            vec![
                OutputTarget::Tun,
                OutputTarget::Endpoint,
                OutputTarget::Transport,
            ]
        );
        assert_eq!(
            outputs
                .iter()
                .map(|output| output.counter)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn stateless_aead_worker_opens_fmp_and_fsp_packets() {
        let fmp = fmp_owner(77);
        let fsp = fsp_owner(88);
        let key = 9;
        let mut mover = mover();
        mover.register_owner(fmp, OwnerConfig::new(1, 8));
        mover.register_owner(fsp, OwnerConfig::new(1, 8));

        let fmp_plaintext = b"fmp inner packet";
        let fsp_plaintext = b"fsp inner packet";
        let fmp_wire = fmp_encrypted_wire(77, 100, 0x02, fmp_plaintext, key);
        let fsp_wire = fsp_encrypted_wire(101, 0, fsp_plaintext, key);

        mover
            .submit_socket_packet(
                SocketPacket::from_fmp_established_wire(fmp, 1, OutputTarget::Transport, fmp_wire)
                    .unwrap(),
            )
            .unwrap();
        mover
            .submit_socket_packet(
                SocketPacket::from_fsp_established_wire(fsp, 1, OutputTarget::Tun, fsp_wire)
                    .unwrap(),
            )
            .unwrap();

        let worker = StatelessAeadOpenWorker;
        let mut retired = Vec::new();
        for work in dispatch_available(&mut mover, 8) {
            let work = AeadOpenWork::from_crypto_work(work, test_key(key)).unwrap();
            retired.extend(mover.retire_completion(worker.execute(work)));
        }

        let outputs = outputs(retired);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].counter, 100);
        assert_eq!(outputs[0].target, OutputTarget::Transport);
        assert_eq!(
            &outputs[0].payload[FMP_ESTABLISHED_HEADER_SIZE..],
            fmp_plaintext
        );
        assert_eq!(
            outputs[0].payload.len(),
            FMP_ESTABLISHED_HEADER_SIZE + fmp_plaintext.len()
        );
        assert_eq!(outputs[1].counter, 101);
        assert_eq!(outputs[1].target, OutputTarget::Tun);
        assert_eq!(&outputs[1].payload[FSP_HEADER_SIZE..], fsp_plaintext);
        assert_eq!(
            outputs[1].payload.len(),
            FSP_HEADER_SIZE + fsp_plaintext.len()
        );
    }

    #[test]
    fn stateless_aead_worker_crypto_failure_retires_in_owner_order() {
        let owner = fmp_owner(91);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        mover
            .submit_socket_packet(
                SocketPacket::from_fmp_established_wire(
                    owner,
                    1,
                    OutputTarget::Transport,
                    fmp_encrypted_wire(91, 1, 0, b"first", 1),
                )
                .unwrap(),
            )
            .unwrap();
        mover
            .submit_socket_packet(
                SocketPacket::from_fmp_established_wire(
                    owner,
                    1,
                    OutputTarget::Transport,
                    fmp_encrypted_wire(91, 2, 0, b"second", 1),
                )
                .unwrap(),
            )
            .unwrap();

        let worker = StatelessAeadOpenWorker;
        let work = dispatch_available(&mut mover, 8);
        assert_eq!(work.len(), 2);

        let second = AeadOpenWork::from_crypto_work(work[1].clone(), test_key(1)).unwrap();
        assert!(mover.retire_completion(worker.execute(second)).is_empty());

        let first = AeadOpenWork::from_crypto_work(work[0].clone(), test_key(2)).unwrap();
        let retired = mover.retire_completion(worker.execute(first));
        assert_eq!(retired.len(), 2);
        match &retired[0] {
            RetiredPacket::Drop(drop) => {
                assert_eq!(drop.counter, Some(1));
                assert_eq!(drop.reason, PacketDropReason::CryptoFailed);
            }
            RetiredPacket::Output(output) => panic!("unexpected output: {output:?}"),
            RetiredPacket::Outbound(packet) => panic!("unexpected outbound: {packet:?}"),
        }
        match &retired[1] {
            RetiredPacket::Output(output) => {
                assert_eq!(output.counter, 2);
                assert_eq!(&output.payload[FMP_ESTABLISHED_HEADER_SIZE..], b"second");
            }
            RetiredPacket::Drop(drop) => panic!("unexpected drop: {drop:?}"),
            RetiredPacket::Outbound(packet) => panic!("unexpected outbound: {packet:?}"),
        }
    }

    #[test]
    fn outbound_seal_worker_builds_fmp_and_fsp_wire_from_owner_reserved_counters() {
        let fmp = fmp_owner(77);
        let fsp = fsp_owner(88);
        let key = 6;
        let mut mover = mover();
        mover.register_owner(fmp, OwnerConfig::new(1, 8).with_next_send_counter(10));
        mover.register_owner(fsp, OwnerConfig::new(1, 8).with_next_send_counter(20));

        mover
            .submit_outbound_packet(OutboundPacket::fmp(
                fmp,
                1,
                PacketClass::Bulk,
                777,
                0x02,
                b"fmp outbound".to_vec(),
            ))
            .unwrap();
        mover
            .submit_outbound_packet(OutboundPacket::fsp(
                fsp,
                1,
                PacketClass::Bulk,
                0,
                b"fsp outbound".to_vec(),
            ))
            .unwrap();

        let worker = StatelessAeadSealWorker;
        let mut retired = Vec::new();
        for work in dispatch_outbound_available(&mut mover, 8) {
            let work = AeadSealWork::from_outbound_work(work, test_key(key)).unwrap();
            retired.extend(mover.retire_completion(worker.execute(work)));
        }

        let outputs = outputs(retired);
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].owner, fmp);
        assert_eq!(outputs[0].counter, 10);
        assert_eq!(outputs[0].target, OutputTarget::Transport);
        let fmp_header = FmpWireHeader::parse(&outputs[0].payload).unwrap();
        assert_eq!(fmp_header.receiver_idx(), 777);
        assert_eq!(fmp_header.counter(), 10);
        assert_eq!(fmp_header.flags(), 0x02);
        assert_eq!(
            u16::from_le_bytes([outputs[0].payload[2], outputs[0].payload[3]]) as usize,
            b"fmp outbound".len()
        );
        assert_eq!(open_sealed_output(&outputs[0], key), b"fmp outbound");
        assert_eq!(
            outputs[0].payload.len(),
            FMP_ESTABLISHED_HEADER_SIZE + b"fmp outbound".len() + AEAD_TAG_SIZE
        );

        assert_eq!(outputs[1].owner, fsp);
        assert_eq!(outputs[1].counter, 20);
        assert_eq!(outputs[1].target, OutputTarget::Transport);
        let fsp_header = FspWireHeader::parse(&outputs[1].payload).unwrap();
        assert_eq!(fsp_header.counter(), 20);
        assert_eq!(fsp_header.flags(), 0);
        assert_eq!(
            u16::from_le_bytes([outputs[1].payload[2], outputs[1].payload[3]]) as usize,
            b"fsp outbound".len()
        );
        assert_eq!(open_sealed_output(&outputs[1], key), b"fsp outbound");
        assert_eq!(
            outputs[1].payload.len(),
            FSP_HEADER_SIZE + b"fsp outbound".len() + AEAD_TAG_SIZE
        );
    }

    #[test]
    fn outbound_owner_spends_fsp_coords_warmup_on_reserved_packets() {
        let owner = fsp_owner(89);
        let coords_prefix = empty_fsp_coords_prefix();
        let mut mover = PacketMover2::new(AdmissionConfig::new(4, 4));
        mover.register_owner(
            owner,
            OwnerConfig::new(1, 8).with_fsp_coords_warmup(1, coords_prefix.clone()),
        );

        mover
            .submit_outbound_packet(OutboundPacket::fsp(
                owner,
                1,
                PacketClass::Bulk,
                0,
                b"first".to_vec(),
            ))
            .unwrap();
        mover
            .submit_outbound_packet(OutboundPacket::fsp(
                owner,
                1,
                PacketClass::Bulk,
                0,
                b"second".to_vec(),
            ))
            .unwrap();

        let work = dispatch_outbound_available(&mut mover, 8);
        assert_eq!(work.len(), 2);
        assert_eq!(work[0].packet.fsp_cleartext_prefix, coords_prefix);
        assert_eq!(
            work[0].packet.wire,
            OutboundWire::Fsp {
                flags: crate::node::session_wire::FSP_FLAG_CP
            }
        );
        assert!(work[1].packet.fsp_cleartext_prefix.is_empty());
        assert_eq!(work[1].packet.wire, OutboundWire::Fsp { flags: 0 });
    }

    #[test]
    fn outbound_owner_reserves_counters_after_priority_overtakes_bulk() {
        let owner = fsp_owner(33);
        let mut mover = PacketMover2::new(AdmissionConfig::new(2, 1));
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(40));

        mover
            .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Bulk, b"bulk-a"))
            .unwrap();
        let bulk_drop = mover
            .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Bulk, b"bulk-b"))
            .unwrap_err();
        mover
            .submit_outbound_packet(outbound_packet(
                owner,
                1,
                PacketClass::Liveness,
                b"priority",
            ))
            .unwrap();

        assert_eq!(bulk_drop.owner(), owner);
        assert_eq!(bulk_drop.class(), PacketClass::Bulk);
        assert_eq!(bulk_drop.lane(), Lane::Bulk);
        assert_eq!(bulk_drop.payload_len(), b"bulk-b".len());
        assert_eq!(bulk_drop.reason(), AdmissionDropReason::BulkFull);
        assert_eq!(outbound_queue_lens(&mover), (1, 1));

        let work = dispatch_outbound_available(&mut mover, 8);
        assert_eq!(work.len(), 2);
        assert_eq!(work[0].packet.class, PacketClass::Liveness);
        assert_eq!(work[0].reservation.counter, 40);
        assert_eq!(work[1].packet.class, PacketClass::Bulk);
        assert_eq!(work[1].reservation.counter, 41);
        assert_eq!(mover.owner_mut(owner).unwrap().next_send_counter, 42);

        let drops = mover.drain_drops();
        assert_eq!(
            drops[0].reason(),
            PacketDropReason::Admission(AdmissionDropReason::BulkFull)
        );
        assert_eq!(drops[0].owner(), owner);
        assert_eq!(drops[0].counter(), None);
        assert_eq!(drops[0].ingress_seq(), None);
        assert_eq!(drops[0].lane(), Lane::Bulk);
    }

    #[test]
    fn outbound_owner_uses_shared_send_counter_authority() {
        let owner = fsp_owner(34);
        let authority = crate::noise::SendCounterAuthority::new_for_test(90);
        let mut mover = PacketMover2::new(AdmissionConfig::new(4, 4));
        mover.register_owner(
            owner,
            OwnerConfig::new(1, 8).with_send_counter_authority(authority.clone()),
        );

        mover
            .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Bulk, b"first"))
            .unwrap();
        assert_eq!(authority.reserve().unwrap(), 90);
        mover
            .submit_outbound_packet(outbound_packet(
                owner,
                1,
                PacketClass::Liveness,
                b"priority",
            ))
            .unwrap();

        let work = dispatch_outbound_available(&mut mover, 8);
        assert_eq!(work.len(), 2);
        assert_eq!(work[0].packet.class, PacketClass::Liveness);
        assert_eq!(work[0].reservation.counter, 91);
        assert_eq!(work[1].packet.class, PacketClass::Bulk);
        assert_eq!(work[1].reservation.counter, 92);
        assert_eq!(mover.owner_mut(owner).unwrap().next_send_counter, 93);
        assert_eq!(authority.reserve().unwrap(), 93);
    }

    #[test]
    fn outbound_owner_live_config_refresh_updates_existing_owner() {
        let owner = fsp_owner(35);
        let stale_authority = crate::noise::SendCounterAuthority::new_for_test(35);
        let refreshed_authority = crate::noise::SendCounterAuthority::new_for_test(350);
        let coords_prefix = empty_fsp_coords_prefix();
        let mut mover = PacketMover2::new(AdmissionConfig::new(4, 4));
        mover.register_owner(
            owner,
            OwnerConfig::new(1, 8).with_send_counter_authority(stale_authority),
        );

        mover.owner_mut(owner).unwrap().apply_live_config(
            OwnerConfig::new(1, 8)
                .with_send_counter_authority(refreshed_authority.clone())
                .with_fsp_coords_warmup(1, coords_prefix.clone()),
        );

        mover
            .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Bulk, b"refreshed"))
            .unwrap();

        let work = dispatch_outbound_available(&mut mover, 8);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].reservation.counter, 350);
        assert_eq!(work[0].packet.fsp_cleartext_prefix, coords_prefix);
        assert_eq!(
            work[0].packet.wire,
            OutboundWire::Fsp {
                flags: crate::node::session_wire::FSP_FLAG_CP
            }
        );
        assert_eq!(mover.owner_mut(owner).unwrap().next_send_counter, 351);
        assert_eq!(refreshed_authority.reserve().unwrap(), 351);
    }

    #[test]
    fn outbound_owner_live_config_without_coords_keeps_transferred_warmup() {
        let owner = fsp_owner(36);
        let coords_prefix = empty_fsp_coords_prefix();
        let mut mover = PacketMover2::new(AdmissionConfig::new(4, 4));
        mover.register_owner(
            owner,
            OwnerConfig::new(1, 8).with_fsp_coords_warmup(2, coords_prefix.clone()),
        );

        mover
            .owner_mut(owner)
            .unwrap()
            .apply_live_config(OwnerConfig::new(1, 8));
        mover
            .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Bulk, b"first"))
            .unwrap();
        mover
            .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Bulk, b"second"))
            .unwrap();

        let work = dispatch_outbound_available(&mut mover, 8);
        assert_eq!(work.len(), 2);
        assert_eq!(work[0].packet.fsp_cleartext_prefix, coords_prefix);
        assert_eq!(work[1].packet.fsp_cleartext_prefix, coords_prefix);
    }

    #[test]
    fn outbound_completions_retire_in_owner_order() {
        let owner = fmp_owner(44);
        let key = 7;
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(5));
        for payload in [
            b"first".as_slice(),
            b"second".as_slice(),
            b"third".as_slice(),
        ] {
            mover
                .submit_outbound_packet(outbound_packet(owner, 1, PacketClass::Bulk, payload))
                .unwrap();
        }

        let work = dispatch_outbound_available(&mut mover, 8);
        assert_eq!(
            work.iter()
                .map(outbound_crypto_work_order)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );

        let worker = StatelessAeadSealWorker;
        let third = AeadSealWork::from_outbound_work(work[2].clone(), test_key(key)).unwrap();
        assert!(mover.retire_completion(worker.execute(third)).is_empty());

        let first = AeadSealWork::from_outbound_work(work[0].clone(), test_key(key)).unwrap();
        let retired = outputs(mover.retire_completion(worker.execute(first)));
        assert_eq!(retired.len(), 1);
        assert_eq!(retired[0].counter, 5);
        assert_eq!(open_sealed_output(&retired[0], key), b"first");

        let second = AeadSealWork::from_outbound_work(work[1].clone(), test_key(key)).unwrap();
        let retired = outputs(mover.retire_completion(worker.execute(second)));
        assert_eq!(
            retired
                .iter()
                .map(|output| output.counter)
                .collect::<Vec<_>>(),
            vec![6, 7]
        );
        assert_eq!(open_sealed_output(&retired[0], key), b"second");
        assert_eq!(open_sealed_output(&retired[1], key), b"third");
    }

    #[test]
    fn outbound_wire_build_rejects_mismatched_protocol_and_plaintext_fsp() {
        let fmp_owner = fmp_owner(12);
        let fsp_owner = fsp_owner(12);
        let mut fmp_state =
            OwnerState::new(fmp_owner, OwnerConfig::new(1, 8).with_next_send_counter(1));
        let mismatch = OutboundPacket::fsp(fmp_owner, 1, PacketClass::Bulk, 0, b"body".to_vec());
        let (reservation, mismatch) = fmp_state.reserve_outbound(mismatch, 0).unwrap();
        let mismatch_work = OutboundCryptoWork::new(reservation, mismatch);
        assert_eq!(
            AeadSealWork::from_outbound_work(mismatch_work, test_key(1)).err(),
            Some(WireBuildError::ProtocolMismatch)
        );

        let mut fsp_state =
            OwnerState::new(fsp_owner, OwnerConfig::new(1, 8).with_next_send_counter(1));
        let plaintext_fsp = OutboundPacket::fsp(
            fsp_owner,
            1,
            PacketClass::Bulk,
            FSP_FLAG_U,
            b"body".to_vec(),
        );
        let (reservation, plaintext_fsp) = fsp_state.reserve_outbound(plaintext_fsp, 0).unwrap();
        let plaintext_work = OutboundCryptoWork::new(reservation, plaintext_fsp);
        assert_eq!(
            AeadSealWork::from_outbound_work(plaintext_work, test_key(1)).err(),
            Some(WireBuildError::PlaintextFsp)
        );
    }
