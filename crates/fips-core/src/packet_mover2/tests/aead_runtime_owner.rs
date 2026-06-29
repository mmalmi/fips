    #[test]
    fn aead_turn_runner_uses_owner_keys_for_inbound_and_outbound_work() {
        let owner = fmp_owner(70);
        let open_key = 11;
        let seal_key = 12;
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(200));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));

        mover
            .submit_socket_packet(
                SocketPacket::from_fmp_established_wire(
                    owner,
                    1,
                    OutputTarget::Tun,
                    fmp_encrypted_wire(70, 100, 0, b"inbound", open_key),
                )
                .unwrap(),
            )
            .unwrap();
        mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Bulk,
                700,
                0,
                b"outbound".to_vec(),
            ))
            .unwrap();

        let mut open_work_buffer = Vec::with_capacity(4);
        let mut seal_work_buffer = Vec::with_capacity(4);
        let turn = run_aead_available_with_work_buffers(&mut mover, 8, &mut open_work_buffer, &mut seal_work_buffer);
        assert_eq!(turn.dispatched(), 2);
        assert!(turn.drops().is_empty());
        assert!(open_work_buffer.is_empty());
        assert!(seal_work_buffer.is_empty());

        let outputs = turn.outputs();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].counter, 100);
        assert_eq!(outputs[0].target, OutputTarget::Tun);
        assert_eq!(
            &outputs[0].payload[FMP_ESTABLISHED_HEADER_SIZE..],
            b"inbound"
        );
        assert_eq!(outputs[1].counter, 200);
        assert_eq!(outputs[1].target, OutputTarget::Transport);
        let sealed_header = FmpWireHeader::parse(&outputs[1].payload).unwrap();
        assert_eq!(sealed_header.receiver_idx(), 700);
        assert_eq!(sealed_header.counter(), 200);
        assert_eq!(open_sealed_output(outputs[1], seal_key), b"outbound");
        assert_eq!(open_work_buffer.capacity(), 4);
        assert_eq!(seal_work_buffer.capacity(), 4);
    }

    #[derive(Debug, Default)]
    struct RecordingChunkExecutor {
        inline: InlinePacketMover2CryptoExecutor,
        nonempty_chunks: Vec<usize>,
    }

    impl PacketMover2CryptoExecutor for RecordingChunkExecutor {
        fn execute_prepared_chunk(
            &mut self,
            prepared: &mut Vec<PreparedCryptoWork>,
            completions: &mut Vec<CryptoCompletion>,
        ) -> usize {
            if !prepared.is_empty() {
                self.nonempty_chunks.push(prepared.len());
            }
            self.inline.execute_prepared_chunk(prepared, completions)
        }
    }

    #[derive(Debug, Default)]
    struct DelayedChunkExecutor {
        inline: InlinePacketMover2CryptoExecutor,
        ready: VecDeque<Vec<CryptoCompletion>>,
        nonempty_chunks: Vec<usize>,
    }

    impl DelayedChunkExecutor {
        fn take_ready(&mut self) -> VecDeque<Vec<CryptoCompletion>> {
            std::mem::take(&mut self.ready)
        }
    }

    impl PacketMover2CryptoExecutor for DelayedChunkExecutor {
        fn execute_prepared_chunk(
            &mut self,
            prepared: &mut Vec<PreparedCryptoWork>,
            completions: &mut Vec<CryptoCompletion>,
        ) -> usize {
            if !prepared.is_empty() {
                self.nonempty_chunks.push(prepared.len());
            }
            let count = self.inline.execute_prepared_chunk(prepared, completions);
            if !completions.is_empty() {
                self.ready.push_back(std::mem::take(completions));
            }
            count
        }
    }

    #[test]
    fn aead_turn_runner_hands_executor_prepared_crypto_chunks() {
        let owner = fmp_owner(702);
        let open_key = 15;
        let seal_key = 16;
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(300));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));

        for counter in 100..104 {
            mover
                .submit_socket_packet(
                    SocketPacket::from_fmp_established_wire(
                        owner,
                        1,
                        OutputTarget::Tun,
                        fmp_encrypted_wire(70, counter, 0, b"inbound", open_key),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        for idx in 0..2 {
            mover
                .submit_outbound_packet(OutboundPacket::fmp(
                    owner,
                    1,
                    PacketClass::Bulk,
                    702,
                    0,
                    format!("outbound-{idx}").into_bytes(),
                ))
                .unwrap();
        }

        let mut open_work = Vec::new();
        let mut seal_work = Vec::new();
        let mut prepared_work = Vec::new();
        let mut completion_work = Vec::new();
        let mut retired = Vec::new();
        let mut drops = Vec::new();
        let mut executor = RecordingChunkExecutor::default();
        let dispatched = mover.run_aead_available_into_with_executor(
            6,
            &mut open_work,
            &mut seal_work,
            &mut prepared_work,
            &mut completion_work,
            &mut retired,
            &mut drops,
            &mut executor,
        );

        assert_eq!(dispatched, 6);
        assert_eq!(executor.nonempty_chunks, vec![4, 2]);
        assert!(drops.is_empty());
        assert!(open_work.is_empty());
        assert!(seal_work.is_empty());
        assert!(prepared_work.is_empty());
        assert!(completion_work.is_empty());

        let outputs = outputs(retired);
        assert_eq!(outputs.len(), 6);
        assert_eq!(
            outputs
                .iter()
                .map(PacketOutput::counter)
                .collect::<Vec<_>>(),
            vec![100, 101, 102, 103, 300, 301]
        );
        assert_eq!(
            open_sealed_output(&outputs[4], seal_key),
            b"outbound-0"
        );
        assert_eq!(
            open_sealed_output(&outputs[5], seal_key),
            b"outbound-1"
        );
    }

    #[test]
    fn executor_turn_dispatches_chunk_and_retires_delayed_completion_later() {
        let owner = fmp_owner(703);
        let seal_key = 17;
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(500));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(seal_key), test_key(seal_key)));

        let mut raw_ingress = VecDeque::new();
        let mut outbound = VecDeque::from([OutboundPacket::fmp(
            owner,
            1,
            PacketClass::Bulk,
            703,
            0,
            b"delayed-outbound".to_vec(),
        )]);
        let mut sink = BatchRecordingOutputSink::default();
        let mut empty_completions: VecDeque<CryptoCompletion> = VecDeque::new();
        let mut executor = DelayedChunkExecutor::default();

        {
            let turn = driver.pump_aead_output_completion_executor_turn(
                &mut empty_completions,
                8,
                &mut executor,
                &mut raw_ingress,
                &mut NullIngressRouter,
                0,
                &mut outbound,
                1,
                &mut sink,
                8,
            );
            assert_eq!(turn.summary().completions(), 0);
            assert_eq!(turn.summary().outbound_admitted(), 1);
            assert_eq!(turn.summary().dispatched(), 1);
            assert_eq!(turn.summary().outputs_sent(), 0);
            assert!(turn.outputs().is_empty());
            assert!(turn.drops().is_empty());
        }
        assert!(empty_completions.is_empty());
        assert!(outbound.is_empty());
        assert!(sink.outputs.is_empty());
        assert_eq!(executor.nonempty_chunks, vec![1]);
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 1);

        let mut ready_completions = executor.take_ready();
        {
            let turn = driver.pump_aead_output_completion_executor_turn(
                &mut ready_completions,
                8,
                &mut executor,
                &mut raw_ingress,
                &mut NullIngressRouter,
                0,
                &mut outbound,
                0,
                &mut sink,
                0,
            );
            assert_eq!(turn.summary().completions(), 1);
            assert_eq!(turn.summary().dispatched(), 0);
            assert_eq!(turn.summary().outputs_sent(), 1);
            assert!(turn.outputs().is_empty());
            assert!(turn.drops().is_empty());
        }

        assert!(ready_completions.is_empty());
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 0);
        assert_eq!(sink.outputs.len(), 1);
        assert_eq!(sink.outputs[0].owner(), owner);
        assert_eq!(sink.outputs[0].counter(), 500);
        assert_eq!(sink.outputs[0].target(), OutputTarget::Transport);
        assert_eq!(
            open_sealed_output(&sink.outputs[0], seal_key),
            b"delayed-outbound"
        );
    }

    #[test]
    fn aead_turn_runner_wraps_fsp_post_seal_into_next_hop_fmp() {
        let source = NodeAddr::from_bytes([0x21; 16]);
        let dest = NodeAddr::from_bytes([0x22; 16]);
        let next_hop = NodeAddr::from_bytes([0x23; 16]);
        let fsp_owner = OwnerId::fsp_node(dest);
        let fmp_owner = OwnerId::fmp_node(next_hop);
        let fsp_key = 21;
        let fmp_key = 22;
        let fmp_path = live_path(2200);
        let mut driver =
            PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(fsp_owner, OwnerConfig::new(1, 8).with_next_send_counter(50));
        driver.register_owner(fmp_owner, OwnerConfig::new(1, 8).with_next_send_counter(70));
        driver
            .owner_mut(fsp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fsp_key), test_key(fsp_key)));
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fmp_key), test_key(fmp_key)));
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_active_path(fmp_path.clone());

        let wrap = PacketMover2FspWrapRoute::new(
            fmp_owner,
            1,
            4242,
            source,
            dest,
        )
        .with_fmp_flags(0x05)
        .with_ttl(42)
        .with_path_mtu(1280);
        let packet = OutboundPacket::fsp(
            fsp_owner,
            1,
            PacketClass::Liveness,
            0x03,
            b"session-body".to_vec(),
        )
        .with_fsp_cleartext_prefix(empty_fsp_coords_prefix())
        .with_post_seal(OutboundPostSeal::FmpWrap(wrap));
        let queued_bulk = OutboundPacket::fmp(
            fmp_owner,
            1,
            PacketClass::Bulk,
            4243,
            0,
            b"queued-bulk".to_vec(),
        );

        let first = run_aead_classified_turn(&mut driver, std::iter::empty(), [packet, queued_bulk], 1);
        assert_eq!(first.summary().outbound_admitted(), 3);
        assert_eq!(first.summary().dispatched(), 1);
        assert_eq!(first.summary().outputs(), 0);
        assert!(first.outputs().is_empty());
        assert!(first.drops().is_empty());

        let second = run_aead_classified_turn(&mut driver,
            std::iter::empty::<SocketPacket>(),
            std::iter::empty::<OutboundPacket>(),
            8,
        );
        assert_eq!(second.summary().dispatched(), 2);
        assert_eq!(second.summary().outputs(), 2);
        assert!(second.drops().is_empty());

        let output = &second.outputs()[0];
        assert_eq!(output.owner(), fmp_owner);
        assert_eq!(output.counter(), 70);
        assert_eq!(output.target(), OutputTarget::Transport);
        assert_eq!(output.path(), Some(fmp_path));

        let fmp_plaintext = open_sealed_output(output, fmp_key);
        assert_eq!(
            fmp_plaintext[0],
            crate::protocol::LinkMessageType::SessionDatagram.to_byte()
        );
        let datagram = crate::protocol::SessionDatagramRef::decode(&fmp_plaintext[1..])
            .expect("wrapped session datagram");
        assert_eq!(datagram.ttl, 42);
        assert_eq!(datagram.path_mtu, 1280);
        assert_eq!(datagram.src_addr, source);
        assert_eq!(datagram.dest_addr, dest);

        let fsp_header = FspWireHeader::parse(datagram.payload).unwrap();
        assert_eq!(fsp_header.counter(), 50);
        assert_eq!(fsp_header.flags(), 0x03);
        assert_eq!(
            open_fsp_wire_payload(datagram.payload, fsp_key),
            b"session-body"
        );

        let output = &second.outputs()[1];
        assert_eq!(output.owner(), fmp_owner);
        assert_eq!(output.counter(), 71);
        assert_eq!(open_sealed_output(output, fmp_key), b"queued-bulk");
    }

    #[test]
    fn aead_turn_runner_spends_remaining_budget_on_fsp_post_seal_wrap() {
        let source = NodeAddr::from_bytes([0x31; 16]);
        let dest = NodeAddr::from_bytes([0x32; 16]);
        let next_hop = NodeAddr::from_bytes([0x33; 16]);
        let fsp_owner = OwnerId::fsp_node(dest);
        let fmp_owner = OwnerId::fmp_node(next_hop);
        let fsp_key = 31;
        let fmp_key = 32;
        let fmp_path = live_path(3200);
        let mut driver =
            PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(fsp_owner, OwnerConfig::new(1, 8).with_next_send_counter(90));
        driver.register_owner(fmp_owner, OwnerConfig::new(1, 8).with_next_send_counter(100));
        driver
            .owner_mut(fsp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fsp_key), test_key(fsp_key)));
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fmp_key), test_key(fmp_key)));
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_active_path(fmp_path.clone());

        let wrap = PacketMover2FspWrapRoute::new(fmp_owner, 1, 5151, source, dest)
            .with_ttl(42)
            .with_path_mtu(1280);
        let packet = OutboundPacket::fsp(
            fsp_owner,
            1,
            PacketClass::Liveness,
            0x03,
            b"session-priority".to_vec(),
        )
        .with_fsp_cleartext_prefix(empty_fsp_coords_prefix())
        .with_post_seal(OutboundPostSeal::FmpWrap(wrap));

        let turn = run_aead_classified_turn(&mut driver, std::iter::empty(), [packet], 2);
        assert_eq!(turn.summary().outbound_admitted(), 2);
        assert_eq!(turn.summary().dispatched(), 2);
        assert_eq!(turn.summary().outputs(), 1);
        assert!(turn.drops().is_empty());

        let output = &turn.outputs()[0];
        assert_eq!(output.owner(), fmp_owner);
        assert_eq!(output.counter(), 100);
        assert_eq!(output.target(), OutputTarget::Transport);
        assert_eq!(output.path(), Some(fmp_path));
        let fmp_plaintext = open_sealed_output(output, fmp_key);
        let datagram = crate::protocol::SessionDatagramRef::decode(&fmp_plaintext[1..])
            .expect("wrapped session datagram");
        let fsp_header = FspWireHeader::parse(datagram.payload).unwrap();
        assert_eq!(fsp_header.counter(), 90);
        assert_eq!(
            open_fsp_wire_payload(datagram.payload, fsp_key),
            b"session-priority"
        );
    }

    #[test]
    fn aead_turn_runner_drains_queued_wrap_outputs_until_budget_exhausts() {
        let source = NodeAddr::from_bytes([0x41; 16]);
        let dest = NodeAddr::from_bytes([0x42; 16]);
        let next_hop = NodeAddr::from_bytes([0x43; 16]);
        let fsp_owner = OwnerId::fsp_node(dest);
        let fmp_owner = OwnerId::fmp_node(next_hop);
        let fsp_key = 41;
        let fmp_key = 42;
        let fmp_path = live_path(4200);
        let mut driver =
            PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(
            fsp_owner,
            OwnerConfig::new(1, 8)
                .with_bulk_in_flight_limit(2)
                .with_next_send_counter(10),
        );
        driver.register_owner(
            fmp_owner,
            OwnerConfig::new(1, 8)
                .with_bulk_in_flight_limit(2)
                .with_next_send_counter(20),
        );
        driver
            .owner_mut(fsp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fsp_key), test_key(fsp_key)));
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fmp_key), test_key(fmp_key)));
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_active_path(fmp_path.clone());

        let wrap = PacketMover2FspWrapRoute::new(fmp_owner, 1, 6000, source, dest)
            .with_ttl(42)
            .with_path_mtu(1280);
        let packets = (0..4).map(|idx| {
            OutboundPacket::fsp(
                fsp_owner,
                1,
                PacketClass::Bulk,
                crate::node::session_wire::FSP_FLAG_CP,
                format!("session-{idx}").into_bytes(),
            )
            .with_fsp_cleartext_prefix(empty_fsp_coords_prefix())
            .with_post_seal(OutboundPostSeal::FmpWrap(wrap))
        });

        let turn = run_aead_classified_turn(&mut driver, std::iter::empty(), packets, 8);
        assert_eq!(turn.summary().outbound_admitted(), 8);
        assert_eq!(turn.summary().dispatched(), 8);
        assert_eq!(turn.summary().outputs(), 4);
        assert!(turn.drops().is_empty());

        for (idx, output) in turn.outputs().iter().enumerate() {
            assert_eq!(output.owner(), fmp_owner);
            assert_eq!(output.counter(), 20 + idx as u64);
            assert_eq!(output.target(), OutputTarget::Transport);
            assert_eq!(output.path(), Some(fmp_path.clone()));
            let fmp_plaintext = open_sealed_output(output, fmp_key);
            let datagram = crate::protocol::SessionDatagramRef::decode(&fmp_plaintext[1..])
                .expect("wrapped session datagram");
            assert_eq!(
                open_fsp_wire_payload(datagram.payload, fsp_key),
                format!("session-{idx}").as_bytes()
            );
        }
    }

    #[test]
    fn aead_turn_runner_reserves_progress_for_outbound_priority_under_inbound_bulk() {
        let owner = fmp_owner(701);
        let open_key = 13;
        let seal_key = 14;
        let path = live_path(7010);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(900));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_active_path(path.clone());
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));

        for counter in 100..104 {
            mover
                .submit_socket_packet(
                    SocketPacket::from_fmp_established_wire(
                        owner,
                        1,
                        OutputTarget::Tun,
                        fmp_encrypted_wire(70, counter, 0, b"inbound-bulk", open_key),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Liveness,
                701,
                0,
                b"outbound-liveness".to_vec(),
            ))
            .unwrap();

        let mut open_work_buffer = Vec::new();
        let mut seal_work_buffer = Vec::new();
        let turn = run_aead_available_with_work_buffers(&mut mover, 2, &mut open_work_buffer, &mut seal_work_buffer);

        assert_eq!(turn.dispatched(), 2);
        let outputs = turn.outputs();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].target, OutputTarget::Tun);
        assert_eq!(outputs[0].counter, 100);
        assert_eq!(outputs[1].target, OutputTarget::Transport);
        assert_eq!(outputs[1].counter, 900);
        assert_eq!(outputs[1].path(), Some(path));
        assert_eq!(
            open_sealed_output(outputs[1], seal_key),
            b"outbound-liveness"
        );
        assert_eq!(queue_lens(&mover), (0, 3));
        assert_eq!(outbound_queue_lens(&mover), (0, 0));
    }

    #[test]
    fn aead_turn_runner_missing_keys_retires_failed_work_and_releases_in_flight() {
        let owner = fsp_owner(71);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        mover
            .submit_outbound_packet(OutboundPacket::fsp(
                owner,
                1,
                PacketClass::Bulk,
                0,
                b"needs key".to_vec(),
            ))
            .unwrap();

        let turn = run_aead_available(&mut mover, 8);
        assert_eq!(turn.dispatched(), 1);
        assert_eq!(turn.retired().len(), 1);
        match &turn.retired()[0] {
            RetiredPacket::Drop(drop) => {
                assert_eq!(drop.reason, PacketDropReason::CryptoFailed);
                assert_eq!(drop.counter, Some(0));
                assert_eq!(drop.lane, Lane::Bulk);
            }
            RetiredPacket::Output(output) => panic!("unexpected output: {output:?}"),
            RetiredPacket::Outbound(packet) => panic!("unexpected outbound: {packet:?}"),
        }
        assert_eq!(turn.drops().len(), 1);
        assert_eq!(turn.drops()[0].reason, PacketDropReason::CryptoFailed);
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight, 0);
    }

    #[test]
    fn rekey_clears_owner_crypto_keys_and_restarts_send_counter() {
        let owner = fmp_owner(72);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(99));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(1), test_key(1)));
        mover.owner_mut(owner).unwrap().rekey(2);
        mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                2,
                PacketClass::Bulk,
                720,
                0,
                b"after rekey".to_vec(),
            ))
            .unwrap();

        let turn = run_aead_available(&mut mover, 8);
        assert_eq!(turn.dispatched(), 1);
        match &turn.retired()[0] {
            RetiredPacket::Drop(drop) => {
                assert_eq!(drop.reason, PacketDropReason::CryptoFailed);
                assert_eq!(drop.counter, Some(0));
            }
            RetiredPacket::Output(output) => panic!("unexpected output: {output:?}"),
            RetiredPacket::Outbound(packet) => panic!("unexpected outbound: {packet:?}"),
        }
        let owner = mover.owner_mut(owner).unwrap();
        assert_eq!(owner.next_send_counter, 1);
        assert_eq!(owner.in_flight, 0);
    }

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

        let inbound_a = SocketPacket::from_fmp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
            fmp_encrypted_wire(73, 1000, 0, b"in-a", open_key),
        )
        .unwrap()
        .with_source_path(path_a.clone());
        mover.submit_socket_packet(inbound_a).unwrap();
        let turn = run_aead_available(&mut mover, 8);
        assert!(turn.drops().is_empty());
        assert_eq!(turn.outputs()[0].path(), None);
        assert_eq!(
            mover.owner_mut(owner).unwrap().active_path(),
            Some(path_a.clone())
        );

        mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Bulk,
                730,
                0,
                b"out-a".to_vec(),
            ))
            .unwrap();
        let turn = run_aead_available(&mut mover, 8);
        let output = turn.outputs()[0];
        assert_eq!(output.counter, 500);
        assert_eq!(output.target, OutputTarget::Transport);
        assert_eq!(output.path(), Some(path_a));
        assert_eq!(open_sealed_output(output, seal_key), b"out-a");

        let inbound_b = SocketPacket::from_fmp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
            fmp_encrypted_wire(73, 1001, 0, b"in-b", open_key),
        )
        .unwrap()
        .with_source_path(path_b.clone());
        mover.submit_socket_packet(inbound_b).unwrap();
        let turn = run_aead_available(&mut mover, 8);
        assert!(turn.drops().is_empty());
        assert_eq!(turn.outputs()[0].path(), None);
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
                b"out-b".to_vec(),
            ))
            .unwrap();
        let turn = run_aead_available(&mut mover, 8);
        let output = turn.outputs()[0];
        assert_eq!(output.counter, 501);
        assert_eq!(output.path(), Some(path_b));
        assert_eq!(open_sealed_output(output, seal_key), b"out-b");
    }

    #[test]
    fn stale_generation_does_not_move_owner_path() {
        let owner = fsp_owner(74);
        let old_path = live_path(10);
        let stale_path = live_path(11);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(2, 8));
        mover
            .owner_mut(owner)
            .unwrap()
            .set_active_path(old_path.clone());
        mover
            .submit_socket_packet(
                SocketPacket::new(
                    owner,
                    1,
                    5,
                    PacketClass::Bulk,
                    OutputTarget::Tun,
                    b"stale".to_vec(),
                )
                .with_source_path(stale_path),
            )
            .unwrap();

        let work = dispatch_available(&mut mover, 8);
        assert!(work.is_empty());
        let drops = mover.drain_drops();
        assert_eq!(drops.len(), 1);
        assert_eq!(drops[0].reason, PacketDropReason::StaleGeneration);
        assert_eq!(
            mover.owner_mut(owner).unwrap().active_path(),
            Some(old_path)
        );
    }

    #[test]
    fn owner_tracks_inbound_activity_only_for_reserved_packets() {
        let owner = fsp_owner(75);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));

        mover
            .submit_socket_packet(
                packet(owner, 1, 1, PacketClass::Bulk, OutputTarget::Tun)
                    .with_activity_tick(ActivityTick::new(10)),
            )
            .unwrap();
        assert_eq!(dispatch_available(&mut mover, 8).len(), 1);
        assert_eq!(
            mover.owner_mut(owner).unwrap().last_rx_activity(),
            Some(ActivityTick::new(10))
        );

        mover
            .submit_socket_packet(
                packet(owner, 1, 1, PacketClass::Bulk, OutputTarget::Tun)
                    .with_activity_tick(ActivityTick::new(20)),
            )
            .unwrap();
        assert!(dispatch_available(&mut mover, 8).is_empty());
        assert_eq!(
            mover.owner_mut(owner).unwrap().last_rx_activity(),
            Some(ActivityTick::new(10))
        );

        mover
            .submit_socket_packet(
                packet(owner, 0, 2, PacketClass::Bulk, OutputTarget::Tun)
                    .with_activity_tick(ActivityTick::new(30)),
            )
            .unwrap();
        assert!(dispatch_available(&mut mover, 8).is_empty());
        assert_eq!(
            mover.owner_mut(owner).unwrap().last_rx_activity(),
            Some(ActivityTick::new(10))
        );

        let drops = mover.drain_drops();
        assert!(
            drops
                .iter()
                .any(|drop| drop.reason == PacketDropReason::Replay && drop.counter == Some(1))
        );
        assert!(drops.iter().any(
            |drop| drop.reason == PacketDropReason::StaleGeneration && drop.counter == Some(2)
        ));
    }

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
                .any(|drop| drop.reason == PacketDropReason::StaleGeneration
                    && drop.counter.is_none())
        );
    }

    #[test]
    fn hard_event_liveness_state_stays_owner_owned_across_rekey() {
        let owner = fmp_owner(77);
        let mut state = OwnerState::new(owner, OwnerConfig::new(1, 8));

        state.record_hard_event(ActivityTick::new(100));
        state.record_hard_event(ActivityTick::new(90));
        assert_eq!(state.hard_events(), 2);
        assert_eq!(state.last_hard_event(), Some(ActivityTick::new(100)));

        state.rekey(2);
        assert_eq!(state.hard_events(), 2);
        assert_eq!(state.last_hard_event(), Some(ActivityTick::new(100)));
        assert_eq!(state.last_rx_activity(), None);
        assert_eq!(state.last_tx_activity(), None);
    }

    #[test]
    fn runtime_turn_driver_runs_classified_inbound_and_outbound_once() {
        let owner = fmp_owner(78);
        let open_key = 31;
        let seal_key = 32;
        let path = live_path(7800);
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(300));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));

        let inbound = SocketPacket::from_fmp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
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
            b"outbound".to_vec(),
        )
        .with_activity_tick(ActivityTick::new(11));

        let turn = run_aead_classified_turn(&mut driver, [inbound], [outbound], 8);
        assert_eq!(
            turn.summary(),
            PacketMover2RuntimeSummary {
                raw_ingress_dropped: 0,
                inbound_admitted: 1,
                inbound_dropped: 0,
                outbound_admitted: 1,
                outbound_dropped: 0,
                completions: 0,
                dispatched: 2,
                outputs: 2,
                outputs_sent: 0,
                outputs_dropped: 0,
                drops: 0,
            }
        );
        assert!(turn.drops().is_empty());

        let outputs = turn.outputs();
        assert_eq!(outputs[0].target, OutputTarget::Tun);
        assert_eq!(outputs[0].counter, 100);
        assert_eq!(
            &outputs[0].payload[FMP_ESTABLISHED_HEADER_SIZE..],
            b"inbound"
        );
        assert_eq!(outputs[0].path(), None);

        assert_eq!(outputs[1].target, OutputTarget::Transport);
        assert_eq!(outputs[1].counter, 300);
        assert_eq!(outputs[1].path(), Some(path.clone()));
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
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8));

        driver
            .mover
            .submit_socket_packet(
                SocketPacket::from_fmp_established_wire(
                    owner,
                    1,
                    OutputTarget::Tun,
                    fmp_encrypted_wire(80, 100, 0, b"completion-only", open_key),
                )
                .unwrap(),
            )
            .unwrap();

        let mut work = Vec::new();
        assert_eq!(driver.mover.dispatch_available_into(8, &mut work), 1);
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 1);

        let worker = StatelessAeadOpenWorker;
        let open_work =
            AeadOpenWork::from_crypto_work(work.pop().unwrap(), test_key(open_key)).unwrap();
        let completion = worker.execute(open_work);

        {
            let turn = run_aead_completion_turn(&mut driver, [completion], 8);
            assert_eq!(
                turn.summary(),
                PacketMover2RuntimeSummary {
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
            assert_eq!(turn.outputs()[0].target(), OutputTarget::Tun);
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
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8));

        let packets: [(u64, &[u8]); 3] = [(100, b"first"), (101, b"second"), (102, b"third")];
        for (counter, payload) in packets {
            driver
                .mover
                .submit_socket_packet(
                    SocketPacket::from_fmp_established_wire(
                        owner,
                        1,
                        OutputTarget::Tun,
                        fmp_encrypted_wire(84, counter, 0, payload, open_key),
                    )
                    .unwrap(),
                )
                .unwrap();
        }

        let mut work = Vec::new();
        assert_eq!(driver.mover.dispatch_available_into(8, &mut work), 3);

        let worker = StatelessAeadOpenWorker;
        let mut completions = work
            .drain(..)
            .map(|work| {
                worker.execute(AeadOpenWork::from_crypto_work(work, test_key(open_key)).unwrap())
            })
            .collect::<VecDeque<_>>();
        let third = completions.pop_back().unwrap();
        let first = completions.pop_front().unwrap();
        let second = completions.pop_front().unwrap();

        let mut raw_ingress = VecDeque::new();
        let mut outbound = VecDeque::new();
        let mut sink = BatchRecordingOutputSink::default();
        let mut completion_source = VecDeque::from([third]);

        {
            let turn = pump_aead_output_completion_turn(&mut driver,
                &mut completion_source,
                8,
                &mut raw_ingress,
                &mut NullIngressRouter,
                0,
                &mut outbound,
                0,
                &mut sink,
                8,
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

        completion_source.extend([first, second]);
        {
            let turn = pump_aead_output_completion_turn(&mut driver,
                &mut completion_source,
                8,
                &mut raw_ingress,
                &mut NullIngressRouter,
                0,
                &mut outbound,
                0,
                &mut sink,
                8,
            );
            assert_eq!(turn.summary().completions(), 2);
            assert_eq!(turn.summary().outputs(), 3);
            assert_eq!(turn.summary().outputs_sent(), 3);
            assert!(turn.outputs().is_empty());
            assert!(turn.drops().is_empty());
        }

        assert!(completion_source.is_empty());
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

    #[test]
    fn completion_batch_source_preserves_leftover_batch_order_when_limited() {
        let owner = fmp_owner(85);
        let open_key = 85;
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8));

        let packets: [(u64, &[u8]); 3] = [(100, b"first"), (101, b"second"), (102, b"third")];
        for (counter, payload) in packets {
            driver
                .mover
                .submit_socket_packet(
                    SocketPacket::from_fmp_established_wire(
                        owner,
                        1,
                        OutputTarget::Tun,
                        fmp_encrypted_wire(85, counter, 0, payload, open_key),
                    )
                    .unwrap(),
                )
                .unwrap();
        }

        let mut work = Vec::new();
        assert_eq!(driver.mover.dispatch_available_into(8, &mut work), 3);

        let worker = StatelessAeadOpenWorker;
        let completions = work
            .drain(..)
            .map(|work| {
                worker.execute(AeadOpenWork::from_crypto_work(work, test_key(open_key)).unwrap())
            })
            .collect::<Vec<_>>();

        let mut raw_ingress = VecDeque::new();
        let mut outbound = VecDeque::new();
        let mut sink = BatchRecordingOutputSink::default();
        let mut completion_source = VecDeque::from([completions]);

        {
            let turn = pump_aead_output_completion_turn(&mut driver,
                &mut completion_source,
                2,
                &mut raw_ingress,
                &mut NullIngressRouter,
                0,
                &mut outbound,
                0,
                &mut sink,
                8,
            );
            assert_eq!(turn.summary().completions(), 2);
            assert_eq!(turn.summary().outputs_sent(), 2);
            assert!(turn.drops().is_empty());
        }
        assert_eq!(completion_source.len(), 1);
        assert_eq!(completion_source[0].len(), 1);
        assert_eq!(completion_source[0][0].reservation.counter, 102);
        assert_eq!(
            sink.outputs
                .iter()
                .map(PacketOutput::counter)
                .collect::<Vec<_>>(),
            vec![100, 101]
        );

        {
            let turn = pump_aead_output_completion_turn(&mut driver,
                &mut completion_source,
                8,
                &mut raw_ingress,
                &mut NullIngressRouter,
                0,
                &mut outbound,
                0,
                &mut sink,
                8,
            );
            assert_eq!(turn.summary().completions(), 1);
            assert_eq!(turn.summary().outputs_sent(), 1);
            assert!(turn.drops().is_empty());
        }
        assert!(completion_source.is_empty());
        assert_eq!(
            sink.outputs
                .iter()
                .map(PacketOutput::counter)
                .collect::<Vec<_>>(),
            vec![100, 101, 102]
        );
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 0);
    }

    #[test]
    fn completion_only_turn_retires_out_of_order_completions_in_owner_order() {
        let owner = fmp_owner(81);
        let open_key = 81;
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8));

        let packets: [(u64, &[u8]); 3] = [(100, b"first"), (101, b"second"), (102, b"third")];
        for (counter, payload) in packets {
            driver
                .mover
                .submit_socket_packet(
                    SocketPacket::from_fmp_established_wire(
                        owner,
                        1,
                        OutputTarget::Tun,
                        fmp_encrypted_wire(81, counter, 0, payload, open_key),
                    )
                    .unwrap(),
                )
                .unwrap();
        }

        let mut work = Vec::new();
        assert_eq!(driver.mover.dispatch_available_into(8, &mut work), 3);
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 3);

        let worker = StatelessAeadOpenWorker;
        let mut completions = work
            .drain(..)
            .map(|work| {
                worker.execute(AeadOpenWork::from_crypto_work(work, test_key(open_key)).unwrap())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            completions
                .iter()
                .map(|completion| completion.reservation.counter)
                .collect::<Vec<_>>(),
            vec![100, 101, 102]
        );

        let third = completions.pop().unwrap();
        let first = completions.remove(0);
        let second = completions.remove(0);

        {
            let turn = run_aead_completion_turn(&mut driver, [third], 8);
            assert_eq!(turn.summary().dispatched(), 0);
            assert_eq!(turn.summary().outputs(), 0);
            assert!(turn.outputs().is_empty());
            assert!(turn.drops().is_empty());
        }
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 3);

        {
            let turn = run_aead_completion_turn(&mut driver, [first], 8);
            assert_eq!(turn.summary().dispatched(), 0);
            assert_eq!(turn.summary().outputs(), 1);
            assert_eq!(turn.outputs()[0].counter(), 100);
            assert_eq!(
                &turn.outputs()[0].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
                b"first"
            );
            assert!(turn.drops().is_empty());
        }
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 2);

        {
            let turn = run_aead_completion_turn(&mut driver, [second], 8);
            assert_eq!(turn.summary().dispatched(), 0);
            assert_eq!(turn.summary().outputs(), 2);
            assert_eq!(turn.outputs()[0].counter(), 101);
            assert_eq!(turn.outputs()[1].counter(), 102);
            assert_eq!(
                &turn.outputs()[0].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
                b"second"
            );
            assert_eq!(
                &turn.outputs()[1].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
                b"third"
            );
            assert!(turn.drops().is_empty());
        }
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 0);
    }

    #[test]
    fn completion_only_turn_drops_stale_generation_and_unblocks_newer_completion() {
        let owner = fmp_owner(82);
        let open_key = 82;
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8));

        driver
            .mover
            .submit_socket_packet(
                SocketPacket::from_fmp_established_wire(
                    owner,
                    1,
                    OutputTarget::Tun,
                    fmp_encrypted_wire(82, 100, 0, b"stale", open_key),
                )
                .unwrap(),
            )
            .unwrap();
        let mut old_work = Vec::new();
        assert_eq!(driver.mover.dispatch_available_into(8, &mut old_work), 1);

        driver.owner_mut(owner).unwrap().rekey(2);
        driver
            .mover
            .submit_socket_packet(
                SocketPacket::from_fmp_established_wire(
                    owner,
                    2,
                    OutputTarget::Tun,
                    fmp_encrypted_wire(82, 101, 0, b"new", open_key),
                )
                .unwrap(),
            )
            .unwrap();
        let mut new_work = Vec::new();
        assert_eq!(driver.mover.dispatch_available_into(8, &mut new_work), 1);
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 2);

        let worker = StatelessAeadOpenWorker;
        let old_completion = worker.execute(
            AeadOpenWork::from_crypto_work(old_work.pop().unwrap(), test_key(open_key)).unwrap(),
        );
        let new_completion = worker.execute(
            AeadOpenWork::from_crypto_work(new_work.pop().unwrap(), test_key(open_key)).unwrap(),
        );

        {
            let turn = run_aead_completion_turn(&mut driver, [new_completion], 8);
            assert_eq!(turn.summary().dispatched(), 0);
            assert_eq!(turn.summary().outputs(), 0);
            assert_eq!(turn.summary().drops(), 0);
            assert!(turn.outputs().is_empty());
            assert!(turn.drops().is_empty());
        }
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 2);

        {
            let turn = run_aead_completion_turn(&mut driver, [old_completion], 8);
            assert_eq!(turn.summary().dispatched(), 0);
            assert_eq!(turn.summary().outputs(), 1);
            assert_eq!(turn.summary().drops(), 1);
            assert_eq!(turn.outputs()[0].counter(), 101);
            assert_eq!(
                &turn.outputs()[0].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
                b"new"
            );
            assert_eq!(turn.drops().len(), 1);
            assert_eq!(
                turn.drops()[0].reason(),
                PacketDropReason::StaleCompletionGeneration
            );
            assert_eq!(turn.drops()[0].counter(), Some(100));
        }
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 0);
    }

    #[test]
    fn completion_only_turn_reserves_priority_progress_after_bulk_completion() {
        let owner = fmp_owner(83);
        let seal_key = 83;
        let path = live_path(8300);
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(
            owner,
            OwnerConfig::new(1, 3)
                .with_bulk_in_flight_limit(1)
                .with_next_send_counter(10),
        );
        driver
            .owner_mut(owner)
            .unwrap()
            .set_active_path(path.clone());
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(seal_key), test_key(seal_key)));

        driver
            .mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Bulk,
                830,
                0,
                b"bulk-1".to_vec(),
            ))
            .unwrap();
        let mut seal_work = Vec::new();
        assert_eq!(
            driver
                .mover
                .dispatch_outbound_available_into(1, &mut seal_work),
            1
        );
        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 1);

        driver
            .mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Bulk,
                830,
                0,
                b"bulk-2".to_vec(),
            ))
            .unwrap();
        driver
            .mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Liveness,
                830,
                0,
                b"priority".to_vec(),
            ))
            .unwrap();

        let worker = StatelessAeadSealWorker;
        let completion = worker.execute(
            AeadSealWork::from_outbound_work(seal_work.pop().unwrap(), test_key(seal_key))
                .unwrap(),
        );

        {
            let turn = run_aead_completion_turn(&mut driver, [completion], 1);
            assert_eq!(turn.summary().dispatched(), 1);
            assert_eq!(turn.summary().outputs(), 2);
            assert!(turn.drops().is_empty());
            assert_eq!(turn.outputs()[0].counter(), 10);
            assert_eq!(turn.outputs()[0].target(), OutputTarget::Transport);
            assert_eq!(turn.outputs()[0].path(), Some(path.clone()));
            assert_eq!(open_sealed_output(&turn.outputs()[0], seal_key), b"bulk-1");
            assert_eq!(turn.outputs()[1].counter(), 11);
            assert_eq!(turn.outputs()[1].target(), OutputTarget::Transport);
            assert_eq!(turn.outputs()[1].path(), Some(path));
            assert_eq!(
                open_sealed_output(&turn.outputs()[1], seal_key),
                b"priority"
            );
        }

        assert_eq!(driver.owner_mut(owner).unwrap().in_flight, 0);
        assert_eq!(outbound_queue_lens(&driver.mover), (0, 1));
    }

    #[test]
    fn completion_only_turn_continues_fsp_post_seal_wrap_to_fmp_output() {
        let source = NodeAddr::from_bytes([0x80; 16]);
        let dest = NodeAddr::from_bytes([0x81; 16]);
        let next_hop = NodeAddr::from_bytes([0x82; 16]);
        let fsp_owner = OwnerId::fsp_node(dest);
        let fmp_owner = OwnerId::fmp_node(next_hop);
        let fsp_key = 81;
        let fmp_key = 82;
        let fmp_path = live_path(8200);
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(fsp_owner, OwnerConfig::new(1, 8).with_next_send_counter(50));
        driver.register_owner(fmp_owner, OwnerConfig::new(1, 8).with_next_send_counter(70));
        driver
            .owner_mut(fsp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fsp_key), test_key(fsp_key)));
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fmp_key), test_key(fmp_key)));
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_active_path(fmp_path.clone());

        let wrap = PacketMover2FspWrapRoute::new(fmp_owner, 1, 8282, source, dest)
            .with_ttl(42)
            .with_path_mtu(1280);
        let packet = OutboundPacket::fsp(
            fsp_owner,
            1,
            PacketClass::Liveness,
            0x03,
            b"wake-wrap".to_vec(),
        )
        .with_fsp_cleartext_prefix(empty_fsp_coords_prefix())
        .with_post_seal(OutboundPostSeal::FmpWrap(wrap));

        driver.mover.submit_outbound_packet(packet).unwrap();
        let mut seal_work = Vec::new();
        assert_eq!(
            driver
                .mover
                .dispatch_outbound_available_into(1, &mut seal_work),
            1
        );
        assert_eq!(driver.owner_mut(fsp_owner).unwrap().in_flight, 1);

        let worker = StatelessAeadSealWorker;
        let completion = worker.execute(
            AeadSealWork::from_outbound_work(seal_work.pop().unwrap(), test_key(fsp_key)).unwrap(),
        );

        {
            let turn = run_aead_completion_turn(&mut driver, [completion], 1);
            assert_eq!(turn.summary().outbound_admitted(), 1);
            assert_eq!(turn.summary().dispatched(), 1);
            assert_eq!(turn.summary().outputs(), 1);
            assert!(turn.drops().is_empty());

            let output = &turn.outputs()[0];
            assert_eq!(output.owner(), fmp_owner);
            assert_eq!(output.counter(), 70);
            assert_eq!(output.target(), OutputTarget::Transport);
            assert_eq!(output.path(), Some(fmp_path));

            let fmp_plaintext = open_sealed_output(output, fmp_key);
            assert_eq!(
                fmp_plaintext[0],
                crate::protocol::LinkMessageType::SessionDatagram.to_byte()
            );
            let datagram = crate::protocol::SessionDatagramRef::decode(&fmp_plaintext[1..])
                .expect("wrapped session datagram");
            assert_eq!(datagram.src_addr, source);
            assert_eq!(datagram.dest_addr, dest);
            assert_eq!(datagram.ttl, 42);
            assert_eq!(datagram.path_mtu, 1280);
            assert_eq!(
                open_fsp_wire_payload(datagram.payload, fsp_key),
                b"wake-wrap"
            );
        }

        assert_eq!(driver.owner_mut(fsp_owner).unwrap().in_flight, 0);
        assert_eq!(driver.owner_mut(fmp_owner).unwrap().in_flight, 0);
    }

    #[test]
    fn runtime_turn_driver_reports_admission_and_crypto_drops() {
        let owner = fsp_owner(79);
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(1, 1));
        driver.register_owner(owner, OwnerConfig::new(1, 8));

        let first = SocketPacket::from_fsp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
            fsp_encrypted_wire(10, 0, b"first", 40),
        )
        .unwrap();
        let second = SocketPacket::from_fsp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
            fsp_encrypted_wire(11, 0, b"second", 40),
        )
        .unwrap();

        let turn = run_aead_classified_turn(&mut driver, [first, second], std::iter::empty(), 8);
        assert_eq!(turn.summary().inbound_admitted(), 1);
        assert_eq!(turn.summary().inbound_dropped(), 1);
        assert_eq!(turn.summary().outbound_admitted(), 0);
        assert_eq!(turn.summary().outbound_dropped(), 0);
        assert_eq!(turn.summary().dispatched(), 1);
        assert_eq!(turn.summary().outputs(), 0);
        assert_eq!(turn.summary().drops(), 2);
        assert!(turn.outputs().is_empty());

        let admission_drop = turn
            .drops()
            .iter()
            .find(|drop| {
                drop.reason() == PacketDropReason::Admission(AdmissionDropReason::BulkFull)
            })
            .expect("admission drop");
        assert_eq!(admission_drop.owner(), owner);
        assert_eq!(admission_drop.counter(), Some(11));
        assert_eq!(admission_drop.ingress_seq(), None);
        assert_eq!(admission_drop.lane(), Lane::Bulk);

        let crypto_drop = turn
            .drops()
            .iter()
            .find(|drop| drop.reason() == PacketDropReason::CryptoFailed)
            .expect("crypto drop");
        assert_eq!(crypto_drop.owner(), owner);
        assert_eq!(crypto_drop.counter(), Some(10));
        assert_eq!(crypto_drop.ingress_seq(), Some(0));
        assert_eq!(crypto_drop.lane(), Lane::Bulk);
    }

    #[test]
    fn runtime_turn_driver_reuses_work_and_output_buffers() {
        let owner = fsp_owner(80);
        let key = 41;
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(20));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));

        let inbound = SocketPacket::from_fsp_established_wire(
            owner,
            1,
            OutputTarget::Endpoint,
            fsp_encrypted_wire(50, 0, b"in", key),
        )
        .unwrap();
        let outbound = OutboundPacket::fsp(owner, 1, PacketClass::Bulk, 0, b"out".to_vec());
        {
            let turn = run_aead_classified_turn(&mut driver, [inbound], [outbound], 8);
            assert_eq!(turn.outputs().len(), 2);
            assert!(turn.drops().is_empty());
        }

        let capacities = (
            driver.open_work.capacity(),
            driver.seal_work.capacity(),
            driver.raw_ingress_drops.capacity(),
            driver.output_drops.capacity(),
            driver.outputs.capacity(),
            driver.drops.capacity(),
        );
        let turn = run_aead_classified_turn(&mut driver, std::iter::empty(), std::iter::empty(), 8);
        assert_eq!(turn.summary(), PacketMover2RuntimeSummary::default());
        assert!(turn.outputs().is_empty());
        assert!(turn.drops().is_empty());
        assert_eq!(
            capacities,
            (
                driver.open_work.capacity(),
                driver.seal_work.capacity(),
                driver.raw_ingress_drops.capacity(),
                driver.output_drops.capacity(),
                driver.outputs.capacity(),
                driver.drops.capacity(),
            )
        );
    }

    struct FixedIngressRouter {
        route: Option<PacketMover2IngressRoute>,
    }

    impl PacketMover2IngressRouter for FixedIngressRouter {
        fn route(
            &mut self,
            packet: &PacketMover2RawIngress,
            header: PacketMover2IngressHeader,
        ) -> Option<PacketMover2IngressRoute> {
            assert_eq!(packet.transport_id(), TransportId::new(5));
            assert_eq!(
                packet.remote_addr(),
                &TransportAddr::from_string("198.51.100.9:9000")
            );
            assert_eq!(packet.path(), live_path(9005));
            assert_eq!(packet.activity_tick(), Some(ActivityTick::new(123_456)));
            assert_eq!(
                packet.payload_len(),
                FMP_ESTABLISHED_HEADER_SIZE + b"raw-in".len() + AEAD_TAG_SIZE
            );
            assert_eq!(packet.protocol(), PacketProtocol::Fmp);
            assert!(matches!(header, PacketMover2IngressHeader::Fmp(_)));
            assert_eq!(header.counter(), 1200);
            self.route
        }
    }

    struct NullIngressRouter;

    impl PacketMover2IngressRouter for NullIngressRouter {
        fn route(
            &mut self,
            _packet: &PacketMover2RawIngress,
            _header: PacketMover2IngressHeader,
        ) -> Option<PacketMover2IngressRoute> {
            None
        }
    }

    #[derive(Default)]
    struct RecordingOutputSink {
        outputs: Vec<PacketOutput>,
        fail_counter: Option<u64>,
    }

    impl PacketMover2OutputSink for RecordingOutputSink {
        fn send(&mut self, output: PacketOutput) -> Result<(), PacketMover2OutputError> {
            if Some(output.counter) == self.fail_counter {
                return Err(PacketMover2OutputError::Backpressure);
            }
            self.outputs.push(output);
            Ok(())
        }
    }

    #[derive(Default)]
    struct BatchRecordingOutputSink {
        batch_calls: usize,
        outputs: Vec<PacketOutput>,
    }

    impl PacketMover2OutputSink for BatchRecordingOutputSink {
        fn send(&mut self, _output: PacketOutput) -> Result<(), PacketMover2OutputError> {
            panic!("batch sink must not use per-output send")
        }

        fn send_batch<I>(&mut self, outputs: I, drops: &mut Vec<PacketMover2OutputDrop>) -> usize
        where
            I: IntoIterator<Item = PacketOutput>,
        {
            self.batch_calls += 1;
            let drops_before = drops.len();
            let mut sent = 0;
            for output in outputs {
                assert_eq!(output.payload_len(), output.payload().len());
                self.outputs.push(output);
                sent += 1;
            }
            assert_eq!(drops.len(), drops_before);
            sent
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct LiveOutputRecord {
        owner: OwnerId,
        counter: u64,
        ingress_seq: u64,
        payload: Vec<u8>,
    }

    impl LiveOutputRecord {
        fn from_opened(output: &PacketOutput, payload: &[u8]) -> Self {
            Self {
                owner: output.owner(),
                counter: output.counter(),
                ingress_seq: output.ingress_seq(),
                payload: payload.to_vec(),
            }
        }
    }

    #[derive(Default)]
    struct LiveTunRecorder {
        outputs: Vec<LiveOutputRecord>,
    }

    impl PacketMover2TunOutput for LiveTunRecorder {
        fn send_tun(
            &mut self,
            output: &PacketOutput,
            payload: PacketBuffer,
        ) -> Result<(), PacketMover2OutputError> {
            let payload = payload.into_vec();
            self.outputs
                .push(LiveOutputRecord::from_opened(output, &payload));
            Ok(())
        }
    }

    #[derive(Default)]
    struct LiveEndpointRecorder {
        outputs: Vec<LiveOutputRecord>,
    }

    impl PacketMover2EndpointOutput for LiveEndpointRecorder {
        fn send_endpoint(
            &mut self,
            output: &PacketOutput,
            payload: PacketBuffer,
        ) -> Result<(), PacketMover2OutputError> {
            let payload = payload.into_vec();
            self.outputs
                .push(LiveOutputRecord::from_opened(output, &payload));
            Ok(())
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct LiveTransportRecord {
        transport_id: TransportId,
        remote_addr: TransportAddr,
        owner: OwnerId,
        counter: u64,
        ingress_seq: u64,
        payload: Vec<u8>,
    }

    #[derive(Default)]
    struct LiveTransportRecorder {
        outputs: Vec<LiveTransportRecord>,
    }

    impl PacketMover2TransportOutput for LiveTransportRecorder {
        fn send_transport(
            &mut self,
            transport_id: TransportId,
            remote_addr: TransportAddr,
            output: PacketOutput,
        ) -> Result<(), PacketMover2OutputError> {
            self.outputs.push(LiveTransportRecord {
                transport_id,
                remote_addr,
                owner: output.owner(),
                counter: output.counter(),
                ingress_seq: output.ingress_seq(),
                payload: output.payload().to_vec(),
            });
            Ok(())
        }
    }

    struct SimpleIngressRouter {
        owner: OwnerId,
        generation: u64,
        class: PacketClass,
        output: OutputTarget,
    }

    impl PacketMover2IngressRouter for SimpleIngressRouter {
        fn route(
            &mut self,
            _packet: &PacketMover2RawIngress,
            _header: PacketMover2IngressHeader,
        ) -> Option<PacketMover2IngressRoute> {
            Some(
                PacketMover2IngressRoute::new(self.owner, self.generation, self.output)
                    .with_class(self.class),
            )
        }
    }
