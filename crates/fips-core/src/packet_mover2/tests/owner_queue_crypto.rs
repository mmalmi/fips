    #[test]
    fn happy_path_dispatches_fmp_and_fsp_packets() {
        let fmp = OwnerId::fmp(7);
        let fsp = OwnerId::fsp(7);
        let mut mover = mover();
        mover.register_owner(fmp, OwnerConfig::new(1, 8));
        mover.register_owner(fsp, OwnerConfig::new(1, 8));

        mover
            .submit_socket_packet(packet(fsp, 1, 10, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap();
        mover
            .submit_socket_packet(packet(
                fmp,
                1,
                20,
                PacketClass::Control,
                OutputTarget::Transport,
            ))
            .unwrap();

        let work = mover.dispatch_available(8);
        assert_eq!(work.len(), 2);
        assert_eq!(work[0].packet.owner, fmp);
        assert_eq!(work[1].packet.owner, fsp);

        let mut retired = Vec::new();
        for item in work {
            let completion = mover.execute_work(item);
            retired.extend(mover.retire_completion(completion));
        }
        let outputs = outputs(retired);
        assert_eq!(outputs[0].target, OutputTarget::Transport);
        assert_eq!(outputs[1].target, OutputTarget::Tun);
        assert_eq!(outputs[0].payload, vec![20]);
        assert_eq!(outputs[1].payload, vec![10]);
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

        let owner = OwnerId::fmp(77);
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
            target: OutputTarget::SessionIngress { local_addr },
            source_path: Some(source_path.clone()),
            previous_hop: None,
            ce_flag: false,
            path: None,
            activity_tick: Some(activity_tick),
            source_wire_len: Some(payload.len()),
            payload: payload.into(),
        };

        let raw = packet_mover2_session_ingress_from_output(&output, local_addr)
            .expect("session datagram should route to sourced FSP ingress");

        assert_eq!(raw.protocol, PacketProtocol::Fsp);
        assert_eq!(raw.transport_id, transport_id);
        assert_eq!(raw.remote_addr, remote_addr);
        assert_eq!(raw.path, source_path);
        assert_eq!(raw.fsp_source, Some(source_addr));
        assert_eq!(raw.activity_tick, Some(activity_tick));
        assert_eq!(raw.payload.as_ref(), fsp_wire.as_slice());
    }

    #[test]
    fn session_handoff_delivers_opened_fsp_endpoint_payload() {
        let local_addr = NodeAddr::from_bytes([0x51; 16]);
        let source_addr = NodeAddr::from_bytes([0x52; 16]);
        let endpoint_payload = b"endpoint-body";
        let inner = crate::node::session_wire::fsp_prepend_inner_header(
            51_000,
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0x03,
            endpoint_payload,
        );
        let mut payload = fsp_wire(510, 0);
        payload.truncate(FSP_HEADER_SIZE);
        payload.extend_from_slice(&inner);
        let output = PacketOutput {
            owner: OwnerId::fsp_node(source_addr),
            counter: 510,
            ingress_seq: 51,
            target: OutputTarget::SessionPayload { local_addr },
            source_path: None,
            previous_hop: None,
            ce_flag: false,
            path: None,
            activity_tick: Some(ActivityTick::new(51_000)),
            source_wire_len: Some(payload.len()),
            payload: payload.into(),
        };

        assert_eq!(
            packet_mover2_fsp_payload_delivery(&output, local_addr),
            Ok(PacketMover2FspPayloadDelivery::Endpoint(
                endpoint_payload.to_vec(),
            ))
        );
    }

    #[test]
    fn priority_admission_keeps_reserved_progress_when_bulk_is_full() {
        let owner = OwnerId::fsp(1);
        let mut mover = PacketMover2::new(AdmissionConfig::new(2, 1), CopyCryptoWorker);
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
        assert_eq!(mover.queue_lens(), (1, 1));
        let work = mover.dispatch_available(1);
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
    fn turn_runner_batches_admission_and_reuses_work_scratch() {
        let owner = OwnerId::fsp(11);
        let mut mover = PacketMover2::new(AdmissionConfig::new(2, 4), CopyCryptoWorker);
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        let summary = mover.submit_socket_batch([
            packet(owner, 1, 1, PacketClass::Bulk, OutputTarget::Tun),
            packet(owner, 1, 2, PacketClass::Liveness, OutputTarget::Endpoint),
            packet(owner, 1, 3, PacketClass::Bulk, OutputTarget::Transport),
        ]);
        assert_eq!(summary.admitted(), 3);
        assert_eq!(summary.dropped(), 0);

        let mut work = Vec::with_capacity(8);
        let turn = mover.run_available_with_scratch(2, &mut work);
        assert!(work.is_empty());
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

        let turn = mover.run_available_with_scratch(2, &mut work);
        assert_eq!(turn.dispatched(), 1);
        assert_eq!(turn.outputs()[0].counter, 3);
        assert_eq!(work.capacity(), 8);
    }

    #[test]
    fn owner_retires_worker_completions_in_owner_order() {
        let owner = OwnerId::fsp(9);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        for counter in 1..=3 {
            mover
                .submit_socket_packet(packet(
                    owner,
                    1,
                    counter,
                    PacketClass::Bulk,
                    OutputTarget::Tun,
                ))
                .unwrap();
        }

        let work = mover.dispatch_available(8);
        assert_eq!(
            work.iter().map(CryptoWork::order).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );

        let completion_2 = mover.execute_work(work[2].clone());
        assert!(mover.retire_completion(completion_2).is_empty());

        let completion_0 = mover.execute_work(work[0].clone());
        let retired = outputs(mover.retire_completion(completion_0));
        assert_eq!(
            retired
                .iter()
                .map(|output| output.counter)
                .collect::<Vec<_>>(),
            vec![1]
        );

        let completion_1 = mover.execute_work(work[1].clone());
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
    fn owner_rejects_replay_and_in_flight_overflow_at_reservation() {
        let owner = OwnerId::fsp(3);
        let mut mover = PacketMover2::new(AdmissionConfig::new(4, 4), CopyCryptoWorker);
        mover.register_owner(owner, OwnerConfig::new(1, 1));

        mover
            .submit_socket_packet(packet(owner, 1, 8, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap();
        mover
            .submit_socket_packet(packet(owner, 1, 9, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap();
        mover
            .submit_socket_packet(packet(owner, 1, 8, PacketClass::Bulk, OutputTarget::Tun))
            .unwrap();

        let work = mover.dispatch_available(8);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].packet.counter, 8);
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight(), 1);

        let drops = mover.drain_drops();
        assert_eq!(drops[0].owner(), owner);
        assert_eq!(drops[0].reason(), PacketDropReason::OwnerInFlightFull);
        assert_eq!(drops[0].counter(), Some(9));
        assert_eq!(drops[0].ingress_seq(), Some(1));
        assert_eq!(drops[0].lane(), Lane::Bulk);
        assert_eq!(drops[1].owner(), owner);
        assert_eq!(drops[1].reason(), PacketDropReason::Replay);
        assert_eq!(drops[1].counter(), Some(8));
        assert_eq!(drops[1].ingress_seq(), Some(2));
        assert_eq!(drops[1].lane(), Lane::Bulk);

        let completion = mover.execute_work(work[0].clone());
        assert_eq!(outputs(mover.retire_completion(completion)).len(), 1);
        assert_eq!(mover.owner_mut(owner).unwrap().in_flight(), 0);
    }

    #[test]
    fn stale_generation_is_dropped_before_dispatch_and_at_retire() {
        let owner = OwnerId::fmp(4);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        mover
            .submit_socket_packet(packet(
                owner,
                1,
                1,
                PacketClass::Control,
                OutputTarget::Transport,
            ))
            .unwrap();

        let mut work = mover.dispatch_available(8);
        assert_eq!(work.len(), 1);
        mover.owner_mut(owner).unwrap().rekey(2);
        let stale_retire = mover.retire_completion(mover.execute_work(work.pop().unwrap()));
        let stale_retire_drops = drops(stale_retire);
        assert_eq!(
            stale_retire_drops[0].reason,
            PacketDropReason::StaleCompletionGeneration
        );

        mover
            .submit_socket_packet(packet(
                owner,
                1,
                2,
                PacketClass::Control,
                OutputTarget::Transport,
            ))
            .unwrap();
        mover
            .submit_socket_packet(packet(
                owner,
                2,
                3,
                PacketClass::Control,
                OutputTarget::Transport,
            ))
            .unwrap();
        let work = mover.dispatch_available(8);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].packet.counter, 3);

        let drops = mover.drain_drops();
        assert!(drops.iter().any(
            |drop| drop.reason == PacketDropReason::StaleGeneration && drop.counter == Some(2)
        ));
    }

    #[test]
    fn tun_endpoint_and_transport_outputs_keep_owner_order() {
        let owner = OwnerId::fsp(42);
        let mut mover = mover();
        mover.register_owner(owner, OwnerConfig::new(1, 8));
        let targets = [
            OutputTarget::Tun,
            OutputTarget::Endpoint,
            OutputTarget::Transport,
        ];
        for (idx, target) in targets.into_iter().enumerate() {
            mover
                .submit_socket_packet(packet(owner, 1, idx as u64 + 1, PacketClass::Bulk, target))
                .unwrap();
        }

        let work = mover.dispatch_available(8);
        let mut retired = Vec::new();
        for work in work.into_iter().rev() {
            retired.extend(mover.retire_completion(mover.execute_work(work)));
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
        let fmp = OwnerId::fmp(77);
        let fsp = OwnerId::fsp(88);
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
        for work in mover.dispatch_available(8) {
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
        let owner = OwnerId::fmp(91);
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
        let work = mover.dispatch_available(8);
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
        let fmp = OwnerId::fmp(77);
        let fsp = OwnerId::fsp(88);
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
        for work in mover.dispatch_outbound_available(8) {
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
    fn outbound_owner_reserves_counters_after_priority_overtakes_bulk() {
        let owner = OwnerId::fsp(33);
        let mut mover = PacketMover2::new(AdmissionConfig::new(2, 1), CopyCryptoWorker);
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
        assert_eq!(mover.outbound_queue_lens(), (1, 1));

        let work = mover.dispatch_outbound_available(8);
        assert_eq!(work.len(), 2);
        assert_eq!(work[0].packet.class, PacketClass::Liveness);
        assert_eq!(work[0].reservation.counter, 40);
        assert_eq!(work[1].packet.class, PacketClass::Bulk);
        assert_eq!(work[1].reservation.counter, 41);
        assert_eq!(mover.owner_mut(owner).unwrap().next_send_counter(), 42);

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
        let owner = OwnerId::fsp(34);
        let authority = crate::noise::SendCounterAuthority::new_for_test(90);
        let mut mover = PacketMover2::new(AdmissionConfig::new(4, 4), CopyCryptoWorker);
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

        let work = mover.dispatch_outbound_available(8);
        assert_eq!(work.len(), 2);
        assert_eq!(work[0].packet.class, PacketClass::Liveness);
        assert_eq!(work[0].reservation.counter, 91);
        assert_eq!(work[1].packet.class, PacketClass::Bulk);
        assert_eq!(work[1].reservation.counter, 92);
        assert_eq!(mover.owner_mut(owner).unwrap().next_send_counter(), 93);
        assert_eq!(authority.reserve().unwrap(), 93);
    }

    #[test]
    fn outbound_completions_retire_in_owner_order() {
        let owner = OwnerId::fmp(44);
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

        let work = mover.dispatch_outbound_available(8);
        assert_eq!(
            work.iter()
                .map(OutboundCryptoWork::order)
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
        let fmp_owner = OwnerId::fmp(12);
        let fsp_owner = OwnerId::fsp(12);
        let mut fmp_state =
            OwnerState::new(fmp_owner, OwnerConfig::new(1, 8).with_next_send_counter(1));
        let mismatch = OutboundPacket::fsp(fmp_owner, 1, PacketClass::Bulk, 0, b"body".to_vec());
        let mismatch_work = OutboundCryptoWork {
            reservation: fmp_state.reserve_outbound(&mismatch, 0).unwrap(),
            packet: mismatch,
        };
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
        let plaintext_work = OutboundCryptoWork {
            reservation: fsp_state.reserve_outbound(&plaintext_fsp, 0).unwrap(),
            packet: plaintext_fsp,
        };
        assert_eq!(
            AeadSealWork::from_outbound_work(plaintext_work, test_key(1)).err(),
            Some(WireBuildError::PlaintextFsp)
        );
    }
