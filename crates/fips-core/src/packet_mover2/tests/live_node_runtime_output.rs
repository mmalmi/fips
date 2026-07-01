    #[test]
    fn runtime_pump_output_turn_drains_bounded_sources_without_vec_staging() {
        let owner = fmp_owner(86);
        let open_key = 75;
        let seal_key = 76;
        let path = live_path(8600);
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(3, 8).with_next_send_counter(700));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));

        let mut raw_source = VecDeque::from([
            PacketMover2RawIngress::from_received(
                PacketProtocol::Fmp,
                path.clone(),
                ReceivedPacket::with_timestamp(
                    TransportId::new(6),
                    TransportAddr::from_string("198.51.100.10:9000"),
                    fmp_encrypted_wire(86, 1300, 0, b"raw-a", open_key),
                    1,
                ),
            ),
            PacketMover2RawIngress::from_received(
                PacketProtocol::Fmp,
                path.clone(),
                ReceivedPacket::with_timestamp(
                    TransportId::new(6),
                    TransportAddr::from_string("198.51.100.10:9000"),
                    fmp_encrypted_wire(86, 1301, 0, b"raw-b", open_key),
                    2,
                ),
            ),
        ]);

        let mut outbound_source = VecDeque::from([
            OutboundPacket::fmp(owner, 3, PacketClass::Bulk, 860, 0, b"out-a".to_vec()),
            OutboundPacket::fmp(owner, 3, PacketClass::Bulk, 860, 0, b"out-b".to_vec()),
        ]);

        let mut router = SimpleIngressRouter {
            owner,
            generation: 3,
            class: PacketClass::Liveness,
            output: OutputTarget::Tun,
        };
        let mut sink = BatchRecordingOutputSink::default();

        let first = pump_aead_output_turn(&mut driver,
            &mut raw_source,
            &mut router,
            1,
            &mut outbound_source,
            1,
            &mut sink,
            8,
        );
        assert_eq!(first.summary().raw_ingress_dropped(), 0);
        assert_eq!(first.summary().inbound_admitted(), 1);
        assert_eq!(first.summary().outbound_admitted(), 1);
        assert_eq!(first.summary().dispatched(), 2);
        assert_eq!(first.summary().outputs(), 2);
        assert_eq!(first.summary().outputs_sent(), 2);
        assert!(first.outputs().is_empty());
        assert!(first.output_drops().is_empty());
        assert_eq!(raw_source.len(), 1);
        assert_eq!(outbound_source.len(), 1);
        assert_eq!(sink.batch_calls, 1);

        let second = pump_aead_output_turn(&mut driver,
            &mut raw_source,
            &mut router,
            1,
            &mut outbound_source,
            1,
            &mut sink,
            8,
        );
        assert_eq!(second.summary().inbound_admitted(), 1);
        assert_eq!(second.summary().outbound_admitted(), 1);
        assert_eq!(second.summary().outputs_sent(), 2);
        assert!(second.outputs().is_empty());
        assert!(second.output_drops().is_empty());
        assert_eq!(raw_source.len(), 0);
        assert_eq!(outbound_source.len(), 0);
        assert_eq!(sink.batch_calls, 2);
        assert_eq!(
            sink.outputs
                .iter()
                .map(PacketOutput::counter)
                .collect::<Vec<_>>(),
            vec![1300, 700, 1301, 701]
        );
        assert_eq!(
            sink.outputs
                .iter()
                .map(PacketOutput::target)
                .collect::<Vec<_>>(),
            vec![
                OutputTarget::Tun,
                OutputTarget::Transport,
                OutputTarget::Tun,
                OutputTarget::Transport,
            ]
        );
        assert_eq!(
            sink.outputs
                .iter()
                .map(PacketOutput::path)
                .collect::<Vec<_>>(),
            vec![None, Some(path.clone()), None, Some(path)]
        );
        assert_eq!(open_sealed_output(&sink.outputs[1], seal_key), b"out-a");
        assert_eq!(open_sealed_output(&sink.outputs[3], seal_key), b"out-b");
    }

    #[test]
    fn runtime_output_sink_preserves_live_transport_path() {
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x87; 16]));
        let key = 87;
        let transport_id = TransportId::new(87);
        let remote_addr = TransportAddr::from_string("198.51.100.87:9000");
        let path = TransportPath::live(transport_id, remote_addr.clone());
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(8700));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_active_path(path.clone());
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));
        let outbound = OutboundPacket::fmp(
            owner,
            1,
            PacketClass::Liveness,
            870,
            0,
            b"live-path".to_vec(),
        );
        let mut sink = RecordingOutputSink::default();

        let turn =
            run_aead_classified_output_turn(&mut driver, std::iter::empty(), [outbound], &mut sink, 8);

        assert_eq!(turn.summary().outputs(), 1);
        assert_eq!(turn.summary().outputs_sent(), 1);
        assert!(turn.outputs().is_empty());
        assert!(turn.output_drops().is_empty());
        assert_eq!(sink.outputs.len(), 1);
        let output_path = sink.outputs[0].path().expect("transport output path");
        assert_eq!(output_path.transport_id(), Some(transport_id));
        assert_eq!(output_path.remote_addr(), Some(&remote_addr));
        assert_eq!(open_sealed_output(&sink.outputs[0], key), b"live-path");
    }

    #[test]
    fn runtime_output_sink_sends_ordered_outputs_once() {
        let owner = fmp_owner(83);
        let key = 71;
        let path = live_path(8300);
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(400));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_active_path(path.clone());
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));

        let inbound_tun = SocketPacket::from_fmp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
            fmp_encrypted_wire(83, 10, 0, b"tun", key),
        )
        .unwrap();
        let inbound_endpoint = SocketPacket::from_fmp_established_wire(
            owner,
            1,
            OutputTarget::Endpoint,
            fmp_encrypted_wire(83, 11, 0, b"endpoint", key),
        )
        .unwrap();
        let outbound =
            OutboundPacket::fmp(owner, 1, PacketClass::Bulk, 830, 0, b"transport".to_vec());
        let mut sink = RecordingOutputSink::default();

        let turn = run_aead_classified_output_turn(&mut driver,
            [inbound_tun, inbound_endpoint],
            [outbound],
            &mut sink,
            8,
        );
        assert_eq!(turn.summary().outputs(), 3);
        assert_eq!(turn.summary().outputs_sent(), 3);
        assert_eq!(turn.summary().outputs_dropped(), 0);
        assert!(turn.outputs().is_empty());
        assert!(turn.output_drops().is_empty());
        assert_eq!(
            sink.outputs
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
            sink.outputs
                .iter()
                .map(|output| output.counter)
                .collect::<Vec<_>>(),
            vec![10, 11, 400]
        );
        assert_eq!(sink.outputs[2].path(), Some(path));
        assert_eq!(open_sealed_output(&sink.outputs[2], key), b"transport");
    }

    #[test]
    fn runtime_keeps_opened_fsp_data_on_bulk_lane() {
        let owner = fsp_owner(88);
        let key = 88;
        let payload = b"small-data-payload".to_vec();
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));
        let packet = SocketPacket::from_fsp_established_wire(
            owner,
            1,
            OutputTarget::Tun,
            fsp_encrypted_wire(88, 0, &payload, key),
        )
        .unwrap();
        assert_eq!(packet.lane(), Lane::Bulk);
        let mut sink = RecordingOutputSink::default();

        let turn =
            run_aead_classified_output_turn(&mut driver, [packet], std::iter::empty(), &mut sink, 8);

        assert_eq!(turn.summary().outputs_sent(), 1);
        assert!(turn.output_drops().is_empty());
        assert_eq!(sink.outputs.len(), 1);
        assert_eq!(sink.outputs[0].lane(), Lane::Bulk);
        assert_eq!(sink.outputs[0].target(), OutputTarget::Tun);
        assert_eq!(sink.outputs[0].opened_payload(), Some(payload.as_slice()));
    }

    #[test]
    fn runtime_output_sink_reports_failures_without_retrying() {
        let owner = fsp_owner(84);
        let key = 72;
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));
        let packets = [
            SocketPacket::from_fsp_established_wire(
                owner,
                1,
                OutputTarget::Tun,
                fsp_encrypted_wire(20, 0, b"first", key),
            )
            .unwrap(),
            SocketPacket::from_fsp_established_wire(
                owner,
                1,
                OutputTarget::Endpoint,
                fsp_encrypted_wire(21, 0, b"second", key),
            )
            .unwrap(),
            SocketPacket::from_fsp_established_wire(
                owner,
                1,
                OutputTarget::Transport,
                fsp_encrypted_wire(22, 0, b"third", key),
            )
            .unwrap(),
        ];
        let mut sink = RecordingOutputSink {
            outputs: Vec::new(),
            fail_counter: Some(21),
        };

        let turn =
            run_aead_classified_output_turn(&mut driver, packets, std::iter::empty(), &mut sink, 8);
        assert_eq!(turn.summary().outputs(), 3);
        assert_eq!(turn.summary().outputs_sent(), 2);
        assert_eq!(turn.summary().outputs_dropped(), 1);
        assert!(turn.outputs().is_empty());
        assert_eq!(
            sink.outputs
                .iter()
                .map(|output| output.counter)
                .collect::<Vec<_>>(),
            vec![20, 22]
        );
        assert_eq!(turn.output_drops().len(), 1);
        let drop = &turn.output_drops()[0];
        assert_eq!(drop.owner(), owner);
        assert_eq!(drop.counter(), 21);
        assert_eq!(drop.ingress_seq(), 1);
        assert_eq!(drop.target(), OutputTarget::Endpoint);
        assert_eq!(drop.reason(), PacketMover2OutputError::Backpressure);
        assert_eq!(drop.payload_len(), FSP_HEADER_SIZE + b"second".len());
    }
