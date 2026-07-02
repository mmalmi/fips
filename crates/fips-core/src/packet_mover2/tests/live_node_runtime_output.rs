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
    let mut completions = VecDeque::<CryptoCompletion>::new();

    let first = pump_aead_output_completion_turn(
        &mut driver,
        &mut completions,
        0,
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

    let second = pump_aead_output_completion_turn(
        &mut driver,
        &mut completions,
        0,
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
