#[test]
fn wrapped_fsp_completion_refreshes_fmp_send_context_after_rekey() {
    let source = NodeAddr::from_bytes([0x90; 16]);
    let dest = NodeAddr::from_bytes([0x91; 16]);
    let next_hop = NodeAddr::from_bytes([0x92; 16]);
    let fsp_owner = OwnerId::fsp_node(dest);
    let fmp_owner = OwnerId::fmp_node(next_hop);
    let fsp_key = 91;
    let old_fmp_key = 92;
    let new_fmp_key = 93;
    let fmp_path = live_path(9200);
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(fsp_owner, OwnerConfig::new(1, 8).with_next_send_counter(50));
    driver.register_owner(
        fmp_owner,
        OwnerConfig::new(1, 8)
            .with_next_send_counter(70)
            .with_fmp_send_headers(8282, 0),
    );
    driver
        .owner_mut(fsp_owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(fsp_key), test_key(fsp_key)));
    driver
        .owner_mut(fmp_owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(
            test_key(old_fmp_key),
            test_key(old_fmp_key),
        ));
    driver
        .owner_mut(fmp_owner)
        .unwrap()
        .set_active_path(fmp_path.clone());

    let wrap = DataplaneFspWrapRoute::new(fmp_owner, 1, 8282, source, dest)
        .with_ttl(42)
        .with_path_mtu(1280);
    driver
        .owner_mut(fsp_owner)
        .unwrap()
        .set_fsp_wrap_route(Some(wrap));
    let packet = OutboundPacket::fsp(
        fsp_owner,
        1,
        PacketClass::Liveness,
        0x03,
        PacketBuffer::new(b"wake-wrap".to_vec()),
    )
    .with_fsp_cleartext_prefix(empty_fsp_coords_prefix());

    driver.mover.submit_outbound_packet(packet).unwrap();
    let mut seal_work = dispatch_outbound_available(&mut driver.mover, 1);
    assert_eq!(seal_work.len(), 1);

    let completion = complete_test_seal_work(seal_work.pop().unwrap(), fsp_key);

    assert!(
        driver.owner_mut(fmp_owner).unwrap().install_fmp_session(
            OwnerConfig::new(2, 8)
                .with_next_send_counter(90)
                .with_fmp_send_headers(9292, crate::node::wire::FLAG_KEY_EPOCH),
            OwnerCryptoKeys::new(test_key(new_fmp_key), test_key(new_fmp_key)),
        )
    );
    driver
        .owner_mut(fmp_owner)
        .unwrap()
        .set_active_path(fmp_path.clone());

    let turn = run_aead_completion_turn(&mut driver, [completion], 1);
    assert_eq!(turn.summary().outbound_admitted(), 1);
    assert_eq!(turn.summary().dispatched(), 1);
    assert_eq!(turn.summary().outputs(), 1);
    assert!(turn.drops().is_empty());

    let output = &turn.outputs()[0];
    assert_eq!(output.owner(), fmp_owner);
    assert_eq!(output.counter(), 0);
    assert_eq!(output.path.clone(), Some(fmp_path));
    let header = FmpWireHeader::parse(output.payload()).unwrap();
    assert_eq!(header.receiver_idx(), 9292);
    assert_eq!(header.flags(), crate::node::wire::FLAG_KEY_EPOCH);

    let fmp_plaintext = open_sealed_output(output, new_fmp_key);
    let datagram = crate::protocol::SessionDatagramRef::decode(&fmp_plaintext[1..])
        .expect("wrapped session datagram");
    assert_eq!(
        open_fsp_wire_payload(datagram.payload, fsp_key),
        b"wake-wrap"
    );
    assert_eq!(driver.owner_mut(fsp_owner).unwrap().in_flight, 0);
    assert_eq!(driver.owner_mut(fmp_owner).unwrap().in_flight, 0);
}

#[test]
fn failed_owner_routed_fsp_wrap_releases_inner_owner_only() {
    let source = NodeAddr::from_bytes([0x83; 16]);
    let dest = NodeAddr::from_bytes([0x84; 16]);
    let next_hop = NodeAddr::from_bytes([0x85; 16]);
    let fsp_owner = OwnerId::fsp_node(dest);
    let fmp_owner = OwnerId::fmp_node(next_hop);
    let fmp_path = live_path(8500);
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
    driver.register_owner(fsp_owner, OwnerConfig::new(1, 8).with_next_send_counter(50));
    driver.register_owner(fmp_owner, OwnerConfig::new(1, 8).with_next_send_counter(70));
    driver
        .owner_mut(fsp_owner)
        .unwrap()
        .set_crypto_keys(OwnerCryptoKeys::new(test_key(84), test_key(84)));
    driver
        .owner_mut(fmp_owner)
        .unwrap()
        .set_active_path(fmp_path);

    let wrap = DataplaneFspWrapRoute::new(fmp_owner, 1, 8585, source, dest)
        .with_ttl(42)
        .with_path_mtu(1280);
    driver
        .owner_mut(fsp_owner)
        .unwrap()
        .set_fsp_wrap_route(Some(wrap));
    let packet = OutboundPacket::fsp(
        fsp_owner,
        1,
        PacketClass::Bulk,
        0x03,
        PacketBuffer::new(b"failed-wrap".to_vec()),
    )
    .with_fsp_cleartext_prefix(empty_fsp_coords_prefix());

    driver.mover.submit_outbound_packet(packet).unwrap();
    let mut seal_work = dispatch_outbound_available(&mut driver.mover, 1);
    assert_eq!(seal_work.len(), 1);
    let work = seal_work.pop().unwrap();
    assert_eq!(driver.owner_mut(fsp_owner).unwrap().in_flight, 1);
    assert_eq!(driver.owner_mut(fmp_owner).unwrap().in_flight, 0);

    let completion = failed_crypto_completion(work.reservation, CryptoFailureKind::Seal);
    let turn = run_aead_completion_turn(&mut driver, [completion], 1);
    assert_eq!(turn.summary().completions(), 1);
    assert_eq!(turn.summary().outputs(), 0);
    assert_eq!(turn.drops().len(), 1);
    assert!(
        turn.drops()
            .iter()
            .all(|drop| drop.reason() == PacketDropReason::CryptoFailed)
    );
    assert_eq!(driver.owner_mut(fsp_owner).unwrap().in_flight, 0);
    assert_eq!(driver.owner_mut(fmp_owner).unwrap().in_flight, 0);
}

#[test]
fn runtime_turn_driver_reports_admission_and_crypto_drops() {
    let owner = fsp_owner(79);
    let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(1, 1));
    driver.register_owner(owner, OwnerConfig::new(1, 8));

    let first = fsp_socket_packet(
        owner,
        1,
        OutputTarget::Transport,
        fsp_encrypted_wire(10, 0, b"first", 40),
    )
    .unwrap();
    let second = fsp_socket_packet(
        owner,
        1,
        OutputTarget::Transport,
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
        .find(|drop| drop.reason() == PacketDropReason::Admission(AdmissionDropReason::BulkFull))
        .expect("admission drop");
    assert_eq!(admission_drop.owner(), owner);
    assert_eq!(admission_drop.counter(), Some(11));

    let crypto_drop = turn
        .drops()
        .iter()
        .find(|drop| drop.reason() == PacketDropReason::CryptoFailed)
        .expect("crypto drop");
    assert_eq!(crypto_drop.owner(), owner);
    assert_eq!(crypto_drop.counter(), Some(10));
}

struct FixedIngressRouter {
    route: Option<DataplaneIngressRoute>,
}

impl DataplaneIngressRouter for FixedIngressRouter {
    fn route(
        &mut self,
        packet: &DataplaneRawIngress,
        header: DataplaneIngressHeader,
    ) -> Option<DataplaneIngressRoute> {
        assert_eq!(packet.transport_id, TransportId::new(5));
        assert_eq!(
            packet.remote_addr,
            TransportAddr::from_string("198.51.100.9:9000")
        );
        assert_eq!(packet.path, live_path(9005));
        assert_eq!(packet.activity_tick, Some(ActivityTick::new(123_456)));
        assert_eq!(
            packet.payload.len(),
            FMP_ESTABLISHED_HEADER_SIZE + b"raw-in".len() + AEAD_TAG_SIZE
        );
        assert_eq!(packet.protocol, PacketProtocol::Fmp);
        assert!(matches!(header, DataplaneIngressHeader::Fmp(_)));
        assert_eq!(header.open_metadata().0, 1200);
        self.route
    }
}

struct NullIngressRouter;

impl DataplaneIngressRouter for NullIngressRouter {
    fn route(
        &mut self,
        _packet: &DataplaneRawIngress,
        _header: DataplaneIngressHeader,
    ) -> Option<DataplaneIngressRoute> {
        None
    }
}

#[derive(Default)]
struct BatchRecordingOutputSink {
    batch_calls: usize,
    outputs: Vec<PacketOutput>,
}

impl DataplaneOutputSink for BatchRecordingOutputSink {
    fn send_batch<I>(&mut self, outputs: I, drops: &mut Vec<DataplaneOutputDrop>) -> usize
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

struct SimpleIngressRouter {
    owner: OwnerId,
    generation: u64,
    class: PacketClass,
    output: OutputTarget,
}

impl DataplaneIngressRouter for SimpleIngressRouter {
    fn route(
        &mut self,
        _packet: &DataplaneRawIngress,
        _header: DataplaneIngressHeader,
    ) -> Option<DataplaneIngressRoute> {
        Some(
            DataplaneIngressRoute::new(self.owner, self.generation, self.output)
                .with_class(self.class),
        )
    }
}
