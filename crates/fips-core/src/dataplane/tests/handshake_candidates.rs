#[test]
fn packet_rx_source_confirms_only_exact_fmp_handshake_candidates() {
    fn check_route(
        live_node: &DataplaneLiveNode,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
        receiver_idx: u32,
        expect_control: bool,
    ) {
        for use_first in [true, false] {
            let (tx, mut rx) = crate::transport::packet_channel(1);
            let packet = ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr.clone(),
                PacketBuffer::new(fmp_wire(receiver_idx, 10, 0)),
                1_000,
            );
            let first = if use_first {
                Some(packet)
            } else {
                tx.send(packet).expect("queue packet");
                None
            };
            let mut source =
                DataplaneFmpPacketRxSource::with_first_direct_fsp_sources_and_reassembler(
                    &mut rx,
                    first,
                    Arc::default(),
                    None,
                    live_node.fmp_handshake_candidates.clone(),
                );
            let mut raw = Vec::new();
            assert_eq!(source.drain_raw_ingress(1, |packet| raw.push(packet)), 1);
            let mut control = source.take_control_ingress();
            assert_eq!(control.len(), usize::from(expect_control));
            assert_eq!(raw.len(), usize::from(!expect_control));
            if expect_control {
                let packet = control.pop().unwrap().into_packet();
                assert_eq!(packet.transport_id, transport_id);
                assert_eq!(&packet.remote_addr, remote_addr);
                assert_eq!(packet.timestamp_ms, 1_000);
                assert_eq!(packet.data.as_slice(), fmp_wire(receiver_idx, 10, 0));
            } else {
                assert_eq!(raw[0].protocol, PacketProtocol::Fmp);
            }
        }
    }

    let mut live_node = DataplaneLiveNode::new(AdmissionConfig::new(1, 1));
    let transport_id = TransportId::new(46);
    let remote_addr = TransportAddr::from_string("198.51.100.46:9000");
    let wrong_addr = TransportAddr::from_string("198.51.100.46:9001");
    live_node.register_fmp_handshake_candidate(transport_id, &remote_addr, 460);
    live_node.remove_fmp_handshake_candidate(transport_id, &wrong_addr, 460);

    for (transport, addr, index, expected) in [
        (transport_id, &remote_addr, 460, true),
        (TransportId::new(47), &remote_addr, 460, false),
        (transport_id, &wrong_addr, 460, false),
        (transport_id, &remote_addr, 461, false),
    ] {
        check_route(&live_node, transport, addr, index, expected);
    }

    live_node.remove_fmp_handshake_candidate(transport_id, &remote_addr, 460);
    check_route(&live_node, transport_id, &remote_addr, 460, false);
}
