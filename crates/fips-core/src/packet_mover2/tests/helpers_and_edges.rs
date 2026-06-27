    use super::*;
    use crate::transport::{ReceivedPacket, TransportAddr, TransportId};
    use ring::aead::UnboundKey;

    fn mover() -> PacketMover2 {
        PacketMover2::new(AdmissionConfig::new(4, 8), CopyCryptoWorker)
    }

    fn packet(
        owner: OwnerId,
        generation: u64,
        counter: u64,
        class: PacketClass,
        output: OutputTarget,
    ) -> SocketPacket {
        SocketPacket::new(
            owner,
            generation,
            counter,
            class,
            output,
            vec![counter as u8],
        )
    }

    fn fmp_wire(receiver_idx: u32, counter: u64, flags: u8) -> Vec<u8> {
        let mut data = vec![0u8; FMP_ESTABLISHED_HEADER_SIZE + 16];
        data[0] = (FMP_VERSION << 4) | FMP_PHASE_ESTABLISHED;
        data[1] = flags;
        data[4..8].copy_from_slice(&receiver_idx.to_le_bytes());
        data[8..16].copy_from_slice(&counter.to_le_bytes());
        data
    }

    fn fsp_wire(counter: u64, flags: u8) -> Vec<u8> {
        let mut data = vec![0u8; FSP_HEADER_SIZE + 16];
        data[0] = (FSP_VERSION << 4) | FSP_PHASE_ESTABLISHED;
        data[1] = flags;
        data[4..12].copy_from_slice(&counter.to_le_bytes());
        data
    }

    fn opened_output(
        owner: OwnerId,
        counter: u64,
        ingress_seq: u64,
        target: OutputTarget,
        plaintext: &[u8],
    ) -> PacketOutput {
        let mut payload = match owner.protocol() {
            PacketProtocol::Fmp => fmp_wire(0, counter, 0),
            PacketProtocol::Fsp => fsp_wire(counter, 0),
        };
        payload.truncate(match owner.protocol() {
            PacketProtocol::Fmp => FMP_ESTABLISHED_HEADER_SIZE,
            PacketProtocol::Fsp => FSP_HEADER_SIZE,
        });
        payload.extend_from_slice(plaintext);
        PacketOutput {
            owner,
            counter,
            ingress_seq,
            target,
            path: None,
            payload: payload.into(),
        }
    }

    fn transport_output(
        owner: OwnerId,
        counter: u64,
        ingress_seq: u64,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        payload: impl Into<PacketBuffer>,
    ) -> PacketOutput {
        PacketOutput {
            owner,
            counter,
            ingress_seq,
            target: OutputTarget::Transport,
            path: Some(TransportPath::live(transport_id, remote_addr)),
            payload: payload.into(),
        }
    }

    fn test_cipher(byte: u8) -> LessSafeKey {
        let key = [byte; 32];
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key).unwrap();
        LessSafeKey::new(unbound)
    }

    fn test_key(byte: u8) -> AeadKey {
        Arc::new(test_cipher(byte))
    }

    fn unstarted_udp_transport(transport_id: TransportId) -> TransportHandle {
        let (packet_tx, _packet_rx) = crate::transport::packet_channel(4);
        TransportHandle::Udp(crate::transport::udp::UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx,
        ))
    }

    fn missing_endpoint_peer(_: &NodeAddr) -> Option<PeerIdentity> {
        None
    }

    fn fmp_encrypted_wire(
        receiver_idx: u32,
        counter: u64,
        flags: u8,
        plaintext: &[u8],
        key: u8,
    ) -> Vec<u8> {
        let mut data = fmp_wire(receiver_idx, counter, flags);
        data.truncate(FMP_ESTABLISHED_HEADER_SIZE);
        let mut ciphertext = plaintext.to_vec();
        test_cipher(key)
            .seal_in_place_append_tag(
                aead_nonce(counter),
                Aad::from(&data[..FMP_ESTABLISHED_HEADER_SIZE]),
                &mut ciphertext,
            )
            .unwrap();
        data.extend_from_slice(&ciphertext);
        data
    }

    fn fsp_encrypted_wire(counter: u64, flags: u8, plaintext: &[u8], key: u8) -> Vec<u8> {
        let mut data = fsp_wire(counter, flags);
        data.truncate(FSP_HEADER_SIZE);
        let mut ciphertext = plaintext.to_vec();
        test_cipher(key)
            .seal_in_place_append_tag(
                aead_nonce(counter),
                Aad::from(&data[..FSP_HEADER_SIZE]),
                &mut ciphertext,
            )
            .unwrap();
        data.extend_from_slice(&ciphertext);
        data
    }

    fn open_sealed_output(output: &PacketOutput, key: u8) -> Vec<u8> {
        match output.owner.protocol {
            PacketProtocol::Fmp => {
                let header = FmpWireHeader::parse(&output.payload).unwrap();
                let aad = header.header_bytes();
                let mut ciphertext = output.payload[header.ciphertext_offset()..].to_vec();
                let plaintext_len = test_cipher(key)
                    .open_in_place(
                        aead_nonce(header.counter()),
                        Aad::from(&aad),
                        &mut ciphertext,
                    )
                    .unwrap()
                    .len();
                ciphertext.truncate(plaintext_len);
                ciphertext
            }
            PacketProtocol::Fsp => {
                let header = FspWireHeader::parse(&output.payload).unwrap();
                let aad = header.header_bytes();
                let mut ciphertext = output.payload[header.ciphertext_offset()..].to_vec();
                let plaintext_len = test_cipher(key)
                    .open_in_place(
                        aead_nonce(header.counter()),
                        Aad::from(&aad),
                        &mut ciphertext,
                    )
                    .unwrap()
                    .len();
                ciphertext.truncate(plaintext_len);
                ciphertext
            }
        }
    }

    fn open_fmp_wire_payload(payload: &[u8], key: u8) -> Vec<u8> {
        let header = FmpWireHeader::parse(payload).unwrap();
        let aad = header.header_bytes();
        let mut ciphertext = payload[header.ciphertext_offset()..].to_vec();
        let plaintext_len = test_cipher(key)
            .open_in_place(
                aead_nonce(header.counter()),
                Aad::from(&aad),
                &mut ciphertext,
            )
            .unwrap()
            .len();
        ciphertext.truncate(plaintext_len);
        ciphertext
    }

    fn open_fsp_wire_payload(payload: &[u8], key: u8) -> Vec<u8> {
        let header = FspWireHeader::parse(payload).unwrap();
        let aad = header.header_bytes();
        let mut ciphertext = payload[header.ciphertext_offset()..].to_vec();
        let plaintext_len = test_cipher(key)
            .open_in_place(
                aead_nonce(header.counter()),
                Aad::from(&aad),
                &mut ciphertext,
            )
            .unwrap()
            .len();
        ciphertext.truncate(plaintext_len);
        ciphertext
    }

    fn outbound_packet(
        owner: OwnerId,
        generation: u64,
        class: PacketClass,
        payload: &[u8],
    ) -> OutboundPacket {
        match owner.protocol {
            PacketProtocol::Fmp => OutboundPacket::fmp(
                owner,
                generation,
                class,
                owner
                    .scratch_peer()
                    .expect("test outbound FMP helper requires scratch owner")
                    as u32,
                0,
                payload.to_vec(),
            ),
            PacketProtocol::Fsp => {
                OutboundPacket::fsp(owner, generation, class, 0, payload.to_vec())
            }
        }
    }

    fn outputs(items: Vec<RetiredPacket>) -> Vec<PacketOutput> {
        items
            .into_iter()
            .map(|item| match item {
                RetiredPacket::Output(output) => output,
                RetiredPacket::Outbound(packet) => panic!("unexpected outbound: {packet:?}"),
                RetiredPacket::Drop(drop) => panic!("unexpected drop: {drop:?}"),
            })
            .collect()
    }

    fn drops(items: Vec<RetiredPacket>) -> Vec<PacketDrop> {
        items
            .into_iter()
            .map(|item| match item {
                RetiredPacket::Drop(drop) => drop,
                RetiredPacket::Output(output) => panic!("unexpected output: {output:?}"),
                RetiredPacket::Outbound(packet) => panic!("unexpected outbound: {packet:?}"),
            })
            .collect()
    }

    #[test]
    fn owner_id_supports_real_node_addr_owners() {
        let node_addr = NodeAddr::from_bytes([0x42; 16]);
        let fmp = OwnerId::fmp_node(node_addr);
        let fsp = OwnerId::fsp_node(node_addr);

        assert_eq!(fmp.peer_id(), OwnerPeerId::Node(node_addr));
        assert_eq!(fmp.node_addr(), Some(node_addr));
        assert_eq!(fmp.protocol(), PacketProtocol::Fmp);
        assert_eq!(fsp.protocol(), PacketProtocol::Fsp);
        assert_ne!(fmp, fsp);
        assert_ne!(fmp, OwnerId::fmp(0x42));
        assert_eq!(OwnerId::fmp(0x42).scratch_peer(), Some(0x42));
        assert_eq!(OwnerId::fmp(0x42).node_addr(), None);
    }

    #[test]
    fn transport_path_supports_live_transport_targets() {
        let transport_id = TransportId::new(17);
        let remote_addr = TransportAddr::from_string("198.51.100.17:9000");
        let path = TransportPath::live(transport_id, remote_addr.clone());

        assert_eq!(path.transport_id(), Some(transport_id));
        assert_eq!(path.remote_addr(), Some(&remote_addr));
        assert_eq!(path.scratch_id(), None);

        let raw = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(transport_id, remote_addr.clone(), vec![0xaa], 42),
        );
        let raw_path = raw.path();
        assert_eq!(raw_path.transport_id(), Some(transport_id));
        assert_eq!(raw_path.remote_addr(), Some(&remote_addr));
        assert_eq!(raw.transport_id(), transport_id);
        assert_eq!(raw.remote_addr(), &remote_addr);
    }

    #[test]
    fn live_raw_ingress_source_drains_received_packets_by_limit() {
        let fsp_source = NodeAddr::from_bytes([0x18; 16]);
        let fmp_addr = TransportAddr::from_string("198.51.100.18:9000");
        let fsp_addr = TransportAddr::from_string("198.51.100.19:9000");
        let mut source = PacketMover2LiveRawIngressSource::new(VecDeque::from([
            PacketMover2LiveIngressPacket::fmp(ReceivedPacket::with_timestamp(
                TransportId::new(18),
                fmp_addr.clone(),
                fmp_wire(180, 1, 0),
                18_000,
            )),
            PacketMover2LiveIngressPacket::fsp(
                ReceivedPacket::with_timestamp(
                    TransportId::new(19),
                    fsp_addr.clone(),
                    fsp_wire(2, 0),
                    19_000,
                ),
                fsp_source,
            ),
        ]));
        let mut drained = Vec::new();

        assert_eq!(
            source.drain_raw_ingress(1, |packet| drained.push(packet)),
            1
        );

        assert_eq!(drained.len(), 1);
        assert_eq!(source.source_mut().len(), 1);
        assert_eq!(drained[0].protocol(), PacketProtocol::Fmp);
        assert_eq!(drained[0].transport_id(), TransportId::new(18));
        assert_eq!(drained[0].remote_addr(), &fmp_addr);
        assert_eq!(drained[0].path().transport_id(), Some(TransportId::new(18)));
        assert_eq!(drained[0].activity_tick(), Some(ActivityTick::new(18_000)));

        assert_eq!(
            source.drain_raw_ingress(8, |packet| drained.push(packet)),
            1
        );
        assert!(source.source_mut().is_empty());
        assert_eq!(drained[1].protocol(), PacketProtocol::Fsp);
        assert_eq!(drained[1].transport_id(), TransportId::new(19));
        assert_eq!(drained[1].remote_addr(), &fsp_addr);
        assert_eq!(drained[1].fsp_source(), Some(fsp_source));
        assert_eq!(drained[1].path().remote_addr(), Some(&fsp_addr));
    }

    #[test]
    fn fmp_packet_rx_source_drains_packet_rx_by_limit() {
        let (tx, mut rx) = crate::transport::packet_channel(8);
        let transport_id = TransportId::new(20);
        let priority_addr = TransportAddr::from_string("198.51.100.20:9000");
        let bulk_addr = TransportAddr::from_string("198.51.100.21:9000");
        let priority_wire = fmp_wire(200, 1, 0);
        let mut bulk_wire = fmp_wire(201, 2, 0);
        bulk_wire.resize(700, 0xee);
        tx.send_batch(vec![
            ReceivedPacket::with_timestamp(transport_id, bulk_addr.clone(), bulk_wire, 20_000),
            ReceivedPacket::with_timestamp(
                transport_id,
                priority_addr.clone(),
                priority_wire.clone(),
                20_001,
            ),
        ])
        .expect("enqueue mixed packet batch");

        let mut source = PacketMover2FmpPacketRxSource::new(&mut rx);
        let mut drained = Vec::new();

        assert_eq!(
            source.drain_raw_ingress(1, |packet| drained.push(packet)),
            1
        );

        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].protocol(), PacketProtocol::Fmp);
        assert_eq!(drained[0].transport_id(), transport_id);
        assert_eq!(drained[0].remote_addr(), &priority_addr);
        assert_eq!(drained[0].path().remote_addr(), Some(&priority_addr));
        assert_eq!(drained[0].activity_tick(), Some(ActivityTick::new(20_001)));
        assert_eq!(drained[0].payload_len(), priority_wire.len());

        assert_eq!(
            source.drain_raw_ingress(8, |packet| drained.push(packet)),
            1
        );
        assert_eq!(drained[1].protocol(), PacketProtocol::Fmp);
        assert_eq!(drained[1].transport_id(), transport_id);
        assert_eq!(drained[1].remote_addr(), &bulk_addr);
        assert_eq!(drained[1].path().remote_addr(), Some(&bulk_addr));
        assert_eq!(drained[1].activity_tick(), Some(ActivityTick::new(20_000)));
        assert_eq!(drained[1].payload_len(), 700);

        assert_eq!(
            source.drain_raw_ingress(8, |packet| drained.push(packet)),
            0
        );
    }
