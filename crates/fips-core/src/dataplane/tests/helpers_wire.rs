    fn test_node_addr(id: u64) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[8..16].copy_from_slice(&id.to_be_bytes());
        NodeAddr::from_bytes(bytes)
    }

    fn fmp_owner(id: u64) -> OwnerId {
        OwnerId::fmp_node(test_node_addr(id))
    }

    fn fsp_owner(id: u64) -> OwnerId {
        OwnerId::fsp_node(test_node_addr(id))
    }

    fn test_receiver_idx(owner: OwnerId) -> u32 {
        let node_addr = owner.node_addr();
        let bytes: [u8; 4] = node_addr.as_bytes()[12..16]
            .try_into()
            .expect("test owner embeds receiver index");
        u32::from_be_bytes(bytes)
    }

    fn live_path(id: u32) -> TransportPath {
        let port = 10_000 + id % 50_000;
        let remote_addr = format!("198.51.100.1:{port}");
        TransportPath::live(TransportId::new(id), TransportAddr::from_string(&remote_addr))
    }

    fn tun_ipv6_packet(dest_addr: NodeAddr, len: usize) -> Vec<u8> {
        assert!(len >= 40);
        let mut packet = vec![0u8; len];
        packet[0] = 0x60;
        packet[6] = 17;
        let dest = crate::FipsAddress::from_node_addr(&dest_addr);
        packet[24..40].copy_from_slice(dest.as_bytes());
        packet
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
            0,
            class,
            output,
            PacketBuffer::new(vec![counter as u8]),
        )
    }

    fn fmp_socket_packet(
        owner: OwnerId,
        generation: u64,
        output: OutputTarget,
        payload: Vec<u8>,
    ) -> Result<SocketPacket, WirePreflightError> {
        let payload = PacketBuffer::new(payload);
        let header = FmpWireHeader::parse(payload.as_slice())?;
        Ok(SocketPacket::new(
            owner,
            generation,
            header.counter(),
            header.ciphertext_offset(),
            PacketClass::Bulk,
            output,
            payload,
        )
        .with_wire_flags(header.flags()))
    }

    fn fsp_socket_packet(
        owner: OwnerId,
        generation: u64,
        output: OutputTarget,
        payload: Vec<u8>,
    ) -> Result<SocketPacket, WirePreflightError> {
        let payload = PacketBuffer::new(payload);
        let header = FspWireHeader::parse(payload.as_slice())?;
        Ok(SocketPacket::new(
            owner,
            generation,
            header.counter(),
            header.ciphertext_offset(),
            PacketClass::Bulk,
            output,
            payload,
        )
        .with_wire_flags(header.flags()))
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

    fn transport_output(
        owner: OwnerId,
        counter: u64,
        ingress_seq: u64,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        payload: Vec<u8>,
    ) -> PacketOutput {
        PacketOutput {
            owner,
            counter,
            ingress_seq,
            lane: Lane::Bulk,
            target: OutputTarget::Transport,
            source_path: None,
            previous_hop: None,
            ce_flag: false,
            path_mtu: u16::MAX,
            wire_flags: 0,
            opened_payload_offset: 0,
            source_peer: None,
            path: Some(TransportPath::live(transport_id, remote_addr)),
            activity_tick: None,
            source_wire_len: None,
            fmp_timestamp_ms: None,
            fsp_send_receipt: None,
            send_token: None,
            payload: PacketBuffer::new(payload),
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
        fsp_encrypted_wire_with_coords(
            counter,
            flags,
            plaintext,
            key,
            &empty_fsp_coords_prefix(),
        )
    }

    fn fsp_encrypted_wire_with_coords(
        counter: u64,
        flags: u8,
        plaintext: &[u8],
        key: u8,
        coords_prefix: &[u8],
    ) -> Vec<u8> {
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
        if flags & crate::node::session_wire::FSP_FLAG_CP != 0 {
            data.extend_from_slice(coords_prefix);
        }
        data.extend_from_slice(&ciphertext);
        data
    }

    fn encrypted_fmp_packet(
        owner: OwnerId,
        generation: u64,
        counter: u64,
        class: PacketClass,
        output: OutputTarget,
        key: u8,
    ) -> SocketPacket {
        SocketPacket::new(
            owner,
            generation,
            counter,
            FMP_ESTABLISHED_HEADER_SIZE as u16,
            class,
            output,
            PacketBuffer::new(fmp_encrypted_wire(
                test_receiver_idx(owner),
                counter,
                0,
                &[counter as u8],
                key,
            )),
        )
    }

    fn retire_ready_slots_to_outputs(
        mover: &mut Dataplane,
        limit: usize,
        retired: &mut Vec<PacketOutput>,
    ) -> usize {
        let mut outbound_packets = Vec::new();
        let mut fsp_authenticated_ingress = DataplaneFspAuthenticatedIngress::default();
        let retired_count = mover.retire_ready_slots_into(
            limit,
            &mut DataplaneRetiredOutputSink::new(
                retired,
                &mut outbound_packets,
                &mut fsp_authenticated_ingress,
            ),
            false,
        );
        assert!(outbound_packets.is_empty());
        assert!(fsp_authenticated_ingress.is_empty());
        retired_count
    }

    fn empty_fsp_coords_prefix() -> Vec<u8> {
        let mut prefix = Vec::with_capacity(2 * std::mem::size_of::<u16>());
        prefix.extend_from_slice(&0u16.to_le_bytes());
        prefix.extend_from_slice(&0u16.to_le_bytes());
        prefix
    }

    fn open_sealed_output(output: &PacketOutput, key: u8) -> Vec<u8> {
        match output.owner.protocol {
            PacketProtocol::Fmp => open_fmp_wire_payload(output.payload.as_slice(), key),
            PacketProtocol::Fsp => open_fsp_wire_payload(output.payload.as_slice(), key),
        }
    }

    fn open_fmp_wire_payload(payload: &[u8], key: u8) -> Vec<u8> {
        let header = FmpWireHeader::parse(payload).unwrap();
        open_wire_payload(
            payload,
            key,
            header.counter(),
            &payload[..FMP_ESTABLISHED_HEADER_SIZE],
            usize::from(header.ciphertext_offset()),
        )
    }

    fn open_fsp_wire_payload(payload: &[u8], key: u8) -> Vec<u8> {
        let header = FspWireHeader::parse(payload).unwrap();
        open_wire_payload(
            payload,
            key,
            header.counter(),
            &payload[..FSP_HEADER_SIZE],
            usize::from(header.ciphertext_offset()),
        )
    }

    fn open_wire_payload(
        payload: &[u8],
        key: u8,
        counter: u64,
        aad: &[u8],
        ciphertext_offset: usize,
    ) -> Vec<u8> {
        let mut ciphertext = payload[ciphertext_offset..].to_vec();
        let plaintext_len = test_cipher(key)
            .open_in_place(aead_nonce(counter), Aad::from(aad), &mut ciphertext)
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
                test_receiver_idx(owner),
                0,
                PacketBuffer::new(payload.to_vec()),
            ),
            PacketProtocol::Fsp => {
                OutboundPacket::fsp(owner, generation, class, 0, PacketBuffer::new(payload.to_vec()))
            }
        }
    }
