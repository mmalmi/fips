    #[tokio::test]
    async fn live_node_session_ingress_reports_fmp_receipt_before_fast_fsp_delivery() {
        let local_addr = NodeAddr::from_bytes([0xa1; 16]);
        let source_identity = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source_identity.pubkey_full());
        let source_addr = *source_peer.node_addr();
        let next_hop = NodeAddr::from_bytes([0xa3; 16]);
        let fmp_owner = OwnerId::fmp_node(next_hop);
        let fsp_owner = OwnerId::fsp_node(source_addr);
        let fmp_key = 0xa4;
        let fsp_key = 0xa5;
        let transport_id = TransportId::new(0xa6);
        let remote_addr = TransportAddr::from_string("198.51.100.166:9000");
        let fmp_timestamp = 166_001;
        let fmp_inner_timestamp = 166_002_u32;
        let fsp_inner_timestamp = 166_003_u32;
        let fsp_inner_flags = 0x05;
        let fmp_counter = 166;
        let fsp_counter = 167;
        let fmp_flags = crate::node::wire::FLAG_CE | crate::node::wire::FLAG_SP;
        let endpoint_payload = b"fast-endpoint";
        let fsp_inner = crate::node::session_wire::fsp_prepend_inner_header(
            fsp_inner_timestamp,
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            fsp_inner_flags,
            endpoint_payload,
        );
        let fsp_wire = fsp_encrypted_wire(
            fsp_counter,
            crate::node::session_wire::FSP_FLAG_CP,
            &fsp_inner,
            fsp_key,
        );
        let datagram = crate::protocol::SessionDatagram::new(source_addr, local_addr, fsp_wire)
            .with_ttl(8)
            .with_path_mtu(1280)
            .encode();
        let mut fmp_plaintext = fmp_inner_timestamp.to_le_bytes().to_vec();
        fmp_plaintext.extend_from_slice(&datagram);
        let fmp_wire = fmp_encrypted_wire(0xa7, fmp_counter, fmp_flags, &fmp_plaintext, fmp_key);
        let fmp_wire_len = fmp_wire.len();

        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(fmp_owner, OwnerConfig::new(1, 8));
        driver.register_owner(fsp_owner, OwnerConfig::new(1, 8));
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fmp_key), test_key(fmp_key)));
        driver
            .owner_mut(fsp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fsp_key), test_key(fsp_key)));

        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_fmp(
            transport_id,
            0xa7,
            PacketMover2IngressRoute::new(
                fmp_owner,
                1,
                OutputTarget::SessionIngress { local_addr },
            )
            .with_class(PacketClass::Liveness),
        );
        routes.register_fsp(
            source_addr,
            PacketMover2IngressRoute::new(
                fsp_owner,
                1,
                OutputTarget::SessionPayload { local_addr },
            )
            .with_class(PacketClass::Liveness),
        );
        let mut raw_source =
            PacketMover2LiveRawIngressSource::new(VecDeque::from([PacketMover2LiveIngressPacket::fmp(
                ReceivedPacket::with_timestamp(
                    transport_id,
                    remote_addr.clone(),
                    fmp_wire,
                    fmp_timestamp,
                ),
            )]));
        let (_endpoint_priority_tx, mut endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
        let (_endpoint_bulk_tx, mut endpoint_bulk_rx) = tokio::sync::mpsc::channel(1);
        let (_tun_outbound_tx, mut tun_outbound_rx) =
            crate::upper::tun::tun_outbound_channel(1);
        let (tun_tx, _tun_rx) = crate::upper::tun::write_channel();
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let mut deferred_endpoint_commands = Vec::new();
        let transports = HashMap::<TransportId, TransportHandle>::new();
        let resolver = |addr: &NodeAddr| (addr == &source_addr).then_some(source_peer);

        let turn = driver
            .pump_aead_live_node_route_table_turn(
                &mut raw_source,
                &mut routes,
                8,
                &mut endpoint_priority_rx,
                &mut endpoint_bulk_rx,
                0,
                &mut tun_outbound_rx,
                0,
                &mut deferred_endpoint_commands,
                &tun_tx,
                &endpoint_io.event_tx,
                resolver,
                &transports,
                8,
            )
            .await;

        assert_eq!(turn.summary().raw_ingress_dropped(), 0);
        assert_eq!(turn.summary().inbound_admitted(), 2);
        assert_eq!(turn.summary().outputs_dropped(), 0);
        assert_eq!(turn.fmp_ingress_receipts().len(), 1);
        assert!(turn.fmp_link_ingress().is_empty());
        let receipt = &turn.fmp_ingress_receipts()[0];
        assert_eq!(receipt.source_addr(), &next_hop);
        assert_eq!(receipt.transport_id(), transport_id);
        assert_eq!(receipt.remote_addr(), &remote_addr);
        assert_eq!(receipt.packet_timestamp_ms(), fmp_timestamp);
        assert_eq!(receipt.packet_len(), fmp_wire_len);
        assert_eq!(receipt.fmp_counter(), fmp_counter);
        assert_eq!(receipt.inner_timestamp_ms(), fmp_inner_timestamp);
        assert_eq!(receipt.fmp_flags(), fmp_flags);
        assert!(endpoint_io.event_rx.try_recv().is_err());
        assert_eq!(turn.fsp_session_ingress().len(), 1);
        let session_ingress = &turn.fsp_session_ingress()[0];
        assert_eq!(session_ingress.source_addr(), source_addr);
        assert_eq!(session_ingress.previous_hop_addr(), next_hop);
        assert!(session_ingress.ce_flag());
        assert_eq!(session_ingress.timestamp_ms(), fsp_inner_timestamp);
        assert_eq!(
            session_ingress.msg_type(),
            crate::protocol::SessionMessageType::EndpointData.to_byte()
        );
        assert_eq!(session_ingress.inner_flags(), fsp_inner_flags);
        assert_eq!(session_ingress.plaintext(), fsp_inner.as_slice());
        assert_eq!(
            &session_ingress.plaintext()[crate::node::session_wire::FSP_INNER_HEADER_SIZE..],
            endpoint_payload
        );
    }

    #[tokio::test]
    async fn live_node_session_ingress_keeps_fsp_handshake_on_local_session_path() {
        let local_addr = NodeAddr::from_bytes([0xac; 16]);
        let source_addr = NodeAddr::from_bytes([0xad; 16]);
        let next_hop = NodeAddr::from_bytes([0xae; 16]);
        let fmp_owner = OwnerId::fmp_node(next_hop);
        let fmp_key = 0xaf;
        let transport_id = TransportId::new(0xb0);
        let remote_addr = TransportAddr::from_string("198.51.100.176:9000");
        let fmp_timestamp = 176_001;
        let fmp_inner_timestamp = 176_002_u32;
        let fmp_counter = 176;
        let fmp_flags = crate::node::wire::FLAG_CE;
        let path_mtu = 1240;
        let mut fsp_handshake =
            crate::node::session_wire::build_fsp_handshake_prefix(
                crate::node::session_wire::FSP_PHASE_MSG1,
                4,
            )
            .to_vec();
        fsp_handshake.extend_from_slice(b"msg1");
        let datagram =
            crate::protocol::SessionDatagram::new(source_addr, local_addr, fsp_handshake.clone())
                .with_ttl(8)
                .with_path_mtu(path_mtu)
                .encode();
        let mut fmp_plaintext = fmp_inner_timestamp.to_le_bytes().to_vec();
        fmp_plaintext.extend_from_slice(&datagram);
        let fmp_wire = fmp_encrypted_wire(0xb1, fmp_counter, fmp_flags, &fmp_plaintext, fmp_key);
        let fmp_wire_len = fmp_wire.len();

        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(fmp_owner, OwnerConfig::new(1, 8));
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fmp_key), test_key(fmp_key)));
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_fmp(
            transport_id,
            0xb1,
            PacketMover2IngressRoute::new(
                fmp_owner,
                1,
                OutputTarget::SessionIngress { local_addr },
            )
            .with_class(PacketClass::Liveness),
        );
        let mut raw_source =
            PacketMover2LiveRawIngressSource::new(VecDeque::from([PacketMover2LiveIngressPacket::fmp(
                ReceivedPacket::with_timestamp(
                    transport_id,
                    remote_addr.clone(),
                    fmp_wire,
                    fmp_timestamp,
                ),
            )]));
        let (_endpoint_priority_tx, mut endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
        let (_endpoint_bulk_tx, mut endpoint_bulk_rx) = tokio::sync::mpsc::channel(1);
        let (_tun_outbound_tx, mut tun_outbound_rx) =
            crate::upper::tun::tun_outbound_channel(1);
        let (tun_tx, _tun_rx) = crate::upper::tun::write_channel();
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let mut deferred_endpoint_commands = Vec::new();
        let transports = HashMap::<TransportId, TransportHandle>::new();

        let turn = driver
            .pump_aead_live_node_route_table_turn(
                &mut raw_source,
                &mut routes,
                8,
                &mut endpoint_priority_rx,
                &mut endpoint_bulk_rx,
                0,
                &mut tun_outbound_rx,
                0,
                &mut deferred_endpoint_commands,
                &tun_tx,
                &endpoint_io.event_tx,
                missing_endpoint_peer,
                &transports,
                8,
            )
            .await;

        assert_eq!(turn.summary().raw_ingress_dropped(), 0);
        assert_eq!(turn.summary().inbound_admitted(), 1);
        assert_eq!(turn.summary().outputs_dropped(), 0);
        assert_eq!(turn.fmp_ingress_receipts().len(), 1);
        assert!(turn.fmp_link_ingress().is_empty());
        assert!(turn.fsp_session_ingress().is_empty());
        assert_eq!(turn.fsp_local_session_ingress().len(), 1);
        let receipt = &turn.fmp_ingress_receipts()[0];
        assert_eq!(receipt.source_addr(), &next_hop);
        assert_eq!(receipt.transport_id(), transport_id);
        assert_eq!(receipt.remote_addr(), &remote_addr);
        assert_eq!(receipt.packet_timestamp_ms(), fmp_timestamp);
        assert_eq!(receipt.packet_len(), fmp_wire_len);
        assert_eq!(receipt.fmp_counter(), fmp_counter);
        assert_eq!(receipt.inner_timestamp_ms(), fmp_inner_timestamp);
        assert_eq!(receipt.fmp_flags(), fmp_flags);
        let local_ingress = &turn.fsp_local_session_ingress()[0];
        assert_eq!(local_ingress.source_addr(), source_addr);
        assert_eq!(local_ingress.previous_hop_addr(), next_hop);
        assert!(local_ingress.ce_flag());
        assert_eq!(local_ingress.path_mtu(), path_mtu);
        assert_eq!(local_ingress.payload(), fsp_handshake.as_slice());
        assert!(turn.raw_ingress_drops().is_empty());
        assert!(turn.output_drops().is_empty());
    }

    #[tokio::test]
    async fn live_node_session_ingress_reports_non_local_fmp_link_message() {
        let local_addr = NodeAddr::from_bytes([0xb1; 16]);
        let next_hop = NodeAddr::from_bytes([0xb2; 16]);
        let fmp_owner = OwnerId::fmp_node(next_hop);
        let fmp_key = 0xb3;
        let transport_id = TransportId::new(0xb4);
        let remote_addr = TransportAddr::from_string("198.51.100.180:9000");
        let fmp_timestamp = 180_001;
        let fmp_inner_timestamp = 180_002_u32;
        let fmp_counter = 180;
        let fmp_flags = crate::node::wire::FLAG_SP;
        let mut fmp_plaintext = fmp_inner_timestamp.to_le_bytes().to_vec();
        fmp_plaintext.push(crate::protocol::LinkMessageType::Heartbeat.to_byte());
        let fmp_wire = fmp_encrypted_wire(0xb5, fmp_counter, fmp_flags, &fmp_plaintext, fmp_key);
        let fmp_wire_len = fmp_wire.len();

        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(fmp_owner, OwnerConfig::new(1, 8));
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fmp_key), test_key(fmp_key)));
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_fmp(
            transport_id,
            0xb5,
            PacketMover2IngressRoute::new(
                fmp_owner,
                1,
                OutputTarget::SessionIngress { local_addr },
            )
            .with_class(PacketClass::Liveness),
        );
        let mut raw_source =
            PacketMover2LiveRawIngressSource::new(VecDeque::from([PacketMover2LiveIngressPacket::fmp(
                ReceivedPacket::with_timestamp(
                    transport_id,
                    remote_addr.clone(),
                    fmp_wire,
                    fmp_timestamp,
                ),
            )]));
        let (_endpoint_priority_tx, mut endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
        let (_endpoint_bulk_tx, mut endpoint_bulk_rx) = tokio::sync::mpsc::channel(1);
        let (_tun_outbound_tx, mut tun_outbound_rx) =
            crate::upper::tun::tun_outbound_channel(1);
        let (tun_tx, _tun_rx) = crate::upper::tun::write_channel();
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let mut deferred_endpoint_commands = Vec::new();
        let transports = HashMap::<TransportId, TransportHandle>::new();

        let turn = driver
            .pump_aead_live_node_route_table_turn(
                &mut raw_source,
                &mut routes,
                8,
                &mut endpoint_priority_rx,
                &mut endpoint_bulk_rx,
                0,
                &mut tun_outbound_rx,
                0,
                &mut deferred_endpoint_commands,
                &tun_tx,
                &endpoint_io.event_tx,
                missing_endpoint_peer,
                &transports,
                8,
            )
            .await;

        assert_eq!(turn.summary().raw_ingress_dropped(), 0);
        assert_eq!(turn.summary().inbound_admitted(), 1);
        assert_eq!(turn.summary().outputs(), 0);
        assert_eq!(turn.summary().outputs_dropped(), 0);
        assert!(turn.fmp_ingress_receipts().is_empty());
        assert_eq!(turn.fmp_link_ingress().len(), 1);
        let ingress = &turn.fmp_link_ingress()[0];
        assert_eq!(
            ingress.msg_type(),
            Some(crate::protocol::LinkMessageType::Heartbeat.to_byte())
        );
        assert_eq!(ingress.payload(), &[] as &[u8]);
        let receipt = ingress.receipt();
        assert_eq!(receipt.source_addr(), &next_hop);
        assert_eq!(receipt.transport_id(), transport_id);
        assert_eq!(receipt.remote_addr(), &remote_addr);
        assert_eq!(receipt.packet_timestamp_ms(), fmp_timestamp);
        assert_eq!(receipt.packet_len(), fmp_wire_len);
        assert_eq!(receipt.fmp_counter(), fmp_counter);
        assert_eq!(receipt.inner_timestamp_ms(), fmp_inner_timestamp);
        assert_eq!(receipt.fmp_flags(), fmp_flags);
        assert!(turn.output_drops().is_empty());
    }
