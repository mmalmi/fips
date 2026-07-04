    fn assert_fmp_receipt(
        receipt: &DataplaneFmpIngressReceipt,
        source_addr: NodeAddr,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
        packet_timestamp_ms: u64,
        packet_len: usize,
        fmp_counter: u64,
        inner_timestamp_ms: u32,
        fmp_flags: u8,
    ) {
        assert_eq!(receipt.source_addr(), &source_addr);
        assert_eq!(receipt.transport_id(), transport_id);
        assert_eq!(receipt.remote_addr(), remote_addr);
        assert_eq!(receipt.packet_timestamp_ms(), packet_timestamp_ms);
        assert_eq!(receipt.packet_len(), packet_len);
        assert_eq!(receipt.fmp_counter(), fmp_counter);
        assert_eq!(receipt.inner_timestamp_ms(), inner_timestamp_ms);
        assert_eq!(receipt.fmp_flags(), fmp_flags);
    }

    fn register_keyed_owner(
        driver: &mut DataplaneTurnDriver,
        owner: OwnerId,
        config: OwnerConfig,
        key: u8,
    ) {
        driver.register_owner(owner, config);
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));
    }

    fn register_fmp_session_ingress_route(
        routes: &mut DataplaneLiveRouteTable,
        transport_id: TransportId,
        receiver_idx: u32,
        owner: OwnerId,
        local_addr: NodeAddr,
    ) {
        routes.register_fmp(
            transport_id,
            receiver_idx,
            DataplaneIngressRoute::new(
                owner,
                1,
                OutputTarget::SessionIngress { local_addr },
            )
            .with_class(PacketClass::Liveness),
        );
    }

    fn register_fsp_session_payload_route(
        routes: &mut DataplaneLiveRouteTable,
        source_addr: NodeAddr,
        owner: OwnerId,
        local_addr: NodeAddr,
    ) {
        routes.register_fsp(
            source_addr,
            DataplaneIngressRoute::new(
                owner,
                1,
                OutputTarget::SessionPayload { local_addr },
            )
            .with_class(PacketClass::Liveness),
        );
    }

    async fn pump_one_fmp_session_ingress_turn(
        driver: &mut DataplaneTurnDriver,
        routes: &mut DataplaneLiveRouteTable,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        wire: Vec<u8>,
        timestamp_ms: u64,
    ) -> DataplaneLiveNodeTurn {
        let mut raw_source =
            DataplaneLiveRawIngressSource::new(VecDeque::from([DataplaneLiveIngressPacket::fmp(
                ReceivedPacket::with_timestamp(transport_id, remote_addr, wire, timestamp_ms),
            )]));
        let (_endpoint_data_tx, mut endpoint_data_rx) = endpoint_data_batch_channel(1);
        let (_tun_outbound_tx, mut tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
        let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let mut deferred_endpoint_data_batches = Vec::new();
        let mut deferred_tun_packets = Vec::new();
        let transports = HashMap::<TransportId, TransportHandle>::new();

        let turn = pump_aead_live_node_route_table_turn(
            driver,
            &mut raw_source,
            routes,
            8,
            &mut endpoint_data_rx,
            0,
            &mut tun_outbound_rx,
            0,
            &mut deferred_endpoint_data_batches,
            &mut deferred_tun_packets,
            &tun_tx,
            &endpoint_io.event_tx,
            &transports,
            8,
        )
        .await;

        assert!(raw_source.source.is_empty());
        assert!(deferred_endpoint_data_batches.is_empty());
        assert!(deferred_tun_packets.is_empty());
        assert!(tun_outbound_rx.try_recv().is_err());
        assert!(tun_rx.try_recv().is_err());
        assert!(endpoint_io.event_rx.try_recv().is_err());
        turn
    }

    #[tokio::test]
    async fn live_node_session_ingress_reports_fmp_receipt_before_fast_fsp_delivery() {
        let local_addr = NodeAddr::from_bytes([0xa1; 16]);
        let source_identity = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source_identity.pubkey_full());
        let source_addr = *source_peer.node_addr();
        let next_hop_peer =
            PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let next_hop = *next_hop_peer.node_addr();
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

        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        register_keyed_owner(
            &mut driver,
            fmp_owner,
            OwnerConfig::new(1, 8).with_source_peer(next_hop_peer),
            fmp_key,
        );
        register_keyed_owner(
            &mut driver,
            fsp_owner,
            OwnerConfig::new(1, 8).with_source_peer(source_peer),
            fsp_key,
        );

        let mut routes = DataplaneLiveRouteTable::default();
        register_fmp_session_ingress_route(&mut routes, transport_id, 0xa7, fmp_owner, local_addr);
        register_fsp_session_payload_route(&mut routes, source_addr, fsp_owner, local_addr);

        let turn = pump_one_fmp_session_ingress_turn(
            &mut driver,
            &mut routes,
            transport_id,
            remote_addr.clone(),
            fmp_wire,
            fmp_timestamp,
        )
        .await;

        assert_eq!(turn.summary().raw_ingress_dropped(), 0);
        assert_eq!(turn.summary().inbound_admitted(), 2);
        assert_eq!(turn.summary().outputs_dropped(), 0);
        assert_eq!(turn.fmp_ingress_receipts().len(), 1);
        assert!(turn.fmp_link_ingress().is_empty());
        assert_fmp_receipt(
            &turn.fmp_ingress_receipts()[0],
            next_hop,
            transport_id,
            &remote_addr,
            fmp_timestamp,
            fmp_wire_len,
            fmp_counter,
            fmp_inner_timestamp,
            fmp_flags,
        );
        assert!(driver
            .owner_fsp_activity(fsp_owner)
            .unwrap()
            .current_epoch_confirmed());
        assert_eq!(turn.fsp_session_ingress_count(), 1);
        let session_ingress = turn
            .fsp_session_ingress()
            .next()
            .expect("session ingress");
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
    async fn live_node_session_ingress_reports_fsp_coord_warmup_before_fsp_delivery() {
        let local_addr = NodeAddr::from_bytes([0xc1; 16]);
        let source_identity = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source_identity.pubkey_full());
        let source_addr = *source_peer.node_addr();
        let next_hop_peer =
            PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let next_hop = *next_hop_peer.node_addr();
        let root_addr = NodeAddr::from_bytes([0xcf; 16]);
        let source_coords =
            crate::tree::TreeCoordinate::from_addrs(vec![source_addr, root_addr]).unwrap();
        let local_coords =
            crate::tree::TreeCoordinate::from_addrs(vec![local_addr, root_addr]).unwrap();
        let mut coords_prefix = Vec::new();
        crate::protocol::encode_coords(&source_coords, &mut coords_prefix);
        crate::protocol::encode_coords(&local_coords, &mut coords_prefix);

        let fmp_owner = OwnerId::fmp_node(next_hop);
        let fsp_owner = OwnerId::fsp_node(source_addr);
        let fmp_key = 0xc4;
        let fsp_key = 0xc5;
        let transport_id = TransportId::new(0xc6);
        let remote_addr = TransportAddr::from_string("198.51.100.198:9000");
        let fmp_timestamp = 198_001;
        let fmp_inner_timestamp = 198_002_u32;
        let fsp_inner_timestamp = 198_003_u32;
        let endpoint_payload = b"coord-warm-endpoint";
        let fsp_inner = crate::node::session_wire::fsp_prepend_inner_header(
            fsp_inner_timestamp,
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0,
            endpoint_payload,
        );
        let fsp_wire = fsp_encrypted_wire_with_coords(
            198,
            crate::node::session_wire::FSP_FLAG_CP,
            &fsp_inner,
            fsp_key,
            &coords_prefix,
        );
        let datagram = crate::protocol::SessionDatagram::new(source_addr, local_addr, fsp_wire)
            .with_ttl(8)
            .with_path_mtu(1280)
            .encode();
        let mut fmp_plaintext = fmp_inner_timestamp.to_le_bytes().to_vec();
        fmp_plaintext.extend_from_slice(&datagram);
        let fmp_wire = fmp_encrypted_wire(0xc7, 199, 0, &fmp_plaintext, fmp_key);

        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        register_keyed_owner(
            &mut driver,
            fmp_owner,
            OwnerConfig::new(1, 8).with_source_peer(next_hop_peer),
            fmp_key,
        );
        register_keyed_owner(
            &mut driver,
            fsp_owner,
            OwnerConfig::new(1, 8).with_source_peer(source_peer),
            fsp_key,
        );
        assert_eq!(driver.record_fsp_decrypt_failure(fsp_owner), Some(1));
        let mut routes = DataplaneLiveRouteTable::default();
        register_fmp_session_ingress_route(&mut routes, transport_id, 0xc7, fmp_owner, local_addr);
        register_fsp_session_payload_route(&mut routes, source_addr, fsp_owner, local_addr);

        let turn = pump_one_fmp_session_ingress_turn(
            &mut driver,
            &mut routes,
            transport_id,
            remote_addr,
            fmp_wire,
            fmp_timestamp,
        )
        .await;

        assert_eq!(turn.summary().raw_ingress_dropped(), 0);
        assert_eq!(turn.summary().inbound_admitted(), 2);
        assert_eq!(turn.fsp_coord_warmups().len(), 1);
        assert_eq!(
            turn.fsp_coord_warmups()[0].source(),
            Some((source_addr, &source_coords))
        );
        assert_eq!(
            turn.fsp_coord_warmups()[0].local(),
            Some((local_addr, &local_coords))
        );
        let mut coord_cache = crate::cache::CoordCache::new(8, 1_000);
        turn.fsp_coord_warmups()[0]
            .clone()
            .apply_to(&mut coord_cache, 10);
        assert_eq!(coord_cache.get(&source_addr, 10), Some(&source_coords));
        assert_eq!(coord_cache.get(&local_addr, 10), Some(&local_coords));
        assert_eq!(turn.fsp_session_ingress_count(), 1);
        assert!(turn.fsp_local_session_ingress().is_empty());
        assert!(turn.fmp_link_ingress().is_empty());
        let activity = driver.owner_fsp_activity(fsp_owner).unwrap();
        assert!(activity.current_epoch_confirmed());
        assert_eq!(activity.last_rx_age_ms(fmp_timestamp), Some(0));
        assert_eq!(
            driver.record_fsp_decrypt_failure(fsp_owner),
            Some(1),
            "authenticated FSP output collection should reset the owner failure streak"
        );
    }

    #[tokio::test]
    async fn live_node_session_ingress_keeps_fsp_handshake_on_local_session_path() {
        let local_addr = NodeAddr::from_bytes([0xac; 16]);
        let source_addr = NodeAddr::from_bytes([0xad; 16]);
        let next_hop_peer =
            PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let next_hop = *next_hop_peer.node_addr();
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

        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        register_keyed_owner(
            &mut driver,
            fmp_owner,
            OwnerConfig::new(1, 8).with_source_peer(next_hop_peer),
            fmp_key,
        );
        let mut routes = DataplaneLiveRouteTable::default();
        register_fmp_session_ingress_route(&mut routes, transport_id, 0xb1, fmp_owner, local_addr);

        let turn = pump_one_fmp_session_ingress_turn(
            &mut driver,
            &mut routes,
            transport_id,
            remote_addr.clone(),
            fmp_wire,
            fmp_timestamp,
        )
        .await;

        assert_eq!(turn.summary().raw_ingress_dropped(), 0);
        assert_eq!(turn.summary().inbound_admitted(), 1);
        assert_eq!(turn.summary().outputs_dropped(), 0);
        assert_eq!(turn.fmp_ingress_receipts().len(), 1);
        assert!(turn.fmp_link_ingress().is_empty());
        assert_eq!(turn.fsp_session_ingress_count(), 0);
        assert_eq!(turn.fsp_local_session_ingress().len(), 1);
        assert_fmp_receipt(
            &turn.fmp_ingress_receipts()[0],
            next_hop,
            transport_id,
            &remote_addr,
            fmp_timestamp,
            fmp_wire_len,
            fmp_counter,
            fmp_inner_timestamp,
            fmp_flags,
        );
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
        let next_hop_peer =
            PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let next_hop = *next_hop_peer.node_addr();
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

        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        register_keyed_owner(
            &mut driver,
            fmp_owner,
            OwnerConfig::new(1, 8).with_source_peer(next_hop_peer),
            fmp_key,
        );
        let mut routes = DataplaneLiveRouteTable::default();
        register_fmp_session_ingress_route(&mut routes, transport_id, 0xb5, fmp_owner, local_addr);

        let turn = pump_one_fmp_session_ingress_turn(
            &mut driver,
            &mut routes,
            transport_id,
            remote_addr.clone(),
            fmp_wire,
            fmp_timestamp,
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
        assert_fmp_receipt(
            ingress.receipt(),
            next_hop,
            transport_id,
            &remote_addr,
            fmp_timestamp,
            fmp_wire_len,
            fmp_counter,
            fmp_inner_timestamp,
            fmp_flags,
        );
        assert!(turn.output_drops().is_empty());
    }
