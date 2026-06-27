    #[test]
    fn live_ingress_routes_fmp_by_transport_and_receiver_idx() {
        let transport_id = TransportId::new(40);
        let remote_addr = TransportAddr::from_string("198.51.100.40:9000");
        let source_a = NodeAddr::from_bytes([0x40; 16]);
        let source_b = NodeAddr::from_bytes([0x41; 16]);
        let owner_a = OwnerId::fmp_node(source_a);
        let owner_b = OwnerId::fmp_node(source_b);
        let route_a = PacketMover2IngressRoute::new(owner_a, 7, OutputTarget::Endpoint)
            .with_class(PacketClass::Liveness);
        let route_b = PacketMover2IngressRoute::new(owner_b, 8, OutputTarget::Endpoint)
            .with_class(PacketClass::Rekey);
        let mut routes = PacketMover2LiveRouteTable::default();
        assert_eq!(routes.register_fmp(transport_id, 404, route_a), None);

        let raw = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr.clone(),
                fmp_wire(404, 9, 0),
                9_000,
            ),
        );
        let header = PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&raw.payload).unwrap());
        assert_eq!(raw.path().transport_id(), Some(transport_id));
        assert_eq!(raw.path().remote_addr(), Some(&remote_addr));
        assert_eq!(raw.activity_tick(), Some(ActivityTick::new(9_000)));
        assert_eq!(routes.route(&raw, header), Some(route_a));

        let wrong_transport = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                TransportId::new(41),
                remote_addr.clone(),
                fmp_wire(404, 10, 0),
                9_001,
            ),
        );
        let header =
            PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&wrong_transport.payload).unwrap());
        assert_eq!(routes.route(&wrong_transport, header), None);

        assert_eq!(
            routes.register_fmp(transport_id, 404, route_b),
            Some(route_a)
        );
        let header = PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&raw.payload).unwrap());
        assert_eq!(routes.route(&raw, header), Some(route_b));
        assert_eq!(routes.unregister_fmp(transport_id, 404), Some(route_b));
        let header = PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&raw.payload).unwrap());
        assert_eq!(routes.route(&raw, header), None);
    }

    #[test]
    fn live_ingress_routes_fsp_require_source_context_and_refresh_cleanly() {
        let source = NodeAddr::from_bytes([0x42; 16]);
        let owner = OwnerId::fsp_node(source);
        let mut routes = PacketMover2LiveRouteTable::default();
        let old_route = PacketMover2IngressRoute::new(owner, 3, OutputTarget::Tun)
            .with_class(PacketClass::Bulk);
        let new_route = PacketMover2IngressRoute::new(owner, 4, OutputTarget::Endpoint)
            .with_class(PacketClass::Mmp);
        assert_eq!(routes.register_fsp(source, old_route), None);

        let bare_raw = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fsp,
            ReceivedPacket::with_timestamp(
                TransportId::new(42),
                TransportAddr::from_string("198.51.100.42:9000"),
                fsp_wire(77, 0),
                1,
            ),
        );
        let header =
            PacketMover2IngressHeader::Fsp(FspWireHeader::parse(&bare_raw.payload).unwrap());
        assert_eq!(bare_raw.fsp_source(), None);
        assert_eq!(routes.route(&bare_raw, header), None);

        let sourced_raw = bare_raw.clone().with_fsp_source(source);
        let header =
            PacketMover2IngressHeader::Fsp(FspWireHeader::parse(&sourced_raw.payload).unwrap());
        assert_eq!(sourced_raw.fsp_source(), Some(source));
        assert_eq!(routes.route(&sourced_raw, header), Some(old_route));

        assert_eq!(routes.register_fsp(source, new_route), Some(old_route));
        let header =
            PacketMover2IngressHeader::Fsp(FspWireHeader::parse(&sourced_raw.payload).unwrap());
        assert_eq!(routes.route(&sourced_raw, header), Some(new_route));
        assert_eq!(routes.unregister_fsp(source), Some(new_route));
        let header =
            PacketMover2IngressHeader::Fsp(FspWireHeader::parse(&sourced_raw.payload).unwrap());
        assert_eq!(routes.route(&sourced_raw, header), None);
    }

    #[test]
    fn live_ingress_routes_unregister_owner_prunes_stale_fmp_and_fsp_routes() {
        let stale_source = NodeAddr::from_bytes([0x4a; 16]);
        let keep_source = NodeAddr::from_bytes([0x4b; 16]);
        let stale_fmp_owner = OwnerId::fmp_node(stale_source);
        let stale_fsp_owner = OwnerId::fsp_node(stale_source);
        let keep_owner = OwnerId::fmp_node(keep_source);
        let transport_a = TransportId::new(50);
        let transport_b = TransportId::new(51);
        let transport_keep = TransportId::new(52);
        let remote_addr = TransportAddr::from_string("198.51.100.50:9000");
        let mut routes = PacketMover2LiveRouteTable::default();

        routes.register_fmp(
            transport_a,
            500,
            PacketMover2IngressRoute::new(stale_fmp_owner, 1, OutputTarget::Endpoint)
                .with_class(PacketClass::Liveness),
        );
        routes.register_fmp(
            transport_b,
            501,
            PacketMover2IngressRoute::new(stale_fmp_owner, 2, OutputTarget::Tun)
                .with_class(PacketClass::Rekey),
        );
        routes.register_fsp(
            stale_source,
            PacketMover2IngressRoute::new(stale_fsp_owner, 3, OutputTarget::Endpoint)
                .with_class(PacketClass::Mmp),
        );
        let keep_route = PacketMover2IngressRoute::new(keep_owner, 4, OutputTarget::Endpoint)
            .with_class(PacketClass::Control);
        routes.register_fmp(transport_keep, 502, keep_route);

        assert_eq!(routes.unregister_owner(stale_fmp_owner), 2);
        assert_eq!(routes.unregister_owner(stale_fsp_owner), 1);
        assert_eq!(routes.unregister_owner(stale_fmp_owner), 0);

        let stale_a = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                transport_a,
                remote_addr.clone(),
                fmp_wire(500, 10, 0),
                50_000,
            ),
        );
        let header =
            PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&stale_a.payload).unwrap());
        assert_eq!(routes.route(&stale_a, header), None);

        let stale_b = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                transport_b,
                remote_addr.clone(),
                fmp_wire(501, 11, 0),
                50_001,
            ),
        );
        let header =
            PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&stale_b.payload).unwrap());
        assert_eq!(routes.route(&stale_b, header), None);

        let stale_fsp = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fsp,
            ReceivedPacket::with_timestamp(
                transport_a,
                remote_addr.clone(),
                fsp_wire(12, 0),
                50_002,
            ),
        )
        .with_fsp_source(stale_source);
        let header =
            PacketMover2IngressHeader::Fsp(FspWireHeader::parse(&stale_fsp.payload).unwrap());
        assert_eq!(routes.route(&stale_fsp, header), None);

        let keep_raw = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                transport_keep,
                remote_addr,
                fmp_wire(502, 13, 0),
                50_003,
            ),
        );
        let header =
            PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&keep_raw.payload).unwrap());
        assert_eq!(routes.route(&keep_raw, header), Some(keep_route));
    }

    #[test]
    fn runtime_raw_ingress_turn_uses_live_ingress_routes() {
        let fmp_source = NodeAddr::from_bytes([0x43; 16]);
        let fsp_source = NodeAddr::from_bytes([0x44; 16]);
        let fmp_owner = OwnerId::fmp_node(fmp_source);
        let fsp_owner = OwnerId::fsp_node(fsp_source);
        let fmp_key = 43;
        let fsp_key = 44;
        let transport_id = TransportId::new(43);
        let remote_addr = TransportAddr::from_string("198.51.100.43:9000");

        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8), CopyCryptoWorker);
        driver.register_owner(fmp_owner, OwnerConfig::new(11, 8));
        driver.register_owner(fsp_owner, OwnerConfig::new(12, 8));
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
            430,
            PacketMover2IngressRoute::new(fmp_owner, 11, OutputTarget::Endpoint)
                .with_class(PacketClass::Liveness),
        );
        routes.register_fsp(
            fsp_source,
            PacketMover2IngressRoute::new(fsp_owner, 12, OutputTarget::Tun)
                .with_class(PacketClass::Mmp),
        );

        let fmp_raw = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr.clone(),
                fmp_encrypted_wire(430, 1, 0, b"fmp-live", fmp_key),
                100,
            ),
        );
        let fsp_raw = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fsp,
            ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr.clone(),
                fsp_encrypted_wire(2, 0, b"fsp-live", fsp_key),
                101,
            ),
        )
        .with_fsp_source(fsp_source);

        let turn = driver.run_aead_raw_ingress_turn(
            [fmp_raw, fsp_raw],
            &mut routes,
            std::iter::empty(),
            8,
        );

        assert_eq!(turn.summary().raw_ingress_dropped(), 0);
        assert_eq!(turn.summary().inbound_admitted(), 2);
        assert_eq!(turn.summary().dispatched(), 2);
        assert_eq!(turn.summary().outputs(), 2);
        assert!(turn.raw_ingress_drops().is_empty());
        assert!(turn.drops().is_empty());
        assert_eq!(
            turn.outputs()
                .iter()
                .map(PacketOutput::owner)
                .collect::<Vec<_>>(),
            vec![fmp_owner, fsp_owner]
        );
        assert_eq!(
            turn.outputs()
                .iter()
                .map(PacketOutput::target)
                .collect::<Vec<_>>(),
            vec![OutputTarget::Endpoint, OutputTarget::Tun]
        );
        assert_eq!(
            &turn.outputs()[0].payload[FMP_ESTABLISHED_HEADER_SIZE..],
            b"fmp-live"
        );
        assert_eq!(&turn.outputs()[1].payload[FSP_HEADER_SIZE..], b"fsp-live");

        let live_path = Some(TransportPath::live(transport_id, remote_addr));
        assert_eq!(
            driver.owner_mut(fmp_owner).unwrap().active_path(),
            live_path.clone()
        );
        assert_eq!(
            driver.owner_mut(fsp_owner).unwrap().active_path(),
            live_path
        );
    }

    #[test]
    fn live_output_sink_sends_tun_endpoint_and_transport_once() {
        let fmp_source = NodeAddr::from_bytes([0x45; 16]);
        let fsp_source = NodeAddr::from_bytes([0x46; 16]);
        let fmp_owner = OwnerId::fmp_node(fmp_source);
        let fsp_owner = OwnerId::fsp_node(fsp_source);
        let fmp_key = 45;
        let fsp_key = 46;
        let transport_id = TransportId::new(45);
        let remote_addr = TransportAddr::from_string("198.51.100.45:9000");

        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8), CopyCryptoWorker);
        driver.register_owner(
            fmp_owner,
            OwnerConfig::new(1, 8).with_next_send_counter(700),
        );
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
            450,
            PacketMover2IngressRoute::new(fmp_owner, 1, OutputTarget::Tun)
                .with_class(PacketClass::Liveness),
        );
        routes.register_fsp(
            fsp_source,
            PacketMover2IngressRoute::new(fsp_owner, 1, OutputTarget::Endpoint)
                .with_class(PacketClass::Mmp),
        );
        let mut raw_source = PacketMover2LiveRawIngressSource::new(VecDeque::from([
            PacketMover2LiveIngressPacket::fmp(ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr.clone(),
                fmp_encrypted_wire(450, 1, 0, b"tun-live", fmp_key),
                450_001,
            )),
            PacketMover2LiveIngressPacket::fsp(
                ReceivedPacket::with_timestamp(
                    transport_id,
                    remote_addr.clone(),
                    fsp_encrypted_wire(2, 0, b"endpoint-live", fsp_key),
                    450_002,
                ),
                fsp_source,
            ),
        ]));
        let mut outbound_source = VecDeque::from([OutboundPacket::fmp(
            fmp_owner,
            1,
            PacketClass::Bulk,
            451,
            0,
            b"transport-live".to_vec(),
        )]);
        let mut tun = LiveTunRecorder::default();
        let mut endpoint = LiveEndpointRecorder::default();
        let mut transport = LiveTransportRecorder::default();

        let turn = {
            let mut sink = PacketMover2LiveOutputSink::new(&mut tun, &mut endpoint, &mut transport);
            driver.pump_aead_output_turn(
                &mut raw_source,
                &mut routes,
                8,
                &mut outbound_source,
                8,
                &mut sink,
                8,
            )
        };

        assert_eq!(turn.summary().raw_ingress_dropped(), 0);
        assert_eq!(turn.summary().inbound_admitted(), 2);
        assert_eq!(turn.summary().outbound_admitted(), 1);
        assert_eq!(turn.summary().outputs(), 3);
        assert_eq!(turn.summary().outputs_sent(), 3);
        assert_eq!(turn.summary().outputs_dropped(), 0);
        assert!(turn.outputs().is_empty());
        assert!(turn.output_drops().is_empty());
        assert!(turn.raw_ingress_drops().is_empty());
        assert!(turn.drops().is_empty());
        assert!(raw_source.source_mut().is_empty());
        assert!(outbound_source.is_empty());

        assert_eq!(
            tun.outputs,
            vec![LiveOutputRecord {
                owner: fmp_owner,
                counter: 1,
                ingress_seq: 0,
                payload: b"tun-live".to_vec(),
            }]
        );
        assert_eq!(
            endpoint.outputs,
            vec![LiveOutputRecord {
                owner: fsp_owner,
                counter: 2,
                ingress_seq: 1,
                payload: b"endpoint-live".to_vec(),
            }]
        );
        assert_eq!(transport.outputs.len(), 1);
        let sent = &transport.outputs[0];
        assert_eq!(sent.transport_id, transport_id);
        assert_eq!(sent.remote_addr, remote_addr);
        assert_eq!(sent.owner, fmp_owner);
        assert_eq!(sent.counter, 700);
        assert_eq!(sent.ingress_seq, 0);
        let header = FmpWireHeader::parse(&sent.payload).unwrap();
        assert_eq!(header.receiver_idx(), 451);
        assert_eq!(header.counter(), 700);
        assert_eq!(
            open_fmp_wire_payload(&sent.payload, fmp_key),
            b"transport-live"
        );
    }

    #[tokio::test]
    async fn live_node_turn_sends_node_outputs_and_attributes_transport_drop() {
        let fmp_source = NodeAddr::from_bytes([0x4a; 16]);
        let source_peer = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let fsp_source = *source_peer.node_addr();
        let fmp_owner = OwnerId::fmp_node(fmp_source);
        let fsp_owner = OwnerId::fsp_node(fsp_source);
        let fmp_key = 74;
        let fsp_key = 75;
        let transport_id = TransportId::new(74);
        let remote_addr = TransportAddr::from_string("198.51.100.74:9000");
        let live_path = TransportPath::live(transport_id, remote_addr.clone());

        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let (tun_tx, tun_rx) = std::sync::mpsc::channel();
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8), CopyCryptoWorker);
        driver.register_owner(
            fmp_owner,
            OwnerConfig::new(1, 8).with_next_send_counter(740),
        );
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
            740,
            PacketMover2IngressRoute::new(fmp_owner, 1, OutputTarget::Tun)
                .with_class(PacketClass::Liveness),
        );
        routes.register_fsp(
            fsp_source,
            PacketMover2IngressRoute::new(fsp_owner, 1, OutputTarget::Endpoint)
                .with_class(PacketClass::Mmp),
        );
        routes.register_tun_destination(
            fmp_source,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                fmp_owner,
                1,
                PacketClass::Bulk,
                741,
                0,
            )),
        );
        let mut raw_source = PacketMover2LiveRawIngressSource::new(VecDeque::from([
            PacketMover2LiveIngressPacket::fmp(ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr.clone(),
                fmp_encrypted_wire(740, 1, 0, b"tun-live-node", fmp_key),
                740_001,
            )),
            PacketMover2LiveIngressPacket::fsp(
                ReceivedPacket::with_timestamp(
                    transport_id,
                    remote_addr.clone(),
                    fsp_encrypted_wire(2, 0, b"endpoint-live-node", fsp_key),
                    740_002,
                ),
                fsp_source,
            ),
        ]));
        let (_endpoint_priority_tx, mut endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
        let (_endpoint_bulk_tx, mut endpoint_bulk_rx) = tokio::sync::mpsc::channel(1);
        let (tun_outbound_tx, mut tun_outbound_rx) = tokio::sync::mpsc::channel(1);
        tun_outbound_tx
            .try_send(tun_ipv6_packet(fmp_source, 48))
            .expect("enqueue TUN outbound packet");
        let mut deferred_endpoint_commands = Vec::new();
        let transports = HashMap::<TransportId, TransportHandle>::new();
        let resolver = |addr: &NodeAddr| {
            if addr == &fsp_source {
                Some(source_peer)
            } else {
                None
            }
        };

        let turn = driver
            .pump_aead_live_node_route_table_turn(
                &mut raw_source,
                &mut routes,
                8,
                &mut endpoint_priority_rx,
                &mut endpoint_bulk_rx,
                0,
                &mut tun_outbound_rx,
                8,
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
        assert_eq!(turn.summary().outbound_admitted(), 1);
        assert_eq!(turn.summary().outputs(), 3);
        assert_eq!(turn.summary().outputs_sent(), 2);
        assert_eq!(turn.summary().outputs_dropped(), 1);
        assert_eq!(turn.transport_planned(), 1);
        assert_eq!(turn.transport_sent(), 0);
        assert_eq!(turn.transport_dropped(), 1);
        assert!(turn.raw_ingress_drops().is_empty());
        assert!(turn.drops().is_empty());
        assert_eq!(turn.output_drops().len(), 1);
        assert_eq!(turn.output_drops()[0].owner(), fmp_owner);
        assert_eq!(turn.output_drops()[0].counter(), 740);
        assert_eq!(turn.output_drops()[0].target(), OutputTarget::Transport);
        assert_eq!(turn.output_drops()[0].path(), Some(live_path.clone()));
        assert_eq!(
            turn.output_drops()[0].reason(),
            PacketMover2OutputError::NoRoute
        );
        assert!(turn.endpoint_command_drops().is_empty());
        assert!(turn.tun_outbound_drops().is_empty());
        assert!(raw_source.source_mut().is_empty());
        assert!(tun_outbound_rx.try_recv().is_err());

        assert_eq!(tun_rx.try_recv().unwrap(), b"tun-live-node".to_vec());
        match endpoint_io.event_rx.try_recv().expect("endpoint event") {
            NodeEndpointEvent::Data {
                source_peer: delivered_source,
                payload,
                ..
            } => {
                assert_eq!(delivered_source, source_peer);
                assert_eq!(payload, b"endpoint-live-node");
            }
            event => panic!("expected single endpoint event, got {event:?}"),
        }
        assert_eq!(
            driver.owner_mut(fmp_owner).unwrap().active_path(),
            Some(live_path)
        );
    }

    #[tokio::test]
    async fn live_node_packet_rx_turn_drains_transport_channel_to_tun() {
        let fmp_source = NodeAddr::from_bytes([0x4b; 16]);
        let fmp_owner = OwnerId::fmp_node(fmp_source);
        let fmp_key = 75;
        let transport_id = TransportId::new(75);
        let remote_addr = TransportAddr::from_string("198.51.100.75:9000");
        let live_path = TransportPath::live(transport_id, remote_addr.clone());
        let (packet_tx, mut packet_rx) = crate::transport::packet_channel(8);
        packet_tx
            .send(ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr.clone(),
                fmp_encrypted_wire(750, 1, 0, b"packet-rx-tun", fmp_key),
                750_001,
            ))
            .expect("enqueue packet rx input");

        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let (tun_tx, tun_rx) = std::sync::mpsc::channel();
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8), CopyCryptoWorker);
        driver.register_owner(fmp_owner, OwnerConfig::new(1, 8));
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fmp_key), test_key(fmp_key)));

        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_fmp(
            transport_id,
            750,
            PacketMover2IngressRoute::new(fmp_owner, 1, OutputTarget::Tun)
                .with_class(PacketClass::Liveness),
        );
        let (_endpoint_priority_tx, mut endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
        let (_endpoint_bulk_tx, mut endpoint_bulk_rx) = tokio::sync::mpsc::channel(1);
        let (_tun_outbound_tx, mut tun_outbound_rx) = tokio::sync::mpsc::channel(1);
        let mut deferred_endpoint_commands = Vec::new();
        let transports = HashMap::<TransportId, TransportHandle>::new();
        let mut raw_ingress = PacketMover2FmpPacketRxSource::new(&mut packet_rx);

        let turn = driver
            .pump_aead_live_node_route_table_turn(
                &mut raw_ingress,
                &mut routes,
                8,
                &mut endpoint_priority_rx,
                &mut endpoint_bulk_rx,
                0,
                &mut tun_outbound_rx,
                8,
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
        assert_eq!(turn.summary().outbound_admitted(), 0);
        assert_eq!(turn.summary().outputs(), 1);
        assert_eq!(turn.summary().outputs_sent(), 1);
        assert_eq!(turn.summary().outputs_dropped(), 0);
        assert_eq!(turn.transport_planned(), 0);
        assert_eq!(turn.transport_sent(), 0);
        assert_eq!(turn.transport_dropped(), 0);
        assert!(turn.raw_ingress_drops().is_empty());
        assert!(turn.output_drops().is_empty());
        assert!(turn.drops().is_empty());
        assert!(turn.endpoint_command_drops().is_empty());
        assert!(turn.tun_outbound_drops().is_empty());
        assert!(packet_rx.try_recv().is_err());
        assert_eq!(tun_rx.try_recv().unwrap(), b"packet-rx-tun".to_vec());
        assert!(endpoint_io.event_rx.try_recv().is_err());
        assert_eq!(
            driver.owner_mut(fmp_owner).unwrap().active_path(),
            Some(live_path)
        );
    }
