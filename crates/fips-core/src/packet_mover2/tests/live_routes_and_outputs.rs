    fn materialize_direct_fsp_segments(
        segments: &PacketMover2DirectFspTransportSegments,
    ) -> Vec<PacketOutput> {
        let mut outputs = Vec::with_capacity(segments.len());
        for index in 0..segments.len() {
            let mut payload = Vec::with_capacity(segments.payload_len(index));
            let mut slices = [None; crate::transport::udp::UDP_PAYLOAD_MAX_SLICES];
            let slice_count = segments.payload_slices(index, &mut slices);
            for slice in slices.iter().take(slice_count).flatten() {
                payload.extend_from_slice(slice);
            }
            outputs.push(packet_output_with_payload(&segments.output, payload.into()));
        }
        outputs
    }

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
        routes.register_fmp(transport_id, 404, route_a);

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

        routes.register_fmp(transport_id, 404, route_b);
        let header = PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&raw.payload).unwrap());
        assert_eq!(routes.route(&raw, header), Some(route_b));
        assert_eq!(routes.unregister_owner(owner_b), 1);
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
        routes.register_fsp(source, old_route);

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
        let routed = routes.route(&sourced_raw, header).expect("sourced FSP route");
        assert_eq!(routed.owner, old_route.owner);
        assert_eq!(routed.generation, old_route.generation);
        assert_eq!(routed.output, old_route.output);
        assert_eq!(routed.class, PacketClass::Bulk);

        routes.register_fsp(source, new_route);
        let header =
            PacketMover2IngressHeader::Fsp(FspWireHeader::parse(&sourced_raw.payload).unwrap());
        assert_eq!(routes.route(&sourced_raw, header), Some(new_route));
        assert_eq!(routes.unregister_owner(owner), 1);
        let header =
            PacketMover2IngressHeader::Fsp(FspWireHeader::parse(&sourced_raw.payload).unwrap());
        assert_eq!(routes.route(&sourced_raw, header), None);
    }

    #[test]
    fn packet_rx_source_classifies_flagged_direct_fsp_with_source_context() {
        let source = NodeAddr::from_bytes([0x44; 16]);
        let transport_id = TransportId::new(44);
        let remote_addr = TransportAddr::from_string("198.51.100.44:9000");
        let (_tx, mut rx) = crate::transport::packet_channel(1);
        let mut direct_sources = std::collections::HashMap::new();
        direct_sources.insert(
            (transport_id, remote_addr.clone()),
            PacketMover2DirectFspSource {
                source_addr: source,
                path_mtu: 1400,
            },
        );
        let first = ReceivedPacket::with_timestamp(
            transport_id,
            remote_addr.clone(),
            fsp_wire(
                88,
                crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
            ),
            44_000,
        );
        let mut source_rx =
            PacketMover2FmpPacketRxSource::with_first_and_direct_fsp_sources(
                &mut rx,
                Some(first),
                direct_sources,
            );
        let mut packets = Vec::new();
        assert_eq!(
            source_rx.drain_raw_ingress(1, |packet| packets.push(packet)),
            1
        );
        assert!(source_rx.take_control_ingress().is_empty());
        assert_eq!(packets.len(), 1);
        let packet = &packets[0];
        assert_eq!(packet.protocol(), PacketProtocol::Fsp);
        assert_eq!(packet.fsp_source(), Some(source));
        assert_eq!(packet.previous_hop(), Some(source));
        assert_eq!(packet.path_mtu(), 1400);
        assert_eq!(packet.path().transport_id(), Some(transport_id));
        assert_eq!(packet.path().remote_addr(), Some(&remote_addr));
        assert_eq!(packet.activity_tick(), Some(ActivityTick::new(44_000)));
    }

    #[test]
    fn direct_fsp_transport_segments_reassemble_before_classification() {
        let source = NodeAddr::from_bytes([0x45; 16]);
        let owner = OwnerId::fsp_node(source);
        let transport_id = TransportId::new(45);
        let remote_addr = TransportAddr::from_string("198.51.100.45:9000");
        let mut direct_sources = std::collections::HashMap::new();
        direct_sources.insert(
            (transport_id, remote_addr.clone()),
            PacketMover2DirectFspSource {
                source_addr: source,
                path_mtu: 220,
            },
        );

        let mut wire = fsp_wire(
            4242,
            crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
        );
        wire.extend((0..700).map(|idx| (idx % 251) as u8));
        let mut output =
            transport_output(owner, 4242, 9, transport_id, remote_addr.clone(), wire.clone());
        output.path_mtu = 220;

        let segments = match packet_mover2_direct_fsp_transport_output(output).unwrap() {
            PacketMover2DirectFspTransportOutput::Segments(segments) => {
                materialize_direct_fsp_segments(&segments)
            }
            PacketMover2DirectFspTransportOutput::Whole(_) => panic!("expected segmented output"),
        };
        assert!(segments.len() > 1);
        assert!(segments.iter().all(|segment| segment.payload_len() <= 220));
        assert!(segments.iter().all(|segment| {
            packet_mover2_direct_fsp_transport_fragment_is_fragment(segment.payload())
        }));

        let (_tx, mut rx) = crate::transport::packet_channel(1);
        let mut reassembler = PacketMover2DirectFspReassembler::default();
        let mut packets = Vec::new();
        for (idx, segment) in segments.into_iter().rev().enumerate() {
            let received = ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr.clone(),
                segment.payload,
                45_000 + idx as u64,
            );
            let mut source_rx =
                PacketMover2FmpPacketRxSource::with_first_direct_fsp_sources_and_reassembler(
                    &mut rx,
                    Some(received),
                    direct_sources.clone(),
                    Some(&mut reassembler),
                );
            assert_eq!(
                source_rx.drain_raw_ingress(1, |packet| packets.push(packet)),
                1
            );
            assert!(source_rx.take_control_ingress().is_empty());
        }

        assert_eq!(packets.len(), 1);
        let packet = &packets[0];
        assert_eq!(packet.protocol(), PacketProtocol::Fsp);
        assert_eq!(packet.fsp_source(), Some(source));
        assert_eq!(packet.path_mtu(), 220);
        assert_eq!(packet.payload.as_slice(), wire.as_slice());
    }

    #[test]
    fn fast_ingress_routes_direct_fsp_segments_before_packet_channel() {
        let source = NodeAddr::from_bytes([0x46; 16]);
        let owner = OwnerId::fsp_node(source);
        let transport_id = TransportId::new(46);
        let remote_addr = TransportAddr::from_string("198.51.100.46:9000");
        let route = PacketMover2IngressRoute::new(owner, 10, OutputTarget::Endpoint)
            .with_class(PacketClass::Bulk);
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_fsp(source, route);
        let mut direct_sources = std::collections::HashMap::new();
        direct_sources.insert(
            (transport_id, remote_addr.clone()),
            PacketMover2DirectFspSource {
                source_addr: source,
                path_mtu: 240,
            },
        );
        routes.set_established_fast_ingress_direct_fsp_sources(direct_sources);

        let mut wire = fsp_wire(
            4646,
            crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
        );
        wire.extend((0..900).map(|idx| (idx % 251) as u8));
        let mut output =
            transport_output(owner, 4646, 10, transport_id, remote_addr.clone(), wire.clone());
        output.path_mtu = 240;

        let segments = match packet_mover2_direct_fsp_transport_output(output).unwrap() {
            PacketMover2DirectFspTransportOutput::Segments(segments) => {
                materialize_direct_fsp_segments(&segments)
            }
            PacketMover2DirectFspTransportOutput::Whole(_) => panic!("expected segmented output"),
        };
        assert!(segments.len() > 1);

        let (sink, mut fast_rx) =
            PacketMover2EstablishedFastIngressSink::channel(
                routes.established_fast_ingress_snapshot(),
                64,
            );
        let mut first_half: Vec<_> = segments[..segments.len() / 2]
            .iter()
            .enumerate()
            .map(|(idx, segment)| {
                ReceivedPacket::with_timestamp(
                    transport_id,
                    remote_addr.clone(),
                    segment.payload.clone(),
                    46_000 + idx as u64,
                )
            })
            .collect();
        let first_half_len = first_half.len();
        assert_eq!(sink.try_ingest_batch(&mut first_half), first_half_len);
        assert!(first_half.is_empty());
        assert!(fast_rx.try_recv().is_err());

        let mut second_half: Vec<_> = segments[segments.len() / 2..]
            .iter()
            .enumerate()
            .map(|(idx, segment)| {
                ReceivedPacket::with_timestamp(
                    transport_id,
                    remote_addr.clone(),
                    segment.payload.clone(),
                    46_100 + idx as u64,
                )
            })
            .collect();
        assert_eq!(
            sink.try_ingest_batch(&mut second_half),
            segments.len() - segments.len() / 2
        );
        assert!(second_half.is_empty());
        let batch = fast_rx.try_recv().expect("direct FSP fast batch");
        assert_eq!(batch.len(), 1);
        let packet = batch
            .into_packets()
            .pop()
            .expect("direct FSP socket packet");
        assert_eq!(packet.owner, owner);
        assert_eq!(packet.generation, 10);
        assert_eq!(packet.counter, 4646);
        assert_eq!(packet.class, PacketClass::Bulk);
        assert_eq!(packet.output, OutputTarget::Endpoint);
        assert_eq!(
            packet.source_path,
            Some(TransportPath::live(transport_id, remote_addr))
        );
        assert_eq!(packet.previous_hop, Some(source));
        assert_eq!(packet.path_mtu, 240);
        assert_eq!(
            packet.wire_flags & crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
            crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT
        );
        assert_eq!(packet.payload.as_slice(), wire.as_slice());
    }

    #[test]
    fn fast_ingress_consumes_direct_fsp_fragments_while_output_queue_full() {
        let source = NodeAddr::from_bytes([0x48; 16]);
        let owner = OwnerId::fsp_node(source);
        let transport_id = TransportId::new(48);
        let remote_addr = TransportAddr::from_string("198.51.100.48:9000");
        let route = PacketMover2IngressRoute::new(owner, 12, OutputTarget::Endpoint)
            .with_class(PacketClass::Bulk);
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_fsp(source, route);
        let mut direct_sources = std::collections::HashMap::new();
        direct_sources.insert(
            (transport_id, remote_addr.clone()),
            PacketMover2DirectFspSource {
                source_addr: source,
                path_mtu: 240,
            },
        );
        routes.set_established_fast_ingress_direct_fsp_sources(direct_sources);

        let (sink, fast_rx) =
            PacketMover2EstablishedFastIngressSink::channel(
                routes.established_fast_ingress_snapshot(),
                1,
            );
        let mut fill_queue = vec![ReceivedPacket::with_timestamp(
            transport_id,
            remote_addr.clone(),
            fsp_wire(
                4800,
                crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
            ),
            48_000,
        )];
        assert_eq!(sink.try_ingest_batch(&mut fill_queue), 1);
        assert!(fill_queue.is_empty());
        assert_eq!(fast_rx.len(), 1);

        let mut wire = fsp_wire(
            4848,
            crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
        );
        wire.extend((0..900).map(|idx| (idx % 251) as u8));
        let mut output =
            transport_output(owner, 4848, 12, transport_id, remote_addr.clone(), wire.clone());
        output.path_mtu = 240;
        let segments = match packet_mover2_direct_fsp_transport_output(output).unwrap() {
            PacketMover2DirectFspTransportOutput::Segments(segments) => {
                materialize_direct_fsp_segments(&segments)
            }
            PacketMover2DirectFspTransportOutput::Whole(_) => panic!("expected segmented output"),
        };
        assert!(segments.len() > 2);

        let split = segments.len() / 2;
        let mut first_half: Vec<_> = segments[..split]
            .iter()
            .enumerate()
            .map(|(idx, segment)| {
                ReceivedPacket::with_timestamp(
                    transport_id,
                    remote_addr.clone(),
                    segment.payload.clone(),
                    48_100 + idx as u64,
                )
            })
            .collect();
        let first_half_len = first_half.len();
        assert_eq!(sink.try_ingest_batch(&mut first_half), first_half_len);
        assert!(
            first_half.is_empty(),
            "pending direct-FSP fragments should not fall back to the packet channel"
        );
        assert_eq!(fast_rx.len(), 1);

        let mut second_half: Vec<_> = segments[split..]
            .iter()
            .enumerate()
            .map(|(idx, segment)| {
                ReceivedPacket::with_timestamp(
                    transport_id,
                    remote_addr.clone(),
                    segment.payload.clone(),
                    48_200 + idx as u64,
                )
            })
            .collect();
        let second_half_len = second_half.len();
        assert_eq!(sink.try_ingest_batch(&mut second_half), second_half_len);
        assert_eq!(
            second_half.len(),
            1,
            "full fast queue should fall back with one reassembled direct-FSP record"
        );
        assert_eq!(second_half[0].data.as_slice(), wire.as_slice());
        assert_eq!(fast_rx.len(), 1);
    }

    #[test]
    fn fast_ingress_preserves_direct_fsp_fragment_until_route_exists() {
        let source = NodeAddr::from_bytes([0x47; 16]);
        let owner = OwnerId::fsp_node(source);
        let transport_id = TransportId::new(47);
        let remote_addr = TransportAddr::from_string("198.51.100.47:9000");
        let routes = PacketMover2LiveRouteTable::default();
        let mut direct_sources = std::collections::HashMap::new();
        direct_sources.insert(
            (transport_id, remote_addr.clone()),
            PacketMover2DirectFspSource {
                source_addr: source,
                path_mtu: 240,
            },
        );
        routes.set_established_fast_ingress_direct_fsp_sources(direct_sources);

        let mut wire = fsp_wire(
            4747,
            crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
        );
        wire.extend((0..900).map(|idx| (idx % 251) as u8));
        let mut output =
            transport_output(owner, 4747, 10, transport_id, remote_addr.clone(), wire);
        output.path_mtu = 240;
        let segments = match packet_mover2_direct_fsp_transport_output(output).unwrap() {
            PacketMover2DirectFspTransportOutput::Segments(segments) => {
                materialize_direct_fsp_segments(&segments)
            }
            PacketMover2DirectFspTransportOutput::Whole(_) => panic!("expected segmented output"),
        };
        let fragment = segments.into_iter().next().expect("fragment").payload;
        let original = fragment.clone();
        let (sink, mut fast_rx) =
            PacketMover2EstablishedFastIngressSink::channel(
                routes.established_fast_ingress_snapshot(),
                64,
            );
        let mut packets = vec![ReceivedPacket::with_timestamp(
            transport_id,
            remote_addr,
            fragment,
            47_000,
        )];

        assert_eq!(sink.try_ingest_batch(&mut packets), 0);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].data.as_slice(), original.as_slice());
        assert!(fast_rx.try_recv().is_err());
    }

    #[test]
    fn live_ingress_keeps_encrypted_fsp_bulk_before_decrypt() {
        let source = NodeAddr::from_bytes([0x43; 16]);
        let local = NodeAddr::from_bytes([0x44; 16]);
        let owner = OwnerId::fsp_node(source);
        let transport_id = TransportId::new(43);
        let remote_addr = TransportAddr::from_string("198.51.100.43:9000");
        let mut routes = PacketMover2LiveRouteTable::default();
        let route = PacketMover2IngressRoute::new(
            owner,
            3,
            OutputTarget::SessionPayload { local_addr: local },
        )
        .with_class(PacketClass::Bulk);
        routes.register_fsp(source, route);

        let mut large_wire = fsp_wire(79, 0);
        large_wire.resize(
            FSP_HEADER_SIZE
                .saturating_add(FSP_INNER_HEADER_SIZE)
                .saturating_add(crate::node::ENDPOINT_EVENT_TEST_PAYLOAD_LEN)
                .saturating_add(AEAD_TAG_SIZE)
                .saturating_add(1),
            0,
        );
        let large_raw = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fsp,
            ReceivedPacket::with_timestamp(transport_id, remote_addr, large_wire, 43_001),
        )
        .with_fsp_source(source);
        let header =
            PacketMover2IngressHeader::Fsp(FspWireHeader::parse(&large_raw.payload).unwrap());
        assert_eq!(
            routes.route(&large_raw, header).expect("large FSP route").class,
            PacketClass::Bulk
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
        let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(
            fmp_owner,
            OwnerConfig::new(1, 8).with_next_send_counter(740),
        );
        driver.register_owner(
            fsp_owner,
            OwnerConfig::new(1, 8).with_source_peer(source_peer),
        );
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
        let (_endpoint_data_tx, mut endpoint_data_rx) = endpoint_data_batch_channel(1);
        let (tun_outbound_tx, mut tun_outbound_rx) =
            crate::upper::tun::tun_outbound_channel(1);
        tun_outbound_tx
            .try_send(tun_ipv6_packet(fmp_source, 48))
            .expect("enqueue TUN outbound packet");
        let mut deferred_endpoint_data_batches = Vec::new();
        let mut deferred_tun_packets = Vec::new();
        let transports = HashMap::<TransportId, TransportHandle>::new();

        let turn = pump_aead_live_node_route_table_turn(&mut driver,
                &mut raw_source,
                &mut routes,
                8,
                &mut endpoint_data_rx,
                0,
                &mut tun_outbound_rx,
                8,
                &mut deferred_endpoint_data_batches,
                &mut deferred_tun_packets,
                &tun_tx,
                &endpoint_io.event_tx,
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
        assert!(deferred_tun_packets.is_empty());
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
        assert!(turn.endpoint_data_drops().is_empty());
        assert!(turn.tun_outbound_drops().is_empty());
        assert!(raw_source.source.is_empty());
        assert!(tun_outbound_rx.try_recv().is_err());

        assert_eq!(tun_rx.try_recv().unwrap(), b"tun-live-node".to_vec());
        match endpoint_io.event_rx.try_recv().expect("endpoint event") {
            NodeEndpointEvent { messages, .. } => {
                assert_eq!(messages.len(), 1);
                assert_eq!(messages[0].source_peer, source_peer);
                assert_eq!(messages[0].payload, b"endpoint-live-node");
            }
        }
        assert_eq!(
            driver.owner_mut(fmp_owner).unwrap().active_path(),
            Some(live_path)
        );
    }
