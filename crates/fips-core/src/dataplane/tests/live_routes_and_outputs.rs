    fn materialize_direct_fsp_segments(
        segments: &DataplaneDirectFspTransportSegments,
    ) -> Vec<PacketOutput> {
        let mut outputs = Vec::with_capacity(segments.len());
        for index in 0..segments.len() {
            let mut payload = Vec::with_capacity(segments.payload_len(index));
            let mut slices = [None; crate::transport::udp::UDP_PAYLOAD_MAX_SLICES];
            let slice_count = segments.payload_slices(index, &mut slices);
            for slice in slices.iter().take(slice_count).flatten() {
                payload.extend_from_slice(slice);
            }
            let mut output = segments.output.clone();
            output.payload = PacketBuffer::new(payload);
            outputs.push(output);
        }
        outputs
    }

    fn direct_fsp_sources(
        transport_id: TransportId,
        remote_addr: TransportAddr,
        source_addr: NodeAddr,
        path_mtu: u16,
    ) -> DataplaneDirectFspSources {
        direct_fsp_sources_from([(transport_id, remote_addr, source_addr, path_mtu)])
    }

    fn direct_fsp_sources_from(
        sources: impl IntoIterator<Item = (TransportId, TransportAddr, NodeAddr, u16)>,
    ) -> DataplaneDirectFspSources {
        dataplane_direct_fsp_sources_from_exact(sources.into_iter().map(
            |(transport_id, remote_addr, source_addr, path_mtu)| {
                (
                    transport_id,
                    remote_addr,
                    DataplaneDirectFspSource {
                        source_addr,
                        path_mtu,
                    },
                )
            },
        ))
    }

    #[test]
    fn tcp_priority_output_keeps_its_short_internal_send_bound() {
        assert_eq!(
            non_udp_transport_send_timeout("tcp", Lane::Priority),
            Some(DATAPLANE_TCP_PRIORITY_SEND_TIMEOUT)
        );
        assert_eq!(non_udp_transport_send_timeout("tcp", Lane::Bulk), None);
        assert_eq!(
            non_udp_transport_send_timeout("tor", Lane::Priority),
            None
        );
    }

    #[test]
    fn live_ingress_routes_fmp_by_transport_and_receiver_idx() {
        let transport_id = TransportId::new(40);
        let other_transport_id = TransportId::new(41);
        let remote_addr = TransportAddr::from_string("198.51.100.40:9000");
        let source_a = NodeAddr::from_bytes([0x40; 16]);
        let source_b = NodeAddr::from_bytes([0x41; 16]);
        let owner_a = OwnerId::fmp_node(source_a);
        let owner_b = OwnerId::fmp_node(source_b);
        let route_a = DataplaneIngressRoute::new(owner_a, 7, OutputTarget::Transport)
            .with_class(PacketClass::Liveness);
        let route_b = DataplaneIngressRoute::new(owner_b, 8, OutputTarget::Transport)
            .with_class(PacketClass::Mmp);
        let mut routes = DataplaneLiveRouteTable::default();
        routes.register_fmp(transport_id, 404, route_a);

        let raw = DataplaneRawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr.clone(),
                PacketBuffer::new(fmp_wire(404, 9, 0)),
                9_000,
            ),
        );
        let header = DataplaneIngressHeader::Fmp(FmpWireHeader::parse(raw.payload.as_slice()).unwrap());
        assert_eq!(raw.path.transport_id, transport_id);
        assert_eq!(raw.path.remote_addr, remote_addr);
        assert_eq!(raw.activity_tick, Some(ActivityTick::new(9_000)));
        assert_eq!(routes.route(&raw, header), Some(route_a));

        let wrong_transport = DataplaneRawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                other_transport_id,
                remote_addr.clone(),
                PacketBuffer::new(fmp_wire(404, 10, 0)),
                9_001,
            ),
        );
        let header =
            DataplaneIngressHeader::Fmp(
                FmpWireHeader::parse(wrong_transport.payload.as_slice()).unwrap(),
            );
        assert_eq!(routes.route(&wrong_transport, header), None);

        routes.register_fmp(other_transport_id, 404, route_b);
        let header =
            DataplaneIngressHeader::Fmp(FmpWireHeader::parse(raw.payload.as_slice()).unwrap());
        assert_eq!(routes.route(&raw, header), Some(route_a));
        let header =
            DataplaneIngressHeader::Fmp(
                FmpWireHeader::parse(wrong_transport.payload.as_slice()).unwrap(),
            );
        assert_eq!(routes.route(&wrong_transport, header), Some(route_b));

        routes.register_fmp(transport_id, 404, route_b);
        let header =
            DataplaneIngressHeader::Fmp(FmpWireHeader::parse(raw.payload.as_slice()).unwrap());
        assert_eq!(routes.route(&raw, header), Some(route_b));
        assert_eq!(routes.unregister_owner(owner_b), 2);
        let header =
            DataplaneIngressHeader::Fmp(FmpWireHeader::parse(raw.payload.as_slice()).unwrap());
        assert_eq!(routes.route(&raw, header), None);
    }

    #[test]
    fn live_ingress_routes_fsp_require_source_context_and_refresh_cleanly() {
        let source = NodeAddr::from_bytes([0x42; 16]);
        let owner = OwnerId::fsp_node(source);
        let mut routes = DataplaneLiveRouteTable::default();
        let old_route = DataplaneIngressRoute::new(owner, 3, OutputTarget::Transport)
            .with_class(PacketClass::Bulk);
        let new_route = DataplaneIngressRoute::new(owner, 4, OutputTarget::Transport)
            .with_class(PacketClass::Mmp);
        routes.register_fsp(source, old_route);

        let bare_raw = DataplaneRawIngress::from_live_received(
            PacketProtocol::Fsp,
            ReceivedPacket::with_timestamp(
                TransportId::new(42),
                TransportAddr::from_string("198.51.100.42:9000"),
                PacketBuffer::new(fsp_wire(77, 0)),
                1,
            ),
        );
        let header =
            DataplaneIngressHeader::Fsp(FspWireHeader::parse(bare_raw.payload.as_slice()).unwrap());
        assert_eq!(bare_raw.fsp_source, None);
        assert_eq!(routes.route(&bare_raw, header), None);

        let sourced_raw = bare_raw.clone().with_fsp_source(source);
        let header =
            DataplaneIngressHeader::Fsp(
                FspWireHeader::parse(sourced_raw.payload.as_slice()).unwrap(),
            );
        assert_eq!(sourced_raw.fsp_source, Some(source));
        let routed = routes.route(&sourced_raw, header).expect("sourced FSP route");
        assert_eq!(routed.owner, old_route.owner);
        assert_eq!(routed.generation, old_route.generation);
        assert_eq!(routed.output, old_route.output);
        assert_eq!(routed.class, PacketClass::Bulk);

        routes.register_fsp(source, new_route);
        let header =
            DataplaneIngressHeader::Fsp(
                FspWireHeader::parse(sourced_raw.payload.as_slice()).unwrap(),
            );
        assert_eq!(routes.route(&sourced_raw, header), Some(new_route));
        assert_eq!(routes.unregister_owner(owner), 1);
        let header =
            DataplaneIngressHeader::Fsp(
                FspWireHeader::parse(sourced_raw.payload.as_slice()).unwrap(),
            );
        assert_eq!(routes.route(&sourced_raw, header), None);
    }

    #[test]
    fn packet_rx_source_classifies_flagged_direct_fsp_with_source_context() {
        let source = NodeAddr::from_bytes([0x44; 16]);
        let transport_id = TransportId::new(44);
        let remote_addr = TransportAddr::from_string("198.51.100.44:9000");
        let (_tx, mut rx) = crate::transport::packet_channel(1);
        let direct_sources = direct_fsp_sources(transport_id, remote_addr.clone(), source, 1400);
        let first = ReceivedPacket::with_timestamp(
            transport_id,
            remote_addr.clone(),
            PacketBuffer::new(fsp_wire(
                88,
                crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
            )),
            44_000,
        );
        let mut source_rx =
            DataplaneFmpPacketRxSource::with_first_direct_fsp_sources_and_reassembler(
                &mut rx,
                Some(first),
                direct_sources,
                None,
            );
        let mut packets = Vec::new();
        assert_eq!(
            source_rx.drain_raw_ingress(1, |packet| packets.push(packet)),
            1
        );
        assert!(source_rx.take_control_ingress().is_empty());
        assert_eq!(packets.len(), 1);
        let packet = &packets[0];
        assert_eq!(packet.protocol, PacketProtocol::Fsp);
        assert_eq!(packet.fsp_source, Some(source));
        assert_eq!(packet.previous_hop, Some(source));
        assert_eq!(packet.path_mtu, 1400);
        assert_eq!(packet.path.transport_id, transport_id);
        assert_eq!(packet.path.remote_addr, remote_addr);
        assert_eq!(packet.activity_tick, Some(ActivityTick::new(44_000)));
    }

    #[test]
    fn packet_rx_source_classifies_flagged_direct_fsp_after_nat_port_rewrite() {
        let source = NodeAddr::from_bytes([0x4e; 16]);
        let transport_id = TransportId::new(44);
        let learned_addr = TransportAddr::from_string("198.51.100.44:9000");
        let rewritten_addr = TransportAddr::from_string("198.51.100.44:53000");
        let (_tx, mut rx) = crate::transport::packet_channel(1);
        let direct_sources = direct_fsp_sources(transport_id, learned_addr, source, 1400);
        let first = ReceivedPacket::with_timestamp(
            transport_id,
            rewritten_addr.clone(),
            PacketBuffer::new(fsp_wire(
                89,
                crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
            )),
            44_001,
        );
        let mut source_rx =
            DataplaneFmpPacketRxSource::with_first_direct_fsp_sources_and_reassembler(
                &mut rx,
                Some(first),
                direct_sources,
                None,
            );
        let mut packets = Vec::new();
        assert_eq!(
            source_rx.drain_raw_ingress(1, |packet| packets.push(packet)),
            1
        );
        assert!(source_rx.take_control_ingress().is_empty());
        assert_eq!(packets.len(), 1);
        let packet = &packets[0];
        assert_eq!(packet.protocol, PacketProtocol::Fsp);
        assert_eq!(packet.fsp_source, Some(source));
        assert_eq!(packet.previous_hop, Some(source));
        assert_eq!(packet.path_mtu, 1400);
        assert_eq!(packet.path.transport_id, transport_id);
        assert_eq!(packet.path.remote_addr, rewritten_addr);
        assert_eq!(packet.activity_tick, Some(ActivityTick::new(44_001)));
    }

    #[test]
    fn direct_fsp_source_classifier_merges_mtu_and_rejects_ambiguous_ip() {
        let transport_id = TransportId::new(44);
        let source = NodeAddr::from_bytes([0x44; 16]);
        let learned_addr = TransportAddr::from_string("198.51.100.44:9000");
        let rewritten_addr = TransportAddr::from_string("198.51.100.44:53000");
        let wildcard_addr = TransportAddr::from_string("0.0.0.0:53000");

        let direct_sources = direct_fsp_sources_from([
            (transport_id, learned_addr.clone(), source, 1400),
            (transport_id, learned_addr, source, 1500),
        ]);
        assert_eq!(
            lookup_direct_fsp_source(&direct_sources, transport_id, &rewritten_addr),
            Some(DataplaneDirectFspSource {
                source_addr: source,
                path_mtu: 1400,
            })
        );

        let direct_sources = direct_fsp_sources_from([
            (
                transport_id,
                TransportAddr::from_string("198.51.100.44:9000"),
                source,
                1400,
            ),
            (
                transport_id,
                TransportAddr::from_string("198.51.100.44:9001"),
                NodeAddr::from_bytes([0x45; 16]),
                1400,
            ),
            (transport_id, wildcard_addr, source, 1400),
        ]);

        assert_eq!(
            lookup_direct_fsp_source(&direct_sources, transport_id, &rewritten_addr),
            None
        );
    }

    #[test]
    fn direct_fsp_source_classifier_matches_configured_udp_port_wildcard() {
        let transport_id = TransportId::new(44);
        let source = NodeAddr::from_bytes([0x46; 16]);
        let actual_source = TransportAddr::from_string("192.168.64.5:52528");
        let ipv4_wildcard = TransportAddr::from_string("0.0.0.0:52528");
        let ipv6_wildcard = TransportAddr::from_string("[::]:52528");
        let direct_sources = direct_fsp_sources_from([
            (transport_id, ipv4_wildcard.clone(), source, 1400),
            (transport_id, ipv6_wildcard.clone(), source, 1300),
        ]);

        let matched = lookup_direct_fsp_source(&direct_sources, transport_id, &actual_source)
            .expect("configured static UDP port wildcard should match actual source IP");
        assert_eq!(matched.source_addr, source);
        assert_eq!(matched.path_mtu, 1300);

        let ambiguous_sources = direct_fsp_sources_from([
            (transport_id, ipv4_wildcard, source, 1400),
            (
                transport_id,
                ipv6_wildcard,
                NodeAddr::from_bytes([0x47; 16]),
                1300,
            ),
        ]);
        assert_eq!(
            lookup_direct_fsp_source(&ambiguous_sources, transport_id, &actual_source),
            None
        );
    }

    #[test]
    fn fast_ingress_routes_direct_fsp_after_nat_port_rewrite() {
        let source = NodeAddr::from_bytes([0x4f; 16]);
        let owner = OwnerId::fsp_node(source);
        let transport_id = TransportId::new(44);
        let learned_addr = TransportAddr::from_string("198.51.100.44:9000");
        let rewritten_addr = TransportAddr::from_string("198.51.100.44:53000");
        let route = DataplaneIngressRoute::new(owner, 11, OutputTarget::Transport)
            .with_class(PacketClass::Bulk);
        let mut routes = DataplaneLiveRouteTable::default();
        routes.register_fsp(source, route);
        let direct_sources = direct_fsp_sources(transport_id, learned_addr, source, 1400);
        routes.set_established_fast_ingress_direct_fsp_sources(direct_sources);

        let (sink, mut fast_rx) =
            DataplaneEstablishedFastIngressSink::channel(
                routes.established_fast_ingress_snapshot(),
                4,
            );
        let mut packets = vec![ReceivedPacket::with_timestamp(
            transport_id,
            rewritten_addr.clone(),
            PacketBuffer::new(fsp_wire(
                90,
                crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
            )),
            44_002,
        )];

        assert_eq!(sink.try_ingest_batch(&mut packets), 1);
        assert!(packets.is_empty());
        let batch = fast_rx.try_recv().expect("direct FSP fast batch");
        assert_eq!(batch.len(), 1);
        let mut runs = batch.into_runs();
        let (_, _, mut packets) = runs.pop().expect("direct FSP fast run").into_parts();
        let packet = packets.pop().expect("direct FSP socket packet");
        assert_eq!(packet.owner, owner);
        assert_eq!(packet.generation, 11);
        assert_eq!(packet.counter, 90);
        assert_eq!(
            packet.source_path,
            Some(TransportPath::live(transport_id, rewritten_addr))
        );
        assert_eq!(packet.previous_hop, Some(source));
        assert_eq!(packet.path_mtu, 1400);
    }

    #[test]
    fn direct_fsp_transport_segments_reassemble_before_classification() {
        let source = NodeAddr::from_bytes([0x45; 16]);
        let owner = OwnerId::fsp_node(source);
        let transport_id = TransportId::new(45);
        let remote_addr = TransportAddr::from_string("198.51.100.45:9000");
        let direct_sources = direct_fsp_sources(transport_id, remote_addr.clone(), source, 220);

        let mut wire = fsp_wire(
            4242,
            crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
        );
        wire.extend((0..700).map(|idx| (idx % 251) as u8));
        let mut output =
            transport_output(owner, 4242, 9, transport_id, remote_addr.clone(), wire.clone());
        output.path_mtu = 220;

        let segments = match dataplane_direct_fsp_transport_output(output) {
            DataplaneDirectFspTransportOutput::Segments(segments) => {
                materialize_direct_fsp_segments(&segments)
            }
            DataplaneDirectFspTransportOutput::Whole(_) => panic!("expected segmented output"),
            DataplaneDirectFspTransportOutput::MtuExceeded(_) => panic!("expected segmented output"),
        };
        assert!(segments.len() > 1);
        assert!(segments.iter().all(|segment| segment.payload_len() <= 220));
        assert!(segments.iter().all(|segment| {
            dataplane_direct_fsp_transport_fragment_is_fragment(segment.payload())
        }));

        let (_tx, mut rx) = crate::transport::packet_channel(1);
        let mut reassembler = DataplaneDirectFspReassembler::default();
        let mut packets = Vec::new();
        for (idx, segment) in segments.into_iter().rev().enumerate() {
            let received = ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr.clone(),
                segment.payload,
                45_000 + idx as u64,
            );
            let mut source_rx =
                DataplaneFmpPacketRxSource::with_first_direct_fsp_sources_and_reassembler(
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
        assert_eq!(packet.protocol, PacketProtocol::Fsp);
        assert_eq!(packet.fsp_source, Some(source));
        assert_eq!(packet.path_mtu, 220);
        assert_eq!(packet.payload.as_slice(), wire.as_slice());
    }

    #[test]
    fn direct_fsp_reassembly_keeps_existing_record_at_capacity() {
        let source = NodeAddr::from_bytes([0x49; 16]);
        let owner = OwnerId::fsp_node(source);
        let transport_id = TransportId::new(49);
        let remote_addr = TransportAddr::from_string("198.51.100.49:9000");
        let make_segments = |counter: u64, ingress_seq: u64| {
            let mut wire = fsp_wire(
                counter,
                crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
            );
            wire.extend((0..700).map(|idx| (idx % 251) as u8));
            let mut output = transport_output(
                owner,
                counter,
                ingress_seq,
                transport_id,
                remote_addr.clone(),
                wire.clone(),
            );
            output.path_mtu = 220;
            let segments = match dataplane_direct_fsp_transport_output(output) {
                DataplaneDirectFspTransportOutput::Segments(segments) => {
                    materialize_direct_fsp_segments(&segments)
                }
                DataplaneDirectFspTransportOutput::Whole(_) => panic!("expected segmented output"),
            DataplaneDirectFspTransportOutput::MtuExceeded(_) => panic!("expected segmented output"),
            };
            assert!(segments.len() > 1);
            (wire, segments)
        };

        let (target_wire, target_segments) = make_segments(49_000, 0);
        let mut reassembler = DataplaneDirectFspReassembler::default();
        assert!(matches!(
            reassembler.ingest_fragment(ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr.clone(),
                target_segments[0].payload.clone(),
                49_000,
            )),
            DataplaneDirectFspReassemblyResult::Pending
        ));

        for idx in 0..DIRECT_FSP_TRANSPORT_MAX_REASSEMBLY_RECORDS - 1 {
            let (_wire, segments) = make_segments(50_000 + idx as u64, idx as u64 + 1);
            assert!(matches!(
                reassembler.ingest_fragment(ReceivedPacket::with_timestamp(
                    transport_id,
                    remote_addr.clone(),
                    segments[0].payload.clone(),
                    49_001 + idx as u64,
                )),
                DataplaneDirectFspReassemblyResult::Pending
            ));
        }
        assert_eq!(
            reassembler.entries.len(),
            DIRECT_FSP_TRANSPORT_MAX_REASSEMBLY_RECORDS
        );

        let mut complete = None;
        for (idx, segment) in target_segments.iter().enumerate().skip(1) {
            match reassembler.ingest_fragment(ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr.clone(),
                segment.payload.clone(),
                49_700 + idx as u64,
            )) {
                DataplaneDirectFspReassemblyResult::Pending => {}
                DataplaneDirectFspReassemblyResult::Complete(packet) => {
                    complete = Some(packet);
                }
                other => panic!("unexpected reassembly result: {other:?}"),
            }
        }
        let packet = complete.expect("capacity should not evict a live matching record");
        assert_eq!(packet.data.as_slice(), target_wire.as_slice());
    }

    #[test]
    fn fast_ingress_routes_direct_fsp_segments_before_packet_channel() {
        let source = NodeAddr::from_bytes([0x46; 16]);
        let owner = OwnerId::fsp_node(source);
        let transport_id = TransportId::new(46);
        let remote_addr = TransportAddr::from_string("198.51.100.46:9000");
        let route = DataplaneIngressRoute::new(owner, 10, OutputTarget::Transport)
            .with_class(PacketClass::Bulk);
        let mut routes = DataplaneLiveRouteTable::default();
        routes.register_fsp(source, route);
        routes.set_established_fast_ingress_direct_fsp_sources(
            direct_fsp_sources(transport_id, remote_addr.clone(), source, 240),
        );

        let mut wire = fsp_wire(
            4646,
            crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
        );
        wire.extend((0..900).map(|idx| (idx % 251) as u8));
        let mut output =
            transport_output(owner, 4646, 10, transport_id, remote_addr.clone(), wire.clone());
        output.path_mtu = 240;

        let segments = match dataplane_direct_fsp_transport_output(output) {
            DataplaneDirectFspTransportOutput::Segments(segments) => {
                materialize_direct_fsp_segments(&segments)
            }
            DataplaneDirectFspTransportOutput::Whole(_) => panic!("expected segmented output"),
            DataplaneDirectFspTransportOutput::MtuExceeded(_) => panic!("expected segmented output"),
        };
        assert!(segments.len() > 1);

        let (sink, mut fast_rx) =
            DataplaneEstablishedFastIngressSink::channel(
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
        let mut runs = batch.into_runs();
        assert_eq!(runs.len(), 1);
        let (run_owner, run_lane, mut packets) = runs.pop().unwrap().into_parts();
        assert_eq!(run_owner, owner);
        assert_eq!(run_lane, PacketClass::Bulk.lane());
        let packet = packets.pop().expect("direct FSP socket packet");
        assert!(packets.is_empty());
        assert_eq!(packet.owner, owner);
        assert_eq!(packet.generation, 10);
        assert_eq!(packet.counter, 4646);
        assert_eq!(packet.class, PacketClass::Bulk);
        assert_eq!(packet.output, OutputTarget::Transport);
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
        let route = DataplaneIngressRoute::new(owner, 12, OutputTarget::Transport)
            .with_class(PacketClass::Bulk);
        let mut routes = DataplaneLiveRouteTable::default();
        routes.register_fsp(source, route);
        routes.set_established_fast_ingress_direct_fsp_sources(
            direct_fsp_sources(transport_id, remote_addr.clone(), source, 240),
        );

        let (sink, fast_rx) =
            DataplaneEstablishedFastIngressSink::channel(
                routes.established_fast_ingress_snapshot(),
                1,
            );
        let mut fill_queue = vec![ReceivedPacket::with_timestamp(
            transport_id,
            remote_addr.clone(),
            PacketBuffer::new(fsp_wire(
                4800,
                crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
            )),
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
        let segments = match dataplane_direct_fsp_transport_output(output) {
            DataplaneDirectFspTransportOutput::Segments(segments) => {
                materialize_direct_fsp_segments(&segments)
            }
            DataplaneDirectFspTransportOutput::Whole(_) => panic!("expected segmented output"),
            DataplaneDirectFspTransportOutput::MtuExceeded(_) => panic!("expected segmented output"),
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
        let routes = DataplaneLiveRouteTable::default();
        routes.set_established_fast_ingress_direct_fsp_sources(
            direct_fsp_sources(transport_id, remote_addr.clone(), source, 240),
        );

        let mut wire = fsp_wire(
            4747,
            crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
        );
        wire.extend((0..900).map(|idx| (idx % 251) as u8));
        let mut output =
            transport_output(owner, 4747, 10, transport_id, remote_addr.clone(), wire);
        output.path_mtu = 240;
        let segments = match dataplane_direct_fsp_transport_output(output) {
            DataplaneDirectFspTransportOutput::Segments(segments) => {
                materialize_direct_fsp_segments(&segments)
            }
            DataplaneDirectFspTransportOutput::Whole(_) => panic!("expected segmented output"),
            DataplaneDirectFspTransportOutput::MtuExceeded(_) => panic!("expected segmented output"),
        };
        let fragment = segments.into_iter().next().expect("fragment").payload;
        let original = fragment.clone();
        let (sink, mut fast_rx) =
            DataplaneEstablishedFastIngressSink::channel(
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
        let mut routes = DataplaneLiveRouteTable::default();
        let route = DataplaneIngressRoute::new(
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
        let large_raw = DataplaneRawIngress::from_live_received(
            PacketProtocol::Fsp,
            ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr,
                PacketBuffer::new(large_wire),
                43_001,
            ),
        )
        .with_fsp_source(source);
        let header =
            DataplaneIngressHeader::Fsp(FspWireHeader::parse(large_raw.payload.as_slice()).unwrap());
        assert_eq!(
            routes.route(&large_raw, header).expect("large FSP route").class,
            PacketClass::Bulk
        );
    }
