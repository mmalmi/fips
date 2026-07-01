    fn tun_ipv6_packet(dest_addr: NodeAddr, len: usize) -> Vec<u8> {
        assert!(len >= 40);
        let mut packet = vec![0u8; len];
        packet[0] = 0x60;
        packet[6] = 17;
        let dest = crate::FipsAddress::from_node_addr(&dest_addr);
        packet[24..40].copy_from_slice(dest.as_bytes());
        packet
    }

    fn tun_tcp_data_packet(dest_addr: NodeAddr) -> Vec<u8> {
        let tcp_payload_len = 512usize;
        let tcp_len = 20 + tcp_payload_len;
        let mut packet = tun_ipv6_packet(dest_addr, 40 + tcp_len);
        packet[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
        packet[6] = 6;
        packet[52] = 5 << 4;
        packet[53] = 0x18;
        packet
    }

    fn app_endpoint_payload() -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60;
        packet[6] = 58;
        packet
    }

    fn bulk_endpoint_payload() -> Vec<u8> {
        vec![0x01, 0x02, 0x03, 0x04]
    }

    fn bulk_tcp_endpoint_payload() -> Vec<u8> {
        let tcp_payload_len = 512usize;
        let tcp_len = 20 + tcp_payload_len;
        let mut packet = vec![0u8; 40 + tcp_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
        packet[6] = 6;
        packet[52] = 5 << 4;
        packet[53] = 0x18;
        packet
    }

    fn drain_outbound_packets<Routes>(
        source: &mut PacketMover2RouteTableOutboundSource<'_, Routes>,
        limit: usize,
        outbound: &mut Vec<OutboundPacket>,
    ) -> usize
    where
        Routes: PacketMover2EndpointDataRouter + PacketMover2TunOutboundRouter,
    {
        source.drain_outbound_batched(limit, |routed| match routed {
            PacketMover2RoutedOutbound::Packet(packet) => outbound.push(packet),
            PacketMover2RoutedOutbound::Batch(packets) => outbound.extend(packets),
        })
    }

    #[test]
    fn live_route_table_routes_tun_outbound_by_fips_destination_prefix() {
        let dest = NodeAddr::from_bytes([0x61; 16]);
        let owner = OwnerId::fmp_node(dest);
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_tun_destination(
            dest,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                owner,
                5,
                PacketClass::Bulk,
                610,
                0x02,
            ))
            .with_max_packet_len(64),
        );

        let valid = tun_ipv6_packet(dest, 48);
        let unknown = tun_ipv6_packet(NodeAddr::from_bytes([0x62; 16]), 48);
        let invalid = vec![0u8; 39];
        let oversize = tun_ipv6_packet(dest, 65);
        let (tx, mut rx) = crate::upper::tun::tun_outbound_channel(8);
        tx.try_send(valid.clone()).expect("enqueue valid TUN packet");
        tx.try_send(unknown.clone())
            .expect("enqueue unknown TUN packet");
        tx.try_send(invalid.clone())
            .expect("enqueue invalid TUN packet");
        tx.try_send(oversize.clone())
            .expect("enqueue oversized TUN packet");

        let (bulk_tx, mut bulk_rx) = endpoint_data_batch_channel(1);
        drop(bulk_tx);
        let mut source =
            PacketMover2RouteTableOutboundSource::new(&mut bulk_rx, 0, &mut rx, 8, &mut routes);
        let mut outbound = Vec::new();

        assert_eq!(drain_outbound_packets(&mut source, 8, &mut outbound), 4);

        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].owner, owner);
        assert_eq!(outbound[0].generation, 5);
        assert_eq!(outbound[0].class, PacketClass::Bulk);
        assert_eq!(
            outbound[0].wire,
            OutboundWire::Fmp {
                receiver_idx: 610,
                flags: 0x02,
            }
        );
        assert_eq!(outbound[0].payload.as_ref(), valid.as_slice());
        let report = source.take_report_buffers();
        assert_eq!(report.tun_deferred_packets, vec![unknown.clone()]);
        let drops = report.tun_drops;
        assert_eq!(
            drops
                .iter()
                .map(PacketMover2TunOutboundDrop::reason)
                .collect::<Vec<_>>(),
            vec![
                PacketMover2TunOutboundDropReason::InvalidPacket,
                PacketMover2TunOutboundDropReason::MtuExceeded { mtu: 64 },
            ]
        );
        assert_eq!(drops[0].payload_len(), invalid.len());
        assert_eq!(drops[1].payload_len(), oversize.len());
        assert_eq!(drops[1].packet(), oversize.as_slice());
    }

    #[test]
    fn live_route_table_keeps_tcp_tun_data_on_bulk_class() {
        let dest = NodeAddr::from_bytes([0x63; 16]);
        let owner = OwnerId::fmp_node(dest);
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_tun_destination(
            dest,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                owner,
                5,
                PacketClass::Bulk,
                610,
                0x02,
            )),
        );

        let tcp_data = tun_tcp_data_packet(dest);
        let udp_data = tun_ipv6_packet(dest, 64);
        let (tx, mut rx) = crate::upper::tun::tun_outbound_channel(8);
        tx.try_send(tcp_data.clone())
            .expect("enqueue TCP TUN packet");
        tx.try_send(udp_data.clone())
            .expect("enqueue UDP TUN packet");

        let (bulk_tx, mut bulk_rx) = endpoint_data_batch_channel(1);
        drop(bulk_tx);
        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut bulk_rx,
            0,
            &mut rx,
            8,
            &mut routes,
        );
        let mut outbound = Vec::new();

        assert_eq!(drain_outbound_packets(&mut source, 8, &mut outbound), 2);
        assert_eq!(outbound.len(), 2);
        assert_eq!(outbound[0].class, PacketClass::Bulk);
        assert_eq!(outbound[0].payload.as_ref(), tcp_data.as_slice());
        assert_eq!(outbound[1].class, PacketClass::Bulk);
        assert_eq!(outbound[1].payload.as_ref(), udp_data.as_slice());
    }

    #[test]
    fn live_route_table_routes_endpoint_data_batches_into_fsp_endpoint_data() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let missing_remote =
            PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let owner = OwnerId::fsp_node(*remote.node_addr());
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_endpoint_destination(
            *remote.node_addr(),
            PacketMover2EndpointDataRoute::fsp(owner, 7, 0x03, 0x09),
        );
        let app_payload = app_endpoint_payload();
        let bulk_payload = bulk_endpoint_payload();
        let missing_payload = b"missing-route".to_vec();
        let (bulk_tx, mut bulk_rx) = endpoint_data_batch_channel(8);
        bulk_tx
            .send_or_drop(
                NodeEndpointDataBatch::batch(
                    remote,
                    vec![
                        app_payload.clone(),
                        bulk_payload.clone(),
                    ],
                    None,
                )
                .expect("bulk data batch"),
            )
            .expect("enqueue endpoint data batch");
        bulk_tx
            .send_or_drop(
                NodeEndpointDataBatch::batch(missing_remote, vec![missing_payload.clone()], None)
                    .expect("one-packet endpoint data batch"),
            )
            .expect("enqueue missing endpoint data batch");
        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        drop(tun_tx);
        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut bulk_rx,
            16,
            &mut tun_rx,
            0,
            &mut routes,
        );
        let mut outbound = Vec::new();
        assert_eq!(drain_outbound_packets(&mut source, 16, &mut outbound), 2);
        assert_eq!(outbound.len(), 2);
        assert_eq!(outbound[0].owner, owner);
        assert_eq!(outbound[0].generation, 7);
        assert_eq!(outbound[0].class, PacketClass::Bulk);
        assert_eq!(outbound[0].wire, OutboundWire::Fsp { flags: 0x03 });
        assert_eq!(
            outbound[0].payload_transform,
            OutboundPayloadTransform::FspInnerHeader {
                msg_type: crate::protocol::SessionMessageType::EndpointData.to_byte(),
                inner_flags: 0x09,
            }
        );
        assert_eq!(outbound[0].payload.as_ref(), app_payload.as_slice());
        assert_eq!(outbound[1].owner, owner);
        assert_eq!(outbound[1].generation, 7);
        assert_eq!(outbound[1].class, PacketClass::Bulk);
        assert_eq!(
            outbound[1].payload_transform,
            OutboundPayloadTransform::FspInnerHeader {
                msg_type: crate::protocol::SessionMessageType::EndpointData.to_byte(),
                inner_flags: 0x09,
            }
        );
        assert_eq!(outbound[1].payload.as_ref(), bulk_payload.as_slice());
        let report = source.take_report_buffers();
        assert!(report.endpoint_drops.is_empty());
        let deferred = report.deferred_endpoint_data_batches;
        assert_eq!(deferred.len(), 1);
        assert_eq!(deferred[0].packet_count(), 1);
    }

    #[test]
    fn live_route_table_keeps_tcp_endpoint_data_on_bulk_class() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let owner = OwnerId::fsp_node(*remote.node_addr());
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_endpoint_destination(
            *remote.node_addr(),
            PacketMover2EndpointDataRoute::fsp(owner, 7, 0x03, 0x09),
        );

        let tcp_payload = bulk_tcp_endpoint_payload();
        let udp_payload = bulk_endpoint_payload();
        let (bulk_tx, mut bulk_rx) = endpoint_data_batch_channel(8);
        bulk_tx
            .send_or_drop(
                NodeEndpointDataBatch::batch(
                    remote,
                    vec![
                        tcp_payload.clone(),
                        udp_payload.clone(),
                    ],
                    None,
                )
                .expect("endpoint data batch"),
            )
            .expect("enqueue endpoint data batch");

        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        drop(tun_tx);
        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut bulk_rx,
            8,
            &mut tun_rx,
            0,
            &mut routes,
        );
        let mut outbound = Vec::new();

        assert_eq!(drain_outbound_packets(&mut source, 8, &mut outbound), 1);
        assert_eq!(outbound.len(), 2);
        assert_eq!(outbound[0].class, PacketClass::Bulk);
        assert_eq!(outbound[0].payload.as_ref(), tcp_payload.as_slice());
        assert_eq!(outbound[1].class, PacketClass::Bulk);
        assert_eq!(outbound[1].payload.as_ref(), udp_payload.as_slice());
    }

    #[test]
    fn live_route_table_outbound_source_defers_unrouted_one_packet_endpoint_batch() {
        let missing_remote =
            PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let (bulk_tx, mut bulk_rx) = endpoint_data_batch_channel(1);
        bulk_tx
            .send_or_drop(
                NodeEndpointDataBatch::batch(missing_remote, vec![app_endpoint_payload()], None)
                    .expect("one-packet endpoint data batch"),
            )
            .expect("enqueue endpoint data batch");
        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        drop((bulk_tx, tun_tx));
        let mut routes = PacketMover2LiveRouteTable::default();
        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut bulk_rx,
            1,
            &mut tun_rx,
            0,
            &mut routes,
        );
        let mut outbound = Vec::new();

        assert_eq!(drain_outbound_packets(&mut source, 1, &mut outbound), 1);

        assert!(outbound.is_empty());
        let report = source.take_report_buffers();
        assert!(report.endpoint_drops.is_empty());
        let deferred = report.deferred_endpoint_data_batches;
        assert_eq!(deferred.len(), 1);
        assert_eq!(deferred[0].packet_count(), 1);
    }

    #[test]
    fn live_route_table_outbound_source_drains_endpoint_data_batch_in_queue_order() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let owner = OwnerId::fsp_node(*remote.node_addr());
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_endpoint_destination(
            *remote.node_addr(),
            PacketMover2EndpointDataRoute::fsp(owner, 7, 0x03, 0x09),
        );

        let first_bulk_payload = b"first-bulk".to_vec();
        let queued_bulk_payload = b"queued-bulk".to_vec();
        let (bulk_tx, mut bulk_rx) = endpoint_data_batch_channel(4);
        bulk_tx
            .send_or_drop(
                NodeEndpointDataBatch::batch(
                    remote,
                    vec![queued_bulk_payload.clone()],
                    None,
                )
                .expect("queued endpoint data batch"),
            )
            .expect("enqueue queued endpoint data batch");

        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        drop(tun_tx);
        let firsts = PacketMover2LiveOutboundFirsts::default().with_endpoint_data_batch(Some(
            NodeEndpointDataBatch::batch(
                remote,
                vec![first_bulk_payload.clone()],
                None,
            )
            .expect("first endpoint data batch"),
        ));
        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut bulk_rx,
            8,
            &mut tun_rx,
            0,
            &mut routes,
        )
        .with_firsts(firsts);
        let mut outbound = Vec::new();

        assert_eq!(drain_outbound_packets(&mut source, 8, &mut outbound), 2);

        assert_eq!(outbound.len(), 2);
        assert_eq!(outbound[0].class, PacketClass::Bulk);
        assert_eq!(outbound[0].payload.as_ref(), first_bulk_payload);
        assert_eq!(outbound[1].class, PacketClass::Bulk);
        assert_eq!(outbound[1].payload.as_ref(), queued_bulk_payload);

        let mut bulk_outbound = Vec::new();
        assert_eq!(
            drain_outbound_packets(&mut source, 8, &mut bulk_outbound),
            0
        );
        assert!(bulk_outbound.is_empty());
        let report = source.take_report_buffers();
        let drops = report.endpoint_drops;
        let deferred = report.deferred_endpoint_data_batches;
        drop(source);
        assert!(bulk_rx.try_recv().is_err());
        assert!(drops.is_empty());
        assert!(deferred.is_empty());
    }

    #[test]
    fn live_route_table_outbound_source_drops_stale_endpoint_data_batch_when_data_drains() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let owner = OwnerId::fsp_node(*remote.node_addr());
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_endpoint_destination(
            *remote.node_addr(),
            PacketMover2EndpointDataRoute::fsp(owner, 7, 0x03, 0x09),
        );

        let stale_payload = bulk_endpoint_payload();
        let old_ms = crate::time::now_ms().saturating_sub(1_000);
        let stale_batch = NodeEndpointDataBatch::batch_with_enqueued_at_ms(
            remote,
            vec![stale_payload.clone()],
            None,
            old_ms,
        )
        .expect("stale endpoint data batch");

        let (batch_tx, mut batch_rx) = endpoint_data_batch_channel(1);
        batch_tx
            .send_or_drop(stale_batch)
            .expect("enqueue stale endpoint data batch");

        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        drop(tun_tx);
        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut batch_rx,
            8,
            &mut tun_rx,
            0,
            &mut routes,
        );
        source.endpoint_stale_data_drop_ms = 50;
        let mut outbound = Vec::new();

        assert_eq!(drain_outbound_packets(&mut source, 8, &mut outbound), 1);

        assert!(outbound.is_empty());
        let report = source.take_report_buffers();
        let drops = report.endpoint_drops;
        assert_eq!(drops.len(), 1);
        assert_eq!(drops[0].dest_addr(), *remote.node_addr());
        assert_eq!(drops[0].payload_len(), stale_payload.len());
        assert_eq!(
            drops[0].reason(),
            PacketMover2EndpointDataDropReason::StaleQueuedBatch
        );
        assert!(report.deferred_endpoint_data_batches.is_empty());
    }

    #[test]
    fn live_route_table_outbound_source_drains_first_tun_packet_before_channel() {
        let dest = NodeAddr::from_bytes([0x6a; 16]);
        let owner = OwnerId::fmp_node(dest);
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_tun_destination(
            dest,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                owner,
                5,
                PacketClass::Bulk,
                610,
                0x02,
            ))
            .with_max_packet_len(64),
        );

        let first_tun_packet = tun_ipv6_packet(dest, 48);
        let queued_tun_packet = tun_ipv6_packet(dest, 56);
        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(2);
        tun_tx
            .try_send(queued_tun_packet.clone())
            .expect("enqueue queued TUN packet");
        let (bulk_tx, mut bulk_rx) = endpoint_data_batch_channel(1);
        drop(bulk_tx);
        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut bulk_rx,
            0,
            &mut tun_rx,
            2,
            &mut routes,
        )
        .with_firsts(
            PacketMover2LiveOutboundFirsts::default()
                .with_tun_packet(Some(first_tun_packet.clone())),
        );
        let mut outbound = Vec::new();

        assert_eq!(drain_outbound_packets(&mut source, 2, &mut outbound), 2);

        assert_eq!(outbound.len(), 2);
        assert_eq!(outbound[0].owner, owner);
        assert_eq!(outbound[0].payload.as_ref(), first_tun_packet);
        assert_eq!(outbound[1].owner, owner);
        assert_eq!(outbound[1].payload.as_ref(), queued_tun_packet);
        let report = source.take_report_buffers();
        let drops = report.tun_drops;
        drop(source);
        assert!(tun_rx.try_recv().is_err());
        assert!(drops.is_empty());
    }

    #[test]
    fn live_route_table_outbound_source_preserves_tun_slice_after_endpoint_batch_overrun() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let endpoint_owner = OwnerId::fsp_node(*remote.node_addr());
        let tun_dest = NodeAddr::from_bytes([0x65; 16]);
        let tun_owner = OwnerId::fmp_node(tun_dest);
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_endpoint_destination(
            *remote.node_addr(),
            PacketMover2EndpointDataRoute::fsp(endpoint_owner, 1, 0, 0),
        );
        routes.register_tun_destination(
            tun_dest,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                tun_owner,
                2,
                PacketClass::Bulk,
                650,
                0,
            )),
        );

        let (bulk_tx, mut bulk_rx) = endpoint_data_batch_channel(16);
        let payloads = (0..9)
            .map(|idx| vec![idx as u8, 0])
            .collect::<Vec<_>>();
        bulk_tx
            .send_or_drop(
                NodeEndpointDataBatch::batch(
                    remote,
                    payloads,
                    None,
                )
                .expect("endpoint data batch"),
            )
            .expect("enqueue endpoint batch");
        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        let tun_packet = tun_ipv6_packet(tun_dest, 48);
        tun_tx
            .try_send(tun_packet.clone())
            .expect("enqueue TUN packet");

        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut bulk_rx,
            1,
            &mut tun_rx,
            1,
            &mut routes,
        );
        let mut outbound = Vec::new();

        assert_eq!(drain_outbound_packets(&mut source, 2, &mut outbound), 3);

        assert_eq!(outbound.len(), 10);
        assert_eq!(
            outbound.iter().filter(|packet| packet.owner == endpoint_owner).count(),
            9
        );
        let tun_outbound = outbound
            .iter()
            .find(|packet| packet.owner == tun_owner)
            .expect("TUN outbound packet kept reserved progress");
        assert_eq!(tun_outbound.generation, 2);
        assert_eq!(tun_outbound.class, PacketClass::Bulk);
        assert_eq!(
            tun_outbound.wire,
            OutboundWire::Fmp {
                receiver_idx: 650,
                flags: 0,
            }
        );
        assert_eq!(tun_outbound.payload.as_ref(), tun_packet.as_slice());
        let report = source.take_report_buffers();
        assert!(report.endpoint_drops.is_empty());
        assert!(report.deferred_endpoint_data_batches.is_empty());
        assert!(report.tun_drops.is_empty());
    }
