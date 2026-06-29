    use crate::node::EndpointDataPayload;

    fn tun_ipv6_packet(dest_addr: NodeAddr, len: usize) -> Vec<u8> {
        assert!(len >= 40);
        let mut packet = vec![0u8; len];
        packet[0] = 0x60;
        packet[6] = 17;
        let dest = crate::FipsAddress::from_node_addr(&dest_addr);
        packet[24..40].copy_from_slice(dest.as_bytes());
        packet
    }

    fn tun_icmpv6_packet(dest_addr: NodeAddr, len: usize) -> Vec<u8> {
        let mut packet = tun_ipv6_packet(dest_addr, len);
        packet[6] = 58;
        packet
    }

    fn tun_tcp_ack_packet(dest_addr: NodeAddr) -> Vec<u8> {
        let mut packet = tun_ipv6_packet(dest_addr, 60);
        packet[4..6].copy_from_slice(&20u16.to_be_bytes());
        packet[6] = 6;
        packet[52] = 5 << 4;
        packet[53] = 0x10;
        packet
    }

    fn priority_endpoint_payload() -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60;
        packet[6] = 58;
        packet
    }

    fn priority_tcp_ack_endpoint_payload() -> Vec<u8> {
        let mut packet = vec![0u8; 60];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&20u16.to_be_bytes());
        packet[6] = 6;
        packet[52] = 5 << 4;
        packet[53] = 0x10;
        packet
    }

    fn bulk_endpoint_payload() -> Vec<u8> {
        vec![0x01, 0x02, 0x03, 0x04]
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

        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(1);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(1);
        drop((priority_tx, bulk_tx));
        let mut source =
            PacketMover2RouteTableOutboundSource::new(&mut priority_rx, &mut bulk_rx, 0, &mut rx, 8, &mut routes);
        let mut outbound = Vec::new();

        assert_eq!(source.drain_outbound(8, |packet| outbound.push(packet)), 4);

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
        let deferred = source.take_tun_deferred_packets();
        assert_eq!(deferred, vec![unknown.clone()]);
        let drops = source.take_tun_outbound_drops();
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
    fn live_route_table_routes_endpoint_commands_into_fsp_endpoint_data() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let missing_remote =
            PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let owner = OwnerId::fsp_node(*remote.node_addr());
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_endpoint_destination(
            *remote.node_addr(),
            PacketMover2EndpointCommandRoute::fsp(owner, 7, 0x03, 0x09)
                .with_max_payload_len(64),
        );
        let priority_payload = priority_endpoint_payload();
        let bulk_payload = bulk_endpoint_payload();
        let oversized_payload = vec![0xaa; 65];
        let missing_payload = b"missing-route".to_vec();
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(8);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(8);
        priority_tx
            .try_send(NodeEndpointCommand::send_oneway(
                remote,
                priority_payload.clone(),
                None,
            ))
            .expect("enqueue priority endpoint command");
        bulk_tx
            .try_send(
                NodeEndpointCommand::send_batch_oneway(
                    remote,
                    vec![
                        EndpointDataPayload::new(bulk_payload.clone()),
                        EndpointDataPayload::new(oversized_payload.clone()),
                    ],
                    None,
                    EndpointCommandLane::Bulk,
                )
                .expect("bulk batch command"),
            )
            .expect("enqueue bulk endpoint batch");
        bulk_tx
            .try_send(NodeEndpointCommand::send_oneway(
                missing_remote,
                missing_payload.clone(),
                None,
            ))
            .expect("enqueue missing endpoint command");
        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        drop(tun_tx);
        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut priority_rx,
            &mut bulk_rx,
            16,
            &mut tun_rx,
            0,
            &mut routes,
        );
        let mut outbound = Vec::new();
        assert_eq!(source.drain_outbound(16, |packet| outbound.push(packet)), 1);
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].owner, owner);
        assert_eq!(outbound[0].generation, 7);
        assert_eq!(outbound[0].class, PacketClass::Control);
        assert_eq!(outbound[0].wire, OutboundWire::Fsp { flags: 0x03 });
        assert_eq!(
            outbound[0].payload_transform,
            OutboundPayloadTransform::FspInnerHeader {
                msg_type: crate::protocol::SessionMessageType::EndpointData.to_byte(),
                inner_flags: 0x09,
            }
        );
        assert_eq!(outbound[0].payload.as_ref(), priority_payload.as_slice());
        assert!(source.take_endpoint_command_drops().is_empty());

        let mut bulk_outbound = Vec::new();
        assert_eq!(
            source.drain_outbound(16, |packet| bulk_outbound.push(packet)),
            2
        );
        assert_eq!(bulk_outbound.len(), 1);
        assert_eq!(bulk_outbound[0].owner, owner);
        assert_eq!(bulk_outbound[0].generation, 7);
        assert_eq!(bulk_outbound[0].class, PacketClass::Bulk);
        assert_eq!(
            bulk_outbound[0].payload_transform,
            OutboundPayloadTransform::FspInnerHeader {
                msg_type: crate::protocol::SessionMessageType::EndpointData.to_byte(),
                inner_flags: 0x09,
            }
        );
        assert_eq!(bulk_outbound[0].payload.as_ref(), bulk_payload.as_slice());
        let drops = source.take_endpoint_command_drops();
        assert_eq!(drops.len(), 1);
        assert_eq!(drops[0].dest_addr(), *remote.node_addr());
        assert_eq!(drops[0].lane(), EndpointCommandLane::Bulk);
        assert_eq!(drops[0].payload_len(), oversized_payload.len());
        assert_eq!(
            drops[0].reason(),
            PacketMover2EndpointCommandDropReason::MtuExceeded
        );
        let deferred = source.take_endpoint_deferred_commands();
        assert_eq!(deferred.len(), 1);
        assert_eq!(deferred[0].lane(), EndpointCommandLane::Bulk);
        assert_eq!(deferred[0].packet_count(), 1);
    }

    #[test]
    fn live_route_table_outbound_source_defers_unrouted_endpoint_send_with_response() {
        let missing_remote =
            PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let (response_tx, mut response_rx) = tokio::sync::oneshot::channel();
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(1);
        priority_tx
            .try_send(NodeEndpointCommand::send(
                missing_remote,
                priority_endpoint_payload(),
                None,
                response_tx,
            ))
            .expect("enqueue endpoint command");

        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(1);
        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        drop((bulk_tx, tun_tx));
        let mut routes = PacketMover2LiveRouteTable::default();
        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut priority_rx,
            &mut bulk_rx,
            1,
            &mut tun_rx,
            0,
            &mut routes,
        );
        let mut outbound = Vec::new();

        assert_eq!(source.drain_outbound(1, |packet| outbound.push(packet)), 1);

        assert!(outbound.is_empty());
        assert!(source.take_endpoint_command_drops().is_empty());
        let deferred = source.take_endpoint_deferred_commands();
        assert_eq!(deferred.len(), 1);
        assert_eq!(deferred[0].lane(), EndpointCommandLane::Priority);
        assert_eq!(deferred[0].packet_count(), 1);
        assert!(matches!(
            response_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn live_route_table_outbound_source_drains_first_endpoint_commands_in_lane_order() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let owner = OwnerId::fsp_node(*remote.node_addr());
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_endpoint_destination(
            *remote.node_addr(),
            PacketMover2EndpointCommandRoute::fsp(owner, 7, 0x03, 0x09)
                .with_max_payload_len(64),
        );

        let mut first_priority_payload = priority_endpoint_payload();
        let mut queued_priority_payload = priority_endpoint_payload();
        first_priority_payload[47] = 1;
        queued_priority_payload[47] = 2;
        let first_bulk_payload = b"first-bulk".to_vec();
        let queued_bulk_payload = b"queued-bulk".to_vec();
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(4);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(4);
        priority_tx
            .try_send(NodeEndpointCommand::send_oneway(
                remote,
                queued_priority_payload.clone(),
                None,
            ))
            .expect("enqueue queued priority endpoint command");
        bulk_tx
            .try_send(
                NodeEndpointCommand::send_batch_oneway(
                    remote,
                    vec![EndpointDataPayload::new(queued_bulk_payload.clone())],
                    None,
                    EndpointCommandLane::Bulk,
                )
                .expect("queued bulk endpoint command"),
            )
            .expect("enqueue queued bulk endpoint command");

        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        drop(tun_tx);
        let firsts = PacketMover2LiveOutboundFirsts::default()
            .with_endpoint_priority(Some(NodeEndpointCommand::send_oneway(
                remote,
                first_priority_payload.clone(),
                None,
            )))
            .with_endpoint_bulk(Some(
                NodeEndpointCommand::send_batch_oneway(
                    remote,
                    vec![EndpointDataPayload::new(first_bulk_payload.clone())],
                    None,
                    EndpointCommandLane::Bulk,
                )
                .expect("first bulk endpoint command"),
            ));
        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut priority_rx,
            &mut bulk_rx,
            8,
            &mut tun_rx,
            0,
            &mut routes,
        )
        .with_firsts(firsts);
        let mut outbound = Vec::new();

        assert_eq!(source.drain_outbound(8, |packet| outbound.push(packet)), 2);

        assert_eq!(outbound.len(), 2);
        assert_eq!(outbound[0].class, PacketClass::Control);
        assert_eq!(outbound[0].payload.as_ref(), first_priority_payload);
        assert_eq!(outbound[1].class, PacketClass::Control);
        assert_eq!(outbound[1].payload.as_ref(), queued_priority_payload);
        assert!(source.take_endpoint_command_drops().is_empty());

        let mut bulk_outbound = Vec::new();
        assert_eq!(
            source.drain_outbound(8, |packet| bulk_outbound.push(packet)),
            2
        );
        assert_eq!(bulk_outbound.len(), 2);
        assert_eq!(bulk_outbound[0].class, PacketClass::Bulk);
        assert_eq!(bulk_outbound[0].payload.as_ref(), first_bulk_payload);
        assert_eq!(bulk_outbound[1].class, PacketClass::Bulk);
        assert_eq!(bulk_outbound[1].payload.as_ref(), queued_bulk_payload);
        let drops = source.take_endpoint_command_drops();
        let deferred = source.take_endpoint_deferred_commands();
        drop(source);
        assert!(priority_rx.try_recv().is_err());
        assert!(bulk_rx.try_recv().is_err());
        assert!(drops.is_empty());
        assert!(deferred.is_empty());
    }

    #[test]
    fn live_route_table_outbound_source_drops_stale_bulk_after_priority_progress() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let owner = OwnerId::fsp_node(*remote.node_addr());
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_endpoint_destination(
            *remote.node_addr(),
            PacketMover2EndpointCommandRoute::fsp(owner, 7, 0x03, 0x09),
        );

        let priority_payload = priority_endpoint_payload();
        let stale_bulk_payload = bulk_endpoint_payload();
        let old_ms = crate::time::now_ms().saturating_sub(1_000);
        let stale_bulk = EndpointSendBatchCommand::new_with_enqueued_at_ms(
            remote,
            vec![EndpointDataPayload::new(stale_bulk_payload.clone())],
            None,
            old_ms,
        )
        .expect("stale bulk command");

        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(1);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(1);
        priority_tx
            .try_send(NodeEndpointCommand::send_oneway(
                remote,
                priority_payload.clone(),
                None,
            ))
            .expect("enqueue priority endpoint command");
        bulk_tx
            .try_send(NodeEndpointCommand::SendBatchOneway {
                command: stale_bulk,
                lane: EndpointCommandLane::Bulk,
            })
            .expect("enqueue stale bulk command");

        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        drop(tun_tx);
        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut priority_rx,
            &mut bulk_rx,
            8,
            &mut tun_rx,
            0,
            &mut routes,
        );
        source.endpoint_stale_bulk_drop_ms = 50;
        let mut outbound = Vec::new();

        assert_eq!(source.drain_outbound(8, |packet| outbound.push(packet)), 2);

        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].class, PacketClass::Control);
        assert_eq!(outbound[0].payload.as_ref(), priority_payload);
        let drops = source.take_endpoint_command_drops();
        assert_eq!(drops.len(), 1);
        assert_eq!(drops[0].dest_addr(), *remote.node_addr());
        assert_eq!(drops[0].lane(), EndpointCommandLane::Bulk);
        assert_eq!(drops[0].payload_len(), stale_bulk_payload.len());
        assert_eq!(
            drops[0].reason(),
            PacketMover2EndpointCommandDropReason::StaleQueuedBulk
        );
        assert!(source.take_endpoint_deferred_commands().is_empty());
    }

    #[test]
    fn live_route_table_outbound_source_drops_stale_bulk_when_tun_liveness_waits() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let endpoint_owner = OwnerId::fsp_node(*remote.node_addr());
        let tun_dest = NodeAddr::from_bytes([0x6f; 16]);
        let tun_owner = OwnerId::fmp_node(tun_dest);
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_endpoint_destination(
            *remote.node_addr(),
            PacketMover2EndpointCommandRoute::fsp(endpoint_owner, 7, 0x03, 0x09),
        );
        routes.register_tun_destination(
            tun_dest,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                tun_owner,
                5,
                PacketClass::Liveness,
                610,
                0x02,
            )),
        );

        let stale_bulk_payload = bulk_endpoint_payload();
        let old_ms = crate::time::now_ms().saturating_sub(1_000);
        let stale_bulk = EndpointSendBatchCommand::new_with_enqueued_at_ms(
            remote,
            vec![EndpointDataPayload::new(stale_bulk_payload.clone())],
            None,
            old_ms,
        )
        .expect("stale bulk command");

        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(1);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(1);
        drop(priority_tx);
        bulk_tx
            .try_send(NodeEndpointCommand::SendBatchOneway {
                command: stale_bulk,
                lane: EndpointCommandLane::Bulk,
            })
            .expect("enqueue stale bulk command");

        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        let tun_packet = tun_icmpv6_packet(tun_dest, 48);
        tun_tx
            .try_send(tun_packet.clone())
            .expect("enqueue TUN liveness packet");

        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut priority_rx,
            &mut bulk_rx,
            8,
            &mut tun_rx,
            1,
            &mut routes,
        );
        source.endpoint_stale_bulk_drop_ms = 50;
        let mut outbound = Vec::new();

        assert_eq!(source.drain_outbound(8, |packet| outbound.push(packet)), 2);

        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].owner, tun_owner);
        assert_eq!(outbound[0].class, PacketClass::Liveness);
        assert_eq!(outbound[0].payload.as_ref(), tun_packet);
        let drops = source.take_endpoint_command_drops();
        assert_eq!(drops.len(), 1);
        assert_eq!(drops[0].dest_addr(), *remote.node_addr());
        assert_eq!(drops[0].lane(), EndpointCommandLane::Bulk);
        assert_eq!(drops[0].payload_len(), stale_bulk_payload.len());
        assert_eq!(
            drops[0].reason(),
            PacketMover2EndpointCommandDropReason::StaleQueuedBulk
        );
        assert!(source.take_endpoint_deferred_commands().is_empty());
        drop(source);
        assert!(bulk_rx.try_recv().is_err());
        assert!(tun_rx.try_recv().is_err());
    }

    #[test]
    fn live_route_table_outbound_source_defers_endpoint_bulk_for_tun_priority() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let endpoint_owner = OwnerId::fsp_node(*remote.node_addr());
        let tun_dest = NodeAddr::from_bytes([0x72; 16]);
        let tun_owner = OwnerId::fmp_node(tun_dest);
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_endpoint_destination(
            *remote.node_addr(),
            PacketMover2EndpointCommandRoute::fsp(endpoint_owner, 7, 0x03, 0x09),
        );
        routes.register_tun_destination(
            tun_dest,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                tun_owner,
                5,
                PacketClass::Bulk,
                610,
                0x02,
            )),
        );

        let fresh_bulk_payload = bulk_endpoint_payload();
        let fresh_bulk = EndpointSendBatchCommand::new(
            remote,
            vec![EndpointDataPayload::new(fresh_bulk_payload.clone())],
            None,
        )
        .expect("fresh bulk command");

        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(1);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(1);
        drop(priority_tx);
        bulk_tx
            .try_send(NodeEndpointCommand::SendBatchOneway {
                command: fresh_bulk,
                lane: EndpointCommandLane::Bulk,
            })
            .expect("enqueue fresh bulk command");

        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        let tun_packet = tun_tcp_ack_packet(tun_dest);
        tun_tx
            .try_send(tun_packet.clone())
            .expect("enqueue TUN priority packet");

        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut priority_rx,
            &mut bulk_rx,
            8,
            &mut tun_rx,
            1,
            &mut routes,
        );
        source.endpoint_stale_bulk_drop_ms = 50;
        let mut outbound = Vec::new();

        assert_eq!(source.drain_outbound(8, |packet| outbound.push(packet)), 1);
        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].owner, tun_owner);
        assert_eq!(outbound[0].class, PacketClass::Control);
        assert_eq!(outbound[0].payload.as_ref(), tun_packet);
        assert!(source.take_endpoint_command_drops().is_empty());

        let mut next_outbound = Vec::new();
        assert_eq!(
            source.drain_outbound(8, |packet| next_outbound.push(packet)),
            1
        );
        assert_eq!(next_outbound.len(), 1);
        assert_eq!(next_outbound[0].owner, endpoint_owner);
        assert_eq!(next_outbound[0].class, PacketClass::Bulk);
        assert_eq!(next_outbound[0].payload.as_ref(), fresh_bulk_payload);
    }

    #[test]
    fn live_route_table_outbound_source_does_not_drop_stale_bulk_after_tcp_ack_progress() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let owner = OwnerId::fsp_node(*remote.node_addr());
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_endpoint_destination(
            *remote.node_addr(),
            PacketMover2EndpointCommandRoute::fsp(owner, 7, 0x03, 0x09),
        );

        let tcp_ack_payload = priority_tcp_ack_endpoint_payload();
        let stale_bulk_payload = bulk_endpoint_payload();
        let old_ms = crate::time::now_ms().saturating_sub(1_000);
        let stale_bulk = EndpointSendBatchCommand::new_with_enqueued_at_ms(
            remote,
            vec![EndpointDataPayload::new(stale_bulk_payload.clone())],
            None,
            old_ms,
        )
        .expect("stale bulk command");

        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(1);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(1);
        priority_tx
            .try_send(NodeEndpointCommand::send_oneway(
                remote,
                tcp_ack_payload.clone(),
                None,
            ))
            .expect("enqueue TCP ACK endpoint command");
        bulk_tx
            .try_send(NodeEndpointCommand::SendBatchOneway {
                command: stale_bulk,
                lane: EndpointCommandLane::Bulk,
            })
            .expect("enqueue stale bulk command");

        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        drop(tun_tx);
        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut priority_rx,
            &mut bulk_rx,
            8,
            &mut tun_rx,
            0,
            &mut routes,
        );
        source.endpoint_stale_bulk_drop_ms = 50;
        let mut outbound = Vec::new();

        assert_eq!(source.drain_outbound(8, |packet| outbound.push(packet)), 2);

        assert_eq!(outbound.len(), 2);
        assert_eq!(outbound[0].class, PacketClass::Control);
        assert_eq!(outbound[0].payload.as_ref(), tcp_ack_payload);
        assert_eq!(outbound[1].class, PacketClass::Bulk);
        assert_eq!(outbound[1].payload.as_ref(), stale_bulk_payload);
        assert!(source.take_endpoint_command_drops().is_empty());
        assert!(source.take_endpoint_deferred_commands().is_empty());
    }

    #[test]
    fn live_route_table_outbound_source_routes_stale_bulk_without_priority_progress() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let owner = OwnerId::fsp_node(*remote.node_addr());
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_endpoint_destination(
            *remote.node_addr(),
            PacketMover2EndpointCommandRoute::fsp(owner, 7, 0x03, 0x09),
        );

        let stale_bulk_payload = bulk_endpoint_payload();
        let old_ms = crate::time::now_ms().saturating_sub(1_000);
        let stale_bulk = EndpointSendBatchCommand::new_with_enqueued_at_ms(
            remote,
            vec![EndpointDataPayload::new(stale_bulk_payload.clone())],
            None,
            old_ms,
        )
        .expect("stale bulk command");

        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(1);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(1);
        drop(priority_tx);
        bulk_tx
            .try_send(NodeEndpointCommand::SendBatchOneway {
                command: stale_bulk,
                lane: EndpointCommandLane::Bulk,
            })
            .expect("enqueue stale bulk command");

        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        drop(tun_tx);
        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut priority_rx,
            &mut bulk_rx,
            8,
            &mut tun_rx,
            0,
            &mut routes,
        );
        source.endpoint_stale_bulk_drop_ms = 50;
        let mut outbound = Vec::new();

        assert_eq!(source.drain_outbound(8, |packet| outbound.push(packet)), 1);

        assert_eq!(outbound.len(), 1);
        assert_eq!(outbound[0].class, PacketClass::Bulk);
        assert_eq!(outbound[0].payload.as_ref(), stale_bulk_payload);
        assert!(source.take_endpoint_command_drops().is_empty());
        assert!(source.take_endpoint_deferred_commands().is_empty());
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
        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(1);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(1);
        drop((priority_tx, bulk_tx));
        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut priority_rx,
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

        assert_eq!(source.drain_outbound(2, |packet| outbound.push(packet)), 2);

        assert_eq!(outbound.len(), 2);
        assert_eq!(outbound[0].owner, owner);
        assert_eq!(outbound[0].payload.as_ref(), first_tun_packet);
        assert_eq!(outbound[1].owner, owner);
        assert_eq!(outbound[1].payload.as_ref(), queued_tun_packet);
        let drops = source.take_tun_outbound_drops();
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
            PacketMover2EndpointCommandRoute::fsp(endpoint_owner, 1, 0, 0),
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

        let (priority_tx, mut priority_rx) = tokio::sync::mpsc::channel(1);
        let (bulk_tx, mut bulk_rx) = tokio::sync::mpsc::channel(1);
        let payloads = (0..9)
            .map(|idx| EndpointDataPayload::new(vec![idx as u8, 0]))
            .collect::<Vec<_>>();
        bulk_tx
            .try_send(
                NodeEndpointCommand::send_batch_oneway(
                    remote,
                    payloads,
                    None,
                    EndpointCommandLane::Bulk,
                )
                .expect("endpoint batch command"),
            )
            .expect("enqueue endpoint batch");
        drop(priority_tx);

        let (tun_tx, mut tun_rx) = crate::upper::tun::tun_outbound_channel(1);
        let tun_packet = tun_ipv6_packet(tun_dest, 48);
        tun_tx
            .try_send(tun_packet.clone())
            .expect("enqueue TUN packet");

        let mut source = PacketMover2RouteTableOutboundSource::new(
            &mut priority_rx,
            &mut bulk_rx,
            1,
            &mut tun_rx,
            1,
            &mut routes,
        );
        let mut outbound = Vec::new();

        assert_eq!(source.drain_outbound(2, |packet| outbound.push(packet)), 3);

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
        assert!(source.take_endpoint_command_drops().is_empty());
        assert!(source.take_endpoint_deferred_commands().is_empty());
        assert!(source.take_tun_outbound_drops().is_empty());
    }
