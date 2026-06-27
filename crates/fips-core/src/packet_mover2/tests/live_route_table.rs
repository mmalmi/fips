    fn tun_ipv6_packet(dest_addr: NodeAddr, len: usize) -> Vec<u8> {
        assert!(len >= 40);
        let mut packet = vec![0u8; len];
        packet[0] = 0x60;
        packet[6] = 17;
        let dest = crate::FipsAddress::from_node_addr(&dest_addr);
        packet[24..40].copy_from_slice(dest.as_bytes());
        packet
    }

    fn priority_endpoint_payload() -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60;
        packet[6] = 58;
        packet
    }

    fn bulk_endpoint_payload() -> Vec<u8> {
        vec![0x01, 0x02, 0x03, 0x04]
    }

    #[test]
    fn live_route_table_routes_tun_outbound_by_fips_destination_prefix() {
        let dest = NodeAddr::from_bytes([0x61; 16]);
        let owner = OwnerId::fmp_node(dest);
        let mut routes = PacketMover2LiveIngressRoutes::default();
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
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tx.try_send(valid.clone()).expect("enqueue valid TUN packet");
        tx.try_send(unknown.clone())
            .expect("enqueue unknown TUN packet");
        tx.try_send(invalid.clone())
            .expect("enqueue invalid TUN packet");
        tx.try_send(oversize.clone())
            .expect("enqueue oversized TUN packet");

        let mut source = PacketMover2TunOutboundSource::new(&mut rx, &mut routes);
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
        assert_eq!(
            source
                .drops()
                .iter()
                .map(PacketMover2TunOutboundDrop::reason)
                .collect::<Vec<_>>(),
            vec![
                PacketMover2TunOutboundDropReason::NoRoute,
                PacketMover2TunOutboundDropReason::InvalidPacket,
                PacketMover2TunOutboundDropReason::MtuExceeded,
            ]
        );
        assert_eq!(source.drops()[0].payload_len(), unknown.len());
        assert_eq!(source.drops()[1].payload_len(), invalid.len());
        assert_eq!(source.drops()[2].payload_len(), oversize.len());
    }

    #[test]
    fn live_route_table_routes_endpoint_commands_into_fsp_endpoint_data() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let missing_remote =
            PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let owner = OwnerId::fsp_node(*remote.node_addr());
        let mut routes = PacketMover2LiveIngressRoutes::default();
        routes.register_endpoint_destination(
            *remote.node_addr(),
            PacketMover2EndpointCommandRoute::fsp(owner, 7, 0x03, 12_345, 0x09)
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

        let mut source =
            PacketMover2EndpointCommandSource::new(&mut priority_rx, &mut bulk_rx, &mut routes);
        let mut outbound = Vec::new();

        assert_eq!(source.drain_outbound(16, |packet| outbound.push(packet)), 3);

        assert_eq!(outbound.len(), 2);
        assert_eq!(outbound[0].owner, owner);
        assert_eq!(outbound[0].generation, 7);
        assert_eq!(outbound[0].class, PacketClass::Control);
        assert_eq!(outbound[0].wire, OutboundWire::Fsp { flags: 0x03 });
        let (timestamp, msg_type, inner_flags, payload) =
            crate::node::session_wire::fsp_strip_inner_header(outbound[0].payload.as_ref())
                .expect("priority FSP endpoint header");
        assert_eq!(timestamp, 12_345);
        assert_eq!(
            msg_type,
            crate::protocol::SessionMessageType::EndpointData.to_byte()
        );
        assert_eq!(inner_flags, 0x09);
        assert_eq!(payload, priority_payload.as_slice());

        assert_eq!(outbound[1].owner, owner);
        assert_eq!(outbound[1].generation, 7);
        assert_eq!(outbound[1].class, PacketClass::Bulk);
        let (_, msg_type, _, payload) =
            crate::node::session_wire::fsp_strip_inner_header(outbound[1].payload.as_ref())
                .expect("bulk FSP endpoint header");
        assert_eq!(
            msg_type,
            crate::protocol::SessionMessageType::EndpointData.to_byte()
        );
        assert_eq!(payload, bulk_payload.as_slice());

        assert_eq!(source.drops().len(), 2);
        assert_eq!(source.drops()[0].dest_addr(), *remote.node_addr());
        assert_eq!(source.drops()[0].lane(), EndpointCommandLane::Bulk);
        assert_eq!(source.drops()[0].payload_len(), oversized_payload.len());
        assert_eq!(
            source.drops()[0].reason(),
            PacketMover2EndpointCommandDropReason::MtuExceeded
        );
        assert_eq!(source.drops()[1].dest_addr(), *missing_remote.node_addr());
        assert_eq!(source.drops()[1].lane(), EndpointCommandLane::Bulk);
        assert_eq!(source.drops()[1].payload_len(), missing_payload.len());
        assert_eq!(
            source.drops()[1].reason(),
            PacketMover2EndpointCommandDropReason::NoRoute
        );
    }

    #[test]
    fn live_route_table_unregister_owner_prunes_output_routes() {
        let stale = NodeAddr::from_bytes([0x63; 16]);
        let keep = NodeAddr::from_bytes([0x64; 16]);
        let stale_fmp_owner = OwnerId::fmp_node(stale);
        let stale_fsp_owner = OwnerId::fsp_node(stale);
        let keep_fmp_owner = OwnerId::fmp_node(keep);
        let keep_fsp_owner = OwnerId::fsp_node(keep);
        let mut routes = PacketMover2LiveIngressRoutes::default();
        routes.register_fmp(
            TransportId::new(63),
            630,
            PacketMover2IngressRoute::new(stale_fmp_owner, 1, OutputTarget::Tun),
        );
        routes.register_tun_destination(
            stale,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                stale_fmp_owner,
                1,
                PacketClass::Bulk,
                630,
                0,
            )),
        );
        routes.register_fsp(
            stale,
            PacketMover2IngressRoute::new(stale_fsp_owner, 2, OutputTarget::Endpoint),
        );
        routes.register_endpoint_destination(
            stale,
            PacketMover2EndpointCommandRoute::fsp(stale_fsp_owner, 2, 0, 1, 0),
        );
        routes.register_tun_destination(
            keep,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                keep_fmp_owner,
                3,
                PacketClass::Bulk,
                640,
                0,
            )),
        );
        routes.register_endpoint_destination(
            keep,
            PacketMover2EndpointCommandRoute::fsp(keep_fsp_owner, 4, 0, 1, 0),
        );

        assert_eq!(routes.unregister_owner(stale_fmp_owner), 2);
        assert_eq!(routes.unregister_owner(stale_fsp_owner), 2);
        assert_eq!(routes.unregister_owner(stale_fmp_owner), 0);

        assert_eq!(
            routes.route_tun_outbound(&tun_ipv6_packet(stale, 48)),
            Err(PacketMover2TunOutboundDropReason::NoRoute)
        );
        assert_eq!(
            routes.route_endpoint_command_payload(PacketMover2EndpointCommandPayload {
                dest_addr: stale,
                dest_pubkey: crate::Identity::generate().pubkey_full(),
                lane: EndpointCommandLane::Bulk,
                payload: b"stale",
            }),
            Err(PacketMover2EndpointCommandDropReason::NoRoute)
        );
        assert_eq!(
            routes
                .route_tun_outbound(&tun_ipv6_packet(keep, 48))
                .expect("keep TUN route")
                .owner(),
            keep_fmp_owner
        );
        assert_eq!(
            routes
                .route_endpoint_command_payload(PacketMover2EndpointCommandPayload {
                    dest_addr: keep,
                    dest_pubkey: crate::Identity::generate().pubkey_full(),
                    lane: EndpointCommandLane::Bulk,
                    payload: b"keep",
                })
                .expect("keep endpoint route")
                .owner,
            keep_fsp_owner
        );
    }
