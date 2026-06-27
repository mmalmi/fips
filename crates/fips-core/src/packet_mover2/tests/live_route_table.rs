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
    fn live_route_table_outbound_source_preserves_tun_slice_after_endpoint_batch_overrun() {
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let endpoint_owner = OwnerId::fsp_node(*remote.node_addr());
        let tun_dest = NodeAddr::from_bytes([0x65; 16]);
        let tun_owner = OwnerId::fmp_node(tun_dest);
        let mut routes = PacketMover2LiveIngressRoutes::default();
        routes.register_endpoint_destination(
            *remote.node_addr(),
            PacketMover2EndpointCommandRoute::fsp(endpoint_owner, 1, 0, 1_000, 0),
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

        let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel(1);
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

    #[test]
    fn live_route_table_refresh_owner_generation_preserves_routes_across_rekey() {
        let fmp_source = NodeAddr::from_bytes([0x66; 16]);
        let fsp_source = NodeAddr::from_bytes([0x67; 16]);
        let keep = NodeAddr::from_bytes([0x68; 16]);
        let fmp_owner = OwnerId::fmp_node(fmp_source);
        let fsp_owner = OwnerId::fsp_node(fsp_source);
        let keep_fmp_owner = OwnerId::fmp_node(keep);
        let keep_fsp_owner = OwnerId::fsp_node(keep);
        let transport_id = TransportId::new(66);
        let keep_transport_id = TransportId::new(68);
        let remote_addr = TransportAddr::from_string("198.51.100.66:9000");
        let mut routes = PacketMover2LiveIngressRoutes::default();

        routes.register_fmp(
            transport_id,
            660,
            PacketMover2IngressRoute::new(fmp_owner, 1, OutputTarget::Endpoint)
                .with_class(PacketClass::Liveness),
        );
        routes.register_tun_destination(
            fmp_source,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                fmp_owner,
                1,
                PacketClass::Bulk,
                661,
                0,
            )),
        );
        routes.register_fsp(
            fsp_source,
            PacketMover2IngressRoute::new(fsp_owner, 2, OutputTarget::Tun)
                .with_class(PacketClass::Mmp),
        );
        routes.register_endpoint_destination(
            fsp_source,
            PacketMover2EndpointCommandRoute::fsp(fsp_owner, 2, 0, 6_700, 0),
        );
        routes.register_fmp(
            keep_transport_id,
            680,
            PacketMover2IngressRoute::new(keep_fmp_owner, 5, OutputTarget::Endpoint),
        );
        routes.register_endpoint_destination(
            keep,
            PacketMover2EndpointCommandRoute::fsp(keep_fsp_owner, 6, 0, 6_800, 0),
        );

        assert_eq!(routes.refresh_owner_generation(fmp_owner, 10), 2);
        assert_eq!(routes.refresh_owner_generation(fsp_owner, 11), 2);
        assert_eq!(
            routes.refresh_owner_generation(
                OwnerId::fmp_node(NodeAddr::from_bytes([0x69; 16])),
                12,
            ),
            0
        );

        let fmp_raw = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr.clone(),
                fmp_wire(660, 1, 0),
                66_000,
            ),
        );
        let header =
            PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&fmp_raw.payload).unwrap());
        let route = routes
            .route(&fmp_raw, header)
            .expect("FMP route survives refresh");
        assert_eq!(route.owner, fmp_owner);
        assert_eq!(route.generation, 10);
        assert_eq!(route.class, PacketClass::Liveness);

        let fsp_raw = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fsp,
            ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr.clone(),
                fsp_wire(2, 0),
                67_000,
            ),
        )
        .with_fsp_source(fsp_source);
        let header =
            PacketMover2IngressHeader::Fsp(FspWireHeader::parse(&fsp_raw.payload).unwrap());
        let route = routes
            .route(&fsp_raw, header)
            .expect("FSP route survives refresh");
        assert_eq!(route.owner, fsp_owner);
        assert_eq!(route.generation, 11);
        assert_eq!(route.class, PacketClass::Mmp);

        let tun_route = routes
            .route_tun_outbound(&tun_ipv6_packet(fmp_source, 48))
            .expect("TUN route survives refresh");
        assert_eq!(tun_route.owner(), fmp_owner);
        assert_eq!(tun_route.generation, 10);

        let endpoint_packet = routes
            .route_endpoint_command_payload(PacketMover2EndpointCommandPayload {
                dest_addr: fsp_source,
                dest_pubkey: crate::Identity::generate().pubkey_full(),
                lane: EndpointCommandLane::Bulk,
                payload: b"after-rekey",
            })
            .expect("endpoint route survives refresh");
        assert_eq!(endpoint_packet.owner, fsp_owner);
        assert_eq!(endpoint_packet.generation, 11);

        let keep_raw = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                keep_transport_id,
                remote_addr,
                fmp_wire(680, 1, 0),
                68_000,
            ),
        );
        let header =
            PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&keep_raw.payload).unwrap());
        assert_eq!(routes.route(&keep_raw, header).unwrap().generation, 5);
        assert_eq!(
            routes
                .route_endpoint_command_payload(PacketMover2EndpointCommandPayload {
                    dest_addr: keep,
                    dest_pubkey: crate::Identity::generate().pubkey_full(),
                    lane: EndpointCommandLane::Bulk,
                    payload: b"keep",
                })
                .unwrap()
                .generation,
            6
        );
    }

    #[tokio::test]
    async fn live_node_packet_rx_route_table_turn_sends_endpoint_and_tun_to_transport() {
        let send_transport_id = TransportId::new(82);
        let recv_transport_id = TransportId::new(83);
        let remote = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let fsp_source = *remote.node_addr();
        let fsp_owner = OwnerId::fsp_node(fsp_source);
        let tun_dest = NodeAddr::from_bytes([0x52; 16]);
        let fmp_owner = OwnerId::fmp_node(tun_dest);
        let fsp_key = 82;
        let fmp_key = 83;
        let (recv_packet_tx, mut recv_packet_rx) = crate::transport::packet_channel(4);
        let mut recv_transport = TransportHandle::Udp(crate::transport::udp::UdpTransport::new(
            recv_transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            recv_packet_tx,
        ));
        recv_transport.start().await.expect("start recv udp");
        let remote_addr = TransportAddr::from_string(
            &recv_transport
                .local_addr()
                .expect("recv udp local addr")
                .to_string(),
        );
        let mut send_transport = unstarted_udp_transport(send_transport_id);
        send_transport.start().await.expect("start send udp");
        let live_path = TransportPath::live(send_transport_id, remote_addr);
        let mut transports = HashMap::from([(send_transport_id, send_transport)]);
        let (_packet_tx, mut packet_rx) = crate::transport::packet_channel(8);

        let (endpoint_priority_tx, mut endpoint_priority_rx) = tokio::sync::mpsc::channel(8);
        let (endpoint_bulk_tx, mut endpoint_bulk_rx) = tokio::sync::mpsc::channel(8);
        let endpoint_payload = bulk_endpoint_payload();
        endpoint_bulk_tx
            .try_send(
                NodeEndpointCommand::send_batch_oneway(
                    remote,
                    vec![EndpointDataPayload::new(endpoint_payload.clone())],
                    None,
                    EndpointCommandLane::Bulk,
                )
                .expect("endpoint batch command"),
            )
            .expect("enqueue endpoint command");
        drop(endpoint_priority_tx);

        let (tun_outbound_tx, mut tun_outbound_rx) = tokio::sync::mpsc::channel(8);
        let tun_packet = tun_ipv6_packet(tun_dest, 48);
        tun_outbound_tx
            .try_send(tun_packet.clone())
            .expect("enqueue TUN outbound packet");
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let (tun_tx, tun_rx) = std::sync::mpsc::channel();
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(8, 16), CopyCryptoWorker);
        driver.register_owner(
            fsp_owner,
            OwnerConfig::new(1, 8).with_next_send_counter(820),
        );
        driver.register_owner(
            fmp_owner,
            OwnerConfig::new(1, 8).with_next_send_counter(830),
        );
        driver
            .owner_mut(fsp_owner)
            .unwrap()
            .set_active_path(live_path.clone());
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_active_path(live_path.clone());
        driver
            .owner_mut(fsp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fsp_key), test_key(fsp_key)));
        driver
            .owner_mut(fmp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fmp_key), test_key(fmp_key)));

        let mut routes = PacketMover2LiveIngressRoutes::default();
        routes.register_endpoint_destination(
            fsp_source,
            PacketMover2EndpointCommandRoute::fsp(fsp_owner, 1, 0, 8_200, 0)
                .with_max_payload_len(64),
        );
        routes.register_tun_destination(
            tun_dest,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                fmp_owner,
                1,
                PacketClass::Bulk,
                830,
                0,
            ))
            .with_max_packet_len(64),
        );
        let mut deferred_endpoint_commands = Vec::new();

        let turn = driver
            .pump_aead_live_node_packet_rx_route_table_turn(
                &mut packet_rx,
                &mut routes,
                8,
                &mut endpoint_priority_rx,
                &mut endpoint_bulk_rx,
                8,
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
        assert_eq!(turn.summary().inbound_admitted(), 0);
        assert_eq!(turn.summary().outbound_admitted(), 2);
        assert_eq!(turn.summary().outbound_dropped(), 0);
        assert_eq!(turn.summary().outputs(), 2);
        assert_eq!(turn.summary().outputs_sent(), 2);
        assert_eq!(turn.summary().outputs_dropped(), 0);
        assert!(turn.raw_ingress_drops().is_empty());
        assert!(turn.endpoint_command_drops().is_empty());
        assert_eq!(turn.endpoint_deferred_commands(), 0);
        assert!(deferred_endpoint_commands.is_empty());
        assert!(turn.tun_outbound_drops().is_empty());
        assert!(turn.output_drops().is_empty());
        assert!(turn.drops().is_empty());
        assert_eq!(turn.transport_planned(), 2);
        assert_eq!(turn.transport_sent(), 2);
        assert_eq!(turn.transport_dropped(), 0);
        assert!(packet_rx.try_recv().is_err());
        assert!(endpoint_priority_rx.try_recv().is_err());
        assert!(endpoint_bulk_rx.try_recv().is_err());
        assert!(tun_outbound_rx.try_recv().is_err());
        assert!(tun_rx.try_recv().is_err());
        assert!(endpoint_io.event_rx.try_recv().is_err());

        let mut received = Vec::new();
        for _ in 0..2 {
            received.push(
                tokio::time::timeout(std::time::Duration::from_secs(1), recv_packet_rx.recv())
                    .await
                    .expect("receive route-table transport output")
                    .expect("packet channel open"),
            );
        }
        assert!(received
            .iter()
            .all(|packet| packet.transport_id == recv_transport_id));

        let fsp_packet = received
            .iter()
            .find(|packet| FspWireHeader::parse(&packet.data).is_ok())
            .expect("FSP endpoint transport output");
        let fsp_header = FspWireHeader::parse(&fsp_packet.data).unwrap();
        assert_eq!(fsp_header.counter(), 820);
        let plaintext = open_fsp_wire_payload(&fsp_packet.data, fsp_key);
        let (timestamp, msg_type, inner_flags, delivered_endpoint_payload) =
            crate::node::session_wire::fsp_strip_inner_header(&plaintext)
                .expect("endpoint FSP inner header");
        assert_eq!(timestamp, 8_200);
        assert_eq!(
            msg_type,
            crate::protocol::SessionMessageType::EndpointData.to_byte()
        );
        assert_eq!(inner_flags, 0);
        assert_eq!(delivered_endpoint_payload, endpoint_payload.as_slice());

        let fmp_packet = received
            .iter()
            .find(|packet| {
                FmpWireHeader::parse(&packet.data)
                    .is_ok_and(|header| header.receiver_idx() == 830)
            })
            .expect("FMP TUN transport output");
        let fmp_header = FmpWireHeader::parse(&fmp_packet.data).unwrap();
        assert_eq!(fmp_header.counter(), 830);
        assert_eq!(
            open_fmp_wire_payload(&fmp_packet.data, fmp_key),
            tun_packet
        );
        assert_eq!(
            driver.owner_mut(fsp_owner).unwrap().active_path(),
            Some(live_path.clone())
        );
        assert_eq!(
            driver.owner_mut(fmp_owner).unwrap().active_path(),
            Some(live_path)
        );

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send udp");
        recv_transport.stop().await.expect("stop recv udp");
    }
