    #[tokio::test]
    async fn live_node_owner_routes_send_endpoint_and_tun_to_transport() {
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

        let (tun_outbound_tx, mut tun_outbound_rx) =
            crate::upper::tun::tun_outbound_channel(8);
        let tun_packet = tun_ipv6_packet(tun_dest, 48);
        tun_outbound_tx
            .try_send(tun_packet.clone())
            .expect("enqueue TUN outbound packet");
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
        let mut live_node =
            PacketMover2LiveNode::new(AdmissionConfig::new(8, 16));
        live_node.register_owner(
            fsp_owner,
            OwnerConfig::new(1, 8).with_next_send_counter(820),
        );
        live_node.register_owner(
            fmp_owner,
            OwnerConfig::new(1, 8).with_next_send_counter(830),
        );
        live_node.driver.owner_mut(fsp_owner)
            .unwrap()
            .set_active_path(live_path.clone());
        live_node.driver.owner_mut(fmp_owner)
            .unwrap()
            .set_active_path(live_path.clone());
        live_node.driver.owner_mut(fsp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fsp_key), test_key(fsp_key)));
        live_node.driver.owner_mut(fmp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fmp_key), test_key(fmp_key)));
        let fsp_session_start_ms = crate::time::now_ms().saturating_sub(8_200);
        assert_eq!(
            live_node.set_owner_fsp_session_start_ms(fsp_owner, fsp_session_start_ms),
            Ok(())
        );

        let mut fsp_routes = PacketMover2LiveOwnerRoutes::new();
        fsp_routes.push_endpoint_destination(PacketMover2LiveEndpointRoute::new(
            fsp_source,
            PacketMover2EndpointCommandRoute::fsp(fsp_owner, 1, 0, 0)
                .with_max_payload_len(64),
        ));
        let mut fmp_routes = PacketMover2LiveOwnerRoutes::new();
        fmp_routes.push_tun_destination(PacketMover2LiveTunRoute::new(
            tun_dest,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                fmp_owner,
                1,
                PacketClass::Bulk,
                830,
                0,
            ))
            .with_max_packet_len(64),
        ));
        assert_eq!(
            live_node
                .replace_owner_routes(fsp_owner, fsp_routes)
                .expect("install endpoint route")
                .routes_added(),
            1
        );
        assert_eq!(
            live_node
                .replace_owner_routes(fmp_owner, fmp_routes)
                .expect("install TUN route")
                .routes_added(),
            1
        );

        let turn = live_node
            .pump_packet_rx_turn(
                &mut packet_rx,
                8,
                &mut endpoint_priority_rx,
                &mut endpoint_bulk_rx,
                8,
                &mut tun_outbound_rx,
                8,
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
        assert!(
            (8_200..=8_500).contains(&timestamp),
            "unexpected endpoint timestamp {timestamp}"
        );
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
            live_node.driver.owner_mut(fsp_owner).unwrap().active_path(),
            Some(live_path.clone())
        );
        assert_eq!(
            live_node.driver.owner_mut(fmp_owner).unwrap().active_path(),
            Some(live_path)
        );

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send udp");
        recv_transport.stop().await.expect("stop recv udp");
    }

    #[tokio::test]
    async fn live_node_route_table_turn_drains_sourced_fsp_ingress_to_endpoint() {
        let source_peer =
            PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let fsp_source = *source_peer.node_addr();
        let fsp_owner = OwnerId::fsp_node(fsp_source);
        let fsp_key = 84;
        let transport_id = TransportId::new(84);
        let remote_addr = TransportAddr::from_string("198.51.100.84:9000");
        let mut raw_source = PacketMover2LiveRawIngressSource::new(VecDeque::from([
            PacketMover2LiveIngressPacket::fsp(
                ReceivedPacket::with_timestamp(
                    transport_id,
                    remote_addr,
                    fsp_encrypted_wire(20, 0, b"route-table-fsp-ingress", fsp_key),
                    84_000,
                ),
                fsp_source,
            ),
        ]));

        let (endpoint_priority_tx, mut endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
        let (endpoint_bulk_tx, mut endpoint_bulk_rx) = tokio::sync::mpsc::channel(1);
        let (tun_outbound_tx, mut tun_outbound_rx) =
            crate::upper::tun::tun_outbound_channel(1);
        drop((endpoint_priority_tx, endpoint_bulk_tx, tun_outbound_tx));
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let mut endpoint_io = node.attach_endpoint_data_io(1).expect("endpoint io");
        let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(fsp_owner, OwnerConfig::new(1, 8));
        driver
            .owner_mut(fsp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fsp_key), test_key(fsp_key)));

        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_fsp(
            fsp_source,
            PacketMover2IngressRoute::new(fsp_owner, 1, OutputTarget::Endpoint)
                .with_class(PacketClass::Mmp),
        );
        let mut deferred_endpoint_commands = Vec::new();
        let mut deferred_tun_packets = Vec::new();
        let transports = HashMap::<TransportId, TransportHandle>::new();
        let resolver = |addr: &NodeAddr| {
            if addr == &fsp_source {
                Some(source_peer)
            } else {
                None
            }
        };

        let turn = pump_aead_live_node_route_table_turn(&mut driver,
                &mut raw_source,
                &mut routes,
                8,
                &mut endpoint_priority_rx,
                &mut endpoint_bulk_rx,
                8,
                &mut tun_outbound_rx,
                8,
                &mut deferred_endpoint_commands,
                &mut deferred_tun_packets,
                &tun_tx,
                &endpoint_io.event_tx,
                resolver,
                &transports,
                8,
            )
            .await;

        assert_eq!(turn.summary().raw_ingress_dropped(), 0);
        assert_eq!(turn.summary().inbound_admitted(), 1);
        assert_eq!(turn.summary().outbound_admitted(), 0);
        assert!(deferred_tun_packets.is_empty());
        assert_eq!(turn.summary().outputs(), 1);
        assert_eq!(turn.summary().outputs_sent(), 1);
        assert_eq!(turn.summary().outputs_dropped(), 0);
        assert!(turn.raw_ingress_drops().is_empty());
        assert!(turn.endpoint_command_drops().is_empty());
        assert!(turn.tun_outbound_drops().is_empty());
        assert!(turn.output_drops().is_empty());
        assert!(turn.drops().is_empty());
        assert!(deferred_endpoint_commands.is_empty());
        assert!(raw_source.source.is_empty());
        assert!(tun_rx.try_recv().is_err());

        match endpoint_io.event_rx.try_recv().expect("endpoint event") {
            NodeEndpointEvent::Data {
                source_peer: delivered_source,
                payload,
                ..
            } => {
                assert_eq!(delivered_source, source_peer);
                assert_eq!(payload, b"route-table-fsp-ingress");
            }
            event => panic!("expected endpoint data, got {event:?}"),
        }
    }
