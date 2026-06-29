    #[test]
    fn live_node_replaces_rekeys_and_unregisters_owner_routes() {
        let owner_addr = NodeAddr::from_bytes([0x91; 16]);
        let owner = OwnerId::fmp_node(owner_addr);
        let other_owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x92; 16]));
        let transport_a = TransportId::new(91);
        let transport_b = TransportId::new(92);
        let remote_addr = TransportAddr::from_string("198.51.100.91:9000");
        let mut live_node =
            PacketMover2LiveNode::new(AdmissionConfig::new(4, 8));

        assert_eq!(
            live_node.replace_owner_routes(owner, PacketMover2LiveOwnerRoutes::new()),
            Err(PacketMover2LiveOwnerError::UnknownOwner)
        );
        assert_eq!(
            live_node.set_owner_active_path(owner, live_path(91)),
            Err(PacketMover2LiveOwnerError::UnknownOwner)
        );
        assert_eq!(
            live_node.set_owner_crypto_keys(
                owner,
                OwnerCryptoKeys::new(test_key(91), test_key(91)),
            ),
            Err(PacketMover2LiveOwnerError::UnknownOwner)
        );
        assert_eq!(
            live_node.owner_active_path(owner),
            Err(PacketMover2LiveOwnerError::UnknownOwner)
        );

        live_node.register_owner(owner, OwnerConfig::new(1, 8));
        let mut routes = PacketMover2LiveOwnerRoutes::new();
        routes.push_fmp_ingress(PacketMover2LiveFmpIngressRoute::new(
            transport_a,
            910,
            PacketMover2IngressRoute::new(owner, 1, OutputTarget::Tun)
                .with_class(PacketClass::Liveness),
        ));
        routes.push_tun_destination(PacketMover2LiveTunRoute::new(
            owner_addr,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                owner,
                1,
                PacketClass::Bulk,
                911,
                0,
            )),
        ));

        let summary = live_node
            .replace_owner_routes(owner, routes)
            .expect("owner routes should replace");
        assert!(!summary.owner_removed());
        assert_eq!(summary.routes_removed(), 0);
        assert_eq!(summary.routes_added(), 2);

        let old_raw = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                transport_a,
                remote_addr.clone(),
                fmp_wire(910, 1, 0),
                91_000,
            ),
        );
        let old_header =
            PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&old_raw.payload).unwrap());
        assert_eq!(
            live_node.routes.route(&old_raw, old_header).unwrap(),
            PacketMover2IngressRoute::new(owner, 1, OutputTarget::Tun)
                .with_class(PacketClass::Liveness)
        );

        let mut mismatched = PacketMover2LiveOwnerRoutes::new();
        mismatched.push_fmp_ingress(PacketMover2LiveFmpIngressRoute::new(
            transport_b,
            920,
            PacketMover2IngressRoute::new(other_owner, 1, OutputTarget::Endpoint),
        ));
        assert_eq!(
            live_node.replace_owner_routes(owner, mismatched),
            Err(PacketMover2LiveOwnerError::OwnerMismatch)
        );

        let mut replacement = PacketMover2LiveOwnerRoutes::new();
        replacement.push_fmp_ingress(PacketMover2LiveFmpIngressRoute::new(
            transport_b,
            920,
            PacketMover2IngressRoute::new(owner, 2, OutputTarget::Endpoint)
                .with_class(PacketClass::Mmp),
        ));
        let summary = live_node
            .replace_owner_routes(owner, replacement)
            .expect("replacement routes should apply");
        assert_eq!(summary.routes_removed(), 2);
        assert_eq!(summary.routes_added(), 1);

        let old_header =
            PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&old_raw.payload).unwrap());
        assert_eq!(live_node.routes.route(&old_raw, old_header), None);

        let new_raw = PacketMover2RawIngress::from_live_received(
            PacketProtocol::Fmp,
            ReceivedPacket::with_timestamp(
                transport_b,
                remote_addr,
                fmp_wire(920, 1, 0),
                92_000,
            ),
        );
        let new_header =
            PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&new_raw.payload).unwrap());
        assert_eq!(
            live_node.routes.route(&new_raw, new_header).unwrap(),
            PacketMover2IngressRoute::new(owner, 2, OutputTarget::Endpoint)
                .with_class(PacketClass::Mmp)
        );

        assert_eq!(live_node.rekey_owner(owner, 9).unwrap(), 1);
        let new_header =
            PacketMover2IngressHeader::Fmp(FmpWireHeader::parse(&new_raw.payload).unwrap());
        assert_eq!(
            live_node.routes.route(&new_raw, new_header).unwrap(),
            PacketMover2IngressRoute::new(owner, 9, OutputTarget::Endpoint)
                .with_class(PacketClass::Mmp)
        );

        let summary = live_node.unregister_owner(owner);
        assert!(summary.owner_removed());
        assert_eq!(summary.routes_removed(), 1);
        assert_eq!(summary.routes_added(), 0);
        assert_eq!(
            live_node.rekey_owner(owner, 10),
            Err(PacketMover2LiveOwnerError::UnknownOwner)
        );
    }

    #[test]
    fn live_node_register_owner_if_missing_preserves_existing_owner_state() {
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x93; 16]));
        let active_path = live_path(93);
        let mut live_node =
            PacketMover2LiveNode::new(AdmissionConfig::new(4, 8));

        assert!(live_node.register_owner_if_missing(
            owner,
            OwnerConfig::new(1, 8).with_next_send_counter(93_000),
        ));
        assert_eq!(live_node.set_owner_active_path(owner, active_path.clone()), Ok(()));

        assert!(!live_node.register_owner_if_missing(
            owner,
            OwnerConfig::new(99, 1).with_next_send_counter(1),
        ));

        assert_eq!(live_node.owner_active_path(owner), Ok(Some(active_path)));
    }

    #[tokio::test]
    async fn live_node_rekey_owner_keeps_registered_routes_live() {
        let send_transport_id = TransportId::new(93);
        let recv_transport_id = TransportId::new(94);
        let source = NodeAddr::from_bytes([0x93; 16]);
        let owner = OwnerId::fmp_node(source);
        let old_key = 93;
        let new_key = 94;

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
        let live_path = TransportPath::live(send_transport_id, remote_addr.clone());
        let mut transports = HashMap::from([(send_transport_id, send_transport)]);

        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
        let mut live_node =
            PacketMover2LiveNode::new(AdmissionConfig::new(4, 8));
        live_node.register_owner(
            owner,
            OwnerConfig::new(1, 8).with_next_send_counter(93_000),
        );
        assert_eq!(
            live_node.set_owner_active_path(owner, live_path.clone()),
            Ok(())
        );
        assert_eq!(
            live_node.set_owner_crypto_keys(
                owner,
                OwnerCryptoKeys::new(test_key(old_key), test_key(old_key)),
            ),
            Ok(())
        );

        let mut routes = PacketMover2LiveOwnerRoutes::new();
        routes.push_fmp_ingress(PacketMover2LiveFmpIngressRoute::new(
            send_transport_id,
            930,
            PacketMover2IngressRoute::new(owner, 1, OutputTarget::Tun)
                .with_class(PacketClass::Rekey),
        ));
        routes.push_tun_destination(PacketMover2LiveTunRoute::new(
            source,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                owner,
                1,
                PacketClass::Liveness,
                931,
                0,
            )),
        ));
        assert_eq!(
            live_node
                .replace_owner_routes(owner, routes)
                .expect("install owner routes")
                .routes_added(),
            2
        );

        assert_eq!(live_node.rekey_owner(owner, 2), Ok(2));
        assert_eq!(
            live_node.set_owner_crypto_keys(
                owner,
                OwnerCryptoKeys::new(test_key(new_key), test_key(new_key)),
            ),
            Ok(())
        );

        let mut raw_source =
            PacketMover2LiveRawIngressSource::new(VecDeque::from([PacketMover2LiveIngressPacket::fmp(
                ReceivedPacket::with_timestamp(
                    send_transport_id,
                    remote_addr.clone(),
                    fmp_encrypted_wire(930, 5, 0, b"after-rekey-in", new_key),
                    93_000,
                ),
            )]));
        let (_endpoint_priority_tx, mut endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
        let (_endpoint_bulk_tx, mut endpoint_bulk_rx) = tokio::sync::mpsc::channel(1);
        let (tun_outbound_tx, mut tun_outbound_rx) =
            crate::upper::tun::tun_outbound_channel(1);
        let tun_packet = tun_ipv6_packet(source, 56);
        tun_outbound_tx
            .try_send(tun_packet.clone())
            .expect("enqueue post-rekey TUN packet");

        let first = live_node
            .pump_turn_with_firsts(
                &mut raw_source,
                8,
                PacketMover2LiveOutboundFirsts::default(),
                &mut endpoint_priority_rx,
                &mut endpoint_bulk_rx,
                0,
                &mut tun_outbound_rx,
                8,
                &tun_tx,
                &endpoint_io.event_tx,
                missing_endpoint_peer,
                &transports,
                8,
            )
            .await;

        assert_eq!(first.summary().raw_ingress_dropped(), 0);
        assert_eq!(first.summary().inbound_admitted(), 1);
        assert_eq!(first.summary().outbound_admitted(), 1);
        assert_eq!(first.summary().dispatched(), 2);
        assert_eq!(first.summary().outputs(), 0);
        assert_eq!(first.summary().outputs_sent(), 0);
        assert_eq!(first.summary().outputs_dropped(), 0);
        assert_eq!(first.transport_planned(), 0);
        assert_eq!(first.transport_sent(), 0);
        assert!(first.raw_ingress_drops().is_empty());
        assert!(first.output_drops().is_empty());
        assert!(first.drops().is_empty());
        assert!(first.tun_outbound_drops().is_empty());
        assert!(first.endpoint_command_drops().is_empty());
        assert!(tun_rx.try_recv().is_err());
        assert!(endpoint_io.event_rx.try_recv().is_err());

        wait_for_live_worker_completion(&live_node).await;
        let turn = live_node
            .pump_outbound_firsts(
                PacketMover2LiveOutboundFirsts::default(),
                0,
                0,
                &tun_tx,
                &endpoint_io.event_tx,
                missing_endpoint_peer,
                &transports,
                8,
            )
            .await;
        assert_eq!(turn.summary().completions(), 2);
        assert_eq!(turn.summary().outputs(), 2);
        assert_eq!(turn.summary().outputs_sent(), 2);
        assert_eq!(turn.summary().outputs_dropped(), 0);
        assert_eq!(turn.transport_planned(), 1);
        assert_eq!(turn.transport_sent(), 1);
        assert_eq!(tun_rx.try_recv().unwrap(), b"after-rekey-in".to_vec());
        assert!(endpoint_io.event_rx.try_recv().is_err());

        let received =
            tokio::time::timeout(std::time::Duration::from_secs(1), recv_packet_rx.recv())
                .await
                .expect("receive post-rekey transport output")
                .expect("packet channel open");
        assert_eq!(received.transport_id, recv_transport_id);
        let header = FmpWireHeader::parse(&received.data).unwrap();
        assert_eq!(header.receiver_idx(), 931);
        assert_eq!(header.counter(), 0);
        assert_eq!(open_fmp_wire_payload(&received.data, new_key), tun_packet);
        assert_eq!(live_node.owner_active_path(owner), Ok(Some(live_path)));

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send udp");
        recv_transport.stop().await.expect("stop recv udp");
    }
