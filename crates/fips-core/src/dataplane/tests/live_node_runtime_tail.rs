    #[tokio::test]
    async fn transport_plan_dispatch_spools_ordered_bulk_past_soft_capacity() {
        let send_transport_id = TransportId::new(64);
        let recv_transport_id = TransportId::new(65);
        let (recv_packet_tx, mut recv_packet_rx) = crate::transport::packet_channel(8);
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
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x64; 16]));
        let groups = vec![
            DataplaneTransportPlanGroup::new(
                send_transport_id,
                remote_addr.clone(),
                transport_output(
                    owner,
                    640,
                    40,
                    send_transport_id,
                    remote_addr.clone(),
                    b"bulk-full-a".to_vec(),
                ),
            ),
            DataplaneTransportPlanGroup::new(
                send_transport_id,
                remote_addr.clone(),
                transport_output(
                    owner,
                    641,
                    41,
                    send_transport_id,
                    remote_addr.clone(),
                    b"bulk-full-b".to_vec(),
                ),
            ),
        ];
        let mut transports = HashMap::from([(send_transport_id, send_transport)]);
        let mut drops = Vec::new();
        let max_batch_packets = 1;

        let sent = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            send_dataplane_transport_groups(
                &transports,
                groups,
                &mut drops,
                max_batch_packets,
                None,
            ),
        )
        .await
        .expect("ordered worker spool should not block on soft capacity");

        assert_eq!(sent, 2);
        assert!(drops.is_empty());
        let mut payloads = Vec::new();
        for _ in 0..2 {
            let received =
                tokio::time::timeout(std::time::Duration::from_secs(1), recv_packet_rx.recv())
                    .await
                    .expect("receive ordered worker packet")
                    .expect("packet channel open");
            payloads.push(received.data.as_slice().to_vec());
        }
        assert_eq!(
            payloads,
            [b"bulk-full-a".to_vec(), b"bulk-full-b".to_vec()]
        );

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send udp");
        recv_transport.stop().await.expect("stop recv udp");
    }

    #[test]
    fn live_output_sink_drops_transport_without_live_path() {
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x47; 16]));
        let key = 47;
        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(470));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));
        let outbound =
            OutboundPacket::fmp(owner, 1, PacketClass::Bulk, 471, 0, PacketBuffer::new(b"no-route".to_vec()));
        let mut transport = DataplaneTransportSendGroups::new();

        let turn = {
            let mut sink = DataplaneLiveOutputSink::new(&mut transport);
            run_aead_classified_output_turn(&mut driver, std::iter::empty(), [outbound], &mut sink, 8)
        };

        assert_eq!(turn.summary().outputs(), 1);
        assert_eq!(turn.summary().outputs_sent(), 0);
        assert_eq!(turn.summary().outputs_dropped(), 1);
        assert!(turn.outputs().is_empty());
        assert_eq!(turn.output_drops().len(), 1);
        assert_eq!(
            turn.output_drops()[0].reason(),
            DataplaneOutputError::NoRoute
        );
        assert!(transport.groups.is_empty());
    }

    #[test]
    fn runtime_raw_ingress_turn_parses_received_packet_before_owner_admission() {
        let owner = fmp_owner(81);
        let open_key = 51;
        let path = live_path(9005);
        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(7, 8));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(open_key)));
        let received = ReceivedPacket::with_timestamp(
            TransportId::new(5),
            TransportAddr::from_string("198.51.100.9:9000"),
            PacketBuffer::new(fmp_encrypted_wire(81, 1200, 0, b"raw-in", open_key)),
            123_456,
        );
        let raw =
            DataplaneRawIngress::from_received(PacketProtocol::Fmp, path.clone(), received);
        let mut router = FixedIngressRouter {
            route: Some(
                DataplaneIngressRoute::new(owner, 7, OutputTarget::Transport)
                    .with_class(PacketClass::Liveness),
            ),
        };

        let turn = run_aead_raw_ingress_turn(&mut driver, [raw], &mut router, std::iter::empty(), 8);
        assert_eq!(turn.summary().raw_ingress_dropped(), 0);
        assert_eq!(turn.summary().inbound_admitted(), 1);
        assert_eq!(turn.summary().dispatched(), 1);
        assert_eq!(turn.summary().outputs(), 1);
        assert!(turn.raw_ingress_drops().is_empty());
        assert!(turn.drops().is_empty());
        assert_eq!(turn.outputs()[0].target, OutputTarget::Transport);
        assert_eq!(turn.outputs()[0].counter, 1200);
        assert_eq!(
            &turn.outputs()[0].payload.as_slice()[FMP_ESTABLISHED_HEADER_SIZE..],
            b"raw-in"
        );

        let owner_state = driver.owner_mut(owner).unwrap();
        assert_eq!(owner_state.active_path(), Some(path));
        assert_eq!(
            owner_state.last_rx_activity(),
            Some(ActivityTick::new(123_456))
        );
    }

    #[test]
    fn runtime_raw_ingress_turn_drops_wire_and_unrouted_packets_before_admission() {
        let owner = fsp_owner(82);
        let path = live_path(9105);
        let mut driver = DataplaneTurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8));
        let bad_wire = DataplaneRawIngress::from_received(
            PacketProtocol::Fmp,
            path.clone(),
            ReceivedPacket::with_timestamp(
                TransportId::new(5),
                TransportAddr::from_string("198.51.100.9:9000"),
                PacketBuffer::new(vec![0]),
                1,
            ),
        );
        let unrouted = DataplaneRawIngress::from_received(
            PacketProtocol::Fsp,
            path.clone(),
            ReceivedPacket::with_timestamp(
                TransportId::new(5),
                TransportAddr::from_string("198.51.100.9:9000"),
                PacketBuffer::new(fsp_encrypted_wire(44, 0, b"unrouted", 61)),
                2,
            ),
        );
        let mut router = NullIngressRouter;

        let turn = run_aead_raw_ingress_turn(&mut driver,
            [bad_wire, unrouted],
            &mut router,
            std::iter::empty(),
            8,
        );
        assert_eq!(turn.summary().raw_ingress_dropped(), 2);
        assert_eq!(turn.summary().inbound_admitted(), 0);
        assert_eq!(turn.summary().dispatched(), 0);
        assert!(turn.outputs().is_empty());
        assert!(turn.drops().is_empty());
        assert_eq!(turn.raw_ingress_drops().len(), 2);
        assert_eq!(
            turn.raw_ingress_drops()[0].reason(),
            DataplaneRawIngressDropReason::Wire(WirePreflightError::TooShort)
        );
        assert_eq!(
            turn.raw_ingress_drops()[1].reason(),
            DataplaneRawIngressDropReason::Unrouted
        );
        assert_eq!(
            turn.raw_ingress_drops()[1].transport_id(),
            TransportId::new(5)
        );
    }
