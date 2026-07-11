    async fn pump_live_node_outbound_firsts(
        live_node: &mut DataplaneLiveNode,
        outbound_firsts: DataplaneLiveOutboundFirsts,
        endpoint_tx: &EndpointEventSender,
        transports: &HashMap<TransportId, TransportHandle>,
        crypto_limit: usize,
        transport_send_batch_packets: usize,
    ) -> DataplaneLiveNodeTurn
    {
        let mut raw_source = VecDeque::<DataplaneRawIngress>::new();
        let (_endpoint_data_tx, mut endpoint_data_rx) = endpoint_data_batch_channel(1);
        let (_tun_outbound_tx, mut tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
        live_node
            .pump_turn_with_firsts_and_transport_batch(
                None,
                &mut raw_source,
                0,
                outbound_firsts,
                DataplaneLiveTurnIo {
                    endpoint_data_rx: &mut endpoint_data_rx,
                    endpoint_limit: 0,
                    tun_outbound_rx: &mut tun_outbound_rx,
                    tun_limit: 0,
                    endpoint_tx,
                    transports,
                    crypto_limit,
                    transport_send_batch_packets,
                },
            )
            .await
    }

    #[tokio::test]
    async fn live_node_route_table_turn_flushes_planned_transport_output() {
        let send_transport_id = TransportId::new(76);
        let recv_transport_id = TransportId::new(77);
        let fsp_dest = NodeAddr::from_bytes([0x4c; 16]);
        let fsp_owner = OwnerId::fsp_node(fsp_dest);
        let fsp_key = 76;
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
        let (_tun_tx, tun_rx) = crate::upper::tun::write_channel();
        let mut live_node = DataplaneLiveNode::new(AdmissionConfig::new(4, 8));
        let transport_send_batch_packets = 8;
        live_node.register_owner(
            fsp_owner,
            OwnerConfig::new(1, 8)
                .with_next_send_counter(760)
                .with_fsp_session_start_ms(0)
                .with_fsp_send_headers(0, 0),
        );
        live_node.driver.owner_mut(fsp_owner)
            .unwrap()
            .set_active_path(live_path.clone());
        live_node.driver.owner_mut(fsp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fsp_key), test_key(fsp_key)));
        let mut raw_source = VecDeque::<DataplaneRawIngress>::new();
        live_node.routes.register_tun_destination(
            fsp_dest,
            DataplaneTunOutboundRoute::fsp_ipv6_shim(
                fsp_owner,
                1,
                PacketClass::Bulk,
                0,
                0,
            ),
        );
        let (_endpoint_data_tx, mut endpoint_data_rx) = endpoint_data_batch_channel(1);
        let (tun_outbound_tx, mut tun_outbound_rx) =
            crate::upper::tun::tun_outbound_channel(1);
        let tun_packet = tun_ipv6_packet(fsp_dest, 48);
        let mut expected_payload = tun_packet.clone();
        assert!(crate::upper::ipv6_shim::compress_ipv6_with_port_header_in_place(
            &mut expected_payload,
            crate::node::session_wire::FSP_PORT_IPV6_SHIM,
            crate::node::session_wire::FSP_PORT_IPV6_SHIM,
        ));
        tun_outbound_tx
            .try_send(tun_packet.clone())
            .expect("enqueue TUN outbound packet");

        let first = live_node
            .pump_turn_with_firsts_and_transport_batch(
                None,
                &mut raw_source,
                8,
                DataplaneLiveOutboundFirsts::default(),
                DataplaneLiveTurnIo {
                    endpoint_data_rx: &mut endpoint_data_rx,
                    endpoint_limit: 0,
                    tun_outbound_rx: &mut tun_outbound_rx,
                    tun_limit: 8,
                    endpoint_tx: &endpoint_io.event_tx,
                    transports: &transports,
                    crypto_limit: 8,
                    transport_send_batch_packets,
                },
            )
            .await;

        assert_eq!(first.summary().raw_ingress_dropped(), 0);
        assert_eq!(first.summary().inbound_admitted(), 0);
        assert_eq!(first.summary().outbound_admitted(), 1);
        assert_eq!(first.summary().dispatched(), 1);
        assert_eq!(first.summary().outputs(), 0);
        assert_eq!(first.summary().outputs_sent(), 0);
        assert_eq!(first.summary().outputs_dropped(), 0);
        assert_eq!(first.transport_sent(), 0);
        assert_eq!(first.transport_dropped(), 0);
        assert!(first.raw_ingress_drops().is_empty());
        assert!(first.output_drops().is_empty());
        assert!(first.drops().is_empty());
        assert!(raw_source.is_empty());
        assert!(first.endpoint_data_drops().is_empty());
        assert!(first.tun_outbound_drops().is_empty());
        assert!(tun_outbound_rx.try_recv().is_err());
        assert!(tun_rx.try_recv_packet().is_err());
        assert!(endpoint_io.event_rx.try_recv().is_err());

        wait_for_live_worker_completion(&live_node).await;
        let mut turn = pump_live_node_outbound_firsts(
            &mut live_node,
            DataplaneLiveOutboundFirsts::default(),
            &endpoint_io.event_tx,
            &transports,
            8,
            transport_send_batch_packets,
        )
        .await;
        assert_eq!(turn.summary().completions(), 1);
        assert_eq!(turn.summary().outputs(), 1);
        assert_eq!(turn.summary().outputs_sent(), 1);
        assert_eq!(turn.transport_sent(), 1);
        assert_eq!(turn.transport_dropped(), 0);
        assert!(turn.take_transport_sent_receipts().is_empty());

        let received =
            tokio::time::timeout(std::time::Duration::from_secs(1), recv_packet_rx.recv())
                .await
                .expect("receive live transport output")
                .expect("packet channel open");
        assert_eq!(received.transport_id, recv_transport_id);
        let header = FspWireHeader::parse(received.data.as_slice()).unwrap();
        assert_eq!(header.counter(), 760);
        let plaintext = open_fsp_wire_payload(received.data.as_slice(), fsp_key);
        let (_timestamp_ms, msg_type, inner_flags, payload) =
            crate::node::session_wire::fsp_strip_inner_header(&plaintext).unwrap();
        assert_eq!(
            msg_type,
            crate::protocol::SessionMessageType::DataPacket.to_byte()
        );
        assert_eq!(inner_flags, 0);
        assert_eq!(payload, expected_payload.as_slice());
        assert_eq!(
            live_node.driver.owner_mut(fsp_owner).unwrap().active_path(),
            Some(live_path)
        );

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send udp");
        recv_transport.stop().await.expect("stop recv udp");
    }

    #[tokio::test]
    async fn live_completion_turn_without_completion_is_empty() {
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let (_endpoint_data_tx, mut endpoint_data_rx) = endpoint_data_batch_channel(1);
        let (_tun_outbound_tx, mut tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
        let transports = HashMap::<TransportId, TransportHandle>::new();
        let mut live_node = DataplaneLiveNode::new(AdmissionConfig::new(4, 8));
        let transport_send_batch_packets = 8;

        let turn = live_node
            .pump_completion_output_turn_with_transport_batch(
                false,
                DataplaneLiveTurnIo {
                    endpoint_data_rx: &mut endpoint_data_rx,
                    endpoint_limit: 0,
                    tun_outbound_rx: &mut tun_outbound_rx,
                    tun_limit: 0,
                    endpoint_tx: &endpoint_io.event_tx,
                    transports: &transports,
                    crypto_limit: 8,
                    transport_send_batch_packets,
                },
            )
            .await;

        assert!(!turn.has_activity());
    }

    #[test]
    fn deferred_raw_ingress_waits_for_route_progress_before_retrying() {
        let source = NodeAddr::from_bytes([0x75; 16]);
        let raw = DataplaneRawIngress::from_live_received(
            PacketProtocol::Fsp,
            ReceivedPacket::with_timestamp(
                TransportId::new(175),
                TransportAddr::from_string("198.51.100.175:9000"),
                PacketBuffer::new(fsp_wire(
                    175,
                    crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
                )),
                175_000,
            ),
        )
        .with_fsp_source(source);
        let mut live_node = DataplaneLiveNode::new(AdmissionConfig::new(4, 8));
        live_node.deferred_raw_ingress.push_back((raw, 1));

        assert!(live_node.has_deferred_raw_ingress());
        assert!(!live_node.has_runnable_work());
    }

    #[tokio::test]
    async fn live_completion_turn_sends_ready_output_and_dispatches_next_work() {
        let send_transport_id = TransportId::new(176);
        let recv_transport_id = TransportId::new(177);
        let owner = fmp_owner(176);
        let key = 176;
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
        let path = TransportPath::live(send_transport_id, remote_addr);
        let mut transports = HashMap::from([(send_transport_id, send_transport)]);
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let (_endpoint_data_tx, mut endpoint_data_rx) = endpoint_data_batch_channel(1);
        let (_tun_outbound_tx, mut tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
        let mut live_node = DataplaneLiveNode::new(AdmissionConfig::new(4, 8));
        let transport_send_batch_packets = 8;
        live_node.register_owner(
            owner,
            OwnerConfig::new(1, 8).with_next_send_counter(900),
        );
        live_node
            .driver
            .owner_mut(owner)
            .unwrap()
            .set_active_path(path);
        live_node
            .driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));

        live_node
            .driver
            .mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Bulk,
                901,
                0,
                PacketBuffer::new(b"ready-first".to_vec()),
            ))
            .unwrap();
        let first_feed = pump_live_node_outbound_firsts(
            &mut live_node,
            DataplaneLiveOutboundFirsts::default(),
            &endpoint_io.event_tx,
            &transports,
            8,
            transport_send_batch_packets,
        )
        .await;
        assert_eq!(first_feed.summary().completions(), 0);
        assert_eq!(first_feed.summary().dispatched(), 1);
        assert_eq!(first_feed.summary().outputs_sent(), 0);

        wait_for_live_worker_completion(&live_node).await;
        live_node
            .driver
            .mover
            .submit_outbound_packet(OutboundPacket::fmp(
                owner,
                1,
                PacketClass::Bulk,
                901,
                0,
                PacketBuffer::new(b"fed-after-output".to_vec()),
            ))
            .unwrap();
        let completion_turn = live_node
            .pump_completion_output_turn_with_transport_batch(
                false,
                DataplaneLiveTurnIo {
                    endpoint_data_rx: &mut endpoint_data_rx,
                    endpoint_limit: 0,
                    tun_outbound_rx: &mut tun_outbound_rx,
                    tun_limit: 0,
                    endpoint_tx: &endpoint_io.event_tx,
                    transports: &transports,
                    crypto_limit: 8,
                    transport_send_batch_packets,
                },
            )
            .await;
        assert_eq!(completion_turn.summary().completions(), 1);
        assert_eq!(completion_turn.summary().outputs_sent(), 1);
        assert_eq!(completion_turn.summary().dispatched(), 1);
        assert_eq!(completion_turn.transport_sent(), 1);

        let first_received =
            tokio::time::timeout(std::time::Duration::from_secs(1), recv_packet_rx.recv())
                .await
                .expect("receive first output")
                .expect("packet channel open");
        assert_eq!(
            open_fmp_wire_payload(first_received.data.as_slice(), key),
            b"ready-first"
        );
        assert!(
            recv_packet_rx.try_recv().is_err(),
            "newly fed work must wait for its own completion turn"
        );

        wait_for_live_worker_completion(&live_node).await;
        let second_turn = live_node
            .pump_completion_output_turn_with_transport_batch(
                false,
                DataplaneLiveTurnIo {
                    endpoint_data_rx: &mut endpoint_data_rx,
                    endpoint_limit: 0,
                    tun_outbound_rx: &mut tun_outbound_rx,
                    tun_limit: 0,
                    endpoint_tx: &endpoint_io.event_tx,
                    transports: &transports,
                    crypto_limit: 8,
                    transport_send_batch_packets,
                },
            )
            .await;
        assert_eq!(second_turn.summary().completions(), 1);
        assert_eq!(second_turn.summary().outputs_sent(), 1);
        assert_eq!(second_turn.summary().dispatched(), 0);
        assert_eq!(second_turn.transport_sent(), 1);
        let second_received =
            tokio::time::timeout(std::time::Duration::from_secs(1), recv_packet_rx.recv())
                .await
                .expect("receive second output")
                .expect("packet channel open");
        assert_eq!(
            open_fmp_wire_payload(second_received.data.as_slice(), key),
            b"fed-after-output"
        );

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send udp");
        recv_transport.stop().await.expect("stop recv udp");
    }

    #[tokio::test]
    async fn live_node_outbound_continuation_collects_transport_sent_receipts() {
        let send_transport_id = TransportId::new(176);
        let recv_transport_id = TransportId::new(177);
        let peer = NodeAddr::from_bytes([0x76; 16]);
        let owner = OwnerId::fmp_node(peer);
        let key = 176;
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
        let (_tun_tx, tun_rx) = crate::upper::tun::write_channel();
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let mut live_node = DataplaneLiveNode::new(AdmissionConfig::new(4, 8));
        let transport_send_batch_packets = 8;
        live_node.register_owner(
            owner,
            OwnerConfig::new(1, 8)
                .with_next_send_counter(1760)
                .with_fmp_session_start_ms(1_000),
        );
        live_node.driver.owner_mut(owner)
            .unwrap()
            .set_active_path(live_path);
        live_node.driver.owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));

        let outbound = OutboundPacket::fmp(
            owner,
            1,
            PacketClass::Liveness,
            1761,
            0,
            PacketBuffer::new(b"continuation".to_vec()),
        )
        .with_activity_tick(ActivityTick::new(1_234));
        let mut first = pump_live_node_outbound_firsts(
            &mut live_node,
            DataplaneLiveOutboundFirsts {
                initial_outbound: Some(outbound),
                collect_transport_sent_receipts: true,
                ..Default::default()
            },
            &endpoint_io.event_tx,
            &transports,
            0,
            transport_send_batch_packets,
        )
        .await;
        assert_eq!(first.summary().outbound_admitted(), 1);
        assert_eq!(first.summary().dispatched(), 0);
        assert_eq!(first.transport_sent(), 0);
        assert!(first.take_transport_sent_receipts().is_empty());

        let mut second = pump_live_node_outbound_firsts(
            &mut live_node,
            DataplaneLiveOutboundFirsts {
                collect_transport_sent_receipts: true,
                ..Default::default()
            },
            &endpoint_io.event_tx,
            &transports,
            1,
            transport_send_batch_packets,
        )
        .await;
        assert_eq!(second.summary().dispatched(), 1);
        assert_eq!(second.summary().outputs(), 0);
        assert_eq!(second.transport_sent(), 0);
        assert_eq!(second.transport_dropped(), 0);
        assert!(second.take_transport_sent_receipts().is_empty());

        let mut third = None;
        for _ in 0..50 {
            let turn = pump_live_node_outbound_firsts(
                &mut live_node,
                DataplaneLiveOutboundFirsts {
                    collect_transport_sent_receipts: true,
                    ..Default::default()
                },
                &endpoint_io.event_tx,
                &transports,
                1,
                transport_send_batch_packets,
            )
            .await;
            if turn.transport_sent() > 0 {
                third = Some(turn);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        let mut third = third.expect("completion turn should send continuation output");
        assert_eq!(third.summary().completions(), 1);
        assert_eq!(third.transport_sent(), 1);
        assert_eq!(third.transport_dropped(), 0);
        let mut sent_receipts = third.take_transport_sent_receipts();
        assert_eq!(sent_receipts.len(), 1);
        let sent = sent_receipts.pop().unwrap();
        assert_eq!(sent.owner, owner);
        assert_eq!(sent.counter, 1760);
        assert_eq!(sent.fmp_timestamp_ms, Some(234));
        assert!(sent.payload_len > b"continuation".len());
        assert!(tun_rx.try_recv_packet().is_err());
        assert!(endpoint_io.event_rx.try_recv().is_err());

        let received =
            tokio::time::timeout(std::time::Duration::from_secs(1), recv_packet_rx.recv())
                .await
                .expect("receive continuation transport output")
                .expect("packet channel open");
        assert_eq!(received.transport_id, recv_transport_id);
        let header = FmpWireHeader::parse(received.data.as_slice()).unwrap();
        assert_eq!(header.receiver_idx(), 1761);
        assert_eq!(header.counter(), 1760);
        let mut expected_payload = 234u32.to_le_bytes().to_vec();
        expected_payload.extend_from_slice(b"continuation");
        assert_eq!(open_fmp_wire_payload(received.data.as_slice(), key), expected_payload);

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send udp");
        recv_transport.stop().await.expect("stop recv udp");
    }

    #[test]
    fn transport_plan_output_takes_owned_wire_payload_from_live_sink() {
        let transport_id = TransportId::new(54);
        let remote_addr = TransportAddr::from_string("198.51.100.54:9000");
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x54; 16]));
        let output = transport_output(
            owner,
            540,
            12,
            transport_id,
            remote_addr.clone(),
            b"wire-packet".to_vec(),
        );
        let mut transport = DataplaneTransportSendGroups::new();

        let mut drops = Vec::new();
        let sent = {
            let mut sink = DataplaneLiveOutputSink::new(&mut transport);
            sink.send_batch(std::iter::once(output), &mut drops)
        };

        assert_eq!(sent, 1);
        assert!(drops.is_empty());
        assert_eq!(transport.groups.len(), 1);
        let group = &transport.groups[0];
        assert_eq!(group.transport_id, transport_id);
        assert_eq!(group.remote_addr, remote_addr);
        assert_eq!(group.outputs.len(), 1);
        let output = &group.outputs[0];
        assert_eq!(output.owner(), owner);
        assert_eq!(output.counter(), 540);
        assert_eq!(output.ingress_seq, 12);
        assert_eq!(output.payload(), b"wire-packet");
        assert_eq!(
            output.path.clone(),
            Some(TransportPath::live(transport_id, remote_addr))
        );
    }

    #[tokio::test]
    async fn transport_plan_dispatch_records_send_failures_without_retry() {
        for (id, remote, counter, payload, has_transport, expected) in [
            (
                55,
                "198.51.100.55:9000",
                550,
                b"missing-transport".as_slice(),
                false,
                DataplaneOutputError::NoRoute,
            ),
            (
                56,
                "127.0.0.1:9",
                560,
                b"not-started".as_slice(),
                true,
                DataplaneOutputError::Unavailable,
            ),
        ] {
            let transport_id = TransportId::new(id);
            let remote_addr = TransportAddr::from_string(remote);
            let owner = OwnerId::fmp_node(NodeAddr::from_bytes([id as u8; 16]));
            let plan = DataplaneTransportPlanGroup::new(
                transport_id,
                remote_addr.clone(),
                transport_output(
                    owner,
                    counter,
                    0,
                    transport_id,
                    remote_addr.clone(),
                    payload.to_vec(),
                ),
            );
            let mut transports = HashMap::new();
            if has_transport {
                transports.insert(transport_id, unstarted_udp_transport(transport_id));
            }
            let mut drops = Vec::new();
            let max_batch_packets = 8;

            let sent = send_dataplane_transport_groups(
                &transports,
                vec![plan],
                &mut drops,
                max_batch_packets,
                None,
            )
            .await;

            assert_eq!(sent, 0);
            assert_eq!(drops.len(), 1);
            let drop = &drops[0];
            assert_eq!(drop.payload_len(), payload.len());
            assert_eq!(drop.reason(), expected);
        }
    }

    #[tokio::test]
    async fn transport_plan_dispatch_sends_with_resolved_live_transport() {
        let send_transport_id = TransportId::new(57);
        let recv_transport_id = TransportId::new(58);
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
        let send_local_addr = TransportAddr::from_string(
            &send_transport
                .local_addr()
                .expect("send udp local addr")
                .to_string(),
        );
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x57; 16]));
        let plan = DataplaneTransportPlanGroup::new(
            send_transport_id,
            remote_addr.clone(),
            transport_output(
                owner,
                570,
                15,
                send_transport_id,
                remote_addr,
                b"live-transport".to_vec(),
            ),
        );
        let mut transports = HashMap::from([(send_transport_id, send_transport)]);
        let mut drops = Vec::new();
        let max_batch_packets = 8;

        let sent = send_dataplane_transport_groups(
            &transports,
            vec![plan],
            &mut drops,
            max_batch_packets,
            None,
        )
        .await;

        assert_eq!(sent, 1);
        assert!(drops.is_empty());
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(1), recv_packet_rx.recv())
                .await
                .expect("receive forwarded packet")
                .expect("packet channel open");
        assert_eq!(received.transport_id, recv_transport_id);
        assert_eq!(received.remote_addr, send_local_addr);
        assert_eq!(received.data.as_slice(), &b"live-transport"[..]);

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send udp");
        recv_transport.stop().await.expect("stop recv udp");
    }

    #[tokio::test]
    async fn transport_plan_dispatch_preserves_retired_order_across_lanes() {
        let send_transport_id = TransportId::new(62);
        let recv_transport_id = TransportId::new(63);
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
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x62; 16]));
        let mut priority = transport_output(
            owner,
            620,
            20,
            send_transport_id,
            remote_addr.clone(),
            b"priority-worker".to_vec(),
        );
        priority.lane = Lane::Priority;
        let mut bulk_a = transport_output(
            owner,
            621,
            21,
            send_transport_id,
            remote_addr.clone(),
            b"bulk-worker-a".to_vec(),
        );
        bulk_a.lane = Lane::Bulk;
        let mut bulk_b = transport_output(
            owner,
            622,
            22,
            send_transport_id,
            remote_addr.clone(),
            b"bulk-worker-b".to_vec(),
        );
        bulk_b.lane = Lane::Bulk;
        let groups = vec![
            DataplaneTransportPlanGroup::new(send_transport_id, remote_addr.clone(), bulk_a),
            DataplaneTransportPlanGroup::new(send_transport_id, remote_addr.clone(), priority),
            DataplaneTransportPlanGroup::new(send_transport_id, remote_addr, bulk_b),
        ];
        let mut transports = HashMap::from([(send_transport_id, send_transport)]);
        let mut drops = Vec::new();
        let max_batch_packets = 8;

        let sent = send_dataplane_transport_groups(
            &transports,
                    groups,
            &mut drops,
            max_batch_packets,
            None,
        )
        .await;

        assert_eq!(sent, 3);
        assert!(drops.is_empty());
        let mut payloads = Vec::new();
        for _ in 0..3 {
            let received =
                tokio::time::timeout(std::time::Duration::from_secs(1), recv_packet_rx.recv())
                    .await
                    .expect("receive worker packet")
                    .expect("packet channel open");
            payloads.push(received.data.as_slice().to_vec());
        }
        assert_eq!(
            payloads,
            [
                b"bulk-worker-a".to_vec(),
                b"priority-worker".to_vec(),
                b"bulk-worker-b".to_vec()
            ]
        );

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send udp");
        recv_transport.stop().await.expect("stop recv udp");
    }

    #[tokio::test]
    async fn transport_plan_dispatch_segments_direct_fsp_record_after_enqueue() {
        let send_transport_id = TransportId::new(66);
        let recv_transport_id = TransportId::new(67);
        let (recv_packet_tx, mut recv_packet_rx) = crate::transport::packet_channel(16);
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
        let owner = fsp_owner(66);
        let mut wire = fsp_wire(
            660,
            crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
        );
        wire.extend((0..700).map(|idx| (idx % 251) as u8));
        let path_mtu = 220usize;
        let mut output =
            transport_output(owner, 660, 60, send_transport_id, remote_addr.clone(), wire.clone());
        output.path_mtu = path_mtu as u16;
        let expected_fragments =
            wire.len().div_ceil(path_mtu - DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN);
        assert!(expected_fragments > 1);
        let groups = vec![DataplaneTransportPlanGroup::new(
            send_transport_id,
            remote_addr,
            output,
        )];
        let mut transports = HashMap::from([(send_transport_id, send_transport)]);
        let mut drops = Vec::new();
        let max_batch_packets = 1;
        let mut sent_receipts = Vec::new();

        let sent = send_dataplane_transport_groups(
            &transports,
            groups,
            &mut drops,
            max_batch_packets,
            Some(&mut sent_receipts),
        )
        .await;

        assert_eq!(sent, 1);
        assert!(drops.is_empty());
        assert_eq!(sent_receipts.len(), 1);
        assert_eq!(sent_receipts[0].owner, owner);
        assert_eq!(sent_receipts[0].counter, 660);
        assert_eq!(sent_receipts[0].payload_len, wire.len());

        let mut reassembled = Vec::with_capacity(wire.len());
        for expected_index in 0..expected_fragments {
            let received =
                tokio::time::timeout(std::time::Duration::from_secs(1), recv_packet_rx.recv())
                    .await
                    .expect("receive direct-FSP transport fragment")
                    .expect("packet channel open");
            assert_eq!(received.transport_id, recv_transport_id);
            assert!(received.data.len() <= path_mtu);
            let header = parse_direct_fsp_transport_fragment_header(received.data.as_slice())
                .expect("DFP1 fragment header");
            assert_eq!(header.total_len, wire.len());
            assert_eq!(header.fragment_index, expected_index);
            assert_eq!(header.fragment_count, expected_fragments);
            reassembled.extend_from_slice(
                &received.data.as_slice()[DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN..],
            );
        }
        assert_eq!(reassembled, wire);

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send udp");
        recv_transport.stop().await.expect("stop recv udp");
    }

    #[cfg(feature = "sim-transport")]
    #[tokio::test]
    async fn transport_plan_dispatch_segments_direct_fsp_record_over_non_udp_transport() {
        let network_name = "dataplane-direct-fsp-non-udp-segmentation";
        crate::register_sim_network(network_name, crate::SimNetwork::new(680));
        let send_transport_id = TransportId::new(68);
        let recv_transport_id = TransportId::new(69);
        let path_mtu = 220usize;
        let config = |addr: &str| crate::SimTransportConfig {
            network: Some(network_name.to_string()),
            addr: Some(addr.to_string()),
            mtu: Some(path_mtu as u16),
            ..Default::default()
        };
        let (recv_packet_tx, mut recv_packet_rx) = crate::transport::packet_channel(16);
        let mut recv_transport = TransportHandle::Sim(crate::SimTransport::new(
            recv_transport_id,
            None,
            config("receiver"),
            recv_packet_tx,
        ));
        recv_transport.start().await.expect("start recv sim");
        let (send_packet_tx, _send_packet_rx) = crate::transport::packet_channel(1);
        let mut send_transport = TransportHandle::Sim(crate::SimTransport::new(
            send_transport_id,
            None,
            config("sender"),
            send_packet_tx,
        ));
        send_transport.start().await.expect("start send sim");

        let owner = fsp_owner(68);
        let mut wire = fsp_wire(
            680,
            crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
        );
        wire.extend((0..700).map(|idx| (idx % 251) as u8));
        let mut output = transport_output(
            owner,
            680,
            80,
            send_transport_id,
            TransportAddr::from_string("receiver"),
            wire.clone(),
        );
        output.path_mtu = path_mtu as u16;
        let expected_fragments =
            wire.len().div_ceil(path_mtu - DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN);
        let groups = vec![DataplaneTransportPlanGroup::new(
            send_transport_id,
            TransportAddr::from_string("receiver"),
            output,
        )];
        let mut transports = HashMap::from([(send_transport_id, send_transport)]);
        let mut drops = Vec::new();
        let mut sent_receipts = Vec::new();

        let sent = send_dataplane_transport_groups(
            &transports,
            groups,
            &mut drops,
            1,
            Some(&mut sent_receipts),
        )
        .await;

        assert_eq!(sent, 1);
        assert!(drops.is_empty());
        assert_eq!(sent_receipts.len(), 1);
        assert_eq!(sent_receipts[0].owner, owner);
        assert_eq!(sent_receipts[0].counter, 680);
        assert_eq!(sent_receipts[0].payload_len, wire.len());

        let mut reassembled = Vec::with_capacity(wire.len());
        for expected_index in 0..expected_fragments {
            let received =
                tokio::time::timeout(std::time::Duration::from_secs(1), recv_packet_rx.recv())
                    .await
                    .expect("receive direct-FSP sim fragment")
                    .expect("packet channel open");
            assert_eq!(received.transport_id, recv_transport_id);
            assert!(received.data.len() <= path_mtu);
            let header = parse_direct_fsp_transport_fragment_header(received.data.as_slice())
                .expect("DFP1 fragment header");
            assert_eq!(header.total_len, wire.len());
            assert_eq!(header.fragment_index, expected_index);
            assert_eq!(header.fragment_count, expected_fragments);
            reassembled.extend_from_slice(
                &received.data.as_slice()[DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN..],
            );
        }
        assert_eq!(reassembled, wire);

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send sim");
        recv_transport.stop().await.expect("stop recv sim");
        crate::unregister_sim_network(network_name);
    }
