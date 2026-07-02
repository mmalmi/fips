    async fn pump_live_node_outbound_firsts<Transports>(
        live_node: &mut PacketMover2LiveNode,
        outbound_firsts: PacketMover2LiveOutboundFirsts,
        tun_tx: &crate::upper::tun::TunTx,
        endpoint_tx: &EndpointEventSender,
        transports: &Transports,
        crypto_limit: usize,
        transport_worker: &mut PacketMover2TransportSendWorkerPool,
    ) -> PacketMover2LiveNodeTurn
    where
        Transports: PacketMover2TransportResolver + ?Sized,
    {
        let mut raw_source = PacketMover2LiveRawIngressSource::new(VecDeque::new());
        let (_endpoint_data_tx, mut endpoint_data_rx) = endpoint_data_batch_channel(1);
        let (_tun_outbound_tx, mut tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
        live_node
            .pump_turn_with_firsts_and_transport_worker(
                None,
                &mut raw_source,
                0,
                outbound_firsts,
                &mut endpoint_data_rx,
                0,
                &mut tun_outbound_rx,
                0,
                tun_tx,
                endpoint_tx,
                transports,
                crypto_limit,
                transport_worker,
            )
            .await
    }

    #[tokio::test]
    async fn live_node_route_table_turn_flushes_planned_transport_output() {
        let send_transport_id = TransportId::new(76);
        let recv_transport_id = TransportId::new(77);
        let fmp_source = NodeAddr::from_bytes([0x4c; 16]);
        let fmp_owner = OwnerId::fmp_node(fmp_source);
        let fmp_key = 76;
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
        let mut live_node = PacketMover2LiveNode::new(AdmissionConfig::new(4, 8));
        let mut transport_worker = PacketMover2TransportSendWorkerPool::new(8);
        live_node.register_owner(
            fmp_owner,
            OwnerConfig::new(1, 8).with_next_send_counter(760),
        );
        live_node.driver.owner_mut(fmp_owner)
            .unwrap()
            .set_active_path(live_path.clone());
        live_node.driver.owner_mut(fmp_owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(fmp_key), test_key(fmp_key)));
        let mut raw_source = PacketMover2LiveRawIngressSource::new(VecDeque::new());
        live_node.routes.register_tun_destination(
            fmp_source,
            PacketMover2TunDestinationRoute::new(PacketMover2TunOutboundRoute::fmp(
                fmp_owner,
                1,
                PacketClass::Bulk,
                761,
                0,
            )),
        );
        let (_endpoint_data_tx, mut endpoint_data_rx) = endpoint_data_batch_channel(1);
        let (tun_outbound_tx, mut tun_outbound_rx) =
            crate::upper::tun::tun_outbound_channel(1);
        let tun_packet = tun_ipv6_packet(fmp_source, 48);
        tun_outbound_tx
            .try_send(tun_packet.clone())
            .expect("enqueue TUN outbound packet");

        let first = live_node
            .pump_turn_with_firsts_and_transport_worker(
                None,
                &mut raw_source,
                8,
                PacketMover2LiveOutboundFirsts::default(),
                &mut endpoint_data_rx,
                0,
                &mut tun_outbound_rx,
                8,
                &tun_tx,
                &endpoint_io.event_tx,
                &transports,
                8,
                &mut transport_worker,
            )
            .await;

        assert_eq!(first.summary().raw_ingress_dropped(), 0);
        assert_eq!(first.summary().inbound_admitted(), 0);
        assert_eq!(first.summary().outbound_admitted(), 1);
        assert_eq!(first.summary().dispatched(), 1);
        assert_eq!(first.summary().outputs(), 0);
        assert_eq!(first.summary().outputs_sent(), 0);
        assert_eq!(first.summary().outputs_dropped(), 0);
        assert_eq!(first.transport_planned(), 0);
        assert_eq!(first.transport_sent(), 0);
        assert_eq!(first.transport_dropped(), 0);
        assert!(first.raw_ingress_drops().is_empty());
        assert!(first.output_drops().is_empty());
        assert!(first.drops().is_empty());
        assert!(raw_source.source.is_empty());
        assert!(first.endpoint_data_drops().is_empty());
        assert!(first.tun_outbound_drops().is_empty());
        assert!(tun_outbound_rx.try_recv().is_err());
        assert!(tun_rx.try_recv().is_err());
        assert!(endpoint_io.event_rx.try_recv().is_err());

        wait_for_live_worker_completion(&live_node).await;
        let mut turn = pump_live_node_outbound_firsts(
            &mut live_node,
            PacketMover2LiveOutboundFirsts::default(),
            &tun_tx,
            &endpoint_io.event_tx,
            &transports,
            8,
            &mut transport_worker,
        )
        .await;
        assert_eq!(turn.summary().completions(), 1);
        assert_eq!(turn.summary().outputs(), 1);
        assert_eq!(turn.summary().outputs_sent(), 1);
        assert_eq!(turn.transport_planned(), 1);
        assert_eq!(turn.transport_sent(), 1);
        assert_eq!(turn.transport_dropped(), 0);
        assert!(turn.take_transport_sent_receipts().is_empty());

        let received =
            tokio::time::timeout(std::time::Duration::from_secs(1), recv_packet_rx.recv())
                .await
                .expect("receive live transport output")
                .expect("packet channel open");
        assert_eq!(received.transport_id, recv_transport_id);
        let header = FmpWireHeader::parse(&received.data).unwrap();
        assert_eq!(header.receiver_idx(), 761);
        assert_eq!(header.counter(), 760);
        assert_eq!(
            open_fmp_wire_payload(&received.data, fmp_key),
            tun_packet
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
    async fn live_completion_turn_without_completion_is_empty() {
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let (tun_tx, _tun_rx) = crate::upper::tun::write_channel();
        let transports = HashMap::<TransportId, TransportHandle>::new();
        let mut live_node = PacketMover2LiveNode::new(AdmissionConfig::new(4, 8));
        let mut transport_worker = PacketMover2TransportSendWorkerPool::new(8);

        let turn = live_node
            .pump_completion_output_turn_with_transport_worker(
                &tun_tx,
                &endpoint_io.event_tx,
                &transports,
                8,
                &mut transport_worker,
            )
            .await;

        assert!(!turn.has_activity());
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
        let (tun_tx, _tun_rx) = crate::upper::tun::write_channel();
        let mut live_node = PacketMover2LiveNode::new(AdmissionConfig::new(4, 8));
        let mut transport_worker = PacketMover2TransportSendWorkerPool::new(8);
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
                b"ready-first".to_vec(),
            ))
            .unwrap();
        let first_feed = pump_live_node_outbound_firsts(
            &mut live_node,
            PacketMover2LiveOutboundFirsts::default(),
            &tun_tx,
            &endpoint_io.event_tx,
            &transports,
            8,
            &mut transport_worker,
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
                b"fed-after-output".to_vec(),
            ))
            .unwrap();
        let completion_turn = live_node
            .pump_completion_output_turn_with_transport_worker(
                &tun_tx,
                &endpoint_io.event_tx,
                &transports,
                8,
                &mut transport_worker,
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
            open_fmp_wire_payload(&first_received.data, key),
            b"ready-first"
        );
        assert!(
            recv_packet_rx.try_recv().is_err(),
            "newly fed work must wait for its own completion turn"
        );

        wait_for_live_worker_completion(&live_node).await;
        let second_turn = live_node
            .pump_completion_output_turn_with_transport_worker(
                &tun_tx,
                &endpoint_io.event_tx,
                &transports,
                8,
                &mut transport_worker,
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
            open_fmp_wire_payload(&second_received.data, key),
            b"fed-after-output"
        );

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send udp");
        recv_transport.stop().await.expect("stop recv udp");
    }

    #[tokio::test]
    async fn live_route_table_turn_flushes_completed_output_before_fresh_admission() {
        let transport_id = TransportId::new(178);
        let receiver_idx = 780;
        let remote_addr = TransportAddr::from_string("198.51.100.178:9000");
        let owner = fmp_owner(178);
        let key = 78;
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));

        driver
            .mover
            .submit_socket_packet(
                fmp_socket_packet(
                    owner,
                    1,
                    OutputTarget::Tun,
                    fmp_encrypted_wire(receiver_idx, 10, 0, b"completed", key),
                )
                .unwrap(),
            )
            .unwrap();
        let mut work = dispatch_available(&mut driver.mover, 8);
        assert_eq!(work.len(), 1);
        let completion = open_aead_completion(work.pop().unwrap(), key);
        let mut completions = VecDeque::from([completion]);

        let raw = PacketMover2LiveIngressPacket::fmp(
            ReceivedPacket::with_timestamp(
                transport_id,
                remote_addr,
                fmp_encrypted_wire(receiver_idx, 11, 0, b"fresh", key),
                crate::time::now_ms(),
            ),
        );
        let mut raw_source = PacketMover2LiveRawIngressSource::new(VecDeque::from([raw]));
        let mut routes = PacketMover2LiveRouteTable::default();
        routes.register_fmp(
            transport_id,
            receiver_idx,
            PacketMover2IngressRoute::new(owner, 1, OutputTarget::Tun),
        );
        let (endpoint_data_tx, mut endpoint_data_rx) = endpoint_data_batch_channel(1);
        let (tun_outbound_tx, mut tun_outbound_rx) =
            crate::upper::tun::tun_outbound_channel(1);
        drop((endpoint_data_tx, tun_outbound_tx));
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let mut endpoint_io = node.attach_endpoint_data_io(1).expect("endpoint io");
        let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
        let mut deferred_endpoint_data_batches = Vec::new();
        let mut deferred_tun_packets = Vec::new();
        let transports = HashMap::<TransportId, TransportHandle>::new();

        let turn = pump_aead_live_node_route_table_turn_with_completions(
            &mut driver,
            &mut completions,
            8,
            &mut raw_source,
            &mut routes,
            1,
            &mut endpoint_data_rx,
            0,
            &mut tun_outbound_rx,
            0,
            &mut deferred_endpoint_data_batches,
            &mut deferred_tun_packets,
            &tun_tx,
            &endpoint_io.event_tx,
            &transports,
            8,
        )
        .await;

        assert_eq!(turn.summary().completions(), 1);
        assert_eq!(turn.summary().inbound_admitted(), 1);
        assert_eq!(turn.summary().dispatched(), 1);
        assert_eq!(turn.summary().outputs_sent(), 2);
        assert!(turn.raw_ingress_drops().is_empty());
        assert!(turn.output_drops().is_empty());
        assert!(turn.drops().is_empty());
        assert!(raw_source.source.is_empty());
        assert!(deferred_endpoint_data_batches.is_empty());
        assert!(deferred_tun_packets.is_empty());
        assert!(endpoint_io.event_rx.try_recv().is_err());
        assert_eq!(tun_rx.try_recv().unwrap(), b"completed".to_vec());
        assert_eq!(tun_rx.try_recv().unwrap(), b"fresh".to_vec());
        assert!(tun_rx.try_recv().is_err());
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
        let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let mut live_node = PacketMover2LiveNode::new(AdmissionConfig::new(4, 8));
        let mut transport_worker = PacketMover2TransportSendWorkerPool::new(8);
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
            b"continuation".to_vec(),
        )
        .with_activity_tick(ActivityTick::new(1_234));
        let mut first = pump_live_node_outbound_firsts(
            &mut live_node,
            PacketMover2LiveOutboundFirsts {
                initial_outbound: Some(outbound),
                collect_transport_sent_receipts: true,
                ..Default::default()
            },
            &tun_tx,
            &endpoint_io.event_tx,
            &transports,
            0,
            &mut transport_worker,
        )
        .await;
        assert_eq!(first.summary().outbound_admitted(), 1);
        assert_eq!(first.summary().dispatched(), 0);
        assert_eq!(first.transport_sent(), 0);
        assert!(first.take_transport_sent_receipts().is_empty());

        let mut second = pump_live_node_outbound_firsts(
            &mut live_node,
            PacketMover2LiveOutboundFirsts {
                collect_transport_sent_receipts: true,
                ..Default::default()
            },
            &tun_tx,
            &endpoint_io.event_tx,
            &transports,
            1,
            &mut transport_worker,
        )
        .await;
        assert_eq!(second.summary().dispatched(), 1);
        assert_eq!(second.summary().outputs(), 0);
        assert_eq!(second.transport_sent(), 0);
        assert_eq!(second.transport_dropped(), 0);
        assert!(second.take_transport_sent_receipts().is_empty());

        wait_for_live_worker_completion(&live_node).await;
        let mut third = pump_live_node_outbound_firsts(
            &mut live_node,
            PacketMover2LiveOutboundFirsts {
                collect_transport_sent_receipts: true,
                ..Default::default()
            },
            &tun_tx,
            &endpoint_io.event_tx,
            &transports,
            1,
            &mut transport_worker,
        )
        .await;
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
        assert!(tun_rx.try_recv().is_err());
        assert!(endpoint_io.event_rx.try_recv().is_err());

        let received =
            tokio::time::timeout(std::time::Duration::from_secs(1), recv_packet_rx.recv())
                .await
                .expect("receive continuation transport output")
                .expect("packet channel open");
        assert_eq!(received.transport_id, recv_transport_id);
        let header = FmpWireHeader::parse(&received.data).unwrap();
        assert_eq!(header.receiver_idx(), 1761);
        assert_eq!(header.counter(), 1760);
        let mut expected_payload = 234u32.to_le_bytes().to_vec();
        expected_payload.extend_from_slice(b"continuation");
        assert_eq!(open_fmp_wire_payload(&received.data, key), expected_payload);

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send udp");
        recv_transport.stop().await.expect("stop recv udp");
    }

    #[test]
    fn tun_tx_output_bounds_bulk_without_blocking_liveness() {
        let (tun_tx, tun_rx) = crate::upper::tun::write_channel_with_bulk_capacity(1);
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x47; 16]));
        let mut endpoint = LiveEndpointRecorder::default();
        let mut transport = PacketMover2TransportSendGroups::new();
        let mut sink = PacketMover2LiveOutputSink::new(
            PacketMover2TunTxOutput::new(&tun_tx),
            &mut endpoint,
            &mut transport,
        );

        assert_eq!(
            send_one_output(
                &mut sink,
                opened_output(owner, 47, 0, OutputTarget::Tun, b"bulk-a")
            ),
            Ok(())
        );
        assert_eq!(
            send_one_output(
                &mut sink,
                opened_output(owner, 48, 1, OutputTarget::Tun, b"bulk-b")
            ),
            Err(PacketMover2OutputError::Backpressure)
        );

        let mut liveness = opened_output(owner, 49, 2, OutputTarget::Tun, b"live");
        liveness.lane = Lane::Priority;
        assert_eq!(send_one_output(&mut sink, liveness), Ok(()));

        assert_eq!(tun_rx.try_recv().unwrap(), b"live".to_vec());
        assert_eq!(tun_rx.try_recv().unwrap(), b"bulk-a".to_vec());
        assert!(tun_rx.try_recv().is_err());
        assert!(endpoint.outputs.is_empty());
        assert!(transport.groups.is_empty());
    }

    #[test]
    fn live_output_sink_drops_stale_bulk_without_dropping_priority_or_fresh_bulk() {
        let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x46; 16]));
        let mut endpoint = LiveEndpointRecorder::default();
        let mut transport = PacketMover2TransportSendGroups::new();
        let mut sink = PacketMover2LiveOutputSink::new(
            PacketMover2TunTxOutput::new(&tun_tx),
            &mut endpoint,
            &mut transport,
        );
        sink.stale_bulk_output_drop_ms = 1;

        let mut stale_bulk = opened_output(owner, 46, 0, OutputTarget::Tun, b"stale-bulk");
        stale_bulk.activity_tick = Some(ActivityTick::new(1));
        assert_eq!(
            send_one_output(&mut sink, stale_bulk),
            Err(PacketMover2OutputError::StaleQueuedBulk)
        );

        let mut stale_priority = opened_output(owner, 47, 1, OutputTarget::Tun, b"priority");
        stale_priority.lane = Lane::Priority;
        stale_priority.activity_tick = Some(ActivityTick::new(1));
        assert_eq!(send_one_output(&mut sink, stale_priority), Ok(()));

        let fresh_bulk = opened_output(owner, 48, 2, OutputTarget::Tun, b"fresh-bulk");
        assert_eq!(send_one_output(&mut sink, fresh_bulk), Ok(()));

        let transport_id = TransportId::new(46);
        let remote_addr = TransportAddr::from_string("198.51.100.46:9000");
        let mut stale_transport = transport_output(
            owner,
            49,
            3,
            transport_id,
            remote_addr.clone(),
            b"sealed-wire".to_vec(),
        );
        stale_transport.activity_tick = Some(ActivityTick::new(1));
        assert_eq!(send_one_output(&mut sink, stale_transport), Ok(()));

        assert_eq!(tun_rx.try_recv().unwrap(), b"priority".to_vec());
        assert_eq!(tun_rx.try_recv().unwrap(), b"fresh-bulk".to_vec());
        assert!(tun_rx.try_recv().is_err());
        assert!(endpoint.outputs.is_empty());
        assert_eq!(transport.groups.len(), 1);
        let group = &transport.groups[0];
        assert_eq!(group.transport_id, transport_id);
        assert_eq!(group.remote_addr, remote_addr);
        assert_eq!(group.outputs.len(), 1);
        assert_eq!(group.outputs[0].payload(), b"sealed-wire");
    }

    #[test]
    fn endpoint_event_output_reports_unavailable_when_endpoint_channel_is_closed() {
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let endpoint_tx = endpoint_io.event_tx.clone();
        drop(endpoint_io);
        let source_peer = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let source_addr = *source_peer.node_addr();
        let owner = OwnerId::fsp_node(source_addr);
        let output = opened_endpoint_output(owner, source_peer, 53, 0, b"closed-endpoint");
        let mut tun = LiveTunRecorder::default();
        let mut transport = PacketMover2TransportSendGroups::new();

        let sent = {
            let endpoint = PacketMover2EndpointEventOutput::new(&endpoint_tx);
            let mut sink = PacketMover2LiveOutputSink::new(&mut tun, endpoint, &mut transport);
            send_one_output(&mut sink, output)
        };

        assert_eq!(sent, Err(PacketMover2OutputError::Unavailable));
        assert!(tun.outputs.is_empty());
        assert!(transport.groups.is_empty());
    }

    #[test]
    fn endpoint_event_output_requires_owner_matching_peer_identity() {
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let source_peer = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let source_addr = *source_peer.node_addr();
        let wrong_peer = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let owner = OwnerId::fsp_node(source_addr);
        let missing_output =
            opened_output(owner, 51, 0, OutputTarget::Endpoint, b"missing-identity");
        let mismatched_output = opened_endpoint_output(owner, wrong_peer, 52, 1, b"wrong-identity");
        let mut tun = LiveTunRecorder::default();
        let mut transport = PacketMover2TransportSendGroups::new();

        let missing = {
            let endpoint = PacketMover2EndpointEventOutput::new(&endpoint_io.event_tx);
            let mut sink = PacketMover2LiveOutputSink::new(&mut tun, endpoint, &mut transport);
            send_one_output(&mut sink, missing_output)
        };
        assert_eq!(missing, Err(PacketMover2OutputError::NoRoute));

        let mismatched = {
            let endpoint = PacketMover2EndpointEventOutput::new(&endpoint_io.event_tx);
            let mut sink = PacketMover2LiveOutputSink::new(&mut tun, endpoint, &mut transport);
            send_one_output(&mut sink, mismatched_output)
        };
        assert_eq!(mismatched, Err(PacketMover2OutputError::NoRoute));
        assert!(endpoint_io.event_rx.try_recv().is_err());
        assert!(tun.outputs.is_empty());
        assert!(transport.groups.is_empty());
    }

    #[test]
    fn endpoint_event_output_keeps_generic_batches_on_event_queue_with_direct_sink() {
        let direct_batches = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_batches = Arc::clone(&direct_batches);
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let direct_sink = crate::node::EndpointDirectSink::new(
            move |batch: crate::FipsEndpointDirectPacketBatch| {
                captured_batches
                    .lock()
                    .expect("direct batches lock")
                    .push(batch.len());
                Ok::<(), crate::FipsEndpointDirectDeliveryError>(())
            },
        );
        let mut endpoint_io = node
            .attach_endpoint_data_io_with_direct_sink(8, direct_sink)
            .expect("endpoint io");
        let source_peer = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let source_addr = *source_peer.node_addr();
        let owner = OwnerId::fsp_node(source_addr);
        let first = opened_endpoint_output(owner, source_peer, 53, 0, b"direct-one");
        let second = opened_endpoint_output(owner, source_peer, 54, 1, b"direct-two");
        let mut tun = LiveTunRecorder::default();
        let mut transport = PacketMover2TransportSendGroups::new();
        let mut drops = Vec::new();

        let sent = {
            let endpoint = PacketMover2EndpointEventOutput::new(&endpoint_io.event_tx);
            let mut sink = PacketMover2LiveOutputSink::new(&mut tun, endpoint, &mut transport);
            sink.send_batch([first, second], &mut drops)
        };

        assert_eq!(sent, 2);
        assert!(drops.is_empty());
        assert_eq!(endpoint_io.event_tx.queued_messages(), 2);
        assert!(tun.outputs.is_empty());
        assert!(transport.groups.is_empty());

        let direct_batches = direct_batches.lock().expect("direct batches lock");
        assert!(
            direct_batches.is_empty(),
            "generic endpoint output must not use direct packet-batch sink"
        );
        drop(direct_batches);
        let event = endpoint_io.event_rx.try_recv().expect("endpoint event");
        endpoint_io.event_rx.release_messages(event.messages.len());
        assert_eq!(event.messages.len(), 2);
        assert_eq!(event.messages[0].source_peer, source_peer);
        assert_eq!(event.messages[0].payload.as_slice(), b"direct-one");
        assert_eq!(event.messages[1].source_peer, source_peer);
        assert_eq!(event.messages[1].payload.as_slice(), b"direct-two");
        assert_eq!(endpoint_io.event_tx.queued_messages(), 0);
    }

    #[test]
    fn endpoint_event_output_ignores_direct_sink_failures_for_generic_events() {
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let direct_sink = crate::node::EndpointDirectSink::new(
            |_batch: crate::FipsEndpointDirectPacketBatch| {
                Err(crate::FipsEndpointDirectDeliveryError::Unavailable)
            },
        );
        let mut endpoint_io = node
            .attach_endpoint_data_io_with_direct_sink(8, direct_sink)
            .expect("endpoint io");
        let source_peer = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let source_addr = *source_peer.node_addr();
        let owner = OwnerId::fsp_node(source_addr);
        let output = opened_endpoint_output(owner, source_peer, 55, 0, b"direct-fail");
        let mut tun = LiveTunRecorder::default();
        let mut transport = PacketMover2TransportSendGroups::new();

        let sent = {
            let endpoint = PacketMover2EndpointEventOutput::new(&endpoint_io.event_tx);
            let mut sink = PacketMover2LiveOutputSink::new(&mut tun, endpoint, &mut transport);
            send_one_output(&mut sink, output)
        };

        assert_eq!(sent, Ok(()));
        assert_eq!(endpoint_io.event_tx.queued_messages(), 1);
        let event = endpoint_io.event_rx.try_recv().expect("endpoint event");
        endpoint_io.event_rx.release_messages(event.messages.len());
        assert_eq!(event.messages.len(), 1);
        assert_eq!(event.messages[0].source_peer, source_peer);
        assert_eq!(event.messages[0].payload.as_slice(), b"direct-fail");
        assert!(tun.outputs.is_empty());
        assert!(transport.groups.is_empty());
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
        let mut tun = LiveTunRecorder::default();
        let mut endpoint = LiveEndpointRecorder::default();
        let mut transport = PacketMover2TransportSendGroups::new();

        let sent = {
            let mut sink = PacketMover2LiveOutputSink::new(&mut tun, &mut endpoint, &mut transport);
            send_one_output(&mut sink, output)
        };

        assert_eq!(sent, Ok(()));
        assert!(tun.outputs.is_empty());
        assert!(endpoint.outputs.is_empty());
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
            output.path(),
            Some(TransportPath::live(transport_id, remote_addr))
        );
    }

    #[tokio::test]
    async fn transport_plan_dispatch_records_send_failures_without_retry() {
        for (id, remote, counter, ingress_seq, payload, has_transport, expected) in [
            (
                55,
                "198.51.100.55:9000",
                550,
                13,
                b"missing-transport".as_slice(),
                false,
                PacketMover2OutputError::NoRoute,
            ),
            (
                56,
                "127.0.0.1:9",
                560,
                14,
                b"not-started".as_slice(),
                true,
                PacketMover2OutputError::Unavailable,
            ),
        ] {
            let transport_id = TransportId::new(id);
            let remote_addr = TransportAddr::from_string(remote);
            let owner = OwnerId::fmp_node(NodeAddr::from_bytes([id as u8; 16]));
            let plan = PacketMover2TransportPlanGroup::new(
                transport_id,
                remote_addr.clone(),
                transport_output(
                    owner,
                    counter,
                    ingress_seq,
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
            let mut worker = PacketMover2TransportSendWorkerPool::new(8);

            let sent = send_packet_mover2_transport_groups_with_worker(
                &transports,
                vec![plan],
                &mut drops,
                &mut worker,
                None,
            )
            .await;

            assert_eq!(sent, 0);
            assert_eq!(drops.len(), 1);
            let drop = &drops[0];
            assert_eq!(drop.owner(), owner);
            assert_eq!(drop.counter(), counter);
            assert_eq!(drop.ingress_seq(), ingress_seq);
            assert_eq!(drop.target(), OutputTarget::Transport);
            assert_eq!(
                drop.path(),
                Some(TransportPath::live(transport_id, remote_addr))
            );
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
        let plan = PacketMover2TransportPlanGroup::new(
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
        let mut worker = PacketMover2TransportSendWorkerPool::new(8);

        let sent = send_packet_mover2_transport_groups_with_worker(
            &transports,
            vec![plan],
            &mut drops,
            &mut worker,
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
        assert_eq!(received.data, b"live-transport");

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send udp");
        recv_transport.stop().await.expect("stop recv udp");
    }

    #[tokio::test]
    async fn transport_plan_worker_preserves_retired_order_across_lanes() {
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
            PacketMover2TransportPlanGroup::new(send_transport_id, remote_addr.clone(), bulk_a),
            PacketMover2TransportPlanGroup::new(send_transport_id, remote_addr.clone(), priority),
            PacketMover2TransportPlanGroup::new(send_transport_id, remote_addr, bulk_b),
        ];
        let mut transports = HashMap::from([(send_transport_id, send_transport)]);
        let mut drops = Vec::new();
        let mut worker = PacketMover2TransportSendWorkerPool::new(8);

        let sent = send_packet_mover2_transport_groups_with_worker(
            &transports,
                    groups,
            &mut drops,
            &mut worker,
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
    async fn transport_plan_worker_segments_direct_fsp_record_after_enqueue() {
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
        let groups = vec![PacketMover2TransportPlanGroup::new(
            send_transport_id,
            remote_addr,
            output,
        )];
        let mut transports = HashMap::from([(send_transport_id, send_transport)]);
        let mut drops = Vec::new();
        let mut worker = PacketMover2TransportSendWorkerPool::new(1);
        let mut sent_receipts = Vec::new();

        let sent = send_packet_mover2_transport_groups_with_worker(
            &transports,
            groups,
            &mut drops,
            &mut worker,
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
            reassembled
                .extend_from_slice(&received.data[DIRECT_FSP_TRANSPORT_FRAGMENT_HEADER_LEN..]);
        }
        assert_eq!(reassembled, wire);

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send udp");
        recv_transport.stop().await.expect("stop recv udp");
    }

    #[tokio::test]
    async fn transport_plan_worker_spools_ordered_bulk_past_soft_capacity() {
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
            PacketMover2TransportPlanGroup::new(
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
            PacketMover2TransportPlanGroup::new(
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
        let mut worker = PacketMover2TransportSendWorkerPool::new(1);

        let sent = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            send_packet_mover2_transport_groups_with_worker(
                &transports,
                groups,
                &mut drops,
                &mut worker,
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
    fn transport_send_worker_live_bulk_jobs_use_coalesce_cadence() {
        let worker = PacketMover2TransportSendWorkerPool::default_live();

        assert_eq!(
            worker.max_job_records_for_lane(Lane::Bulk),
            TRANSPORT_SEND_WORKER_COALESCE_PACKETS
        );
        assert_eq!(
            worker.max_job_records_for_lane(Lane::Priority),
            TRANSPORT_SEND_WORKER_PRIORITY_RESERVE_PACKETS
        );

        let small_worker = PacketMover2TransportSendWorkerPool::new(8);
        assert_eq!(small_worker.max_job_records_for_lane(Lane::Bulk), 8);
        assert_eq!(small_worker.max_job_records_for_lane(Lane::Priority), 8);
    }

    #[test]
    fn live_output_sink_drops_transport_without_live_path() {
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x47; 16]));
        let key = 47;
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(470));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(key), test_key(key)));
        let outbound =
            OutboundPacket::fmp(owner, 1, PacketClass::Bulk, 471, 0, b"no-route".to_vec());
        let mut tun = LiveTunRecorder::default();
        let mut endpoint = LiveEndpointRecorder::default();
        let mut transport = PacketMover2TransportSendGroups::new();

        let turn = {
            let mut sink = PacketMover2LiveOutputSink::new(&mut tun, &mut endpoint, &mut transport);
            run_aead_classified_output_turn(&mut driver, std::iter::empty(), [outbound], &mut sink, 8)
        };

        assert_eq!(turn.summary().outputs(), 1);
        assert_eq!(turn.summary().outputs_sent(), 0);
        assert_eq!(turn.summary().outputs_dropped(), 1);
        assert!(turn.outputs().is_empty());
        assert_eq!(turn.output_drops().len(), 1);
        assert_eq!(
            turn.output_drops()[0].reason(),
            PacketMover2OutputError::NoRoute
        );
        assert_eq!(turn.output_drops()[0].path(), None);
        assert!(tun.outputs.is_empty());
        assert!(endpoint.outputs.is_empty());
        assert!(transport.groups.is_empty());
    }

    #[test]
    fn runtime_raw_ingress_turn_parses_received_packet_before_owner_admission() {
        let owner = fmp_owner(81);
        let open_key = 51;
        let path = live_path(9005);
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(7, 8));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(open_key)));
        let received = ReceivedPacket::with_timestamp(
            TransportId::new(5),
            TransportAddr::from_string("198.51.100.9:9000"),
            fmp_encrypted_wire(81, 1200, 0, b"raw-in", open_key),
            123_456,
        );
        let raw =
            PacketMover2RawIngress::from_received(PacketProtocol::Fmp, path.clone(), received);
        let mut router = FixedIngressRouter {
            route: Some(
                PacketMover2IngressRoute::new(owner, 7, OutputTarget::Tun)
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
        assert_eq!(turn.outputs()[0].target, OutputTarget::Tun);
        assert_eq!(turn.outputs()[0].counter, 1200);
        assert_eq!(
            &turn.outputs()[0].payload[FMP_ESTABLISHED_HEADER_SIZE..],
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
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(1, 8));
        let bad_wire = PacketMover2RawIngress::from_received(
            PacketProtocol::Fmp,
            path.clone(),
            ReceivedPacket::with_timestamp(
                TransportId::new(5),
                TransportAddr::from_string("198.51.100.9:9000"),
                vec![0],
                1,
            ),
        );
        let unrouted = PacketMover2RawIngress::from_received(
            PacketProtocol::Fsp,
            path.clone(),
            ReceivedPacket::with_timestamp(
                TransportId::new(5),
                TransportAddr::from_string("198.51.100.9:9000"),
                fsp_encrypted_wire(44, 0, b"unrouted", 61),
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
            PacketMover2RawIngressDropReason::Wire(WirePreflightError::TooShort)
        );
        assert_eq!(
            turn.raw_ingress_drops()[1].reason(),
            PacketMover2RawIngressDropReason::Unrouted
        );
        assert_eq!(
            turn.raw_ingress_drops()[1].transport_id(),
            TransportId::new(5)
        );
        assert_eq!(turn.raw_ingress_drops()[1].path(), path);
    }
