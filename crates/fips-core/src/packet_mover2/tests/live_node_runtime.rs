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
        let (_endpoint_priority_tx, mut endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
        let (_endpoint_bulk_tx, mut endpoint_bulk_rx) = tokio::sync::mpsc::channel(1);
        let (tun_outbound_tx, mut tun_outbound_rx) =
            crate::upper::tun::tun_outbound_channel(1);
        let tun_packet = tun_ipv6_packet(fmp_source, 48);
        tun_outbound_tx
            .try_send(tun_packet.clone())
            .expect("enqueue TUN outbound packet");

        let first = live_node
            .pump_turn(
                &mut raw_source,
                8,
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
        assert!(first.endpoint_command_drops().is_empty());
        assert!(first.tun_outbound_drops().is_empty());
        assert!(tun_outbound_rx.try_recv().is_err());
        assert!(tun_rx.try_recv().is_err());
        assert!(endpoint_io.event_rx.try_recv().is_err());

        wait_for_live_worker_completion(&live_node).await;
        let mut turn = live_node
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
        assert_eq!(turn.summary().completions(), 1);
        assert_eq!(turn.summary().outputs(), 1);
        assert_eq!(turn.summary().outputs_sent(), 1);
        assert_eq!(turn.transport_planned(), 1);
        assert_eq!(turn.transport_sent(), 1);
        assert_eq!(turn.transport_dropped(), 0);
        assert!(turn.take_transport_sent_outputs().is_empty());

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
    async fn live_node_completion_executor_turn_retires_ready_completion_without_new_input() {
        let transport_id = TransportId::new(181);
        let remote_addr = TransportAddr::from_string("198.51.100.181:18100");
        let path = TransportPath::live(transport_id, remote_addr.clone());
        let source = NodeAddr::from_bytes([0x81; 16]);
        let owner = OwnerId::fmp_node(source);
        let open_key = 181;
        let mut live_node = PacketMover2LiveNode::new(AdmissionConfig::new(4, 8));
        live_node.register_owner(owner, OwnerConfig::new(1, 8));
        live_node
            .driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(open_key)));
        live_node.routes.register_fmp(
            transport_id,
            181,
            PacketMover2IngressRoute::new(owner, 1, OutputTarget::Tun)
                .with_class(PacketClass::Liveness),
        );

        let received = ReceivedPacket::with_timestamp(
            transport_id,
            remote_addr,
            fmp_encrypted_wire(181, 1200, 0, b"completion-wake", open_key),
            181_000,
        );
        let mut raw_ingress = VecDeque::from([PacketMover2RawIngress::from_received(
            PacketProtocol::Fmp,
            path.clone(),
            received,
        )]);
        let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let (_endpoint_priority_tx, mut endpoint_priority_rx) = tokio::sync::mpsc::channel(1);
        let (_endpoint_bulk_tx, mut endpoint_bulk_rx) = tokio::sync::mpsc::channel(1);
        let (_tun_outbound_tx, mut tun_outbound_rx) = crate::upper::tun::tun_outbound_channel(1);
        let transports: HashMap<TransportId, TransportHandle> = HashMap::new();
        let mut empty_completions: VecDeque<CryptoCompletion> = VecDeque::new();
        let mut executor = DelayedChunkExecutor::default();

        let first = live_node
            .pump_turn_with_completion_executor(
                &mut empty_completions,
                8,
                &mut executor,
                &mut raw_ingress,
                1,
                PacketMover2LiveOutboundFirsts::default(),
                &mut endpoint_priority_rx,
                &mut endpoint_bulk_rx,
                0,
                &mut tun_outbound_rx,
                0,
                &tun_tx,
                &endpoint_io.event_tx,
                missing_endpoint_peer,
                &transports,
                8,
            )
            .await;
        assert_eq!(first.summary().raw_ingress_dropped(), 0);
        assert_eq!(first.summary().inbound_admitted(), 1);
        assert_eq!(first.summary().dispatched(), 1);
        assert_eq!(first.summary().completions(), 0);
        assert_eq!(first.summary().outputs_sent(), 0);
        assert!(first.output_drops().is_empty());
        assert!(first.drops().is_empty());
        assert!(raw_ingress.is_empty());
        assert!(tun_rx.try_recv().is_err());
        assert_eq!(executor.nonempty_chunks, vec![1]);
        assert_eq!(live_node.driver.owner_mut(owner).unwrap().in_flight, 1);

        let mut ready_completions = executor.take_ready();
        let second = live_node
            .pump_outbound_firsts_with_completion_executor(
                &mut ready_completions,
                8,
                &mut executor,
                PacketMover2LiveOutboundFirsts::default(),
                0,
                0,
                &tun_tx,
                &endpoint_io.event_tx,
                missing_endpoint_peer,
                &transports,
                0,
            )
            .await;
        assert_eq!(second.summary().completions(), 1);
        assert_eq!(second.summary().dispatched(), 0);
        assert_eq!(second.summary().outputs_sent(), 1);
        assert_eq!(second.summary().outputs_dropped(), 0);
        assert!(second.output_drops().is_empty());
        assert!(second.drops().is_empty());
        assert!(ready_completions.is_empty());
        assert_eq!(live_node.driver.owner_mut(owner).unwrap().in_flight, 0);
        assert_eq!(live_node.driver.owner_active_path(owner), Some(path));
        assert_eq!(tun_rx.try_recv().unwrap(), b"completion-wake".to_vec());
        assert!(endpoint_io.event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn live_node_outbound_continuation_collects_transport_sent_outputs() {
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
        live_node.register_owner(owner, OwnerConfig::new(1, 8).with_next_send_counter(1760));
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
        );
        let mut first = live_node
            .pump_outbound_firsts(
                PacketMover2LiveOutboundFirsts::default()
                    .with_initial_outbound(Some(outbound))
                    .with_transport_sent_output_collection(true),
                0,
                0,
                &tun_tx,
                &endpoint_io.event_tx,
                missing_endpoint_peer,
                &transports,
                0,
            )
            .await;
        assert_eq!(first.summary().outbound_admitted(), 1);
        assert_eq!(first.summary().dispatched(), 0);
        assert_eq!(first.transport_sent(), 0);
        assert!(first.take_transport_sent_outputs().is_empty());

        let mut second = live_node
            .pump_outbound_firsts(
                PacketMover2LiveOutboundFirsts::default()
                    .with_transport_sent_output_collection(true),
                0,
                0,
                &tun_tx,
                &endpoint_io.event_tx,
                missing_endpoint_peer,
                &transports,
                1,
            )
            .await;
        assert_eq!(second.summary().dispatched(), 1);
        assert_eq!(second.summary().outputs(), 0);
        assert_eq!(second.transport_sent(), 0);
        assert_eq!(second.transport_dropped(), 0);
        assert!(second.take_transport_sent_outputs().is_empty());

        wait_for_live_worker_completion(&live_node).await;
        let mut third = live_node
            .pump_outbound_firsts(
                PacketMover2LiveOutboundFirsts::default()
                    .with_transport_sent_output_collection(true),
                0,
                0,
                &tun_tx,
                &endpoint_io.event_tx,
                missing_endpoint_peer,
                &transports,
                1,
            )
            .await;
        assert_eq!(third.summary().completions(), 1);
        assert_eq!(third.transport_sent(), 1);
        assert_eq!(third.transport_dropped(), 0);
        let mut sent_outputs = third.take_transport_sent_outputs();
        assert_eq!(sent_outputs.len(), 1);
        let sent = sent_outputs.pop().unwrap();
        assert_eq!(sent.owner(), owner);
        assert_eq!(sent.counter(), 1760);
        assert_eq!(open_sealed_output(&sent, key), b"continuation");
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
        assert_eq!(
            open_fmp_wire_payload(&received.data, key),
            b"continuation"
        );

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send udp");
        recv_transport.stop().await.expect("stop recv udp");
    }

    #[test]
    fn tun_tx_output_sends_opened_payload_to_node_tun_channel() {
        let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x48; 16]));
        let output = opened_output(owner, 48, 0, OutputTarget::Tun, b"tun-node");
        let mut endpoint = LiveEndpointRecorder::default();
        let mut transport = LiveTransportRecorder::default();

        let sent = {
            let tun = PacketMover2TunTxOutput::new(&tun_tx);
            let mut sink = PacketMover2LiveOutputSink::new(tun, &mut endpoint, &mut transport);
            sink.send(output)
        };

        assert_eq!(sent, Ok(()));
        assert_eq!(tun_rx.try_recv().unwrap(), b"tun-node".to_vec());
        assert!(endpoint.outputs.is_empty());
        assert!(transport.outputs.is_empty());
    }

    #[test]
    fn tun_tx_output_bounds_bulk_without_blocking_liveness() {
        let (tun_tx, tun_rx) = crate::upper::tun::write_channel_with_bulk_capacity(1);
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x47; 16]));
        let mut endpoint = LiveEndpointRecorder::default();
        let mut transport = LiveTransportRecorder::default();
        let mut sink = PacketMover2LiveOutputSink::new(
            PacketMover2TunTxOutput::new(&tun_tx),
            &mut endpoint,
            &mut transport,
        );

        assert_eq!(
            sink.send(opened_output(owner, 47, 0, OutputTarget::Tun, b"bulk-a")),
            Ok(())
        );
        assert_eq!(
            sink.send(opened_output(owner, 48, 1, OutputTarget::Tun, b"bulk-b")),
            Err(PacketMover2OutputError::Backpressure)
        );

        let mut liveness = opened_output(owner, 49, 2, OutputTarget::Tun, b"live");
        liveness.lane = Lane::Priority;
        assert_eq!(sink.send(liveness), Ok(()));

        assert_eq!(tun_rx.try_recv().unwrap(), b"live".to_vec());
        assert_eq!(tun_rx.try_recv().unwrap(), b"bulk-a".to_vec());
        assert!(tun_rx.try_recv().is_err());
        assert!(endpoint.outputs.is_empty());
        assert!(transport.outputs.is_empty());
    }

    #[test]
    fn live_output_sink_drops_stale_bulk_without_dropping_priority_or_fresh_bulk() {
        let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x46; 16]));
        let mut endpoint = LiveEndpointRecorder::default();
        let mut transport = LiveTransportRecorder::default();
        let mut sink = PacketMover2LiveOutputSink::new(
            PacketMover2TunTxOutput::new(&tun_tx),
            &mut endpoint,
            &mut transport,
        );
        sink.stale_bulk_output_drop_ms = 1;

        let mut stale_bulk = opened_output(owner, 46, 0, OutputTarget::Tun, b"stale-bulk");
        stale_bulk.activity_tick = Some(ActivityTick::new(1));
        assert_eq!(
            sink.send(stale_bulk),
            Err(PacketMover2OutputError::StaleQueuedBulk)
        );

        let mut stale_priority = opened_output(owner, 47, 1, OutputTarget::Tun, b"priority");
        stale_priority.lane = Lane::Priority;
        stale_priority.activity_tick = Some(ActivityTick::new(1));
        assert_eq!(sink.send(stale_priority), Ok(()));

        let fresh_bulk = opened_output(owner, 48, 2, OutputTarget::Tun, b"fresh-bulk");
        assert_eq!(sink.send(fresh_bulk), Ok(()));

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
        assert_eq!(sink.send(stale_transport), Ok(()));

        assert_eq!(tun_rx.try_recv().unwrap(), b"priority".to_vec());
        assert_eq!(tun_rx.try_recv().unwrap(), b"fresh-bulk".to_vec());
        assert!(tun_rx.try_recv().is_err());
        assert!(endpoint.outputs.is_empty());
        assert_eq!(transport.outputs.len(), 1);
        assert_eq!(transport.outputs[0].transport_id, transport_id);
        assert_eq!(transport.outputs[0].remote_addr, remote_addr);
        assert_eq!(transport.outputs[0].payload, b"sealed-wire");
    }

    #[test]
    fn tun_tx_output_reports_unavailable_when_node_tun_channel_is_closed() {
        let (tun_tx, tun_rx) = crate::upper::tun::write_channel();
        drop(tun_rx);
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x49; 16]));
        let output = opened_output(owner, 49, 0, OutputTarget::Tun, b"closed");
        let mut endpoint = LiveEndpointRecorder::default();
        let mut transport = LiveTransportRecorder::default();

        let sent = {
            let tun = PacketMover2TunTxOutput::new(&tun_tx);
            let mut sink = PacketMover2LiveOutputSink::new(tun, &mut endpoint, &mut transport);
            sink.send(output)
        };

        assert_eq!(sent, Err(PacketMover2OutputError::Unavailable));
        assert!(endpoint.outputs.is_empty());
        assert!(transport.outputs.is_empty());
    }

    #[test]
    fn endpoint_event_output_sends_resolved_peer_payload_to_node_endpoint_channel() {
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let source_peer = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let source_addr = *source_peer.node_addr();
        let owner = OwnerId::fsp_node(source_addr);
        let output = opened_output(owner, 50, 7, OutputTarget::Endpoint, b"endpoint-node");
        let resolver = |addr: &NodeAddr| {
            assert_eq!(addr, &source_addr);
            Some(source_peer)
        };
        let mut tun = LiveTunRecorder::default();
        let mut transport = LiveTransportRecorder::default();

        let sent = {
            let endpoint = PacketMover2EndpointEventOutput::new(&endpoint_io.event_tx, resolver);
            let mut sink = PacketMover2LiveOutputSink::new(&mut tun, endpoint, &mut transport);
            sink.send(output)
        };

        assert_eq!(sent, Ok(()));
        match endpoint_io.event_rx.try_recv().expect("endpoint event") {
            NodeEndpointEvent::Data {
                source_peer: delivered_source,
                payload,
                ..
            } => {
                assert_eq!(delivered_source, source_peer);
                assert_eq!(payload, b"endpoint-node");
            }
            event => panic!("expected single endpoint event, got {event:?}"),
        }
        assert!(tun.outputs.is_empty());
        assert!(transport.outputs.is_empty());
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
        let output = opened_output(owner, 53, 0, OutputTarget::Endpoint, b"closed-endpoint");
        let mut tun = LiveTunRecorder::default();
        let mut transport = LiveTransportRecorder::default();

        let sent = {
            let endpoint = PacketMover2EndpointEventOutput::new(&endpoint_tx, |_: &NodeAddr| {
                Some(source_peer)
            });
            let mut sink = PacketMover2LiveOutputSink::new(&mut tun, endpoint, &mut transport);
            sink.send(output)
        };

        assert_eq!(sent, Err(PacketMover2OutputError::Unavailable));
        assert!(tun.outputs.is_empty());
        assert!(transport.outputs.is_empty());
    }

    #[test]
    fn endpoint_event_output_requires_resolved_matching_peer_identity() {
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let mut endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let source_peer = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let source_addr = *source_peer.node_addr();
        let wrong_peer = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let owner = OwnerId::fsp_node(source_addr);
        let missing_output =
            opened_output(owner, 51, 0, OutputTarget::Endpoint, b"missing-identity");
        let mismatched_output =
            opened_output(owner, 52, 1, OutputTarget::Endpoint, b"wrong-identity");
        let mut tun = LiveTunRecorder::default();
        let mut transport = LiveTransportRecorder::default();

        let missing = {
            let endpoint =
                PacketMover2EndpointEventOutput::new(&endpoint_io.event_tx, |_: &NodeAddr| {
                    None::<PeerIdentity>
                });
            let mut sink = PacketMover2LiveOutputSink::new(&mut tun, endpoint, &mut transport);
            sink.send(missing_output)
        };
        assert_eq!(missing, Err(PacketMover2OutputError::NoRoute));

        let mismatched = {
            let endpoint =
                PacketMover2EndpointEventOutput::new(&endpoint_io.event_tx, |_: &NodeAddr| {
                    Some(wrong_peer)
                });
            let mut sink = PacketMover2LiveOutputSink::new(&mut tun, endpoint, &mut transport);
            sink.send(mismatched_output)
        };
        assert_eq!(mismatched, Err(PacketMover2OutputError::NoRoute));
        assert!(endpoint_io.event_rx.try_recv().is_err());
        assert!(tun.outputs.is_empty());
        assert!(transport.outputs.is_empty());
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
        let mut transport = PacketMover2TransportSendPlanOutput::new();

        let sent = {
            let mut sink = PacketMover2LiveOutputSink::new(&mut tun, &mut endpoint, &mut transport);
            sink.send(output)
        };

        assert_eq!(sent, Ok(()));
        assert!(tun.outputs.is_empty());
        assert!(endpoint.outputs.is_empty());
        assert_eq!(transport.plans().len(), 1);
        let plan = &transport.plans()[0];
        assert_eq!(plan.transport_id(), transport_id);
        assert_eq!(plan.remote_addr(), &remote_addr);
        assert_eq!(plan.output().owner(), owner);
        assert_eq!(plan.output().counter(), 540);
        assert_eq!(plan.output().ingress_seq(), 12);
        assert_eq!(plan.output().payload(), b"wire-packet");
        assert_eq!(
            plan.output().path(),
            Some(TransportPath::live(transport_id, remote_addr))
        );
    }

    #[tokio::test]
    async fn transport_plan_dispatch_records_no_route_without_retry() {
        let transport_id = TransportId::new(55);
        let remote_addr = TransportAddr::from_string("198.51.100.55:9000");
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x55; 16]));
        let plan = PacketMover2TransportSendPlan::new(
            transport_id,
            remote_addr.clone(),
            transport_output(
                owner,
                550,
                13,
                transport_id,
                remote_addr.clone(),
                b"missing-transport".to_vec(),
            ),
        );
        let transports = HashMap::<TransportId, TransportHandle>::new();
        let mut drops = Vec::new();

        let sent = send_packet_mover2_transport_plans(&transports, &[plan], &mut drops).await;

        assert_eq!(sent, 0);
        assert_eq!(drops.len(), 1);
        let drop = &drops[0];
        assert_eq!(drop.owner(), owner);
        assert_eq!(drop.counter(), 550);
        assert_eq!(drop.ingress_seq(), 13);
        assert_eq!(drop.target(), OutputTarget::Transport);
        assert_eq!(
            drop.path(),
            Some(TransportPath::live(transport_id, remote_addr))
        );
        assert_eq!(drop.payload_len(), b"missing-transport".len());
        assert_eq!(drop.reason(), PacketMover2OutputError::NoRoute);
    }

    #[tokio::test]
    async fn transport_plan_dispatch_records_unavailable_transport_send_failure() {
        let transport_id = TransportId::new(56);
        let remote_addr = TransportAddr::from_string("127.0.0.1:9");
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x56; 16]));
        let plan = PacketMover2TransportSendPlan::new(
            transport_id,
            remote_addr.clone(),
            transport_output(
                owner,
                560,
                14,
                transport_id,
                remote_addr.clone(),
                b"not-started".to_vec(),
            ),
        );
        let mut transports = HashMap::new();
        transports.insert(transport_id, unstarted_udp_transport(transport_id));
        let mut drops = Vec::new();

        let sent = send_packet_mover2_transport_plans(&transports, &[plan], &mut drops).await;

        assert_eq!(sent, 0);
        assert_eq!(drops.len(), 1);
        let drop = &drops[0];
        assert_eq!(drop.owner(), owner);
        assert_eq!(drop.counter(), 560);
        assert_eq!(drop.ingress_seq(), 14);
        assert_eq!(drop.target(), OutputTarget::Transport);
        assert_eq!(
            drop.path(),
            Some(TransportPath::live(transport_id, remote_addr))
        );
        assert_eq!(drop.payload_len(), b"not-started".len());
        assert_eq!(drop.reason(), PacketMover2OutputError::Unavailable);
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
        let plan = PacketMover2TransportSendPlan::new(
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

        let sent = send_packet_mover2_transport_plans(&transports, &[plan], &mut drops).await;

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

    #[test]
    fn transport_batch_mapper_prioritizes_within_transport_runs() {
        let transport_a = TransportId::new(60);
        let transport_b = TransportId::new(61);
        let remote_addr = TransportAddr::from_string("127.0.0.1:6000");
        let owner = OwnerId::fmp_node(NodeAddr::from_bytes([0x60; 16]));
        let mut bulk_a0 = transport_output(
            owner,
            600,
            10,
            transport_a,
            remote_addr.clone(),
            b"bulk-a0".to_vec(),
        );
        let mut priority_a = transport_output(
            owner,
            601,
            11,
            transport_a,
            remote_addr.clone(),
            b"priority-a".to_vec(),
        );
        let mut bulk_a1 = transport_output(
            owner,
            602,
            12,
            transport_a,
            remote_addr.clone(),
            b"bulk-a1".to_vec(),
        );
        let mut priority_b = transport_output(
            owner,
            603,
            13,
            transport_b,
            remote_addr.clone(),
            b"priority-b".to_vec(),
        );
        let mut bulk_b = transport_output(
            owner,
            604,
            14,
            transport_b,
            remote_addr.clone(),
            b"bulk-b".to_vec(),
        );
        bulk_a0.lane = Lane::Bulk;
        priority_a.lane = Lane::Priority;
        bulk_a1.lane = Lane::Bulk;
        priority_b.lane = Lane::Priority;
        bulk_b.lane = Lane::Bulk;
        let plans = vec![
            PacketMover2TransportSendPlan::new(transport_a, remote_addr.clone(), bulk_a0),
            PacketMover2TransportSendPlan::new(transport_a, remote_addr.clone(), priority_a),
            PacketMover2TransportSendPlan::new(transport_a, remote_addr.clone(), bulk_a1),
            PacketMover2TransportSendPlan::new(transport_b, remote_addr.clone(), priority_b),
            PacketMover2TransportSendPlan::new(transport_b, remote_addr, bulk_b),
        ];
        let mut batch = Vec::new();

        append_transport_batch_plans(&plans, 0, 3, Lane::Priority, &mut batch);
        append_transport_batch_plans(&plans, 0, 3, Lane::Bulk, &mut batch);
        append_transport_batch_plans(&plans, 3, plans.len(), Lane::Priority, &mut batch);
        append_transport_batch_plans(&plans, 3, plans.len(), Lane::Bulk, &mut batch);

        let indexes = batch
            .iter()
            .map(|(index, _, _)| *index)
            .collect::<Vec<_>>();
        assert_eq!(indexes, [1, 0, 2, 3, 4]);
        let payloads = batch
            .iter()
            .map(|(_, _, payload)| *payload)
            .collect::<Vec<_>>();
        assert_eq!(
            payloads,
            [
                b"priority-a".as_slice(),
                b"bulk-a0".as_slice(),
                b"bulk-a1".as_slice(),
                b"priority-b".as_slice(),
                b"bulk-b".as_slice()
            ]
        );
        assert_eq!(
            next_transport_batch_range(&plans, 0),
            Some((0, 3, transport_a))
        );
        assert_eq!(
            next_transport_batch_range(&plans, 3),
            Some((3, plans.len(), transport_b))
        );
        assert_eq!(next_transport_batch_range(&plans, plans.len()), None);
        assert_eq!(
            next_transport_priority_cut_in_batch_range(&plans, 0, 1),
            Some((1, 3, transport_a))
        );
        assert_eq!(
            next_transport_priority_cut_in_batch_range(&plans, 3, 32),
            Some((3, plans.len(), transport_b))
        );
    }

    #[test]
    fn transport_error_mapping_keeps_mtu_and_route_failures_attributable() {
        assert_eq!(
            packet_mover2_output_error_for_transport(&TransportError::MtuExceeded {
                packet_size: 1501,
                mtu: 1500,
            }),
            PacketMover2OutputError::MtuExceeded
        );
        assert_eq!(
            packet_mover2_output_error_for_transport(&TransportError::Io(std::io::Error::from(
                std::io::ErrorKind::NetworkUnreachable,
            ))),
            PacketMover2OutputError::NoRoute
        );
        assert_eq!(
            packet_mover2_output_error_for_transport(&TransportError::SendFailed(
                "some other send failure".to_string(),
            )),
            PacketMover2OutputError::TransportFailed
        );
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
        let mut transport = LiveTransportRecorder::default();

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
        assert!(transport.outputs.is_empty());
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

    #[test]
    fn runtime_raw_ingress_output_turn_batches_ordered_outputs_once() {
        let owner = fmp_owner(85);
        let open_key = 73;
        let seal_key = 74;
        let path = live_path(9005);
        let mut driver = PacketMover2TurnDriver::new(AdmissionConfig::new(4, 8));
        driver.register_owner(owner, OwnerConfig::new(7, 8).with_next_send_counter(500));
        driver
            .owner_mut(owner)
            .unwrap()
            .set_crypto_keys(OwnerCryptoKeys::new(test_key(open_key), test_key(seal_key)));
        let received = ReceivedPacket::with_timestamp(
            TransportId::new(5),
            TransportAddr::from_string("198.51.100.9:9000"),
            fmp_encrypted_wire(85, 1200, 0, b"raw-in", open_key),
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
        let outbound =
            OutboundPacket::fmp(owner, 7, PacketClass::Bulk, 850, 0, b"raw-out".to_vec());
        let mut sink = BatchRecordingOutputSink::default();

        let turn =
            run_aead_raw_ingress_output_turn(&mut driver, [raw], &mut router, [outbound], &mut sink, 8);
        assert_eq!(
            turn.summary(),
            PacketMover2RuntimeSummary {
                raw_ingress_dropped: 0,
                inbound_admitted: 1,
                inbound_dropped: 0,
                outbound_admitted: 1,
                outbound_dropped: 0,
                completions: 0,
                dispatched: 2,
                outputs: 2,
                outputs_sent: 2,
                outputs_dropped: 0,
                drops: 0,
            }
        );
        assert!(turn.outputs().is_empty());
        assert!(turn.output_drops().is_empty());
        assert!(turn.raw_ingress_drops().is_empty());
        assert!(turn.drops().is_empty());

        assert_eq!(sink.batch_calls, 1);
        assert_eq!(sink.outputs.len(), 2);
        assert_eq!(
            sink.outputs
                .iter()
                .map(PacketOutput::owner)
                .collect::<Vec<_>>(),
            vec![owner, owner]
        );
        assert_eq!(
            sink.outputs
                .iter()
                .map(PacketOutput::counter)
                .collect::<Vec<_>>(),
            vec![1200, 500]
        );
        assert_eq!(
            sink.outputs
                .iter()
                .map(PacketOutput::target)
                .collect::<Vec<_>>(),
            vec![OutputTarget::Tun, OutputTarget::Transport]
        );
        assert_eq!(
            sink.outputs
                .iter()
                .map(PacketOutput::path)
                .collect::<Vec<_>>(),
            vec![None, Some(path)]
        );
        assert_eq!(
            sink.outputs
                .iter()
                .map(PacketOutput::ingress_seq)
                .collect::<Vec<_>>(),
            vec![0, 0]
        );
        assert_eq!(
            &sink.outputs[0].payload()[FMP_ESTABLISHED_HEADER_SIZE..],
            b"raw-in"
        );
        assert_eq!(open_sealed_output(&sink.outputs[1], seal_key), b"raw-out");
    }
