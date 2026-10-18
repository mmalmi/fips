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
                    endpoint_data_rx: Some(&mut endpoint_data_rx),
                    endpoint_limit: 0,
                    tun_outbound_rx: Some(&mut tun_outbound_rx),
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
        assert_eq!(first.summary().outputs_dropped(), 0);
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

        let mut turn = if first.transport_sent() > 0 {
            first
        } else {
            assert_eq!(first.summary().outputs(), 0);
            assert_eq!(first.summary().outputs_sent(), 0);
            wait_for_live_worker_completion(&live_node).await;
            pump_live_node_outbound_firsts(
                &mut live_node,
                DataplaneLiveOutboundFirsts::default(),
                &endpoint_io.event_tx,
                &transports,
                8,
                transport_send_batch_packets,
            )
            .await
        };
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

        // A real send warms the transport-group buffer. Subsequent empty
        // completion turns should retain that allocation without sending work.
        let group_capacity = live_node.driver.transport_output.groups.capacity();
        let group_allocation = live_node.driver.transport_output.groups.as_ptr();
        assert!(group_capacity > 0);
        for _ in 0..16 {
            let mut empty = live_node
                .pump_completion_output_turn_with_transport_batch(
                    true,
                    DataplaneLiveTurnIo {
                        endpoint_data_rx: None,
                        endpoint_limit: 0,
                        tun_outbound_rx: None,
                        tun_limit: 0,
                        endpoint_tx: &endpoint_io.event_tx,
                        transports: &transports,
                        crypto_limit: 8,
                        transport_send_batch_packets,
                    },
                )
                .await;
            assert!(!empty.has_activity());
            assert_eq!(empty.transport_sent(), 0);
            assert_eq!(empty.transport_dropped(), 0);
            assert!(empty.output_drops().is_empty());
            assert!(empty.drops().is_empty());
            assert!(empty.take_transport_sent_receipts().is_empty());
            assert!(live_node.driver.transport_output.groups.is_empty());
            assert_eq!(
                live_node.driver.transport_output.groups.capacity(),
                group_capacity
            );
            assert_eq!(
                live_node.driver.transport_output.groups.as_ptr(),
                group_allocation,
                "an empty completion turn must not replace the warmed group allocation"
            );
        }
        assert!(recv_packet_rx.try_recv().is_err());

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
                    endpoint_data_rx: Some(&mut endpoint_data_rx),
                    endpoint_limit: 0,
                    tun_outbound_rx: Some(&mut tun_outbound_rx),
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
        live_node
            .deferred_raw_ingress
            .push_back((raw.into(), crate::time::now_ms()));

        assert!(live_node.has_deferred_raw_ingress());
        assert!(!live_node.has_runnable_work());
    }

    #[tokio::test]
    async fn deferred_first_session_ingress_survives_unrelated_completion_turns() {
        let source = NodeAddr::from_bytes([0x76; 16]);
        let raw = DataplaneRawIngress::from_live_received(
            PacketProtocol::Fsp,
            ReceivedPacket::with_timestamp(
                TransportId::new(176),
                TransportAddr::from_string("198.51.100.176:9000"),
                PacketBuffer::new(fsp_wire(
                    176,
                    crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
                )),
                176_000,
            ),
        )
        .with_fsp_source(source);
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let (_endpoint_data_tx, mut endpoint_data_rx) = endpoint_data_batch_channel(1);
        let (_tun_outbound_tx, mut tun_outbound_rx) =
            crate::upper::tun::tun_outbound_channel(1);
        let transports = HashMap::<TransportId, TransportHandle>::new();
        let mut live_node = DataplaneLiveNode::new(AdmissionConfig::new(4, 8));
        live_node
            .deferred_raw_ingress
            .push_back((raw.into(), crate::time::now_ms()));

        for _ in 0..16 {
            let _turn = live_node
                .pump_completion_output_turn_with_transport_batch(
                    false,
                    DataplaneLiveTurnIo {
                        endpoint_data_rx: Some(&mut endpoint_data_rx),
                        endpoint_limit: 0,
                        tun_outbound_rx: Some(&mut tun_outbound_rx),
                        tun_limit: 0,
                        endpoint_tx: &endpoint_io.event_tx,
                        transports: &transports,
                        crypto_limit: 8,
                        transport_send_batch_packets: 8,
                    },
                )
                .await;
        }

        assert!(
            live_node.has_deferred_raw_ingress(),
            "first session data must remain queued until its handshake installs an owner",
        );
        assert!(!live_node.has_runnable_work());
        assert!(futures::FutureExt::now_or_never(live_node.readiness_notify().notified()).is_none());
    }

    #[tokio::test]
    async fn pending_outbound_turn_retains_deferred_handshake_proof() {
        let source_peer = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let source = *source_peer.node_addr();
        let owner = OwnerId::fmp_node(source);
        let transport_id = TransportId::new(179);
        let mut node = crate::Node::new(crate::Config::new()).unwrap();
        let endpoint_io = node.attach_endpoint_data_io(8).unwrap();
        let transports = HashMap::<TransportId, TransportHandle>::new();
        let mut live_node = DataplaneLiveNode::new(AdmissionConfig::new(4, 8));
        register_keyed_owner(
            &mut live_node.driver,
            owner,
            OwnerConfig::new(1, 8).with_source_peer(source_peer),
            179,
        );
        register_fmp_session_ingress_route(
            &mut live_node.routes,
            transport_id,
            179,
            owner,
            *node.node_addr(),
        );
        let mut proof_payload = 179_000u32.to_le_bytes().to_vec();
        proof_payload.push(crate::protocol::LinkMessageType::Heartbeat.to_byte());
        live_node.defer_fmp_handshake_proof(ReceivedPacket::with_timestamp(
            transport_id,
            TransportAddr::from_string("198.51.100.179:9000"),
            PacketBuffer::new(fmp_encrypted_wire(179, 0, 0, &proof_payload, 179)),
            179_000,
        ));
        let mut empty_raw = VecDeque::<DataplaneRawIngress>::new();
        // Bootstrap sends can suspend or fail before the outer receive loop
        // handles their turn. A turn with no raw budget must leave the retained
        // handshake proof available to that loop, even if its caller drops it.
        let turn = live_node
            .pump_turn_with_firsts_and_transport_batch(
                None,
                &mut empty_raw,
                0,
                DataplaneLiveOutboundFirsts::default(),
                DataplaneLiveTurnIo {
                    endpoint_data_rx: None,
                    endpoint_limit: 0,
                    tun_outbound_rx: None,
                    tun_limit: 0,
                    endpoint_tx: &endpoint_io.event_tx,
                    transports: &transports,
                    crypto_limit: 8,
                    transport_send_batch_packets: 8,
                },
            )
            .await;
        assert_eq!(turn.summary().inbound_admitted(), 0);
        drop(turn);
        assert_eq!(live_node.deferred_raw_ingress.len(), 1);
        assert!(live_node.has_runnable_work());
        assert!(
            !live_node.has_runnable_output_work(),
            "a retained proof cannot advance a send with no raw-ingress budget"
        );
        let turn = live_node
            .pump_completion_output_turn_with_transport_batch(
                false,
                DataplaneLiveTurnIo {
                    endpoint_data_rx: None,
                    endpoint_limit: 0,
                    tun_outbound_rx: None,
                    tun_limit: 0,
                    endpoint_tx: &endpoint_io.event_tx,
                    transports: &transports,
                    crypto_limit: 8,
                    transport_send_batch_packets: 8,
                },
            )
            .await;
        assert_eq!(turn.summary().inbound_admitted(), 1);
        assert!(turn.raw_ingress_drops().is_empty());
        assert!(live_node.deferred_raw_ingress.is_empty());
    }

    #[tokio::test]
    async fn deferred_session_packet_precedes_fresh_packet_after_route_install() {
        deferred_session_packet_precedes_new_ingress(false, None, 1, false, None).await;
    }

    #[tokio::test]
    async fn deferred_session_packet_precedes_ready_link_completion_after_route_install() {
        deferred_session_packet_precedes_new_ingress(true, None, 1, false, None).await;
    }

    #[tokio::test]
    async fn retained_handshake_proof_does_not_hide_older_session_from_completion() {
        deferred_session_packet_precedes_new_ingress(true, Some(0), 1, false, None).await;
    }

    #[tokio::test]
    async fn admitted_handshake_proof_does_not_hide_older_session_from_completion() {
        deferred_session_packet_precedes_new_ingress(true, Some(1), 1, false, None).await;
    }

    #[tokio::test]
    async fn session_backlog_exceeding_allowance_precedes_ready_link_completion() {
        deferred_session_packet_precedes_new_ingress(true, Some(1), 2, false, None).await;
    }

    #[tokio::test]
    async fn session_backlog_exceeding_allowance_precedes_fresh_raw_ingress() {
        deferred_session_packet_precedes_new_ingress(false, None, 2, false, None).await;
    }

    #[tokio::test]
    async fn session_backlog_exceeding_allowance_precedes_fast_ingress() {
        deferred_session_packet_precedes_new_ingress(false, None, 2, true, None).await;
    }

    #[tokio::test]
    async fn packet_rx_first_survives_deferred_ingress_budget() {
        deferred_session_packet_precedes_new_ingress(false, None, 1, false, Some(false)).await;
    }

    #[tokio::test]
    async fn packet_rx_prefetch_survives_deferred_ingress_budget() {
        deferred_session_packet_precedes_new_ingress(false, None, 1, false, Some(true)).await;
    }

    async fn deferred_session_packet_precedes_new_ingress(
        ready_link: bool,
        proof_raw_budget: Option<usize>,
        older_count: usize,
        fast_packet: bool,
        packet_rx_prefetch: Option<bool>,
    ) {
        let retained_proof = proof_raw_budget.is_some();
        let source_peer = PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full());
        let source = *source_peer.node_addr();
        let local = NodeAddr::from_bytes([0x78; 16]);
        let owner = OwnerId::fsp_node(source);
        let key = 178;
        let raw = |counter: u64| {
            let inner = crate::node::session_wire::fsp_prepend_inner_header(
                178_000,
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                0,
                &[counter as u8],
            );
            DataplaneRawIngress::from_live_received(
                PacketProtocol::Fsp,
                ReceivedPacket::with_timestamp(
                    TransportId::new(178),
                    TransportAddr::from_string("198.51.100.178:9000"),
                    PacketBuffer::new(fsp_encrypted_wire(
                        counter,
                        if fast_packet || packet_rx_prefetch.is_some() { crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT } else { 0 },
                        &inner, key,
                    )),
                    178_000,
                ),
            )
            .with_fsp_source(source)
            .with_previous_hop(source)
        };
        let mut node = crate::Node::new(crate::Config::new()).unwrap();
        let endpoint_io = node.attach_endpoint_data_io(8).unwrap();
        let transports = HashMap::<TransportId, TransportHandle>::new();
        let mut live_node = DataplaneLiveNode::new(AdmissionConfig::new(4, 8));
        let mut raw_source = (0..older_count as u64).map(raw).collect::<VecDeque<_>>();
        let blocked_source = NodeAddr::from_bytes([0x79; 16]);
        let unrelated_backlog = usize::from(older_count > 1);
        if unrelated_backlog > 0 {
            raw_source.push_front(raw(255).with_fsp_source(blocked_source));
        }
        let mut fast_ingress = None;
        let mut first_packet = None;
        let (_packet_tx, mut packet_rx) = crate::transport::packet_channel(1);
        let first = live_node
            .pump_turn_with_firsts_and_transport_batch(
                None,
                &mut raw_source,
                8,
                DataplaneLiveOutboundFirsts::default(),
                DataplaneLiveTurnIo {
                    endpoint_data_rx: None,
                    endpoint_limit: 0,
                    tun_outbound_rx: None,
                    tun_limit: 0,
                    endpoint_tx: &endpoint_io.event_tx,
                    transports: &transports,
                    crypto_limit: 8,
                    transport_send_batch_packets: 8,
                },
            )
            .await;
        assert!(raw_source.is_empty());
        assert_eq!(first.summary().inbound_admitted(), 0);
        assert_eq!(live_node.deferred_raw_ingress.len(), older_count + unrelated_backlog);
        if older_count > 1 {
            // Exercise a partial retry before the route exists. The original
            // records must keep their relative order across that waiting turn.
            live_node.pump_turn_with_firsts_and_transport_batch(
                None, &mut raw_source, 1, DataplaneLiveOutboundFirsts::default(),
                DataplaneLiveTurnIo {
                    endpoint_data_rx: None, endpoint_limit: 0,
                    tun_outbound_rx: None, tun_limit: 0,
                    endpoint_tx: &endpoint_io.event_tx, transports: &transports,
                    crypto_limit: 1, transport_send_batch_packets: 8,
                },
            ).await;
            assert_eq!(live_node.deferred_raw_ingress.len(), older_count + unrelated_backlog);
        }

        // The handshake installs keys while the first encrypted record is
        // waiting. A newly arrived record must not overtake that original.
        register_keyed_owner(
            &mut live_node.driver,
            owner,
            OwnerConfig::new(1, 8).with_source_peer(source_peer),
            key,
        );
        register_fsp_session_payload_route(&mut live_node.routes, source, owner, local);
        if ready_link {
            // Stage an actual authenticated link completion, as when msg3 and
            // the first data record arrive in adjacent native crypto turns.
            // The regular live pump must admit the waiting FSP record before
            // unwrapping this newer record into the same session owner.
            let link_owner = OwnerId::fmp_node(source);
            register_keyed_owner(
                &mut live_node.driver,
                link_owner,
                OwnerConfig::new(1, 8).with_source_peer(source_peer),
                key,
            );
            if retained_proof {
                let mut proof_payload = 178_000u32.to_le_bytes().to_vec();
                proof_payload.push(crate::protocol::LinkMessageType::Heartbeat.to_byte());
                register_fmp_session_ingress_route(
                    &mut live_node.routes, TransportId::new(178), 178, link_owner, local,
                );
                live_node.deferred_raw_ingress.push_front((
                    DataplaneRawIngress::from_live_received(
                        PacketProtocol::Fmp,
                        ReceivedPacket::with_timestamp(
                            TransportId::new(178),
                            TransportAddr::from_string("198.51.100.178:9000"),
                            PacketBuffer::new(fmp_encrypted_wire(
                                178, 0, 0, &proof_payload, key,
                            )),
                            178_000,
                        ),
                    ).into(),
                    crate::time::now_ms(),
                ));
            }
            let datagram = crate::protocol::SessionDatagram::new(
                source,
                local,
                raw(older_count as u64).payload.as_slice().to_vec(),
            );
            let mut plaintext = 178_000u32.to_le_bytes().to_vec();
            plaintext.extend_from_slice(&datagram.encode());
            let packet = fmp_socket_packet(
                link_owner,
                1,
                OutputTarget::SessionIngress { local_addr: local },
                fmp_encrypted_wire(178, 1, 0, &plaintext, key),
            )
            .unwrap()
            .with_source_path(TransportPath::live(
                TransportId::new(178),
                TransportAddr::from_string("198.51.100.178:9000"),
            ));
            let driver = &mut live_node.driver;
            driver.mover.submit_socket_packet(packet).unwrap();
            assert_eq!(
                driver.mover.prepare_aead_available_into(
                    1,
                    &mut driver.prepared_work,
                    &mut driver.ready_slots,
                    &live_node.crypto_worker,
                ),
                1,
            );
            driver.mover.stage_retire_slots(&mut driver.ready_slots);
            live_node.crypto_worker.submit_prepared_chunk(
                &mut driver.prepared_work,
                |slot| driver.mover.stage_retire_slot(slot),
            );
            wait_for_live_worker_completion(&live_node).await;
        } else if fast_packet {
            let transport_id = TransportId::new(178);
            let remote = TransportAddr::from_string("198.51.100.178:9000");
            live_node.routes.set_established_fast_ingress_direct_fsp_sources(
                direct_fsp_sources(transport_id, remote.clone(), source, 1400),
            );
            let (sink, mut fast_rx) = DataplaneEstablishedFastIngressSink::channel(
                live_node.routes.established_fast_ingress_snapshot(), 8,
            );
            let mut packets = vec![ReceivedPacket::with_timestamp(
                transport_id, remote, raw(older_count as u64).payload, 178_000,
            )];
            assert_eq!(sink.try_ingest_batch(&mut packets), 1);
            assert!(packets.is_empty());
            fast_ingress = Some(fast_rx.try_recv().unwrap());
        } else if packet_rx_prefetch.is_some() {
            first_packet = Some(ReceivedPacket::with_timestamp(
                TransportId::new(178),
                TransportAddr::from_string("198.51.100.178:9000"),
                raw(older_count as u64).payload,
                178_000,
            ));
        } else {
            raw_source.push_back(raw(older_count as u64));
        }
        let mut delivered = Vec::new();
        let mut proof_controls = 0;
        let mut first_turn = true;
        let readiness = live_node.readiness_notify();
        // The first turn consumes the already-ready completion. Further turns
        // must wake themselves as the real receive loop does, with no new
        // packet source or maintenance tick to rescue a retained backlog.
        while futures::FutureExt::now_or_never(readiness.notified()).is_some() {}
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while delivered.len() <= older_count {
                if !first_turn {
                    readiness.notified().await;
                }
                let io = DataplaneLiveTurnIo {
                    endpoint_data_rx: None,
                    endpoint_limit: 0,
                    tun_outbound_rx: None,
                    tun_limit: 0,
                    endpoint_tx: &endpoint_io.event_tx,
                    transports: &transports,
                    crypto_limit: if retained_proof || older_count > 1 { 1 } else { 8 },
                    transport_send_batch_packets: 8,
                };
                let raw_limit = if first_turn {
                    proof_raw_budget.unwrap_or(if ready_link { 0 } else { 1 })
                } else { 1 };
                let turn = if let Some(prefetch) = packet_rx_prefetch {
                    live_node.pump_packet_rx_turn_with_firsts_direct_fsp_sources_and_transport_batch(
                        &mut packet_rx,
                        DataplaneLiveTurnFirsts {
                            raw_packet: first_packet.take(),
                            raw_ingress_prefetch: prefetch,
                            ..Default::default()
                        },
                        raw_limit,
                        direct_fsp_sources(
                            TransportId::new(178),
                            TransportAddr::from_string("198.51.100.178:9000"),
                            source, 1400,
                        ),
                        false,
                        io,
                    ).await
                } else {
                    live_node.pump_turn_with_firsts_and_transport_batch(
                        fast_ingress.take(), &mut raw_source, raw_limit,
                        DataplaneLiveOutboundFirsts::default(), io,
                    ).await
                };
                first_turn = false;
                if !ready_link && !fast_packet {
                    assert!(
                        turn.summary().inbound_admitted() <= 1,
                        "deferred and fresh raw ingress must share the admission budget",
                    );
                }
                assert!(turn.drops().is_empty());
                assert!(turn.raw_ingress_drops().is_empty());
                assert!(turn.output_drops().is_empty());
                for ingress in turn.fmp_link_ingress() {
                    assert_eq!(ingress.msg_type(), Some(crate::protocol::LinkMessageType::Heartbeat.to_byte()));
                    proof_controls += 1;
                }
                for ingress in turn.fsp_authenticated_ingress.sessions {
                    let (_, _, _, _, _, _, _, _, plaintext) = ingress.into_parts();
                    delivered.push(plaintext.as_slice()[FSP_INNER_HEADER_SIZE]);
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both genuine encrypted records finish authentication");
        assert_eq!(delivered, (0..=older_count as u8).collect::<Vec<_>>());
        assert_eq!(proof_controls, usize::from(retained_proof));
        assert_eq!(live_node.deferred_raw_ingress.len(), unrelated_backlog);
        if unrelated_backlog > 0 {
            assert_eq!(live_node.deferred_raw_ingress[0].0.session_source(), Some(blocked_source));
            assert!(!live_node.has_runnable_work());
        }
    }

    #[tokio::test]
    async fn deferred_first_session_ingress_expires_after_handshake_window() {
        let source = NodeAddr::from_bytes([0x77; 16]);
        let raw = DataplaneRawIngress::from_live_received(
            PacketProtocol::Fsp,
            ReceivedPacket::with_timestamp(
                TransportId::new(177),
                TransportAddr::from_string("198.51.100.177:9000"),
                PacketBuffer::new(fsp_wire(
                    177,
                    crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT,
                )),
                177_000,
            ),
        )
        .with_fsp_source(source);
        let mut node = crate::Node::new(crate::Config::new()).expect("node");
        let endpoint_io = node.attach_endpoint_data_io(8).expect("endpoint io");
        let (_endpoint_data_tx, mut endpoint_data_rx) = endpoint_data_batch_channel(1);
        let (_tun_outbound_tx, mut tun_outbound_rx) =
            crate::upper::tun::tun_outbound_channel(1);
        let transports = HashMap::<TransportId, TransportHandle>::new();
        let mut live_node = DataplaneLiveNode::new(AdmissionConfig::new(4, 8));
        live_node.deferred_raw_ingress.push_back((
            raw.into(),
            crate::time::now_ms()
                .saturating_sub(DATAPLANE_DEFERRED_RAW_INGRESS_MAX_AGE_MS + 1),
        ));

        let turn = live_node
            .pump_completion_output_turn_with_transport_batch(
                false,
                DataplaneLiveTurnIo {
                    endpoint_data_rx: Some(&mut endpoint_data_rx),
                    endpoint_limit: 0,
                    tun_outbound_rx: Some(&mut tun_outbound_rx),
                    tun_limit: 0,
                    endpoint_tx: &endpoint_io.event_tx,
                    transports: &transports,
                    crypto_limit: 8,
                    transport_send_batch_packets: 8,
                },
            )
            .await;

        assert!(!live_node.has_deferred_raw_ingress());
        assert_eq!(turn.summary.raw_ingress_dropped(), 1);
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
        assert_eq!(first_feed.summary().dispatched(), 1);
        let inline_outputs = first_feed.summary().outputs_sent();
        assert!(inline_outputs <= 1);
        let inline_completions = first_feed.summary().completions();
        assert!(
            inline_completions <= inline_outputs
                && inline_outputs <= inline_completions.saturating_add(1),
            "the initial dispatch may add one same-turn output beyond drained completions"
        );
        assert_eq!(first_feed.transport_sent(), inline_outputs);

        if inline_outputs == 0 {
            wait_for_live_worker_completion(&live_node).await;
        }
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
                    endpoint_data_rx: Some(&mut endpoint_data_rx),
                    endpoint_limit: 0,
                    tun_outbound_rx: Some(&mut tun_outbound_rx),
                    tun_limit: 0,
                    endpoint_tx: &endpoint_io.event_tx,
                    transports: &transports,
                    crypto_limit: 8,
                    transport_send_batch_packets,
                },
            )
            .await;
        let completion_outputs = completion_turn.summary().outputs_sent();
        assert!(
            completion_outputs <= 2 - inline_outputs
                && (inline_outputs > 0 || completion_outputs > 0),
            "the newly dispatched packet may complete in this turn"
        );
        let completion_count = completion_turn.summary().completions();
        assert!(
            completion_count <= completion_outputs
                && completion_outputs <= completion_count.saturating_add(1),
            "the newly dispatched packet may add one inline output beyond drained completions"
        );
        assert_eq!(completion_turn.summary().dispatched(), 1);
        assert_eq!(completion_turn.transport_sent(), completion_outputs);
        let sent_total = inline_outputs + completion_outputs;

        let first_received =
            tokio::time::timeout(std::time::Duration::from_secs(1), recv_packet_rx.recv())
                .await
                .expect("receive first output")
                .expect("packet channel open");
        assert_eq!(
            open_fmp_wire_payload(first_received.data.as_slice(), key),
            b"ready-first"
        );
        let second_received = if sent_total == 1 {
            assert!(
                recv_packet_rx.try_recv().is_err(),
                "the second output must follow its crypto completion"
            );
            wait_for_live_worker_completion(&live_node).await;
            let second_turn = live_node
                .pump_completion_output_turn_with_transport_batch(
                    false,
                    DataplaneLiveTurnIo {
                        endpoint_data_rx: Some(&mut endpoint_data_rx),
                        endpoint_limit: 0,
                        tun_outbound_rx: Some(&mut tun_outbound_rx),
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
            tokio::time::timeout(std::time::Duration::from_secs(1), recv_packet_rx.recv())
                .await
                .expect("receive second output")
                .expect("packet channel open")
        } else {
            tokio::time::timeout(std::time::Duration::from_secs(1), recv_packet_rx.recv())
                .await
                .expect("receive same-turn second output")
                .expect("packet channel open")
        };
        assert_eq!(
            open_fmp_wire_payload(second_received.data.as_slice(), key),
            b"fed-after-output"
        );

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send udp");
        recv_transport.stop().await.expect("stop recv udp");
    }
    include!("live_node_runtime_dispatch.rs");
