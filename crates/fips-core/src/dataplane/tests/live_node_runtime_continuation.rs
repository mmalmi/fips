
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
        let mut completed = if second.transport_sent() > 0 {
            second
        } else {
            assert_eq!(second.summary().outputs(), 0);
            assert_eq!(second.transport_dropped(), 0);
            assert!(second.take_transport_sent_receipts().is_empty());

            let (_ordinary_packet_tx, mut ordinary_packet_rx) =
                crate::transport::packet_channel(1);
            let (_endpoint_data_tx, mut endpoint_data_rx) = endpoint_data_batch_channel(1);
            let (_tun_outbound_tx, mut tun_outbound_rx) =
                crate::upper::tun::tun_outbound_channel(1);
            let mut completion = None;
            for _ in 0..50 {
                let turn = live_node
                    .pump_packet_rx_turn_with_firsts_direct_fsp_sources_and_transport_batch(
                        &mut ordinary_packet_rx,
                        DataplaneLiveTurnFirsts::default(),
                        0,
                        Default::default(),
                        true,
                        DataplaneLiveTurnIo {
                            endpoint_data_rx: &mut endpoint_data_rx,
                            endpoint_limit: 0,
                            tun_outbound_rx: &mut tun_outbound_rx,
                            tun_limit: 0,
                            endpoint_tx: &endpoint_io.event_tx,
                            transports: &transports,
                            crypto_limit: 1,
                            transport_send_batch_packets,
                        },
                    )
                    .await;
                if turn.transport_sent() > 0 {
                    completion = Some(turn);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            completion.expect("completion turn should send continuation output")
        };
        assert_eq!(completed.summary().completions(), 1);
        assert_eq!(completed.transport_sent(), 1);
        assert_eq!(completed.transport_dropped(), 0);
        let mut sent_receipts = completed.take_transport_sent_receipts();
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

