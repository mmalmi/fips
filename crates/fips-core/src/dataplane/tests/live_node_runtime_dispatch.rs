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
