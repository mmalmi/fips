    #[tokio::test]
    async fn tcp_carries_direct_record_above_path_mtu_and_preserves_next_boundary() {
        let send_transport_id = TransportId::new(70);
        let recv_transport_id = TransportId::new(71);
        let path_mtu = 220u16;
        let tcp_config = |bind_addr| crate::config::TcpConfig {
            bind_addr,
            mtu: Some(path_mtu),
            ..Default::default()
        };
        let (recv_packet_tx, mut recv_packet_rx) = crate::transport::packet_channel(4);
        let mut recv_transport = TransportHandle::Tcp(crate::transport::tcp::TcpTransport::new(
            recv_transport_id,
            None,
            tcp_config(Some("127.0.0.1:0".to_string())),
            recv_packet_tx,
        ));
        recv_transport.start().await.expect("start recv TCP");
        let remote_addr = TransportAddr::from_string(
            &recv_transport
                .local_addr()
                .expect("recv TCP local addr")
                .to_string(),
        );
        let (send_packet_tx, _send_packet_rx) = crate::transport::packet_channel(1);
        let mut send_transport = TransportHandle::Tcp(crate::transport::tcp::TcpTransport::new(
            send_transport_id,
            None,
            tcp_config(None),
            send_packet_tx,
        ));
        send_transport.start().await.expect("start send TCP");

        let direct_frame = |counter: u64, payload_len: u16| {
            let mut frame = vec![
                0u8;
                FSP_HEADER_SIZE + payload_len as usize + crate::noise::TAG_SIZE
            ];
            frame[0] = FSP_PHASE_ESTABLISHED;
            frame[1] = crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT;
            frame[2..4].copy_from_slice(&payload_len.to_le_bytes());
            frame[4..12].copy_from_slice(&counter.to_le_bytes());
            frame
        };
        let owner = fsp_owner(70);
        let large_wire = direct_frame(700, 300);
        let mut large = transport_output(
            owner,
            700,
            81,
            send_transport_id,
            remote_addr.clone(),
            large_wire.clone(),
        );
        large.path_mtu = path_mtu;
        let small_wire = direct_frame(701, 7);
        let mut small = transport_output(
            owner,
            701,
            82,
            send_transport_id,
            remote_addr.clone(),
            small_wire.clone(),
        );
        small.path_mtu = path_mtu;
        let mut group =
            DataplaneTransportPlanGroup::new(send_transport_id, remote_addr, large);
        group.push(small);
        let mut transports = HashMap::from([(send_transport_id, send_transport)]);
        let mut drops = Vec::new();
        let mut sent_receipts = Vec::new();

        let sent = send_dataplane_transport_groups(
            &transports,
            vec![group],
            &mut drops,
            1,
            Some(&mut sent_receipts),
        )
        .await;

        assert_eq!(sent, 2);
        assert!(drops.is_empty());
        assert_eq!(
            sent_receipts
                .iter()
                .map(|receipt| receipt.counter)
                .collect::<Vec<_>>(),
            [700, 701]
        );
        for expected in [&large_wire, &small_wire] {
            let received = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                recv_packet_rx.recv(),
            )
            .await
            .expect("receive complete TCP stream record")
            .expect("recv TCP packet channel open");
            assert_eq!(received.data.as_slice(), expected.as_slice());
        }

        send_transport = transports.remove(&send_transport_id).unwrap();
        send_transport.stop().await.expect("stop send TCP");
        recv_transport.stop().await.expect("stop recv TCP");
    }
