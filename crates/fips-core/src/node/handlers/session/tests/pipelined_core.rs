    #[cfg(unix)]
    #[test]
    fn pipelined_endpoint_wire_plan_owns_payload_sizing_and_worker_offsets() {
        use crate::node::wire::EncryptedHeader;
        use crate::node::wire::{FLAG_KEY_EPOCH, FLAG_SP, build_established_header};
        use crate::node::{PreparedFmpWorkerReservation, session::FspSendReservation};
        use crate::tree::TreeCoordinate;
        use crate::utils::index::SessionIndex;
        use ring::aead::{LessSafeKey, UnboundKey};

        fn test_cipher(byte: u8) -> LessSafeKey {
            let unbound =
                UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &[byte; 32]).expect("test key");
            LessSafeKey::new(unbound)
        }

        let source_addr = node_addr(0x10);
        let dest_addr = node_addr(0x20);
        let root_addr = node_addr(0x01);
        let source_coords = TreeCoordinate::from_addrs(vec![source_addr, root_addr]).unwrap();
        let dest_coords = TreeCoordinate::from_addrs(vec![dest_addr, root_addr]).unwrap();
        let inner_plaintext = [0x55; 48];
        let fsp_counter = 0x0102_0304_0506_0708;
        let fmp_counter = 0x1112_1314_1516_1718;
        let fmp_flags = FLAG_SP | FLAG_KEY_EPOCH;
        let fsp_flags = FSP_FLAG_CP | FSP_FLAG_K;
        let fsp_header = build_fsp_header(fsp_counter, fsp_flags, inner_plaintext.len() as u16);
        let their_index = SessionIndex::new(0xA0B0_C0D0);
        let path_mtu = 1234;
        let default_ttl = 9;
        let timestamp_ms = 0x1122_3344;
        let plan = PipelinedEndpointWirePlan::new(
            &source_addr,
            &dest_addr,
            PipelinedEndpointInnerPlaintext::borrowed(&inner_plaintext),
            Some(&source_coords),
            Some(&dest_coords),
            path_mtu,
            default_ttl,
        )
        .expect("valid pipelined endpoint plan");
        let coords_size = coords_wire_size(&source_coords) + coords_wire_size(&dest_coords);
        assert_eq!(
            plan.link_plaintext_len(),
            SESSION_DATAGRAM_HEADER_SIZE + FSP_HEADER_SIZE + coords_size + inner_plaintext.len()
        );
        assert_eq!(
            plan.fmp_payload_len() as usize,
            4 + plan.link_plaintext_len() + crate::noise::TAG_SIZE
        );
        let fmp_header =
            build_established_header(their_index, fmp_counter, fmp_flags, plan.fmp_payload_len());

        let wire = plan.build(fmp_header, fsp_header, timestamp_ms);

        assert_eq!(
            wire.link_plaintext_len,
            SESSION_DATAGRAM_HEADER_SIZE + FSP_HEADER_SIZE + coords_size + inner_plaintext.len()
        );
        assert_eq!(
            wire.fmp_inner_len,
            4 + wire.link_plaintext_len + crate::noise::TAG_SIZE
        );
        assert_eq!(
            wire.wire_capacity,
            ESTABLISHED_HEADER_SIZE + wire.fmp_inner_len + crate::noise::TAG_SIZE
        );
        assert_eq!(
            wire.wire_buf.len(),
            ESTABLISHED_HEADER_SIZE + 4 + wire.link_plaintext_len
        );

        let fmp = EncryptedHeader::parse(&wire.wire_buf).expect("FMP header parses");
        assert_eq!(fmp.receiver_idx, their_index);
        assert_eq!(fmp.counter, fmp_counter);
        assert_eq!(fmp.flags, fmp_flags);
        assert_eq!(fmp.payload_len as usize, wire.fmp_inner_len);

        let link_offset = ESTABLISHED_HEADER_SIZE + 4;
        assert_eq!(
            &wire.wire_buf[ESTABLISHED_HEADER_SIZE..link_offset],
            &timestamp_ms.to_le_bytes()
        );
        assert_eq!(
            wire.wire_buf[link_offset],
            LinkMessageType::SessionDatagram.to_byte()
        );
        assert_eq!(wire.wire_buf[link_offset + 1], default_ttl);
        assert_eq!(
            u16::from_le_bytes([
                wire.wire_buf[link_offset + 2],
                wire.wire_buf[link_offset + 3]
            ]),
            path_mtu
        );
        assert_eq!(
            &wire.wire_buf[link_offset + 4..link_offset + 20],
            source_addr.as_bytes()
        );
        assert_eq!(
            &wire.wire_buf[link_offset + 20..link_offset + 36],
            dest_addr.as_bytes()
        );

        assert_eq!(
            wire.fsp_aad_offset,
            link_offset + SESSION_DATAGRAM_HEADER_SIZE
        );
        let fsp =
            FspEncryptedHeader::parse(&wire.wire_buf[wire.fsp_aad_offset..]).expect("FSP header");
        assert_eq!(fsp.counter, fsp_counter);
        assert_eq!(fsp.flags, fsp_flags);
        assert_eq!(fsp.payload_len as usize, inner_plaintext.len());
        assert_eq!(
            wire.fsp_plaintext_offset,
            wire.fsp_aad_offset + FSP_HEADER_SIZE + coords_size
        );
        assert_eq!(&wire.wire_buf[wire.fsp_plaintext_offset..], inner_plaintext);

        let fmp_reservation = PreparedFmpWorkerReservation {
            counter: fmp_counter,
            header: fmp_header,
            cipher: test_cipher(7).into(),
            predicted_bytes: wire.wire_capacity,
        };
        let fsp_reservation = FspSendReservation {
            counter: fsp_counter,
            header: fsp_header,
            cipher: test_cipher(8).into(),
        };
        let worker_wire = wire.into_worker_wire(fmp_reservation, fsp_reservation);
        assert_eq!(worker_wire.fmp_counter, fmp_counter);
        assert_eq!(worker_wire.fsp_counter, fsp_counter);
        assert_eq!(
            worker_wire.fsp_seal.aad_offset,
            ESTABLISHED_HEADER_SIZE + 4 + SESSION_DATAGRAM_HEADER_SIZE
        );
        assert_eq!(
            worker_wire.fsp_seal.plaintext_offset,
            ESTABLISHED_HEADER_SIZE
                + 4
                + SESSION_DATAGRAM_HEADER_SIZE
                + FSP_HEADER_SIZE
                + coords_size
        );
        assert_eq!(
            worker_wire.wire_capacity,
            ESTABLISHED_HEADER_SIZE + plan.fmp_payload_len() as usize + crate::noise::TAG_SIZE
        );
    }

    #[cfg(unix)]
    #[test]
    fn pipelined_endpoint_wire_plan_builds_endpoint_data_inner_plaintext() {
        use crate::node::wire::build_established_header;
        use crate::utils::index::SessionIndex;

        let source_addr = node_addr(0x10);
        let dest_addr = node_addr(0x20);
        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let timestamp = 0x1122_3344;
        let inner_flags = 0x01;
        let expected_inner_plaintext = fsp_prepend_inner_header(
            timestamp,
            SessionMessageType::EndpointData.to_byte(),
            inner_flags,
            payload.as_slice(),
        );
        let plan = PipelinedEndpointWirePlan::new(
            &source_addr,
            &dest_addr,
            PipelinedEndpointInnerPlaintext::endpoint_data(
                timestamp,
                inner_flags,
                payload.as_slice(),
            ),
            None,
            None,
            1234,
            9,
        )
        .expect("valid endpoint-data wire plan");

        assert_eq!(
            plan.link_plaintext_len(),
            SESSION_DATAGRAM_HEADER_SIZE + FSP_HEADER_SIZE + expected_inner_plaintext.len()
        );

        let fsp_header = build_fsp_header(7, 0, expected_inner_plaintext.len() as u16);
        let fmp_header =
            build_established_header(SessionIndex::new(3), 5, 0, plan.fmp_payload_len());
        let wire = plan.build(fmp_header, fsp_header, 0x5566_7788);

        assert_eq!(
            &wire.wire_buf[wire.fsp_plaintext_offset..],
            expected_inner_plaintext.as_slice()
        );
    }

    #[cfg(unix)]
    #[test]
    fn pipelined_endpoint_dispatch_plan_owns_worker_policy_and_bookkeeping() {
        let dest_addr = node_addr(0x20);
        let relay_addr = node_addr(0x30);
        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: PipelinedEndpointInnerPlaintext::borrowed(&inner_plaintext),
            my_coords: None,
            dest_coords: None,
        };

        let direct =
            PipelinedEndpointDispatchPlan::new(&send, dest_addr, 1234, 7, false).expect("direct");
        assert_eq!(direct.fsp_payload_len, inner_plaintext.len() as u16);
        assert!(direct.bulk_endpoint_data);
        assert!(direct.drop_on_backpressure);
        assert_eq!(direct.scheduling_weight, 7);
        let reservation = direct.fsp_reservation_input();
        assert_eq!(
            reservation,
            crate::node::FspWorkerSendReservationInput {
                flags: 0,
                payload_len: inner_plaintext.len() as u16,
                path_mtu: 1234
            }
        );
        let bookkeeping = direct.fsp_bookkeeping_input(0x0102_0304_0506_0708);
        assert_eq!(bookkeeping.data_bytes, Some(payload.len()));
        assert_eq!(bookkeeping.counter, 0x0102_0304_0506_0708);
        assert_eq!(bookkeeping.timestamp, send.timestamp);
        assert_eq!(
            bookkeeping.frame_bytes,
            inner_plaintext.len() + crate::noise::TAG_SIZE
        );
        assert_eq!(bookkeeping.touch_ms, Some(send.now_ms));
        assert_eq!(bookkeeping.next_hop, Some(dest_addr));

        let relayed =
            PipelinedEndpointDispatchPlan::new(&send, relay_addr, 1234, 7, false).expect("relay");
        assert!(relayed.bulk_endpoint_data);
        assert!(!relayed.drop_on_backpressure);

        let degraded_direct =
            PipelinedEndpointDispatchPlan::new(&send, dest_addr, 1234, 7, true).expect("degraded");
        assert!(degraded_direct.bulk_endpoint_data);
        assert!(!degraded_direct.drop_on_backpressure);

        let control_send = PipelinedEndpointSend {
            fsp_flags: FSP_FLAG_CP,
            ..send
        };
        let control = PipelinedEndpointDispatchPlan::new(&control_send, dest_addr, 1234, 7, false)
            .expect("control");
        assert!(!control.bulk_endpoint_data);
        assert!(!control.drop_on_backpressure);
    }

    #[cfg(unix)]
    #[test]
    fn direct_endpoint_fmp_only_parser_is_explicit_opt_in() {
        for raw in [None, Some(""), Some("0"), Some("false"), Some("no"), Some("off")] {
            assert!(
                !parse_direct_endpoint_fmp_only_enabled(raw),
                "{raw:?} should leave direct-FMP endpoint data disabled"
            );
        }
        for raw in [Some("1"), Some("true"), Some("yes"), Some("on")] {
            assert!(
                parse_direct_endpoint_fmp_only_enabled(raw),
                "{raw:?} should enable direct-FMP endpoint data"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn pipelined_endpoint_direct_fmp_mode_is_opt_in_direct_bulk_only() {
        let dest_addr = node_addr(0x20);
        let relay_addr = node_addr(0x30);
        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: PipelinedEndpointInnerPlaintext::endpoint_data(
                0x5566_7788,
                0,
                payload.as_slice(),
            ),
            my_coords: None,
            dest_coords: None,
        };

        let default_plan = PipelinedEndpointSendPlan::new_with_direct_fmp_opt_in(
            &node_addr(0x10),
            &send,
            dest_addr,
            1234,
            9,
            1,
            false,
            false,
        )
        .expect("default plan");
        assert!(!default_plan.direct_fmp_endpoint());

        let direct_plan = PipelinedEndpointSendPlan::new_with_direct_fmp_opt_in(
            &node_addr(0x10),
            &send,
            dest_addr,
            1234,
            9,
            1,
            false,
            true,
        )
        .expect("direct opt-in plan");
        assert!(direct_plan.direct_fmp_endpoint());
        assert_eq!(direct_plan.fmp_payload_len() as usize, 4 + 1 + payload.len());

        let direct_route = PipelinedEndpointRoutePlan::new(
            node_addr(0x10),
            dest_addr,
            1234,
            9,
            1,
            false,
        );
        assert!(direct_route.direct_fmp_endpoint_batch_eligible(
            dest_addr,
            std::slice::from_ref(&payload),
            true
        ));
        assert!(!direct_route.direct_fmp_endpoint_batch_eligible(
            dest_addr,
            std::slice::from_ref(&payload),
            false
        ));
        let direct_payload = EndpointDataPayload::new(vec![0xdd; 64]).allow_direct_fmp_endpoint_data();
        let direct_payload_send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &direct_payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: PipelinedEndpointInnerPlaintext::endpoint_data(
                0x5566_7788,
                0,
                direct_payload.as_slice(),
            ),
            my_coords: None,
            dest_coords: None,
        };
        let direct_payload_plan = PipelinedEndpointSendPlan::new_with_direct_fmp_opt_in(
            &node_addr(0x10),
            &direct_payload_send,
            dest_addr,
            1234,
            9,
            1,
            false,
            false,
        )
        .expect("direct payload plan");
        assert!(direct_payload_plan.direct_fmp_endpoint());
        assert!(direct_route.direct_fmp_endpoint_batch_eligible(
            dest_addr,
            std::slice::from_ref(&direct_payload),
            false
        ));
        assert!(!direct_route.direct_fmp_endpoint_batch_eligible(
            dest_addr,
            &[payload.clone(), direct_payload.clone()],
            false
        ));

        let relayed_plan = PipelinedEndpointSendPlan::new_with_direct_fmp_opt_in(
            &node_addr(0x10),
            &send,
            relay_addr,
            1234,
            9,
            1,
            false,
            true,
        )
        .expect("relayed plan");
        assert!(!relayed_plan.direct_fmp_endpoint());
        let relayed_route = PipelinedEndpointRoutePlan::new(
            node_addr(0x10),
            relay_addr,
            1234,
            9,
            1,
            false,
        );
        assert!(!relayed_route.direct_fmp_endpoint_batch_eligible(
            dest_addr,
            std::slice::from_ref(&payload),
            true
        ));

        let degraded_plan = PipelinedEndpointSendPlan::new_with_direct_fmp_opt_in(
            &node_addr(0x10),
            &send,
            dest_addr,
            1234,
            9,
            1,
            true,
            true,
        )
        .expect("degraded direct plan");
        assert!(!degraded_plan.direct_fmp_endpoint());
        let degraded_route = PipelinedEndpointRoutePlan::new(
            node_addr(0x10),
            dest_addr,
            1234,
            9,
            1,
            true,
        );
        assert!(!degraded_route.direct_fmp_endpoint_batch_eligible(
            dest_addr,
            std::slice::from_ref(&payload),
            true
        ));

        let control_send = PipelinedEndpointSend {
            fsp_flags: FSP_FLAG_CP,
            ..send
        };
        let control_plan = PipelinedEndpointSendPlan::new_with_direct_fmp_opt_in(
            &node_addr(0x10),
            &control_send,
            dest_addr,
            1234,
            9,
            1,
            false,
            true,
        )
        .expect("control plan");
        assert!(!control_plan.direct_fmp_endpoint());

        let mut priority_ipv4 = vec![0_u8; 28];
        priority_ipv4[0] = 0x45;
        priority_ipv4[9] = 1;
        let priority_payload = EndpointDataPayload::new(priority_ipv4);
        assert!(!priority_payload.bulk_endpoint_data());
        assert!(!direct_route.direct_fmp_endpoint_batch_eligible(
            dest_addr,
            &[priority_payload],
            true
        ));
    }

    #[test]
    fn session_fsp_send_plan_owns_flags_coords_wire_and_bookkeeping() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut session = make_xk_session(&local, &peer);
        let dest_addr = *peer.node_addr();
        let src_coords = crate::tree::TreeCoordinate::root(node_addr(0x11));
        let dst_coords = crate::tree::TreeCoordinate::root(node_addr(0x22));
        let inner_plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            1,
            b"hello",
        );
        let plan = SessionFspSendPlan::new(
            dest_addr,
            0x0102_0304,
            FSP_FLAG_CP | FSP_FLAG_K,
            &inner_plaintext,
            Some((&src_coords, &dst_coords)),
            SessionFspSendBookkeeping::Data {
                payload_len: 5,
                now_ms: 0x5566_7788,
            },
        );

        let counter_before = session.current_send_counter();
        let sealed = plan.seal(&mut session).expect("seal should succeed");
        assert_eq!(sealed.dest_addr(), dest_addr);
        assert_eq!(sealed.counter(), counter_before);
        assert_eq!(
            session.current_send_counter(),
            counter_before + 1,
            "sealing should consume exactly one FSP counter"
        );

        let (datagram, bookkeeping) = sealed.into_datagram(node_addr(0xaa), 7);
        assert_eq!(datagram.dest_addr, dest_addr);
        assert_eq!(datagram.ttl, 7);
        let header =
            FspEncryptedHeader::parse(&datagram.payload).expect("sealed payload has FSP header");
        assert_eq!(header.flags, FSP_FLAG_CP | FSP_FLAG_K);
        assert_eq!(header.counter, counter_before);
        assert_eq!(header.payload_len as usize, inner_plaintext.len());
        assert!(
            header.has_coords(),
            "send plan should carry coords-present flag and coords together"
        );
        let expected_coords_size = coords_wire_size(&src_coords) + coords_wire_size(&dst_coords);
        assert_eq!(
            datagram.payload.len(),
            FSP_HEADER_SIZE + expected_coords_size + inner_plaintext.len() + crate::noise::TAG_SIZE
        );
        assert_eq!(
            bookkeeping,
            FspSendBookkeepingInput::data(
                5,
                counter_before,
                0x0102_0304,
                inner_plaintext.len() + crate::noise::TAG_SIZE,
                0x5566_7788,
            )
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipelined_endpoint_send_target_owns_connected_udp_preference_and_fallback() {
        use crate::transport::udp::UdpTransport;
        use crate::transport::{TransportAddr, TransportId, packet_channel};
        use crate::utils::index::SessionIndex;
        use std::net::SocketAddr;

        fn prepared(
            transport_id: TransportId,
            remote_addr: TransportAddr,
            #[cfg(any(target_os = "linux", target_os = "macos"))] connected_socket: Option<
                std::sync::Arc<crate::transport::udp::connected_peer::ConnectedPeerSocket>,
            >,
        ) -> crate::node::FmpSendPreparation {
            crate::node::FmpSendPreparation {
                their_index: SessionIndex::new(0xA0B0_C0D0),
                transport_id,
                remote_addr,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                connected_socket,
                timestamp_ms: 123,
                flags: 0,
                payload_len: 16,
            }
        }

        let transport_id = TransportId::new(0x77);
        let (packet_tx, _packet_rx) = packet_channel(8);
        let mut udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx,
        );

        let fallback_addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let fallback_prepared = prepared(
            transport_id,
            TransportAddr::from_string(&fallback_addr.to_string()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            None,
        );
        assert!(
            PipelinedEndpointSendTarget::resolve(&udp, &fallback_prepared)
                .await
                .is_none(),
            "an unstarted UDP transport has no worker socket to own"
        );

        udp.start_async().await.expect("start UDP transport");
        let fallback_target = PipelinedEndpointSendTarget::resolve(&udp, &fallback_prepared)
            .await
            .expect("started UDP transport resolves numeric fallback");
        assert_eq!(fallback_target.socket_addr, fallback_addr);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert!(fallback_target.connected_socket.is_none());

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let peer_udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind peer udp");
            let peer_addr = peer_udp.local_addr().expect("peer udp addr");
            let connected = std::sync::Arc::new(
                crate::transport::udp::connected_peer::ConnectedPeerSocket::open(
                    "127.0.0.1:0".parse().unwrap(),
                    peer_addr,
                    1 << 20,
                    1 << 20,
                )
                .expect("open connected udp"),
            );
            let connected_prepared = prepared(
                transport_id,
                TransportAddr::from_string("invalid fallback target"),
                Some(connected.clone()),
            );
            let connected_target = PipelinedEndpointSendTarget::resolve(&udp, &connected_prepared)
                .await
                .expect("connected socket should avoid fallback resolution");
            assert_eq!(connected_target.socket_addr, peer_addr);
            assert!(std::sync::Arc::ptr_eq(
                connected_target.connected_socket.as_ref().unwrap(),
                &connected
            ));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipelined_endpoint_send_plan_owns_worker_job_and_bookkeeping_handoff() {
        use crate::node::wire::{FLAG_SP, build_established_header};
        use crate::node::{PreparedFmpWorkerReservation, session::FspSendReservation};
        use crate::transport::udp::UdpTransport;
        use crate::transport::{TransportAddr, TransportId, packet_channel};
        use crate::utils::index::SessionIndex;
        use ring::aead::{LessSafeKey, UnboundKey};

        fn test_cipher(byte: u8) -> LessSafeKey {
            let unbound =
                UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &[byte; 32]).expect("test key");
            LessSafeKey::new(unbound)
        }

        let source_addr = node_addr(0x10);
        let dest_addr = node_addr(0x20);
        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: PipelinedEndpointInnerPlaintext::borrowed(&inner_plaintext),
            my_coords: None,
            dest_coords: None,
        };

        let path_mtu = 1234;
        let default_ttl = 9;
        let scheduling_weight = 7;
        let plan = PipelinedEndpointSendPlan::new(
            &source_addr,
            &send,
            dest_addr,
            path_mtu,
            default_ttl,
            scheduling_weight,
            false,
        )
        .expect("valid send plan");
        assert_eq!(
            plan.fsp_reservation_input(),
            crate::node::FspWorkerSendReservationInput {
                flags: 0,
                payload_len: inner_plaintext.len() as u16,
                path_mtu
            }
        );
        let fsp_payload_len = plan.fsp_reservation_input().payload_len;
        let expected_originated_bytes = plan.link_plaintext_len() + crate::noise::TAG_SIZE;

        let transport_id = TransportId::new(0x55);
        let (packet_tx, _packet_rx) = packet_channel(8);
        let mut udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx,
        );
        udp.start_async().await.expect("start UDP transport");
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        let fmp_prepared = crate::node::FmpSendPreparation {
            their_index: SessionIndex::new(0xA0B0_C0D0),
            transport_id,
            remote_addr: TransportAddr::from_string(&fallback_addr.to_string()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket: None,
            timestamp_ms: 0x0102_0304,
            flags: FLAG_SP,
            payload_len: plan.fmp_payload_len(),
        };
        let send_target = PipelinedEndpointSendTarget::resolve(&udp, &fmp_prepared)
            .await
            .expect("started UDP transport resolves send target");

        let fmp_counter = 0x1112_1314_1516_1718;
        let fsp_counter = 0x0102_0304_0506_0708;
        let fmp_header = build_established_header(
            fmp_prepared.their_index,
            fmp_counter,
            fmp_prepared.flags,
            plan.fmp_payload_len(),
        );
        let fsp_header = build_fsp_header(fsp_counter, send.fsp_flags, fsp_payload_len);
        let fmp_reservation = PreparedFmpWorkerReservation {
            counter: fmp_counter,
            header: fmp_header,
            cipher: test_cipher(7).into(),
            predicted_bytes: ESTABLISHED_HEADER_SIZE
                + plan.fmp_payload_len() as usize
                + crate::noise::TAG_SIZE,
        };
        let fsp_reservation = FspSendReservation {
            counter: fsp_counter,
            header: fsp_header,
            cipher: test_cipher(8).into(),
        };

        let prepared = plan.into_prepared_worker_send(
            &fmp_prepared,
            fmp_reservation,
            fsp_reservation,
            send_target,
            None,
        );

        assert_eq!(prepared.dest_addr, dest_addr);
        assert_eq!(prepared.next_hop_addr, dest_addr);
        assert_eq!(prepared.fmp_counter, fmp_counter);
        assert_eq!(prepared.fmp_timestamp_ms, fmp_prepared.timestamp_ms);
        assert_eq!(
            prepared.fmp_wire_capacity,
            ESTABLISHED_HEADER_SIZE + fmp_prepared.payload_len as usize + crate::noise::TAG_SIZE
        );
        assert_eq!(prepared.originated_bytes, expected_originated_bytes);

        assert_eq!(prepared.session_bookkeeping.fsp().expect("FSP bookkeeping").data_bytes, Some(payload.len()));
        assert_eq!(prepared.session_bookkeeping.fsp().expect("FSP bookkeeping").counter, fsp_counter);
        assert_eq!(prepared.session_bookkeeping.fsp().expect("FSP bookkeeping").timestamp, send.timestamp);
        assert_eq!(
            prepared.session_bookkeeping.fsp().expect("FSP bookkeeping").frame_bytes,
            inner_plaintext.len() + crate::noise::TAG_SIZE
        );
        assert_eq!(prepared.session_bookkeeping.fsp().expect("FSP bookkeeping").touch_ms, Some(send.now_ms));
        assert_eq!(prepared.session_bookkeeping.fsp().expect("FSP bookkeeping").next_hop, Some(dest_addr));

        assert_eq!(prepared.worker_job.counter, fmp_counter);
        assert!(prepared.worker_job.bulk_endpoint_data);
        assert!(prepared.worker_job.drop_on_backpressure);
        assert_eq!(prepared.worker_job.scheduling_weight, scheduling_weight);
        assert!(prepared.worker_job.queued_at.is_none());
        assert_eq!(
            &prepared.worker_job.wire_buf[..ESTABLISHED_HEADER_SIZE],
            &fmp_header
        );
        let fsp_seal = prepared.worker_job.fsp_seal.as_ref().expect("FSP seal");
        assert_eq!(fsp_seal.counter, fsp_counter);
        assert_eq!(
            fsp_seal.aad_offset,
            ESTABLISHED_HEADER_SIZE + 4 + SESSION_DATAGRAM_HEADER_SIZE
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pipelined_endpoint_direct_fmp_worker_job_omits_fsp_seal() {
        use crate::node::PreparedFmpWorkerReservation;
        use crate::node::wire::{EncryptedHeader, build_established_header};
        use crate::transport::udp::UdpTransport;
        use crate::transport::{TransportAddr, TransportId, packet_channel};
        use crate::utils::index::SessionIndex;
        use ring::aead::{LessSafeKey, UnboundKey};

        fn test_cipher(byte: u8) -> LessSafeKey {
            let unbound =
                UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &[byte; 32]).expect("test key");
            LessSafeKey::new(unbound)
        }

        let source_addr = node_addr(0x10);
        let dest_addr = node_addr(0x20);
        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: 0,
            inner_plaintext: PipelinedEndpointInnerPlaintext::endpoint_data(
                0x5566_7788,
                0,
                payload.as_slice(),
            ),
            my_coords: None,
            dest_coords: None,
        };
        let plan = PipelinedEndpointSendPlan::new_with_direct_fmp_opt_in(
            &source_addr,
            &send,
            dest_addr,
            1234,
            9,
            7,
            false,
            true,
        )
        .expect("direct-FMP endpoint plan");
        assert!(plan.direct_fmp_endpoint());

        let transport_id = TransportId::new(0x55);
        let (packet_tx, _packet_rx) = packet_channel(8);
        let mut udp = UdpTransport::new(
            transport_id,
            None,
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
            packet_tx,
        );
        udp.start_async().await.expect("start UDP transport");
        let fallback_addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        let fmp_prepared = crate::node::FmpSendPreparation {
            their_index: SessionIndex::new(0xA0B0_C0D0),
            transport_id,
            remote_addr: TransportAddr::from_string(&fallback_addr.to_string()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket: None,
            timestamp_ms: 0x0102_0304,
            flags: 0,
            payload_len: plan.fmp_payload_len(),
        };
        let send_target = PipelinedEndpointSendTarget::resolve(&udp, &fmp_prepared)
            .await
            .expect("started UDP transport resolves send target");
        let fmp_counter = 0x1112_1314_1516_1718;
        let fmp_header = build_established_header(
            fmp_prepared.their_index,
            fmp_counter,
            fmp_prepared.flags,
            plan.fmp_payload_len(),
        );
        let fmp_reservation = PreparedFmpWorkerReservation {
            counter: fmp_counter,
            header: fmp_header,
            cipher: test_cipher(7).into(),
            predicted_bytes: ESTABLISHED_HEADER_SIZE
                + plan.fmp_payload_len() as usize
                + crate::noise::TAG_SIZE,
        };

        let prepared =
            plan.into_prepared_direct_fmp_worker_send(&fmp_prepared, fmp_reservation, send_target, None);

        assert_eq!(prepared.dest_addr, dest_addr);
        assert_eq!(prepared.next_hop_addr, dest_addr);
        assert_eq!(prepared.fmp_counter, fmp_counter);
        assert_eq!(
            prepared.session_bookkeeping.direct_fmp(),
            Some((payload.len(), send.now_ms, dest_addr))
        );
        assert_eq!(
            prepared.originated_bytes,
            1 + payload.len() + crate::noise::TAG_SIZE
        );
        assert!(prepared.worker_job.fsp_seal.is_none());
        assert!(prepared.worker_job.bulk_endpoint_data);
        assert!(prepared.worker_job.drop_on_backpressure);
        assert_eq!(
            prepared.worker_job.wire_buf.len(),
            ESTABLISHED_HEADER_SIZE + 4 + 1 + payload.len()
        );
        let fmp = EncryptedHeader::parse(&prepared.worker_job.wire_buf).expect("FMP header");
        assert_eq!(fmp.payload_len as usize, 4 + 1 + payload.len());
        let link_offset = ESTABLISHED_HEADER_SIZE + 4;
        assert_eq!(
            prepared.worker_job.wire_buf[link_offset],
            LinkMessageType::DirectEndpointData.to_byte()
        );
        assert_eq!(
            &prepared.worker_job.wire_buf[link_offset + 1..],
            payload.as_slice()
        );
    }

    #[cfg(unix)]
    #[test]
    fn pipelined_endpoint_runtime_send_plan_owns_route_and_fmp_preparation() {
        use crate::node::FmpSendPreparation;
        use crate::node::wire::FLAG_SP;
        use crate::transport::{TransportAddr, TransportId};
        use crate::utils::index::SessionIndex;

        let source_addr = node_addr(0x10);
        let dest_addr = node_addr(0x20);
        let next_hop_addr = node_addr(0x30);
        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: FSP_FLAG_K,
            inner_plaintext: PipelinedEndpointInnerPlaintext::borrowed(&inner_plaintext),
            my_coords: None,
            dest_coords: None,
        };
        let route = PipelinedEndpointRoutePlan::new(source_addr, next_hop_addr, 1234, 9, 7, false);
        let plan = route
            .build_send_plan(&send)
            .expect("route plan should build send plan");
        let fmp_payload_len = plan.fmp_payload_len();
        let transport_id = TransportId::new(0x55);
        let prepared = FmpSendPreparation {
            their_index: SessionIndex::new(0xA0B0_C0D0),
            transport_id,
            remote_addr: TransportAddr::from_string("127.0.0.1:9"),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket: None,
            timestamp_ms: 0x0102_0304,
            flags: FLAG_SP,
            payload_len: fmp_payload_len,
        };
        let bad_prepared = FmpSendPreparation {
            their_index: SessionIndex::new(0xA0B0_C0D0),
            transport_id,
            remote_addr: TransportAddr::from_string("127.0.0.1:9"),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket: None,
            timestamp_ms: 0x0102_0304,
            flags: FLAG_SP,
            payload_len: fmp_payload_len - 1,
        };

        let snapshot = crate::node::PeerRuntimeSendSnapshot::new(next_hop_addr, prepared, true);
        let bad_snapshot =
            crate::node::PeerRuntimeSendSnapshot::new(next_hop_addr, bad_prepared, true);

        let runtime = PipelinedEndpointRuntimeSendPlan::from_parts(route, plan, snapshot)
            .expect("matching route/send/FMP preparation should form runtime plan");

        assert_eq!(runtime.source_addr(), source_addr);
        assert_eq!(runtime.dest_addr(), dest_addr);
        assert_eq!(runtime.next_hop_addr(), next_hop_addr);
        assert_eq!(runtime.transport_id(), transport_id);
        assert_eq!(runtime.fmp_payload_len(), fmp_payload_len);
        assert_eq!(
            runtime.fsp_reservation_input(),
            crate::node::FspWorkerSendReservationInput {
                flags: FSP_FLAG_K,
                payload_len: inner_plaintext.len() as u16,
                path_mtu: 1234,
            }
        );
        assert_eq!(
            runtime.fmp_prepared().payload_len,
            runtime.fmp_payload_len()
        );
        assert_eq!(runtime.fmp_prepared().timestamp_ms, 0x0102_0304);

        let (route, plan) = runtime.into_parts_for_test();
        assert!(matches!(
            PipelinedEndpointRuntimeSendPlan::from_parts(route, plan, bad_snapshot),
            Err(PipelinedEndpointRuntimeSendPlanError::FmpPayloadMismatch {
                prepared_payload_len,
                plan_payload_len,
            }) if prepared_payload_len == fmp_payload_len - 1
                && plan_payload_len == fmp_payload_len
        ));
    }

    #[cfg(unix)]
    #[test]
    fn pipelined_endpoint_runtime_send_plan_owns_peer_route_snapshot_handoff() {
        use crate::node::wire::FLAG_SP;
        use crate::transport::{TransportAddr, TransportId};
        use crate::utils::index::SessionIndex;

        let source_addr = node_addr(0x10);
        let dest_addr = node_addr(0x20);
        let next_hop_addr = node_addr(0x30);
        let other_next_hop_addr = node_addr(0x31);
        let payload = EndpointDataPayload::new(vec![0xee; 64]);
        let inner_plaintext = vec![0xaa; 80];
        let send = PipelinedEndpointSend {
            dest_addr: &dest_addr,
            payload: &payload,
            now_ms: 0x1122_3344,
            timestamp: 0x5566_7788,
            fsp_flags: FSP_FLAG_K,
            inner_plaintext: PipelinedEndpointInnerPlaintext::borrowed(&inner_plaintext),
            my_coords: None,
            dest_coords: None,
        };
        let route = PipelinedEndpointRoutePlan::new(source_addr, next_hop_addr, 1234, 9, 7, false);
        let plan = route
            .build_send_plan(&send)
            .expect("route plan should build send plan");
        let fmp_payload_len = plan.fmp_payload_len();
        let transport_id = TransportId::new(0x55);
        let remote_addr = TransportAddr::from_string("127.0.0.1:9");
        let route_snapshot = crate::node::PeerRuntimeRouteSnapshot::new(
            next_hop_addr,
            SessionIndex::new(0xA0B0_C0D0),
            transport_id,
            remote_addr.clone(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            None,
            0x0102_0304,
            FLAG_SP,
            true,
        );

        let runtime =
            PipelinedEndpointRuntimeSendPlan::from_peer_route_snapshot(route, plan, route_snapshot)
                .expect("route snapshot should form runtime plan for the same next hop");

        assert_eq!(runtime.next_hop_addr(), next_hop_addr);
        assert_eq!(runtime.transport_id(), transport_id);
        assert_eq!(runtime.fmp_payload_len(), fmp_payload_len);
        assert_eq!(runtime.fmp_prepared().remote_addr, remote_addr);
        assert_eq!(runtime.fmp_prepared().flags, FLAG_SP);
        assert_eq!(runtime.fmp_prepared().timestamp_ms, 0x0102_0304);
        assert!(
            runtime.fmp_worker_send_available(),
            "runtime plan should carry worker availability derived from route snapshot"
        );

        let (route, plan) = runtime.into_parts_for_test();
        let mismatched_snapshot = crate::node::PeerRuntimeRouteSnapshot::new(
            other_next_hop_addr,
            SessionIndex::new(0xA0B0_C0D0),
            transport_id,
            TransportAddr::from_string("127.0.0.1:10"),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            None,
            0x0102_0304,
            FLAG_SP,
            true,
        );
        assert!(matches!(
            PipelinedEndpointRuntimeSendPlan::from_peer_route_snapshot(
                route,
                plan,
                mismatched_snapshot,
            ),
            Err(PipelinedEndpointRuntimeSendPlanError::RoutePeerMismatch {
                route_next_hop,
                peer_snapshot_addr,
            }) if route_next_hop == next_hop_addr
                && peer_snapshot_addr == other_next_hop_addr
        ));
    }
