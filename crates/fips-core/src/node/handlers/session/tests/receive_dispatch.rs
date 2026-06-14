    #[test]
    fn session_runtime_receive_owns_fsp_open_bookkeeping_and_dispatch_metadata() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let (local_session, mut peer_sender) = make_xk_session_pair(&local, &peer);
        let mut entry = SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Established(local_session),
            1_000,
            true,
        );
        entry.mark_established(1_000);
        entry.record_decrypt_failure();

        let endpoint_payload = b"endpoint runtime receive".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );
        let counter = peer_sender.current_send_counter();
        let header = build_fsp_header(counter, 0, plaintext.len() as u16);
        let ciphertext = peer_sender
            .encrypt_with_aad(&plaintext, &header)
            .expect("test frame should encrypt");
        let mut wire = header.to_vec();
        wire.extend_from_slice(&ciphertext);
        let parsed = FspEncryptedHeader::parse(&wire).expect("test frame should parse");

        let outcome = SessionRuntimeReceive::new(
            &mut entry,
            &parsed,
            &wire[FSP_HEADER_SIZE..],
            1_280,
            true,
            2_000,
        )
        .open_established();

        match outcome {
            FspFrameOutcome::Authentic(message) => {
                assert_eq!(message.source_peer().node_addr(), peer.node_addr());
                assert_eq!(message.plaintext(), plaintext);
                assert_eq!(
                    message.msg_type(),
                    SessionMessageType::EndpointData.to_byte()
                );
                assert_eq!(message.inner_flags_byte(), 0);
                assert_eq!(message.timestamp(), 0x0102_0304);
                assert_eq!(message.body(), endpoint_payload);
                assert!(message.is_application_data());
            }
            other => panic!("expected authentic FSP frame, got {other:?}"),
        }
        assert_eq!(entry.consecutive_decrypt_failures(), 0);
        assert_eq!(entry.last_inbound_frame_ms(), 2_000);
    }

    #[test]
    fn established_fsp_wire_owns_ciphertext_offset_and_coord_warmup() {
        use crate::tree::TreeCoordinate;

        let source_addr = node_addr(0x01);
        let local_addr = node_addr(0x02);
        let root_addr = node_addr(0xf0);
        let source_coords = TreeCoordinate::from_addrs(vec![source_addr, root_addr]).unwrap();
        let local_coords = TreeCoordinate::from_addrs(vec![local_addr, root_addr]).unwrap();

        let header = build_fsp_header(42, FSP_FLAG_CP | FSP_FLAG_K, 20);
        let mut wire_bytes = header.to_vec();
        encode_coords(&source_coords, &mut wire_bytes);
        encode_coords(&local_coords, &mut wire_bytes);
        let ciphertext_offset = wire_bytes.len();
        wire_bytes.extend_from_slice(&[0xcc; 36]);

        let mut wire = EstablishedFspWire::parse(&wire_bytes, source_addr, local_addr)
            .expect("wire should parse with coord warmup");
        assert_eq!(wire.header.counter, 42);
        assert_eq!(wire.header.flags, FSP_FLAG_CP | FSP_FLAG_K);
        assert_eq!(wire.ciphertext, &wire_bytes[ciphertext_offset..]);
        assert!(wire.has_coord_warmup());

        let receive = wire.receive(1_280, true, 2_000);
        assert_eq!(receive.header.counter, 42);
        assert_eq!(receive.ciphertext, &wire_bytes[ciphertext_offset..]);
        assert_eq!(receive.path_mtu, 1_280);
        assert!(receive.ce_flag);
        assert_eq!(receive.now_ms, 2_000);

        let mut coord_cache = crate::cache::CoordCache::new(16, 1_000);
        wire.apply_coord_warmup(&mut coord_cache, 1_500);
        assert!(!wire.has_coord_warmup());
        assert_eq!(
            coord_cache
                .get(&source_addr, 1_500)
                .expect("source coords should be cached")
                .root_id(),
            &root_addr
        );
        assert_eq!(
            coord_cache
                .get(&local_addr, 1_500)
                .expect("local coords should be cached")
                .root_id(),
            &root_addr
        );

        assert!(matches!(
            EstablishedFspWire::parse(&wire_bytes[..FSP_HEADER_SIZE - 1], source_addr, local_addr),
            Err(EstablishedFspWireError::BadHeader)
        ));
        let mut truncated_coords = build_fsp_header(43, FSP_FLAG_CP, 20).to_vec();
        truncated_coords.extend_from_slice(&2u16.to_le_bytes());
        truncated_coords.extend_from_slice(&[0u8; 14]);
        assert!(matches!(
            EstablishedFspWire::parse(&truncated_coords, source_addr, local_addr),
            Err(EstablishedFspWireError::BadCoords(_))
        ));
    }

    #[test]
    fn session_registry_owns_early_encrypted_handshake_resend_budget() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let handshake = HandshakeState::new_xk_initiator(local.keypair(), peer.pubkey_full());
        let mut entry = SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Initiating(handshake),
            1_000,
            true,
        );
        let payload = vec![0x10, 0x20, 0x30];
        entry.set_handshake_payload(payload.clone(), 1_500);

        let mut sessions = crate::node::SessionRegistry::default();
        sessions.insert(*peer.node_addr(), entry);

        match sessions.prepare_handshake_resend_after_early_encrypted_data(peer.node_addr(), 2) {
            EarlyEncryptedHandshakeResend::Resend { payload: resend } => {
                assert_eq!(resend, payload);
            }
            other => panic!("expected resend decision, got {other:?}"),
        }
        assert!(sessions.record_handshake_resend(peer.node_addr(), 2_000));
        let entry = sessions
            .get(peer.node_addr())
            .expect("session should remain");
        assert_eq!(entry.resend_count(), 1);
        assert_eq!(entry.next_resend_at_ms(), 2_000);
        assert_eq!(entry.handshake_payload(), Some(payload.as_slice()));

        assert!(matches!(
            sessions.prepare_handshake_resend_after_early_encrypted_data(peer.node_addr(), 1),
            EarlyEncryptedHandshakeResend::BudgetExhausted
        ));
        let entry = sessions
            .get(peer.node_addr())
            .expect("session should remain");
        assert!(entry.handshake_payload().is_none());
        assert_eq!(entry.next_resend_at_ms(), 0);
        assert_eq!(
            entry.resend_count(),
            1,
            "clearing an exhausted payload must not rewrite resend history"
        );

        let missing = node_addr(0x77);
        assert!(matches!(
            sessions.prepare_handshake_resend_after_early_encrypted_data(&missing, 2),
            EarlyEncryptedHandshakeResend::NoPayload
        ));
        assert!(!sessions.record_handshake_resend(&missing, 3_000));
    }

    #[test]
    fn session_registry_owns_established_fsp_open_lookup_and_bookkeeping() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let (local_session, mut peer_sender) = make_xk_session_pair(&local, &peer);
        let mut entry = SessionEntry::new(
            *peer.node_addr(),
            peer.pubkey_full(),
            EndToEndState::Established(local_session),
            1_000,
            true,
        );
        entry.mark_established(1_000);
        entry.record_decrypt_failure();

        let endpoint_payload = b"registry runtime receive".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );
        let counter = peer_sender.current_send_counter();
        let header = build_fsp_header(counter, 0, plaintext.len() as u16);
        let ciphertext = peer_sender
            .encrypt_with_aad(&plaintext, &header)
            .expect("test frame should encrypt");
        let mut wire = header.to_vec();
        wire.extend_from_slice(&ciphertext);
        let parsed = FspEncryptedHeader::parse(&wire).expect("test frame should parse");

        let mut sessions = crate::node::SessionRegistry::default();
        sessions.insert(*peer.node_addr(), entry);

        let outcome = sessions.open_established_fsp_frame(
            peer.node_addr(),
            EstablishedFspReceive::new(&parsed, &wire[FSP_HEADER_SIZE..], 1_280, true, 2_000),
        );

        match outcome {
            FspFrameOutcome::Authentic(message) => {
                assert_eq!(message.source_peer().node_addr(), peer.node_addr());
                assert_eq!(
                    message.msg_type(),
                    SessionMessageType::EndpointData.to_byte()
                );
                assert_eq!(message.body(), endpoint_payload);
            }
            other => panic!("expected authentic FSP frame, got {other:?}"),
        }
        let entry = sessions
            .get(peer.node_addr())
            .expect("session should remain");
        assert_eq!(entry.consecutive_decrypt_failures(), 0);
        assert_eq!(entry.last_inbound_frame_ms(), 2_000);

        let missing = node_addr(0x77);
        let outcome = sessions.open_established_fsp_frame(
            &missing,
            EstablishedFspReceive::new(&parsed, &wire[FSP_HEADER_SIZE..], 1_280, false, 2_001),
        );
        assert!(matches!(outcome, FspFrameOutcome::UnknownSession));
    }

    #[test]
    fn authenticated_session_message_owns_endpoint_delivery_conversion() {
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let endpoint_payload = b"endpoint delivery".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );

        let message = AuthenticatedSessionMessage::new(
            source_peer,
            plaintext,
            SessionMessageType::EndpointData.to_byte(),
            0,
            0x0102_0304,
        );

        assert_eq!(message.body(), endpoint_payload);
        let delivery = message.into_endpoint_data_delivery();
        assert_eq!(delivery.source_peer, source_peer);
        assert_eq!(delivery.payload, endpoint_payload);
    }

    #[test]
    fn authenticated_session_message_can_own_plaintext_inside_wire_buffer() {
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let endpoint_payload = b"buffer endpoint delivery".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );
        let mut buffer = b"outer-fmp-prefix".to_vec();
        let plaintext_offset = buffer.len();
        buffer.extend_from_slice(&plaintext);
        buffer.extend_from_slice(b"outer-fmp-trailer");

        let message = AuthenticatedSessionMessage::from_buffer(
            source_peer,
            buffer,
            plaintext_offset,
            plaintext.len(),
            SessionMessageType::EndpointData.to_byte(),
            0,
            0x0102_0304,
        );

        assert_eq!(message.plaintext(), plaintext);
        assert_eq!(message.body(), endpoint_payload);
        let delivery = message.into_endpoint_data_delivery();
        assert_eq!(delivery.source_peer, source_peer);
        assert_eq!(delivery.payload, endpoint_payload);
    }

    #[test]
    fn authenticated_session_dispatch_owns_route_ce_and_completion_facts() {
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let source_addr = *peer.node_addr();
        let previous_hop_addr = node_addr(0x55);
        let endpoint_payload = b"endpoint completion".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );
        let dispatch = AuthenticatedSessionDispatch::new(
            source_addr,
            previous_hop_addr,
            true,
            AuthenticatedSessionMessage::new(
                source_peer,
                plaintext,
                SessionMessageType::EndpointData.to_byte(),
                0,
                0x0102_0304,
            ),
        );

        assert_eq!(dispatch.source_addr(), &source_addr);
        assert_eq!(dispatch.previous_hop_addr(), &previous_hop_addr);
        assert!(dispatch.ce_flag());
        assert_eq!(
            dispatch.msg_type(),
            SessionMessageType::EndpointData.to_byte()
        );
        assert_eq!(dispatch.body(), endpoint_payload);
        assert_eq!(
            dispatch.receive_completion(),
            Some(SessionReceiveCompletion {
                source_addr,
                body_len: endpoint_payload.len()
            })
        );
        let commit = dispatch.commit();
        assert_eq!(commit.source_addr(), &source_addr);
        assert_eq!(
            commit.receive_completion(),
            Some(SessionReceiveCompletion {
                source_addr,
                body_len: endpoint_payload.len()
            })
        );
        let local = Identity::generate();
        let mut sessions = crate::node::SessionRegistry::default();
        sessions.insert(source_addr, established_entry(&local, &peer));
        assert!(commit.record_receive(&mut sessions, 0x0bad_cafe));
        let entry = sessions.get(&source_addr).expect("session should remain");
        assert_eq!(
            entry.traffic_counters(),
            (0, 1, 0, endpoint_payload.len() as u64)
        );
        assert_eq!(entry.last_activity(), 0x0bad_cafe);

        let delivery = dispatch.into_endpoint_data_delivery();
        assert_eq!(delivery.source_peer, source_peer);
        assert_eq!(delivery.payload, endpoint_payload);

        let report_plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::SenderReport.to_byte(),
            0,
            b"report",
        );
        let report_dispatch = AuthenticatedSessionDispatch::new(
            source_addr,
            previous_hop_addr,
            false,
            AuthenticatedSessionMessage::new(
                source_peer,
                report_plaintext,
                SessionMessageType::SenderReport.to_byte(),
                0,
                0x0102_0304,
            ),
        );
        assert_eq!(
            report_dispatch.receive_completion(),
            None,
            "MMP reports must not reset session idle/traffic counters"
        );
        let report_commit = report_dispatch.commit();
        assert_eq!(report_commit.source_addr(), &source_addr);
        assert_eq!(
            report_commit.receive_completion(),
            None,
            "MMP reports still flush pending packets without recording receive progress"
        );
        assert!(!report_commit.record_receive(&mut sessions, 0x0bad_f00d));
        let entry = sessions.get(&source_addr).expect("session should remain");
        assert_eq!(
            entry.traffic_counters(),
            (0, 1, 0, endpoint_payload.len() as u64)
        );
        assert_eq!(entry.last_activity(), 0x0bad_cafe);
    }

    #[test]
    fn endpoint_data_fast_dispatch_finishes_receive_without_pending_flush() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let source_addr = *peer.node_addr();
        let previous_hop_addr = node_addr(0x55);
        let endpoint_payload = b"fast endpoint delivery".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );
        let dispatch = AuthenticatedSessionDispatch::new(
            source_addr,
            previous_hop_addr,
            false,
            AuthenticatedSessionMessage::new(
                source_peer,
                plaintext,
                SessionMessageType::EndpointData.to_byte(),
                0,
                0x0102_0304,
            ),
        );

        let mut node = Node::new(crate::config::Config::new()).expect("node");
        let mut endpoint_io = node
            .attach_endpoint_data_io(8)
            .expect("endpoint I/O should attach");
        node.sessions
            .insert(source_addr, established_entry(&local, &peer));

        let finish = dispatch.dispatch_endpoint_data_fast(&mut node);
        assert_eq!(finish.pending_flush_dest(), None);
        match endpoint_io.event_rx.try_recv().expect("endpoint event") {
            crate::node::NodeEndpointEvent::Data {
                source_peer: delivered_source,
                payload,
                ..
            } => {
                assert_eq!(delivered_source, source_peer);
                assert_eq!(payload, endpoint_payload);
            }
            event => panic!("expected single endpoint data event, got {event:?}"),
        }
        let entry = node
            .sessions
            .get(&source_addr)
            .expect("session should remain");
        assert_eq!(
            entry.traffic_counters(),
            (0, 1, 0, endpoint_payload.len() as u64)
        );
        assert!(
            !node.pending_session_traffic.has_traffic_for(&source_addr),
            "empty pending guard should keep the fast path synchronous"
        );
    }

    #[test]
    fn endpoint_data_fast_dispatch_reports_pending_flush_owner() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let source_addr = *peer.node_addr();
        let previous_hop_addr = node_addr(0x55);
        let endpoint_payload = b"fast endpoint pending".to_vec();
        let plaintext = fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::EndpointData.to_byte(),
            0,
            &endpoint_payload,
        );
        let dispatch = AuthenticatedSessionDispatch::new(
            source_addr,
            previous_hop_addr,
            false,
            AuthenticatedSessionMessage::new(
                source_peer,
                plaintext,
                SessionMessageType::EndpointData.to_byte(),
                0,
                0x0102_0304,
            ),
        );

        let mut node = Node::new(crate::config::Config::new()).expect("node");
        let _endpoint_io = node
            .attach_endpoint_data_io(8)
            .expect("endpoint I/O should attach");
        node.sessions
            .insert(source_addr, established_entry(&local, &peer));
        assert!(
            !node
                .pending_session_traffic
                .push_endpoint_data(source_addr, vec![0xaa], 8, 8)
                .destination_dropped()
        );

        let finish = dispatch.dispatch_endpoint_data_fast(&mut node);

        assert_eq!(finish.pending_flush_dest(), Some(source_addr));
        assert!(
            node.pending_session_traffic.has_traffic_for(&source_addr),
            "fast dispatch should report, not synchronously drain, pending traffic"
        );
    }

    #[tokio::test]
    async fn worker_direct_session_data_commits_before_endpoint_delivery() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let previous_hop = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let previous_hop_peer = PeerIdentity::from_pubkey_full(previous_hop.pubkey_full());
        let source_addr = *peer.node_addr();
        let endpoint_payload = b"worker decoded endpoint".to_vec();
        let plaintext_len = FSP_INNER_HEADER_SIZE + endpoint_payload.len();

        let mut node = Node::new(crate::config::Config::new()).expect("node");
        let mut endpoint_io = node
            .attach_endpoint_data_io(8)
            .expect("endpoint I/O should attach");
        node.sessions
            .insert(source_addr, established_entry(&local, &peer));

        let direct = DecryptDirectSessionData::for_test(
            crate::node::decrypt_worker::DecryptFmpBookkeeping {
                source_peer: previous_hop_peer,
                transport_id: crate::transport::TransportId::new(1),
                remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                packet_timestamp_ms: 2_000,
                packet_len: 256,
                fmp_counter: 11,
                inner_timestamp_ms: 22,
                fmp_flags: 0,
            },
            source_addr,
            previous_hop_peer,
            false,
            crate::node::session::FspReceiveSync {
                counter: 7,
                slot: EpochSlot::Current,
                received_k_bit: false,
                timestamp: 0x0102_0304,
                plaintext_len,
                ce_flag: false,
                path_mtu: 1_280,
                spin_bit: false,
            },
            endpoint_payload.len(),
            DecryptDirectSessionDelivery::EndpointData(EndpointDataDelivery::new(
                source_peer,
                endpoint_payload.clone(),
            )),
        );

        node.process_direct_session_data_from_worker(direct).await;

        match endpoint_io.event_rx.try_recv().expect("endpoint event") {
            crate::node::NodeEndpointEvent::Data {
                source_peer: delivered_source,
                payload,
                ..
            } => {
                assert_eq!(delivered_source, source_peer);
                assert_eq!(payload, endpoint_payload);
            }
            event => panic!("expected worker-decoded endpoint data event, got {event:?}"),
        }
        let entry = node
            .sessions
            .get(&source_addr)
            .expect("session should remain");
        assert_eq!(
            entry.traffic_counters(),
            (0, 1, 0, endpoint_payload.len() as u64)
        );
        assert_eq!(entry.current_highest_counter(), Some(7));
    }

    #[tokio::test]
    async fn worker_direct_session_commit_updates_metadata_without_payload_bounce() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let source_addr = *peer.node_addr();
        let body_len = b"already delivered".len();
        let plaintext_len = FSP_INNER_HEADER_SIZE + body_len;

        let mut node = Node::new(crate::config::Config::new()).expect("node");
        let mut endpoint_io = node
            .attach_endpoint_data_io(8)
            .expect("endpoint I/O should attach");
        node.sessions
            .insert(source_addr, established_entry(&local, &peer));

        let commit = DecryptDirectSessionCommit::for_test(
            crate::node::decrypt_worker::DecryptFmpBookkeeping {
                source_peer,
                transport_id: crate::transport::TransportId::new(1),
                remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                packet_timestamp_ms: 2_000,
                packet_len: 256,
                fmp_counter: 11,
                inner_timestamp_ms: 22,
                fmp_flags: 0,
            },
            source_addr,
            source_peer,
            false,
            crate::node::session::FspReceiveSync {
                counter: 7,
                slot: EpochSlot::Current,
                received_k_bit: false,
                timestamp: 0x0102_0304,
                plaintext_len,
                ce_flag: false,
                path_mtu: 1_280,
                spin_bit: false,
            },
            body_len,
            false,
        );

        node.process_direct_session_commit_from_worker(commit).await;

        assert!(
            endpoint_io.event_rx.try_recv().is_err(),
            "compact direct commit must not bounce payload bytes through rx_loop"
        );
        let entry = node
            .sessions
            .get(&source_addr)
            .expect("session should remain");
        assert_eq!(entry.traffic_counters(), (0, 1, 0, body_len as u64));
        assert_eq!(entry.current_highest_counter(), Some(7));
    }

    #[tokio::test]
    async fn direct_fmp_endpoint_data_requires_established_session() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let source_addr = *peer.node_addr();
        let payload = b"direct fmp endpoint".to_vec();
        let mut plaintext = 0x0102_0304u32.to_le_bytes().to_vec();
        plaintext.push(crate::protocol::LinkMessageType::DirectEndpointData.to_byte());
        plaintext.extend_from_slice(&payload);
        let remote_addr = crate::transport::TransportAddr::from_string("127.0.0.1:1234");

        let mut node = Node::new(crate::config::Config::new()).expect("node");
        let mut endpoint_io = node
            .attach_endpoint_data_io(8)
            .expect("endpoint I/O should attach");

        node.process_authentic_fmp_plaintext(crate::node::AuthenticatedFmpPlaintext::new(
            source_peer,
            crate::transport::TransportId::new(1),
            &remote_addr,
            2_000,
            plaintext.len() + crate::node::wire::ESTABLISHED_HEADER_SIZE + crate::noise::TAG_SIZE,
            11,
            0,
            &plaintext,
        ))
        .await;
        assert!(
            endpoint_io.event_rx.try_recv().is_err(),
            "direct-FMP endpoint data without an established session must be dropped"
        );

        node.sessions
            .insert(source_addr, established_entry(&local, &peer));
        node.process_authentic_fmp_plaintext(crate::node::AuthenticatedFmpPlaintext::new(
            source_peer,
            crate::transport::TransportId::new(1),
            &remote_addr,
            2_100,
            plaintext.len() + crate::node::wire::ESTABLISHED_HEADER_SIZE + crate::noise::TAG_SIZE,
            12,
            0,
            &plaintext,
        ))
        .await;

        match endpoint_io.event_rx.try_recv().expect("endpoint event") {
            crate::node::NodeEndpointEvent::Data {
                source_peer: delivered_source,
                payload: delivered_payload,
                ..
            } => {
                assert_eq!(delivered_source, source_peer);
                assert_eq!(delivered_payload, payload);
            }
            event => panic!("expected direct-FMP endpoint data event, got {event:?}"),
        }
        let entry = node
            .sessions
            .get(&source_addr)
            .expect("session should remain");
        assert_eq!(entry.traffic_counters(), (0, 1, 0, payload.len() as u64));
        assert!(entry.last_inbound_frame_ms() > 1_000);
    }

    #[tokio::test]
    async fn worker_direct_fmp_endpoint_data_uses_established_session_gate() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let source_addr = *peer.node_addr();
        let payload = b"worker direct fmp endpoint".to_vec();
        let fmp = || crate::node::decrypt_worker::DecryptFmpBookkeeping {
            source_peer,
            transport_id: crate::transport::TransportId::new(1),
            remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            packet_timestamp_ms: 2_000,
            packet_len: payload.len() + crate::node::wire::ESTABLISHED_HEADER_SIZE
                + crate::noise::TAG_SIZE
                + 5,
            fmp_counter: 21,
            inner_timestamp_ms: 0x0102_0304,
            fmp_flags: 0,
        };

        let mut node = Node::new(crate::config::Config::new()).expect("node");
        let mut endpoint_io = node
            .attach_endpoint_data_io(8)
            .expect("endpoint I/O should attach");

        node.process_direct_fmp_endpoint_data_from_worker(
            crate::node::decrypt_worker::DecryptDirectFmpEndpointData::for_test(
                fmp(),
                payload.clone(),
            ),
        )
        .await;
        assert!(
            endpoint_io.event_rx.try_recv().is_err(),
            "worker direct-FMP endpoint data without an established session must be dropped"
        );

        node.sessions
            .insert(source_addr, established_entry(&local, &peer));
        node.process_direct_fmp_endpoint_data_from_worker(
            crate::node::decrypt_worker::DecryptDirectFmpEndpointData::for_test(
                fmp(),
                payload.clone(),
            ),
        )
        .await;

        match endpoint_io.event_rx.try_recv().expect("endpoint event") {
            crate::node::NodeEndpointEvent::Data {
                source_peer: delivered_source,
                payload: delivered_payload,
                ..
            } => {
                assert_eq!(delivered_source, source_peer);
                assert_eq!(delivered_payload, payload);
            }
            event => panic!("expected worker direct-FMP endpoint data event, got {event:?}"),
        }
        let entry = node
            .sessions
            .get(&source_addr)
            .expect("session should remain");
        assert_eq!(entry.traffic_counters(), (0, 1, 0, payload.len() as u64));
        assert!(entry.last_inbound_frame_ms() > 1_000);
    }

    #[tokio::test]
    async fn worker_direct_fmp_endpoint_data_batch_records_receive_once_per_group() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(peer.pubkey_full());
        let source_addr = *peer.node_addr();
        let payloads = vec![
            b"worker batch one".to_vec(),
            b"worker batch two".to_vec(),
            b"worker batch three".to_vec(),
        ];
        let total_len = payloads.iter().map(Vec::len).sum::<usize>();
        let fmp = |counter: u64, payload_len: usize| {
            crate::node::decrypt_worker::DecryptFmpBookkeeping {
                source_peer,
                transport_id: crate::transport::TransportId::new(1),
                remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                packet_timestamp_ms: 2_000 + counter,
                packet_len: payload_len
                    + crate::node::wire::ESTABLISHED_HEADER_SIZE
                    + crate::noise::TAG_SIZE
                    + 5,
                fmp_counter: counter,
                inner_timestamp_ms: 0x0102_0304,
                fmp_flags: 0,
            }
        };
        let endpoints = || {
            payloads
                .iter()
                .enumerate()
                .map(|(index, payload)| {
                    crate::node::decrypt_worker::DecryptDirectFmpEndpointData::for_test(
                        fmp(index as u64 + 1, payload.len()),
                        payload.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };

        let mut node = Node::new(crate::config::Config::new()).expect("node");
        let mut endpoint_io = node
            .attach_endpoint_data_io(8)
            .expect("endpoint I/O should attach");

        node.begin_endpoint_event_batch();
        node.process_direct_fmp_endpoint_data_batch_from_worker(endpoints())
            .await;
        node.finish_endpoint_event_batch();
        assert!(
            endpoint_io.event_rx.try_recv().is_err(),
            "worker direct-FMP endpoint data batch without an established session must be dropped"
        );

        node.sessions
            .insert(source_addr, established_entry(&local, &peer));
        node.begin_endpoint_event_batch();
        node.process_direct_fmp_endpoint_data_batch_from_worker(endpoints())
            .await;
        node.finish_endpoint_event_batch();

        match endpoint_io.event_rx.try_recv().expect("endpoint event") {
            crate::node::NodeEndpointEvent::DataBatch { messages, .. } => {
                assert_eq!(messages.len(), payloads.len());
                for (message, expected_payload) in messages.iter().zip(payloads.iter()) {
                    assert_eq!(message.source_peer, source_peer);
                    assert_eq!(&message.payload, expected_payload);
                }
            }
            event => panic!("expected worker direct-FMP endpoint data batch event, got {event:?}"),
        }
        let entry = node
            .sessions
            .get(&source_addr)
            .expect("session should remain");
        assert_eq!(
            entry.traffic_counters(),
            (0, payloads.len() as u64, 0, total_len as u64)
        );
        assert!(entry.last_inbound_frame_ms() > 1_000);
    }

    #[test]
    fn session_runtime_receive_owns_decrypt_failure_recovery_gate() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let mut entry = established_entry(&local, &peer);
        entry.mark_established(1_000);
        let plaintext_len = FSP_INNER_HEADER_SIZE + 32;
        let forged_ciphertext = vec![0u8; plaintext_len + crate::noise::TAG_SIZE];

        for attempt in 1..=DECRYPT_FAILURE_RECOVERY_THRESHOLD {
            let header = build_fsp_header(attempt as u64, 0, plaintext_len as u16);
            let mut wire = header.to_vec();
            wire.extend_from_slice(&forged_ciphertext);
            let parsed = FspEncryptedHeader::parse(&wire).expect("forged frame should parse");
            let outcome = SessionRuntimeReceive::new(
                &mut entry,
                &parsed,
                &wire[FSP_HEADER_SIZE..],
                1_280,
                false,
                2_000 + attempt as u64,
            )
            .open_established();

            match outcome {
                FspFrameOutcome::DecryptFailed {
                    counter,
                    consecutive,
                    recover_session,
                    ..
                } => {
                    assert_eq!(counter, attempt as u64);
                    assert_eq!(consecutive, attempt);
                    assert_eq!(
                        recover_session,
                        attempt == DECRYPT_FAILURE_RECOVERY_THRESHOLD
                    );
                }
                other => panic!("expected decrypt failure, got {other:?}"),
            }
        }
    }
