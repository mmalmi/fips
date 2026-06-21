    struct FspOrderedDrainWithOutputs {
        drain: FspOrderedDrain,
        outputs: Vec<FspReadyCompletion>,
    }

    impl std::ops::Deref for FspOrderedDrainWithOutputs {
        type Target = FspOrderedDrain;

        fn deref(&self) -> &Self::Target {
            &self.drain
        }
    }

    trait OwnedFspSessionStateTestExt {
        fn complete_ordered_fsp_open_for_test(
            &mut self,
            ticket: FspReceiveTicket,
            completion: FspOrderedCompletion,
        ) -> Result<FspOrderedDrainWithOutputs, OrderedCompletionError>;
    }

    impl OwnedFspSessionStateTestExt for OwnedFspSessionState {
        fn complete_ordered_fsp_open_for_test(
            &mut self,
            ticket: FspReceiveTicket,
            completion: FspOrderedCompletion,
        ) -> Result<FspOrderedDrainWithOutputs, OrderedCompletionError> {
            let mut outputs = Vec::new();
            let drain =
                self.complete_ordered_fsp_open(ticket, completion, |output| outputs.push(output))?;
            Ok(FspOrderedDrainWithOutputs { drain, outputs })
        }
    }

    #[test]
    fn worker_decodes_local_ipv6_shim_data_without_plaintext_bounce() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let source_addr = *source.node_addr();
        let local_addr = *local.node_addr();
        let src_ipv6 = FipsAddress::from_node_addr(&source_addr).to_ipv6().octets();
        let dst_ipv6 = FipsAddress::from_node_addr(&local_addr).to_ipv6().octets();
        let payload = b"worker-decompressed-ipv6";

        let mut ipv6 = Vec::with_capacity(40 + payload.len());
        ipv6.extend_from_slice(&[0x60, 0, 0, 0]);
        ipv6.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        ipv6.push(59);
        ipv6.push(64);
        ipv6.extend_from_slice(&src_ipv6);
        ipv6.extend_from_slice(&dst_ipv6);
        ipv6.extend_from_slice(payload);

        let compressed = crate::upper::ipv6_shim::compress_ipv6(&ipv6)
            .expect("test IPv6 packet should compress");
        let mut data_packet_body = Vec::with_capacity(FSP_PORT_HEADER_SIZE + compressed.len());
        data_packet_body.extend_from_slice(&0u16.to_le_bytes());
        data_packet_body.extend_from_slice(&FSP_PORT_IPV6_SHIM.to_le_bytes());
        data_packet_body.extend_from_slice(&compressed);
        let plaintext = crate::node::session_wire::fsp_prepend_inner_header(
            0x0102_0304,
            SessionMessageType::DataPacket.to_byte(),
            0,
            &data_packet_body,
        );
        let message = AuthenticatedSessionMessage::new(
            source_peer,
            plaintext,
            SessionMessageType::DataPacket.to_byte(),
            0,
            0x0102_0304,
        );

        match DecryptWorkerShard::direct_session_delivery_from_message(
            source_addr,
            local_addr,
            message,
        )
        .expect("IPv6 shim data packet should decode in worker")
        {
            DecryptDirectSessionDelivery::Ipv6Packet(packet) => assert_eq!(packet, ipv6),
            DecryptDirectSessionDelivery::EndpointData(_) => {
                panic!("IPv6 shim data must not become endpoint data")
            }
        }
    }

    #[test]
    fn worker_directs_local_established_session_datagram_to_fsp_owner() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let previous_hop = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let previous_hop_peer = PeerIdentity::from_pubkey_full(previous_hop.pubkey_full());
        let (mut fsp_sender, fsp_receiver) = test_xk_session_pair(&source, &local);
        let endpoint_body = vec![0x42; DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 256];
        let inner_plaintext = crate::node::session_wire::fsp_prepend_inner_header(
            0x0102_0304,
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0x01,
            &endpoint_body,
        );
        let fsp_counter = fsp_sender.current_send_counter();
        let fsp_header = crate::node::session_wire::build_fsp_header(
            fsp_counter,
            0,
            inner_plaintext.len() as u16,
        );
        let fsp_ciphertext = fsp_sender
            .encrypt_with_aad(&inner_plaintext, &fsp_header)
            .unwrap();
        let mut fsp_payload = Vec::with_capacity(fsp_header.len() + fsp_ciphertext.len());
        fsp_payload.extend_from_slice(&fsp_header);
        fsp_payload.extend_from_slice(&fsp_ciphertext);
        let datagram = crate::protocol::SessionDatagram::new(
            *source.node_addr(),
            *local.node_addr(),
            fsp_payload,
        );
        let inner_timestamp_ms = 0x0a0b_0c0d_u32;
        let mut fmp_plaintext = Vec::new();
        fmp_plaintext.extend_from_slice(&inner_timestamp_ms.to_le_bytes());
        fmp_plaintext.extend_from_slice(&datagram.encode());

        let fmp_key_bytes = [0x33; 32];
        let fmp_seal = test_chacha_key(fmp_key_bytes);
        let fmp_open = test_chacha_key(fmp_key_bytes);
        let fmp_counter = 77;
        let (wire, fmp_header) =
            sealed_fmp_test_packet_with_plaintext(&fmp_seal, fmp_counter, 0, &fmp_plaintext);
        let session_key = test_session_key(1, 9);
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let job = DecryptJob::new(
            wire,
            session_key,
            0,
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *local.node_addr(),
            1_000,
            fmp_counter,
            0,
            fmp_header,
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
            fallback_tx,
        );

        let (pool, _control, _priority, _bulk) = test_worker_pool(1, 8);
        let mut shard = DecryptWorkerShard::new(pool);
        shard.register_session(
            0,
            session_key,
            OwnedSessionState::new(fmp_open, ReplayWindow::new(), previous_hop_peer),
        );
        let fsp_snapshot = crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: fsp_receiver.recv_cipher_clone().unwrap(),
                replay: fsp_receiver.recv_replay_snapshot_owned(),
            },
            pending: None,
            previous: None,
        };
        shard.register_fsp_session(
            0,
            *source.node_addr(),
            OwnedFspSessionState::from(fsp_snapshot),
        );

        shard.handle_job(job).expect("worker job should not fail");
        let event = fallback_rx
            .authenticated_bulk
            .try_recv()
            .expect("direct FSP path should emit an event");
        match event {
            DecryptWorkerEvent::DirectSessionData(direct) => {
                assert_eq!(direct.source_addr, *source.node_addr());
                assert_eq!(direct.previous_hop_peer, previous_hop_peer);
                assert_eq!(direct.fmp.source_peer, previous_hop_peer);
                assert_eq!(direct.fmp.fmp_counter, fmp_counter);
                assert_eq!(direct.fmp.inner_timestamp_ms, inner_timestamp_ms);
                assert_eq!(direct.receive_sync.counter, fsp_counter);
                assert_eq!(direct.receive_sync.slot, EpochSlot::Current);
                assert_eq!(direct.receive_sync.timestamp, 0x0102_0304);
                assert_eq!(direct.receive_sync.plaintext_len, inner_plaintext.len());
                assert_eq!(direct.body_len, endpoint_body.len());
                assert!(direct.receive_sync.spin_bit);
                match direct.delivery {
                    DecryptDirectSessionDelivery::EndpointData(delivery) => {
                        assert_eq!(delivery.source_peer, source_peer);
                        assert_eq!(delivery.payload, endpoint_body);
                    }
                    DecryptDirectSessionDelivery::Ipv6Packet(_) => {
                        panic!("endpoint data must not become an IPv6 packet")
                    }
                }
            }
            other => panic!(
                "expected direct session data event, got {:?}",
                other.packet_count()
            ),
        }
    }

    #[test]
    fn bulk_local_fsp_push_path_batches_direct_data_outputs() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let previous_hop = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let previous_hop_peer = PeerIdentity::from_pubkey_full(previous_hop.pubkey_full());
        let (mut fsp_sender, fsp_receiver) = test_xk_session_pair(&source, &local);
        let fmp_key_bytes = [0x45; 32];
        let fmp_seal = test_chacha_key(fmp_key_bytes);
        let fmp_open = test_chacha_key(fmp_key_bytes);
        let session_key = test_session_key(1, 9);
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);

        let mut make_job = |fmp_counter: u64, endpoint_body: &[u8]| {
            let inner_plaintext = crate::node::session_wire::fsp_prepend_inner_header(
                0x0102_0304,
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                0x01,
                endpoint_body,
            );
            let fsp_counter = fsp_sender.current_send_counter();
            let fsp_header = crate::node::session_wire::build_fsp_header(
                fsp_counter,
                0,
                inner_plaintext.len() as u16,
            );
            let fsp_ciphertext = fsp_sender
                .encrypt_with_aad(&inner_plaintext, &fsp_header)
                .expect("test FSP frame should encrypt");
            let mut fsp_payload = Vec::with_capacity(fsp_header.len() + fsp_ciphertext.len());
            fsp_payload.extend_from_slice(&fsp_header);
            fsp_payload.extend_from_slice(&fsp_ciphertext);
            let datagram = crate::protocol::SessionDatagram::new(
                *source.node_addr(),
                *local.node_addr(),
                fsp_payload,
            );
            let mut fmp_plaintext = Vec::new();
            fmp_plaintext.extend_from_slice(&0x0a0b_0c0d_u32.to_le_bytes());
            fmp_plaintext.extend_from_slice(&datagram.encode());
            let (wire, fmp_header) =
                sealed_fmp_test_packet_with_plaintext(&fmp_seal, fmp_counter, 0, &fmp_plaintext);
            let mut job = DecryptJob::new(
                wire,
                session_key,
                0,
                TransportId::new(1),
                crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                *local.node_addr(),
                1_000,
                fmp_counter,
                0,
                fmp_header,
                crate::node::wire::ESTABLISHED_HEADER_SIZE,
                fallback_tx.clone(),
            );
            job.lane = DecryptWorkerLane::Bulk;
            job
        };

        let first_payload = vec![0x11; DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 256];
        let second_payload = vec![0x22; DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 256];
        let first = make_job(77, &first_payload);
        let second = make_job(78, &second_payload);
        let (pool, _control, _priority, _bulk) = test_worker_pool(1, 8);
        let mut shard = DecryptWorkerShard::new(pool);
        shard.register_session(
            0,
            session_key,
            OwnedSessionState::new(fmp_open, ReplayWindow::new(), previous_hop_peer),
        );
        let fsp_snapshot = crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: fsp_receiver.recv_cipher_clone().unwrap(),
                replay: fsp_receiver.recv_replay_snapshot_owned(),
            },
            pending: None,
            previous: None,
        };
        shard.register_fsp_session(
            0,
            *source.node_addr(),
            OwnedFspSessionState::from(fsp_snapshot),
        );

        let mut plaintext_batch = DecryptPlaintextFallbackBatch::new();
        shard.handle_bulk_job_msg(0, first, &mut plaintext_batch);
        assert!(
            fallback_rx.authenticated_bulk.try_recv().is_err(),
            "first local FSP direct-data output should stay in the worker return batch"
        );
        shard.handle_bulk_job_msg(0, second, &mut plaintext_batch);
        assert!(
            fallback_rx.authenticated_bulk.try_recv().is_err(),
            "second local FSP direct-data output should still wait below the batch cap"
        );

        plaintext_batch.flush();
        let event = fallback_rx
            .authenticated_bulk
            .try_recv()
            .expect("direct data batch");
        match &event {
            DecryptWorkerEvent::DirectSessionDataBatch(directs) => {
                assert_eq!(directs.len(), 2);
                assert_eq!(directs[0].source_addr, *source.node_addr());
                assert_eq!(directs[1].source_addr, *source.node_addr());
                assert_eq!(directs[0].fmp.fmp_counter, 77);
                assert_eq!(directs[1].fmp.fmp_counter, 78);
                match &directs[0].delivery {
                    DecryptDirectSessionDelivery::EndpointData(delivery) => {
                        assert_eq!(delivery.payload, first_payload);
                    }
                    DecryptDirectSessionDelivery::Ipv6Packet(_) => {
                        panic!("first endpoint payload must not become IPv6")
                    }
                }
                match &directs[1].delivery {
                    DecryptDirectSessionDelivery::EndpointData(delivery) => {
                        assert_eq!(delivery.payload, second_payload);
                    }
                    DecryptDirectSessionDelivery::Ipv6Packet(_) => {
                        panic!("second endpoint payload must not become IPv6")
                    }
                }
            }
            other => panic!(
                "expected local FSP direct data batch, got {:?}",
                other.packet_count()
            ),
        }
        fallback_rx.release_dequeued_event(&event);
    }

    #[test]
    fn worker_leaves_coordinate_fsp_plaintext_for_rx_loop_owner() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let fsp_header =
            crate::node::session_wire::build_fsp_header(7, crate::node::session_wire::FSP_FLAG_CP, 0);
        let mut fsp_payload = fsp_header.to_vec();
        fsp_payload.extend_from_slice(&[0u8; 16]);
        let datagram = crate::protocol::SessionDatagram::new(
            *source.node_addr(),
            *local.node_addr(),
            fsp_payload,
        );
        let inner_timestamp_ms = 0x0a0b_0c0d_u32;
        let mut packet_data = Vec::new();
        packet_data.extend_from_slice(&inner_timestamp_ms.to_le_bytes());
        packet_data.extend_from_slice(&datagram.encode());
        assert!(
            packet_data.len() <= DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN,
            "test packet must stay on the priority lane"
        );

        let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let action = DecryptWorkerShard::handle_opened_fmp_job(OpenedFmpJob {
            packet_data: packet_data.clone().into(),
            source_peer,
            transport_id: TransportId::new(1),
            remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            local_node_addr: *local.node_addr(),
            timestamp_ms: 1_000,
            packet_len: packet_data.len(),
            fmp_counter: 77,
            fmp_flags: 0,
            fmp_plaintext_offset: 0,
            fmp_plaintext_len: packet_data.len(),
            fallback_tx,
        })
        .expect("coordinate FSP plaintext should return to rx_loop");

        match action {
            DecryptWorkerJobAction::Output(output) => match output.event {
                DecryptWorkerEvent::Plaintext(fallback) => {
                    assert_eq!(&fallback.packet_data[..], packet_data.as_slice());
                }
                other => panic!(
                    "coordinate FSP should return as plaintext, got {:?}",
                    other.packet_count()
                ),
            },
            DecryptWorkerJobAction::FspJob(_) => {
                panic!("coordinate FSP must not use worker-owned FSP open")
            }
        }
    }

    #[test]
    fn fsp_aead_open_completion_opens_then_owner_accepts_replay() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let previous_hop_peer = test_source_peer();
        let source_addr = *source.node_addr();
        let local_addr = *local.node_addr();
        let (mut fsp_sender, fsp_receiver) = test_xk_session_pair(&source, &local);
        let inner_plaintext = crate::node::session_wire::fsp_prepend_inner_header(
            0x0102_0304,
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0,
            b"ordered worker-open",
        );
        let fsp_counter = fsp_sender.current_send_counter();
        let fsp_header = crate::node::session_wire::build_fsp_header(
            fsp_counter,
            0,
            inner_plaintext.len() as u16,
        );
        let fsp_ciphertext = fsp_sender
            .encrypt_with_aad(&inner_plaintext, &fsp_header)
            .expect("test FSP frame should encrypt");
        let mut fsp_payload = Vec::with_capacity(fsp_header.len() + fsp_ciphertext.len());
        fsp_payload.extend_from_slice(&fsp_header);
        fsp_payload.extend_from_slice(&fsp_ciphertext);
        let fsp_payload_len = fsp_payload.len();
        let header = FspEncryptedHeader::parse(&fsp_payload).expect("encrypted FSP header");
        let snapshot = crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: fsp_receiver.recv_cipher_clone().unwrap(),
                replay: fsp_receiver.recv_replay_snapshot_owned(),
            },
            pending: None,
            previous: None,
        };
        let mut state = OwnedFspSessionState::from(snapshot);
        let shared = state
            .shared_crypto_session(0)
            .expect("single-current FSP session should expose shared crypto");
        let receive_order_id = state.fsp_receive_order_id();

        let make_job = |packet_data: Vec<u8>| {
            let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, 4);
            FspDecryptJob {
                fallback_tx,
                lane: decrypt_worker_packet_lane(packet_data.len()),
                fallback: DecryptFallback::new(
                    previous_hop_peer,
                    TransportId::new(1),
                    crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                    1_000,
                    packet_data.len(),
                    10,
                    0,
                    packet_data,
                    0,
                    fsp_payload_len,
                ),
                local_node_addr: local_addr,
                source_addr,
                previous_hop_peer,
                path_mtu: 1_280,
                ce_flag: false,
                inner_timestamp_ms: 0x0a0b_0c0d,
                fsp_payload_offset: 0,
                fsp_payload_len,
                trace_enqueued_at: None,
            }
        };

        let completion = FspAeadOpenJob {
            source_addr,
            receive_order_id,
            ticket: shared.issue_ticket(),
            cipher: Arc::clone(&shared.cipher),
            job: make_job(fsp_payload.clone()),
            header: header.clone(),
            completion_source: FspAeadCompletionSource::WorkerOpen,
            completion_owner_idx: None,
            open_queued_at: None,
        }
        .into_completion();

        let drain = state
            .complete_ordered_fsp_open_for_test(completion.ticket, completion.result)
            .expect("first worker-open completion should fit receive order");
        assert_eq!(drain.ready, 1);
        assert_eq!(drain.accepted, 1);
        assert_eq!(drain.replay_drops, 0);
        assert_eq!(drain.outputs.len(), 1);
        match &drain.outputs[0] {
            FspReadyCompletion::Opened {
                opened,
                slot,
                source_peer: got_source_peer,
            } => {
                assert_eq!(*slot, EpochSlot::Current);
                assert_eq!(*got_source_peer, source_peer);
                assert_eq!(opened.plaintext_len, inner_plaintext.len());
            }
            FspReadyCompletion::AeadFailed { .. } => panic!("valid worker-open frame must open"),
        }

        let duplicate = FspAeadOpenJob {
            source_addr,
            receive_order_id,
            ticket: shared.issue_ticket(),
            cipher: Arc::clone(&shared.cipher),
            job: make_job(fsp_payload),
            header,
            completion_source: FspAeadCompletionSource::WorkerOpen,
            completion_owner_idx: None,
            open_queued_at: None,
        }
        .into_completion();
        let duplicate_drain = state
            .complete_ordered_fsp_open_for_test(duplicate.ticket, duplicate.result)
            .expect("duplicate worker-open completion should fit receive order");
        assert_eq!(duplicate_drain.ready, 1);
        assert_eq!(duplicate_drain.accepted, 0);
        assert_eq!(duplicate_drain.replay_drops, 1);
        assert_eq!(
            duplicate_drain.replay_drop_sources,
            FspReplayDropSources {
                worker_open: 1,
                ..FspReplayDropSources::default()
            }
        );
        assert!(
            duplicate_drain.outputs.is_empty(),
            "replayed worker-open completion must not emit authenticated output"
        );
    }

    #[test]
    fn fsp_session_refresh_preserves_inflight_worker_open_order() {
        let source = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let snapshot = || crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: test_chacha_key([0x51; 32]),
                replay: ReplayWindow::new(),
            },
            pending: None,
            previous: None,
        };

        let mut state = OwnedFspSessionState::from(snapshot());
        let shared = Arc::new(
            state
                .shared_crypto_session(0)
                .expect("single-current FSP session should expose shared crypto"),
        );
        state.attach_shared_crypto_session(Arc::clone(&shared));
        let receive_order_id = state.fsp_receive_order_id();
        let ticket = shared.issue_ticket();

        let mut refreshed = OwnedFspSessionState::from(snapshot());
        refreshed.preserve_receive_order_from(state);
        assert_eq!(refreshed.fsp_receive_order_id(), receive_order_id);
        assert_eq!(refreshed.fsp_receive_order.next_ticket(), ticket.sequence + 1);

        let drain = refreshed
            .complete_ordered_fsp_open_for_test(
                ticket,
                FspOrderedCompletion::Dropped {
                    source: FspAeadCompletionSource::WorkerOpen,
                },
            )
            .expect("pre-refresh worker-open completion should remain in order");
        assert_eq!(drain.ready, 1);
        assert_eq!(drain.dropped, 1);
        assert_eq!(refreshed.fsp_receive_order_next_ready(), ticket.sequence + 1);

        let next_shared = refreshed
            .shared_crypto_session(0)
            .expect("refreshed single-current FSP session should expose shared crypto");
        assert_eq!(next_shared.receive_order_id, receive_order_id);
        assert_eq!(next_shared.issue_ticket().sequence, ticket.sequence + 1);
    }

    #[test]
    fn fsp_ordered_completion_buffers_out_of_order_worker_open_results() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let previous_hop_peer = test_source_peer();
        let source_addr = *source.node_addr();
        let local_addr = *local.node_addr();
        let (mut fsp_sender, fsp_receiver) = test_xk_session_pair(&source, &local);
        let snapshot = crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: fsp_receiver.recv_cipher_clone().unwrap(),
                replay: fsp_receiver.recv_replay_snapshot_owned(),
            },
            pending: None,
            previous: None,
        };
        let mut state = OwnedFspSessionState::from(snapshot);
        let shared = state
            .shared_crypto_session(0)
            .expect("single-current FSP session should expose shared crypto");
        let receive_order_id = state.fsp_receive_order_id();

        let mut make_payload = |body: &'static [u8]| {
            let inner_plaintext = crate::node::session_wire::fsp_prepend_inner_header(
                0x0102_0304,
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                0,
                body,
            );
            let fsp_counter = fsp_sender.current_send_counter();
            let fsp_header = crate::node::session_wire::build_fsp_header(
                fsp_counter,
                0,
                inner_plaintext.len() as u16,
            );
            let fsp_ciphertext = fsp_sender
                .encrypt_with_aad(&inner_plaintext, &fsp_header)
                .expect("test FSP frame should encrypt");
            let mut fsp_payload = Vec::with_capacity(fsp_header.len() + fsp_ciphertext.len());
            fsp_payload.extend_from_slice(&fsp_header);
            fsp_payload.extend_from_slice(&fsp_ciphertext);
            (fsp_payload, inner_plaintext.len())
        };

        let make_job = |packet_data: Vec<u8>, fsp_payload_len: usize| {
            let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, 4);
            FspDecryptJob {
                fallback_tx,
                lane: decrypt_worker_packet_lane(packet_data.len()),
                fallback: DecryptFallback::new(
                    previous_hop_peer,
                    TransportId::new(1),
                    crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                    1_000,
                    packet_data.len(),
                    10,
                    0,
                    packet_data,
                    0,
                    fsp_payload_len,
                ),
                local_node_addr: local_addr,
                source_addr,
                previous_hop_peer,
                path_mtu: 1_280,
                ce_flag: false,
                inner_timestamp_ms: 0x0a0b_0c0d,
                fsp_payload_offset: 0,
                fsp_payload_len,
                trace_enqueued_at: None,
            }
        };

        let (first_payload, first_plaintext_len) = make_payload(b"first worker-open");
        let first_payload_len = first_payload.len();
        let first_header = FspEncryptedHeader::parse(&first_payload).expect("first FSP header");
        let first_completion = FspAeadOpenJob {
            source_addr,
            receive_order_id,
            ticket: shared.issue_ticket(),
            cipher: Arc::clone(&shared.cipher),
            job: make_job(first_payload, first_payload_len),
            header: first_header,
            completion_source: FspAeadCompletionSource::WorkerOpen,
            completion_owner_idx: None,
            open_queued_at: None,
        }
        .into_completion();

        let (second_payload, second_plaintext_len) = make_payload(b"second worker-open");
        let second_payload_len = second_payload.len();
        let second_header = FspEncryptedHeader::parse(&second_payload).expect("second FSP header");
        let second_completion = FspAeadOpenJob {
            source_addr,
            receive_order_id,
            ticket: shared.issue_ticket(),
            cipher: Arc::clone(&shared.cipher),
            job: make_job(second_payload, second_payload_len),
            header: second_header,
            completion_source: FspAeadCompletionSource::WorkerOpen,
            completion_owner_idx: None,
            open_queued_at: None,
        }
        .into_completion();

        let second_drain = state
            .complete_ordered_fsp_open_for_test(second_completion.ticket, second_completion.result)
            .expect("later worker-open completion should buffer behind missing first ticket");
        assert_eq!(second_drain.ready, 0);
        assert_eq!(second_drain.accepted, 0);
        assert_eq!(second_drain.replay_drops, 0);
        assert!(
            second_drain.outputs.is_empty(),
            "later completion must not emit before the receive-order gap closes"
        );

        let first_drain = state
            .complete_ordered_fsp_open_for_test(first_completion.ticket, first_completion.result)
            .expect("first worker-open completion should drain itself and buffered second");
        assert_eq!(first_drain.ready, 2);
        assert_eq!(first_drain.accepted, 2);
        assert_eq!(first_drain.replay_drops, 0);
        assert_eq!(first_drain.outputs.len(), 2);
        match (&first_drain.outputs[0], &first_drain.outputs[1]) {
            (
                FspReadyCompletion::Opened {
                    opened: first_opened,
                    slot: first_slot,
                    ..
                },
                FspReadyCompletion::Opened {
                    opened: second_opened,
                    slot: second_slot,
                    ..
                },
            ) => {
                assert_eq!(*first_slot, EpochSlot::Current);
                assert_eq!(*second_slot, EpochSlot::Current);
                assert_eq!(first_opened.plaintext_len, first_plaintext_len);
                assert_eq!(second_opened.plaintext_len, second_plaintext_len);
            }
            _ => panic!("worker-open completions should both authenticate"),
        }
    }

    #[test]
    fn fsp_ordered_completion_tracks_ready_aead_failure_source() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let previous_hop_peer = test_source_peer();
        let source_addr = *source.node_addr();
        let local_addr = *local.node_addr();
        let (mut fsp_sender, fsp_receiver) = test_xk_session_pair(&source, &local);
        let snapshot = crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: fsp_receiver.recv_cipher_clone().unwrap(),
                replay: fsp_receiver.recv_replay_snapshot_owned(),
            },
            pending: None,
            previous: None,
        };
        let mut state = OwnedFspSessionState::from(snapshot);
        let shared = state
            .shared_crypto_session(0)
            .expect("single-current FSP session should expose shared crypto");
        let receive_order_id = state.fsp_receive_order_id();

        let mut make_payload = |body: &'static [u8]| {
            let inner_plaintext = crate::node::session_wire::fsp_prepend_inner_header(
                0x0102_0304,
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                0,
                body,
            );
            let fsp_counter = fsp_sender.current_send_counter();
            let fsp_header = crate::node::session_wire::build_fsp_header(
                fsp_counter,
                0,
                inner_plaintext.len() as u16,
            );
            let fsp_ciphertext = fsp_sender
                .encrypt_with_aad(&inner_plaintext, &fsp_header)
                .expect("test FSP frame should encrypt");
            let mut fsp_payload = Vec::with_capacity(fsp_header.len() + fsp_ciphertext.len());
            fsp_payload.extend_from_slice(&fsp_header);
            fsp_payload.extend_from_slice(&fsp_ciphertext);
            (fsp_payload, inner_plaintext.len())
        };

        let make_job = |packet_data: Vec<u8>, fsp_payload_len: usize| {
            let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, 4);
            FspDecryptJob {
                fallback_tx,
                lane: decrypt_worker_packet_lane(packet_data.len()),
                fallback: DecryptFallback::new(
                    previous_hop_peer,
                    TransportId::new(1),
                    crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                    1_000,
                    packet_data.len(),
                    10,
                    0,
                    packet_data,
                    0,
                    fsp_payload_len,
                ),
                local_node_addr: local_addr,
                source_addr,
                previous_hop_peer,
                path_mtu: 1_280,
                ce_flag: false,
                inner_timestamp_ms: 0x0a0b_0c0d,
                fsp_payload_offset: 0,
                fsp_payload_len,
                trace_enqueued_at: None,
            }
        };

        let (first_payload, first_plaintext_len) = make_payload(b"first worker-open");
        let first_payload_len = first_payload.len();
        let first_header = FspEncryptedHeader::parse(&first_payload).expect("first FSP header");
        let first_completion = FspAeadOpenJob {
            source_addr,
            receive_order_id,
            ticket: shared.issue_ticket(),
            cipher: Arc::clone(&shared.cipher),
            job: make_job(first_payload, first_payload_len),
            header: first_header,
            completion_source: FspAeadCompletionSource::WorkerOpen,
            completion_owner_idx: None,
            open_queued_at: None,
        }
        .into_completion();

        let (mut second_payload, second_plaintext_len) = make_payload(b"second worker-open");
        *second_payload
            .last_mut()
            .expect("test FSP frame has ciphertext") ^= 0x55;
        let second_payload_len = second_payload.len();
        let second_header = FspEncryptedHeader::parse(&second_payload).expect("second FSP header");
        let second_completion = FspAeadOpenJob {
            source_addr,
            receive_order_id,
            ticket: shared.issue_ticket(),
            cipher: Arc::clone(&shared.cipher),
            job: make_job(second_payload, second_payload_len),
            header: second_header,
            completion_source: FspAeadCompletionSource::WorkerOpen,
            completion_owner_idx: None,
            open_queued_at: None,
        }
        .into_completion();

        let second_drain = state
            .complete_ordered_fsp_open_for_test(second_completion.ticket, second_completion.result)
            .expect("later failed completion should wait behind missing first ticket");
        assert_eq!(second_drain.ready, 0);
        assert_eq!(second_drain.aead_failures, 0);
        assert_eq!(
            second_drain.aead_failure_sources,
            FspAeadFailureSources::default()
        );

        let first_drain = state
            .complete_ordered_fsp_open_for_test(first_completion.ticket, first_completion.result)
            .expect("first completion should release the queued AEAD failure");
        assert_eq!(first_drain.ready, 2);
        assert_eq!(first_drain.accepted, 1);
        assert_eq!(first_drain.aead_failures, 1);
        assert_eq!(
            first_drain.aead_failure_sources,
            FspAeadFailureSources {
                worker_open: 1,
                ..FspAeadFailureSources::default()
            }
        );
        assert_eq!(first_drain.outputs.len(), 2);
        match (&first_drain.outputs[0], &first_drain.outputs[1]) {
            (
                FspReadyCompletion::Opened { opened, .. },
                FspReadyCompletion::AeadFailed { .. },
            ) => assert_eq!(opened.plaintext_len, first_plaintext_len),
            _ => panic!("first packet should open, second packet should fail AEAD"),
        }
        assert!(
            second_plaintext_len > 0,
            "test should corrupt a non-empty encrypted frame"
        );
    }

    #[test]
    fn fsp_recoverable_local_aead_miss_falls_back_without_hard_failure_count() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let previous_hop_peer = test_source_peer();
        let source_addr = *source.node_addr();
        let local_addr = *local.node_addr();
        let (_fsp_sender, fsp_receiver) = test_xk_session_pair(&source, &local);
        let snapshot = crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: fsp_receiver.recv_cipher_clone().unwrap(),
                replay: fsp_receiver.recv_replay_snapshot_owned(),
            },
            pending: None,
            previous: None,
        };
        let mut state = OwnedFspSessionState::from(snapshot);

        let mut frame = crate::node::session_wire::build_fsp_header(1, 0, 1).to_vec();
        frame.extend_from_slice(&[0u8; 16]);
        let frame_len = frame.len();
        let header = FspEncryptedHeader::parse(&frame).expect("test FSP header");
        let mut packet_data = frame;
        packet_data.resize(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1, 0);
        let packet_len = packet_data.len();
        let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, 4);
        let job = FspDecryptJob {
            fallback_tx,
            lane: decrypt_worker_packet_lane(packet_len),
            fallback: DecryptFallback::new(
                previous_hop_peer,
                TransportId::new(1),
                crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                1_000,
                packet_len,
                10,
                0,
                packet_data,
                0,
                frame_len,
            ),
            local_node_addr: local_addr,
            source_addr,
            previous_hop_peer,
            path_mtu: 1_280,
            ce_flag: false,
            inner_timestamp_ms: 0x0a0b_0c0d,
            fsp_payload_offset: 0,
            fsp_payload_len: frame_len,
            trace_enqueued_at: None,
        };
        assert_eq!(job.lane, DecryptWorkerLane::Bulk);
        let ticket = state
            .issue_fsp_receive_ticket()
            .expect("recoverable local open still reserves an ordered receive ticket");
        let drain = state
            .complete_ordered_fsp_open_for_test(
                ticket,
                FspOrderedCompletion::AeadFailed {
                    job,
                    header,
                    source: FspAeadCompletionSource::Local,
                    fallback_to_rx_loop: true,
                    count_failure: false,
                },
            )
            .expect("recoverable local AEAD miss should complete its ordered slot");

        assert_eq!(drain.ready, 1);
        assert_eq!(drain.accepted, 0);
        assert_eq!(drain.aead_failures, 0);
        assert_eq!(drain.rx_loop_fallbacks, 1);
        assert_eq!(
            drain.aead_failure_sources,
            FspAeadFailureSources::default()
        );
        assert_eq!(drain.outputs.len(), 1);
        match &drain.outputs[0] {
            FspReadyCompletion::AeadFailed {
                header: reported,
                fallback_to_rx_loop,
                ..
            } => {
                assert_eq!(reported.counter, 1);
                assert!(*fallback_to_rx_loop);
            }
            FspReadyCompletion::Opened { .. } => {
                panic!("recoverable AEAD miss must not authenticate an FSP frame")
            }
        }
    }

    #[test]
    fn fsp_ordered_completion_tracks_epoch_mismatch_separately_from_aead() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let previous_hop_peer = test_source_peer();
        let source_addr = *source.node_addr();
        let local_addr = *local.node_addr();
        let (mut fsp_sender, fsp_receiver) = test_xk_session_pair(&source, &local);
        let snapshot = crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: fsp_receiver.recv_cipher_clone().unwrap(),
                replay: fsp_receiver.recv_replay_snapshot_owned(),
            },
            pending: None,
            previous: None,
        };
        let mut state = OwnedFspSessionState::from(snapshot);

        let inner_plaintext = crate::node::session_wire::fsp_prepend_inner_header(
            0x0102_0304,
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0,
            b"key bit mismatch",
        );
        let fsp_counter = fsp_sender.current_send_counter();
        let fsp_header = crate::node::session_wire::build_fsp_header(
            fsp_counter,
            FSP_FLAG_K,
            inner_plaintext.len() as u16,
        );
        let fsp_ciphertext = fsp_sender
            .encrypt_with_aad(&inner_plaintext, &fsp_header)
            .expect("test FSP frame should encrypt");
        let mut fsp_payload = Vec::with_capacity(fsp_header.len() + fsp_ciphertext.len());
        fsp_payload.extend_from_slice(&fsp_header);
        fsp_payload.extend_from_slice(&fsp_ciphertext);
        let header = FspEncryptedHeader::parse(&fsp_payload).expect("FSP header");
        assert!(
            !state.current_epoch_matches(&header),
            "test frame must carry the opposite K-bit from the worker snapshot"
        );

        let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, 4);
        let job = FspDecryptJob {
            fallback_tx,
            lane: decrypt_worker_packet_lane(fsp_payload.len()),
            fallback: DecryptFallback::new(
                previous_hop_peer,
                TransportId::new(1),
                crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                1_000,
                fsp_payload.len(),
                10,
                0,
                fsp_payload,
                0,
                fsp_header.len() + fsp_ciphertext.len(),
            ),
            local_node_addr: local_addr,
            source_addr,
            previous_hop_peer,
            path_mtu: 1_280,
            ce_flag: false,
            inner_timestamp_ms: 0x0a0b_0c0d,
            fsp_payload_offset: 0,
            fsp_payload_len: fsp_header.len() + fsp_ciphertext.len(),
            trace_enqueued_at: None,
        };
        let ticket = state
            .issue_fsp_receive_ticket()
            .expect("single-current local owner should reserve an FSP ticket");
        let drain = state
            .complete_ordered_fsp_open_for_test(
                ticket,
                FspOrderedCompletion::EpochMismatch {
                    job,
                    header,
                    source: FspAeadCompletionSource::Local,
                },
            )
            .expect("epoch-mismatch completion should fit receive order");

        assert_eq!(drain.ready, 1);
        assert_eq!(drain.accepted, 0);
        assert_eq!(drain.aead_failures, 0);
        assert_eq!(drain.epoch_mismatches, 1);
        assert_eq!(drain.replay_drops, 0);
        assert_eq!(drain.dropped, 0);
        assert_eq!(drain.outputs.len(), 1);
        match &drain.outputs[0] {
            FspReadyCompletion::AeadFailed {
                header: reported, ..
            } => {
                assert_eq!(reported.counter, fsp_counter);
                assert_eq!(reported.flags & FSP_FLAG_K, FSP_FLAG_K);
            }
            FspReadyCompletion::Opened { .. } => {
                panic!("epoch mismatch must not authenticate an FSP frame")
            }
        }
    }

    #[test]
    fn fsp_local_owner_open_uses_shared_order_with_worker_open_results() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let previous_hop_peer = test_source_peer();
        let source_addr = *source.node_addr();
        let local_addr = *local.node_addr();
        let (mut fsp_sender, fsp_receiver) = test_xk_session_pair(&source, &local);
        let snapshot = crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: fsp_receiver.recv_cipher_clone().unwrap(),
                replay: fsp_receiver.recv_replay_snapshot_owned(),
            },
            pending: None,
            previous: None,
        };
        let mut state = OwnedFspSessionState::from(snapshot);
        let shared = Arc::new(
            state
                .shared_crypto_session(0)
                .expect("single-current FSP session should expose shared crypto"),
        );
        state.attach_shared_crypto_session(Arc::clone(&shared));
        let receive_order_id = state.fsp_receive_order_id();

        let mut make_payload = |body: &'static [u8]| {
            let inner_plaintext = crate::node::session_wire::fsp_prepend_inner_header(
                0x0102_0304,
                crate::protocol::SessionMessageType::EndpointData.to_byte(),
                0,
                body,
            );
            let fsp_counter = fsp_sender.current_send_counter();
            let fsp_header = crate::node::session_wire::build_fsp_header(
                fsp_counter,
                0,
                inner_plaintext.len() as u16,
            );
            let fsp_ciphertext = fsp_sender
                .encrypt_with_aad(&inner_plaintext, &fsp_header)
                .expect("test FSP frame should encrypt");
            let mut fsp_payload = Vec::with_capacity(fsp_header.len() + fsp_ciphertext.len());
            fsp_payload.extend_from_slice(&fsp_header);
            fsp_payload.extend_from_slice(&fsp_ciphertext);
            (fsp_payload, inner_plaintext.len())
        };

        let make_job = |packet_data: Vec<u8>, fsp_payload_len: usize| {
            let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, 4);
            FspDecryptJob {
                fallback_tx,
                lane: decrypt_worker_packet_lane(packet_data.len()),
                fallback: DecryptFallback::new(
                    previous_hop_peer,
                    TransportId::new(1),
                    crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                    1_000,
                    packet_data.len(),
                    10,
                    0,
                    packet_data,
                    0,
                    fsp_payload_len,
                ),
                local_node_addr: local_addr,
                source_addr,
                previous_hop_peer,
                path_mtu: 1_280,
                ce_flag: false,
                inner_timestamp_ms: 0x0a0b_0c0d,
                fsp_payload_offset: 0,
                fsp_payload_len,
                trace_enqueued_at: None,
            }
        };

        let (open_payload, open_plaintext_len) = make_payload(b"worker-open first");
        let open_payload_len = open_payload.len();
        let open_header = FspEncryptedHeader::parse(&open_payload).expect("worker-open header");
        let open_ticket = shared
            .try_issue_ticket()
            .expect("worker-open should reserve the first FSP ticket");
        assert_eq!(open_ticket.sequence, 0);

        let (local_payload, local_plaintext_len) = make_payload(b"local second");
        let local_payload_len = local_payload.len();
        let local_header = FspEncryptedHeader::parse(&local_payload).expect("local header");
        let local_ticket = state
            .issue_fsp_receive_ticket()
            .expect("local owner open should reserve from the same shared ticket source");
        assert_eq!(local_ticket.sequence, 1);

        let local_completion = FspAeadOpenJob {
            source_addr,
            receive_order_id,
            ticket: local_ticket,
            cipher: Arc::clone(&shared.cipher),
            job: make_job(local_payload, local_payload_len),
            header: local_header,
            completion_source: FspAeadCompletionSource::Local,
            completion_owner_idx: None,
            open_queued_at: None,
        }
        .into_completion();
        let local_drain = state
            .complete_ordered_fsp_open_for_test(local_completion.ticket, local_completion.result)
            .expect("local completion should fit behind the pending worker-open ticket");
        assert_eq!(local_drain.ready, 0);
        assert!(
            local_drain.outputs.is_empty(),
            "local owner completion must not bypass an older worker-open ticket"
        );

        let open_completion = FspAeadOpenJob {
            source_addr,
            receive_order_id,
            ticket: open_ticket,
            cipher: Arc::clone(&shared.cipher),
            job: make_job(open_payload, open_payload_len),
            header: open_header,
            completion_source: FspAeadCompletionSource::WorkerOpen,
            completion_owner_idx: None,
            open_queued_at: None,
        }
        .into_completion();
        let open_drain = state
            .complete_ordered_fsp_open_for_test(open_completion.ticket, open_completion.result)
            .expect("oldest worker-open completion should drain itself and buffered local open");
        assert_eq!(open_drain.ready, 2);
        assert_eq!(open_drain.accepted, 2);
        assert_eq!(open_drain.replay_drops, 0);
        assert_eq!(open_drain.outputs.len(), 2);
        match (&open_drain.outputs[0], &open_drain.outputs[1]) {
            (
                FspReadyCompletion::Opened {
                    opened: worker_opened,
                    ..
                },
                FspReadyCompletion::Opened {
                    opened: local_opened,
                    ..
                },
            ) => {
                assert_eq!(worker_opened.plaintext_len, open_plaintext_len);
                assert_eq!(local_opened.plaintext_len, local_plaintext_len);
            }
            _ => panic!("worker-open and local completions should both authenticate"),
        }
    }

    #[test]
    fn fsp_aead_open_receive_window_tracks_owner_ready_progress() {
        let shared = FspSharedCryptoSession::new(
            0,
            7,
            false,
            Arc::new(test_chacha_key([0x55; 32])),
        );
        let receive_window = fsp_receive_window();

        for expected in 0..receive_window as u64 {
            let ticket = shared
                .try_issue_ticket()
                .expect("window should admit initial worker-open tickets");
            assert_eq!(ticket.sequence, expected);
        }
        assert!(
            !shared.can_issue_ticket(),
            "full ordered-completion window must stop worker-open admission"
        );
        assert!(
            shared.try_issue_ticket().is_none(),
            "full ordered-completion window must not allocate unbounded tickets"
        );

        shared.mark_next_ready(1);
        assert!(
            shared.can_issue_ticket(),
            "owner completion progress should reopen worker-open admission"
        );
        let ticket = shared
            .try_issue_ticket()
            .expect("one completed ticket should free one worker-open slot");
        assert_eq!(ticket.sequence, receive_window as u64);
    }

    #[test]
    fn fsp_owner_completion_marks_attached_shared_ready_progress() {
        let source_peer = test_source_peer();
        let cipher = test_chacha_key([0x56; 32]);
        let mut state = OwnedFspSessionState::from(crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher,
                replay: ReplayWindow::new(),
            },
            pending: None,
            previous: None,
        });
        let shared = Arc::new(
            state
                .shared_crypto_session(0)
                .expect("single-current FSP session should expose shared crypto"),
        );
        state.attach_shared_crypto_session(Arc::clone(&shared));

        let receive_window = fsp_receive_window();
        let first_ticket = shared
            .try_issue_ticket()
            .expect("shared worker-open window should admit the first ticket");
        for expected in 1..receive_window as u64 {
            let ticket = shared
                .try_issue_ticket()
                .expect("shared worker-open window should admit initial tickets");
            assert_eq!(ticket.sequence, expected);
        }
        assert!(
            shared.try_issue_ticket().is_none(),
            "full shared window should block further worker-open tickets"
        );

        let drain = state
            .complete_ordered_fsp_open_for_test(
                first_ticket,
                FspOrderedCompletion::Dropped {
                    source: FspAeadCompletionSource::WorkerOpen,
                },
            )
            .expect("oldest completion should fit the receive-order window");
        assert_eq!(drain.ready, 1);
        assert!(
            shared.try_issue_ticket().is_none(),
            "ordered-owner progress should not reach shared open admission until it is marked"
        );

        state.mark_shared_crypto_ready_progress();
        let reopened = shared
            .try_issue_ticket()
            .expect("owner progress should reopen shared worker-open admission");
        assert_eq!(reopened.sequence, receive_window as u64);
    }

    #[test]
    fn fsp_owner_completion_batches_share_one_ordered_drain() {
        let source_peer = test_source_peer();
        let source_addr = *source_peer.node_addr();
        let mut state = OwnedFspSessionState::from(crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: test_chacha_key([0x57; 32]),
                replay: ReplayWindow::new(),
            },
            pending: None,
            previous: None,
        });
        let shared = Arc::new(
            state
                .shared_crypto_session(0)
                .expect("single-current FSP session should expose shared crypto"),
        );
        state.attach_shared_crypto_session(Arc::clone(&shared));
        let receive_order_id = state.fsp_receive_order_id();
        let tickets = [
            shared.try_issue_ticket().expect("ticket 0"),
            shared.try_issue_ticket().expect("ticket 1"),
            shared.try_issue_ticket().expect("ticket 2"),
        ];

        let pool = DecryptWorkerPool::spawn(1);
        let mut shard = DecryptWorkerShard::new(pool);
        shard.fsp_sessions.insert(source_addr, state);
        let mut plaintext_batch = DecryptPlaintextFallbackBatch::new();

        shard.handle_fsp_aead_completion_batch_msg(
            0,
            FspAeadCompletionBatch::one(FspAeadCompletion {
                source_addr,
                receive_order_id,
                ticket: tickets[0],
                source: FspAeadCompletionSource::WorkerOpen,
                result: FspOrderedCompletion::Dropped {
                    source: FspAeadCompletionSource::WorkerOpen,
                },
                completed_at: None,
            }),
            &mut plaintext_batch,
        );
        let state = shard
            .fsp_sessions
            .get(&source_addr)
            .expect("owner state should remain registered");
        assert_eq!(state.fsp_receive_order_next_ready(), 1);
        assert_eq!(shared.progress().next_ready, 1);

        shard.handle_fsp_aead_completion_batch_msg(
            0,
            FspAeadCompletionBatch::Many {
                source_addr,
                receive_order_id,
                completions: vec![
                    FspAeadCompletion {
                        source_addr,
                        receive_order_id,
                        ticket: tickets[1],
                        source: FspAeadCompletionSource::WorkerOpen,
                        result: FspOrderedCompletion::Dropped {
                            source: FspAeadCompletionSource::WorkerOpen,
                        },
                        completed_at: None,
                    },
                    FspAeadCompletion {
                        source_addr,
                        receive_order_id,
                        ticket: tickets[2],
                        source: FspAeadCompletionSource::WorkerOpen,
                        result: FspOrderedCompletion::Dropped {
                            source: FspAeadCompletionSource::WorkerOpen,
                        },
                        completed_at: None,
                    },
                ],
            },
            &mut plaintext_batch,
        );
        let state = shard
            .fsp_sessions
            .get(&source_addr)
            .expect("owner state should remain registered");
        assert_eq!(state.fsp_receive_order_next_ready(), 3);
        assert_eq!(shared.progress().next_ready, 3);
    }

    #[test]
    fn worker_direct_hop_tun_delivery_waits_for_commit_queue_acceptance() {
        let source_peer = test_source_peer();
        let source_addr = *source_peer.node_addr();
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let (tun_tx, tun_rx) = std::sync::mpsc::channel();
        let mut ipv6 = vec![0u8; 48];
        ipv6[0] = 0x60;
        ipv6[1] = 0x20;

        let commit = DecryptDirectSessionCommit::for_test(
            DecryptFmpBookkeeping {
                source_peer,
                transport_id: TransportId::new(1),
                remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                packet_timestamp_ms: 1_000,
                packet_len: ipv6.len(),
                fmp_counter: 9,
                inner_timestamp_ms: 10,
                fmp_flags: 0,
            },
            source_addr,
            source_peer,
            true,
            FspReceiveSync {
                counter: 7,
                slot: EpochSlot::Current,
                received_k_bit: false,
                timestamp: 0x0102_0304,
                plaintext_len: FSP_HEADER_SIZE + ipv6.len(),
                ce_flag: true,
                path_mtu: 1_280,
                spin_bit: false,
            },
            ipv6.len(),
            true,
        );
        let output = DecryptWorkerOutput {
            fallback_tx,
            event: DecryptWorkerEvent::DirectSessionCommit(commit),
            direct_delivery: Some(PendingDirectSessionDelivery {
                sink: DecryptDirectSessionDeliverySink::new(Some(tun_tx), None, None),
                source_addr,
                source_peer,
                ce_flag: true,
                delivery: DecryptDirectSessionDelivery::Ipv6Packet(ipv6),
            }),
        };

        assert!(
            tun_rx.try_recv().is_err(),
            "direct TUN bytes must wait until the commit is queued"
        );
        assert!(output.send(), "commit queue should accept direct commit");

        match fallback_rx
            .authenticated_bulk
            .try_recv()
            .expect("commit event")
        {
            DecryptWorkerEvent::DirectSessionCommit(commit) => {
                assert_eq!(commit.source_addr, source_addr);
                assert!(commit.delivered_ipv6);
            }
            other => panic!(
                "expected direct commit event, got {:?}",
                other.packet_count()
            ),
        }
        let delivered = tun_rx.try_recv().expect("TUN packet delivered");
        assert_eq!(delivered[1] & 0x30, 0x30, "CE mark should be applied");
    }

    #[test]
    fn decrypt_worker_direct_tun_batch_waits_for_commit_queue_acceptance() {
        let source_peer = test_source_peer();
        let source_addr = *source_peer.node_addr();
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let (tun_tx, tun_rx) = std::sync::mpsc::channel();
        let mut batch = DecryptPlaintextFallbackBatch::new();

        let mut first = vec![0u8; 48];
        first[0] = 0x60;
        first[1] = 0x20;
        let mut second = vec![0u8; 48];
        second[0] = 0x60;

        batch.push_output(dummy_direct_tun_output(
            fallback_tx.clone(),
            tun_tx.clone(),
            source_peer,
            1,
            first,
            true,
        ));
        assert!(
            fallback_rx.authenticated_bulk.try_recv().is_err(),
            "first direct TUN completion should wait for a batch flush"
        );
        assert!(
            tun_rx.try_recv().is_err(),
            "direct TUN bytes must not release before the commit is queued"
        );

        batch.push_output(dummy_direct_tun_output(
            fallback_tx,
            tun_tx,
            source_peer,
            2,
            second,
            false,
        ));
        assert!(
            fallback_rx.authenticated_bulk.try_recv().is_err(),
            "second direct TUN completion should still wait below batch cap"
        );
        assert!(
            tun_rx.try_recv().is_err(),
            "direct TUN bytes must still wait below batch cap"
        );
        batch.flush();

        let event = fallback_rx
            .authenticated_bulk
            .try_recv()
            .expect("direct TUN commit batch");
        assert_eq!(event.packet_count(), 2);
        match &event {
            DecryptWorkerEvent::DirectSessionCommitBatch(commits) => {
                assert_eq!(commits.len(), 2);
                assert_eq!(commits[0].source_addr, source_addr);
                assert_eq!(commits[1].source_addr, source_addr);
                assert_eq!(commits[0].fmp.fmp_counter, 1);
                assert_eq!(commits[1].fmp.fmp_counter, 2);
                assert!(commits.iter().all(|commit| commit.delivered_ipv6));
            }
            DecryptWorkerEvent::DirectSessionCommit(_) => panic!("expected a commit batch"),
            _ => panic!("expected a direct TUN commit batch"),
        }
        fallback_rx.release_dequeued_event(&event);

        let delivered_first = tun_rx.try_recv().expect("first TUN packet delivered");
        assert_eq!(
            delivered_first[1] & 0x30,
            0x30,
            "CE mark should be applied to first packet"
        );
        let delivered_second = tun_rx.try_recv().expect("second TUN packet delivered");
        assert_eq!(
            delivered_second[1] & 0x30,
            0x00,
            "non-CE packet should not be marked"
        );
    }

    #[test]
    fn decrypt_worker_direct_tun_batch_drops_delivery_when_authenticated_lane_is_full() {
        let source_peer = test_source_peer();
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 1);
        let (tun_tx, tun_rx) = std::sync::mpsc::channel();

        let mut first_batch = DecryptPlaintextFallbackBatch::new();
        first_batch.push_output(dummy_direct_tun_output(
            fallback_tx.clone(),
            tun_tx.clone(),
            source_peer,
            1,
            vec![0x60; 48],
            false,
        ));
        first_batch.flush();
        assert_eq!(fallback_rx.authenticated_bulk_queued_packets(), 1);
        tun_rx
            .try_recv()
            .expect("first accepted direct TUN delivery");

        let mut second_batch = DecryptPlaintextFallbackBatch::new();
        second_batch.push_output(dummy_direct_tun_output(
            fallback_tx,
            tun_tx,
            source_peer,
            2,
            vec![0x60; 48],
            false,
        ));
        second_batch.flush();

        assert!(
            tun_rx.try_recv().is_err(),
            "direct TUN bytes must not release when their authenticated commit lane is full"
        );

        let event = fallback_rx
            .authenticated_bulk
            .try_recv()
            .expect("first accepted direct TUN commit");
        assert_eq!(event.packet_count(), 1);
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.authenticated_bulk_queued_packets(), 0);
        assert!(
            fallback_rx.authenticated_bulk.try_recv().is_err(),
            "rejected direct TUN commit must not enqueue after pressure rejection"
        );
    }

    #[test]
    fn worker_drops_replayed_fsp_without_rx_loop_fallback() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let previous_hop = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let previous_hop_peer = PeerIdentity::from_pubkey_full(previous_hop.pubkey_full());
        let (mut fsp_sender, fsp_receiver) = test_xk_session_pair(&source, &local);
        let inner_plaintext = crate::node::session_wire::fsp_prepend_inner_header(
            0x0102_0304,
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0x01,
            b"direct endpoint",
        );
        let fsp_counter = fsp_sender.current_send_counter();
        let fsp_header = crate::node::session_wire::build_fsp_header(
            fsp_counter,
            0,
            inner_plaintext.len() as u16,
        );
        let fsp_ciphertext = fsp_sender
            .encrypt_with_aad(&inner_plaintext, &fsp_header)
            .unwrap();
        let mut fsp_payload = Vec::with_capacity(fsp_header.len() + fsp_ciphertext.len());
        fsp_payload.extend_from_slice(&fsp_header);
        fsp_payload.extend_from_slice(&fsp_ciphertext);
        let datagram = crate::protocol::SessionDatagram::new(
            *source.node_addr(),
            *local.node_addr(),
            fsp_payload,
        );
        let mut fmp_plaintext = Vec::new();
        fmp_plaintext.extend_from_slice(&0x0a0b_0c0d_u32.to_le_bytes());
        fmp_plaintext.extend_from_slice(&datagram.encode());

        let fmp_key_bytes = [0x44; 32];
        let fmp_seal = test_chacha_key(fmp_key_bytes);
        let fmp_open = test_chacha_key(fmp_key_bytes);
        let (wire_a, header_a) =
            sealed_fmp_test_packet_with_plaintext(&fmp_seal, 77, 0, &fmp_plaintext);
        let (wire_b, header_b) =
            sealed_fmp_test_packet_with_plaintext(&fmp_seal, 78, 0, &fmp_plaintext);
        let session_key = test_session_key(1, 9);
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);

        let (pool, _control, _priority, _bulk) = test_worker_pool(1, 8);
        let mut shard = DecryptWorkerShard::new(pool);
        shard.register_session(
            0,
            session_key,
            OwnedSessionState::new(fmp_open, ReplayWindow::new(), previous_hop_peer),
        );
        let fsp_snapshot = crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: fsp_receiver.recv_cipher_clone().unwrap(),
                replay: fsp_receiver.recv_replay_snapshot_owned(),
            },
            pending: None,
            previous: None,
        };
        shard.register_fsp_session(
            0,
            *source.node_addr(),
            OwnedFspSessionState::from(fsp_snapshot),
        );

        let mut first = DecryptJob::new(
            wire_a,
            session_key,
            0,
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *local.node_addr(),
            1_000,
            77,
            0,
            header_a,
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
            fallback_tx.clone(),
        );
        first.lane = DecryptWorkerLane::Bulk;
        let mut second = DecryptJob::new(
            wire_b,
            session_key,
            0,
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *local.node_addr(),
            1_000,
            78,
            0,
            header_b,
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
            fallback_tx,
        );
        second.lane = DecryptWorkerLane::Bulk;

        shard
            .handle_job(first)
            .expect("first worker job should not fail");
        assert!(matches!(
            fallback_rx
                .authenticated_bulk
                .try_recv()
                .expect("first FSP frame should authenticate"),
            DecryptWorkerEvent::DirectSessionData(_)
        ));
        shard
            .handle_job(second)
            .expect("second worker job should not fail");
        assert!(
            fallback_rx.authenticated_bulk.try_recv().is_err()
                && fallback_rx.bulk.try_recv().is_err(),
            "FSP replay must not bounce into rx-loop decrypt failure accounting"
        );
        assert_eq!(
            shard.fmp_replay_highest(session_key),
            Some(78),
            "outer FMP replay still advances independently"
        );
    }

    #[test]
    fn worker_falls_back_to_rx_loop_on_fsp_aead_failure() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let previous_hop = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let previous_hop_peer = PeerIdentity::from_pubkey_full(previous_hop.pubkey_full());
        let (mut fsp_sender, fsp_receiver) = test_xk_session_pair(&source, &local);
        let inner_plaintext = crate::node::session_wire::fsp_prepend_inner_header(
            0x0102_0304,
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0x01,
            b"bad inner tag",
        );
        let fsp_counter = fsp_sender.current_send_counter();
        let fsp_header = crate::node::session_wire::build_fsp_header(
            fsp_counter,
            0,
            inner_plaintext.len() as u16,
        );
        let mut fsp_ciphertext = fsp_sender
            .encrypt_with_aad(&inner_plaintext, &fsp_header)
            .unwrap();
        let last = fsp_ciphertext
            .last_mut()
            .expect("ciphertext includes authentication tag");
        *last ^= 0x80;
        let mut fsp_payload = Vec::with_capacity(fsp_header.len() + fsp_ciphertext.len());
        fsp_payload.extend_from_slice(&fsp_header);
        fsp_payload.extend_from_slice(&fsp_ciphertext);
        let datagram = crate::protocol::SessionDatagram::new(
            *source.node_addr(),
            *local.node_addr(),
            fsp_payload,
        );
        let inner_timestamp_ms = 0x0a0b_0c0d_u32;
        let mut fmp_plaintext = Vec::new();
        fmp_plaintext.extend_from_slice(&inner_timestamp_ms.to_le_bytes());
        fmp_plaintext.extend_from_slice(&datagram.encode());

        let fmp_key_bytes = [0x55; 32];
        let fmp_seal = test_chacha_key(fmp_key_bytes);
        let fmp_open = test_chacha_key(fmp_key_bytes);
        let fmp_counter = 77;
        let (wire, fmp_header) =
            sealed_fmp_test_packet_with_plaintext(&fmp_seal, fmp_counter, 0, &fmp_plaintext);
        let session_key = test_session_key(1, 9);
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let mut job = DecryptJob::new(
            wire,
            session_key,
            0,
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *local.node_addr(),
            1_000,
            fmp_counter,
            0,
            fmp_header,
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
            fallback_tx,
        );
        job.lane = DecryptWorkerLane::Bulk;

        let (pool, _control, _priority, _bulk) = test_worker_pool(1, 8);
        let mut shard = DecryptWorkerShard::new(pool);
        shard.register_session(
            0,
            session_key,
            OwnedSessionState::new(fmp_open, ReplayWindow::new(), previous_hop_peer),
        );
        let fsp_snapshot = crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: fsp_receiver.recv_cipher_clone().unwrap(),
                replay: fsp_receiver.recv_replay_snapshot_owned(),
            },
            pending: None,
            previous: None,
        };
        shard.register_fsp_session(
            0,
            *source.node_addr(),
            OwnedFspSessionState::from(fsp_snapshot),
        );

        shard.handle_job(job).expect("worker job should not fail");
        let event = fallback_rx
            .priority
            .try_recv()
            .expect("FSP AEAD failure should return a plaintext fallback");
        match event {
            DecryptWorkerEvent::Plaintext(fallback) => {
                assert_eq!(fallback.source_peer, previous_hop_peer);
                assert_eq!(fallback.fmp_counter, fmp_counter);
                assert_eq!(fallback.fmp_flags, 0);
                assert_eq!(fallback.timestamp_ms, 1_000);
                assert_eq!(fallback.packet_len, fallback.packet_data.len());
            }
            DecryptWorkerEvent::PlaintextBatch(_)
            | DecryptWorkerEvent::FspDecryptFailure(_)
            | DecryptWorkerEvent::AuthenticatedFmpReceive(_)
            | DecryptWorkerEvent::AuthenticatedSession(_)
            | DecryptWorkerEvent::AuthenticatedSessionBatch(_)
            | DecryptWorkerEvent::DirectSessionCommit(_)
            | DecryptWorkerEvent::DirectSessionCommitBatch(_)
            | DecryptWorkerEvent::DirectSessionData(_)
            | DecryptWorkerEvent::DirectSessionDataBatch(_)
            | DecryptWorkerEvent::DecryptFailure(_) => {
                panic!("expected plaintext fallback")
            }
        }
    }

    #[test]
    fn worker_falls_back_to_rx_loop_on_multi_epoch_fsp_aead_failure() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let previous_hop = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let previous_hop_peer = PeerIdentity::from_pubkey_full(previous_hop.pubkey_full());
        let (mut fsp_sender, fsp_receiver) = test_xk_session_pair(&source, &local);
        let (_pending_sender, pending_receiver) = test_xk_session_pair(&source, &local);
        let inner_plaintext = crate::node::session_wire::fsp_prepend_inner_header(
            0x0102_0304,
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            0x01,
            b"bad multi epoch tag",
        );
        let fsp_counter = fsp_sender.current_send_counter();
        let fsp_header = crate::node::session_wire::build_fsp_header(
            fsp_counter,
            0,
            inner_plaintext.len() as u16,
        );
        let mut fsp_ciphertext = fsp_sender
            .encrypt_with_aad(&inner_plaintext, &fsp_header)
            .unwrap();
        let last = fsp_ciphertext
            .last_mut()
            .expect("ciphertext includes authentication tag");
        *last ^= 0x80;
        let mut fsp_payload = Vec::with_capacity(fsp_header.len() + fsp_ciphertext.len());
        fsp_payload.extend_from_slice(&fsp_header);
        fsp_payload.extend_from_slice(&fsp_ciphertext);
        let datagram = crate::protocol::SessionDatagram::new(
            *source.node_addr(),
            *local.node_addr(),
            fsp_payload,
        );
        let inner_timestamp_ms = 0x0a0b_0c0d_u32;
        let mut fmp_plaintext = Vec::new();
        fmp_plaintext.extend_from_slice(&inner_timestamp_ms.to_le_bytes());
        fmp_plaintext.extend_from_slice(&datagram.encode());

        let fmp_key_bytes = [0x56; 32];
        let fmp_seal = test_chacha_key(fmp_key_bytes);
        let fmp_open = test_chacha_key(fmp_key_bytes);
        let fmp_counter = 78;
        let (wire, fmp_header) =
            sealed_fmp_test_packet_with_plaintext(&fmp_seal, fmp_counter, 0, &fmp_plaintext);
        let session_key = test_session_key(1, 10);
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let mut job = DecryptJob::new(
            wire,
            session_key,
            0,
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *local.node_addr(),
            1_000,
            fmp_counter,
            0,
            fmp_header,
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
            fallback_tx,
        );
        job.lane = DecryptWorkerLane::Bulk;

        let (pool, _control, _priority, _bulk) = test_worker_pool(1, 8);
        let mut shard = DecryptWorkerShard::new(pool);
        shard.register_session(
            0,
            session_key,
            OwnedSessionState::new(fmp_open, ReplayWindow::new(), previous_hop_peer),
        );
        let fsp_snapshot = crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: fsp_receiver.recv_cipher_clone().unwrap(),
                replay: fsp_receiver.recv_replay_snapshot_owned(),
            },
            pending: Some(crate::node::session::FspRecvEpochSnapshot {
                cipher: pending_receiver.recv_cipher_clone().unwrap(),
                replay: pending_receiver.recv_replay_snapshot_owned(),
            }),
            previous: None,
        };
        shard.register_fsp_session(
            0,
            *source.node_addr(),
            OwnedFspSessionState::from(fsp_snapshot),
        );

        shard.handle_job(job).expect("worker job should not fail");
        let event = fallback_rx
            .priority
            .try_recv()
            .expect("multi-epoch FSP AEAD failure should fall back to rx_loop");
        match event {
            DecryptWorkerEvent::Plaintext(fallback) => {
                assert_eq!(fallback.source_peer, previous_hop_peer);
                assert_eq!(fallback.fmp_counter, fmp_counter);
                assert_eq!(fallback.fmp_flags, 0);
                assert_eq!(fallback.timestamp_ms, 1_000);
                assert_eq!(fallback.packet_len, fallback.packet_data.len());
            }
            DecryptWorkerEvent::PlaintextBatch(_)
            | DecryptWorkerEvent::FspDecryptFailure(_)
            | DecryptWorkerEvent::AuthenticatedFmpReceive(_)
            | DecryptWorkerEvent::AuthenticatedSession(_)
            | DecryptWorkerEvent::AuthenticatedSessionBatch(_)
            | DecryptWorkerEvent::DirectSessionCommit(_)
            | DecryptWorkerEvent::DirectSessionCommitBatch(_)
            | DecryptWorkerEvent::DirectSessionData(_)
            | DecryptWorkerEvent::DirectSessionDataBatch(_)
            | DecryptWorkerEvent::DecryptFailure(_) => {
                panic!("expected plaintext fallback")
            }
        }
    }

    #[test]
    fn worker_drops_malformed_registered_fsp_without_plaintext_fallback() {
        let local = crate::Identity::generate();
        let source = crate::Identity::generate();
        let previous_hop = crate::Identity::generate();
        let source_peer = PeerIdentity::from_pubkey_full(source.pubkey_full());
        let previous_hop_peer = PeerIdentity::from_pubkey_full(previous_hop.pubkey_full());
        let (_fsp_sender, fsp_receiver) = test_xk_session_pair(&source, &local);
        let mut fsp_payload = crate::node::session_wire::build_fsp_header(7, 0, 0).to_vec();
        fsp_payload.truncate(crate::node::session_wire::FSP_COMMON_PREFIX_SIZE);
        let datagram = crate::protocol::SessionDatagram::new(
            *source.node_addr(),
            *local.node_addr(),
            fsp_payload,
        );
        let inner_timestamp_ms = 0x0a0b_0c0d_u32;
        let mut fmp_plaintext = Vec::new();
        fmp_plaintext.extend_from_slice(&inner_timestamp_ms.to_le_bytes());
        fmp_plaintext.extend_from_slice(&datagram.encode());

        let fmp_key_bytes = [0x57; 32];
        let fmp_seal = test_chacha_key(fmp_key_bytes);
        let fmp_open = test_chacha_key(fmp_key_bytes);
        let fmp_counter = 79;
        let (wire, fmp_header) =
            sealed_fmp_test_packet_with_plaintext(&fmp_seal, fmp_counter, 0, &fmp_plaintext);
        let session_key = test_session_key(1, 11);
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let mut job = DecryptJob::new(
            wire,
            session_key,
            0,
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *local.node_addr(),
            1_000,
            fmp_counter,
            0,
            fmp_header,
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
            fallback_tx,
        );
        job.lane = DecryptWorkerLane::Bulk;

        let (pool, _control, _priority, _bulk) = test_worker_pool(1, 8);
        let mut shard = DecryptWorkerShard::new(pool);
        shard.register_session(
            0,
            session_key,
            OwnedSessionState::new(fmp_open, ReplayWindow::new(), previous_hop_peer),
        );
        let fsp_snapshot = crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: fsp_receiver.recv_cipher_clone().unwrap(),
                replay: fsp_receiver.recv_replay_snapshot_owned(),
            },
            pending: None,
            previous: None,
        };
        shard.register_fsp_session(
            0,
            *source.node_addr(),
            OwnedFspSessionState::from(fsp_snapshot),
        );

        shard.handle_job(job).expect("worker job should not fail");
        let event = fallback_rx
            .authenticated_bulk
            .try_recv()
            .expect("malformed FSP should still record authenticated FMP receive");
        match event {
            DecryptWorkerEvent::AuthenticatedFmpReceive(receive) => {
                assert_eq!(receive.fmp.source_peer, previous_hop_peer);
                assert_eq!(receive.fmp.fmp_counter, fmp_counter);
                assert_eq!(receive.fmp.inner_timestamp_ms, inner_timestamp_ms);
            }
            DecryptWorkerEvent::Plaintext(_) | DecryptWorkerEvent::PlaintextBatch(_) => {
                panic!("malformed registered FSP must not bounce plaintext")
            }
            DecryptWorkerEvent::FspDecryptFailure(_) => {
                panic!("malformed FSP without an encrypted header has no FSP counter to report")
            }
            DecryptWorkerEvent::AuthenticatedSession(_)
            | DecryptWorkerEvent::AuthenticatedSessionBatch(_)
            | DecryptWorkerEvent::DirectSessionCommit(_)
            | DecryptWorkerEvent::DirectSessionCommitBatch(_)
            | DecryptWorkerEvent::DirectSessionData(_)
            | DecryptWorkerEvent::DirectSessionDataBatch(_)
            | DecryptWorkerEvent::DecryptFailure(_) => {
                panic!("expected authenticated FMP bookkeeping event")
            }
        }
    }

    #[test]
    fn registered_fmp_owner_routes_registration_jobs_and_unregister_to_same_worker() {
        let (pool, control_receivers, priority_receivers, bulk_receivers) =
            test_worker_pool(4, 4);
        let source_peer = test_source_peer();
        let owner = pool.worker_idx_for_fsp(source_peer.node_addr());
        let session_key = (0..128)
            .map(|receiver_idx| test_session_key(7, receiver_idx))
            .find(|key| pool.worker_idx_for(*key) != owner)
            .expect("test should find a session-key hash that differs from source owner");
        let hash_owner = pool.worker_idx_for(session_key);

        let mut pre_registration_job = dummy_priority_decrypt_job(session_key);
        pre_registration_job.worker_idx = hash_owner;
        pool.dispatch_job(pre_registration_job);
        match priority_receivers[hash_owner]
            .try_recv()
            .expect("pre-registration packet should use hash fallback")
        {
            WorkerMsg::Job(job) => assert_eq!(job.session_key, session_key),
            WorkerMsg::RegisterSession { .. }
            | WorkerMsg::FspJob(_)
            | WorkerMsg::RegisterFspSession { .. }
            | WorkerMsg::UnregisterSession { .. }
            | WorkerMsg::UnregisterFspSession { .. } => {
                panic!("expected pre-registration priority job")
            }
        }

        assert_eq!(
            pool.register_session(session_key, test_owned_session_state_for(source_peer)),
            Some(owner)
        );
        let mut registered_job = dummy_priority_decrypt_job(session_key);
        registered_job.worker_idx = owner;
        pool.dispatch_job(registered_job);
        assert!(pool.unregister_session(session_key));

        match control_receivers[owner]
            .try_recv()
            .expect("registration should reach owner")
        {
            WorkerMsg::RegisterSession {
                session_key: queued_key,
                ..
            } => assert_eq!(queued_key, session_key),
            WorkerMsg::Job(_)
            | WorkerMsg::FspJob(_)
            | WorkerMsg::RegisterFspSession { .. }
            | WorkerMsg::UnregisterSession { .. }
            | WorkerMsg::UnregisterFspSession { .. } => {
                panic!("expected registration first")
            }
        }
        match priority_receivers[owner]
            .try_recv()
            .expect("priority packet should reach same owner")
        {
            WorkerMsg::Job(job) => assert_eq!(job.session_key, session_key),
            WorkerMsg::RegisterSession { .. }
            | WorkerMsg::FspJob(_)
            | WorkerMsg::RegisterFspSession { .. }
            | WorkerMsg::UnregisterSession { .. }
            | WorkerMsg::UnregisterFspSession { .. } => {
                panic!("expected priority job second")
            }
        }
        match control_receivers[owner]
            .try_recv()
            .expect("unregister should reach same owner")
        {
            WorkerMsg::UnregisterSession {
                session_key: queued_key,
            } => {
                assert_eq!(queued_key, session_key);
            }
            WorkerMsg::RegisterSession { .. }
            | WorkerMsg::RegisterFspSession { .. }
            | WorkerMsg::Job(_)
            | WorkerMsg::FspJob(_)
            | WorkerMsg::UnregisterFspSession { .. } => {
                panic!("expected unregister third")
            }
        }

        let mut post_unregister_job = dummy_priority_decrypt_job(session_key);
        post_unregister_job.worker_idx = hash_owner;
        pool.dispatch_job(post_unregister_job);
        match priority_receivers[hash_owner]
            .try_recv()
            .expect("post-unregister packet should use hash fallback")
        {
            WorkerMsg::Job(job) => assert_eq!(job.session_key, session_key),
            WorkerMsg::RegisterSession { .. }
            | WorkerMsg::FspJob(_)
            | WorkerMsg::RegisterFspSession { .. }
            | WorkerMsg::UnregisterSession { .. }
            | WorkerMsg::UnregisterFspSession { .. } => {
                panic!("expected post-unregister priority job")
            }
        }

        for (idx, rx) in control_receivers.iter().enumerate() {
            if idx != owner {
                assert!(
                    rx.is_empty(),
                    "other worker {idx} must not receive this session key control item"
                );
            }
        }
        for (idx, rx) in priority_receivers.iter().enumerate() {
            if idx != owner && idx != hash_owner {
                assert!(
                    rx.is_empty(),
                    "other worker {idx} must not receive this session key priority item"
                );
            }
        }
        assert!(
            bulk_receivers.iter().all(Receiver::is_empty),
            "priority session-key dispatch must not consume bulk lanes"
        );
    }
