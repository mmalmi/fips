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
        let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let job = DecryptJob::new(
            wire,
            session_key,
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

        let (pool, _priority, _bulk) = test_worker_pool(1, 8);
        let mut shard = DecryptWorkerShard::new(pool);
        shard.register_session(
            0,
            session_key,
            OwnedSessionState {
                fmp_cipher: fmp_open,
                fmp_replay: ReplayWindow::new(),
                source_peer: previous_hop_peer,
            },
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

        let output = shard
            .handle_job_output(0, job)
            .expect("worker job should not fail")
            .expect("direct FSP path should emit an event");
        match output.event {
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
                assert_eq!(direct.body_len, b"direct endpoint".len());
                assert!(direct.receive_sync.spin_bit);
                match direct.delivery {
                    DecryptDirectSessionDelivery::EndpointData(delivery) => {
                        assert_eq!(delivery.source_peer, source_peer);
                        assert_eq!(delivery.payload, b"direct endpoint");
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
        let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);

        let (pool, _priority, _bulk) = test_worker_pool(1, 8);
        let mut shard = DecryptWorkerShard::new(pool);
        shard.register_session(
            0,
            session_key,
            OwnedSessionState {
                fmp_cipher: fmp_open,
                fmp_replay: ReplayWindow::new(),
                source_peer: previous_hop_peer,
            },
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

        let first = DecryptJob::new(
            wire_a,
            session_key,
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
        let second = DecryptJob::new(
            wire_b,
            session_key,
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

        assert!(matches!(
            shard
                .handle_job_output(0, first)
                .expect("first worker job should not fail")
                .expect("first FSP frame should authenticate")
                .event,
            DecryptWorkerEvent::DirectSessionData(_)
        ));
        assert!(
            shard
                .handle_job_output(0, second)
                .expect("second worker job should not fail")
                .is_none(),
            "FSP replay must not bounce into rx-loop decrypt failure accounting"
        );
        assert_eq!(
            shard.fmp_replay_highest(session_key),
            Some(78),
            "outer FMP replay still advances independently"
        );
    }

    #[test]
    fn worker_reports_fsp_aead_failure_without_plaintext_fallback() {
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
        let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let job = DecryptJob::new(
            wire,
            session_key,
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

        let (pool, _priority, _bulk) = test_worker_pool(1, 8);
        let mut shard = DecryptWorkerShard::new(pool);
        shard.register_session(
            0,
            session_key,
            OwnedSessionState {
                fmp_cipher: fmp_open,
                fmp_replay: ReplayWindow::new(),
                source_peer: previous_hop_peer,
            },
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

        let output = shard
            .handle_job_output(0, job)
            .expect("worker job should not fail")
            .expect("FSP AEAD failure should report to rx_loop");
        match output.event {
            DecryptWorkerEvent::FspDecryptFailure(report) => {
                assert_eq!(report.source_addr, *source.node_addr());
                assert_eq!(report.counter, fsp_counter);
                assert_eq!(report.fmp.source_peer, previous_hop_peer);
                assert_eq!(report.fmp.fmp_counter, fmp_counter);
                assert_eq!(report.fmp.inner_timestamp_ms, inner_timestamp_ms);
            }
            DecryptWorkerEvent::Plaintext(_) | DecryptWorkerEvent::PlaintextBatch(_) => {
                panic!("FSP AEAD failure must not bounce a possibly mutated packet")
            }
            DecryptWorkerEvent::AuthenticatedFmpReceive(_)
            | DecryptWorkerEvent::AuthenticatedSession(_)
            | DecryptWorkerEvent::DirectSessionCommit(_)
            | DecryptWorkerEvent::DirectSessionCommitBatch(_)
            | DecryptWorkerEvent::DirectSessionData(_)
            | DecryptWorkerEvent::DecryptFailure(_) => {
                panic!("expected FSP decrypt failure report")
            }
        }
    }

    #[test]
    fn decrypt_session_key_routes_registration_jobs_and_unregister_to_same_worker() {
        let (pool, priority_receivers, bulk_receivers) = test_worker_pool(4, 4);
        let session_key = test_session_key(7, 42);
        let owner = pool.worker_idx_for(session_key);

        assert!(pool.register_session(session_key, test_owned_session_state()));
        pool.dispatch_job(dummy_priority_decrypt_job(session_key));
        assert!(pool.unregister_session(session_key));

        match priority_receivers[owner]
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
        match priority_receivers[owner]
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

        for (idx, rx) in priority_receivers.iter().enumerate() {
            if idx != owner {
                assert!(
                    rx.is_empty(),
                    "other worker {idx} must not receive this session key"
                );
            }
        }
        assert!(
            bulk_receivers.iter().all(Receiver::is_empty),
            "priority session-key dispatch must not consume bulk lanes"
        );
    }
