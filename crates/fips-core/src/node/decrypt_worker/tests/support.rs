    use super::*;
    use crate::noise::ReplayWindow;
    use crossbeam_channel::bounded;
    use ring::aead::{LessSafeKey, UnboundKey};
    use std::time::Duration;

    #[test]
    fn decrypt_worker_channel_cap_prefers_specific_then_shared_value() {
        assert_eq!(parse_channel_cap(Some("4"), Some("8"), 1024), 4);
        assert_eq!(parse_channel_cap(None, Some("8"), 1024), 8);
        assert_eq!(parse_channel_cap(Some("bad"), Some("9"), 1024), 9);
        assert_eq!(parse_channel_cap(Some("0"), None, 1024), 1);
        assert_eq!(parse_channel_cap(Some("999999"), None, 1024), 1024);
    }

    #[test]
    fn decrypt_fallback_bulk_cap_ignores_shared_worker_cap() {
        assert_eq!(
            parse_channel_cap(None, Some("4"), DEFAULT_DECRYPT_WORKER_BULK_CHANNEL_CAP),
            4
        );
        assert_eq!(
            fallback_bulk_channel_cap_from_raw(None),
            DEFAULT_DECRYPT_FALLBACK_BULK_CHANNEL_CAP
        );
        assert_eq!(fallback_bulk_channel_cap_from_raw(Some("4")), 4);
    }

    #[test]
    fn decrypt_worker_priority_packet_classifier_keeps_small_packets_reserved() {
        assert_eq!(
            decrypt_worker_packet_lane(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN),
            DecryptWorkerLane::Priority
        );
        assert_eq!(
            decrypt_worker_packet_lane(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1),
            DecryptWorkerLane::Bulk
        );
    }

    #[test]
    fn decrypt_worker_batch_stats_counts_packet_work_without_control_messages() {
        let session_key = test_session_key(1, 17);
        let mut stats = DecryptWorkerBatchStats::enabled_for_test();
        let register = WorkerMsg::RegisterSession {
            session_key,
            state: test_owned_session_state(),
        };
        stats.add_msg(&register);
        assert_eq!(stats.packets, 0);
        assert_eq!(stats.priority_packets, 0);
        assert_eq!(stats.bulk_packets, 0);

        let priority_job = WorkerMsg::Job(dummy_priority_decrypt_job(session_key));
        stats.add_msg(&priority_job);
        let bulk_fsp_job =
            WorkerMsg::FspJob(dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1));
        stats.add_msg(&bulk_fsp_job);
        let bulk_batch = DecryptWorkerBulkItem::Batch(vec![
            dummy_bulk_decrypt_job(session_key),
            dummy_bulk_decrypt_job(session_key),
        ]);
        stats.add_bulk_item(&bulk_batch);

        assert_eq!(stats.packets, 4);
        assert_eq!(stats.priority_packets, 1);
        assert_eq!(stats.bulk_packets, 3);
    }

    fn one_slot_worker_pool() -> (
        DecryptWorkerPool,
        Receiver<WorkerMsg>,
        Receiver<DecryptWorkerBulkItem>,
    ) {
        let (priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (bulk_tx, bulk_rx) = bounded::<DecryptWorkerBulkItem>(1);
        let bulk_queued_packets = Arc::new(AtomicUsize::new(0));
        (
            DecryptWorkerPool {
                senders: std::sync::Arc::from(
                    vec![DecryptWorkerSender {
                        priority: priority_tx,
                        bulk: bulk_tx,
                        bulk_queued_packets,
                        bulk_packet_cap: 1,
                    }]
                    .into_boxed_slice(),
                ),
                direct_delivery_sink: DecryptDirectSessionDeliverySink::default(),
            },
            priority_rx,
            bulk_rx,
        )
    }

    fn test_worker_pool(
        worker_count: usize,
        cap: usize,
    ) -> (
        DecryptWorkerPool,
        Vec<Receiver<WorkerMsg>>,
        Vec<Receiver<DecryptWorkerBulkItem>>,
    ) {
        let mut senders = Vec::with_capacity(worker_count);
        let mut priority_receivers = Vec::with_capacity(worker_count);
        let mut bulk_receivers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let (priority_tx, priority_rx) = bounded::<WorkerMsg>(cap);
            let (bulk_tx, bulk_rx) = bounded::<DecryptWorkerBulkItem>(cap);
            let bulk_queued_packets = Arc::new(AtomicUsize::new(0));
            senders.push(DecryptWorkerSender {
                priority: priority_tx,
                bulk: bulk_tx,
                bulk_queued_packets,
                bulk_packet_cap: cap,
            });
            priority_receivers.push(priority_rx);
            bulk_receivers.push(bulk_rx);
        }
        (
            DecryptWorkerPool {
                senders: std::sync::Arc::from(senders.into_boxed_slice()),
                direct_delivery_sink: DecryptDirectSessionDeliverySink::default(),
            },
            priority_receivers,
            bulk_receivers,
        )
    }

    fn test_bulk_lane(
        cap: usize,
    ) -> (
        Sender<DecryptWorkerBulkItem>,
        Receiver<DecryptWorkerBulkItem>,
        Arc<AtomicUsize>,
    ) {
        let (bulk_tx, bulk_rx) = bounded::<DecryptWorkerBulkItem>(cap);
        let bulk_queued_packets = Arc::new(AtomicUsize::new(0));
        (bulk_tx, bulk_rx, bulk_queued_packets)
    }

    fn queue_bulk_item_for_test(
        tx: &Sender<DecryptWorkerBulkItem>,
        queued_packets: &AtomicUsize,
        item: DecryptWorkerBulkItem,
    ) {
        queued_packets.fetch_add(item.packet_count(), Ordering::Relaxed);
        tx.try_send(item).expect("test bulk queue should have room");
    }

    fn test_shard() -> DecryptWorkerShard {
        let (pool, _priority, _bulk) = test_worker_pool(1, 8);
        DecryptWorkerShard::new(pool)
    }

    fn test_source_peer() -> PeerIdentity {
        PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full())
    }

    fn test_owned_session_state() -> OwnedSessionState {
        let key_bytes = [7u8; 32];
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        OwnedSessionState {
            fmp_cipher: LessSafeKey::new(unbound),
            fmp_replay: ReplayWindow::new(),
            source_peer: test_source_peer(),
        }
    }

    #[test]
    fn owned_session_state_carries_authenticated_source_peer() {
        let source_peer = test_source_peer();
        let key_bytes = [8u8; 32];
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        let state = OwnedSessionState {
            fmp_cipher: LessSafeKey::new(unbound),
            fmp_replay: ReplayWindow::new(),
            source_peer,
        };

        assert_eq!(state.source_peer, source_peer);
    }

    fn test_session_key(transport_id: u32, receiver_idx: u32) -> DecryptSessionKey {
        DecryptSessionKey::new(TransportId::new(transport_id), receiver_idx)
    }

    fn dummy_decrypt_job_with_len(session_key: DecryptSessionKey, packet_len: usize) -> DecryptJob {
        let packet_len = packet_len.max(crate::node::wire::ESTABLISHED_HEADER_SIZE + 16);
        let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        DecryptJob::new(
            vec![0; packet_len],
            session_key,
            session_key.transport_id,
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *test_source_peer().node_addr(),
            1_000,
            1,
            0,
            [0u8; crate::node::wire::ESTABLISHED_HEADER_SIZE],
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
            fallback_tx,
        )
    }

    fn dummy_bulk_decrypt_job(session_key: DecryptSessionKey) -> DecryptJob {
        dummy_decrypt_job_with_len(session_key, DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1)
    }

    fn dummy_priority_decrypt_job(session_key: DecryptSessionKey) -> DecryptJob {
        dummy_decrypt_job_with_len(session_key, DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN)
    }

    fn dummy_plaintext_event(packet_len: usize) -> DecryptWorkerEvent {
        DecryptWorkerEvent::Plaintext(DecryptFallback::new(
            test_source_peer(),
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            1_000,
            packet_len,
            1,
            0,
            vec![0; packet_len.max(1)],
            0,
            1,
        ))
    }

    fn dummy_plaintext_batch_event(count: usize, packet_len: usize) -> DecryptWorkerEvent {
        DecryptWorkerEvent::PlaintextBatch(
            (0..count)
                .map(|idx| {
                    DecryptFallback::new(
                        test_source_peer(),
                        TransportId::new(1),
                        crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                        1_000,
                        packet_len,
                        idx as u64,
                        0,
                        vec![0; packet_len.max(1)],
                        0,
                        1,
                    )
                })
                .collect(),
        )
    }

    fn dummy_failure_event() -> DecryptWorkerEvent {
        DecryptWorkerEvent::DecryptFailure(DecryptFailureReport {
            source_peer: test_source_peer(),
            fmp_counter: 2,
            fmp_replay_highest: 1,
            trace_enqueued_at: None,
        })
    }

    fn dummy_direct_endpoint_output(
        fallback_tx: DecryptWorkerFallbackSender,
        sink: DecryptDirectSessionDeliverySink,
        source_peer: PeerIdentity,
        fmp_counter: u64,
        payload: &[u8],
    ) -> DecryptWorkerOutput {
        let source_addr = *source_peer.node_addr();
        let payload_len = payload.len();
        let commit = DecryptDirectSessionCommit::for_test(
            DecryptFmpBookkeeping {
                source_peer,
                transport_id: TransportId::new(1),
                remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                packet_timestamp_ms: 1_000,
                packet_len: payload_len,
                fmp_counter,
                inner_timestamp_ms: fmp_counter as u32,
                fmp_flags: 0,
            },
            source_addr,
            source_peer,
            false,
            FspReceiveSync {
                counter: fmp_counter,
                slot: EpochSlot::Current,
                received_k_bit: false,
                timestamp: fmp_counter as u32,
                plaintext_len: payload_len,
                ce_flag: false,
                path_mtu: 1_280,
                spin_bit: false,
            },
            payload_len,
            false,
        );

        DecryptWorkerOutput {
            fallback_tx,
            event: DecryptWorkerEvent::DirectSessionCommit(commit),
            direct_delivery: Some(PendingDirectSessionDelivery {
                sink,
                source_addr,
                source_peer,
                ce_flag: false,
                delivery: DecryptDirectSessionDelivery::EndpointData(EndpointDataDelivery::new(
                    source_peer,
                    payload.to_vec(),
                )),
            }),
        }
    }

    fn dummy_direct_tun_output(
        fallback_tx: DecryptWorkerFallbackSender,
        tun_tx: TunTx,
        source_peer: PeerIdentity,
        fmp_counter: u64,
        mut ipv6: Vec<u8>,
        ce_flag: bool,
    ) -> DecryptWorkerOutput {
        let source_addr = *source_peer.node_addr();
        let payload_len = ipv6.len();
        let commit = DecryptDirectSessionCommit::for_test(
            DecryptFmpBookkeeping {
                source_peer,
                transport_id: TransportId::new(1),
                remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                packet_timestamp_ms: 1_000,
                packet_len: payload_len,
                fmp_counter,
                inner_timestamp_ms: fmp_counter as u32,
                fmp_flags: 0,
            },
            source_addr,
            source_peer,
            ce_flag,
            FspReceiveSync {
                counter: fmp_counter,
                slot: EpochSlot::Current,
                received_k_bit: false,
                timestamp: fmp_counter as u32,
                plaintext_len: payload_len,
                ce_flag,
                path_mtu: 1_280,
                spin_bit: false,
            },
            payload_len,
            true,
        );
        if ipv6.is_empty() {
            ipv6.resize(48, 0);
            ipv6[0] = 0x60;
        }

        DecryptWorkerOutput {
            fallback_tx,
            event: DecryptWorkerEvent::DirectSessionCommit(commit),
            direct_delivery: Some(PendingDirectSessionDelivery {
                sink: DecryptDirectSessionDeliverySink::new(Some(tun_tx), None, None),
                source_addr,
                source_peer,
                ce_flag,
                delivery: DecryptDirectSessionDelivery::Ipv6Packet(ipv6),
            }),
        }
    }

    #[test]
    fn decrypt_worker_return_drop_metric_splits_fallback_and_authenticated_outputs() {
        let bulk_len = DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1;
        let plaintext = dummy_plaintext_event(bulk_len);
        assert_eq!(
            decrypt_worker_event_drop_event(&plaintext, plaintext.lane()),
            crate::perf_profile::Event::DecryptFallbackBulkDropped
        );

        let failure = dummy_failure_event();
        assert_eq!(
            decrypt_worker_event_drop_event(&failure, failure.lane()),
            crate::perf_profile::Event::DecryptFallbackPriorityDropped
        );

        let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        let (endpoint_tx, _endpoint_rx) = EndpointEventSender::channel(1);
        let sink = DecryptDirectSessionDeliverySink::new(None, None, Some(endpoint_tx));
        let source_peer = test_source_peer();
        let bulk_payload = vec![0x55; bulk_len];
        let output = dummy_direct_endpoint_output(fallback_tx, sink, source_peer, 7, &bulk_payload);
        assert_eq!(
            decrypt_worker_event_drop_event(&output.event, output.event.lane()),
            crate::perf_profile::Event::DecryptAuthenticatedSessionBulkDropped
        );

        let DecryptWorkerEvent::DirectSessionCommit(mut commit) = output.event else {
            panic!("expected direct session commit");
        };
        commit.lane = DecryptWorkerLane::Priority;
        let priority_commit = DecryptWorkerEvent::DirectSessionCommit(commit);
        assert_eq!(
            decrypt_worker_event_drop_event(&priority_commit, priority_commit.lane()),
            crate::perf_profile::Event::DecryptAuthenticatedSessionPriorityDropped
        );
    }

    fn dummy_fsp_job(packet_len: usize) -> FspDecryptJob {
        let source_peer = test_source_peer();
        let (fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        FspDecryptJob {
            fallback_tx,
            fallback: DecryptFallback::new(
                test_source_peer(),
                TransportId::new(1),
                crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                1_000,
                packet_len,
                1,
                0,
                vec![0; packet_len.max(1)],
                0,
                1,
            ),
            local_node_addr: *test_source_peer().node_addr(),
            source_addr: *source_peer.node_addr(),
            previous_hop_peer: test_source_peer(),
            path_mtu: 1_280,
            ce_flag: false,
            inner_timestamp_ms: 2,
            fsp_payload_offset: 0,
            fsp_payload_len: 0,
            trace_enqueued_at: None,
        }
    }

    fn dummy_authenticated_session_event(lane: DecryptWorkerLane) -> DecryptWorkerEvent {
        let source_peer = test_source_peer();
        let previous_hop_peer = test_source_peer();
        DecryptWorkerEvent::AuthenticatedSession(DecryptAuthenticatedSession {
            fmp: DecryptFmpBookkeeping {
                source_peer: previous_hop_peer,
                transport_id: TransportId::new(1),
                remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                packet_timestamp_ms: 1_000,
                packet_len: 128,
                fmp_counter: 2,
                inner_timestamp_ms: 3,
                fmp_flags: 0,
            },
            source_addr: *source_peer.node_addr(),
            previous_hop_peer,
            ce_flag: false,
            message: AuthenticatedSessionMessage::new(source_peer, vec![0; 8], 0x01, 0, 4),
            receive_sync: FspReceiveSync {
                counter: 5,
                slot: EpochSlot::Current,
                received_k_bit: false,
                timestamp: 4,
                plaintext_len: 8,
                ce_flag: false,
                path_mtu: 1_280,
                spin_bit: false,
            },
            lane,
            trace_enqueued_at: None,
        })
    }

    fn test_chacha_key(key_bytes: [u8; 32]) -> LessSafeKey {
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        LessSafeKey::new(unbound)
    }

    fn test_xk_session_pair(
        sender: &crate::Identity,
        receiver: &crate::Identity,
    ) -> (crate::noise::NoiseSession, crate::noise::NoiseSession) {
        let mut initiator = crate::noise::HandshakeState::new_xk_initiator(
            sender.keypair(),
            receiver.pubkey_full(),
        );
        let mut responder = crate::noise::HandshakeState::new_xk_responder(receiver.keypair());
        initiator.set_local_epoch([1u8; 8]);
        responder.set_local_epoch([2u8; 8]);
        let msg1 = initiator.write_xk_message_1().unwrap();
        responder.read_xk_message_1(&msg1).unwrap();
        let msg2 = responder.write_xk_message_2().unwrap();
        initiator.read_xk_message_2(&msg2).unwrap();
        let msg3 = initiator.write_xk_message_3().unwrap();
        responder.read_xk_message_3(&msg3).unwrap();
        (
            initiator.into_session().unwrap(),
            responder.into_session().unwrap(),
        )
    }

    fn sealed_fmp_test_packet(
        cipher: &LessSafeKey,
        counter: u64,
        flags: u8,
    ) -> (Vec<u8>, [u8; crate::node::wire::ESTABLISHED_HEADER_SIZE]) {
        sealed_fmp_test_packet_with_link_body(cipher, counter, flags, 1)
    }

    fn sealed_fmp_test_packet_with_link_body(
        cipher: &LessSafeKey,
        counter: u64,
        flags: u8,
        link_body_len: usize,
    ) -> (Vec<u8>, [u8; crate::node::wire::ESTABLISHED_HEADER_SIZE]) {
        const HDR: usize = crate::node::wire::ESTABLISHED_HEADER_SIZE;
        let mut header = [0u8; HDR];
        header[1] = flags;
        let link_body_len = link_body_len.max(1);
        let mut wire = Vec::with_capacity(HDR + 4 + link_body_len + 16);
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&[0u8; 4]);
        wire.push(0xAB);
        wire.resize(HDR + 4 + link_body_len, 0xCD);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = ring::aead::Nonce::assume_unique_for_key(nonce_bytes);
        let (hdr_slice, payload_slice) = wire.split_at_mut(HDR);
        let tag = cipher
            .seal_in_place_separate_tag(nonce, ring::aead::Aad::from(&*hdr_slice), payload_slice)
            .unwrap();
        wire.extend_from_slice(tag.as_ref());
        (wire, header)
    }

    fn sealed_fmp_test_packet_with_plaintext(
        cipher: &LessSafeKey,
        counter: u64,
        flags: u8,
        plaintext: &[u8],
    ) -> (Vec<u8>, [u8; crate::node::wire::ESTABLISHED_HEADER_SIZE]) {
        const HDR: usize = crate::node::wire::ESTABLISHED_HEADER_SIZE;
        let mut header = [0u8; HDR];
        header[1] = flags;
        let mut wire = Vec::with_capacity(HDR + plaintext.len() + 16);
        wire.extend_from_slice(&header);
        wire.extend_from_slice(plaintext);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = ring::aead::Nonce::assume_unique_for_key(nonce_bytes);
        let (hdr_slice, payload_slice) = wire.split_at_mut(HDR);
        let tag = cipher
            .seal_in_place_separate_tag(nonce, ring::aead::Aad::from(&*hdr_slice), payload_slice)
            .unwrap();
        wire.extend_from_slice(tag.as_ref());
        (wire, header)
    }

    fn invalid_fmp_test_packet(
        flags: u8,
    ) -> (Vec<u8>, [u8; crate::node::wire::ESTABLISHED_HEADER_SIZE]) {
        const HDR: usize = crate::node::wire::ESTABLISHED_HEADER_SIZE;
        let mut header = [0u8; HDR];
        header[1] = flags;
        let mut wire = Vec::with_capacity(HDR + 4 + 1 + 16);
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&[0u8; 4]);
        wire.push(0xAB);
        wire.extend_from_slice(&[0u8; 16]);
        (wire, header)
    }

    fn decrypt_job_for_test_packet(
        packet_data: Vec<u8>,
        header: [u8; crate::node::wire::ESTABLISHED_HEADER_SIZE],
        session_key: DecryptSessionKey,
        fmp_counter: u64,
        fmp_flags: u8,
        fallback_tx: DecryptWorkerFallbackSender,
    ) -> DecryptJob {
        DecryptJob::new(
            packet_data,
            session_key,
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *test_source_peer().node_addr(),
            1_000,
            fmp_counter,
            fmp_flags,
            header,
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
            fallback_tx,
        )
    }

    #[test]
    fn decrypt_session_fast_hash_distinguishes_transport_and_receiver() {
        let baseline = test_session_key(7, 42);
        assert_ne!(
            decrypt_session_fast_hash(baseline),
            decrypt_session_fast_hash(test_session_key(8, 42)),
            "transport id must participate in worker routing"
        );
        assert_ne!(
            decrypt_session_fast_hash(baseline),
            decrypt_session_fast_hash(test_session_key(7, 43)),
            "receiver index must participate in worker routing"
        );

        let mut buckets = [0usize; 8];
        for transport_id in 1..=8 {
            for receiver_idx in 1..=64 {
                let worker =
                    (decrypt_session_fast_hash(test_session_key(transport_id, receiver_idx))
                        as usize)
                        % buckets.len();
                buckets[worker] += 1;
            }
        }
        assert!(
            buckets.iter().all(|count| *count > 0),
            "common session keys should spread across all workers: {buckets:?}"
        );
    }
