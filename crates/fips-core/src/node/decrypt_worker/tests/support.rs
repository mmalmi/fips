    use super::*;
    use crate::noise::ReplayWindow;
    use crate::packet_mover::OwnerReceiveWindow;
    use crossbeam_channel::bounded;
    use ring::aead::{LessSafeKey, UnboundKey};
    use std::time::Duration;

    fn test_fsp_crypto_ticket(
        source_addr: NodeAddr,
        receive_order_id: u64,
        crypto_generation: u64,
        sequence: u64,
    ) -> CryptoTicket {
        let source = OwnerReceiveReservationSource::new(
            OwnerKey::Fsp { source_addr },
            OwnerGeneration(crypto_generation),
            receive_order_id,
        );
        CryptoTicket {
            reservation: source.reservation_for_sequence(sequence, PacketLane::Bulk, 1),
        }
    }

    fn test_fsp_crypto_ticket_for_receive_ticket(
        source_addr: NodeAddr,
        receive_order_id: u64,
        crypto_generation: u64,
        ticket: FspReceiveTicket,
    ) -> CryptoTicket {
        test_fsp_crypto_ticket(
            source_addr,
            receive_order_id,
            crypto_generation,
            ticket.sequence,
        )
    }

    #[test]
    fn decrypt_worker_channel_cap_prefers_specific_then_shared_value() {
        assert_eq!(parse_channel_cap(Some("4"), Some("8"), 1024), 4);
        assert_eq!(parse_channel_cap(None, Some("8"), 1024), 8);
        assert_eq!(parse_channel_cap(Some("bad"), Some("9"), 1024), 9);
        assert_eq!(parse_channel_cap(Some("0"), None, 1024), 1);
        assert_eq!(parse_channel_cap(Some("999999"), None, 1024), 1024);
    }

    #[test]
    fn decrypt_return_bulk_cap_ignores_shared_worker_cap() {
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
    fn fsp_aead_completion_batch_width_matches_benchmarked_bulk_width() {
        assert_eq!(
            DEFAULT_DECRYPT_WORKER_FSP_AEAD_COMPLETION_BATCH_MAX,
            DECRYPT_WORKER_AEAD_COMPLETION_INTERLEAVE_BUDGET
        );
    }

    #[test]
    fn fsp_aead_completion_channel_covers_ordered_receive_window() {
        assert_eq!(
            fsp_aead_completion_channel_cap_from_bulk_cap(0),
            fsp_receive_window_from_bulk_cap(0)
        );
        assert_eq!(
            fsp_aead_completion_channel_cap_from_bulk_cap(1),
            1 + DECRYPT_WORKER_FSP_RECEIVE_WINDOW_RESERVE
        );
        assert_eq!(
            fsp_aead_completion_channel_cap_from_bulk_cap(DEFAULT_DECRYPT_WORKER_BULK_CHANNEL_CAP),
            fsp_receive_window_from_bulk_cap(DEFAULT_DECRYPT_WORKER_BULK_CHANNEL_CAP)
        );
    }

    #[test]
    fn fsp_encrypted_payload_parser_rejects_payload_length_mismatch() {
        let header_bytes = crate::node::session_wire::build_fsp_header(1, 0, 0);
        let mut packet = header_bytes.to_vec();
        packet.extend_from_slice(&[0u8; crate::noise::TAG_SIZE]);

        assert!(DecryptWorkerShard::parse_fsp_encrypted_payload(&packet, 0, packet.len()).is_some());

        packet[2..4].copy_from_slice(&1u16.to_le_bytes());
        assert!(
            DecryptWorkerShard::parse_fsp_encrypted_payload(&packet, 0, packet.len()).is_none(),
            "length-inconsistent FSP payloads must be malformed before ticket/open handling"
        );
    }

    #[test]
    fn fsp_aead_opener_returns_rejected_payload_for_owner_retire() {
        let source_addr = *test_source_peer().node_addr();
        let header_bytes = crate::node::session_wire::build_fsp_header(1, 0, 0);
        let mut packet = header_bytes.to_vec();
        packet.extend_from_slice(&[0u8; crate::noise::TAG_SIZE]);
        let header = FspEncryptedHeader::parse(&packet).expect("test FSP header");
        let mut job = dummy_fsp_job(packet.len());
        job.source_addr = source_addr;
        job.fallback.packet_data = packet.clone().into();
        job.fsp_payload_offset = 0;
        job.fsp_payload_len = packet.len();

        let mut opener = FspAeadOpener;
        let completion = opener.execute(CryptoWork {
            ticket: test_fsp_crypto_ticket(source_addr, 7, 11, 0),
            work: FspAeadOpenWork {
                cipher: Arc::new(test_chacha_key([0x67; 32])),
                job,
                header,
                epoch_id: 0,
            },
        });

        match completion.result {
            CryptoResult::RejectedWith {
                reject: CryptoReject::Aead,
                value,
            } => {
                assert!(value.count_failure);
            }
            _ => panic!("expected payload-carrying AEAD rejection"),
        }
    }

    #[test]
    fn ordered_receive_window_buffers_until_oldest_completion_is_ready() {
        let mut window = OwnerReceiveWindow::new(4);
        let first = window.issue().expect("first ticket");
        let second = window.issue().expect("second ticket");
        let third = window.issue().expect("third ticket");
        assert_eq!(first.sequence, 0);
        assert_eq!(second.sequence, 1);
        assert_eq!(third.sequence, 2);

        let mut ready = Vec::new();
        assert_eq!(
            window
                .complete(second, "second", |ticket, completion| ready
                    .push((ticket.sequence, completion)))
                .expect("second completion should buffer"),
            0
        );
        assert!(ready.is_empty());

        assert_eq!(
            window
                .complete(third, "third", |ticket, completion| ready
                    .push((ticket.sequence, completion)))
                .expect("third completion should buffer behind first"),
            0
        );
        assert!(ready.is_empty());

        assert_eq!(
            window
                .complete(first, "first", |ticket, completion| ready
                    .push((ticket.sequence, completion)))
                .expect("first completion should drain all ready completions"),
            3
        );
        assert_eq!(ready, vec![(0, "first"), (1, "second"), (2, "third")]);
        assert_eq!(window.next_ready(), 3);
    }

    #[test]
    fn ordered_receive_window_bounds_inflight_tickets() {
        let mut window = OwnerReceiveWindow::<&'static str>::new(2);
        let first = window.issue().expect("first ticket");
        let second = window.issue().expect("second ticket");
        assert!(
            window.issue().is_none(),
            "full receive window must not admit unbounded work"
        );

        assert!(matches!(
            window.complete(second, "second", |_, _| {}),
            Ok(0)
        ));
        assert!(
            window.issue().is_none(),
            "out-of-order completion must not free the oldest receive slot"
        );

        assert!(matches!(
            window.complete(first, "first", |_, _| {}),
            Ok(2)
        ));
        let third = window
            .issue()
            .expect("ready progress should reopen one receive slot");
        assert_eq!(third.sequence, 2);
    }

    #[test]
    fn ordered_receive_window_bulk_reserve_leaves_unreserved_tickets() {
        let mut window = OwnerReceiveWindow::<&'static str>::new(4);
        assert_eq!(
            window
                .issue_batch_with_reserve(2, 2)
                .expect("bulk should fit before the reserve"),
            0
        );
        assert!(
            window.issue_with_reserve(2).is_none(),
            "bulk admission must stop before the reserved ticket slice"
        );
        assert_eq!(
            window
                .issue()
                .expect("unreserved owner ticket should still fit")
                .sequence,
            2
        );
        assert_eq!(
            window
                .issue()
                .expect("second unreserved owner ticket should still fit")
                .sequence,
            3
        );
        assert!(
            window.issue().is_none(),
            "the total ordered receive window remains bounded"
        );
    }

    #[test]
    fn fsp_receive_owner_reservations_share_one_order_stream() {
        let source_peer = test_source_peer();
        let mut state = OwnedFspSessionState::from(crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: test_chacha_key([0x72; 32]),
                replay: ReplayWindow::new(),
            },
            pending: None,
            previous: None,
        });
        let receive_order_id = state.fsp_receive_order_id();
        let crypto_generation = state.fsp_crypto_generation();

        let worker = state
            .reserve_worker_fsp_open()
            .expect("worker open should reserve first ticket");
        assert_eq!(worker.receive_order_id(), receive_order_id);
        assert_eq!(worker.crypto_generation(), crypto_generation);
        assert_eq!(worker.ticket().sequence, 0);
        let worker_owner = worker.owner_reservation();
        assert_eq!(worker_owner.owner, OwnerKey::Fsp {
            source_addr: *source_peer.node_addr()
        });
        assert_eq!(worker_owner.lane, PacketLane::Bulk);
        assert_eq!(worker_owner.packet_count, 1);

        let worker_batch = state
            .reserve_worker_fsp_open_batch(2)
            .expect("worker open batch should reserve adjacent tickets");
        assert_eq!(worker_batch.receive_order_id(), receive_order_id);
        assert_eq!(worker_batch.generation().0, crypto_generation);
        assert_eq!(worker_batch.first_sequence(), 1);
        assert_eq!(worker_batch.ticket_at(1).sequence, 2);
        let worker_batch_owner = worker_batch.owner_reservation();
        assert_eq!(worker_batch_owner.lane, PacketLane::Bulk);
        assert_eq!(worker_batch_owner.packet_count, 2);

        let local = state
            .reserve_local_fsp_open(DecryptWorkerLane::Priority)
            .expect("local owner open should reserve from the same stream");
        assert_eq!(local.receive_order_id(), receive_order_id);
        assert_eq!(local.crypto_generation(), crypto_generation);
        assert_eq!(local.ticket().sequence, 3);
        let local_owner = local.owner_reservation();
        assert_eq!(local_owner.lane, PacketLane::Priority);
        assert_eq!(local_owner.packet_count, 1);
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
    fn encrypted_fmp_decrypt_jobs_enter_worker_bulk_lane_even_when_small() {
        let session_key = test_session_key(1, 19);
        let job = dummy_decrypt_job_with_len(session_key, DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN);

        assert_eq!(decrypt_job_lane(&job), DecryptWorkerLane::Bulk);
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
        let bulk_fsp_batch = DecryptWorkerBulkItem::FspBatch(vec![dummy_fsp_job(
            DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1,
        )]);
        stats.add_bulk_item(&bulk_fsp_batch);
        let bulk_batch = decrypt_worker_bulk_item_from_jobs(vec![
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
        Receiver<WorkerMsg>,
        Receiver<DecryptWorkerBulkItem>,
    ) {
        let (control_tx, control_rx) = bounded::<WorkerMsg>(1);
        let (priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (bulk_tx, bulk_rx) = bounded::<DecryptWorkerBulkItem>(1);
        let (fsp_aead_completion_tx, _fsp_aead_completion_rx) =
            bounded::<FspAeadCompletionBatch>(1);
        let bulk_credits = LaneCreditGate::new(PacketLane::Bulk, 1);
        let bulk = BulkLanePrefixSender::new(bulk_tx, bulk_credits);
        let (return_tx, _return_rx) = decrypt_worker_return_channels_with_caps(1, 1);
        (
            DecryptWorkerPool {
                senders: std::sync::Arc::from(
                    vec![DecryptWorkerSender {
                        control: control_tx,
                        priority: priority_tx,
                        bulk,
                        fsp_aead_completion: fsp_aead_completion_tx,
                    }]
                    .into_boxed_slice(),
                ),
                direct_delivery_sink: DecryptDirectSessionDeliverySink::default(),
                return_tx,
            },
            control_rx,
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
        Vec<Receiver<WorkerMsg>>,
        Vec<Receiver<DecryptWorkerBulkItem>>,
    ) {
        let mut senders = Vec::with_capacity(worker_count);
        let mut control_receivers = Vec::with_capacity(worker_count);
        let mut priority_receivers = Vec::with_capacity(worker_count);
        let mut bulk_receivers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let (control_tx, control_rx) = bounded::<WorkerMsg>(cap);
            let (priority_tx, priority_rx) = bounded::<WorkerMsg>(cap);
            let (bulk_tx, bulk_rx) = bounded::<DecryptWorkerBulkItem>(cap);
            let (fsp_aead_completion_tx, _fsp_aead_completion_rx) =
                bounded::<FspAeadCompletionBatch>(cap);
            let bulk_credits = LaneCreditGate::new(PacketLane::Bulk, cap);
            senders.push(DecryptWorkerSender {
                control: control_tx,
                priority: priority_tx,
                bulk: BulkLanePrefixSender::new(bulk_tx, bulk_credits),
                fsp_aead_completion: fsp_aead_completion_tx,
            });
            control_receivers.push(control_rx);
            priority_receivers.push(priority_rx);
            bulk_receivers.push(bulk_rx);
        }
        let (return_tx, _return_rx) = decrypt_worker_return_channels_with_caps(cap, cap);
        (
            DecryptWorkerPool {
                senders: std::sync::Arc::from(senders.into_boxed_slice()),
                direct_delivery_sink: DecryptDirectSessionDeliverySink::default(),
                return_tx,
            },
            control_receivers,
            priority_receivers,
            bulk_receivers,
        )
    }

    fn test_worker_pool_with_fsp_completion_receivers(
        worker_count: usize,
        cap: usize,
    ) -> (
        DecryptWorkerPool,
        Vec<Receiver<WorkerMsg>>,
        Vec<Receiver<WorkerMsg>>,
        Vec<Receiver<DecryptWorkerBulkItem>>,
        Vec<Receiver<FspAeadCompletionBatch>>,
    ) {
        let mut senders = Vec::with_capacity(worker_count);
        let mut control_receivers = Vec::with_capacity(worker_count);
        let mut priority_receivers = Vec::with_capacity(worker_count);
        let mut bulk_receivers = Vec::with_capacity(worker_count);
        let mut fsp_completion_receivers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let (control_tx, control_rx) = bounded::<WorkerMsg>(cap);
            let (priority_tx, priority_rx) = bounded::<WorkerMsg>(cap);
            let (bulk_tx, bulk_rx) = bounded::<DecryptWorkerBulkItem>(cap);
            let (fsp_aead_completion_tx, fsp_aead_completion_rx) =
                bounded::<FspAeadCompletionBatch>(cap);
            let bulk_credits = LaneCreditGate::new(PacketLane::Bulk, cap);
            senders.push(DecryptWorkerSender {
                control: control_tx,
                priority: priority_tx,
                bulk: BulkLanePrefixSender::new(bulk_tx, bulk_credits),
                fsp_aead_completion: fsp_aead_completion_tx,
            });
            control_receivers.push(control_rx);
            priority_receivers.push(priority_rx);
            bulk_receivers.push(bulk_rx);
            fsp_completion_receivers.push(fsp_aead_completion_rx);
        }
        let (return_tx, _return_rx) = decrypt_worker_return_channels_with_caps(cap, cap);
        (
            DecryptWorkerPool {
                senders: std::sync::Arc::from(senders.into_boxed_slice()),
                direct_delivery_sink: DecryptDirectSessionDeliverySink::default(),
                return_tx,
            },
            control_receivers,
            priority_receivers,
            bulk_receivers,
            fsp_completion_receivers,
        )
    }

    fn test_bulk_lane(
        cap: usize,
    ) -> (
        Sender<DecryptWorkerBulkItem>,
        Receiver<DecryptWorkerBulkItem>,
        LaneCreditGate,
    ) {
        let (bulk_tx, bulk_rx) = bounded::<DecryptWorkerBulkItem>(cap);
        let bulk_credits = LaneCreditGate::new(PacketLane::Bulk, cap);
        (bulk_tx, bulk_rx, bulk_credits)
    }

    fn test_fsp_aead_completion_lane(cap: usize) -> Receiver<FspAeadCompletionBatch> {
        let (_completion_tx, completion_rx) = bounded::<FspAeadCompletionBatch>(cap);
        completion_rx
    }

    fn queue_bulk_item_for_test(
        tx: &Sender<DecryptWorkerBulkItem>,
        bulk_credits: &LaneCreditGate,
        item: DecryptWorkerBulkItem,
    ) {
        bulk_credits
            .reserve(item.packet_count(), 0)
            .expect("test bulk queue should have credit room");
        tx.try_send(item).expect("test bulk queue should have room");
    }

    fn test_shard() -> DecryptWorkerShard {
        let (pool, _control, _priority, _bulk) = test_worker_pool(1, 8);
        DecryptWorkerShard::new(pool)
    }

    #[test]
    fn fsp_open_worker_dispatch_avoids_owner_and_returns_ordered_completion() {
        let (pool, control_receivers, priority_receivers, bulk_receivers, fsp_completion_receivers) =
            test_worker_pool_with_fsp_completion_receivers(2, 4);
        let source_addr = NodeAddr::from_bytes([0x42; 16]);
        let owner_idx = 0;
        let open_idx = pool
            .worker_idx_for_fsp_open_avoiding(&source_addr, owner_idx)
            .expect("two-worker pool should have a sibling opener");
        assert_ne!(open_idx, owner_idx);

        let header_bytes = crate::node::session_wire::build_fsp_header(1, 0, 1);
        let mut header_packet = header_bytes.to_vec();
        header_packet.extend_from_slice(&[0u8; 16]);
        let header = FspEncryptedHeader::parse(&header_packet).expect("test FSP header");
        let job = test_fsp_aead_open_job(
            source_addr,
            0,
            Arc::new(test_chacha_key([0x54; 32])),
            header,
            None,
        );

        assert!(
            pool.dispatch_fsp_aead_open_worker_job_batch_or_return(open_idx, owner_idx, vec![job])
                .is_ok(),
            "opener bulk lane should admit the job"
        );
        assert!(control_receivers.iter().all(Receiver::is_empty));
        assert!(priority_receivers.iter().all(Receiver::is_empty));
        assert_eq!(bulk_receivers[open_idx].len(), 1);
        for (idx, rx) in bulk_receivers.iter().enumerate() {
            if idx != open_idx {
                assert!(rx.is_empty(), "worker {idx} should not receive opener work");
            }
        }

        let (control_tx, control_rx) = bounded::<WorkerMsg>(1);
        drop(control_tx);
        let (priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        drop(priority_tx);
        let opener_fsp_completion_rx = test_fsp_aead_completion_lane(1);
        let mut shard = DecryptWorkerShard::new(pool.clone());
        let mut return_batch = DecryptWorkerReturnBatch::new(shard.pool.return_tx.clone());
        let mut batch_stats = DecryptWorkerBatchStats::enabled_for_test();
        let item = bulk_receivers[open_idx]
            .try_recv()
            .expect("opener work should be queued");
        assert!(matches!(
            &item,
            DecryptWorkerBulkItem::FspAeadOpenBatch(jobs) if jobs.len() == 1
        ));
        handle_bulk_item(
            open_idx,
            &mut shard,
            &control_rx,
            &priority_rx,
            &opener_fsp_completion_rx,
            item,
            &mut return_batch,
            &mut batch_stats,
        );

        let completion = fsp_completion_receivers[owner_idx]
            .try_recv()
            .expect("owner should receive ordered FSP completion");
        assert_eq!(completion.len(), 1);
        assert!(fsp_completion_receivers[open_idx].try_recv().is_err());
    }

    #[test]
    fn fsp_open_worker_batch_dispatch_groups_jobs_and_returns_ordered_completion_batch() {
        let (pool, control_receivers, priority_receivers, bulk_receivers, fsp_completion_receivers) =
            test_worker_pool_with_fsp_completion_receivers(2, 4);
        let source_addr = NodeAddr::from_bytes([0x43; 16]);
        let owner_idx = 0;
        let open_idx = pool
            .worker_idx_for_fsp_open_avoiding(&source_addr, owner_idx)
            .expect("two-worker pool should have a sibling opener");
        assert_ne!(open_idx, owner_idx);

        let header_bytes = crate::node::session_wire::build_fsp_header(1, 0, 1);
        let mut header_packet = header_bytes.to_vec();
        header_packet.extend_from_slice(&[0u8; 16]);
        let header = FspEncryptedHeader::parse(&header_packet).expect("test FSP header");
        let cipher = Arc::new(test_chacha_key([0x55; 32]));
        let jobs = vec![
            test_fsp_aead_open_job(
                source_addr,
                0,
                Arc::clone(&cipher),
                header.clone(),
                None,
            ),
            test_fsp_aead_open_job(source_addr, 1, cipher, header, None),
        ];

        assert!(
            pool.dispatch_fsp_aead_open_worker_job_batch_or_return(open_idx, owner_idx, jobs)
                .is_ok(),
            "opener bulk lane should admit the job batch"
        );
        assert!(control_receivers.iter().all(Receiver::is_empty));
        assert!(priority_receivers.iter().all(Receiver::is_empty));
        assert_eq!(bulk_receivers[open_idx].len(), 1);
        let item = bulk_receivers[open_idx]
            .try_recv()
            .expect("opener batch work should be queued");
        match &item {
            DecryptWorkerBulkItem::FspAeadOpenBatch(jobs) => assert_eq!(jobs.len(), 2),
            DecryptWorkerBulkItem::Batch { .. }
            | DecryptWorkerBulkItem::FspBatch(_) => panic!("expected opener batch"),
        }

        let (control_tx, control_rx) = bounded::<WorkerMsg>(1);
        drop(control_tx);
        let (priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        drop(priority_tx);
        let opener_fsp_completion_rx = test_fsp_aead_completion_lane(1);
        let mut shard = DecryptWorkerShard::new(pool.clone());
        let mut return_batch = DecryptWorkerReturnBatch::new(shard.pool.return_tx.clone());
        let mut batch_stats = DecryptWorkerBatchStats::enabled_for_test();
        handle_bulk_item(
            open_idx,
            &mut shard,
            &control_rx,
            &priority_rx,
            &opener_fsp_completion_rx,
            item,
            &mut return_batch,
            &mut batch_stats,
        );

        let completion = fsp_completion_receivers[owner_idx]
            .try_recv()
            .expect("owner should receive ordered FSP completion batch");
        assert_eq!(completion.len(), 2);
        assert!(fsp_completion_receivers[open_idx].try_recv().is_err());
    }

    #[test]
    fn fsp_open_dispatch_batcher_flushes_single_job_as_one_item_batch() {
        let (pool, _control_receivers, _priority_receivers, bulk_receivers, _fsp_completion) =
            test_worker_pool_with_fsp_completion_receivers(2, DECRYPT_WORKER_BULK_BATCH_MAX);
        let source_addr = NodeAddr::from_bytes([0x42; 16]);
        let owner_idx = 0;
        let open_idx = pool
            .worker_idx_for_fsp_open_avoiding(&source_addr, owner_idx)
            .expect("two-worker pool should have a sibling opener");
        let header_bytes = crate::node::session_wire::build_fsp_header(1, 0, 1);
        let mut header_packet = header_bytes.to_vec();
        header_packet.extend_from_slice(&[0u8; 16]);
        let header = FspEncryptedHeader::parse(&header_packet).expect("test FSP header");
        let cipher = Arc::new(test_chacha_key([0x52; 32]));
        let mut batcher = new_fsp_aead_open_dispatch_batcher();

        let returned = push_fsp_aead_open_dispatch(
            &mut batcher,
            &pool,
            open_idx,
            owner_idx,
            test_fsp_aead_open_job(source_addr, 0, cipher, header, None),
        );
        assert!(returned.is_empty(), "single opener job should fit in the batcher");
        assert!(
            flush_fsp_aead_open_dispatch(&mut batcher, &pool).is_empty(),
            "single opener job should queue without returning to caller"
        );

        match bulk_receivers[open_idx]
            .try_recv()
            .expect("single opener job")
        {
            DecryptWorkerBulkItem::FspAeadOpenBatch(mut jobs) => {
                assert_eq!(jobs.len(), 1);
                let job = jobs.pop().expect("checked one opener job");
                assert_eq!(job.completion_owner_idx(), Some(owner_idx));
            }
            DecryptWorkerBulkItem::Batch { .. }
            | DecryptWorkerBulkItem::FspBatch(_) => panic!("expected a one-job opener batch"),
        }
    }

    #[test]
    fn aead_completion_interleave_keeps_pending_fsp_open_batch_together() {
        let (pool, _control_receivers, _priority_receivers, bulk_receivers, _fsp_completion) =
            test_worker_pool_with_fsp_completion_receivers(3, 8);
        let source_addr = NodeAddr::from_bytes([0x4b; 16]);
        let owner_idx = pool.worker_idx_for_fsp(&source_addr);
        let open_idx = pool
            .worker_idx_for_fsp_open_avoiding(&source_addr, owner_idx)
            .expect("three-worker pool should have a sibling opener");
        let header_bytes = crate::node::session_wire::build_fsp_header(1, 0, 1);
        let mut header_packet = header_bytes.to_vec();
        header_packet.extend_from_slice(&[0u8; 16]);
        let header = FspEncryptedHeader::parse(&header_packet).expect("test FSP header");
        let cipher = Arc::new(test_chacha_key([0x5b; 32]));
        let mut fsp_open_batcher = new_fsp_aead_open_dispatch_batcher();

        for sequence in 0..2 {
            let returned = push_fsp_aead_open_dispatch(
                &mut fsp_open_batcher,
                &pool,
                open_idx,
                owner_idx,
                test_fsp_aead_open_job(
                    source_addr,
                    sequence,
                    Arc::clone(&cipher),
                    header.clone(),
                    None,
                ),
            );
            assert!(
                returned.is_empty(),
                "pending opener jobs should fit in the local batcher"
            );
        }
        assert!(
            bulk_receivers.iter().all(Receiver::is_empty),
            "opener work should still be pending before explicit flush"
        );

        let mut shard = DecryptWorkerShard::new(pool.clone());
        let (fsp_completion_tx, fsp_aead_completion_rx) = bounded::<FspAeadCompletionBatch>(1);
        fsp_completion_tx
            .try_send(dummy_fsp_aead_completion_batch(source_addr, 99))
            .expect("test completion lane should have room");
        let mut return_batch = DecryptWorkerReturnBatch::new(shard.pool.return_tx.clone());
        let mut completion_interleave_budget = DECRYPT_WORKER_AEAD_COMPLETION_INTERLEAVE_BUDGET;

        drain_aead_completions_for_bulk_item(
            0,
            &mut shard,
            &fsp_aead_completion_rx,
            &mut return_batch,
            &mut completion_interleave_budget,
        );

        assert!(
            bulk_receivers.iter().all(Receiver::is_empty),
            "completion interleave should not fragment a pending opener batch"
        );
        assert!(
            flush_fsp_aead_open_dispatch(&mut fsp_open_batcher, &shard.pool).is_empty(),
            "explicit batch boundary should dispatch queued opener work"
        );
        match bulk_receivers[open_idx]
            .try_recv()
            .expect("opener work should dispatch at the batch boundary")
        {
            DecryptWorkerBulkItem::FspAeadOpenBatch(jobs) => assert_eq!(jobs.len(), 2),
            DecryptWorkerBulkItem::Batch { .. }
            | DecryptWorkerBulkItem::FspBatch(_) => panic!("expected opener batch"),
        }
    }

    #[test]
    fn fsp_owner_bulk_batch_dispatches_one_worker_open_batch() {
        let (pool, _control_receivers, _priority_receivers, bulk_receivers, _fsp_completion) =
            test_worker_pool_with_fsp_completion_receivers(3, DECRYPT_WORKER_BULK_BATCH_MAX);
        let source_peer = test_source_peer();
        let source_addr = *source_peer.node_addr();
        let owner_idx = pool.worker_idx_for_fsp(&source_addr);
        let cipher = test_chacha_key([0x5c; 32]);
        let state = OwnedFspSessionState::from(crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher,
                replay: ReplayWindow::new(),
            },
            pending: None,
            previous: None,
        });
        let receive_order_id = state.fsp_receive_order_id();
        let crypto_generation = state.fsp_crypto_generation();
        let open_idx = pool
            .worker_idx_for_fsp_open_avoiding(&source_addr, owner_idx)
            .expect("three-worker pool should have a sibling opener");

        let mut shard = DecryptWorkerShard::new(pool.clone());
        shard.register_fsp_session(owner_idx, source_addr, state);
        let (control_tx, control_rx) = bounded::<WorkerMsg>(1);
        drop(control_tx);
        let (priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        drop(priority_tx);
        let fsp_aead_completion_rx = test_fsp_aead_completion_lane(1);
        let mut return_batch = DecryptWorkerReturnBatch::new(shard.pool.return_tx.clone());
        let mut batch_stats = DecryptWorkerBatchStats::enabled_for_test();
        let item = DecryptWorkerBulkItem::FspBatch(vec![
            dummy_bulk_fsp_open_job(source_addr),
            dummy_bulk_fsp_open_job(source_addr),
        ]);
        batch_stats.add_bulk_item(&item);

        let processed = handle_bulk_item(
            owner_idx,
            &mut shard,
            &control_rx,
            &priority_rx,
            &fsp_aead_completion_rx,
            item,
            &mut return_batch,
            &mut batch_stats,
        );

        assert_eq!(processed, 2);
        match bulk_receivers[open_idx]
            .try_recv()
            .expect("owner FSP batch should dispatch one opener batch")
        {
            DecryptWorkerBulkItem::FspAeadOpenBatch(jobs) => {
                assert_eq!(jobs.len(), 2);
                assert!(
                    jobs.iter()
                        .all(|job| job.completion_owner_idx() == Some(owner_idx))
                );
                assert_eq!(
                    jobs.iter()
                        .map(|job| job.receive_ticket().sequence)
                        .collect::<Vec<_>>(),
                    vec![0, 1]
                );
                assert!(
                    jobs.iter()
                        .all(|job| job.receive_order_id() == receive_order_id
                            && job.crypto_generation() == crypto_generation)
                );
                assert!(
                    jobs.iter()
                        .all(|job| job.completion_source().is_worker_open())
                );
            }
            DecryptWorkerBulkItem::Batch { .. }
            | DecryptWorkerBulkItem::FspBatch(_) => panic!("expected opener batch"),
        }
        assert_eq!(
            shard
                .fsp_sessions
                .get(&source_addr)
                .expect("owner state should stay registered")
                .fsp_receive_order
                .next_ticket(),
            2
        );
    }

    #[test]
    fn fsp_preowner_bulk_hands_off_to_owner_before_opening() {
        let (pool, _control_receivers, _priority_receivers, bulk_receivers, _fsp_completion) =
            test_worker_pool_with_fsp_completion_receivers(4, DECRYPT_WORKER_BULK_BATCH_MAX);
        let source_addr = NodeAddr::from_bytes([0x62; 16]);
        let owner_idx = pool.worker_idx_for_fsp(&source_addr);
        let current_idx = (owner_idx + 1) % 4;

        let mut shard = DecryptWorkerShard::new(pool.clone());
        let mut return_batch = DecryptWorkerReturnBatch::new(shard.pool.return_tx.clone());
        let mut fsp_open_batcher = new_fsp_aead_open_dispatch_batcher();
        shard.push_job_action_output(
            current_idx,
            DecryptWorkerJobAction::FspJob(dummy_bulk_fsp_open_job(
                source_addr,
            )),
            &mut return_batch,
            None,
            &mut fsp_open_batcher,
        );
        assert!(
            flush_fsp_aead_open_dispatch(&mut fsp_open_batcher, &shard.pool).is_empty(),
            "pre-owner handoff must not leave opener work batched locally"
        );

        match bulk_receivers[owner_idx]
            .try_recv()
            .expect("pre-owner FSP packet should hand off to the owner")
        {
            DecryptWorkerBulkItem::FspBatch(mut jobs) => {
                assert_eq!(jobs.len(), 1);
                assert_eq!(
                    jobs.pop().expect("checked one owner handoff").source_addr,
                    source_addr
                );
            }
            DecryptWorkerBulkItem::FspAeadOpenBatch(_)
            | DecryptWorkerBulkItem::Batch { .. } => panic!("expected owner FSP job handoff"),
        }
        assert_eq!(
            bulk_receivers[current_idx].len(),
            0,
            "pre-owner opener dispatch should not loop back to the current worker"
        );
        for (idx, receiver) in bulk_receivers.iter().enumerate() {
            if idx != owner_idx {
                assert!(
                    receiver.is_empty(),
                    "pre-owner FSP packet must not enqueue opener work on worker {idx}"
                );
            }
        }
        assert!(return_batch.is_empty());
    }

    #[test]
    fn fsp_job_without_registered_owner_returns_authenticated_link() {
        let (return_tx, mut return_rx) = decrypt_worker_return_channels_with_caps(4, 4);
        let (pool, _control_receivers, _priority_receivers, _bulk_receivers, _fsp_completion) =
            test_worker_pool_with_fsp_completion_receivers(1, DECRYPT_WORKER_BULK_BATCH_MAX);
        let source_addr = NodeAddr::from_bytes([0x63; 16]);
        let mut shard = DecryptWorkerShard::new(pool);
        shard.pool.return_tx = return_tx.clone();
        let mut return_batch = DecryptWorkerReturnBatch::new(return_tx);
        let mut fsp_open_batcher = new_fsp_aead_open_dispatch_batcher();

        shard.push_job_action_output(
            0,
            DecryptWorkerJobAction::FspJob(dummy_bulk_fsp_open_job(source_addr)),
            &mut return_batch,
            None,
            &mut fsp_open_batcher,
        );
        assert!(
            flush_fsp_aead_open_dispatch(&mut fsp_open_batcher, &shard.pool).is_empty(),
            "missing FSP owner should return the authenticated link, not opener work"
        );
        return_batch.flush();

        let event = return_rx
            .authenticated_bulk
            .try_recv()
            .expect("missing FSP owner should return authenticated link");
        match event {
            DecryptWorkerEvent::AuthenticatedLink(link) => {
                assert_eq!(link.fmp_counter, 1);
                assert_eq!(
                    link.packet_len,
                    DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1
                );
            }
            other => panic!(
                "missing FSP owner should return authenticated link, got {} packet(s)",
                other.packet_count()
            ),
        }
    }

    #[test]
    fn fsp_owner_immediate_bulk_job_uses_worker_open() {
        let (pool, _control_receivers, _priority_receivers, bulk_receivers, _fsp_completion) =
            test_worker_pool_with_fsp_completion_receivers(3, DECRYPT_WORKER_BULK_BATCH_MAX);
        let source_peer = test_source_peer();
        let source_addr = *source_peer.node_addr();
        let owner_idx = pool.worker_idx_for_fsp(&source_addr);
        let cipher = test_chacha_key([0x5e; 32]);
        let state = OwnedFspSessionState::from(crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher,
                replay: ReplayWindow::new(),
            },
            pending: None,
            previous: None,
        });
        let receive_order_id = state.fsp_receive_order_id();
        let crypto_generation = state.fsp_crypto_generation();
        let open_idx = pool
            .worker_idx_for_fsp_open_avoiding(&source_addr, owner_idx)
            .expect("three-worker pool should have a sibling opener");

        let mut shard = DecryptWorkerShard::new(pool.clone());
        shard.register_fsp_session(owner_idx, source_addr, state);
        let mut return_batch = DecryptWorkerReturnBatch::new(shard.pool.return_tx.clone());
        let mut fsp_open_batcher = new_fsp_aead_open_dispatch_batcher();
        shard.push_job_action_output(
            owner_idx,
            DecryptWorkerJobAction::FspJob(dummy_bulk_fsp_open_job(
                source_addr,
            )),
            &mut return_batch,
            None,
            &mut fsp_open_batcher,
        );
        assert!(flush_fsp_aead_open_dispatch(&mut fsp_open_batcher, &shard.pool).is_empty());
        return_batch.flush();

        match bulk_receivers[open_idx]
            .try_recv()
            .expect("same-owner immediate bulk FSP job should use opener worker")
        {
            DecryptWorkerBulkItem::FspAeadOpenBatch(mut jobs) => {
                assert_eq!(jobs.len(), 1);
                let job = jobs.pop().expect("checked one opener job");
                assert_eq!(job.source_addr(), source_addr);
                assert_eq!(job.completion_owner_idx(), Some(owner_idx));
                assert_eq!(job.receive_order_id(), receive_order_id);
                assert_eq!(job.crypto_generation(), crypto_generation);
                assert_eq!(job.receive_ticket().sequence, 0);
                assert!(job.completion_source().is_worker_open());
            }
            DecryptWorkerBulkItem::Batch { .. }
            | DecryptWorkerBulkItem::FspBatch(_) => panic!("expected one-job opener batch"),
        }
        assert_eq!(
            shard
                .fsp_sessions
                .get(&source_addr)
                .expect("owner state should stay registered")
                .fsp_receive_order
                .next_ticket(),
            1
        );
    }

    #[test]
    fn fsp_owner_bulk_item_uses_worker_open() {
        let (pool, _control_receivers, _priority_receivers, bulk_receivers, _fsp_completion) =
            test_worker_pool_with_fsp_completion_receivers(3, DECRYPT_WORKER_BULK_BATCH_MAX);
        let source_peer = test_source_peer();
        let source_addr = *source_peer.node_addr();
        let owner_idx = pool.worker_idx_for_fsp(&source_addr);
        let cipher = test_chacha_key([0x63; 32]);
        let state = OwnedFspSessionState::from(crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher,
                replay: ReplayWindow::new(),
            },
            pending: None,
            previous: None,
        });
        let receive_order_id = state.fsp_receive_order_id();
        let crypto_generation = state.fsp_crypto_generation();
        let open_idx = pool
            .worker_idx_for_fsp_open_avoiding(&source_addr, owner_idx)
            .expect("three-worker pool should have a sibling opener");

        let mut shard = DecryptWorkerShard::new(pool.clone());
        shard.register_fsp_session(owner_idx, source_addr, state);
        let (control_tx, control_rx) = bounded::<WorkerMsg>(1);
        drop(control_tx);
        let (priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        drop(priority_tx);
        let fsp_aead_completion_rx = test_fsp_aead_completion_lane(1);
        let mut return_batch = DecryptWorkerReturnBatch::new(shard.pool.return_tx.clone());
        let mut batch_stats = DecryptWorkerBatchStats::enabled_for_test();
        let item = DecryptWorkerBulkItem::FspBatch(vec![dummy_bulk_fsp_open_job(source_addr)]);
        batch_stats.add_bulk_item(&item);

        let processed = handle_bulk_item(
            owner_idx,
            &mut shard,
            &control_rx,
            &priority_rx,
            &fsp_aead_completion_rx,
            item,
            &mut return_batch,
            &mut batch_stats,
        );

        assert_eq!(processed, 1);
        match bulk_receivers[open_idx]
            .try_recv()
            .expect("same-owner bulk FSP item should use opener worker")
        {
            DecryptWorkerBulkItem::FspAeadOpenBatch(mut jobs) => {
                assert_eq!(jobs.len(), 1);
                let job = jobs.pop().expect("checked one opener job");
                assert_eq!(job.source_addr(), source_addr);
                assert_eq!(job.completion_owner_idx(), Some(owner_idx));
                assert_eq!(job.receive_order_id(), receive_order_id);
                assert_eq!(job.crypto_generation(), crypto_generation);
                assert_eq!(job.receive_ticket().sequence, 0);
                assert!(job.completion_source().is_worker_open());
            }
            DecryptWorkerBulkItem::Batch { .. }
            | DecryptWorkerBulkItem::FspBatch(_) => panic!("expected one-job opener batch"),
        }
        assert_eq!(
            shard
                .fsp_sessions
                .get(&source_addr)
                .expect("owner state should stay registered")
                .fsp_receive_order
                .next_ticket(),
            1
        );
    }

    #[test]
    fn fsp_open_worker_rejects_payload_length_mismatch_before_ticket_issue() {
        let (pool, _control_receivers, _priority_receivers, _bulk_receivers, _fsp_completion) =
            test_worker_pool_with_fsp_completion_receivers(3, DECRYPT_WORKER_BULK_BATCH_MAX);
        let source_peer = test_source_peer();
        let source_addr = *source_peer.node_addr();
        let owner_idx = pool.worker_idx_for_fsp(&source_addr);
        let cipher = test_chacha_key([0x5f; 32]);
        let state = OwnedFspSessionState::from(crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher,
                replay: ReplayWindow::new(),
            },
            pending: None,
            previous: None,
        });

        let mut shard = DecryptWorkerShard::new(pool);
        shard.register_fsp_session(owner_idx, source_addr, state);
        let mut job = dummy_bulk_fsp_open_job(source_addr);
        job.fallback.packet_data[2..4].copy_from_slice(&1u16.to_le_bytes());

        let error = match shard.try_prepare_fsp_bulk_open_worker_jobs(
            owner_idx,
            owner_idx,
            FspOpenWorkerJobs::One(job),
        ) {
            Ok(_) => panic!("length-inconsistent FSP frame must not enter opener path"),
            Err(error) => error,
        };
        assert!(matches!(
            error.reason,
            FspOpenWorkerIneligibleReason::Malformed
        ));
        assert_eq!(
            shard
                .fsp_sessions
                .get(&source_addr)
                .expect("owner state should stay registered")
                .fsp_receive_order
                .next_ticket(),
            0,
            "malformed opener candidates must not consume ordered receive tickets"
        );
    }

    #[test]
    fn fsp_open_worker_batch_rejects_payload_length_mismatch_before_ticket_issue() {
        let (pool, _control_receivers, _priority_receivers, _bulk_receivers, _fsp_completion) =
            test_worker_pool_with_fsp_completion_receivers(3, DECRYPT_WORKER_BULK_BATCH_MAX);
        let source_peer = test_source_peer();
        let source_addr = *source_peer.node_addr();
        let owner_idx = pool.worker_idx_for_fsp(&source_addr);
        let cipher = test_chacha_key([0x60; 32]);
        let state = OwnedFspSessionState::from(crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher,
                replay: ReplayWindow::new(),
            },
            pending: None,
            previous: None,
        });

        let mut shard = DecryptWorkerShard::new(pool);
        shard.register_fsp_session(owner_idx, source_addr, state);
        let mut malformed = dummy_bulk_fsp_open_job(source_addr);
        malformed.fallback.packet_data[2..4].copy_from_slice(&1u16.to_le_bytes());

        assert!(
            shard
                .try_prepare_fsp_bulk_open_worker_jobs(
                    owner_idx,
                    owner_idx,
                    FspOpenWorkerJobs::Batch(vec![
                        dummy_bulk_fsp_open_job(source_addr),
                        malformed,
                    ]),
                )
                .is_err(),
            "length-inconsistent FSP batch must not enter opener path"
        );
        assert_eq!(
            shard
                .fsp_sessions
                .get(&source_addr)
                .expect("owner state should stay registered")
                .fsp_receive_order
                .next_ticket(),
            0,
            "malformed opener batches must not consume ordered receive tickets"
        );
    }

    #[test]
    fn fsp_local_open_worker_uses_ticket_window_when_completions_wait() {
        let (pool, _control_receivers, _priority_receivers, bulk_receivers, _fsp_completion) =
            test_worker_pool_with_fsp_completion_receivers(3, DECRYPT_WORKER_BULK_BATCH_MAX);
        let source_peer = test_source_peer();
        let source_addr = *source_peer.node_addr();
        let owner_idx = pool.worker_idx_for_fsp(&source_addr);
        let cipher = test_chacha_key([0x58; 32]);
        for sequence in 0..DECRYPT_WORKER_BULK_BATCH_MAX {
            pool.senders[owner_idx]
                .fsp_aead_completion
                .try_send(dummy_fsp_aead_completion_batch(source_addr, sequence as u64))
                .expect("test completion lane should have room");
        }

        let state = OwnedFspSessionState::from(crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher,
                replay: ReplayWindow::new(),
            },
            pending: None,
            previous: None,
        });
        let open_idx = pool
            .worker_idx_for_fsp_open_avoiding(&source_addr, owner_idx)
            .expect("three-worker pool should have a sibling opener");

        let mut shard = DecryptWorkerShard::new(pool.clone());
        shard.register_fsp_session(owner_idx, source_addr, state);
        let mut return_batch = DecryptWorkerReturnBatch::new(shard.pool.return_tx.clone());
        let mut fsp_open_batcher = new_fsp_aead_open_dispatch_batcher();
        shard.push_job_action_output(
            owner_idx,
            DecryptWorkerJobAction::FspJob(dummy_bulk_fsp_open_job(
                source_addr,
            )),
            &mut return_batch,
            None,
            &mut fsp_open_batcher,
        );
        assert!(flush_fsp_aead_open_dispatch(&mut fsp_open_batcher, &shard.pool).is_empty());
        assert_eq!(
            bulk_receivers[open_idx].len(),
            1,
            "waiting owner completions should not create a local-open fallback path"
        );
        assert_eq!(
            shard
                .fsp_sessions
                .get(&source_addr)
                .expect("owner state should stay registered")
                .fsp_receive_order
                .next_ticket(),
            1,
            "opener path should issue the owner receive ticket"
        );
    }

    #[test]
    fn fsp_worker_open_window_pressure_leaves_owner_receive_reserve() {
        let (pool, _control_receivers, _priority_receivers, bulk_receivers, _fsp_completion) =
            test_worker_pool_with_fsp_completion_receivers(3, DECRYPT_WORKER_BULK_BATCH_MAX);
        let source_peer = test_source_peer();
        let source_addr = *source_peer.node_addr();
        let owner_idx = pool.worker_idx_for_fsp(&source_addr);
        let open_idx = pool
            .worker_idx_for_fsp_open_avoiding(&source_addr, owner_idx)
            .expect("three-worker pool should have a sibling opener");
        let bulk_ticket_limit =
            fsp_receive_window().saturating_sub(DECRYPT_WORKER_FSP_RECEIVE_WINDOW_RESERVE);
        assert!(bulk_ticket_limit > 0);

        let state = OwnedFspSessionState::from(crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: test_chacha_key([0x59; 32]),
                replay: ReplayWindow::new(),
            },
            pending: None,
            previous: None,
        });

        let mut shard = DecryptWorkerShard::new(pool.clone());
        shard.register_fsp_session(owner_idx, source_addr, state);
        shard
            .fsp_sessions
            .get_mut(&source_addr)
            .expect("owner state should stay registered")
            .fsp_receive_order
            .advance_next_ticket_to(bulk_ticket_limit as u64);

        let mut return_batch = DecryptWorkerReturnBatch::new(shard.pool.return_tx.clone());
        let mut fsp_open_batcher = new_fsp_aead_open_dispatch_batcher();
        shard.push_job_action_output(
            owner_idx,
            DecryptWorkerJobAction::FspJob(dummy_bulk_fsp_open_job(
                source_addr,
            )),
            &mut return_batch,
            None,
            &mut fsp_open_batcher,
        );

        assert!(flush_fsp_aead_open_dispatch(&mut fsp_open_batcher, &shard.pool).is_empty());
        assert_eq!(
            bulk_receivers[open_idx].len(),
            0,
            "bulk pressure at the receive reserve must not enqueue opener work"
        );
        let state = shard
            .fsp_sessions
            .get_mut(&source_addr)
            .expect("owner state should stay registered");
        assert_eq!(
            state.fsp_receive_order.next_ticket(),
            bulk_ticket_limit as u64,
            "bulk pressure must drop instead of consuming the owner receive reserve"
        );
        assert_eq!(
            state
                .issue_fsp_receive_ticket()
                .expect("priority/local owner ticket should keep reserved progress")
                .sequence,
            bulk_ticket_limit as u64
        );
    }

    #[test]
    fn fsp_worker_open_batch_window_pressure_drops_without_single_packet_retry() {
        let (pool, _control_receivers, _priority_receivers, bulk_receivers, _fsp_completion) =
            test_worker_pool_with_fsp_completion_receivers(3, DECRYPT_WORKER_BULK_BATCH_MAX);
        let source_peer = test_source_peer();
        let source_addr = *source_peer.node_addr();
        let owner_idx = pool.worker_idx_for_fsp(&source_addr);
        let open_idx = pool
            .worker_idx_for_fsp_open_avoiding(&source_addr, owner_idx)
            .expect("three-worker pool should have a sibling opener");
        let bulk_ticket_limit =
            fsp_receive_window().saturating_sub(DECRYPT_WORKER_FSP_RECEIVE_WINDOW_RESERVE);
        assert!(bulk_ticket_limit > 1);

        let state = OwnedFspSessionState::from(crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: test_chacha_key([0x61; 32]),
                replay: ReplayWindow::new(),
            },
            pending: None,
            previous: None,
        });

        let mut shard = DecryptWorkerShard::new(pool.clone());
        shard.register_fsp_session(owner_idx, source_addr, state);
        shard
            .fsp_sessions
            .get_mut(&source_addr)
            .expect("owner state should stay registered")
            .fsp_receive_order
            .advance_next_ticket_to((bulk_ticket_limit - 1) as u64);

        let mut return_batch = DecryptWorkerReturnBatch::new(shard.pool.return_tx.clone());
        let mut fsp_open_batcher = new_fsp_aead_open_dispatch_batcher();
        shard.handle_bulk_fsp_job_batch_with_open_batcher(
            owner_idx,
            vec![
                dummy_bulk_fsp_open_job(source_addr),
                dummy_bulk_fsp_open_job(source_addr),
            ],
            None,
            false,
            &mut return_batch,
            &mut fsp_open_batcher,
        );

        assert!(flush_fsp_aead_open_dispatch(&mut fsp_open_batcher, &shard.pool).is_empty());
        assert_eq!(
            bulk_receivers[open_idx].len(),
            0,
            "batch pressure must not retry through a smaller opener dispatch"
        );
        let state = shard
            .fsp_sessions
            .get_mut(&source_addr)
            .expect("owner state should stay registered");
        assert_eq!(
            state.fsp_receive_order.next_ticket(),
            (bulk_ticket_limit - 1) as u64,
            "batch pressure must drop without consuming the final bulk ticket"
        );
        assert_eq!(
            state
                .issue_fsp_receive_ticket()
                .expect("priority/local owner ticket should keep reserved progress")
                .sequence,
            (bulk_ticket_limit - 1) as u64
        );
    }

    #[test]
    fn returned_owner_mismatch_fsp_open_job_sends_dropped_completion_to_owner() {
        let (pool, _control, _priority, _bulk, fsp_completion_receivers) =
            test_worker_pool_with_fsp_completion_receivers(3, 4);
        let source_addr = NodeAddr::from_bytes([0x46; 16]);
        let owner_idx = 0;
        let current_idx = 1;
        let header_bytes = crate::node::session_wire::build_fsp_header(1, 0, 1);
        let mut header_packet = header_bytes.to_vec();
        header_packet.extend_from_slice(&[0u8; 16]);
        let header = FspEncryptedHeader::parse(&header_packet).expect("test FSP header");
        let mut open_job = test_fsp_aead_open_job(
            source_addr,
            0,
            Arc::new(test_chacha_key([0x58; 32])),
            header,
            Some(owner_idx),
        );
        open_job.set_completion_source(FspAeadCompletionSource::WorkerOpen);

        let mut shard = DecryptWorkerShard::new(pool);
        let mut return_batch = DecryptWorkerReturnBatch::new(shard.pool.return_tx.clone());
        shard.drop_returned_fsp_aead_open_jobs(
            current_idx,
            std::iter::once(open_job),
            &mut return_batch,
        );

        let completion = fsp_completion_receivers[owner_idx]
            .try_recv()
            .expect("returned mismatch opener job should advance owner order");
        assert_eq!(completion.len(), 1);
        match completion {
            FspAeadCompletionBatch::One(FspAeadCompletion {
                source: FspAeadCompletionSource::WorkerOpenReturned,
                result:
                    FspOrderedCompletion::Dropped {
                        source: FspAeadCompletionSource::WorkerOpenReturned,
                    },
                ..
            }) => {}
            _ => panic!("returned opener job should become an ordered dropped completion"),
        }
        assert!(
            fsp_completion_receivers[current_idx].try_recv().is_err(),
            "wrong shard must not consume the ordered completion"
        );
    }

    #[test]
    fn fsp_open_completion_send_reports_closed_owner_channel() {
        let (pool, _control, _priority, _bulk, mut fsp_completion_receivers) =
            test_worker_pool_with_fsp_completion_receivers(3, 4);
        let source_addr = NodeAddr::from_bytes([0x49; 16]);
        let owner_idx = 0;
        let current_idx = 1;
        let header_bytes = crate::node::session_wire::build_fsp_header(1, 0, 1);
        let mut header_packet = header_bytes.to_vec();
        header_packet.extend_from_slice(&[0u8; 16]);
        let header = FspEncryptedHeader::parse(&header_packet).expect("test FSP header");
        let mut open_job = test_fsp_aead_open_job(
            source_addr,
            0,
            Arc::new(test_chacha_key([0x61; 32])),
            header,
            Some(owner_idx),
        );
        open_job.set_completion_source(FspAeadCompletionSource::WorkerOpen);
        open_job.mark_returned_completion();
        drop(fsp_completion_receivers.remove(owner_idx));

        assert!(
            !send_fsp_aead_open_completion_batch(
                current_idx,
                &pool,
                owner_idx,
                FspAeadCompletionBatch::one(open_job.into_dropped_completion()),
            ),
            "closed owner completion lane must be reported to the caller"
        );
    }

    #[test]
    fn single_fsp_open_job_completion_sends_one_owner_completion() {
        let (pool, _control, _priority, _bulk, fsp_completion_receivers) =
            test_worker_pool_with_fsp_completion_receivers(3, 4);
        let source_addr = NodeAddr::from_bytes([0x4a; 16]);
        let owner_idx = 0;
        let current_idx = 1;
        let header_bytes = crate::node::session_wire::build_fsp_header(1, 0, 1);
        let mut header_packet = header_bytes.to_vec();
        header_packet.extend_from_slice(&[0u8; 16]);
        let header = FspEncryptedHeader::parse(&header_packet).expect("test FSP header");
        let open_job = test_fsp_aead_open_job(
            source_addr,
            0,
            Arc::new(test_chacha_key([0x62; 32])),
            header,
            Some(owner_idx),
        );

        complete_fsp_aead_open_job(current_idx, &pool, open_job);

        let completion = fsp_completion_receivers[owner_idx]
            .try_recv()
            .expect("single opener completion should return to the owner");
        assert_eq!(completion.len(), 1);
        match completion {
            FspAeadCompletionBatch::One(FspAeadCompletion {
                source: FspAeadCompletionSource::WorkerOpen,
                result:
                    FspOrderedCompletion::AeadFailed {
                        source: FspAeadCompletionSource::WorkerOpen,
                        count_failure: true,
                        ..
                    },
                ..
            }) => {}
            _ => panic!("single opener job should send one ordered worker-open completion"),
        }
        assert!(
            fsp_completion_receivers[current_idx].try_recv().is_err(),
            "wrong shard must not receive the ordered completion"
        );
    }

    #[test]
    fn returned_owner_mismatch_fsp_open_jobs_send_one_dropped_completion_batch_to_owner() {
        let (pool, _control, _priority, _bulk, fsp_completion_receivers) =
            test_worker_pool_with_fsp_completion_receivers(3, 4);
        let source_addr = NodeAddr::from_bytes([0x47; 16]);
        let owner_idx = 0;
        let current_idx = 1;
        let header_bytes = crate::node::session_wire::build_fsp_header(1, 0, 1);
        let mut header_packet = header_bytes.to_vec();
        header_packet.extend_from_slice(&[0u8; 16]);
        let header = FspEncryptedHeader::parse(&header_packet).expect("test FSP header");
        let cipher = Arc::new(test_chacha_key([0x59; 32]));
        let jobs = vec![
            {
                let mut job = test_fsp_aead_open_job(
                    source_addr,
                    0,
                    Arc::clone(&cipher),
                    header.clone(),
                    Some(owner_idx),
                );
                job.set_completion_source(FspAeadCompletionSource::WorkerOpen);
                job
            },
            {
                let mut job = test_fsp_aead_open_job(
                    source_addr,
                    1,
                    cipher,
                    header,
                    Some(owner_idx),
                );
                job.set_completion_source(FspAeadCompletionSource::WorkerOpen);
                job
            },
        ];

        let mut shard = DecryptWorkerShard::new(pool);
        let mut return_batch = DecryptWorkerReturnBatch::new(shard.pool.return_tx.clone());
        shard.drop_returned_fsp_aead_open_jobs(current_idx, jobs, &mut return_batch);

        let completion = fsp_completion_receivers[owner_idx]
            .try_recv()
            .expect("returned mismatch opener jobs should advance owner order");
        assert_eq!(completion.len(), 2);
        match completion {
            FspAeadCompletionBatch::Many(completions) => {
                let receive_order_id = completions[0].receive_order_id();
                assert!(
                    completions
                        .iter()
                        .all(|completion| completion.source_addr() == source_addr)
                );
                assert!(
                    completions
                        .iter()
                        .all(|completion| completion.receive_order_id() == receive_order_id)
                );
                assert!(completions.iter().all(|completion| matches!(
                    (
                        completion.source,
                        &completion.result,
                    ),
                    (
                        FspAeadCompletionSource::WorkerOpenReturned,
                        FspOrderedCompletion::Dropped {
                            source: FspAeadCompletionSource::WorkerOpenReturned,
                        },
                    )
                )));
            }
            _ => panic!("returned opener jobs should coalesce into one dropped batch"),
        }
        assert!(
            fsp_completion_receivers[owner_idx].try_recv().is_err(),
            "returned opener jobs should be coalesced into one owner message"
        );
        assert!(
            fsp_completion_receivers[current_idx].try_recv().is_err(),
            "wrong shard must not consume the ordered completions"
        );
    }

    #[test]
    fn returned_owner_mismatch_fsp_open_jobs_are_dropped_by_owner() {
        let (pool, _control, _priority, _bulk, fsp_completion_receivers) =
            test_worker_pool_with_fsp_completion_receivers(3, 4);
        let source_addr = NodeAddr::from_bytes([0x48; 16]);
        let owner_idx = 0;
        let current_idx = 1;
        let header_bytes = crate::node::session_wire::build_fsp_header(1, 0, 1);
        let mut header_packet = header_bytes.to_vec();
        header_packet.extend_from_slice(&[0u8; 16]);
        let header = FspEncryptedHeader::parse(&header_packet).expect("test FSP header");
        let cipher = Arc::new(test_chacha_key([0x5a; 32]));
        let jobs = vec![test_fsp_aead_open_job(
                source_addr,
                0,
                cipher,
                header,
                Some(owner_idx),
            )];

        let mut shard = DecryptWorkerShard::new(pool);
        let mut return_batch = DecryptWorkerReturnBatch::new(shard.pool.return_tx.clone());
        shard.drop_returned_fsp_aead_open_jobs(current_idx, jobs, &mut return_batch);

        let completion = fsp_completion_receivers[owner_idx]
            .try_recv()
            .expect("returned mismatch opener job should advance owner order");
        match completion {
            FspAeadCompletionBatch::One(FspAeadCompletion {
                result: FspOrderedCompletion::Dropped { .. },
                ..
            }) => {}
            _ => panic!("returned opener job should be dropped by the owner"),
        }
    }

    #[test]
    fn returned_local_fsp_open_job_advances_ordered_owner_locally() {
        let (pool, _control, _priority, _bulk, fsp_completion_receivers) =
            test_worker_pool_with_fsp_completion_receivers(2, 4);
        let source_peer = test_source_peer();
        let source_addr = *source_peer.node_addr();
        let mut state = OwnedFspSessionState::from(crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: test_chacha_key([0x5b; 32]),
                replay: ReplayWindow::new(),
            },
            pending: None,
            previous: None,
        });
        let receive_order_id = state.fsp_receive_order_id();
        let crypto_generation = state.fsp_crypto_generation();
        let ticket = state
            .issue_fsp_receive_ticket()
            .expect("owner receive window should admit first ticket");

        let header_bytes = crate::node::session_wire::build_fsp_header(1, 0, 1);
        let mut header_packet = header_bytes.to_vec();
        header_packet.extend_from_slice(&[0u8; 16]);
        let header = FspEncryptedHeader::parse(&header_packet).expect("test FSP header");
        let job = test_fsp_aead_open_job_with_meta(
            source_addr,
            receive_order_id,
            crypto_generation,
            ticket.sequence,
            Arc::new(test_chacha_key([0x5c; 32])),
            header,
            None,
        );

        let mut shard = DecryptWorkerShard::new(pool);
        shard.fsp_sessions.insert(source_addr, state);
        let mut return_batch = DecryptWorkerReturnBatch::new(shard.pool.return_tx.clone());
        shard.drop_returned_fsp_aead_open_jobs(
            0,
            std::iter::once(job),
            &mut return_batch,
        );

        let state = shard
            .fsp_sessions
            .get(&source_addr)
            .expect("local owner state should remain registered");
        assert_eq!(state.fsp_receive_order_next_ready(), ticket.sequence + 1);
        assert!(
            fsp_completion_receivers.iter().all(Receiver::is_empty),
            "local returned opener completions should not bounce to another worker"
        );
    }

    #[test]
    fn fsp_registration_installs_owner_receive_state_without_shared_crypto() {
        let (pool, control_receivers, priority_receivers, _bulk_receivers) =
            test_worker_pool(3, 4);

        let source_peer = test_source_peer();
        let source_addr = *source_peer.node_addr();
        let owner_idx = pool.worker_idx_for_fsp(&source_addr);
        let shard_pool = pool.clone();
        let snapshot = crate::node::session::FspRecvSessionSnapshot {
            source_peer,
            current_k_bit: false,
            current: crate::node::session::FspRecvEpochSnapshot {
                cipher: test_chacha_key([0x66; 32]),
                replay: ReplayWindow::new(),
            },
            pending: None,
            previous: None,
        };

        assert!(pool.register_fsp_session(source_addr, snapshot));
        let mut shard = DecryptWorkerShard::new(shard_pool);
        match control_receivers[owner_idx]
            .recv_timeout(Duration::from_millis(100))
            .expect("FSP registration should reach owner worker")
        {
            WorkerMsg::RegisterFspSession {
                source_addr: got_source_addr,
                state,
            } => {
                assert_eq!(got_source_addr, source_addr);
                shard.register_fsp_session(owner_idx, got_source_addr, state);
            }
            _ => panic!("expected FSP registration"),
        }
        assert!(
            priority_receivers.iter().all(Receiver::is_empty),
            "FSP registration should not consume packet priority lanes"
        );
        let state = shard
            .fsp_sessions
            .get(&source_addr)
            .expect("FSP registration should install owner-local receive state");
        assert_eq!(state.current_k_bit, false);
        assert_eq!(state.fsp_receive_order.next_ticket(), 0);
    }

    fn test_source_peer() -> PeerIdentity {
        PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full())
    }

    fn test_owned_session_state() -> OwnedSessionState {
        test_owned_session_state_for(test_source_peer())
    }

    fn test_owned_session_state_for(source_peer: PeerIdentity) -> OwnedSessionState {
        let key_bytes = [7u8; 32];
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        OwnedSessionState::new(LessSafeKey::new(unbound), ReplayWindow::new(), source_peer)
    }

    #[test]
    fn owned_session_state_carries_authenticated_source_peer() {
        let source_peer = test_source_peer();
        let key_bytes = [8u8; 32];
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        let state =
            OwnedSessionState::new(LessSafeKey::new(unbound), ReplayWindow::new(), source_peer);

        assert_eq!(state.source_peer, source_peer);
    }

    fn test_session_key(transport_id: u32, receiver_idx: u32) -> DecryptSessionKey {
        DecryptSessionKey::new(TransportId::new(transport_id), receiver_idx)
    }

    fn dummy_decrypt_job_with_len(session_key: DecryptSessionKey, packet_len: usize) -> DecryptJob {
        let packet_len = packet_len.max(crate::node::wire::ESTABLISHED_HEADER_SIZE + 16);
        DecryptJob::new(
            vec![0; packet_len],
            session_key,
            0,
            session_key.transport_id,
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *test_source_peer().node_addr(),
            1_000,
            1,
            0,
            [0u8; crate::node::wire::ESTABLISHED_HEADER_SIZE],
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
        )
    }

    fn dummy_bulk_decrypt_job(session_key: DecryptSessionKey) -> DecryptJob {
        dummy_decrypt_job_with_len(session_key, DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1)
    }

    fn dummy_bulk_decrypt_item(session_key: DecryptSessionKey) -> DecryptWorkerBulkItem {
        decrypt_worker_bulk_item_from_jobs(vec![dummy_bulk_decrypt_job(session_key)])
    }

    fn dummy_fsp_aead_completion_batch(
        source_addr: NodeAddr,
        sequence: u64,
    ) -> FspAeadCompletionBatch {
        let header_bytes = crate::node::session_wire::build_fsp_header(1, 0, 1);
        let mut header_packet = header_bytes.to_vec();
        header_packet.extend_from_slice(&[0u8; 16]);
        let header = FspEncryptedHeader::parse(&header_packet).expect("test FSP header");
        let mut job = dummy_fsp_job(FSP_HEADER_SIZE);
        job.source_addr = source_addr;
        FspAeadCompletionBatch::one(FspAeadCompletion {
            crypto_ticket: test_fsp_crypto_ticket(source_addr, 7, 0, sequence),
            source: FspAeadCompletionSource::WorkerOpen,
            result: FspOrderedCompletion::AeadFailed {
                job,
                header,
                source: FspAeadCompletionSource::WorkerOpen,
                count_failure: true,
            },
            completed_at: None,
        })
    }

    fn dummy_priority_decrypt_job(session_key: DecryptSessionKey) -> DecryptJob {
        let mut job = dummy_decrypt_job_with_len(session_key, DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN);
        job.lane = DecryptWorkerLane::Priority;
        job
    }

    fn dummy_authenticated_link_event(packet_len: usize) -> DecryptWorkerEvent {
        let fallback = DecryptFallback::new(
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
        );
        DecryptWorkerEvent::AuthenticatedLink(DecryptAuthenticatedLink::from_opened_fmp(
            fallback,
        ))
    }

    fn dummy_authenticated_link_batch_event(count: usize, packet_len: usize) -> DecryptWorkerEvent {
        DecryptWorkerEvent::AuthenticatedLinkBatch(
            (0..count)
                .map(|idx| {
                    let fallback = DecryptFallback::new(
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
                    );
                    DecryptAuthenticatedLink::from_opened_fmp(fallback)
                })
                .collect(),
        )
    }

    #[test]
    fn bulk_fmp_batch_retires_same_session_with_return_batch_output() {
        let key_bytes = [0x71; 32];
        let seal_cipher = test_chacha_key(key_bytes);
        let open_cipher = test_chacha_key(key_bytes);
        let session_key = test_session_key(1, 84);
        let source_peer = test_source_peer();
        let mut shard = test_shard();
        shard.register_session(
            0,
            session_key,
            OwnedSessionState::new(open_cipher, ReplayWindow::new(), source_peer),
        );
        let (return_tx, mut return_rx) = decrypt_worker_return_channels_with_caps(4, 4);
        shard.pool.return_tx = return_tx.clone();

        let link_body_len = DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1;
        let (packet1, header1) = sealed_fmp_test_packet_with_link_body(
            &seal_cipher,
            1,
            0,
            link_body_len,
        );
        let (packet2, header2) = sealed_fmp_test_packet_with_link_body(
            &seal_cipher,
            2,
            0,
            link_body_len,
        );
        let item = decrypt_worker_bulk_item_from_jobs(vec![
            decrypt_job_for_test_packet(packet1, header1, session_key, 1, 0),
            decrypt_job_for_test_packet(packet2, header2, session_key, 2, 0),
        ]);

        let (_control_tx, control_rx) = bounded::<WorkerMsg>(1);
        let (_priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let fsp_completion_rx = test_fsp_aead_completion_lane(1);
        let mut return_batch = DecryptWorkerReturnBatch::new(return_tx);
        let mut batch_stats = DecryptWorkerBatchStats::default();
        let processed = handle_bulk_item(
            0,
            &mut shard,
            &control_rx,
            &priority_rx,
            &fsp_completion_rx,
            item,
            &mut return_batch,
            &mut batch_stats,
        );
        return_batch.flush();

        assert_eq!(processed, 2);
        let event = return_rx
            .authenticated_bulk
            .try_recv()
            .expect("bulk authenticated link batch");
        match &event {
            DecryptWorkerEvent::AuthenticatedLinkBatch(links) => assert_eq!(links.len(), 2),
            other => panic!(
                "bulk FMP batch should coalesce authenticated link output, got {} packet(s)",
                other.packet_count()
            ),
        }
        return_rx.release_dequeued_event(&event);
        assert_eq!(
            shard.fmp_replay_highest(session_key),
            Some(2),
            "ordered bulk FMP retire should accept both counters"
        );
    }

    #[test]
    fn job_actions_reuse_authenticated_link_output_batcher() {
        let (return_tx, mut return_rx) = decrypt_worker_return_channels_with_caps(4, 4);
        let pool = DecryptWorkerPool {
            senders: Arc::from(Vec::<DecryptWorkerSender>::new().into_boxed_slice()),
            direct_delivery_sink: DecryptDirectSessionDeliverySink::default(),
            return_tx: return_tx.clone(),
        };
        let mut shard = DecryptWorkerShard::new(pool);
        let mut return_batch = DecryptWorkerReturnBatch::new(return_tx);
        let mut fsp_open_batcher = new_fsp_aead_open_dispatch_batcher();
        let packet_len = DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1;

        shard.push_job_action_output(
            0,
            DecryptWorkerJobAction::Output(DecryptWorkerOutput {
                event: dummy_authenticated_link_event(packet_len),
                direct_delivery: None,
            }),
            &mut return_batch,
            None,
            &mut fsp_open_batcher,
        );
        shard.push_job_action_output(
            0,
            DecryptWorkerJobAction::Output(DecryptWorkerOutput {
                event: dummy_authenticated_link_event(packet_len),
                direct_delivery: None,
            }),
            &mut return_batch,
            None,
            &mut fsp_open_batcher,
        );
        assert!(flush_fsp_aead_open_dispatch(&mut fsp_open_batcher, &shard.pool).is_empty());
        return_batch.flush();

        let event = return_rx
            .authenticated_bulk
            .try_recv()
            .expect("batched authenticated link output");
        match &event {
            DecryptWorkerEvent::AuthenticatedLinkBatch(links) => {
                assert_eq!(links.len(), 2);
            }
            other => panic!(
                "sequential output actions should reuse authenticated link batching, got {} packet(s)",
                other.packet_count()
            ),
        }
        return_rx.release_dequeued_event(&event);
        assert_eq!(return_rx.authenticated_bulk_queued_packets(), 0);
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

    fn dummy_routed_direct_data_output(
        source_peer: PeerIdentity,
        fmp_counter: u64,
        payload: &[u8],
    ) -> DecryptWorkerOutput {
        let source_addr = *source_peer.node_addr();
        let payload_len = payload.len();
        let direct = DecryptDirectSessionData::for_test(
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
            DecryptDirectSessionDelivery::EndpointData(EndpointDataDelivery::new(
                source_peer,
                payload.to_vec(),
            )),
        );

        DecryptWorkerOutput {
            event: DecryptWorkerEvent::DirectSessionData(direct),
            direct_delivery: None,
        }
    }

    #[test]
    fn pending_direct_delivery_reports_packet_mover_endpoint_target() {
        let (endpoint_tx, _endpoint_rx) = EndpointEventSender::channel(1);
        let sink = DecryptDirectSessionDeliverySink::new(None, None, Some(endpoint_tx));
        let source_peer = test_source_peer();
        let output = dummy_direct_endpoint_output(sink, source_peer, 7, b"endpoint");
        let delivery = output
            .direct_delivery
            .expect("dummy direct endpoint output carries delivery");

        assert_eq!(delivery.output_target(), Some(OutputTarget::Endpoint));
    }

    #[test]
    fn pending_direct_delivery_reports_packet_mover_tun_target() {
        let (tun_tx, _tun_rx) = std::sync::mpsc::channel();
        let source_peer = test_source_peer();
        let output = dummy_direct_tun_output(tun_tx, source_peer, 8, Vec::new(), false);
        let delivery = output
            .direct_delivery
            .expect("dummy direct TUN output carries delivery");

        assert_eq!(delivery.output_target(), Some(OutputTarget::Tun));
    }

    #[test]
    fn pending_direct_delivery_without_sink_has_no_output_target() {
        let source_peer = test_source_peer();
        let source_addr = *source_peer.node_addr();
        let delivery = PendingDirectSessionDelivery {
            sink: DecryptDirectSessionDeliverySink::default(),
            source_addr,
            source_peer,
            ce_flag: false,
            delivery: DecryptDirectSessionDelivery::EndpointData(EndpointDataDelivery::new(
                source_peer,
                b"endpoint".to_vec(),
            )),
        };

        assert_eq!(delivery.output_target(), None);
    }

    #[test]
    fn decrypt_worker_return_drop_metric_splits_fallback_and_authenticated_outputs() {
        let bulk_len = DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1;
        let link = dummy_authenticated_link_event(bulk_len);
        assert_eq!(
            decrypt_worker_event_drop_event(&link, link.lane()),
            crate::perf_profile::Event::DecryptAuthenticatedSessionBulkDropped
        );

        let failure = dummy_failure_event();
        assert_eq!(
            decrypt_worker_event_drop_event(&failure, failure.lane()),
            crate::perf_profile::Event::DecryptFallbackPriorityDropped
        );

        let (endpoint_tx, _endpoint_rx) = EndpointEventSender::channel(1);
        let sink = DecryptDirectSessionDeliverySink::new(None, None, Some(endpoint_tx));
        let source_peer = test_source_peer();
        let bulk_payload = vec![0x55; bulk_len];
        let output = dummy_direct_endpoint_output(sink, source_peer, 7, &bulk_payload);
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
        FspDecryptJob {
            lane: decrypt_worker_packet_lane(packet_len),
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

    fn dummy_bulk_fsp_open_job(source_addr: NodeAddr) -> FspDecryptJob {
        let header_bytes = crate::node::session_wire::build_fsp_header(1, 0, 0);
        let mut packet_data = header_bytes.to_vec();
        let fsp_payload_len = packet_data.len() + 16;
        packet_data.resize(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1, 0);
        let mut job = dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1);
        job.source_addr = source_addr;
        job.fallback.packet_data = packet_data.into();
        job.fsp_payload_offset = 0;
        job.fsp_payload_len = fsp_payload_len;
        job
    }

    fn test_fsp_aead_open_job(
        source_addr: NodeAddr,
        ticket_sequence: u64,
        cipher: Arc<LessSafeKey>,
        header: FspEncryptedHeader,
        completion_owner_idx: Option<usize>,
    ) -> FspAeadOpenDispatch {
        test_fsp_aead_open_job_with_meta(
            source_addr,
            7,
            0,
            ticket_sequence,
            cipher,
            header,
            completion_owner_idx,
        )
    }

    fn test_fsp_aead_open_job_with_meta(
        source_addr: NodeAddr,
        receive_order_id: u64,
        crypto_generation: u64,
        ticket_sequence: u64,
        cipher: Arc<LessSafeKey>,
        header: FspEncryptedHeader,
        completion_owner_idx: Option<usize>,
    ) -> FspAeadOpenDispatch {
        let mut job = dummy_fsp_job(FSP_HEADER_SIZE);
        job.source_addr = source_addr;
        job.fsp_payload_len = 0;
        new_fsp_aead_open_dispatch(
            test_fsp_crypto_ticket(
                source_addr,
                receive_order_id,
                crypto_generation,
                ticket_sequence,
            ),
            cipher,
            job,
            header,
            0,
            FspAeadCompletionSource::WorkerOpen,
            completion_owner_idx,
            None,
        )
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
    ) -> DecryptJob {
        DecryptJob::new(
            packet_data,
            session_key,
            0,
            TransportId::new(1),
            crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            *test_source_peer().node_addr(),
            1_000,
            fmp_counter,
            fmp_flags,
            header,
            crate::node::wire::ESTABLISHED_HEADER_SIZE,
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
