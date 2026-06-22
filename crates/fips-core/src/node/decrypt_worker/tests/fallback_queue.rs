    #[test]
    fn fsp_jobs_keep_original_priority_and_bulk_lanes_to_fsp_owner() {
        let (pool, _control_receivers, priority_receivers, bulk_receivers) =
            test_worker_pool(4, 4);

        let priority_job = dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN);
        let priority_owner = pool.worker_idx_for_fsp(&priority_job.source_addr);
        assert!(
            pool.dispatch_fsp_job_or_return(priority_job).is_ok(),
            "priority FSP job should queue"
        );
        match priority_receivers[priority_owner]
            .try_recv()
            .expect("priority FSP job should use priority lane")
        {
            WorkerMsg::FspJob(job) => assert_eq!(job.lane(), DecryptWorkerLane::Priority),
            WorkerMsg::Job(_)
            | WorkerMsg::RegisterSession { .. }
            | WorkerMsg::RegisterFspSession { .. }
            | WorkerMsg::UnregisterSession { .. }
            | WorkerMsg::UnregisterFspSession { .. } => {
                panic!("expected priority FSP job")
            }
        }
        assert!(
            bulk_receivers[priority_owner].is_empty(),
            "priority FSP jobs must not wait behind bulk work"
        );

        let bulk_job = dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1);
        let bulk_owner = pool.worker_idx_for_fsp(&bulk_job.source_addr);
        assert!(
            pool.dispatch_fsp_job_or_return(bulk_job).is_ok(),
            "bulk FSP job should queue"
        );
        match bulk_receivers[bulk_owner]
            .try_recv()
            .expect("bulk FSP job should use bulk lane")
        {
            DecryptWorkerBulkItem::FspJob(job) => assert_eq!(job.lane(), DecryptWorkerLane::Bulk),
            DecryptWorkerBulkItem::Job(_)
            | DecryptWorkerBulkItem::FmpAeadOpen(_)
            | DecryptWorkerBulkItem::FspAeadOpen(_)
            | DecryptWorkerBulkItem::FspAeadOpenBatch(_)
            | DecryptWorkerBulkItem::Batch(_)
            | DecryptWorkerBulkItem::FspBatch(_) => {
                panic!("expected bulk FSP job")
            }
        }
    }

    #[test]
    fn fsp_job_batcher_groups_consecutive_bulk_jobs_for_one_owner() {
        let (pool, _control_receivers, _priority_receivers, bulk_receivers) =
            test_worker_pool(4, DECRYPT_WORKER_BULK_BATCH_MAX);
        let source_addr = *test_source_peer().node_addr();
        let owner = pool.worker_idx_for_fsp(&source_addr);
        let mut batcher = FspDecryptJobBatcher::new();

        for _ in 0..3 {
            let mut job = dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1);
            job.source_addr = source_addr;
            batcher.push(&pool, job);
        }
        batcher.flush(&pool);

        assert_eq!(
            bulk_receivers[owner].len(),
            1,
            "three same-owner FSP bulk packets should consume one channel slot"
        );
        match bulk_receivers[owner]
            .try_recv()
            .expect("batched FSP bulk item")
        {
            DecryptWorkerBulkItem::FspBatch(jobs) => {
                assert_eq!(jobs.len(), 3);
                assert!(
                    jobs.iter()
                        .all(|job| matches!(job.lane(), DecryptWorkerLane::Bulk))
                );
                assert!(jobs.iter().all(|job| job.source_addr == source_addr));
            }
            DecryptWorkerBulkItem::FspJob(_) => panic!("expected a multi-job FSP batch"),
            DecryptWorkerBulkItem::Job(_)
            | DecryptWorkerBulkItem::FmpAeadOpen(_)
            | DecryptWorkerBulkItem::FspAeadOpen(_)
            | DecryptWorkerBulkItem::FspAeadOpenBatch(_)
            | DecryptWorkerBulkItem::Batch(_) => {
                panic!("expected a multi-job FSP batch")
            }
        }
        for (idx, rx) in bulk_receivers.iter().enumerate() {
            if idx != owner {
                assert!(
                    rx.is_empty(),
                    "other worker {idx} must not receive this FSP owner batch"
                );
            }
        }
    }

    #[test]
    fn fsp_job_batcher_reuses_pending_buffer_for_single_bulk_flush() {
        let (pool, _control_receivers, _priority_receivers, bulk_receivers) =
            test_worker_pool(4, DECRYPT_WORKER_BULK_BATCH_MAX);
        let source_addr = *test_source_peer().node_addr();
        let owner = pool.worker_idx_for_fsp(&source_addr);
        let mut batcher = FspDecryptJobBatcher::new();
        let pending_buffer = batcher.pending_buffer_ptr();
        let mut job = dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1);
        job.source_addr = source_addr;

        batcher.push(&pool, job);
        batcher.flush(&pool);

        assert_eq!(
            batcher.pending_buffer_ptr(),
            pending_buffer,
            "single FSP bulk flushes should not allocate a replacement pending buffer"
        );
        match bulk_receivers[owner]
            .try_recv()
            .expect("single FSP bulk item")
        {
            DecryptWorkerBulkItem::FspJob(job) => {
                assert_eq!(job.lane(), DecryptWorkerLane::Bulk);
                assert_eq!(job.source_addr, source_addr);
            }
            DecryptWorkerBulkItem::Job(_)
            | DecryptWorkerBulkItem::FmpAeadOpen(_)
            | DecryptWorkerBulkItem::FspAeadOpen(_)
            | DecryptWorkerBulkItem::FspAeadOpenBatch(_)
            | DecryptWorkerBulkItem::Batch(_)
            | DecryptWorkerBulkItem::FspBatch(_) => panic!("expected a single FSP bulk job"),
        }
    }

    #[test]
    fn bulk_fsp_batch_dispatch_uses_partial_worker_capacity() {
        let (pool, _control_receivers, _priority_receivers, bulk_receivers) =
            test_worker_pool(1, 2);
        let existing_job = dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1);
        assert!(
            pool.dispatch_bulk_fsp_job_or_return(0, existing_job)
                .is_ok(),
            "first packet should reserve one of two bulk packet slots"
        );

        let batch = vec![
            dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1),
            dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1),
        ];
        let returned = pool
            .dispatch_bulk_fsp_job_batch_or_return(0, batch)
            .expect_err("only one packet slot remains for the two-packet batch");

        assert_eq!(
            returned.len(),
            1,
            "partial worker capacity should admit one packet and return only overflow"
        );
        assert_eq!(
            bulk_receivers[0].len(),
            2,
            "the existing packet plus one batch packet should remain queued"
        );
        assert_eq!(
            pool.senders[0].bulk_queued_packets.load(Ordering::Relaxed),
            2,
            "bulk packet accounting should match the admitted packet count"
        );
        for item in bulk_receivers[0].try_iter() {
            match item {
                DecryptWorkerBulkItem::FspJob(job) => {
                    assert_eq!(job.lane(), DecryptWorkerLane::Bulk);
                }
                DecryptWorkerBulkItem::Job(_)
                | DecryptWorkerBulkItem::FmpAeadOpen(_)
                | DecryptWorkerBulkItem::FspAeadOpen(_)
                | DecryptWorkerBulkItem::FspAeadOpenBatch(_)
                | DecryptWorkerBulkItem::Batch(_)
                | DecryptWorkerBulkItem::FspBatch(_) => {
                    panic!("partial-capacity retry should fall back to single FSP jobs")
                }
            }
        }
    }

    #[test]
    fn bulk_fsp_batch_dispatch_keeps_partial_capacity_batched() {
        let (pool, _control_receivers, _priority_receivers, bulk_receivers) =
            test_worker_pool(1, 3);
        let existing_job = dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1);
        assert!(
            pool.dispatch_bulk_fsp_job_or_return(0, existing_job)
                .is_ok(),
            "first packet should reserve one of three bulk packet slots"
        );

        let batch = vec![
            dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1),
            dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1),
            dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1),
        ];
        let returned = pool
            .dispatch_bulk_fsp_job_batch_or_return(0, batch)
            .expect_err("only two packet slots remain for the three-packet batch");

        assert_eq!(
            returned.len(),
            1,
            "partial worker capacity should return only the overflow tail"
        );
        assert_eq!(
            bulk_receivers[0].len(),
            2,
            "the existing packet plus one prefix batch should be queued"
        );
        assert_eq!(
            pool.senders[0].bulk_queued_packets.load(Ordering::Relaxed),
            3,
            "bulk packet accounting should include the admitted prefix batch"
        );

        match bulk_receivers[0]
            .try_recv()
            .expect("existing single FSP job")
        {
            DecryptWorkerBulkItem::FspJob(job) => {
                assert_eq!(job.lane(), DecryptWorkerLane::Bulk);
            }
            DecryptWorkerBulkItem::Job(_)
            | DecryptWorkerBulkItem::FmpAeadOpen(_)
            | DecryptWorkerBulkItem::FspAeadOpen(_)
            | DecryptWorkerBulkItem::FspAeadOpenBatch(_)
            | DecryptWorkerBulkItem::Batch(_)
            | DecryptWorkerBulkItem::FspBatch(_) => panic!("expected existing single FSP job"),
        }
        match bulk_receivers[0]
            .try_recv()
            .expect("admitted FSP prefix batch")
        {
            DecryptWorkerBulkItem::FspBatch(jobs) => {
                assert_eq!(jobs.len(), 2);
                assert!(
                    jobs.iter()
                        .all(|job| matches!(job.lane(), DecryptWorkerLane::Bulk))
                );
            }
            DecryptWorkerBulkItem::FspJob(_) => {
                panic!("two available slots should stay grouped as one FSP batch")
            }
            DecryptWorkerBulkItem::Job(_)
            | DecryptWorkerBulkItem::FmpAeadOpen(_)
            | DecryptWorkerBulkItem::FspAeadOpen(_)
            | DecryptWorkerBulkItem::FspAeadOpenBatch(_)
            | DecryptWorkerBulkItem::Batch(_) => {
                panic!("expected an FSP prefix batch")
            }
        }
    }

    #[test]
    fn decrypt_worker_bulk_batch_admits_prefix_when_packet_capacity_is_low() {
        let (pool, _control_receivers, _priority_receivers, bulk_receivers) =
            test_worker_pool(1, 3);
        let session_key = test_session_key(1, 123);
        pool.dispatch_bulk_job(0, dummy_bulk_decrypt_job(session_key));

        pool.dispatch_bulk_job_batch(
            0,
            vec![
                dummy_bulk_decrypt_job(session_key),
                dummy_bulk_decrypt_job(session_key),
                dummy_bulk_decrypt_job(session_key),
            ],
        );

        assert_eq!(
            bulk_receivers[0].len(),
            2,
            "existing packet plus admitted prefix batch should remain queued"
        );
        assert_eq!(
            pool.senders[0].bulk_queued_packets.load(Ordering::Relaxed),
            3,
            "overflow tail must not consume bulk packet capacity"
        );

        match bulk_receivers[0].try_recv().expect("existing bulk job") {
            DecryptWorkerBulkItem::Job(job) => {
                assert_eq!(job.session_key, session_key);
            }
            DecryptWorkerBulkItem::FspJob(_)
            | DecryptWorkerBulkItem::FmpAeadOpen(_)
            | DecryptWorkerBulkItem::FspAeadOpen(_)
            | DecryptWorkerBulkItem::FspAeadOpenBatch(_)
            | DecryptWorkerBulkItem::Batch(_)
            | DecryptWorkerBulkItem::FspBatch(_) => panic!("expected existing bulk job"),
        }
        match bulk_receivers[0].try_recv().expect("admitted prefix batch") {
            DecryptWorkerBulkItem::Batch(jobs) => {
                assert_eq!(jobs.len(), 2);
                assert!(jobs.iter().all(|job| job.session_key == session_key));
            }
            DecryptWorkerBulkItem::Job(_) => {
                panic!("two available slots should stay grouped as one decrypt batch")
            }
            DecryptWorkerBulkItem::FspJob(_)
            | DecryptWorkerBulkItem::FmpAeadOpen(_)
            | DecryptWorkerBulkItem::FspAeadOpen(_)
            | DecryptWorkerBulkItem::FspAeadOpenBatch(_)
            | DecryptWorkerBulkItem::FspBatch(_) => {
                panic!("expected admitted decrypt prefix batch")
            }
        }
    }

    #[test]
    fn full_fsp_owner_queues_return_to_caller_without_waiting() {
        let (pool, _control_rx, priority_rx, bulk_rx) = one_slot_worker_pool();

        let session_key = test_session_key(1, 88);
        pool.dispatch_job(dummy_priority_decrypt_job(session_key));
        assert_eq!(priority_rx.len(), 1, "priority lane should be full");

        let priority_job = dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN);
        assert!(
            pool.dispatch_fsp_job_or_return(priority_job).is_err(),
            "full priority FSP lane should return to caller"
        );
        assert_eq!(
            priority_rx.len(),
            1,
            "returned priority FSP job must not overflow the priority lane"
        );

        pool.dispatch_bulk_job(0, dummy_bulk_decrypt_job(session_key));
        assert_eq!(bulk_rx.len(), 1, "bulk lane should be full");
        let bulk_job = dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1);
        assert!(
            pool.dispatch_fsp_job_or_return(bulk_job).is_err(),
            "full bulk FSP lane should return to caller"
        );
        assert_eq!(
            bulk_rx.len(),
            1,
            "returned bulk FSP job must not overflow the bulk lane"
        );
    }

    #[test]
    fn fsp_owner_handoff_pressure_drops_instead_of_emitting_plaintext_fallback() {
        let (pool, _control_rx, _priority_rx, bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 88);
        pool.dispatch_bulk_job(0, dummy_bulk_decrypt_job(session_key));
        assert_eq!(bulk_rx.len(), 1, "bulk lane should start full");

        let source_peer = test_source_peer();
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        let mut batcher = FspDecryptJobBatcher::new();
        batcher.push(
            &pool,
            FspDecryptJob {
                fallback_tx,
                lane: DecryptWorkerLane::Bulk,
                fallback: DecryptFallback::new(
                    source_peer,
                    TransportId::new(1),
                    crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
                    1_000,
                    DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1,
                    1,
                    0,
                    vec![0; DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1],
                    0,
                    1,
                ),
                local_node_addr: *source_peer.node_addr(),
                source_addr: *source_peer.node_addr(),
                previous_hop_peer: source_peer,
                path_mtu: 1_280,
                ce_flag: false,
                inner_timestamp_ms: 2,
                fsp_payload_offset: 0,
                fsp_payload_len: 0,
                trace_enqueued_at: None,
            },
        );
        batcher.flush(&pool);

        assert_eq!(bulk_rx.len(), 1, "failed FSP handoff must not overflow bulk");
        assert!(
            fallback_rx.priority.try_recv().is_err(),
            "FSP owner pressure must not create a priority plaintext fallback"
        );
        assert!(
            fallback_rx.bulk.try_recv().is_err(),
            "FSP owner pressure must not create a bulk plaintext fallback"
        );
    }

    #[test]
    fn decrypt_worker_fallback_event_classifier_uses_priority_and_bulk_lanes() {
        assert_eq!(
            decrypt_worker_event_lane(&dummy_plaintext_event(
                DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN
            )),
            DecryptWorkerLane::Priority
        );
        assert_eq!(
            decrypt_worker_event_lane(&dummy_plaintext_event(
                DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1
            )),
            DecryptWorkerLane::Bulk
        );
        assert_eq!(
            decrypt_worker_event_lane(&dummy_failure_event()),
            DecryptWorkerLane::Priority
        );
        let batch = dummy_plaintext_batch_event(3, DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1);
        assert_eq!(decrypt_worker_event_lane(&batch), DecryptWorkerLane::Bulk);
        assert_eq!(batch.packet_count(), 3);
    }

    #[test]
    fn decrypt_worker_event_wait_metrics_split_authenticated_sessions_from_fallbacks() {
        let plaintext = dummy_plaintext_event(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN);
        assert_eq!(
            plaintext.queue_wait_stages().0,
            crate::perf_profile::Stage::DecryptFallbackWait
        );

        let failure = dummy_failure_event();
        assert_eq!(
            failure.queue_wait_stages().1,
            crate::perf_profile::Stage::DecryptFallbackPriorityWait
        );

        let authenticated = dummy_authenticated_session_event(DecryptWorkerLane::Bulk);
        assert_eq!(
            decrypt_worker_event_lane(&authenticated),
            DecryptWorkerLane::Bulk
        );
        assert_eq!(
            authenticated.queue_wait_stages(),
            (
                crate::perf_profile::Stage::DecryptAuthenticatedSessionWait,
                crate::perf_profile::Stage::DecryptAuthenticatedSessionPriorityWait,
                crate::perf_profile::Stage::DecryptAuthenticatedSessionBulkWait
            )
        );
    }

    #[test]
    fn decrypt_worker_fallback_sender_stamps_queue_wait_origin() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);

        assert!(fallback_tx.send(dummy_failure_event()));
        match fallback_rx
            .priority
            .try_recv()
            .expect("priority event should enqueue")
        {
            DecryptWorkerEvent::DecryptFailure(report) => {
                assert!(
                    report.trace_enqueued_at.is_none() || crate::perf_profile::enabled(),
                    "trace stamps should only appear when pipeline tracing is enabled"
                );
            }
            DecryptWorkerEvent::Plaintext(_) => panic!("expected failure report"),
            DecryptWorkerEvent::PlaintextBatch(_) => panic!("expected failure report"),
            DecryptWorkerEvent::AuthenticatedFmpReceive(_) => panic!("expected failure report"),
            DecryptWorkerEvent::AuthenticatedSession(_) => panic!("expected failure report"),
            DecryptWorkerEvent::AuthenticatedSessionBatch(_) => panic!("expected failure report"),
            DecryptWorkerEvent::DirectSessionCommit(_) => panic!("expected failure report"),
            DecryptWorkerEvent::DirectSessionCommitBatch(_) => panic!("expected failure report"),
            DecryptWorkerEvent::DirectSessionData(_) => panic!("expected failure report"),
            DecryptWorkerEvent::DirectSessionDataBatch(_) => panic!("expected failure report"),
            DecryptWorkerEvent::FspDecryptFailure(_) => panic!("expected failure report"),
        }
    }

    #[test]
    fn decrypt_job_owns_lane_selected_at_construction() {
        let session_key = test_session_key(1, 55);
        let mut priority =
            dummy_decrypt_job_with_len(session_key, DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN);

        assert_eq!(decrypt_job_lane(&priority), DecryptWorkerLane::Priority);
        priority
            .packet_data
            .resize(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1024, 0);
        assert_eq!(
            decrypt_job_lane(&priority),
            DecryptWorkerLane::Priority,
            "queued decrypt jobs must keep the lane chosen before dispatch"
        );

        let bulk =
            dummy_decrypt_job_with_len(session_key, DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1);
        assert_eq!(decrypt_job_lane(&bulk), DecryptWorkerLane::Bulk);
    }

    #[test]
    fn decrypt_fallback_event_owns_lane_selected_at_construction() {
        let mut priority = dummy_plaintext_event(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN);

        assert_eq!(
            decrypt_worker_event_lane(&priority),
            DecryptWorkerLane::Priority
        );
        let DecryptWorkerEvent::Plaintext(fallback) = &mut priority else {
            panic!("dummy plaintext event should be plaintext");
        };
        fallback.packet_len = DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1024;
        fallback.packet_data.resize(fallback.packet_len, 0);
        assert_eq!(
            decrypt_worker_event_lane(&priority),
            DecryptWorkerLane::Priority,
            "queued fallback events must keep the lane chosen before enqueue"
        );

        let bulk = dummy_plaintext_event(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1);
        assert_eq!(decrypt_worker_event_lane(&bulk), DecryptWorkerLane::Bulk);
    }

    #[test]
    fn decrypt_worker_fallback_bulk_full_does_not_starve_priority_events() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);

        assert!(fallback_tx.send(dummy_plaintext_event(
            DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1
        )));
        assert!(
            !fallback_tx.send(dummy_plaintext_event(
                DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1
            )),
            "second bulk fallback should be dropped at the bounded bulk lane"
        );
        assert!(
            fallback_tx.send(dummy_failure_event()),
            "priority fallback should still fit its reserved lane"
        );

        assert_eq!(fallback_rx.bulk.len(), 1);
        assert_eq!(fallback_rx.priority.len(), 1);
        assert!(matches!(
            fallback_rx.priority.try_recv().expect("priority event"),
            DecryptWorkerEvent::DecryptFailure(_)
        ));
        assert!(matches!(
            fallback_rx.bulk.try_recv().expect("bulk event"),
            DecryptWorkerEvent::Plaintext(_)
        ));
    }

    #[test]
    fn decrypt_worker_fallback_bulk_capacity_counts_batch_packets() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 2);

        assert!(fallback_tx.send(dummy_plaintext_batch_event(
            2,
            DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1
        )));
        assert_eq!(
            fallback_rx.bulk_queued_packets(),
            2,
            "batch should reserve one bulk slot per packet, not per mpsc item"
        );
        assert!(
            !fallback_tx.send(dummy_plaintext_event(
                DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1
            )),
            "bulk packet cap should reject another packet while the two-packet batch is queued"
        );
        assert!(
            fallback_tx.send(dummy_failure_event()),
            "priority fallback must not consume bulk packet capacity"
        );

        let event = fallback_rx.bulk.try_recv().expect("bulk batch event");
        assert!(matches!(event, DecryptWorkerEvent::PlaintextBatch(_)));
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.bulk_queued_packets(), 0);
        assert!(fallback_tx.send(dummy_plaintext_event(
            DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1
        )));
    }

    #[test]
    fn decrypt_worker_fallback_priority_full_returns_false_without_waiting() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);

        assert!(fallback_tx.send(dummy_failure_event()));
        assert_eq!(
            fallback_rx.priority.len(),
            1,
            "test priority fallback lane should start full"
        );

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let tx_for_thread = fallback_tx.clone();
        std::thread::spawn(move || {
            done_tx
                .send(tx_for_thread.send(dummy_failure_event()))
                .unwrap();
        });

        let sent = done_rx
            .recv_timeout(Duration::from_millis(250))
            .expect("full fallback priority lane must not park decrypt worker");
        assert!(
            !sent,
            "priority fallback sender should report pressure when the lane is full"
        );
        assert_eq!(
            fallback_rx.priority.len(),
            1,
            "priority fallback lane must stay bounded"
        );

        assert!(
            fallback_tx.send(dummy_plaintext_event(
                DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1
            )),
            "full priority fallback lane must not consume bulk fallback capacity"
        );
        assert_eq!(fallback_rx.bulk.len(), 1);
        assert!(matches!(
            fallback_rx.priority.try_recv().expect("priority event"),
            DecryptWorkerEvent::DecryptFailure(_)
        ));
        assert!(matches!(
            fallback_rx.bulk.try_recv().expect("bulk event"),
            DecryptWorkerEvent::Plaintext(_)
        ));
    }

    #[test]
    fn decrypt_worker_full_queue_drops_bulk_without_waiting() {
        let (pool, _control_rx, _priority_rx, bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 99);
        pool.dispatch_job(dummy_bulk_decrypt_job(session_key));
        assert_eq!(bulk_rx.len(), 1, "test bulk queue should start full");

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let pool_for_thread = pool.clone();
        std::thread::spawn(move || {
            pool_for_thread.dispatch_job(dummy_bulk_decrypt_job(session_key));
            done_tx.send(()).unwrap();
        });

        done_rx
            .recv_timeout(Duration::from_millis(250))
            .expect("full decrypt-worker bulk queue must not park dispatch");
        assert_eq!(
            bulk_rx.len(),
            1,
            "bulk packet should be dropped rather than queued past the bound"
        );
    }

    #[test]
    fn decrypt_worker_priority_packet_uses_priority_lane_when_bulk_queue_is_full() {
        let (pool, _control_rx, priority_rx, bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 99);
        pool.dispatch_job(dummy_bulk_decrypt_job(session_key));
        assert_eq!(bulk_rx.len(), 1, "test bulk queue should start full");

        pool.dispatch_job(dummy_priority_decrypt_job(session_key));
        assert_eq!(priority_rx.len(), 1, "priority packet should enqueue");
        assert_eq!(
            bulk_rx.len(),
            1,
            "priority packet should not overflow or consume the bulk lane"
        );
    }

    #[test]
    fn decrypt_worker_priority_packet_spills_to_bulk_when_priority_queue_is_full() {
        let (pool, _control_rx, priority_rx, bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 100);
        pool.dispatch_job(dummy_priority_decrypt_job(session_key));
        assert_eq!(priority_rx.len(), 1, "test priority queue should start full");

        pool.dispatch_job(dummy_priority_decrypt_job(session_key));
        assert_eq!(
            priority_rx.len(),
            1,
            "full priority queue should stay bounded"
        );
        assert_eq!(
            bulk_rx.len(),
            1,
            "overflow priority packet should spill to the bulk lane"
        );
        assert_eq!(
            pool.senders[0].bulk_queued_packets.load(Ordering::Relaxed),
            1,
            "spilled packet should reserve one bulk packet slot"
        );

        match bulk_rx.try_recv().expect("spilled priority packet") {
            DecryptWorkerBulkItem::Job(job) => {
                assert_eq!(job.session_key, session_key);
                assert_eq!(decrypt_job_lane(&job), DecryptWorkerLane::Priority);
            }
            DecryptWorkerBulkItem::FspJob(_)
            | DecryptWorkerBulkItem::FmpAeadOpen(_)
            | DecryptWorkerBulkItem::FspAeadOpen(_)
            | DecryptWorkerBulkItem::FspAeadOpenBatch(_)
            | DecryptWorkerBulkItem::Batch(_)
            | DecryptWorkerBulkItem::FspBatch(_) => panic!("expected spilled priority job"),
        }
    }

    #[test]
    fn decrypt_job_batcher_uses_worker_bulk_boundary_when_full() {
        let (pool, _control_rx, priority_rx, bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 100);
        pool.dispatch_job(dummy_bulk_decrypt_job(session_key));
        assert_eq!(bulk_rx.len(), 1, "test bulk queue should start full");

        let mut batcher = DecryptJobBatcher::new();
        batcher.push(&pool, dummy_bulk_decrypt_job(session_key));
        batcher.flush(&pool);
        assert_eq!(
            bulk_rx.len(),
            1,
            "bulk packets stop at the bounded worker queue, not an upstream pressure shedder"
        );

        let priority_job = dummy_priority_decrypt_job(session_key);
        pool.dispatch_job(priority_job);
        assert_eq!(priority_rx.len(), 1, "priority packet should enqueue");
    }

    #[test]
    fn fsp_open_worker_backlog_does_not_shed_fmp_bulk_before_worker_boundary() {
        let (pool, _control_rx, _priority_rx, bulk_rx) = one_slot_worker_pool();
        pool.senders[0]
            .bulk_queued_packets
            .store(1, Ordering::Relaxed);

        let session_key = test_session_key(1, 101);
        let mut batcher = DecryptJobBatcher::new();
        batcher.push(&pool, dummy_bulk_decrypt_job(session_key));
        batcher.flush(&pool);
        assert_eq!(
            bulk_rx.len(),
            0,
            "bulk reservation accounting, not opener pressure probes, decides whether the worker queue accepts"
        );
    }

    #[test]
    fn decrypt_job_batcher_groups_consecutive_bulk_jobs_for_one_worker() {
        let (pool, _control_rx, _priority_rx, bulk_rx) =
            test_worker_pool(1, DECRYPT_WORKER_BULK_BATCH_MAX);
        let session_key = test_session_key(1, 101);
        let mut batcher = DecryptJobBatcher::new();

        for _ in 0..3 {
            batcher.push(&pool, dummy_bulk_decrypt_job(session_key));
        }
        batcher.flush(&pool);

        assert_eq!(
            bulk_rx[0].len(),
            1,
            "three same-worker bulk packets should consume one channel slot"
        );
        match bulk_rx[0].try_recv().expect("batched bulk item") {
            DecryptWorkerBulkItem::Batch(jobs) => {
                assert_eq!(jobs.len(), 3);
                assert!(jobs.iter().all(DecryptJob::is_bulk_lane));
            }
            DecryptWorkerBulkItem::Job(_) => panic!("expected a multi-job bulk batch"),
            DecryptWorkerBulkItem::FspJob(_) => panic!("expected a multi-job bulk batch"),
            DecryptWorkerBulkItem::FmpAeadOpen(_) => panic!("expected a multi-job bulk batch"),
            DecryptWorkerBulkItem::FspAeadOpen(_) => panic!("expected a multi-job bulk batch"),
            DecryptWorkerBulkItem::FspAeadOpenBatch(_) => {
                panic!("expected a multi-job bulk batch")
            }
            DecryptWorkerBulkItem::FspBatch(_) => panic!("expected a multi-job bulk batch"),
        }
    }

    #[test]
    fn decrypt_job_batcher_flushes_bulk_when_session_changes() {
        let (pool, _control_rx, _priority_rx, bulk_rx) =
            test_worker_pool(1, DECRYPT_WORKER_BULK_BATCH_MAX);
        let mut batcher = DecryptJobBatcher::new();

        batcher.push(&pool, dummy_bulk_decrypt_job(test_session_key(1, 101)));
        batcher.push(&pool, dummy_bulk_decrypt_job(test_session_key(2, 101)));
        batcher.flush(&pool);

        assert_eq!(
            bulk_rx[0].len(),
            2,
            "same-worker packets for different sessions should keep separate owner turns"
        );
        assert!(
            matches!(
                bulk_rx[0].try_recv().expect("first session-local bulk item"),
                DecryptWorkerBulkItem::Job(_)
            ),
            "a session change should flush the pending singleton before batching resumes"
        );
        assert!(
            matches!(
                bulk_rx[0].try_recv().expect("second session-local bulk item"),
                DecryptWorkerBulkItem::Job(_)
            ),
            "the new session singleton should flush separately at the end"
        );
    }

    #[test]
    fn decrypt_worker_bulk_batch_emits_one_plaintext_fallback_batch() {
        let session_key = test_session_key(1, 106);
        let source_peer = test_source_peer();
        let cipher = test_chacha_key([0x42; 32]);
        let mut shard = test_shard();
        shard.register_session(
            0,
            session_key,
            OwnedSessionState::new(cipher.clone(), ReplayWindow::new(), source_peer),
        );
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, 4);
        let (control_tx, control_rx) = bounded::<WorkerMsg>(1);
        drop(control_tx);
        let (priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        drop(priority_tx);
        let bulk_body_len = DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 64;
        let (packet_one, header_one) =
            sealed_fmp_test_packet_with_link_body(&cipher, 1, 0, bulk_body_len);
        let (packet_two, header_two) =
            sealed_fmp_test_packet_with_link_body(&cipher, 2, 0, bulk_body_len);

        let mut plaintext_batch = DecryptPlaintextFallbackBatch::new();
        let mut batch_stats = DecryptWorkerBatchStats::default();
        let fmp_aead_completion_rx = test_fmp_aead_completion_lane(1);
        let fsp_aead_completion_rx = test_fsp_aead_completion_lane(1);
        let processed = handle_bulk_item(
            0,
            &mut shard,
            &control_rx,
            &priority_rx,
            &fmp_aead_completion_rx,
            &fsp_aead_completion_rx,
            DecryptWorkerBulkItem::Batch(vec![
                decrypt_job_for_test_packet(
                    packet_one,
                    header_one,
                    session_key,
                    1,
                    0,
                    fallback_tx.clone(),
                ),
                decrypt_job_for_test_packet(packet_two, header_two, session_key, 2, 0, fallback_tx),
            ]),
            &mut plaintext_batch,
            &mut batch_stats,
        );
        assert!(
            fallback_rx.bulk.try_recv().is_err(),
            "shared output batch should wait for an explicit flush"
        );
        plaintext_batch.flush();

        assert_eq!(processed, 2);
        assert_eq!(
            fallback_rx.bulk_queued_packets(),
            2,
            "one fallback batch should still reserve two bulk packet slots"
        );
        let event = fallback_rx.bulk.try_recv().expect("bulk fallback batch");
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.bulk_queued_packets(), 0);
        match event {
            DecryptWorkerEvent::PlaintextBatch(fallbacks) => {
                assert_eq!(fallbacks.len(), 2);
                assert_eq!(fallbacks[0].source_peer, source_peer);
                assert_eq!(fallbacks[1].source_peer, source_peer);
                assert_eq!(fallbacks[0].fmp_counter, 1);
                assert_eq!(fallbacks[1].fmp_counter, 2);
                assert!(fallbacks.iter().all(|fallback| {
                    fallback.packet_len > DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN
                }));
            }
            DecryptWorkerEvent::Plaintext(_)
            | DecryptWorkerEvent::AuthenticatedFmpReceive(_)
            | DecryptWorkerEvent::AuthenticatedSession(_)
            | DecryptWorkerEvent::AuthenticatedSessionBatch(_)
            | DecryptWorkerEvent::DirectSessionCommit(_)
            | DecryptWorkerEvent::DirectSessionCommitBatch(_)
            | DecryptWorkerEvent::DirectSessionData(_)
            | DecryptWorkerEvent::DirectSessionDataBatch(_)
            | DecryptWorkerEvent::FspDecryptFailure(_)
            | DecryptWorkerEvent::DecryptFailure(_) => {
                panic!("expected plaintext fallback batch")
            }
        }
    }

    #[test]
    fn decrypt_worker_bulk_batch_interleaves_priority_work() {
        let session_key = test_session_key(1, 107);
        let mut shard = test_shard();
        let (control_tx, control_rx) = bounded::<WorkerMsg>(1);
        drop(control_tx);
        let (priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        priority_tx
            .try_send(WorkerMsg::Job(dummy_priority_decrypt_job(session_key)))
            .expect("test priority lane should accept one packet");
        drop(priority_tx);

        let fmp_aead_completion_rx = test_fmp_aead_completion_lane(1);
        let fsp_aead_completion_rx = test_fsp_aead_completion_lane(1);
        let mut plaintext_batch = DecryptPlaintextFallbackBatch::new();
        let mut batch_stats = DecryptWorkerBatchStats::enabled_for_test();
        let item = DecryptWorkerBulkItem::Batch(vec![
            dummy_bulk_decrypt_job(session_key),
            dummy_bulk_decrypt_job(session_key),
        ]);
        batch_stats.add_bulk_item(&item);

        let processed = handle_bulk_item(
            0,
            &mut shard,
            &control_rx,
            &priority_rx,
            &fmp_aead_completion_rx,
            &fsp_aead_completion_rx,
            item,
            &mut plaintext_batch,
            &mut batch_stats,
        );

        assert_eq!(processed, 2);
        assert!(
            priority_rx.is_empty(),
            "priority packets must not wait for the rest of the bulk batch"
        );
        assert_eq!(batch_stats.priority_packets, 1);
        assert_eq!(batch_stats.bulk_packets, 2);
    }

    #[test]
    fn decrypt_worker_fsp_bulk_batch_interleaves_priority_work() {
        let mut shard = test_shard();
        let (control_tx, control_rx) = bounded::<WorkerMsg>(1);
        drop(control_tx);
        let (priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        priority_tx
            .try_send(WorkerMsg::FspJob(dummy_fsp_job(
                DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN,
            )))
            .expect("test priority lane should accept one FSP packet");
        drop(priority_tx);

        let fmp_aead_completion_rx = test_fmp_aead_completion_lane(1);
        let fsp_aead_completion_rx = test_fsp_aead_completion_lane(1);
        let mut plaintext_batch = DecryptPlaintextFallbackBatch::new();
        let mut batch_stats = DecryptWorkerBatchStats::enabled_for_test();
        let item = DecryptWorkerBulkItem::FspBatch(vec![
            dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1),
            dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1),
        ]);
        batch_stats.add_bulk_item(&item);

        let processed = handle_bulk_item(
            0,
            &mut shard,
            &control_rx,
            &priority_rx,
            &fmp_aead_completion_rx,
            &fsp_aead_completion_rx,
            item,
            &mut plaintext_batch,
            &mut batch_stats,
        );

        assert_eq!(processed, 2);
        assert!(
            priority_rx.is_empty(),
            "priority FSP packets must not wait for the rest of the bulk batch"
        );
        assert_eq!(batch_stats.priority_packets, 1);
        assert_eq!(batch_stats.bulk_packets, 2);
    }

    #[test]
    fn decrypt_worker_plaintext_batch_never_exceeds_fallback_packet_cap() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, 2);
        let bulk_len = DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1;
        let mut batch = DecryptPlaintextFallbackBatch::new();

        batch.push_output(DecryptWorkerOutput {
            fallback_tx: fallback_tx.clone(),
            event: dummy_plaintext_event(bulk_len),
            direct_delivery: None,
        });
        assert!(
            fallback_rx.bulk.try_recv().is_err(),
            "first packet should stay buffered until the fallback cap-width batch is full"
        );
        batch.push_output(DecryptWorkerOutput {
            fallback_tx: fallback_tx.clone(),
            event: dummy_plaintext_event(bulk_len),
            direct_delivery: None,
        });

        let event = fallback_rx.bulk.try_recv().expect("two-packet batch");
        assert_eq!(
            event.packet_count(),
            2,
            "plaintext batch should fill, but not exceed, the fallback packet cap"
        );
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.bulk_queued_packets(), 0);

        batch.push_output(DecryptWorkerOutput {
            fallback_tx,
            event: dummy_plaintext_event(bulk_len),
            direct_delivery: None,
        });
        batch.flush();

        let event = fallback_rx.bulk.try_recv().expect("single trailing packet");
        assert_eq!(event.packet_count(), 1);
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.bulk_queued_packets(), 0);
    }

    #[test]
    fn decrypt_worker_plaintext_batch_flushes_at_batch_width() {
        let cap = DECRYPT_WORKER_BULK_BATCH_MAX + 1;
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, cap);
        let bulk_len = DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1;
        let mut batch = DecryptPlaintextFallbackBatch::new();

        for _ in 0..DECRYPT_WORKER_BULK_BATCH_MAX {
            batch.push_output(DecryptWorkerOutput {
                fallback_tx: fallback_tx.clone(),
                event: dummy_plaintext_event(bulk_len),
                direct_delivery: None,
            });
        }

        let event = fallback_rx.bulk.try_recv().expect("full-width batch");
        assert_eq!(
            event.packet_count(),
            DECRYPT_WORKER_BULK_BATCH_MAX,
            "plaintext completion batches should use the configured bounded width"
        );
        fallback_rx.release_dequeued_event(&event);

        batch.push_output(DecryptWorkerOutput {
            fallback_tx,
            event: dummy_plaintext_event(bulk_len),
            direct_delivery: None,
        });
        batch.flush();

        let event = fallback_rx.bulk.try_recv().expect("single trailing packet");
        assert_eq!(event.packet_count(), 1);
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.bulk_queued_packets(), 0);
    }

    #[test]
    fn decrypt_worker_authenticated_sessions_batch_authenticated_bulk_returns() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 2);
        let mut batch = DecryptPlaintextFallbackBatch::new();

        batch.push_output(DecryptWorkerOutput {
            fallback_tx: fallback_tx.clone(),
            event: dummy_authenticated_session_event(DecryptWorkerLane::Bulk),
            direct_delivery: None,
        });
        assert!(
            fallback_rx.authenticated_bulk.try_recv().is_err(),
            "first authenticated session should wait for the cap-width batch"
        );

        batch.push_output(DecryptWorkerOutput {
            fallback_tx: fallback_tx.clone(),
            event: dummy_authenticated_session_event(DecryptWorkerLane::Bulk),
            direct_delivery: None,
        });

        assert_eq!(
            fallback_rx.authenticated_bulk_queued_packets(),
            2,
            "one authenticated session batch should reserve two authenticated bulk packet slots"
        );
        let event = fallback_rx
            .authenticated_bulk
            .try_recv()
            .expect("authenticated session batch");
        assert_eq!(event.packet_count(), 2);
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.authenticated_bulk_queued_packets(), 0);
        match event {
            DecryptWorkerEvent::AuthenticatedSessionBatch(sessions) => {
                assert_eq!(sessions.len(), 2);
                assert!(
                    sessions
                        .iter()
                        .all(|session| matches!(session.lane, DecryptWorkerLane::Bulk))
                );
            }
            DecryptWorkerEvent::AuthenticatedSession(_) => {
                panic!("expected authenticated session batch")
            }
            DecryptWorkerEvent::Plaintext(_)
            | DecryptWorkerEvent::PlaintextBatch(_)
            | DecryptWorkerEvent::AuthenticatedFmpReceive(_)
            | DecryptWorkerEvent::DirectSessionCommit(_)
            | DecryptWorkerEvent::DirectSessionCommitBatch(_)
            | DecryptWorkerEvent::DirectSessionData(_)
            | DecryptWorkerEvent::DirectSessionDataBatch(_)
            | DecryptWorkerEvent::FspDecryptFailure(_)
            | DecryptWorkerEvent::DecryptFailure(_) => {
                panic!("expected authenticated session batch")
            }
        }

        batch.push_output(DecryptWorkerOutput {
            fallback_tx,
            event: dummy_authenticated_session_event(DecryptWorkerLane::Bulk),
            direct_delivery: None,
        });
        batch.flush();

        let event = fallback_rx
            .authenticated_bulk
            .try_recv()
            .expect("single trailing authenticated session");
        assert_eq!(event.packet_count(), 1);
        assert!(matches!(
            &event,
            DecryptWorkerEvent::AuthenticatedSession(_)
        ));
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.authenticated_bulk_queued_packets(), 0);
    }

    #[test]
    fn decrypt_worker_priority_authenticated_session_bypasses_bulk_batch() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let mut batch = DecryptPlaintextFallbackBatch::new();

        batch.push_output(DecryptWorkerOutput {
            fallback_tx,
            event: dummy_authenticated_session_event(DecryptWorkerLane::Priority),
            direct_delivery: None,
        });

        let event = fallback_rx
            .priority
            .try_recv()
            .expect("priority authenticated session");
        assert_eq!(event.packet_count(), 1);
        assert!(matches!(
            &event,
            DecryptWorkerEvent::AuthenticatedSession(_)
        ));
        assert!(
            fallback_rx.authenticated_bulk.try_recv().is_err(),
            "priority authenticated session must not wait behind the authenticated bulk lane"
        );
    }

    #[test]
    fn decrypt_worker_routed_direct_data_batches_authenticated_bulk_returns() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let source_peer = test_source_peer();
        let mut batch = DecryptPlaintextFallbackBatch::new();

        batch.push_output(dummy_routed_direct_data_output(
            fallback_tx.clone(),
            source_peer,
            1,
            b"routed-one",
        ));
        assert!(
            fallback_rx.authenticated_bulk.try_recv().is_err(),
            "first routed direct data should wait for a batch flush"
        );

        batch.push_output(dummy_routed_direct_data_output(
            fallback_tx,
            source_peer,
            2,
            b"routed-two",
        ));
        assert!(
            fallback_rx.authenticated_bulk.try_recv().is_err(),
            "second routed direct data should still wait below batch cap"
        );
        batch.flush();

        assert_eq!(
            fallback_rx.authenticated_bulk_queued_packets(),
            2,
            "one routed data batch should reserve two authenticated bulk packet slots"
        );
        let event = fallback_rx
            .authenticated_bulk
            .try_recv()
            .expect("routed direct data batch");
        assert_eq!(event.packet_count(), 2);
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.authenticated_bulk_queued_packets(), 0);
        match event {
            DecryptWorkerEvent::DirectSessionDataBatch(directs) => {
                assert_eq!(directs.len(), 2);
                assert_eq!(directs[0].source_addr, *source_peer.node_addr());
                assert_eq!(directs[1].source_addr, *source_peer.node_addr());
                assert_eq!(directs[0].fmp.fmp_counter, 1);
                assert_eq!(directs[1].fmp.fmp_counter, 2);
            }
            DecryptWorkerEvent::DirectSessionData(_) => {
                panic!("expected routed direct data batch")
            }
            DecryptWorkerEvent::Plaintext(_)
            | DecryptWorkerEvent::PlaintextBatch(_)
            | DecryptWorkerEvent::AuthenticatedFmpReceive(_)
            | DecryptWorkerEvent::AuthenticatedSession(_)
            | DecryptWorkerEvent::AuthenticatedSessionBatch(_)
            | DecryptWorkerEvent::DirectSessionCommit(_)
            | DecryptWorkerEvent::DirectSessionCommitBatch(_)
            | DecryptWorkerEvent::FspDecryptFailure(_)
            | DecryptWorkerEvent::DecryptFailure(_) => panic!("expected routed direct data batch"),
        }
    }
