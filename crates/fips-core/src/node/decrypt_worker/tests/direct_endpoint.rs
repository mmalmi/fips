    #[test]
    fn decrypt_worker_direct_endpoint_batch_waits_for_commit_queue_acceptance() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let (endpoint_tx, mut endpoint_rx) = EndpointEventSender::channel(8);
        let sink = DecryptDirectSessionDeliverySink::new(None, None, Some(endpoint_tx));
        let source_peer = test_source_peer();
        let mut batch = DecryptPlaintextFallbackBatch::new(fallback_tx.clone());

        batch.push_output(dummy_direct_endpoint_output(
            sink.clone(),
            source_peer,
            1,
            b"direct-one",
        ));
        assert!(
            fallback_rx.authenticated_bulk.try_recv().is_err(),
            "first endpoint completion should wait for a batch flush"
        );
        assert!(
            endpoint_rx.try_recv().is_err(),
            "endpoint bytes must not release before the commit is queued"
        );

        batch.push_output(dummy_direct_endpoint_output(
            sink,
            source_peer,
            2,
            b"direct-two",
        ));
        assert!(
            fallback_rx.authenticated_bulk.try_recv().is_err(),
            "second endpoint completion should still wait below batch cap"
        );
        assert!(
            endpoint_rx.try_recv().is_err(),
            "endpoint bytes must still wait below batch cap"
        );
        batch.flush();

        let event = fallback_rx
            .authenticated_bulk
            .try_recv()
            .expect("direct commit batch");
        assert_eq!(event.packet_count(), 2);
        match &event {
            DecryptWorkerEvent::DirectSessionCommitBatch(commits) => {
                assert_eq!(commits.len(), 2);
                assert_eq!(commits[0].source_addr, *source_peer.node_addr());
                assert_eq!(commits[1].source_addr, *source_peer.node_addr());
                assert_eq!(commits[0].fmp.fmp_counter, 1);
                assert_eq!(commits[1].fmp.fmp_counter, 2);
                assert!(commits.iter().all(|commit| !commit.delivered_ipv6));
            }
            DecryptWorkerEvent::DirectSessionCommit(_) => panic!("expected a commit batch"),
            DecryptWorkerEvent::AuthenticatedFmpReceive(_) => {
                panic!("expected a direct commit batch")
            }
            DecryptWorkerEvent::Plaintext(_)
            | DecryptWorkerEvent::PlaintextBatch(_)
            | DecryptWorkerEvent::AuthenticatedSession(_)
            | DecryptWorkerEvent::AuthenticatedSessionBatch(_)
            | DecryptWorkerEvent::DirectSessionData(_)
            | DecryptWorkerEvent::DirectSessionDataBatch(_)
            | DecryptWorkerEvent::FspDecryptFailure(_)
            | DecryptWorkerEvent::DecryptFailure(_) => panic!("expected a direct commit batch"),
        }
        fallback_rx.release_dequeued_event(&event);

        match endpoint_rx.try_recv().expect("endpoint batch") {
            NodeEndpointEvent::DataBatch { messages, .. } => {
                assert_eq!(messages.len(), 2);
                assert_eq!(messages[0].source_peer, source_peer);
                assert_eq!(messages[1].source_peer, source_peer);
                assert_eq!(messages[0].payload, b"direct-one");
                assert_eq!(messages[1].payload, b"direct-two");
            }
            NodeEndpointEvent::Data { .. } => panic!("expected endpoint data batch"),
        }
    }

    #[test]
    fn decrypt_worker_direct_endpoint_batch_has_reserved_authenticated_bulk_lane() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 2);
        let bulk_len = DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1;
        assert!(fallback_tx.send(dummy_plaintext_event(bulk_len)));
        assert_eq!(
            fallback_rx.bulk_queued_packets(),
            1,
            "test precondition should reserve one bulk packet slot"
        );

        let (endpoint_tx, mut endpoint_rx) = EndpointEventSender::channel(8);
        let sink = DecryptDirectSessionDeliverySink::new(None, None, Some(endpoint_tx));
        let source_peer = test_source_peer();
        let mut batch = DecryptPlaintextFallbackBatch::new(fallback_tx.clone());

        batch.push_output(dummy_direct_endpoint_output(
            sink.clone(),
            source_peer,
            1,
            b"drop-one",
        ));
        batch.push_output(dummy_direct_endpoint_output(
            sink,
            source_peer,
            2,
            b"drop-two",
        ));

        assert!(
            fallback_rx.authenticated_bulk_queued_packets() == 2,
            "direct endpoint commits should reserve the authenticated lane, not the fallback lane"
        );
        assert_eq!(
            fallback_rx.bulk_pressure_queued_packets(),
            3,
            "return-lane pressure should include plaintext and authenticated bulk"
        );

        let event = fallback_rx.bulk.try_recv().expect("pre-filled bulk event");
        assert!(
            matches!(event, DecryptWorkerEvent::Plaintext(_)),
            "fallback bulk pressure should remain isolated from authenticated commits"
        );
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.bulk_queued_packets(), 0);
        assert_eq!(
            fallback_rx.bulk_pressure_queued_packets(),
            2,
            "authenticated bulk should still contribute to pressure after plaintext drains"
        );

        let event = fallback_rx
            .authenticated_bulk
            .try_recv()
            .expect("direct commit batch");
        assert_eq!(event.packet_count(), 2);
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.authenticated_bulk_queued_packets(), 0);
        assert_eq!(fallback_rx.bulk_pressure_queued_packets(), 0);

        match endpoint_rx.try_recv().expect("endpoint data batch") {
            NodeEndpointEvent::DataBatch { messages, .. } => {
                assert_eq!(messages.len(), 2);
                assert_eq!(messages[0].payload, b"drop-one");
                assert_eq!(messages[1].payload, b"drop-two");
            }
            event => panic!("expected endpoint data batch, got {event:?}"),
        }
        assert!(
            fallback_rx.bulk.try_recv().is_err(),
            "only the pre-filled plaintext event should have reached the fallback bulk lane"
        );
    }

    #[test]
    fn decrypt_worker_direct_endpoint_batch_drops_delivery_when_authenticated_lane_is_full() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 2);
        let (endpoint_tx, mut endpoint_rx) = EndpointEventSender::channel(8);
        let sink = DecryptDirectSessionDeliverySink::new(None, None, Some(endpoint_tx));
        let source_peer = test_source_peer();

        let mut first_batch = DecryptPlaintextFallbackBatch::new(fallback_tx.clone());
        first_batch.push_output(dummy_direct_endpoint_output(
            sink.clone(),
            source_peer,
            1,
            b"queued-one",
        ));
        first_batch.push_output(dummy_direct_endpoint_output(
            sink.clone(),
            source_peer,
            2,
            b"queued-two",
        ));
        first_batch.flush();
        assert_eq!(fallback_rx.authenticated_bulk_queued_packets(), 2);
        endpoint_rx
            .try_recv()
            .expect("first accepted endpoint batch");

        let mut second_batch = DecryptPlaintextFallbackBatch::new(fallback_tx.clone());
        second_batch.push_output(dummy_direct_endpoint_output(
            sink,
            source_peer,
            3,
            b"dropped-after-auth-pressure",
        ));
        second_batch.flush();

        assert!(
            endpoint_rx.try_recv().is_err(),
            "endpoint bytes must not release when their authenticated commit lane is full"
        );

        let event = fallback_rx
            .authenticated_bulk
            .try_recv()
            .expect("first accepted commit batch");
        assert_eq!(event.packet_count(), 2);
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.authenticated_bulk_queued_packets(), 0);
        assert!(
            fallback_rx.authenticated_bulk.try_recv().is_err(),
            "rejected endpoint commit must not enqueue after pressure rejection"
        );
    }

    #[test]
    fn decrypt_worker_direct_endpoint_delivery_accepts_bulk_payloads() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let (endpoint_tx, mut endpoint_rx) = EndpointEventSender::channel(8);
        let sink = DecryptDirectSessionDeliverySink::new(None, None, Some(endpoint_tx));
        let source_peer = test_source_peer();
        let bulk_payload = vec![0xAB; crate::node::ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1];
        let delivery = DecryptDirectSessionDelivery::EndpointData(EndpointDataDelivery::new(
            source_peer,
            bulk_payload.clone(),
        ));

        assert!(
            sink.can_deliver(&delivery),
            "direct-hop bulk endpoint payloads should not bounce through rx_loop after worker decrypt"
        );

        let mut batch = DecryptPlaintextFallbackBatch::new(fallback_tx.clone());
        batch.push_output(dummy_direct_endpoint_output(
            sink,
            source_peer,
            1,
            &bulk_payload,
        ));
        batch.flush();

        let event = fallback_rx
            .authenticated_bulk
            .try_recv()
            .expect("direct commit");
        assert_eq!(event.packet_count(), 1);
        fallback_rx.release_dequeued_event(&event);

        match endpoint_rx.try_recv().expect("bulk endpoint event") {
            NodeEndpointEvent::Data { payload, .. } => assert_eq!(payload, bulk_payload),
            event => panic!("expected direct bulk endpoint data event, got {event:?}"),
        }
    }

    #[test]
    fn decrypt_worker_direct_endpoint_batch_can_span_one_worker_burst() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(
            8,
            DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX + 1,
        );
        let (endpoint_tx, mut endpoint_rx) =
            EndpointEventSender::channel(DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX + 1);
        let sink = DecryptDirectSessionDeliverySink::new(None, None, Some(endpoint_tx));
        let source_peer = test_source_peer();
        let bulk_payload = vec![0xCD; crate::node::ENDPOINT_EVENT_PRIORITY_MAX_LEN + 1];
        let mut batch = DecryptPlaintextFallbackBatch::new(fallback_tx.clone());

        for idx in 0..DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX {
            batch.push_output(dummy_direct_endpoint_output(
                sink.clone(),
                source_peer,
                idx as u64,
                &bulk_payload,
            ));
        }

        let event = fallback_rx
            .authenticated_bulk
            .try_recv()
            .expect("burst-sized commit batch");
        assert_eq!(
            event.packet_count(),
            DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX
        );
        fallback_rx.release_dequeued_event(&event);

        match endpoint_rx.try_recv().expect("burst-sized endpoint batch") {
            NodeEndpointEvent::DataBatch { messages, .. } => {
                assert_eq!(messages.len(), DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX);
                assert!(
                    messages
                        .iter()
                        .all(|message| message.payload == bulk_payload)
                );
            }
            event => panic!("expected burst-sized endpoint data batch, got {event:?}"),
        }
    }

    #[test]
    fn decrypt_job_batcher_flushes_bulk_before_priority_job() {
        let (pool, _control_rx, priority_rx, bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 102);
        let mut batcher = DecryptJobBatcher::new();

        batcher.push(&pool, dummy_bulk_decrypt_job(session_key));
        batcher.push(&pool, dummy_priority_decrypt_job(session_key));

        assert_eq!(
            bulk_rx.len(),
            1,
            "pending bulk should be flushed before the priority job is queued"
        );
        assert_eq!(
            priority_rx.len(),
            1,
            "priority jobs must keep their reserved lane"
        );
        assert!(matches!(
            priority_rx.try_recv().expect("priority item"),
            WorkerMsg::Job(_)
        ));
        assert!(matches!(
            bulk_rx.try_recv().expect("bulk item"),
            DecryptWorkerBulkItem::Job(_)
        ));
    }

    #[test]
    fn decrypt_job_batcher_keeps_bulk_capacity_in_packet_units() {
        let (pool, _control_rx, _priority_rx, bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 103);
        let mut batcher = DecryptJobBatcher::new();

        batcher.push(&pool, dummy_bulk_decrypt_job(session_key));
        batcher.push(&pool, dummy_bulk_decrypt_job(session_key));
        batcher.flush(&pool);

        assert_eq!(
            bulk_rx.len(),
            1,
            "a one-packet bulk capacity should enqueue exactly one packet"
        );
        assert!(
            matches!(
                bulk_rx.try_recv().expect("single packet bulk item"),
                DecryptWorkerBulkItem::Job(_)
            ),
            "single-packet capacity must not be inflated into a wider batch"
        );
    }

    #[test]
    fn decrypt_job_batcher_reuses_pending_buffer_for_single_bulk_flush() {
        let (pool, _control_rx, _priority_rx, bulk_rx) =
            test_worker_pool(1, DECRYPT_WORKER_BULK_BATCH_MAX);
        let session_key = test_session_key(1, 104);
        let mut batcher = DecryptJobBatcher::new();
        let pending_buffer = batcher.pending_buffer_ptr();

        batcher.push(&pool, dummy_bulk_decrypt_job(session_key));
        batcher.flush(&pool);

        assert_eq!(
            batcher.pending_buffer_ptr(),
            pending_buffer,
            "single-job flushes should not allocate a replacement pending buffer"
        );
        assert!(
            matches!(
                bulk_rx[0].try_recv().expect("single bulk item"),
                DecryptWorkerBulkItem::Job(_)
            ),
            "single-job flush should still dispatch a single job, not a batch"
        );
    }

    #[test]
    fn decrypt_job_batcher_limits_batch_width_to_worker_packet_capacity() {
        const WORKER_PACKET_CAP: usize = 8;

        let (pool, _control_rx, _priority_rx, bulk_rx) =
            test_worker_pool(1, WORKER_PACKET_CAP);
        let session_key = test_session_key(1, 105);
        let mut batcher = DecryptJobBatcher::new();

        for _ in 0..=WORKER_PACKET_CAP {
            batcher.push(&pool, dummy_bulk_decrypt_job(session_key));
        }
        batcher.flush(&pool);

        assert_eq!(
            bulk_rx[0].len(),
            1,
            "worker packet capacity should be consumed by one bounded batch"
        );
        match bulk_rx[0].try_recv().expect("bounded bulk batch") {
            DecryptWorkerBulkItem::Batch(jobs) => assert_eq!(
                jobs.len(),
                WORKER_PACKET_CAP,
                "batch width should stop at the worker packet capacity"
            ),
            DecryptWorkerBulkItem::Job(_) => panic!("expected an eight-packet bulk batch"),
            DecryptWorkerBulkItem::FspJob(_) => panic!("expected an eight-packet bulk batch"),
            DecryptWorkerBulkItem::FspAeadOpen(_) => panic!("expected an eight-packet bulk batch"),
            DecryptWorkerBulkItem::FspAeadOpenBatch(_) => {
                panic!("expected an eight-packet bulk batch")
            }
            DecryptWorkerBulkItem::FspBatch(_) => panic!("expected an eight-packet bulk batch"),
        }
        assert!(
            bulk_rx[0].is_empty(),
            "the ninth packet should be rejected while eight packets remain queued"
        );
    }

    #[test]
    fn decrypt_worker_bulk_accounting_reserves_and_releases_exact_counts() {
        let counter = AtomicUsize::new(0);

        assert!(try_reserve_bulk_packets(&counter, 4, 3));
        assert_eq!(counter.load(Ordering::Relaxed), 3);
        assert!(
            !try_reserve_bulk_packets(&counter, 4, 2),
            "bulk packet capacity must be counted in jobs, not channel items"
        );
        release_bulk_packets(&counter, 2);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        assert!(try_reserve_bulk_packets(&counter, 4, 3));
        assert_eq!(counter.load(Ordering::Relaxed), 4);
        release_bulk_packets(&counter, 4);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn decrypt_worker_bulk_accounting_can_reserve_partial_capacity() {
        let counter = AtomicUsize::new(2);

        assert_eq!(try_reserve_bulk_packets_partial(&counter, 4, 4), 2);
        assert_eq!(counter.load(Ordering::Relaxed), 4);
        assert_eq!(
            try_reserve_bulk_packets_partial(&counter, 4, 1),
            0,
            "full packet capacity should not over-reserve"
        );
        release_bulk_packets(&counter, 3);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        assert_eq!(try_reserve_bulk_packets_partial(&counter, 4, 2), 2);
        assert_eq!(counter.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn decrypt_worker_register_uses_control_lane_when_bulk_queue_is_full() {
        let (pool, control_rx, priority_rx, bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 77);
        pool.dispatch_job(dummy_bulk_decrypt_job(session_key));
        assert_eq!(bulk_rx.len(), 1, "test bulk queue should start full");

        assert_eq!(
            pool.register_session(session_key, test_owned_session_state()),
            Some(0)
        );
        assert_eq!(control_rx.len(), 1, "registration should enqueue");
        assert_eq!(
            priority_rx.len(),
            0,
            "registration should not consume the small-packet priority lane"
        );
        assert_eq!(
            bulk_rx.len(),
            1,
            "registration should not consume the full bulk lane"
        );
    }

    #[test]
    fn decrypt_worker_unregister_uses_control_lane_when_bulk_queue_is_full() {
        let (pool, control_rx, priority_rx, bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 78);
        pool.dispatch_job(dummy_bulk_decrypt_job(session_key));
        assert_eq!(bulk_rx.len(), 1, "test bulk queue should start full");

        assert!(pool.unregister_session(session_key));
        assert_eq!(control_rx.len(), 1, "unregister should enqueue");
        assert_eq!(
            priority_rx.len(),
            0,
            "unregister should not consume the small-packet priority lane"
        );
        assert_eq!(
            bulk_rx.len(),
            1,
            "unregister should not consume the full bulk lane"
        );
    }

    #[test]
    fn decrypt_worker_register_full_returns_false_without_waiting() {
        let (pool, control_rx, priority_rx, _bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 77);
        assert_eq!(
            pool.register_session(session_key, test_owned_session_state()),
            Some(0)
        );
        assert_eq!(
            control_rx.len(),
            1,
            "test control queue should start full"
        );

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let pool_for_thread = pool.clone();
        std::thread::spawn(move || {
            let registered =
                pool_for_thread.register_session(session_key, test_owned_session_state());
            done_tx.send(registered).unwrap();
        });

        let registered = done_rx
            .recv_timeout(Duration::from_millis(250))
            .expect("full decrypt-worker control queue must not park registration");
        assert!(
            registered.is_none(),
            "registration should report pressure so caller retries later"
        );
        assert_eq!(
            control_rx.len(),
            1,
            "registration should not overflow the bounded control queue"
        );
        assert!(priority_rx.is_empty(), "priority lane should remain available");
    }

    #[test]
    fn decrypt_worker_unregister_full_returns_false_without_waiting() {
        let (pool, control_rx, priority_rx, _bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 78);
        assert_eq!(
            pool.register_session(session_key, test_owned_session_state()),
            Some(0)
        );
        assert_eq!(
            control_rx.len(),
            1,
            "test control queue should start full"
        );

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let pool_for_thread = pool.clone();
        std::thread::spawn(move || {
            let unregistered = pool_for_thread.unregister_session(session_key);
            done_tx.send(unregistered).unwrap();
        });

        let unregistered = done_rx
            .recv_timeout(Duration::from_millis(250))
            .expect("full decrypt-worker control queue must not park unregister");
        assert!(
            !unregistered,
            "unregister should report pressure when the control lane is full"
        );
        assert_eq!(
            control_rx.len(),
            1,
            "unregister should not overflow the bounded control queue"
        );
        assert!(priority_rx.is_empty(), "priority lane should remain available");
    }

    #[test]
    fn decrypt_worker_drain_registers_control_before_bulk_jobs() {
        let (control_tx, control_rx) = bounded::<WorkerMsg>(1);
        let (_priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (bulk_tx, bulk_rx, bulk_queued_packets) = test_bulk_lane(1);
        let session_key = test_session_key(1, 77);
        control_tx
            .try_send(WorkerMsg::RegisterSession {
                session_key,
                state: test_owned_session_state(),
            })
            .expect("control registration should enqueue");

        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        let bulk_job = dummy_bulk_decrypt_job(session_key);
        queue_bulk_item_for_test(
            &bulk_tx,
            &bulk_queued_packets,
            DecryptWorkerBulkItem::Job(bulk_job),
        );

        let mut shard = test_shard();
        let fsp_aead_completion_rx = test_fsp_aead_completion_lane(1);
        let mut plaintext_batch = DecryptPlaintextFallbackBatch::new(fallback_tx.clone());
        drain_worker_queues(
            0,
            &mut shard,
            &control_rx,
            &priority_rx,
            &fsp_aead_completion_rx,
            &bulk_rx,
            &bulk_queued_packets,
            &mut plaintext_batch,
        );

        assert!(
            shard.contains_session(session_key),
            "control registration must be applied before queued bulk work"
        );
        match fallback_rx
            .priority
            .try_recv()
            .expect("bulk job should run after registration")
        {
            DecryptWorkerEvent::DecryptFailure(report) => {
                assert_eq!(report.fmp_counter, 1);
            }
            DecryptWorkerEvent::Plaintext(_) => panic!("invalid bulk job should fail AEAD"),
            DecryptWorkerEvent::PlaintextBatch(_) => panic!("invalid bulk job should fail AEAD"),
            DecryptWorkerEvent::AuthenticatedFmpReceive(_) => {
                panic!("invalid bulk job should fail AEAD")
            }
            DecryptWorkerEvent::AuthenticatedSession(_) => {
                panic!("invalid bulk job should fail AEAD")
            }
            DecryptWorkerEvent::AuthenticatedSessionBatch(_) => {
                panic!("invalid bulk job should fail AEAD")
            }
            DecryptWorkerEvent::DirectSessionCommit(_) => {
                panic!("invalid bulk job should fail AEAD")
            }
            DecryptWorkerEvent::DirectSessionCommitBatch(_) => {
                panic!("invalid bulk job should fail AEAD")
            }
            DecryptWorkerEvent::DirectSessionData(_) => {
                panic!("invalid bulk job should fail AEAD")
            }
            DecryptWorkerEvent::DirectSessionDataBatch(_) => {
                panic!("invalid bulk job should fail AEAD")
            }
            DecryptWorkerEvent::FspDecryptFailure(_) => {
                panic!("invalid bulk job should fail FMP AEAD")
            }
        }
        assert!(
            control_rx.is_empty(),
            "control queue should be fully drained before bulk"
        );
        assert!(priority_rx.is_empty(), "priority queue should remain empty");
        assert!(bulk_rx.is_empty(), "bulk queue should be drained");
    }

    #[test]
    fn decrypt_worker_drain_unregisters_control_before_bulk_jobs() {
        let (control_tx, control_rx) = bounded::<WorkerMsg>(1);
        let (_priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (bulk_tx, bulk_rx, bulk_queued_packets) = test_bulk_lane(1);
        let session_key = test_session_key(1, 78);

        control_tx
            .try_send(WorkerMsg::UnregisterSession { session_key })
            .expect("control unregister should enqueue");

        let (fallback_tx, fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        let bulk_job = dummy_bulk_decrypt_job(session_key);
        queue_bulk_item_for_test(
            &bulk_tx,
            &bulk_queued_packets,
            DecryptWorkerBulkItem::Job(bulk_job),
        );

        let mut shard = test_shard();
        shard.register_session(0, session_key, test_owned_session_state());
        let fsp_aead_completion_rx = test_fsp_aead_completion_lane(1);
        let mut plaintext_batch = DecryptPlaintextFallbackBatch::new(fallback_tx.clone());
        drain_worker_queues(
            0,
            &mut shard,
            &control_rx,
            &priority_rx,
            &fsp_aead_completion_rx,
            &bulk_rx,
            &bulk_queued_packets,
            &mut plaintext_batch,
        );

        assert!(
            !shard.contains_session(session_key),
            "control unregister must remove stale session state before queued bulk work"
        );
        assert!(
            fallback_rx.priority.is_empty(),
            "bulk job for unregistered session must not use stale state and emit AEAD failure"
        );
        assert!(
            fallback_rx.bulk.is_empty(),
            "bulk job for unregistered session must not produce plaintext"
        );
        assert!(
            control_rx.is_empty(),
            "control queue should be fully drained before bulk"
        );
        assert!(priority_rx.is_empty(), "priority queue should remain empty");
        assert!(bulk_rx.is_empty(), "bulk queue should be drained");
    }

    #[test]
    fn decrypt_worker_drain_reports_idle_only_after_ready_work_is_empty() {
        let (control_tx, control_rx) = bounded::<WorkerMsg>(1);
        let (_priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (_bulk_tx, bulk_rx, bulk_queued_packets) = test_bulk_lane(1);
        let fsp_aead_completion_rx = test_fsp_aead_completion_lane(1);
        let session_key = test_session_key(1, 79);
        let mut shard = test_shard();
        let mut plaintext_batch =
            DecryptPlaintextFallbackBatch::new(shard.pool.fallback_tx.clone());

        assert!(
            !drain_worker_queues(
                0,
                &mut shard,
                &control_rx,
                &priority_rx,
                &fsp_aead_completion_rx,
                &bulk_rx,
                &bulk_queued_packets,
                &mut plaintext_batch,
            ),
            "empty queues should let the worker enter the blocking receive"
        );

        control_tx
            .try_send(WorkerMsg::RegisterSession {
                session_key,
                state: test_owned_session_state(),
            })
            .expect("control registration should enqueue");

        assert!(
            drain_worker_queues(
                0,
                &mut shard,
                &control_rx,
                &priority_rx,
                &fsp_aead_completion_rx,
                &bulk_rx,
                &bulk_queued_packets,
                &mut plaintext_batch,
            ),
            "ready control work should keep the worker on the bounded drain path"
        );
        assert!(
            shard.contains_session(session_key),
            "ready control work should still be processed by the drain"
        );
        assert!(
            !drain_worker_queues(
                0,
                &mut shard,
                &control_rx,
                &priority_rx,
                &fsp_aead_completion_rx,
                &bulk_rx,
                &bulk_queued_packets,
                &mut plaintext_batch,
            ),
            "drained queues should report idle on the next pass"
        );
    }

    #[test]
    fn decrypt_worker_blocking_receive_prefers_ready_control_over_bulk() {
        let (control_tx, control_rx) = bounded::<WorkerMsg>(1);
        let (priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (bulk_tx, bulk_rx, bulk_queued_packets) = test_bulk_lane(1);
        let session_key = test_session_key(1, 80);
        control_tx
            .try_send(WorkerMsg::RegisterSession {
                session_key,
                state: test_owned_session_state(),
            })
            .expect("control registration should enqueue");
        queue_bulk_item_for_test(
            &bulk_tx,
            &bulk_queued_packets,
            DecryptWorkerBulkItem::Job(dummy_bulk_decrypt_job(session_key)),
        );
        priority_tx
            .try_send(WorkerMsg::Job(dummy_priority_decrypt_job(session_key)))
            .expect("priority packet should enqueue");

        let fsp_aead_completion_rx = test_fsp_aead_completion_lane(1);
        match recv_worker_item_biased(
            &control_rx,
            &priority_rx,
            &fsp_aead_completion_rx,
            &bulk_rx,
        ) {
            DecryptWorkerQueueItem::Control(WorkerMsg::RegisterSession {
                session_key: got,
                ..
            }) => assert_eq!(got, session_key),
            DecryptWorkerQueueItem::Control(_) => {
                panic!("expected control registration item")
            }
            DecryptWorkerQueueItem::Priority(_) => {
                panic!("blocking receive must not select priority while control is ready")
            }
            DecryptWorkerQueueItem::Bulk(_) => {
                panic!("blocking receive must not select bulk while control is ready")
            }
            DecryptWorkerQueueItem::FspAeadCompletion(_) => {
                panic!("blocking receive must not select FSP AEAD completion while control is ready")
            }
            DecryptWorkerQueueItem::Closed => panic!("worker channels should be open"),
        }
        assert_eq!(priority_rx.len(), 1, "priority work should remain queued");
        assert_eq!(
            bulk_rx.len(),
            1,
            "bulk work should remain queued for the next bounded drain"
        );
    }

    #[test]
    fn decrypt_worker_bulk_drain_budget_matches_receive_batch_width() {
        assert_eq!(
            DECRYPT_WORKER_BULK_BURST_BUDGET, 128,
            "worker burst should track the reference packet-mover receive batch width"
        );
        assert_eq!(
            DECRYPT_WORKER_BULK_BATCH_MAX, 16,
            "bulk batches should amortize handoff churn without becoming a long priority-blocking slice"
        );
        assert_eq!(
            DECRYPT_WORKER_BULK_BURST_BUDGET % DECRYPT_WORKER_BULK_BATCH_MAX,
            0,
            "bulk batch width should divide the worker burst budget cleanly"
        );
        const _: () = assert!(
            DECRYPT_WORKER_BULK_BATCH_MAX <= DECRYPT_WORKER_BULK_BURST_BUDGET / 4,
            "one worker burst should still contain several bounded bulk batches"
        );
        assert_eq!(
            DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX, DECRYPT_WORKER_BULK_BATCH_MAX,
            "direct delivery should flush in one bulk-batch slice so decrypted bursts do not reach the TUN/app receiver as a whole worker turn"
        );
        assert_eq!(
            DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX, DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX,
            "direct endpoint delivery should use the same bounded delivery slice as direct TUN delivery"
        );
        assert_eq!(
            DECRYPT_WORKER_AEAD_COMPLETION_DRAIN_BUDGET,
            DECRYPT_WORKER_BULK_BATCH_MAX,
            "completion backlog should get one reserved owner slice before bulk, not consume the whole bulk turn"
        );
        assert_eq!(
            DECRYPT_WORKER_AEAD_COMPLETION_INTERLEAVE_BUDGET,
            DECRYPT_WORKER_BULK_BATCH_MAX,
            "completion interleave should be bounded to one bulk item width"
        );

        let (_control_tx, control_rx) = bounded::<WorkerMsg>(1);
        let (_priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (bulk_tx, bulk_rx, bulk_queued_packets) =
            test_bulk_lane(DECRYPT_WORKER_BULK_BURST_BUDGET + 1);
        let session_key = test_session_key(1, 81);
        for _ in 0..=DECRYPT_WORKER_BULK_BURST_BUDGET {
            queue_bulk_item_for_test(
                &bulk_tx,
                &bulk_queued_packets,
                DecryptWorkerBulkItem::Job(dummy_bulk_decrypt_job(session_key)),
            );
        }

        let mut shard = test_shard();
        let fsp_aead_completion_rx = test_fsp_aead_completion_lane(1);
        let mut plaintext_batch =
            DecryptPlaintextFallbackBatch::new(shard.pool.fallback_tx.clone());
        drain_worker_queues(
            0,
            &mut shard,
            &control_rx,
            &priority_rx,
            &fsp_aead_completion_rx,
            &bulk_rx,
            &bulk_queued_packets,
            &mut plaintext_batch,
        );

        assert_eq!(
            bulk_rx.len(),
            1,
            "one worker drain call must respect the bounded bulk burst budget"
        );
    }

    #[test]
    fn opened_fmp_established_fsp_datagram_is_bulk_even_when_outer_packet_is_small() {
        let previous_hop = test_source_peer();
        let local_addr = *previous_hop.node_addr();
        let source_addr = NodeAddr::from_bytes([0x5a; 16]);
        let fsp_payload = crate::node::session_wire::build_fsp_header(7, 0, 0).to_vec();
        let link_msg = crate::protocol::SessionDatagram::new(source_addr, local_addr, fsp_payload)
            .with_path_mtu(1_280)
            .encode();
        let inner_timestamp_ms = 0x0a0b_0c0du32;
        let mut fmp_plaintext = Vec::with_capacity(4 + link_msg.len());
        fmp_plaintext.extend_from_slice(&inner_timestamp_ms.to_le_bytes());
        fmp_plaintext.extend_from_slice(&link_msg);

        let fmp_plaintext_offset = crate::node::wire::ESTABLISHED_HEADER_SIZE;
        let packet_len = fmp_plaintext_offset + fmp_plaintext.len();
        assert!(
            packet_len <= DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN,
            "test packet should be priority-sized before FMP decrypt"
        );
        let mut packet_data = vec![0; packet_len];
        packet_data[fmp_plaintext_offset..].copy_from_slice(&fmp_plaintext);
        let (_fallback_tx, _fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, 4);
        let action = DecryptWorkerShard::handle_opened_fmp_job(OpenedFmpJob {
            packet_data: packet_data.into(),
            source_peer: previous_hop,
            transport_id: TransportId::new(1),
            remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            local_node_addr: local_addr,
            timestamp_ms: 1_000,
            packet_len,
            fmp_counter: 1,
            fmp_flags: 0,
            fmp_plaintext_offset,
            fmp_plaintext_len: fmp_plaintext.len(),
        })
        .expect("established FSP datagram should produce a worker action");

        match action {
            DecryptWorkerJobAction::FspJob(fsp_job) => {
                assert_eq!(
                    fsp_job.fallback.lane(),
                    DecryptWorkerLane::Priority,
                    "the outer FMP packet remains small enough to be priority-sized"
                );
                assert_eq!(
                    fsp_job.lane(),
                    DecryptWorkerLane::Bulk,
                    "established FSP session traffic must not flood the priority lane"
                );
            }
            DecryptWorkerJobAction::Output(_) => panic!("expected established FSP worker job"),
        }
    }

    #[test]
    fn decrypt_worker_completion_drain_budget_does_not_spend_bulk_turn() {
        let session_key = test_session_key(1, 82);
        let (_control_tx, control_rx) = bounded::<WorkerMsg>(1);
        let (_priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (bulk_tx, bulk_rx, bulk_queued_packets) =
            test_bulk_lane(DECRYPT_WORKER_BULK_BURST_BUDGET + 1);
        for _ in 0..=DECRYPT_WORKER_BULK_BURST_BUDGET {
            queue_bulk_item_for_test(
                &bulk_tx,
                &bulk_queued_packets,
                DecryptWorkerBulkItem::Job(dummy_bulk_decrypt_job(session_key)),
            );
        }

        let completion_count = DECRYPT_WORKER_AEAD_COMPLETION_DRAIN_BUDGET + 3;
        let (fsp_completion_tx, fsp_aead_completion_rx) =
            bounded::<FspAeadCompletionBatch>(completion_count);
        let source_addr = *test_source_peer().node_addr();
        for sequence in 0..completion_count {
            fsp_completion_tx
                .try_send(dummy_fsp_aead_completion_batch(
                    source_addr,
                    sequence as u64,
                ))
                .expect("completion lane should have room");
        }

        let mut shard = test_shard();
        let mut plaintext_batch =
            DecryptPlaintextFallbackBatch::new(shard.pool.fallback_tx.clone());
        drain_worker_queues(
            0,
            &mut shard,
            &control_rx,
            &priority_rx,
            &fsp_aead_completion_rx,
            &bulk_rx,
            &bulk_queued_packets,
            &mut plaintext_batch,
        );

        assert_eq!(
            fsp_aead_completion_rx.len(),
            completion_count - DECRYPT_WORKER_AEAD_COMPLETION_DRAIN_BUDGET,
            "one drain turn should reserve only one bounded completion slice before bulk"
        );
        assert_eq!(
            bulk_rx.len(),
            1,
            "completion backlog must not spend the bounded bulk drain turn"
        );
    }

    #[test]
    fn decrypt_worker_completion_drain_flushes_ready_outputs_before_bulk() {
        let (_control_tx, control_rx) = bounded::<WorkerMsg>(1);
        let (_priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (bulk_tx, bulk_rx, bulk_queued_packets) = test_bulk_lane(1);
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, 2);
        let bulk_len = DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1;

        let mut plaintext_batch = DecryptPlaintextFallbackBatch::new(fallback_tx.clone());
        plaintext_batch.push_output(DecryptWorkerOutput {
            event: dummy_plaintext_event(bulk_len),
            direct_delivery: None,
        });
        assert!(
            fallback_rx.bulk.try_recv().is_err(),
            "first bulk return should stay buffered below the fallback cap"
        );

        let bulk_job = dummy_fsp_job(bulk_len);
        queue_bulk_item_for_test(
            &bulk_tx,
            &bulk_queued_packets,
            DecryptWorkerBulkItem::FspJob(bulk_job),
        );

        let (fsp_completion_tx, fsp_aead_completion_rx) = bounded::<FspAeadCompletionBatch>(1);
        fsp_completion_tx
            .try_send(dummy_fsp_aead_completion_batch(
                *test_source_peer().node_addr(),
                0,
            ))
            .expect("completion lane should have room");

        let mut shard = test_shard();
        drain_worker_queues(
            0,
            &mut shard,
            &control_rx,
            &priority_rx,
            &fsp_aead_completion_rx,
            &bulk_rx,
            &bulk_queued_packets,
            &mut plaintext_batch,
        );

        let first = fallback_rx
            .bulk
            .try_recv()
            .expect("completion drain should flush the already-ready return before bulk work");
        assert_eq!(
            first.packet_count(),
            1,
            "the pre-bulk completion flush must not coalesce with the next bulk packet"
        );
        fallback_rx.release_dequeued_event(&first);
        let second = fallback_rx
            .bulk
            .try_recv()
            .expect("bulk packet should flush at the end of the drain turn");
        assert_eq!(second.packet_count(), 1);
        fallback_rx.release_dequeued_event(&second);
        assert_eq!(fallback_rx.bulk_queued_packets(), 0);
    }

    #[test]
    fn decrypt_worker_bulk_packet_steps_bound_aead_completion_interleave() {
        let session_key = test_session_key(1, 83);
        let mut shard = test_shard();
        let (_control_tx, control_rx) = bounded::<WorkerMsg>(1);
        let (_priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let bulk_packets = 2;
        let completion_count =
            (DECRYPT_WORKER_AEAD_COMPLETION_INTERLEAVE_BUDGET * bulk_packets) + 3;
        let (fsp_completion_tx, fsp_aead_completion_rx) =
            bounded::<FspAeadCompletionBatch>(completion_count);
        let source_addr = *test_source_peer().node_addr();
        for sequence in 0..completion_count {
            fsp_completion_tx
                .try_send(dummy_fsp_aead_completion_batch(
                    source_addr,
                    sequence as u64,
                ))
                .expect("completion lane should have room");
        }

        let mut plaintext_batch =
            DecryptPlaintextFallbackBatch::new(shard.pool.fallback_tx.clone());
        let mut batch_stats = DecryptWorkerBatchStats::enabled_for_test();
        let processed = handle_bulk_item(
            0,
            &mut shard,
            &control_rx,
            &priority_rx,
            &fsp_aead_completion_rx,
            DecryptWorkerBulkItem::Batch(vec![
                dummy_bulk_decrypt_job(session_key),
                dummy_bulk_decrypt_job(session_key),
            ]),
            &mut plaintext_batch,
            &mut batch_stats,
        );

        assert_eq!(processed, 2);
        assert_eq!(
            fsp_aead_completion_rx.len(),
            3,
            "a saturated completion lane should drain one bounded slice per bulk packet"
        );
    }

    #[test]
    fn decrypt_worker_bulk_interleave_flushes_ready_outputs_before_bulk_packet() {
        let mut shard = test_shard();
        let (_control_tx, control_rx) = bounded::<WorkerMsg>(1);
        let (_priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (fsp_completion_tx, fsp_aead_completion_rx) = bounded::<FspAeadCompletionBatch>(1);
        fsp_completion_tx
            .try_send(dummy_fsp_aead_completion_batch(
                *test_source_peer().node_addr(),
                0,
            ))
            .expect("completion lane should have room");

        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(4, 2);
        let bulk_len = DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1;
        let mut plaintext_batch = DecryptPlaintextFallbackBatch::new(fallback_tx.clone());
        plaintext_batch.push_output(DecryptWorkerOutput {
            event: dummy_plaintext_event(bulk_len),
            direct_delivery: None,
        });
        assert!(
            fallback_rx.bulk.try_recv().is_err(),
            "first bulk return should stay buffered below the fallback cap"
        );

        let bulk_job = dummy_fsp_job(bulk_len);
        let mut batch_stats = DecryptWorkerBatchStats::enabled_for_test();
        let processed = handle_bulk_item(
            0,
            &mut shard,
            &control_rx,
            &priority_rx,
            &fsp_aead_completion_rx,
            DecryptWorkerBulkItem::FspBatch(vec![bulk_job]),
            &mut plaintext_batch,
            &mut batch_stats,
        );
        plaintext_batch.flush();

        assert_eq!(processed, 1);
        let first = fallback_rx
            .bulk
            .try_recv()
            .expect("completion interleave should flush the already-ready return");
        assert_eq!(
            first.packet_count(),
            1,
            "the completion interleave flush must not coalesce with the bulk packet"
        );
        fallback_rx.release_dequeued_event(&first);
        let second = fallback_rx
            .bulk
            .try_recv()
            .expect("bulk packet should flush after service");
        assert_eq!(second.packet_count(), 1);
        fallback_rx.release_dequeued_event(&second);
        assert_eq!(fallback_rx.bulk_queued_packets(), 0);
    }

    #[test]
    fn decrypt_worker_fsp_bulk_packet_steps_bound_aead_completion_interleave() {
        let mut shard = test_shard();
        let (_control_tx, control_rx) = bounded::<WorkerMsg>(1);
        let (_priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let bulk_packets = 2;
        let completion_count =
            (DECRYPT_WORKER_AEAD_COMPLETION_INTERLEAVE_BUDGET * bulk_packets) + 5;
        let (fsp_completion_tx, fsp_aead_completion_rx) =
            bounded::<FspAeadCompletionBatch>(completion_count);
        let source_addr = *test_source_peer().node_addr();
        for sequence in 0..completion_count {
            fsp_completion_tx
                .try_send(dummy_fsp_aead_completion_batch(
                    source_addr,
                    sequence as u64,
                ))
                .expect("completion lane should have room");
        }

        let mut plaintext_batch =
            DecryptPlaintextFallbackBatch::new(shard.pool.fallback_tx.clone());
        let mut batch_stats = DecryptWorkerBatchStats::enabled_for_test();
        let processed = handle_bulk_item(
            0,
            &mut shard,
            &control_rx,
            &priority_rx,
            &fsp_aead_completion_rx,
            DecryptWorkerBulkItem::FspBatch(vec![
                dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1),
                dummy_fsp_job(DECRYPT_WORKER_PRIORITY_PACKET_MAX_LEN + 1),
            ]),
            &mut plaintext_batch,
            &mut batch_stats,
        );

        assert_eq!(processed, 2);
        assert_eq!(
            fsp_aead_completion_rx.len(),
            5,
            "FSP owner bulk service should drain one bounded completion slice per bulk packet"
        );
    }
