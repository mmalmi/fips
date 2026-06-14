    #[test]
    fn decrypt_worker_direct_endpoint_batch_waits_for_commit_queue_acceptance() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let (endpoint_tx, mut endpoint_rx) = EndpointEventSender::channel(8);
        let sink = DecryptDirectSessionDeliverySink::new(None, None, Some(endpoint_tx));
        let source_peer = test_source_peer();
        let mut batch = DecryptPlaintextFallbackBatch::new();

        batch.push_output(dummy_direct_endpoint_output(
            fallback_tx.clone(),
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
            fallback_tx,
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
            DecryptWorkerEvent::DirectFmpEndpointData(_) => panic!("expected a direct commit batch"),
            DecryptWorkerEvent::DirectFmpEndpointDataBatch(_) => {
                panic!("expected a direct commit batch")
            }
            DecryptWorkerEvent::Plaintext(_)
            | DecryptWorkerEvent::PlaintextBatch(_)
            | DecryptWorkerEvent::AuthenticatedSession(_)
            | DecryptWorkerEvent::DirectSessionData(_)
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
    fn decrypt_worker_direct_fmp_endpoint_data_batches_authenticated_bulk_lane() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let source_peer = test_source_peer();
        let mut batch = DecryptPlaintextFallbackBatch::new();

        batch.push_output(dummy_direct_fmp_endpoint_output(
            fallback_tx.clone(),
            source_peer,
            1,
            DecryptWorkerLane::Bulk,
            b"direct-fmp-one".to_vec(),
        ));
        assert!(
            fallback_rx.authenticated_bulk.try_recv().is_err(),
            "first bulk direct-FMP endpoint event should wait for a batch flush"
        );

        batch.push_output(dummy_direct_fmp_endpoint_output(
            fallback_tx,
            source_peer,
            2,
            DecryptWorkerLane::Bulk,
            b"direct-fmp-two".to_vec(),
        ));
        batch.flush();

        assert_eq!(
            fallback_rx.authenticated_bulk_queued_packets(),
            2,
            "direct-FMP endpoint batch should reserve by packet count"
        );
        let event = fallback_rx
            .authenticated_bulk
            .try_recv()
            .expect("direct-FMP endpoint batch");
        assert_eq!(event.packet_count(), 2);
        match &event {
            DecryptWorkerEvent::DirectFmpEndpointDataBatch(endpoints) => {
                assert_eq!(endpoints.len(), 2);
                assert_eq!(endpoints[0].fmp.source_peer, source_peer);
                assert_eq!(endpoints[1].fmp.source_peer, source_peer);
                assert_eq!(endpoints[0].fmp.fmp_counter, 1);
                assert_eq!(endpoints[1].fmp.fmp_counter, 2);
                assert_eq!(endpoints[0].payload(), b"direct-fmp-one");
                assert_eq!(endpoints[1].payload(), b"direct-fmp-two");
            }
            DecryptWorkerEvent::DirectFmpEndpointData(_) => {
                panic!("expected a direct-FMP endpoint batch")
            }
            DecryptWorkerEvent::Plaintext(_)
            | DecryptWorkerEvent::PlaintextBatch(_)
            | DecryptWorkerEvent::AuthenticatedFmpReceive(_)
            | DecryptWorkerEvent::AuthenticatedSession(_)
            | DecryptWorkerEvent::DirectSessionCommit(_)
            | DecryptWorkerEvent::DirectSessionCommitBatch(_)
            | DecryptWorkerEvent::DirectSessionData(_)
            | DecryptWorkerEvent::FspDecryptFailure(_)
            | DecryptWorkerEvent::DecryptFailure(_) => {
                panic!("expected a direct-FMP endpoint batch")
            }
        }
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.authenticated_bulk_queued_packets(), 0);
    }

    #[test]
    fn decrypt_worker_direct_fmp_endpoint_data_priority_stays_single() {
        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(8, 8);
        let source_peer = test_source_peer();
        let mut batch = DecryptPlaintextFallbackBatch::new();

        batch.push_output(dummy_direct_fmp_endpoint_output(
            fallback_tx,
            source_peer,
            1,
            DecryptWorkerLane::Priority,
            b"small-control-shaped-endpoint-data".to_vec(),
        ));

        let event = fallback_rx
            .priority
            .try_recv()
            .expect("priority direct-FMP endpoint data");
        match event {
            DecryptWorkerEvent::DirectFmpEndpointData(endpoint) => {
                assert_eq!(endpoint.fmp.source_peer, source_peer);
                assert_eq!(endpoint.fmp.fmp_counter, 1);
                assert_eq!(endpoint.payload(), b"small-control-shaped-endpoint-data");
                assert_eq!(endpoint.lane, DecryptWorkerLane::Priority);
            }
            DecryptWorkerEvent::DirectFmpEndpointDataBatch(_) => {
                panic!("priority direct-FMP endpoint data must not batch")
            }
            DecryptWorkerEvent::Plaintext(_)
            | DecryptWorkerEvent::PlaintextBatch(_)
            | DecryptWorkerEvent::AuthenticatedFmpReceive(_)
            | DecryptWorkerEvent::AuthenticatedSession(_)
            | DecryptWorkerEvent::DirectSessionCommit(_)
            | DecryptWorkerEvent::DirectSessionCommitBatch(_)
            | DecryptWorkerEvent::DirectSessionData(_)
            | DecryptWorkerEvent::FspDecryptFailure(_)
            | DecryptWorkerEvent::DecryptFailure(_) => {
                panic!("expected priority direct-FMP endpoint data")
            }
        }
        assert!(fallback_rx.authenticated_bulk.try_recv().is_err());
        assert_eq!(fallback_rx.authenticated_bulk_queued_packets(), 0);
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
        let mut batch = DecryptPlaintextFallbackBatch::new();

        batch.push_output(dummy_direct_endpoint_output(
            fallback_tx.clone(),
            sink.clone(),
            source_peer,
            1,
            b"drop-one",
        ));
        batch.push_output(dummy_direct_endpoint_output(
            fallback_tx,
            sink,
            source_peer,
            2,
            b"drop-two",
        ));

        assert!(
            fallback_rx.authenticated_bulk_queued_packets() == 2,
            "direct endpoint commits should reserve the authenticated lane, not the fallback lane"
        );

        let event = fallback_rx.bulk.try_recv().expect("pre-filled bulk event");
        assert!(
            matches!(event, DecryptWorkerEvent::Plaintext(_)),
            "fallback bulk pressure should remain isolated from authenticated commits"
        );
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.bulk_queued_packets(), 0);

        let event = fallback_rx
            .authenticated_bulk
            .try_recv()
            .expect("direct commit batch");
        assert_eq!(event.packet_count(), 2);
        fallback_rx.release_dequeued_event(&event);
        assert_eq!(fallback_rx.authenticated_bulk_queued_packets(), 0);

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

        let mut first_batch = DecryptPlaintextFallbackBatch::new();
        first_batch.push_output(dummy_direct_endpoint_output(
            fallback_tx.clone(),
            sink.clone(),
            source_peer,
            1,
            b"queued-one",
        ));
        first_batch.push_output(dummy_direct_endpoint_output(
            fallback_tx.clone(),
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

        let mut second_batch = DecryptPlaintextFallbackBatch::new();
        second_batch.push_output(dummy_direct_endpoint_output(
            fallback_tx,
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

        let mut batch = DecryptPlaintextFallbackBatch::new();
        batch.push_output(dummy_direct_endpoint_output(
            fallback_tx,
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
        let mut batch = DecryptPlaintextFallbackBatch::new();

        for idx in 0..DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX {
            batch.push_output(dummy_direct_endpoint_output(
                fallback_tx.clone(),
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
        let (pool, priority_rx, bulk_rx) = one_slot_worker_pool();
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
        let (pool, _priority_rx, bulk_rx) = one_slot_worker_pool();
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
        let (pool, _priority_rx, bulk_rx) = test_worker_pool(1, DECRYPT_WORKER_BULK_BATCH_MAX);
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

        let (pool, _priority_rx, bulk_rx) = test_worker_pool(1, WORKER_PACKET_CAP);
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
    fn decrypt_worker_register_uses_priority_lane_when_bulk_queue_is_full() {
        let (pool, priority_rx, bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 77);
        pool.dispatch_job(dummy_bulk_decrypt_job(session_key));
        assert_eq!(bulk_rx.len(), 1, "test bulk queue should start full");

        assert!(pool.register_session(session_key, test_owned_session_state()));
        assert_eq!(priority_rx.len(), 1, "registration should enqueue");
        assert_eq!(
            bulk_rx.len(),
            1,
            "registration should not consume the full bulk lane"
        );
    }

    #[test]
    fn decrypt_worker_unregister_uses_priority_lane_when_bulk_queue_is_full() {
        let (pool, priority_rx, bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 78);
        pool.dispatch_job(dummy_bulk_decrypt_job(session_key));
        assert_eq!(bulk_rx.len(), 1, "test bulk queue should start full");

        assert!(pool.unregister_session(session_key));
        assert_eq!(priority_rx.len(), 1, "unregister should enqueue");
        assert_eq!(
            bulk_rx.len(),
            1,
            "unregister should not consume the full bulk lane"
        );
    }

    #[test]
    fn decrypt_worker_register_full_returns_false_without_waiting() {
        let (pool, priority_rx, _bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 77);
        assert!(pool.register_session(session_key, test_owned_session_state()));
        assert_eq!(
            priority_rx.len(),
            1,
            "test priority queue should start full"
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
            !registered,
            "registration should report pressure so caller retries later"
        );
        assert_eq!(
            priority_rx.len(),
            1,
            "registration should not overflow the bounded priority queue"
        );
    }

    #[test]
    fn decrypt_worker_unregister_full_returns_false_without_waiting() {
        let (pool, priority_rx, _bulk_rx) = one_slot_worker_pool();
        let session_key = test_session_key(1, 78);
        assert!(pool.register_session(session_key, test_owned_session_state()));
        assert_eq!(
            priority_rx.len(),
            1,
            "test priority queue should start full"
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
            "unregister should report pressure when the priority lane is full"
        );
        assert_eq!(
            priority_rx.len(),
            1,
            "unregister should not overflow the bounded priority queue"
        );
    }

    #[test]
    fn decrypt_worker_drain_registers_priority_before_bulk_jobs() {
        let (priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (bulk_tx, bulk_rx, bulk_queued_packets) = test_bulk_lane(1);
        let session_key = test_session_key(1, 77);
        priority_tx
            .try_send(WorkerMsg::RegisterSession {
                session_key,
                state: test_owned_session_state(),
            })
            .expect("priority registration should enqueue");

        let (fallback_tx, mut fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        let mut bulk_job = dummy_bulk_decrypt_job(session_key);
        bulk_job.fallback_tx = fallback_tx;
        queue_bulk_item_for_test(
            &bulk_tx,
            &bulk_queued_packets,
            DecryptWorkerBulkItem::Job(bulk_job),
        );

        let mut shard = test_shard();
        let fmp_aead_completion_rx = test_fmp_aead_completion_lane(1);
        drain_worker_queues(
            0,
            &mut shard,
            &priority_rx,
            &fmp_aead_completion_rx,
            &bulk_rx,
            &bulk_queued_packets,
        );

        assert!(
            shard.contains_session(session_key),
            "priority registration must be applied before queued bulk work"
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
            DecryptWorkerEvent::DirectFmpEndpointData(_) => {
                panic!("invalid bulk job should fail AEAD")
            }
            DecryptWorkerEvent::DirectFmpEndpointDataBatch(_) => {
                panic!("invalid bulk job should fail AEAD")
            }
            DecryptWorkerEvent::AuthenticatedSession(_) => {
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
            DecryptWorkerEvent::FspDecryptFailure(_) => {
                panic!("invalid bulk job should fail FMP AEAD")
            }
        }
        assert!(
            priority_rx.is_empty(),
            "priority queue should be fully drained before bulk"
        );
        assert!(bulk_rx.is_empty(), "bulk queue should be drained");
    }

    #[test]
    fn decrypt_worker_drain_unregisters_priority_before_bulk_jobs() {
        let (priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (bulk_tx, bulk_rx, bulk_queued_packets) = test_bulk_lane(1);
        let session_key = test_session_key(1, 78);

        priority_tx
            .try_send(WorkerMsg::UnregisterSession { session_key })
            .expect("priority unregister should enqueue");

        let (fallback_tx, fallback_rx) = decrypt_worker_fallback_channels_with_caps(1, 1);
        let mut bulk_job = dummy_bulk_decrypt_job(session_key);
        bulk_job.fallback_tx = fallback_tx;
        queue_bulk_item_for_test(
            &bulk_tx,
            &bulk_queued_packets,
            DecryptWorkerBulkItem::Job(bulk_job),
        );

        let mut shard = test_shard();
        shard.register_session(0, session_key, test_owned_session_state());
        let fmp_aead_completion_rx = test_fmp_aead_completion_lane(1);
        drain_worker_queues(
            0,
            &mut shard,
            &priority_rx,
            &fmp_aead_completion_rx,
            &bulk_rx,
            &bulk_queued_packets,
        );

        assert!(
            !shard.contains_session(session_key),
            "priority unregister must remove stale session state before queued bulk work"
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
            priority_rx.is_empty(),
            "priority queue should be fully drained before bulk"
        );
        assert!(bulk_rx.is_empty(), "bulk queue should be drained");
    }

    #[test]
    fn decrypt_worker_blocking_receive_prefers_ready_priority_over_bulk() {
        let (priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (bulk_tx, bulk_rx, bulk_queued_packets) = test_bulk_lane(1);
        let session_key = test_session_key(1, 79);
        priority_tx
            .try_send(WorkerMsg::RegisterSession {
                session_key,
                state: test_owned_session_state(),
            })
            .expect("priority registration should enqueue");
        queue_bulk_item_for_test(
            &bulk_tx,
            &bulk_queued_packets,
            DecryptWorkerBulkItem::Job(dummy_bulk_decrypt_job(session_key)),
        );

        let fmp_aead_completion_rx = test_fmp_aead_completion_lane(1);
        match recv_worker_item_biased(&priority_rx, &fmp_aead_completion_rx, &bulk_rx) {
            DecryptWorkerQueueItem::Priority(WorkerMsg::RegisterSession {
                session_key: got,
                ..
            }) => assert_eq!(got, session_key),
            DecryptWorkerQueueItem::Priority(_) => {
                panic!("expected priority registration item")
            }
            DecryptWorkerQueueItem::Bulk(_) => {
                panic!("blocking receive must not select bulk while priority is ready")
            }
            DecryptWorkerQueueItem::FmpAeadCompletion(_) => {
                panic!("blocking receive must not select completion while priority is ready")
            }
            DecryptWorkerQueueItem::Closed => panic!("worker channels should be open"),
        }
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
            DECRYPT_WORKER_FMP_RECEIVE_WINDOW, 1024,
            "FMP helper in-flight order window should absorb several GSO/helper turns"
        );
        assert!(
            DECRYPT_WORKER_FMP_RECEIVE_WINDOW >= DECRYPT_WORKER_BULK_BURST_BUDGET * 8,
            "FMP receive ordering must not force bulk traffic to wait behind a single worker turn"
        );
        assert_eq!(
            DECRYPT_WORKER_BULK_BATCH_MAX, 32,
            "bulk batches should amortize handoff churn without becoming a whole worker turn"
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
            DECRYPT_WORKER_DIRECT_DELIVERY_BATCH_MAX, DECRYPT_WORKER_BULK_BURST_BUDGET,
            "direct delivery may coalesce one bounded worker turn after payload bytes leave the rx-loop bounce"
        );
        assert_eq!(
            DECRYPT_WORKER_ENDPOINT_DELIVERY_BATCH_MAX, DECRYPT_WORKER_BULK_BURST_BUDGET,
            "direct endpoint delivery may coalesce one bounded worker turn after payload bytes leave the rx-loop bounce"
        );

        let (_priority_tx, priority_rx) = bounded::<WorkerMsg>(1);
        let (bulk_tx, bulk_rx, bulk_queued_packets) =
            test_bulk_lane(DECRYPT_WORKER_BULK_BURST_BUDGET + 1);
        let session_key = test_session_key(1, 79);
        for _ in 0..=DECRYPT_WORKER_BULK_BURST_BUDGET {
            queue_bulk_item_for_test(
                &bulk_tx,
                &bulk_queued_packets,
                DecryptWorkerBulkItem::Job(dummy_bulk_decrypt_job(session_key)),
            );
        }

        let mut shard = test_shard();
        let fmp_aead_completion_rx = test_fmp_aead_completion_lane(1);
        drain_worker_queues(
            0,
            &mut shard,
            &priority_rx,
            &fmp_aead_completion_rx,
            &bulk_rx,
            &bulk_queued_packets,
        );

        assert_eq!(
            bulk_rx.len(),
            1,
            "one worker drain call must respect the bounded bulk burst budget"
        );
    }
