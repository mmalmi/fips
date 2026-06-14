    #[test]
    fn queued_fmp_send_job_owns_clamped_scheduling_weight() {
        with_test_socket(|socket, cipher| {
            let addr: SocketAddr = "127.0.0.1:10026".parse().unwrap();

            let mut explicit = queued_job(
                socket.clone(),
                &cipher,
                addr,
                128,
                true,
                EXPLICIT_PEER_SEND_WEIGHT,
            );
            assert_eq!(
                explicit.scheduling_weight(),
                EXPLICIT_PEER_SEND_WEIGHT as usize
            );
            explicit.job.scheduling_weight = MAX_SEND_WEIGHT;
            assert_eq!(
                explicit.scheduling_weight(),
                EXPLICIT_PEER_SEND_WEIGHT as usize,
                "queued worker messages own the scheduling weight used by admission"
            );

            let low = queued_job(socket.clone(), &cipher, addr, 128, true, 0);
            assert_eq!(low.scheduling_weight(), MIN_SEND_WEIGHT as usize);

            let high = queued_job(socket, &cipher, addr, 128, true, u8::MAX);
            assert_eq!(high.scheduling_weight(), MAX_SEND_WEIGHT as usize);
        });
    }

    #[test]
    fn selected_send_target_key_drives_dispatch_and_admission_without_endpoint_flow() {
        with_test_socket(|socket_a, cipher| {
            let raw_b = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open second send socket");
            let socket_b = raw_b.into_async().expect("into_async second socket");
            let dest: SocketAddr = "127.0.0.1:10027".parse().unwrap();

            let senders: Vec<_> = (0..4)
                .map(|_| fair_worker_channel(8, 2, WORKER_FAIR_QUANTUM_BYTES).0)
                .collect();
            let pool = EncryptWorkerPool {
                senders: Arc::from(senders.into_boxed_slice()),
                #[cfg(target_os = "linux")]
                linux_containers: Arc::new(LinuxBulkSendFlows::default()),
                #[cfg(target_os = "linux")]
                next_worker: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            };

            let queued_a = queued_job(
                socket_a.clone(),
                &cipher,
                dest,
                128,
                true,
                DEFAULT_SEND_WEIGHT,
            );
            let key_a = queued_a.flow_key();
            let dispatch_key_a = queued_a.dispatch_key();
            assert_eq!(
                send_dispatch_fast_hash(&dispatch_key_a),
                send_target_fast_hash(&key_a),
                "without an endpoint flow hint, dispatch must use the old selected-target hash"
            );
            let expected_idx_a =
                (send_dispatch_fast_hash(&dispatch_key_a) as usize) % pool.senders.len();
            let (idx_a, queued_a) = pool.prepare_dispatch(queued_a.job);
            assert_eq!(idx_a, expected_idx_a);
            assert_eq!(
                queued_a.flow_key(),
                key_a,
                "dispatch must carry the selected target key, not rebuild it differently"
            );

            let queued_b = queued_job(
                socket_b.clone(),
                &cipher,
                dest,
                128,
                true,
                DEFAULT_SEND_WEIGHT,
            );
            let key_b = queued_b.flow_key();
            assert_ne!(
                key_a, key_b,
                "same sockaddr on a different send fd is a different selected target"
            );

            let (tx, _rx) = fair_worker_channel(4, 1, WORKER_FAIR_QUANTUM_BYTES);
            let warmup: SocketAddr = "127.0.0.1:10028".parse().unwrap();
            for _ in 0..2 {
                tx.try_push(queued_job(
                    socket_a.clone(),
                    &cipher,
                    warmup,
                    128,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .expect("warmup bulk should enter fast lane");
            }

            tx.try_push(queued_a)
                .expect("first selected target should reserve its budget");
            assert!(
                matches!(
                    tx.try_push(queued_job(
                        socket_a,
                        &cipher,
                        dest,
                        128,
                        true,
                        DEFAULT_SEND_WEIGHT,
                    )),
                    Err(FairWorkerTryPushError::Full(_))
                ),
                "same selected target should hit the per-target admission cap"
            );
            tx.try_push(queued_b)
                .expect("different selected target should get its own budget");
        });
    }

    #[test]
    fn endpoint_flow_key_splits_admission_within_one_send_target() {
        with_test_socket(|socket, cipher| {
            let dest: SocketAddr = "127.0.0.1:10027".parse().unwrap();
            let flow_a = 0xaaaa_0001;
            let flow_b = 0xbbbb_0002;

            let senders: Vec<_> = (0..4)
                .map(|_| fair_worker_channel(8, 2, WORKER_FAIR_QUANTUM_BYTES).0)
                .collect();
            let pool = EncryptWorkerPool {
                senders: Arc::from(senders.into_boxed_slice()),
                #[cfg(target_os = "linux")]
                linux_containers: Arc::new(LinuxBulkSendFlows::default()),
                #[cfg(target_os = "linux")]
                next_worker: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            };

            let queued_a = queued_job_classified_with_flow(
                socket.clone(),
                &cipher,
                dest,
                128,
                true,
                false,
                DEFAULT_SEND_WEIGHT,
                Some(flow_a),
            );
            let target_key = queued_a.flow_key();
            let dispatch_key_a = queued_a.dispatch_key();
            assert_eq!(dispatch_key_a.target, target_key);
            assert_eq!(dispatch_key_a.endpoint_flow, Some(flow_a));
            let expected_idx_a =
                (send_dispatch_fast_hash(&dispatch_key_a) as usize) % pool.senders.len();
            let (idx_a, queued_a) = pool.prepare_dispatch(queued_a.job);
            assert_eq!(idx_a, expected_idx_a);
            assert_eq!(
                queued_a.flow_key(),
                target_key,
                "endpoint flow dispatch must not change kernel send grouping"
            );

            let (tx, _rx) = fair_worker_channel(4, 1, WORKER_FAIR_QUANTUM_BYTES);
            let warmup: SocketAddr = "127.0.0.1:10028".parse().unwrap();
            for _ in 0..2 {
                tx.try_push(queued_job(
                    socket.clone(),
                    &cipher,
                    warmup,
                    128,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .expect("warmup bulk should enter fast lane");
            }

            tx.try_push(queued_a)
                .expect("first endpoint flow should reserve its budget");
            assert!(
                matches!(
                    tx.try_push(queued_job_classified_with_flow(
                        socket.clone(),
                        &cipher,
                        dest,
                        128,
                        true,
                        false,
                        DEFAULT_SEND_WEIGHT,
                        Some(flow_a),
                    )),
                    Err(FairWorkerTryPushError::Full(_))
                ),
                "same endpoint flow should hit its per-flow admission cap"
            );
            tx.try_push(queued_job_classified_with_flow(
                socket,
                &cipher,
                dest,
                128,
                true,
                false,
                DEFAULT_SEND_WEIGHT,
                Some(flow_b),
            ))
            .expect("different endpoint flow on same send target should get its own budget");
        });
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_bulk_container_worker_selection_prefers_shorter_queue() {
        with_test_socket(|socket, cipher| {
            let (busy_tx, _busy_rx) = fair_worker_channel(16, 16, WORKER_FAIR_QUANTUM_BYTES);
            let (idle_tx, _idle_rx) = fair_worker_channel(16, 16, WORKER_FAIR_QUANTUM_BYTES);
            let busy_addr: SocketAddr = "127.0.0.1:10042".parse().unwrap();

            for _ in 0..4 {
                busy_tx
                    .try_push(queued_job(
                        socket.clone(),
                        &cipher,
                        busy_addr,
                        128,
                        true,
                        DEFAULT_SEND_WEIGHT,
                    ))
                    .expect("busy worker warmup should enqueue");
            }

            let pool = EncryptWorkerPool {
                senders: Arc::from(vec![busy_tx, idle_tx].into_boxed_slice()),
                #[cfg(target_os = "linux")]
                linux_containers: Arc::new(LinuxBulkSendFlows::default()),
                #[cfg(target_os = "linux")]
                next_worker: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            };

            assert_eq!(
                pool.select_linux_bulk_container_worker(),
                1,
                "Linux bulk containers should avoid a worker that already has queued bulk"
            );
        });
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_bulk_container_queue_full_drops_bulk_without_worker_bypass() {
        with_test_socket(|socket, cipher| {
            let (tx, _rx) = fair_worker_channel(8, 8, WORKER_FAIR_QUANTUM_BYTES);
            let pool = EncryptWorkerPool {
                senders: Arc::from(vec![tx].into_boxed_slice()),
                #[cfg(target_os = "linux")]
                linux_containers: Arc::new(LinuxBulkSendFlows::default()),
                #[cfg(target_os = "linux")]
                next_worker: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            };
            let reliable_addr: SocketAddr = "127.0.0.1:10043".parse().unwrap();
            let discardable_addr: SocketAddr = "127.0.0.1:10044".parse().unwrap();
            let mut run = vec![
                queued_job_classified(
                    socket.clone(),
                    &cipher,
                    reliable_addr,
                    128,
                    true,
                    false,
                    DEFAULT_SEND_WEIGHT,
                )
                .job,
                queued_job_classified(
                    socket,
                    &cipher,
                    discardable_addr,
                    128,
                    true,
                    true,
                    DEFAULT_SEND_WEIGHT,
                )
                .job,
            ];

            pool.dispatch_linux_bulk_container_queue_full_run(&mut run);

            assert!(run.is_empty());
            assert!(
                pool.senders[0].queued_len() == 0,
                "container overflow should be observable bulk loss, not a second send path that can reorder"
            );
        });
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_bulk_container_dispatch_leaves_discardable_bulk_on_fair_worker() {
        with_test_socket(|socket, cipher| {
            let (tx0, mut rx0) = fair_worker_channel(16, 16, WORKER_FAIR_QUANTUM_BYTES);
            let (tx1, mut rx1) = fair_worker_channel(16, 16, WORKER_FAIR_QUANTUM_BYTES);
            let pool = EncryptWorkerPool {
                senders: Arc::from(vec![tx0, tx1].into_boxed_slice()),
                #[cfg(target_os = "linux")]
                linux_containers: Arc::new(LinuxBulkSendFlows::default()),
                #[cfg(target_os = "linux")]
                next_worker: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            };
            let discardable_addr: SocketAddr = "127.0.0.1:10047".parse().unwrap();
            let first = queued_job_classified(
                socket.clone(),
                &cipher,
                discardable_addr,
                128,
                true,
                true,
                DEFAULT_SEND_WEIGHT,
            );
            let expected_idx = (send_target_fast_hash(&first.flow_key()) as usize) % 2;
            let mut jobs = vec![first.job];
            for _ in 1..8 {
                jobs.push(
                    queued_job_classified(
                        socket.clone(),
                        &cipher,
                        discardable_addr,
                        128,
                        true,
                        true,
                        DEFAULT_SEND_WEIGHT,
                    )
                    .job,
                );
            }

            pool.dispatch_linux_bulk_containers(jobs);

            let rx = if expected_idx == 0 { &mut rx0 } else { &mut rx1 };
            let mut batch = Vec::new();
            let stats = rx
                .recv_batch(&mut batch, 16)
                .expect("discardable bulk should dispatch through the fair worker");
            assert_eq!(stats.bulk_packets, 8);
            assert_eq!(batch.len(), 8);
            assert!(batch.iter().all(QueuedFmpSendJob::drop_on_backpressure));
            assert!(
                batch.iter().all(|job| job.linux_container.is_none()),
                "discardable UDP-shaped bulk should not use Linux bulk containers"
            );
        });
    }

    #[test]
    fn boosted_flow_gets_larger_queue_budget() {
        with_test_socket(|socket, cipher| {
            let (tx, _rx) = fair_worker_channel(12, 2, 2048);
            let boosted: SocketAddr = "127.0.0.1:10006".parse().unwrap();
            let normal: SocketAddr = "127.0.0.1:10007".parse().unwrap();

            for _ in 0..6 {
                tx.try_push(queued_job(
                    socket.clone(),
                    &cipher,
                    boosted,
                    1500,
                    true,
                    EXPLICIT_PEER_SEND_WEIGHT,
                ))
                .unwrap();
            }
            assert!(matches!(
                tx.try_push(queued_job(
                    socket.clone(),
                    &cipher,
                    boosted,
                    1500,
                    true,
                    EXPLICIT_PEER_SEND_WEIGHT,
                )),
                Err(FairWorkerTryPushError::Full(_))
            ));

            for _ in 0..2 {
                tx.try_push(queued_job(
                    socket.clone(),
                    &cipher,
                    normal,
                    1500,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .unwrap();
            }
            assert!(matches!(
                tx.try_push(queued_job(
                    socket,
                    &cipher,
                    normal,
                    1500,
                    true,
                    DEFAULT_SEND_WEIGHT,
                )),
                Err(FairWorkerTryPushError::Full(_))
            ));
        });
    }

    #[test]
    fn fair_dispatch_does_not_block_rx_loop_on_full_bulk_queue() {
        with_test_socket(|socket, cipher| {
            let (tx, _rx) = fair_worker_channel(1, 1, WORKER_FAIR_QUANTUM_BYTES);
            let addr: SocketAddr = "127.0.0.1:10008".parse().unwrap();

            assert!(
                tx.try_push(queued_job_classified(
                    socket.clone(),
                    &cipher,
                    addr,
                    128,
                    true,
                    false,
                    DEFAULT_SEND_WEIGHT,
                ))
                .is_ok(),
                "initial bulk job should fit"
            );

            let pool = EncryptWorkerPool {
                senders: Arc::from(vec![tx].into_boxed_slice()),
                #[cfg(target_os = "linux")]
                linux_containers: Arc::new(LinuxBulkSendFlows::default()),
                #[cfg(target_os = "linux")]
                next_worker: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            };
            let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let thread_done = Arc::clone(&done);
            let job =
                queued_job_classified(socket, &cipher, addr, 128, true, false, DEFAULT_SEND_WEIGHT);
            let handle = std::thread::spawn(move || {
                pool.dispatch_to_worker(0, job);
                thread_done.store(true, std::sync::atomic::Ordering::Release);
            });

            for _ in 0..20 {
                if done.load(std::sync::atomic::Ordering::Acquire) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }

            assert!(
                done.load(std::sync::atomic::Ordering::Acquire),
                "full bulk dispatch must not block the rx loop"
            );
            handle.join().expect("dispatch thread should finish");
        });
    }
