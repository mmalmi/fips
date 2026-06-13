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
    fn selected_send_target_key_drives_dispatch_and_admission() {
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
            let expected_idx_a = (send_target_fast_hash(&key_a) as usize) % pool.senders.len();
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
