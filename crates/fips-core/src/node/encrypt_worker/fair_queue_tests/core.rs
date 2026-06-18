    use crate::transport::udp::socket::UdpRawSocket;
    use ring::aead::{LessSafeKey, UnboundKey};

    fn test_cipher() -> LessSafeKey {
        let unbound =
            UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &[0u8; 32]).expect("build key");
        LessSafeKey::new(unbound)
    }

    fn with_test_socket(test: impl FnOnce(AsyncUdpSocket, LessSafeKey)) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            test(raw.into_async().expect("into_async"), test_cipher());
        });
    }

    fn queued_job(
        socket: AsyncUdpSocket,
        cipher: &LessSafeKey,
        dest_addr: SocketAddr,
        payload_len: usize,
        drop_on_backpressure: bool,
        scheduling_weight: u8,
    ) -> QueuedFmpSendJob {
        queued_job_classified(
            socket,
            cipher,
            dest_addr,
            payload_len,
            drop_on_backpressure,
            drop_on_backpressure,
            scheduling_weight,
        )
    }

    fn queued_job_classified(
        socket: AsyncUdpSocket,
        cipher: &LessSafeKey,
        dest_addr: SocketAddr,
        payload_len: usize,
        bulk_endpoint_data: bool,
        drop_on_backpressure: bool,
        scheduling_weight: u8,
    ) -> QueuedFmpSendJob {
        queued_job_classified_with_flow(
            socket,
            cipher,
            dest_addr,
            payload_len,
            bulk_endpoint_data,
            drop_on_backpressure,
            scheduling_weight,
            None,
        )
    }

    fn queued_job_classified_with_flow(
        socket: AsyncUdpSocket,
        cipher: &LessSafeKey,
        dest_addr: SocketAddr,
        payload_len: usize,
        bulk_endpoint_data: bool,
        drop_on_backpressure: bool,
        scheduling_weight: u8,
        endpoint_flow_dispatch_key: Option<u64>,
    ) -> QueuedFmpSendJob {
        let mut wire_buf = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + payload_len + 16);
        wire_buf.extend_from_slice(&[0u8; ESTABLISHED_HEADER_SIZE]);
        wire_buf.resize(ESTABLISHED_HEADER_SIZE + payload_len, 0);
        QueuedFmpSendJob::direct(FmpSendJob {
            cipher: cipher.clone(),
            counter: 0,
            wire_buf,
            fsp_seal: None,
            send_target: SelectedSendTarget::new(
                socket,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                None,
                dest_addr,
            ),
            endpoint_flow_dispatch_key,
            bulk_endpoint_data,
            drop_on_backpressure,
            scheduling_weight,
            queued_at: None,
        })
    }

    #[test]
    fn single_flow_full_backpressures_instead_of_dropping() {
        with_test_socket(|socket, cipher| {
            let (tx, _rx) = fair_worker_channel(2, 2, WORKER_FAIR_QUANTUM_BYTES);
            let addr: SocketAddr = "127.0.0.1:10000".parse().unwrap();

            assert!(
                tx.try_push(queued_job(socket.clone(), &cipher, addr, 128, true, 1))
                    .is_ok()
            );
            assert!(
                tx.try_push(queued_job(socket.clone(), &cipher, addr, 128, true, 1))
                    .is_ok()
            );
            assert!(matches!(
                tx.try_push(queued_job(socket, &cipher, addr, 128, true, 1)),
                Err(FairWorkerTryPushError::Full(_))
            ));
        });
    }

    #[test]
    fn tight_bulk_cap_limits_single_flow_to_fast_lane_plus_fair_budget() {
        with_test_socket(|socket, cipher| {
            let (tx, _rx) = fair_worker_channel(16, 4, WORKER_FAIR_QUANTUM_BYTES);
            let addr: SocketAddr = "127.0.0.1:10026".parse().unwrap();

            for _ in 0..8 {
                tx.try_push(queued_job(
                    socket.clone(),
                    &cipher,
                    addr,
                    128,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .expect("one flow should get one fast burst plus its fair budget");
            }

            assert!(
                matches!(
                    tx.try_push(queued_job(
                        socket,
                        &cipher,
                        addr,
                        128,
                        true,
                        DEFAULT_SEND_WEIGHT,
                    )),
                    Err(FairWorkerTryPushError::Full(_))
                ),
                "tight caps must not hide a third per-flow burst before reporting pressure"
            );
        });
    }

    #[test]
    fn fast_lane_cap_is_one_worker_batch_not_a_second_queue_window() {
        assert_eq!(
            worker_fast_lane_cap(2048, 512),
            DEFAULT_WORKER_BATCH_SIZE,
            "default bulk workers may bypass fair admission for one local batch, not one full per-flow queue"
        );
        assert_eq!(
            worker_fast_lane_cap_for_batch(2048, 512, DEFAULT_WORKER_BATCH_SIZE + 16),
            DEFAULT_WORKER_BATCH_SIZE,
            "larger experimental drain batches must not widen the fair-admission fast lane"
        );
        assert_eq!(
            worker_fast_lane_cap_for_batch(2048, 512, 16),
            16,
            "smaller experimental drain batches should keep pressure tests tight"
        );
        assert_eq!(
            worker_fast_lane_cap(16, 4),
            4,
            "tight test caps still bound the bypass by the fair per-flow cap"
        );
        assert_eq!(
            worker_fast_lane_cap(2, 8),
            2,
            "tiny channels cannot grow a fast lane larger than the physical queue"
        );
    }

    #[test]
    fn single_flow_fast_lane_stops_after_batch_plus_fair_budget() {
        with_test_socket(|socket, cipher| {
            let total_cap = 128;
            let per_flow_cap = 64;
            let (tx, _rx) = fair_worker_channel(total_cap, per_flow_cap, WORKER_FAIR_QUANTUM_BYTES);
            let addr: SocketAddr = "127.0.0.1:10034".parse().unwrap();
            let allowed = worker_fast_lane_cap(total_cap, per_flow_cap) + per_flow_cap;

            assert!(
                allowed < total_cap,
                "test should prove per-flow pressure before the physical queue is full"
            );
            for _ in 0..allowed {
                tx.try_push(queued_job(
                    socket.clone(),
                    &cipher,
                    addr,
                    128,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .expect("single flow should get one fast batch plus its fair budget");
            }

            assert!(
                matches!(
                    tx.try_push(queued_job(
                        socket,
                        &cipher,
                        addr,
                        128,
                        true,
                        DEFAULT_SEND_WEIGHT,
                    )),
                    Err(FairWorkerTryPushError::Full(_))
                ),
                "single flow must report pressure before a hidden second per-flow queue window"
            );
        });
    }

    #[test]
    fn new_flow_can_enter_when_hot_flow_reaches_per_flow_cap() {
        with_test_socket(|socket, cipher| {
            let (tx, mut rx) = fair_worker_channel(4, 2, WORKER_FAIR_QUANTUM_BYTES);
            let hot: SocketAddr = "127.0.0.1:10001".parse().unwrap();
            let quiet: SocketAddr = "127.0.0.1:10002".parse().unwrap();

            tx.try_push(queued_job(socket.clone(), &cipher, hot, 128, true, 1))
                .unwrap();
            tx.try_push(queued_job(socket.clone(), &cipher, hot, 128, true, 1))
                .unwrap();
            tx.try_push(queued_job(socket, &cipher, quiet, 128, true, 1))
                .unwrap();

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 4).is_some());
            let dests: Vec<_> = batch.iter().map(|job| job.flow_key().dest_addr).collect();
            assert_eq!(dests.len(), 3);
            assert_eq!(dests.iter().filter(|addr| **addr == hot).count(), 2);
            assert_eq!(dests.iter().filter(|addr| **addr == quiet).count(), 1);
        });
    }

    #[test]
    fn hot_flow_backpressures_when_others_are_waiting() {
        with_test_socket(|socket, cipher| {
            let (tx, _rx) = fair_worker_channel(8, 2, WORKER_FAIR_QUANTUM_BYTES);
            let hot: SocketAddr = "127.0.0.1:10003".parse().unwrap();
            let quiet: SocketAddr = "127.0.0.1:10004".parse().unwrap();

            tx.try_push(queued_job(socket.clone(), &cipher, hot, 128, true, 1))
                .unwrap();
            tx.try_push(queued_job(socket.clone(), &cipher, hot, 128, true, 1))
                .unwrap();
            tx.try_push(queued_job(socket.clone(), &cipher, hot, 128, true, 1))
                .unwrap();
            tx.try_push(queued_job(socket.clone(), &cipher, hot, 128, true, 1))
                .unwrap();
            tx.try_push(queued_job(socket.clone(), &cipher, quiet, 128, true, 1))
                .unwrap();

            assert!(matches!(
                tx.try_push(queued_job(socket, &cipher, hot, 128, true, 1)),
                Err(FairWorkerTryPushError::Full(_))
            ));
        });
    }

    #[test]
    fn priority_flow_enters_when_bulk_flow_reaches_per_flow_cap() {
        with_test_socket(|socket, cipher| {
            let (tx, mut rx) = fair_worker_channel(8, 2, WORKER_FAIR_QUANTUM_BYTES);
            let warmup: SocketAddr = "127.0.0.1:10022".parse().unwrap();
            let hot: SocketAddr = "127.0.0.1:10023".parse().unwrap();

            // Fill enough bulk slots first so the hot-flow jobs below use fair
            // admission and actually consume the per-flow bulk budget.
            for _ in 0..4 {
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

            for _ in 0..2 {
                tx.try_push(queued_job(
                    socket.clone(),
                    &cipher,
                    hot,
                    128,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .expect("hot bulk should consume fair per-flow budget");
            }

            assert!(
                matches!(
                    tx.try_push(queued_job(
                        socket.clone(),
                        &cipher,
                        hot,
                        128,
                        true,
                        DEFAULT_SEND_WEIGHT,
                    )),
                    Err(FairWorkerTryPushError::Full(_))
                ),
                "bulk should be capped for the hot flow"
            );

            tx.try_push(queued_job_classified(
                socket,
                &cipher,
                hot,
                64,
                false,
                false,
                DEFAULT_SEND_WEIGHT,
            ))
            .expect("priority job must bypass bulk per-flow pressure");

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 8).is_some());
            assert_eq!(batch.len(), 7);
            assert!(
                batch.iter().any(|job| job.flow_key().dest_addr == hot
                    && job.queue_lane() == EncryptWorkerLane::Priority),
                "priority job should be present despite the capped bulk flow"
            );
        });
    }

    #[test]
    fn priority_flow_enters_when_bulk_worker_queue_is_full() {
        with_test_socket(|socket, cipher| {
            let (tx, mut rx) = fair_worker_channel(2, 1, WORKER_FAIR_QUANTUM_BYTES);
            let addr: SocketAddr = "127.0.0.1:10024".parse().unwrap();

            for _ in 0..2 {
                tx.try_push(queued_job_classified(
                    socket.clone(),
                    &cipher,
                    addr,
                    128,
                    true,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .expect("bulk jobs should fill the bounded bulk queue");
            }

            tx.try_push(queued_job_classified(
                socket,
                &cipher,
                addr,
                64,
                false,
                false,
                DEFAULT_SEND_WEIGHT,
            ))
            .expect("priority job must keep its reserve when bulk is full");

            let mut batch = Vec::new();
            let stats = rx
                .recv_batch(&mut batch, 3)
                .expect("worker should drain queued jobs");
            assert_eq!(batch.len(), 3);
            assert_eq!(stats.priority_packets, 1);
            assert_eq!(stats.bulk_packets, 2);
            assert_eq!(batch[0].queue_lane(), EncryptWorkerLane::Priority);
            assert!(
                batch[1..]
                    .iter()
                    .all(|job| job.queue_lane() == EncryptWorkerLane::Bulk)
            );
        });
    }

    #[test]
    fn fair_worker_blocking_receive_prefers_ready_priority_over_bulk() {
        with_test_socket(|socket, cipher| {
            let (tx, mut rx) = fair_worker_channel(4, 2, WORKER_FAIR_QUANTUM_BYTES);
            let addr: SocketAddr = "127.0.0.1:10040".parse().unwrap();

            tx.try_push(queued_job_classified(
                socket.clone(),
                &cipher,
                addr,
                128,
                true,
                true,
                DEFAULT_SEND_WEIGHT,
            ))
            .expect("bulk job should enqueue");
            tx.try_push(queued_job_classified(
                socket,
                &cipher,
                addr,
                64,
                false,
                false,
                DEFAULT_SEND_WEIGHT,
            ))
            .expect("priority job should enqueue");

            let job = rx
                .recv_next_biased_blocking()
                .expect("receiver should select a ready lane");
            assert_eq!(
                job.queue_lane(),
                EncryptWorkerLane::Priority,
                "the blocking worker wake must prefer ready control/rekey work over bulk"
            );
        });
    }

    #[test]
    fn priority_reserve_does_not_shrink_with_tight_bulk_channel_cap() {
        with_test_socket(|socket, cipher| {
            let (tx, mut rx) = fair_worker_channel(2, 1, WORKER_FAIR_QUANTUM_BYTES);
            let addr: SocketAddr = "127.0.0.1:10025".parse().unwrap();

            for _ in 0..2 {
                tx.try_push(queued_job_classified(
                    socket.clone(),
                    &cipher,
                    addr,
                    128,
                    true,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .expect("bulk jobs should fill the bounded bulk queue");
            }

            for _ in 0..3 {
                tx.try_push(queued_job_classified(
                    socket.clone(),
                    &cipher,
                    addr,
                    64,
                    false,
                    false,
                    DEFAULT_SEND_WEIGHT,
                ))
                .expect("priority reserve must not be derived from the tight bulk cap");
            }

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 5).is_some());
            assert_eq!(batch.len(), 5);
            assert_eq!(
                batch
                    .iter()
                    .filter(|job| job.queue_lane() == EncryptWorkerLane::Priority)
                    .count(),
                3
            );
        });
    }

    #[test]
    fn single_flow_drains_full_batch() {
        with_test_socket(|socket, cipher| {
            let (tx, mut rx) = fair_worker_channel(16, 16, 2048);
            let addr: SocketAddr = "127.0.0.1:10005".parse().unwrap();

            for _ in 0..8 {
                tx.try_push(queued_job(
                    socket.clone(),
                    &cipher,
                    addr,
                    1500,
                    true,
                    DEFAULT_SEND_WEIGHT,
                ))
                .unwrap();
            }

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 8).is_some());
            assert_eq!(batch.len(), 8);
            assert!(batch.iter().all(|job| job.flow_key().dest_addr == addr));
        });
    }

    #[test]
    fn encrypt_worker_dispatch_preserves_single_flow_worker_and_fifo_order() {
        with_test_socket(|socket, cipher| {
            let senders: Vec<_> = (0..4)
                .map(|_| fair_worker_channel(16, 16, WORKER_FAIR_QUANTUM_BYTES).0)
                .collect();
            let pool = encrypt_worker_pool_for_test(senders);
            let addr = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 10009));

            let mut owner = None;
            for counter in 0..16 {
                let mut queued = queued_job(
                    socket.clone(),
                    &cipher,
                    addr,
                    1500,
                    true,
                    DEFAULT_SEND_WEIGHT,
                );
                queued.job.counter = counter;
                let (idx, queued) = pool.prepare_dispatch(queued.job);
                assert_eq!(queued.flow_key().dest_addr, addr);
                match owner {
                    Some(owner) => assert_eq!(
                        idx, owner,
                        "one TCP-shaped flow must not round-robin across workers"
                    ),
                    None => owner = Some(idx),
                }
            }

            let (tx, mut rx) = fair_worker_channel(16, 16, WORKER_FAIR_QUANTUM_BYTES);
            for counter in 0..8 {
                let mut queued = queued_job(
                    socket.clone(),
                    &cipher,
                    addr,
                    1500,
                    true,
                    DEFAULT_SEND_WEIGHT,
                );
                queued.job.counter = counter;
                tx.try_push(queued).expect("single-flow job should enqueue");
            }

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 8).is_some());
            let counters: Vec<_> = batch.iter().map(|job| job.job.counter).collect();
            assert_eq!(
                counters,
                (0..8).collect::<Vec<_>>(),
                "single-flow queue must preserve FIFO order"
            );
        });
    }

    #[test]
    fn fair_admission_keys_pressure_by_exact_send_target() {
        with_test_socket(|socket_a, cipher| {
            let raw_b = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open second send socket");
            let socket_b = raw_b.into_async().expect("into_async second socket");
            assert_ne!(
                socket_a.as_raw_fd(),
                socket_b.as_raw_fd(),
                "test requires two distinct send fds"
            );

            let (tx, _rx) = fair_worker_channel(4, 1, WORKER_FAIR_QUANTUM_BYTES);
            let warmup: SocketAddr = "127.0.0.1:10020".parse().unwrap();
            let shared_dest: SocketAddr = "127.0.0.1:10021".parse().unwrap();

            // Fill enough bulk slots first so the next sends exercise
            // fair-admission keys instead of bypassing admission.
            tx.try_push(queued_job(
                socket_a.clone(),
                &cipher,
                warmup,
                128,
                true,
                DEFAULT_SEND_WEIGHT,
            ))
            .unwrap();
            tx.try_push(queued_job(
                socket_a.clone(),
                &cipher,
                warmup,
                128,
                true,
                DEFAULT_SEND_WEIGHT,
            ))
            .unwrap();

            tx.try_push(queued_job(
                socket_a.clone(),
                &cipher,
                shared_dest,
                128,
                true,
                DEFAULT_SEND_WEIGHT,
            ))
            .expect("first send target should reserve its per-target budget");

            tx.try_push(queued_job(
                socket_b,
                &cipher,
                shared_dest,
                128,
                true,
                DEFAULT_SEND_WEIGHT,
            ))
            .expect("different fd to the same dest is a different send target");
        });
    }

    #[test]
    fn fair_admission_reservation_owns_release_key() {
        with_test_socket(|socket_a, cipher| {
            let raw_b = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open second send socket");
            let socket_b = raw_b.into_async().expect("into_async second socket");
            let dest: SocketAddr = "127.0.0.1:10033".parse().unwrap();
            let key_a =
                queued_job(socket_a, &cipher, dest, 128, true, DEFAULT_SEND_WEIGHT).dispatch_key();
            let key_b =
                queued_job(socket_b, &cipher, dest, 128, true, DEFAULT_SEND_WEIGHT).dispatch_key();
            assert_ne!(
                key_a, key_b,
                "same destination on different sockets must have different reservations"
            );

            let admission = FairAdmission {
                state: Mutex::new(FairAdmissionState::default()),
                not_full: Condvar::new(),
                reserved_len: std::sync::atomic::AtomicUsize::new(0),
                total_cap: 2,
                per_flow_cap: 1,
                fast_lane_cap: 1,
            };
            assert!(
                admission.is_idle(),
                "fresh admission should let the sender use the lock-free fast lane"
            );
            let reservation_a = match admission.try_reserve(key_a, DEFAULT_SEND_WEIGHT as usize) {
                FairReserve::Reserved(reservation) => reservation,
                FairReserve::Full => panic!("first key should reserve"),
                FairReserve::Closed => panic!("admission should be open"),
            };
            assert_eq!(reservation_a.key(), key_a);
            assert!(
                !admission.is_idle(),
                "active fair reservation must disable the fast lane"
            );
            assert!(
                matches!(
                    admission.try_reserve(key_a, DEFAULT_SEND_WEIGHT as usize),
                    FairReserve::Full
                ),
                "per-flow cap should block a second reservation for the same key"
            );
            let reservation_b = match admission.try_reserve(key_b, DEFAULT_SEND_WEIGHT as usize) {
                FairReserve::Reserved(reservation) => reservation,
                FairReserve::Full => panic!("different key should reserve independently"),
                FairReserve::Closed => panic!("admission should be open"),
            };
            assert_eq!(reservation_b.key(), key_b);
            assert!(
                !admission.is_idle(),
                "any active reservation should keep the fast lane disabled"
            );

            admission.release(reservation_a);
            assert!(
                !admission.is_idle(),
                "other active reservations should keep the fast lane disabled"
            );
            let reservation_a = match admission.try_reserve(key_a, DEFAULT_SEND_WEIGHT as usize) {
                FairReserve::Reserved(reservation) => reservation,
                FairReserve::Full => panic!("released key should reserve again"),
                FairReserve::Closed => panic!("admission should be open"),
            };
            assert_eq!(reservation_a.key(), key_a);
            admission.release(reservation_a);
            admission.release(reservation_b);
            assert!(
                admission.is_idle(),
                "releasing all fair reservations should re-enable the fast lane"
            );
        });
    }

    #[test]
    fn fair_admission_releases_reserved_batch_together() {
        with_test_socket(|socket_a, cipher| {
            let raw_b = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open second send socket");
            let socket_b = raw_b.into_async().expect("into_async second socket");
            let dest: SocketAddr = "127.0.0.1:10035".parse().unwrap();
            let key_a =
                queued_job(socket_a, &cipher, dest, 128, true, DEFAULT_SEND_WEIGHT).dispatch_key();
            let key_b =
                queued_job(socket_b, &cipher, dest, 128, true, DEFAULT_SEND_WEIGHT).dispatch_key();
            let admission = FairAdmission {
                state: Mutex::new(FairAdmissionState::default()),
                not_full: Condvar::new(),
                reserved_len: std::sync::atomic::AtomicUsize::new(0),
                total_cap: 2,
                per_flow_cap: 1,
                fast_lane_cap: 1,
            };

            let reservation_a = match admission.try_reserve(key_a, DEFAULT_SEND_WEIGHT as usize) {
                FairReserve::Reserved(reservation) => reservation,
                FairReserve::Full => panic!("first key should reserve"),
                FairReserve::Closed => panic!("admission should be open"),
            };
            let reservation_b = match admission.try_reserve(key_b, DEFAULT_SEND_WEIGHT as usize) {
                FairReserve::Reserved(reservation) => reservation,
                FairReserve::Full => panic!("different key should reserve independently"),
                FairReserve::Closed => panic!("admission should be open"),
            };
            assert!(
                !admission.is_idle(),
                "active reservations should disable the fast lane"
            );

            let reservations = vec![reservation_a, reservation_b];
            admission.release_many(&reservations);
            assert!(
                admission.is_idle(),
                "batch release should reopen the whole fair-admission window"
            );

            let reservation_a = match admission.try_reserve(key_a, DEFAULT_SEND_WEIGHT as usize) {
                FairReserve::Reserved(reservation) => reservation,
                FairReserve::Full => panic!("released key should reserve again"),
                FairReserve::Closed => panic!("admission should be open"),
            };
            let reservation_b = match admission.try_reserve(key_b, DEFAULT_SEND_WEIGHT as usize) {
                FairReserve::Reserved(reservation) => reservation,
                FairReserve::Full => panic!("released key should reserve again"),
                FairReserve::Closed => panic!("admission should be open"),
            };
            admission.release_many(&[reservation_a, reservation_b]);
        });
    }

    #[test]
    fn fair_worker_receiver_releases_batch_reservations_after_drain() {
        with_test_socket(|socket, cipher| {
            let (tx, mut rx) = fair_worker_channel(4, 1, WORKER_FAIR_QUANTUM_BYTES);
            let addr: SocketAddr = "127.0.0.1:10036".parse().unwrap();

            tx.try_push(queued_job(
                socket.clone(),
                &cipher,
                addr,
                128,
                true,
                DEFAULT_SEND_WEIGHT,
            ))
            .expect("first packet should enter the lock-free fast lane");
            tx.try_push(queued_job(
                socket.clone(),
                &cipher,
                addr,
                128,
                true,
                DEFAULT_SEND_WEIGHT,
            ))
            .expect("second packet should consume the fair per-flow budget");
            assert!(
                matches!(
                    tx.try_push(queued_job(
                        socket.clone(),
                        &cipher,
                        addr,
                        128,
                        true,
                        DEFAULT_SEND_WEIGHT,
                    )),
                    Err(FairWorkerTryPushError::Full(_))
                ),
                "same flow should be backpressured until the receiver owns the reserved packet"
            );

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 2).is_some());
            assert_eq!(batch.len(), 2);
            assert!(
                rx.release_buffer.is_empty(),
                "reservation release buffer must be reusable across worker batches"
            );

            tx.try_push(queued_job(
                socket,
                &cipher,
                addr,
                128,
                true,
                DEFAULT_SEND_WEIGHT,
            ))
            .expect("draining the worker batch should release fair capacity");
        });
    }
