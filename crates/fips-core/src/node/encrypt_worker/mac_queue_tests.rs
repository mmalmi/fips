#[cfg(all(test, target_os = "macos"))]
mod mac_queue_tests {
    use super::*;
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
        drop_on_backpressure: bool,
    ) -> QueuedFmpSendJob {
        queued_job_classified(
            socket,
            cipher,
            dest_addr,
            drop_on_backpressure,
            drop_on_backpressure,
        )
    }

    fn queued_job_classified(
        socket: AsyncUdpSocket,
        cipher: &LessSafeKey,
        dest_addr: SocketAddr,
        bulk_endpoint_data: bool,
        drop_on_backpressure: bool,
    ) -> QueuedFmpSendJob {
        QueuedFmpSendJob::direct(fmp_job_classified(
            socket,
            cipher,
            dest_addr,
            bulk_endpoint_data,
            drop_on_backpressure,
        ))
    }

    fn fmp_job_classified(
        socket: AsyncUdpSocket,
        cipher: &LessSafeKey,
        dest_addr: SocketAddr,
        bulk_endpoint_data: bool,
        drop_on_backpressure: bool,
    ) -> FmpSendJob {
        let mut wire_buf = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + 64 + 16);
        wire_buf.extend_from_slice(&[0u8; ESTABLISHED_HEADER_SIZE]);
        wire_buf.resize(ESTABLISHED_HEADER_SIZE + 64, 0);
        FmpSendJob {
            cipher: cipher.clone().into(),
            counter: 0,
            wire_buf,
            fsp_seal: None,
            send_target: SelectedSendTarget::new(socket, None, dest_addr),
            endpoint_flow_dispatch_key: None,
            bulk_endpoint_data,
            drop_on_backpressure,
            scheduling_weight: DEFAULT_SEND_WEIGHT,
            queued_at: None,
        }
    }

    fn test_mac_send_flow(
        socket: AsyncUdpSocket,
        dest_addr: SocketAddr,
    ) -> Arc<MacSequencedSendFlow> {
        let send_target = SelectedSendTarget::new(socket, None, dest_addr);
        let key = send_target.key();
        Arc::new(MacSequencedSendFlow {
            key,
            send_target,
            next_seq: std::sync::atomic::AtomicU64::new(0),
            last_used_ms: std::sync::atomic::AtomicU64::new(0),
            state: Mutex::new(MacSendFlowState::default()),
            ready_cv: Condvar::new(),
            space_cv: Condvar::new(),
        })
    }

    #[test]
    fn mac_worker_prioritizes_control_when_bulk_queue_is_full() {
        with_test_socket(|socket, cipher| {
            let (tx, rx) = mac_worker_channel(2);
            let addr: SocketAddr = "127.0.0.1:10010".parse().unwrap();

            assert!(
                tx.try_push(queued_job(socket.clone(), &cipher, addr, true))
                    .is_ok()
            );
            assert!(
                tx.try_push(queued_job(socket.clone(), &cipher, addr, true))
                    .is_ok()
            );
            assert!(
                tx.try_push(queued_job(socket, &cipher, addr, false))
                    .is_ok()
            );

            let mut batch = Vec::new();
            let stats = rx
                .recv_batch(&mut batch, 3)
                .expect("worker should drain queued jobs");
            assert_eq!(batch.len(), 3);
            assert_eq!(stats.priority_packets, 1);
            assert_eq!(stats.bulk_packets, 2);
            assert!(!batch[0].job.drop_on_backpressure);
            assert!(batch[1].job.drop_on_backpressure);
            assert!(batch[2].job.drop_on_backpressure);
        });
    }

    #[test]
    fn mac_completion_group_owns_flow_key_and_fifo_items() {
        with_test_socket(|socket, _cipher| {
            let flow_a = test_mac_send_flow(socket.clone(), "127.0.0.1:10033".parse().unwrap());
            let flow_b = test_mac_send_flow(socket, "127.0.0.1:10034".parse().unwrap());
            let key_a = flow_a.key;
            let key_b = flow_b.key;
            assert_ne!(key_a, key_b);

            let mut groups = Vec::new();
            push_mac_completion(
                &mut groups,
                Arc::clone(&flow_a),
                7,
                MacSendItem::Packet {
                    packet: vec![1],
                    bulk_endpoint_data: true,
                    drop_on_backpressure: true,
                },
            );
            push_mac_completion(&mut groups, Arc::clone(&flow_b), 3, MacSendItem::Skip);
            push_mac_completion(
                &mut groups,
                Arc::clone(&flow_a),
                8,
                MacSendItem::Packet {
                    packet: vec![2],
                    bulk_endpoint_data: false,
                    drop_on_backpressure: false,
                },
            );

            assert_eq!(groups.len(), 2);
            assert_eq!(groups[0].target_key(), key_a);
            assert_eq!(groups[1].target_key(), key_b);
            assert_eq!(groups[0].items.len(), 2);
            assert_eq!(groups[0].items[0].0, 7);
            assert_eq!(groups[0].items[1].0, 8);
            match &groups[0].items[0].1 {
                MacSendItem::Packet {
                    packet,
                    bulk_endpoint_data,
                    drop_on_backpressure,
                } => {
                    assert_eq!(packet.as_slice(), &[1]);
                    assert!(*bulk_endpoint_data);
                    assert!(*drop_on_backpressure);
                }
                MacSendItem::Skip => panic!("expected first flow item to be a packet"),
            }
            match &groups[0].items[1].1 {
                MacSendItem::Packet {
                    packet,
                    bulk_endpoint_data,
                    drop_on_backpressure,
                } => {
                    assert_eq!(packet.as_slice(), &[2]);
                    assert!(!*bulk_endpoint_data);
                    assert!(!*drop_on_backpressure);
                }
                MacSendItem::Skip => panic!("expected second flow item to be a packet"),
            }
            assert!(matches!(groups[1].items[0].1, MacSendItem::Skip));
        });
    }

    #[test]
    fn mac_worker_rejects_bulk_when_bulk_queue_is_full() {
        with_test_socket(|socket, cipher| {
            let (tx, _rx) = mac_worker_channel(2);
            let addr: SocketAddr = "127.0.0.1:10011".parse().unwrap();

            assert!(
                tx.try_push(queued_job(socket.clone(), &cipher, addr, true))
                    .is_ok()
            );
            assert!(
                tx.try_push(queued_job(socket.clone(), &cipher, addr, true))
                    .is_ok()
            );
            assert!(matches!(
                tx.try_push(queued_job(socket, &cipher, addr, true)),
                Err(MacWorkerTryPushError::Full(_))
            ));
        });
    }

    #[test]
    fn mac_worker_keeps_non_droppable_endpoint_data_in_bulk_lane() {
        with_test_socket(|socket, cipher| {
            let (tx, rx) = mac_worker_channel(2);
            let addr: SocketAddr = "127.0.0.1:10013".parse().unwrap();

            assert!(
                tx.try_push(queued_job_classified(
                    socket.clone(),
                    &cipher,
                    addr,
                    true,
                    false
                ))
                .is_ok()
            );
            assert!(
                tx.try_push(queued_job_classified(
                    socket.clone(),
                    &cipher,
                    addr,
                    true,
                    false
                ))
                .is_ok()
            );
            assert!(matches!(
                tx.try_push(queued_job_classified(
                    socket.clone(),
                    &cipher,
                    addr,
                    true,
                    false
                )),
                Err(MacWorkerTryPushError::Full(_))
            ));
            assert!(
                tx.try_push(queued_job_classified(socket, &cipher, addr, false, false))
                    .is_ok()
            );

            let mut batch = Vec::new();
            let stats = rx
                .recv_batch(&mut batch, 3)
                .expect("worker should drain queued jobs");
            assert_eq!(batch.len(), 3);
            assert_eq!(stats.priority_packets, 1);
            assert_eq!(stats.bulk_packets, 2);
            assert_eq!(batch[0].queue_lane(), EncryptWorkerLane::Priority);
            assert!(!batch[0].job.drop_on_backpressure);
            assert_eq!(batch[1].queue_lane(), EncryptWorkerLane::Bulk);
            assert!(!batch[1].job.drop_on_backpressure);
            assert_eq!(batch[2].queue_lane(), EncryptWorkerLane::Bulk);
            assert!(!batch[2].job.drop_on_backpressure);
        });
    }

    #[test]
    fn mac_dispatch_drops_discardable_bulk_on_full_bulk_queue() {
        with_test_socket(|socket, cipher| {
            let (tx, _rx) = mac_worker_channel(1);
            let addr: SocketAddr = "127.0.0.1:10014".parse().unwrap();

            assert!(
                tx.try_push(queued_job_classified(
                    socket.clone(),
                    &cipher,
                    addr,
                    true,
                    true,
                ))
                .is_ok(),
                "initial bulk job should fit"
            );

            let pool = EncryptWorkerPool {
                senders: Arc::from(vec![tx].into_boxed_slice()),
                macos_senders: Arc::new(MacSequencedSendFlows::default()),
                next_worker: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            };
            let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let thread_done = Arc::clone(&done);
            let job = queued_job_classified(socket, &cipher, addr, true, true);
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

    #[test]
    fn mac_dispatch_backpressures_reliable_endpoint_bulk_until_space_is_available() {
        with_test_socket(|socket, cipher| {
            let (tx, rx) = mac_worker_channel(1);
            let addr: SocketAddr = "127.0.0.1:10015".parse().unwrap();

            assert!(
                tx.try_push(queued_job_classified(
                    socket.clone(),
                    &cipher,
                    addr,
                    true,
                    false,
                ))
                .is_ok(),
                "initial reliable bulk job should fit"
            );

            let pool = EncryptWorkerPool {
                senders: Arc::from(vec![tx].into_boxed_slice()),
                macos_senders: Arc::new(MacSequencedSendFlows::default()),
                next_worker: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            };
            let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let thread_done = Arc::clone(&done);
            let job = queued_job_classified(socket, &cipher, addr, true, false);
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
                !done.load(std::sync::atomic::Ordering::Acquire),
                "reliable endpoint bulk should wait while the bulk queue is full"
            );

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 1).is_some());
            assert_eq!(batch.len(), 1);
            assert!(!batch[0].job.drop_on_backpressure);

            handle.join().expect("dispatch thread should finish");
            assert!(done.load(std::sync::atomic::Ordering::Acquire));

            batch.clear();
            assert!(rx.recv_batch(&mut batch, 1).is_some());
            assert_eq!(batch.len(), 1);
            assert!(!batch[0].job.drop_on_backpressure);
        });
    }

    #[test]
    fn mac_dispatch_backpressures_priority_until_space_is_available() {
        with_test_socket(|socket, cipher| {
            let (tx, rx) = mac_worker_channel(1);
            let addr: SocketAddr = "127.0.0.1:10035".parse().unwrap();

            for _ in 0..(1 + MAC_WORKER_CONTROL_RESERVE_CAP) {
                assert!(
                    tx.try_push(queued_job_classified(
                        socket.clone(),
                        &cipher,
                        addr,
                        false,
                        false,
                    ))
                    .is_ok(),
                    "priority reserve should accept the initial fill"
                );
            }

            let pool = EncryptWorkerPool {
                senders: Arc::from(vec![tx].into_boxed_slice()),
                macos_senders: Arc::new(MacSequencedSendFlows::default()),
                next_worker: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            };
            let queued = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let thread_queued = Arc::clone(&queued);
            let job = queued_job_classified(socket, &cipher, addr, false, false);
            let handle = std::thread::spawn(move || {
                pool.dispatch_to_worker(0, job);
                thread_queued.store(true, std::sync::atomic::Ordering::Release);
            });

            std::thread::sleep(std::time::Duration::from_millis(20));
            assert!(
                !queued.load(std::sync::atomic::Ordering::Acquire),
                "priority dispatch should wait while the priority reserve is full"
            );

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 1).is_some());
            assert_eq!(batch.len(), 1);
            assert_eq!(batch[0].queue_lane(), EncryptWorkerLane::Priority);
            handle.join().expect("dispatch thread should finish");
            assert!(queued.load(std::sync::atomic::Ordering::Acquire));
        });
    }

    #[test]
    fn mac_worker_bulk_push_blocks_until_space_is_available() {
        with_test_socket(|socket, cipher| {
            let (tx, rx) = mac_worker_channel(1);
            let addr: SocketAddr = "127.0.0.1:10012".parse().unwrap();

            assert!(
                tx.try_push(queued_job(socket.clone(), &cipher, addr, true))
                    .is_ok()
            );

            let queued = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let queued_in_thread = Arc::clone(&queued);
            let thread_cipher = cipher.clone();
            let handle = std::thread::spawn(move || {
                tx.push_blocking(queued_job(socket, &thread_cipher, addr, true))
                    .expect("bulk push should complete after queue space opens");
                queued_in_thread.store(true, std::sync::atomic::Ordering::Release);
            });

            std::thread::sleep(std::time::Duration::from_millis(20));
            assert!(
                !queued.load(std::sync::atomic::Ordering::Acquire),
                "bulk push should wait while the bulk queue is full"
            );

            let mut batch = Vec::new();
            assert!(rx.recv_batch(&mut batch, 1).is_some());
            assert_eq!(batch.len(), 1);
            assert!(batch[0].job.drop_on_backpressure);

            handle.join().expect("bulk push thread should not panic");
            assert!(queued.load(std::sync::atomic::Ordering::Acquire));

            batch.clear();
            assert!(rx.recv_batch(&mut batch, 1).is_some());
            assert_eq!(batch.len(), 1);
            assert!(batch[0].job.drop_on_backpressure);
        });
    }

    #[test]
    fn direct_send_batch_attempt_owns_cursor_and_backpressure_policy() {
        with_test_socket(|socket, _cipher| {
            let dest: SocketAddr = "127.0.0.1:10032".parse().unwrap();
            let target = SelectedSendTarget::new(socket.clone(), None, dest);
            let target_key = target.key();
            let mut batch = SelectedSendBatch::new(target, target_key, vec![1], true, true);
            batch.push(vec![2], true, true);

            let mut attempt = DirectSendBatchAttempt::from_batch(batch);
            assert_eq!(attempt.target_key(), target_key);
            assert_eq!(attempt.remaining_packets(), &[vec![1], vec![2]]);
            attempt.mark_current_sent();
            assert_eq!(attempt.remaining_packets(), &[vec![2]]);

            let err = std::io::Error::from_raw_os_error(libc::ENOBUFS);
            assert_eq!(
                attempt.handle_backpressure_request(true, &err),
                SendBackpressureDecision::DropCurrentBulk
            );
            assert!(
                attempt.is_complete(),
                "droppable backpressure advances exactly one current packet"
            );

            let target = SelectedSendTarget::new(socket.clone(), None, dest);
            let retry_target_key = target.key();
            let mut retry_batch =
                SelectedSendBatch::new(target, retry_target_key, vec![3], false, false);
            retry_batch.push(vec![4], false, false);
            let mut retry_attempt = DirectSendBatchAttempt::from_batch(retry_batch);
            assert_eq!(
                retry_attempt.handle_backpressure_request(true, &err),
                SendBackpressureDecision::Retry
            );
            assert_eq!(
                retry_attempt.remaining_packets(),
                &[vec![3], vec![4]],
                "non-droppable direct-send batches must not advance on a drop request"
            );

            let target = SelectedSendTarget::new(socket, None, dest);
            let reliable_bulk_key = target.key();
            let reliable_bulk_batch =
                SelectedSendBatch::new(target, reliable_bulk_key, vec![5], true, false);
            let mut reliable_bulk_attempt = DirectSendBatchAttempt::from_batch(reliable_bulk_batch);
            assert_eq!(
                reliable_bulk_attempt.handle_backpressure_request(true, &err),
                SendBackpressureDecision::Retry,
                "reliable endpoint bulk should backpressure by default"
            );
            assert_eq!(
                reliable_bulk_attempt.remaining_packets(),
                &[vec![5]],
                "reliable endpoint bulk must keep its packet on sustained ENOBUFS"
            );
        });
    }
}
