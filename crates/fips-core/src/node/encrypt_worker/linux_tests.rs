/// Standalone tests for the GSO-eligibility predicate. The full
/// `send_batch_gso` is exercised in `tests::gso_roundtrip` below
/// (Linux only — UDP_GSO + connected-peer fast paths are Linux-only,
/// so the entire test module is gated to Linux to avoid dead-code
/// warnings on macOS / BSD builds).
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn pkt(bytes: usize) -> Vec<u8> {
        vec![0u8; bytes]
    }

    async fn test_send_target() -> (SelectedSendTarget, SendTargetKey) {
        let raw = crate::transport::udp::socket::UdpRawSocket::open(
            "127.0.0.1:0".parse().unwrap(),
            1 << 20,
            1 << 20,
        )
        .expect("open send socket");
        let socket = raw.into_async().expect("into_async");
        let dest: SocketAddr = "127.0.0.1:10041".parse().unwrap();
        let target = SelectedSendTarget::new(socket, None, dest);
        let target_key = target.key();
        (target, target_key)
    }

    fn test_cipher() -> LessSafeKey {
        let unbound = ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &[0u8; 32])
            .expect("build key");
        LessSafeKey::new(unbound)
    }

    fn linux_wg_test_job(
        target: SelectedSendTarget,
        cipher: &LessSafeKey,
        counter: u64,
        bulk_endpoint_data: bool,
    ) -> FmpSendJob {
        let payload_len = 128;
        let mut wire_buf = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + payload_len + 16);
        wire_buf.extend_from_slice(&[0u8; ESTABLISHED_HEADER_SIZE]);
        wire_buf.resize(ESTABLISHED_HEADER_SIZE + payload_len, 0);
        FmpSendJob {
            cipher: cipher.clone(),
            counter,
            wire_buf,
            fsp_seal: None,
            send_target: target,
            endpoint_flow_dispatch_key: None,
            bulk_endpoint_data,
            drop_on_backpressure: true,
            scheduling_weight: DEFAULT_SEND_WEIGHT,
            queued_at: None,
        }
    }

    fn selected_test_group(
        target: SelectedSendTarget,
        target_key: SendTargetKey,
        lane: SelectedSendLane,
        bytes: usize,
        drop_on_backpressure: bool,
    ) -> SelectedSendBatch {
        SelectedSendBatch::new_with_capacity(
            target,
            target_key,
            lane,
            pkt(bytes),
            drop_on_backpressure,
            1,
        )
    }

    fn selected_test_packet_group(
        target: SelectedSendTarget,
        target_key: SendTargetKey,
        byte: u8,
    ) -> SelectedSendBatch {
        SelectedSendBatch::new_with_capacity(
            target,
            target_key,
            SelectedSendLane::Bulk,
            vec![byte; 64],
            true,
            1,
        )
    }

    fn recv_packet_first_byte(socket: &std::net::UdpSocket) -> u8 {
        let mut buf = [0u8; 256];
        let (len, _) = socket.recv_from(&mut buf).expect("receive packet");
        assert_eq!(len, 64);
        buf[0]
    }

    #[test]
    fn gso_eligible_rejects_single_packet() {
        assert!(!gso_eligible_sizes_ref(&[pkt(1500)]));
    }

    #[test]
    fn gso_eligible_accepts_uniform_batch() {
        let batch: Vec<_> = (0..18).map(|_| pkt(1500)).collect();
        assert!(gso_eligible_sizes_ref(&batch));
    }

    #[test]
    fn gso_eligible_accepts_short_trailer() {
        let mut batch: Vec<_> = (0..18).map(|_| pkt(1500)).collect();
        batch.push(pkt(900)); // last shorter — kernel handles this
        assert!(gso_eligible_sizes_ref(&batch));
    }

    #[test]
    fn gso_eligible_rejects_mixed_sizes() {
        let mut batch: Vec<_> = (0..18).map(|_| pkt(1500)).collect();
        batch[3] = pkt(800); // mid-batch short packet
        batch.push(pkt(1500));
        assert!(!gso_eligible_sizes_ref(&batch));
    }

    #[test]
    fn gso_capability_errors_disable_gso() {
        assert!(is_gso_capability_error(&std::io::Error::from(
            std::io::ErrorKind::InvalidInput
        )));
        assert!(is_gso_capability_error(&std::io::Error::from_raw_os_error(
            libc::EOPNOTSUPP
        )));
        assert!(is_gso_capability_error(&std::io::Error::from_raw_os_error(
            libc::ENOPROTOOPT
        )));
        assert!(is_gso_capability_error(&std::io::Error::from_raw_os_error(
            libc::EIO
        )));
        assert!(!is_gso_capability_error(
            &std::io::Error::from_raw_os_error(libc::ENOBUFS)
        ));
        assert!(!is_gso_capability_error(&std::io::Error::from(
            std::io::ErrorKind::WouldBlock
        )));
    }

    #[test]
    fn linux_wg_batch_flow_sends_fifo_even_when_completed_out_of_order() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let recv = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
            recv.set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .expect("set read timeout");
            let raw = crate::transport::udp::socket::UdpRawSocket::open(
                "127.0.0.1:0".parse().unwrap(),
                1 << 20,
                1 << 20,
            )
            .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let target = SelectedSendTarget::new(socket, None, recv.local_addr().unwrap());
            let target_key = target.key();
            let flow = LinuxWgBatchSendFlow::spawn(
                target_key,
                target.clone(),
                linux_wg_batch_now_ms(),
                8,
            );

            let batch0 = Arc::new(LinuxWgSendBatch::default());
            let batch1 = Arc::new(LinuxWgSendBatch::default());
            flow.try_enqueue(Arc::clone(&batch0))
                .expect("enqueue first batch");
            flow.try_enqueue(Arc::clone(&batch1))
                .expect("enqueue second batch");

            batch1.complete(vec![selected_test_packet_group(
                target.clone(),
                target_key,
                2,
            )]);
            batch0.complete(vec![selected_test_packet_group(target, target_key, 1)]);

            assert_eq!(recv_packet_first_byte(&recv), 1);
            assert_eq!(recv_packet_first_byte(&recv), 2);
        });
    }

    #[test]
    fn linux_wg_batch_flow_empty_batch_advances_sender() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let recv = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
            recv.set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .expect("set read timeout");
            let raw = crate::transport::udp::socket::UdpRawSocket::open(
                "127.0.0.1:0".parse().unwrap(),
                1 << 20,
                1 << 20,
            )
            .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let target = SelectedSendTarget::new(socket, None, recv.local_addr().unwrap());
            let target_key = target.key();
            let flow = LinuxWgBatchSendFlow::spawn(
                target_key,
                target.clone(),
                linux_wg_batch_now_ms(),
                8,
            );

            let skipped = Arc::new(LinuxWgSendBatch::default());
            let next = Arc::new(LinuxWgSendBatch::default());
            flow.try_enqueue(Arc::clone(&skipped))
                .expect("enqueue skipped batch");
            flow.try_enqueue(Arc::clone(&next))
                .expect("enqueue next batch");

            skipped.complete(Vec::new());
            next.complete(vec![selected_test_packet_group(target, target_key, 9)]);

            assert_eq!(recv_packet_first_byte(&recv), 9);
        });
    }

    #[test]
    fn linux_wg_bulk_batch_dispatch_keeps_enough_target_runs_on_wg_lane() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let pool = EncryptWorkerPool::spawn(1);
            let cipher = test_cipher();
            let (target_a, key_a) = test_send_target().await;
            let (target_b, key_b) = test_send_target().await;
            let min_packets = LINUX_WG_BATCH_MIN_PACKETS;
            let first_a_run = min_packets / 2;
            let second_a_run = min_packets - first_a_run;

            let mut jobs = Vec::new();
            for i in 0..first_a_run {
                jobs.push(linux_wg_test_job(
                    target_a.clone(),
                    &cipher,
                    i as u64,
                    true,
                ));
            }
            jobs.push(linux_wg_test_job(target_b, &cipher, 10_000, true));
            for i in 0..second_a_run {
                jobs.push(linux_wg_test_job(
                    target_a.clone(),
                    &cipher,
                    (first_a_run + i) as u64,
                    true,
                ));
            }

            let selected = linux_wg_bulk_batch_selected_targets(&jobs, min_packets)
                .expect("target A has enough packets across adjacent runs");
            assert_eq!(selected.get(&key_a), Some(&min_packets));
            assert!(!selected.contains_key(&key_b));

            let returned = pool
                .dispatch_linux_wg_bulk_batch_unmeasured(jobs)
                .expect_err("underfilled target B should stay on fallback dispatch");
            assert_eq!(returned.len(), 1);
            assert_eq!(returned[0].send_target_key(), key_b);
        });
    }

    #[test]
    fn linux_wg_bulk_batch_dispatch_rejects_mixed_priority_batch() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let pool = EncryptWorkerPool::spawn(1);
            let cipher = test_cipher();
            let (target, _key) = test_send_target().await;
            let min_packets = LINUX_WG_BATCH_MIN_PACKETS;
            let mut jobs = Vec::new();
            for i in 0..min_packets {
                jobs.push(linux_wg_test_job(
                    target.clone(),
                    &cipher,
                    i as u64,
                    true,
                ));
            }
            jobs.push(linux_wg_test_job(target, &cipher, 10_000, false));

            let returned = pool
                .dispatch_linux_wg_bulk_batch_unmeasured(jobs)
                .expect_err("priority-like work must keep the existing worker path");
            assert_eq!(returned.len(), min_packets + 1);
        });
    }

    #[test]
    fn linux_gso_chunk_len_respects_udp_payload_limit_and_packet_cap() {
        let full_size_packets: Vec<Vec<u8>> = (0..64).map(|_| pkt(1500)).collect();
        let chunk = linux_gso_safe_chunk_len(&full_size_packets);
        assert_eq!(
            chunk, 43,
            "43 * 1500 fits below the UDP payload limit; 44 * 1500 does not"
        );

        let tiny_packets: Vec<Vec<u8>> = (0..80).map(|_| pkt(200)).collect();
        assert_eq!(
            linux_gso_safe_chunk_len(&tiny_packets),
            LINUX_UDP_SEND_BATCH_MAX,
            "small packets should still use the syscall packet-count cap"
        );
    }

    #[test]
    fn linux_deferred_sender_env_defaults_on_and_is_bounded() {
        assert!(parse_linux_deferred_sender_enabled(None));
        assert!(!parse_linux_deferred_sender_enabled(Some("0")));
        assert!(!parse_linux_deferred_sender_enabled(Some("false")));
        assert!(!parse_linux_deferred_sender_enabled(Some("OFF")));
        assert!(parse_linux_deferred_sender_enabled(Some("1")));
        assert!(parse_linux_deferred_sender_enabled(Some("true")));
        assert!(parse_linux_deferred_sender_enabled(Some("YES")));
        assert!(parse_linux_deferred_sender_enabled(Some("unexpected")));

        assert_eq!(
            parse_linux_deferred_sender_cap(None),
            DEFAULT_LINUX_DEFERRED_SENDER_CAP
        );
        assert_eq!(parse_linux_deferred_sender_cap(Some("0")), 1);
        assert_eq!(parse_linux_deferred_sender_cap(Some("17")), 17);
        assert_eq!(parse_linux_deferred_sender_cap(Some("999999")), 1024);
        assert_eq!(
            parse_linux_deferred_sender_cap(Some("nope")),
            DEFAULT_LINUX_DEFERRED_SENDER_CAP
        );
    }

    #[test]
    fn linux_bulk_udp_pacer_env_defaults_off_with_explicit_opt_in() {
        assert_eq!(
            parse_linux_bulk_udp_pace_mbps(None),
            DEFAULT_LINUX_BULK_UDP_PACE_MBPS
        );
        assert_eq!(parse_linux_bulk_udp_pace_mbps(Some("0")), 0);
        assert_eq!(parse_linux_bulk_udp_pace_mbps(Some("2500")), 2500);
        assert_eq!(
            parse_linux_bulk_udp_pace_mbps(Some("999999")),
            100_000
        );
        assert_eq!(
            parse_linux_bulk_udp_pace_mbps(Some("nope")),
            DEFAULT_LINUX_BULK_UDP_PACE_MBPS
        );

        assert_eq!(
            parse_linux_bulk_udp_pace_burst_bytes(None),
            DEFAULT_LINUX_BULK_UDP_PACE_BURST_BYTES
        );
        assert_eq!(parse_linux_bulk_udp_pace_burst_bytes(Some("1")), 8 * 1024);
        assert_eq!(
            parse_linux_bulk_udp_pace_burst_bytes(Some("131072")),
            131_072
        );
        assert_eq!(
            parse_linux_bulk_udp_pace_burst_bytes(Some("99999999")),
            4 * 1024 * 1024
        );

        assert_eq!(
            parse_linux_bulk_udp_pace_spin_ns(None),
            DEFAULT_LINUX_BULK_UDP_PACE_SPIN_NS
        );
        assert_eq!(parse_linux_bulk_udp_pace_spin_ns(Some("0")), 0);
        assert_eq!(parse_linux_bulk_udp_pace_spin_ns(Some("50000")), 50_000);
        assert_eq!(
            parse_linux_bulk_udp_pace_spin_ns(Some("99999999")),
            1_000_000
        );
    }

    #[test]
    fn linux_wg_batch_constants_preserve_sender_shape() {
        assert_eq!(LINUX_WG_BATCH_MIN_PACKETS, 16);
        assert_eq!(LINUX_WG_BATCH_WORKER_CHANNEL_CAP, 1024);
        assert_eq!(LINUX_WG_BATCH_FLOW_CHANNEL_CAP, 1024);
        assert_eq!(
            DEFAULT_LINUX_WG_BATCH_CHUNK_SIZE,
            32,
            "accepted packet-mover chunk keeps the committed bulk run shape bounded"
        );
    }

    #[test]
    fn selected_send_batch_tracks_gso_eligibility_while_grouping() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = crate::transport::udp::socket::UdpRawSocket::open(
                "127.0.0.1:0".parse().unwrap(),
                1 << 20,
                1 << 20,
            )
            .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let dest: SocketAddr = "127.0.0.1:10041".parse().unwrap();
            let target = SelectedSendTarget::new(socket, None, dest);
            let target_key = target.key();

            let mut batch = SelectedSendBatch::new(target, target_key, pkt(1500), true);
            assert_eq!(
                batch.gso_eligible_sizes(),
                gso_eligible_sizes_ref(&batch.wire_packets)
            );
            assert!(
                !batch.gso_eligible_sizes(),
                "single packet groups should stay on the plain send path"
            );

            batch.push(pkt(1500), true);
            assert_eq!(
                batch.gso_eligible_sizes(),
                gso_eligible_sizes_ref(&batch.wire_packets)
            );
            assert!(batch.gso_eligible_sizes());

            batch.push(pkt(900), true);
            assert_eq!(
                batch.gso_eligible_sizes(),
                gso_eligible_sizes_ref(&batch.wire_packets)
            );
            assert!(
                batch.gso_eligible_sizes(),
                "one short final segment is valid UDP_GSO input"
            );

            batch.push(pkt(1500), true);
            assert_eq!(
                batch.gso_eligible_sizes(),
                gso_eligible_sizes_ref(&batch.wire_packets)
            );
            assert!(
                !batch.gso_eligible_sizes(),
                "a short packet stops being GSO-safe once it is no longer the final segment"
            );
        });
    }

    #[test]
    fn selected_send_batch_keeps_priority_and_bulk_lanes_separate() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = crate::transport::udp::socket::UdpRawSocket::open(
                "127.0.0.1:0".parse().unwrap(),
                1 << 20,
                1 << 20,
            )
            .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let dest: SocketAddr = "127.0.0.1:10041".parse().unwrap();
            let target = SelectedSendTarget::new(socket, None, dest);
            let target_key = target.key();
            let mut groups = Vec::new();

            push_selected_send_batch_with_lane_and_capacity(
                &mut groups,
                target.clone(),
                target_key,
                SelectedSendLane::Bulk,
                pkt(1500),
                true,
                8,
            );
            push_selected_send_batch_with_lane_and_capacity(
                &mut groups,
                target.clone(),
                target_key,
                SelectedSendLane::Priority,
                pkt(160),
                false,
                8,
            );
            push_selected_send_batch_with_lane_and_capacity(
                &mut groups,
                target,
                target_key,
                SelectedSendLane::Bulk,
                pkt(1500),
                true,
                8,
            );

            assert_eq!(
                groups.len(),
                3,
                "lane changes must start a fresh send group"
            );
            assert_eq!(groups[0].lane(), SelectedSendLane::Bulk);
            assert_eq!(groups[1].lane(), SelectedSendLane::Priority);
            assert_eq!(groups[2].lane(), SelectedSendLane::Bulk);
        });
    }

    #[test]
    fn linux_deferred_sender_split_preserves_lane_local_order() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let raw = crate::transport::udp::socket::UdpRawSocket::open(
                "127.0.0.1:0".parse().unwrap(),
                1 << 20,
                1 << 20,
            )
            .expect("open send socket");
            let socket = raw.into_async().expect("into_async");
            let dest: SocketAddr = "127.0.0.1:10041".parse().unwrap();
            let target = SelectedSendTarget::new(socket, None, dest);
            let target_key = target.key();

            let groups = vec![
                SelectedSendBatch::new_with_capacity(
                    target.clone(),
                    target_key,
                    SelectedSendLane::Bulk,
                    pkt(1500),
                    true,
                    1,
                ),
                SelectedSendBatch::new_with_capacity(
                    target.clone(),
                    target_key,
                    SelectedSendLane::Priority,
                    pkt(160),
                    false,
                    1,
                ),
                SelectedSendBatch::new_with_capacity(
                    target,
                    target_key,
                    SelectedSendLane::Bulk,
                    pkt(1200),
                    true,
                    1,
                ),
            ];

            let (priority, bulk) = split_linux_deferred_send_groups(groups);
            assert_eq!(priority.len(), 1);
            assert_eq!(priority[0].lane(), SelectedSendLane::Priority);
            assert_eq!(priority[0].packet_count(), 1);
            assert_eq!(priority[0].bulk_wire_bytes(), None);
            assert_eq!(bulk.len(), 2);
            assert!(bulk
                .iter()
                .all(|group| group.lane() == SelectedSendLane::Bulk));
            assert_eq!(bulk[0].packet_count(), 1);
            assert_eq!(bulk[1].packet_count(), 1);
            assert_eq!(bulk[0].bulk_wire_bytes(), Some(1500));
            assert_eq!(bulk[1].bulk_wire_bytes(), Some(1200));
        });
    }

    #[test]
    fn linux_deferred_sender_returns_bulk_when_bulk_queue_is_full() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let (priority_tx, priority_rx) = bounded(1);
            let (bulk_tx, bulk_rx) = bounded(1);
            let sender = LinuxDeferredSender {
                priority_tx,
                bulk_tx,
            };
            let (target, target_key) = test_send_target().await;
            let full_bulk = selected_test_group(
                target.clone(),
                target_key,
                SelectedSendLane::Bulk,
                1500,
                true,
            );
            assert!(sender.bulk_tx.try_send(vec![full_bulk]).is_ok());

            let priority = selected_test_group(
                target.clone(),
                target_key,
                SelectedSendLane::Priority,
                160,
                false,
            );
            let bulk = selected_test_group(target, target_key, SelectedSendLane::Bulk, 1400, true);
            let err = sender
                .send(vec![priority, bulk])
                .expect_err("full bulk queue should return only bulk groups");
            assert!(!err.is_closed());
            let returned = err.into_groups();

            let queued_priority = priority_rx.try_recv().expect("priority queued");
            assert_eq!(queued_priority.len(), 1);
            assert_eq!(queued_priority[0].lane(), SelectedSendLane::Priority);
            assert_eq!(returned.len(), 1);
            assert_eq!(returned[0].lane(), SelectedSendLane::Bulk);
            assert!(bulk_rx.try_recv().is_ok(), "pre-filled bulk stays queued");
        });
    }

    #[test]
    fn linux_deferred_sender_returns_all_when_priority_queue_is_full() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let (priority_tx, priority_rx) = bounded(1);
            let (bulk_tx, bulk_rx) = bounded(1);
            let sender = LinuxDeferredSender {
                priority_tx,
                bulk_tx,
            };
            let (target, target_key) = test_send_target().await;
            let full_priority = selected_test_group(
                target.clone(),
                target_key,
                SelectedSendLane::Priority,
                128,
                false,
            );
            assert!(sender.priority_tx.try_send(vec![full_priority]).is_ok());

            let priority = selected_test_group(
                target.clone(),
                target_key,
                SelectedSendLane::Priority,
                160,
                false,
            );
            let bulk = selected_test_group(target, target_key, SelectedSendLane::Bulk, 1400, true);
            let err = sender
                .send(vec![priority, bulk])
                .expect_err("full priority queue should force synchronous fallback");
            assert!(!err.is_closed());
            let returned = err.into_groups();

            assert_eq!(returned.len(), 2);
            assert_eq!(returned[0].lane(), SelectedSendLane::Priority);
            assert_eq!(returned[1].lane(), SelectedSendLane::Bulk);
            assert!(
                bulk_rx.try_recv().is_err(),
                "fresh bulk must not be queued behind a full priority lane"
            );
            assert!(priority_rx.try_recv().is_ok(), "pre-filled priority stays queued");
        });
    }

    /// End-to-end: bind a real UDP socket pair on loopback, fire
    /// `send_batch_gso` from the sender, recv on the receiver, confirm
    /// we get N segmented datagrams back (one per logical packet).
    ///
    /// This validates the entire UDP_GSO codepath: cmsg setup,
    /// scatter-gather iov assembly, kernel segmentation. If the
    /// running kernel doesn't support UDP_SEGMENT the syscall returns
    /// EOPNOTSUPP and we skip the assertion (the prod path falls back
    /// to sendmmsg via the GSO_DISABLED flag).
    #[test]
    fn gso_roundtrip_loopback() {
        use std::net::UdpSocket;
        use std::os::unix::io::AsRawFd;

        // Sender + receiver on loopback.
        let recv_sock = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
        let recv_addr = recv_sock.local_addr().expect("recv local_addr");
        recv_sock
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .expect("set_read_timeout");
        let send_sock = UdpSocket::bind("127.0.0.1:0").expect("bind send");

        // Build a uniform 18-packet batch addressed at recv_sock.
        const SEG: usize = 200;
        const N: usize = 18;
        let mut batch: Vec<Vec<u8>> = Vec::with_capacity(N);
        for i in 0..N {
            let mut buf = vec![0u8; SEG];
            // Stamp the packet index in the first byte so we can verify
            // ordering on the receive side.
            buf[0] = i as u8;
            batch.push(buf);
        }

        let r = send_batch_gso(
            send_sock.as_raw_fd(),
            &batch,
            recv_addr,
            /* connected */ false,
        );
        match r {
            Ok(()) => {} // proceed to recv
            Err(err)
                if err.raw_os_error() == Some(libc::EOPNOTSUPP)
                    || err.raw_os_error() == Some(libc::ENOPROTOOPT)
                    || err.kind() == std::io::ErrorKind::InvalidInput =>
            {
                eprintln!(
                    "gso_roundtrip_loopback: kernel doesn't support UDP_GSO ({err}); skipping"
                );
                return;
            }
            Err(err) => panic!("send_batch_gso failed: {err}"),
        }

        // Drain receive side — expect exactly N datagrams of SEG bytes
        // each, in order.
        let mut recv_buf = [0u8; SEG + 32];
        for i in 0..N {
            let (len, _from) = recv_sock
                .recv_from(&mut recv_buf)
                .unwrap_or_else(|e| panic!("recv {i}: {e}"));
            assert_eq!(len, SEG, "datagram {i} has wrong length");
            assert_eq!(
                recv_buf[0], i as u8,
                "datagram {i} arrived out of order or with wrong stamp"
            );
        }
    }

    /// `send_batch_raw` (the sendmmsg fallback) must deliver every
    /// packet to the shared dest passed alongside the slice. Two
    /// receivers + one mixed batch would be the wrong shape (the
    /// shared sockaddr means one receiver per call); this test
    /// validates the per-call contract: N packets in, N packets out
    /// at one address.
    #[test]
    fn sendmmsg_uniform_dest_roundtrip() {
        use std::net::UdpSocket;
        use std::os::unix::io::AsRawFd;

        let recv_sock = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
        let recv_addr = recv_sock.local_addr().unwrap();
        recv_sock
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .expect("set_read_timeout");
        let send_sock = UdpSocket::bind("127.0.0.1:0").expect("bind send");
        send_sock.set_nonblocking(true).unwrap();

        const N: usize = 48;
        let packets: Vec<Vec<u8>> = (0..N)
            .map(|i| {
                let mut v = vec![0u8; 16];
                v[0] = i as u8;
                v
            })
            .collect();
        let n =
            send_batch_raw(send_sock.as_raw_fd(), &packets, recv_addr, false).expect("sendmmsg ok");
        assert_eq!(n, N);

        let mut buf = [0u8; 64];
        let mut stamps: Vec<u8> = Vec::with_capacity(N);
        for _ in 0..N {
            let (len, _) = recv_sock.recv_from(&mut buf).expect("recv");
            assert_eq!(len, 16);
            stamps.push(buf[0]);
        }
        stamps.sort();
        let expected: Vec<u8> = (0..N).map(|i| i as u8).collect();
        assert_eq!(stamps, expected);
    }

    /// Mixed-destination batch dispatched to a single worker. The
    /// pre-fix bug used `batch[0].socket` / `batch[0].connected_socket`
    /// / `packets[0].dest_addr` for the whole drained batch, so a
    /// hash-collision (two peers hashing to the same worker) silently
    /// misdirected the second peer's packets to the first peer's
    /// destination. The fix groups jobs by `(socket_fd, connected_fd,
    /// dest_addr)` before flushing.
    ///
    /// This test goes through `flush_batch_sync` directly: it constructs
    /// three `FmpSendJob`s split across two distinct receiver sockaddrs
    /// (A, B, A) on a shared send socket with no connected socket, then
    /// asserts that recv_a gets the two A-stamped packets and recv_b
    /// gets exactly the one B-stamped packet.
    ///
    /// We have to spin a tokio runtime because `AsyncUdpSocket` wraps a
    /// `tokio::io::unix::AsyncFd`, which requires a registered reactor
    /// at construction time. The actual `flush_batch_sync` work is sync
    /// (raw-fd `sendmmsg`); we just need the AsyncFd alive for the
    /// AsRawFd impl.
    #[test]
    fn flush_batch_routes_each_target_separately() {
        use crate::transport::udp::socket::UdpRawSocket;
        use ring::aead::{LessSafeKey, UnboundKey};
        use std::net::UdpSocket;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            // Two receivers — distinct kernel sockaddrs.
            let recv_a = UdpSocket::bind("127.0.0.1:0").expect("bind recv_a");
            let recv_b = UdpSocket::bind("127.0.0.1:0").expect("bind recv_b");
            for s in [&recv_a, &recv_b] {
                s.set_read_timeout(Some(std::time::Duration::from_millis(500)))
                    .expect("set_read_timeout");
            }
            let addr_a = recv_a.local_addr().unwrap();
            let addr_b = recv_b.local_addr().unwrap();

            // One send socket shared by all jobs (the wildcard listen
            // socket in production). `UdpRawSocket::open` builds a
            // socket2 socket; `into_async` wraps it in tokio's AsyncFd
            // and hands back an AsyncUdpSocket.
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let send_sock = raw.into_async().expect("into_async");

            // Throwaway AEAD cipher — content doesn't matter, we just
            // need encrypt to succeed so a wire packet lands.
            let key_bytes = [0u8; 32];
            let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes)
                .expect("build unbound key");
            let cipher = LessSafeKey::new(unbound);

            // Per-target plaintext sizes are distinct so we can
            // identify which receiver got which job by wire-packet
            // length alone — `seal_in_place_separate_tag` scrambles
            // the post-header bytes, so byte-level stamps don't
            // survive the AEAD. Final wire size is 16-byte header
            // + plaintext_size + 16-byte tag.
            const A_PLAINTEXT: usize = 32;
            const B_PLAINTEXT: usize = 64;
            const A_WIRE: usize = 16 + A_PLAINTEXT + 16; // 64
            const B_WIRE: usize = 16 + B_PLAINTEXT + 16; // 96

            fn make_job(
                socket: crate::transport::udp::socket::AsyncUdpSocket,
                cipher: &LessSafeKey,
                counter: u64,
                dest: SocketAddr,
                plaintext_size: usize,
            ) -> FmpSendJob {
                // wire_buf: 16-byte header + plaintext + tag-room.
                let mut wire_buf = Vec::with_capacity(16 + plaintext_size + 16);
                wire_buf.extend_from_slice(&[0u8; 16]);
                wire_buf.extend_from_slice(&vec![0u8; plaintext_size]);
                FmpSendJob {
                    cipher: cipher.clone(),
                    counter,
                    wire_buf,
                    fsp_seal: None,
                    send_target: SelectedSendTarget::new(
                        socket,
                        #[cfg(any(target_os = "linux", target_os = "macos"))]
                        None,
                        dest,
                    ),
                    endpoint_flow_dispatch_key: None,
                    bulk_endpoint_data: true,
                    drop_on_backpressure: true,
                    scheduling_weight: DEFAULT_SEND_WEIGHT,
                    queued_at: None,
                }
            }

            let mut batch = vec![
                make_job(send_sock.clone(), &cipher, 1, addr_a, A_PLAINTEXT),
                make_job(send_sock.clone(), &cipher, 2, addr_b, B_PLAINTEXT),
                make_job(send_sock.clone(), &cipher, 3, addr_a, A_PLAINTEXT),
            ];
            flush_direct_batch_sync(&mut batch).expect("flush ok");
            assert!(batch.is_empty(), "flush must drain the batch");

            // recv_a expects exactly two packets, each A_WIRE bytes.
            let mut buf = [0u8; 256];
            for i in 0..2 {
                let (len, _) = recv_a.recv_from(&mut buf).expect("recv_a");
                assert_eq!(
                    len, A_WIRE,
                    "recv_a packet {i} has wrong length: got {len}, expected {A_WIRE}"
                );
            }

            // recv_b expects exactly one packet, B_WIRE bytes.
            let (len, _) = recv_b.recv_from(&mut buf).expect("recv_b");
            assert_eq!(
                len, B_WIRE,
                "recv_b packet has wrong length: got {len}, expected {B_WIRE}"
            );

            // Neither receiver may have leftovers. The pre-fix bug
            // would have either:
            //   (a) sent all 3 packets to addr_a (first-job dest
            //       used for the whole batch), causing recv_a to
            //       see a B_WIRE-sized packet and recv_b to see
            //       nothing, or
            //   (b) silently sent A's wire packets to addr_b's
            //       connected fd if any was installed.
            for (name, sock) in [("recv_a", &recv_a), ("recv_b", &recv_b)] {
                sock.set_read_timeout(Some(std::time::Duration::from_millis(50)))
                    .unwrap();
                let leftover = sock.recv_from(&mut buf);
                assert!(
                    leftover.is_err(),
                    "{name} got unexpected extra packet: {:?}",
                    leftover
                );
            }
        });
    }
}
